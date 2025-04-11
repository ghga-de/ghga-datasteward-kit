#!/usr/bin/env python3
# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains functionality to actually run the S3 upload."""

import asyncio
import base64
import logging
from pathlib import Path

import typer
from ghga_service_commons.utils.crypt import encrypt

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.config import Config, LegacyConfig
from ghga_datasteward_kit.s3_upload.exceptions import (
    SecretExchangeError,
    WritingOutputError,
)
from ghga_datasteward_kit.s3_upload.http_client import RequestConfigurator, httpx_client
from ghga_datasteward_kit.s3_upload.multipart_upload import MultipartUpload
from ghga_datasteward_kit.s3_upload.utils import (
    LOG,
    check_adjust_part_size,
    check_output_path,
    get_bucket_id,
    handle_superficial_error,
)
from ghga_datasteward_kit.utils import STEWARD_TOKEN, load_config_yaml, path_join


def main(
    input_path: Path = typer.Option(..., help="Local path of the input file"),
    alias: str = typer.Option(..., help="A human readable file alias"),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """
    Custom script to encrypt data using Crypt4GH and directly uploading it to S3
    object storage.
    """
    config = load_config_yaml(config_path, Config)

    token = STEWARD_TOKEN.read_token()
    asyncio.run(
        async_main(input_path=input_path, alias=alias, config=config, token=token)
    )


def legacy_main(
    input_path: Path = typer.Option(..., help="Local path of the input file"),
    alias: str = typer.Option(..., help="A human readable file alias"),
    config_path: Path = typer.Option(..., help="Path to a config YAML."),
):
    """
    Custom script to encrypt data using Crypt4GH and directly uploading it to S3
    object storage.
    """
    config = load_config_yaml(config_path, LegacyConfig)
    asyncio.run(legacy_async_main(input_path=input_path, alias=alias, config=config))


async def async_main(input_path: Path, alias: str, config: Config, token: str):
    """
    Run encryption, upload and validation.
    Prints metadata to <alias>.json in the specified output directory
    """
    RequestConfigurator.configure(config=config)
    file_size = await check_adjust_input_file(
        input_path=input_path, alias=alias, config=config
    )

    async with MultipartUpload(file_size=file_size, config=config) as upload:
        checksums, raw_file_secret = await upload.validate_and_transfer_content(
            input_path=input_path
        )

        (
            unencrypted_checksum,
            encrypted_md5_checksums,
            encrypted_sha256_checksums,
        ) = checksums.get()

        secret_id = await exchange_secret_for_id(
            file_id=upload.file_id,
            secret=raw_file_secret,
            token=token,
            config=config,
        )

        metadata = models.OutputMetadata(
            alias=alias,
            file_id=upload.file_id,
            bucket_id=get_bucket_id(config=config),
            object_id=upload.file_id,
            original_path=input_path,
            part_size=config.part_size,
            secret_id=secret_id,
            unencrypted_checksum=unencrypted_checksum,
            encrypted_md5_checksums=encrypted_md5_checksums,
            encrypted_sha256_checksums=encrypted_sha256_checksums,
            unencrypted_size=file_size,
            encrypted_size=upload.encrypted_file_size,
            storage_alias=config.selected_storage_alias,
        )
        write_output(
            alias=alias,
            bucket_id=get_bucket_id(config),
            object_id=upload.file_id,
            metadata=metadata,
            output_dir=config.output_dir,
        )


async def legacy_async_main(input_path: Path, alias: str, config: LegacyConfig):
    """
    Run encryption, upload and validation.
    Prints metadata to <alias>.json in the specified output directory
    """
    RequestConfigurator.configure(config=config)
    file_size = await check_adjust_input_file(
        input_path=input_path, alias=alias, config=config
    )

    async with MultipartUpload(file_size=file_size, config=config) as upload:
        checksums, raw_file_secret = await upload.validate_and_transfer_content(
            input_path=input_path
        )

        (
            unencrypted_checksum,
            encrypted_md5_checksums,
            encrypted_sha256_checksums,
        ) = checksums.get()

        file_secret = base64.b64encode(raw_file_secret).decode("utf-8")

        metadata = models.LegacyOutputMetadata(
            alias=alias,
            file_id=upload.file_id,
            bucket_id=get_bucket_id(config=config),
            object_id=upload.file_id,
            original_path=input_path,
            part_size=config.part_size,
            file_secret=file_secret,
            unencrypted_checksum=unencrypted_checksum,
            encrypted_md5_checksums=encrypted_md5_checksums,
            encrypted_sha256_checksums=encrypted_sha256_checksums,
            unencrypted_size=file_size,
            encrypted_size=upload.encrypted_file_size,
            storage_alias=config.selected_storage_alias,
        )
        write_output(
            alias=alias,
            bucket_id=get_bucket_id(config),
            object_id=upload.file_id,
            metadata=metadata,
            output_dir=config.output_dir,
        )


async def check_adjust_input_file(
    input_path: Path, alias: str, config: LegacyConfig
) -> int:
    """Check if input file exists, get file size and adjust part size if necessary."""
    if not input_path.exists():
        msg = f"No such file: {input_path.resolve()}"
        handle_superficial_error(msg=msg)

    if input_path.is_dir():
        msg = f"File location points to a directory: {input_path.resolve()}"
        handle_superficial_error(msg=msg)

    check_output_path(config.output_dir / f"{alias}.json")

    file_size = input_path.stat().st_size
    check_adjust_part_size(config=config, file_size=file_size)

    return file_size


async def exchange_secret_for_id(
    *,
    file_id: str,
    secret: bytes,
    token: str,
    config: Config,
) -> str:
    """
    Call file ingest service to store the file secret and obtain a secret ID by which
    it can be retrieved.

    If storing the secret fails, the uploaded file is deleted from object storage and
    a SecretExchangeError is raised with the file ID, bucket ID, and response status code.
    """
    endpoint = "/federated/ingest_secret"
    endpoint_url = path_join(config.secret_ingest_baseurl, endpoint)
    file_secret = base64.b64encode(secret).decode("utf-8")
    payload = encrypt(data=file_secret, key=config.secret_ingest_pubkey)
    encrypted_secret = models.EncryptedPayload(payload=payload)

    async with httpx_client() as client:
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.post(
            url=endpoint_url, json=encrypted_secret.model_dump(), headers=headers
        )

        if response.status_code != 200:
            message = (
                f"Failed to deposit secret for {file_id} with response code"
                + f" {response.status_code}."
            )
            raise SecretExchangeError(
                bucket_id=get_bucket_id(config), object_id=file_id, message=message
            )
        return response.json()["secret_id"]


def write_output(
    *,
    alias: str,
    bucket_id: str,
    object_id: str,
    metadata: models.LegacyOutputMetadata | models.OutputMetadata,
    output_dir: Path,
):
    """Write local output metadata file."""
    output_path = output_dir / f"{alias}.json"
    LOG.info("(4/4) Writing metadata to %s.", output_path)
    try:
        metadata.serialize(output_path)
    except (
        Exception,
        KeyboardInterrupt,
    ) as exc:
        raise WritingOutputError(bucket_id=bucket_id, object_id=object_id) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    typer.run(main)
