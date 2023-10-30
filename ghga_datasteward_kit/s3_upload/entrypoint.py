#!/usr/bin/env python3
# Copyright 2021 - 2023 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""
Contains functionality to actually run the S3 upload.
"""

import asyncio
import base64
import logging
from pathlib import Path

import typer
from ghga_service_commons.utils.crypt import encrypt

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.config import Config, LegacyConfig
from ghga_datasteward_kit.s3_upload.downloader import ChunkedDownloader
from ghga_datasteward_kit.s3_upload.uploader import ChunkedUploader
from ghga_datasteward_kit.s3_upload.utils import (
    LOGGER,
    HttpxClientState,
    check_adjust_part_size,
    check_output_path,
    get_objectstorage,
    handle_superficial_error,
    httpx_client,
)
from ghga_datasteward_kit.utils import load_config_yaml, read_token


async def shared_path(input_path: Path, alias: str, config: LegacyConfig):
    """
    Functionality shared between legacy and non-legacy upload path
    """
    if not input_path.exists():
        msg = f"No such file: {input_path.resolve()}"
        handle_superficial_error(msg=msg)

    if input_path.is_dir():
        msg = f"File location points to a directory: {input_path.resolve()}"
        handle_superficial_error(msg=msg)

    check_output_path(config.output_dir / f"{alias}.json")

    file_size = input_path.stat().st_size
    check_adjust_part_size(config=config, file_size=file_size)

    # set retry policy
    HttpxClientState.configure(5)

    uploader = ChunkedUploader(
        input_path=input_path,
        alias=alias,
        config=config,
        unencrypted_file_size=file_size,
    )
    await uploader.encrypt_and_upload()

    downloader = ChunkedDownloader(
        config=config,
        file_id=uploader.file_id,
        encrypted_file_size=uploader.encryptor.encrypted_file_size,
        file_secret=uploader.encryptor.file_secret,
        part_size=config.part_size,
        target_checksums=uploader.encryptor.checksums,
    )
    await downloader.download()

    return uploader, file_size


async def exchange_secret_for_id(
    *, file_id: str, alias: str, secret: bytes, token: str, config: Config
) -> str:
    """
    Call file ingest service to store the file secret and obtain a secret ID by which
    it can be retrieved.

    If storing the secret fails, the uploaded file is deleted from object storage and
    a ValueError is raised containing the file alias and response status code.
    """

    endpoint_url = f"{config.secret_ingest_baseurl}/federated/ingest_secret"
    file_secret = base64.b64encode(secret).decode("utf-8")
    payload = encrypt(data=file_secret, key=config.secret_ingest_pubkey)
    encrypted_secret = models.EncryptedPayload(payload=payload)

    with httpx_client() as client:
        headers = {"Authorization": f"Bearer {token}"}
        response = client.post(
            url=endpoint_url,
            json=encrypted_secret.dict(),
            headers=headers,
            timeout=60,
        )

        if response.status_code != 200:
            object_storage = get_objectstorage(config=config)
            await object_storage.delete_object(
                bucket_id=config.bucket_id, object_id=file_id
            )
            raise ValueError(
                f"Failed to deposit secret for {alias} with response code"
                + f" {response.status_code}. Removed uploaded file."
            )
        return response.json()["secret_id"]


async def async_main(input_path: Path, alias: str, config: Config, token: str):
    """
    Run encryption, upload and validation.
    Prints metadata to <alias>.json in the specified output directory
    """

    uploader, file_size = await shared_path(
        input_path=input_path, alias=alias, config=config
    )

    (
        unencrypted_checksum,
        encrypted_md5_checksums,
        encrypted_sha256_checksums,
    ) = uploader.encryptor.checksums.get()

    secret_id = await exchange_secret_for_id(
        file_id=uploader.file_id,
        alias=alias,
        secret=uploader.encryptor.file_secret,
        token=token,
        config=config,
    )

    metadata = models.OutputMetadata(
        alias=uploader.alias,
        file_uuid=uploader.file_id,
        original_path=input_path,
        part_size=config.part_size,
        secret_id=secret_id,
        unencrypted_checksum=unencrypted_checksum,
        encrypted_md5_checksums=encrypted_md5_checksums,
        encrypted_sha256_checksums=encrypted_sha256_checksums,
        unencrypted_size=file_size,
        encrypted_size=uploader.encryptor.encrypted_file_size,
    )
    output_path = config.output_dir / f"{uploader.alias}.json"
    LOGGER.info("(7/7) Writing metadata to %s.", output_path)
    metadata.serialize(output_path)


async def legacy_async_main(input_path: Path, alias: str, config: LegacyConfig):
    """
    Run encryption, upload and validation.
    Prints metadata to <alias>.json in the specified output directory
    """

    uploader, file_size = await shared_path(
        input_path=input_path, alias=alias, config=config
    )

    (
        unencrypted_checksum,
        encrypted_md5_checksums,
        encrypted_sha256_checksums,
    ) = uploader.encryptor.checksums.get()

    metadata = models.LegacyOutputMetadata(
        alias=uploader.alias,
        file_uuid=uploader.file_id,
        original_path=input_path,
        part_size=config.part_size,
        file_secret=uploader.encryptor.file_secret,
        unencrypted_checksum=unencrypted_checksum,
        encrypted_md5_checksums=encrypted_md5_checksums,
        encrypted_sha256_checksums=encrypted_sha256_checksums,
        unencrypted_size=file_size,
        encrypted_size=uploader.encryptor.encrypted_file_size,
    )
    output_path = config.output_dir / f"{uploader.alias}.json"
    LOGGER.info("(7/7) Writing metadata to %s.", output_path)
    metadata.serialize(output_path)


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

    token = read_token()
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    typer.run(main)
