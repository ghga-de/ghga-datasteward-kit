# Copyright 2022 Universität Tübingen, DKFZ and EMBL
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
Custom script to encrypt data using Crypt4GH and directly uploading it to S3 objectstorage
"""

import base64
import codecs
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from tempfile import mkstemp
from uuid import uuid4

import crypt4gh.header  # type: ignore
import crypt4gh.keys  # type: ignore
import crypt4gh.lib  # type: ignore
import requests  # type: ignore
import typer  # type: ignore
from ghga_service_chassis_lib.config import config_from_yaml  # type: ignore
from ghga_service_chassis_lib.s3 import ObjectStorageS3, S3ConfigBase  # type: ignore
from pydantic import BaseSettings, Field, SecretStr  # type: ignore


@config_from_yaml(prefix="nct")
class Config(BaseSettings):
    """
    Required options from a config file named .nct.yaml placed next to this script file
    """

    s3_endpoint_url: SecretStr = Field(..., description=("URL of the S3 server"))
    s3_access_key_id: SecretStr = Field(
        ..., description=("Access key ID for the S3 server")
    )
    s3_secret_access_key: SecretStr = Field(
        ..., description=("Secret access key for the S3 server")
    )
    bucket_id: str = Field(
        ..., description=("Bucket id where the encrypted, uploaded file is stored")
    )
    tmp_dir: Path = Field(..., description=("Directory for temporary output files"))
    output_dir: Path = Field(
        ...,
        description=("Directory for the output metadata file"),
    )


CONFIG = Config()
LOGGER = logging.getLogger("nct_upload")
PART_SIZE = 16 * 1024**2


@dataclass
class Keypair:
    """Crypt4GH keypair"""

    public_key: bytes
    private_key: bytes


def main(
    input_path: Path = typer.Argument(..., help="Local path of the input file"),
    alias: str = typer.Argument(..., help="A human readable file alias"),
):
    """
    Run encryption, upload and validation.
    Prints metadata to <alias>.json in the specified output directory
    """
    if not input_path.exists():
        raise ValueError(f"No such file: {input_path.resolve()}")
    if input_path.is_dir():
        raise ValueError(f"File location points to a directory: {input_path.resolve()}")
    file_checksum = get_checksum_unencrypted(input_path=input_path)
    file_id = str(uuid4())

    keypair = generate_crypt4gh_keypair()
    encrypted_file_loc = encrypt_file(
        input_path=input_path, file_alias=alias, file_id=file_id, keypair=keypair
    )
    file_size = encrypted_file_loc.stat().st_size
    file_secret, offset = read_envelope(
        encrypted_file_loc=encrypted_file_loc, keypair=keypair
    )
    enc_md5sums, enc_sha256sums = upload_file(
        encrypted_file_loc=encrypted_file_loc,
        file_id=file_id,
        file_size=file_size,
        offset=offset,
    )
    # delete local file
    encrypted_file_loc.unlink()
    download_and_validate(
        file_id=file_id,
        file_size=file_size,
        destination=encrypted_file_loc,
        checksum=file_checksum,
        file_secret=file_secret,
        keypair=keypair,
    )
    write_metadata(
        alias=alias,
        file_id=file_id,
        local_path=input_path,
        file_checksum=file_checksum,
        enc_md5sums=enc_md5sums,
        enc_sha256sums=enc_sha256sums,
        file_secret=file_secret,
    )


def get_checksum_unencrypted(input_path: Path) -> str:
    """Compute SHA256 checksum over unencrypted file content"""
    LOGGER.info("Computing checksum...\tThis might take a moment")
    chunk_size = 256 * 1024**2
    sha256sum = hashlib.sha256()
    file_size = input_path.stat().st_size
    sum_bytes = 0
    with input_path.open("rb") as file:
        data = file.read(chunk_size)
        while data:
            sum_bytes += len(data)
            LOGGER.info("Processing (%.2f%%)", sum_bytes / file_size * 100)
            sha256sum.update(data)
            data = file.read(chunk_size)
    return sha256sum.hexdigest()


def generate_crypt4gh_keypair() -> Keypair:
    """Creates a keypair using crypt4gh"""
    LOGGER.info("(1/7) Generating keypair")
    # Crypt4GH always writes to file and tmp_path fixture causes permission issues

    sk_file, sk_path = mkstemp(prefix="private", suffix=".key")
    pk_file, pk_path = mkstemp(prefix="public", suffix=".key")

    # Crypt4GH does not reset the umask it sets, so we need to deal with it
    original_umask = os.umask(0o022)
    crypt4gh.keys.c4gh.generate(seckey=sk_file, pubkey=pk_file)
    public_key = crypt4gh.keys.get_public_key(pk_path)
    private_key = crypt4gh.keys.get_private_key(sk_path, lambda: None)
    os.umask(original_umask)

    Path(pk_path).unlink()
    Path(sk_path).unlink()
    return Keypair(public_key=public_key, private_key=private_key)


def encrypt_file(input_path: Path, file_alias: str, file_id: str, keypair: Keypair):
    """Encrypt file using Crypt4GH"""
    LOGGER.info("(2/7) Encrypting file %s", input_path.resolve())
    tmp_dir = CONFIG.tmp_dir / file_alias
    if not tmp_dir.exists():
        tmp_dir.mkdir(parents=True)
    output_path = tmp_dir / file_id

    keys = [(0, keypair.private_key, keypair.public_key)]

    with input_path.open("rb") as infile:
        with output_path.open("wb") as outfile:
            crypt4gh.lib.encrypt(keys=keys, infile=infile, outfile=outfile)
    return output_path


def read_envelope(encrypted_file_loc: Path, keypair: Keypair):
    """Get file encryption/decryption secret and file content offset"""
    LOGGER.info("(3/7) Extracting file secret and content offset")
    with encrypted_file_loc.open("rb") as file:
        keys = [(0, keypair.private_key, None)]
        session_keys, _ = crypt4gh.header.deconstruct(infile=file, keys=keys)

        file_secret = session_keys[0]
        offset = file.tell()

    return file_secret, offset


def get_s3():
    """Configure S3 and return S3 DAO"""
    s3_config = S3ConfigBase(
        s3_endpoint_url=CONFIG.s3_endpoint_url.get_secret_value(),
        s3_access_key_id=CONFIG.s3_access_key_id.get_secret_value(),
        s3_secret_access_key=CONFIG.s3_secret_access_key.get_secret_value(),
    )
    return ObjectStorageS3(config=s3_config)


def upload_file(encrypted_file_loc: Path, file_id: str, file_size: int, offset: int):
    """Perform multipart upload and compute encrypted part checksums"""
    with get_s3() as storage:
        if storage.does_object_exist(bucket_id=CONFIG.bucket_id, object_id=file_id):
            storage.delete_object(bucket_id=CONFIG.bucket_id, object_id=file_id)

        upload_id = storage.init_multipart_upload(
            bucket_id=CONFIG.bucket_id, object_id=file_id
        )

    enc_md5sums = []
    enc_sha256sums = []

    sum_bytes = 0

    with encrypted_file_loc.open("rb") as file:
        file.seek(offset)
        part = file.read(PART_SIZE)
        part_number = 1
        while part:
            sum_bytes += len(part)
            LOGGER.info(
                "(4/7) Uploading part no. %i (%.2f%%)",
                part_number,
                sum_bytes / file_size * 100,
            )
            enc_md5sums.append(hashlib.md5(part, usedforsecurity=False).hexdigest())
            enc_sha256sums.append(hashlib.sha256(part).hexdigest())
            with get_s3() as storage:
                upload_url = storage.get_part_upload_url(
                    upload_id=upload_id,
                    bucket_id=CONFIG.bucket_id,
                    object_id=file_id,
                    part_number=part_number,
                )
            requests.put(upload_url, data=part, timeout=60)
            part_number += 1
            part = file.read(PART_SIZE)
        with get_s3() as storage:
            storage.complete_multipart_upload(
                upload_id=upload_id, bucket_id=CONFIG.bucket_id, object_id=file_id
            )

    return enc_md5sums, enc_sha256sums


def download_and_validate(
    file_id: str,
    file_size: int,
    destination: Path,
    checksum: str,
    file_secret: bytes,
    keypair: Keypair,
):  # pylint: disable=too-many-arguments
    """Download uploaded file, decrypt and verify checksum"""

    with get_s3() as storage:
        download_url = storage.get_object_download_url(
            bucket_id=CONFIG.bucket_id, object_id=file_id
        )
    sum_bytes = 0
    with requests.get(download_url, stream=True, timeout=60) as dl_stream:
        with destination.open("wb") as local_file:
            envelope = prepare_envelope(keypair=keypair, file_secret=file_secret)
            local_file.write(envelope)
            for part in dl_stream.iter_content(chunk_size=PART_SIZE):
                sum_bytes += len(part)
                LOGGER.info(
                    "(5/7) Downloading file for validation (%.2f%%)",
                    sum_bytes / file_size * 100,
                )
                local_file.write(part)
    # only calculate the checksum after we have the complete file
    validate_checksum(destination=destination, checksum=checksum, keypair=keypair)


def prepare_envelope(keypair: Keypair, file_secret: bytes):
    """
    Create personalized envelope
    """
    keys = [(0, keypair.private_key, keypair.public_key)]
    header_content = crypt4gh.header.make_packet_data_enc(0, file_secret)
    header_packets = crypt4gh.header.encrypt(header_content, keys)
    header_bytes = crypt4gh.header.serialize(header_packets)
    return header_bytes


def validate_checksum(destination: Path, checksum: str, keypair: Keypair):
    """Decrypt downloaded file and compare checksum with original"""
    LOGGER.info("(6/7) Decrypting and validating checksum")
    keys = [(0, keypair.private_key, None)]
    name = destination.name
    decrypted = destination.with_name(name + "_decrypted")
    with destination.open("rb") as infile:
        with decrypted.open("wb") as outfile:
            crypt4gh.lib.decrypt(
                keys=keys,
                infile=infile,
                outfile=outfile,
                sender_pubkey=keypair.public_key,
            )
    dl_checksum = get_checksum_unencrypted(decrypted)
    # remove temporary files
    destination.unlink()
    decrypted.unlink()
    if not dl_checksum == checksum:
        raise ValueError(
            f"Checksum mismatch:\nExpected: {checksum}\nActual: {dl_checksum}"
        )


def write_metadata(
    alias: str,
    file_id: str,
    local_path: Path,
    file_checksum: str,
    enc_md5sums: list[str],
    enc_sha256sums: list[str],
    file_secret: bytes,
):  # pylint: disable=too-many-arguments
    """Write all necessary data about the uploaded file"""
    output = {}
    output["Alias"] = alias
    output["File UUID"] = file_id
    output["Original filesystem path"] = str(local_path.resolve())
    output["Unencrpted file checksum"] = file_checksum
    output["Encrypted file part checksums (MD5)"] = json.dumps(enc_md5sums)
    output["Encrypted file part checksums (SHA256)"] = json.dumps(enc_sha256sums)
    output["Symmetric file encryption secret"] = codecs.decode(
        base64.b64encode(file_secret), encoding="utf-8"
    )

    if not CONFIG.output_dir.exists():
        CONFIG.output_dir.mkdir(parents=True)

    output_path = CONFIG.output_dir / f"{alias}.json"
    LOGGER.info("(7/7) Writing file metadata to %s", output_path)
    # owner read-only
    with output_path.open("w") as file:
        json.dump(output, file, indent=2)
    os.chmod(path=output_path, mode=0o400)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    typer.run(main)
