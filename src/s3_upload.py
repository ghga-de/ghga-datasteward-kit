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

import asyncio
import base64
import codecs
import hashlib
import json
import logging
import math
import os
import sys
from dataclasses import dataclass
from io import BufferedReader
from pathlib import Path
from tempfile import mkstemp
from typing import Any
from uuid import uuid4

import crypt4gh.header  # type: ignore
import crypt4gh.keys  # type: ignore
import crypt4gh.lib  # type: ignore
import requests  # type: ignore
import typer  # type: ignore
from ghga_service_chassis_lib.config import config_from_yaml  # type: ignore
from hexkit.providers.s3 import S3Config, S3ObjectStorage  # type: ignore
from pydantic import BaseSettings, Field, SecretStr  # type: ignore
from requests.adapters import HTTPAdapter, Retry  # type: ignore


@config_from_yaml(prefix="upload")
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


def configure_session() -> requests.Session:
    """Configure session with exponential backoff retry"""
    session = requests.session()
    retries = Retry(total=7, backoff_factor=1)
    adapter = HTTPAdapter(max_retries=retries)

    session.mount("http://", adapter=adapter)
    session.mount("https://", adapter=adapter)

    return session


CONFIG = Config()
LOGGER = logging.getLogger("nct_upload")
PART_SIZE = 16 * 1024**2
SESSION = configure_session()


@dataclass
class Keypair:
    """Crypt4GH keypair"""

    public_key: bytes
    private_key: bytes


class Upload:
    """Handler class dealing with most of the upload functionality"""

    def __init__(self, input_path: Path, alias: str) -> None:
        self.file_id = str(uuid4())
        self.alias = alias
        self.input_path = input_path
        self.checksum = get_checksum_unencrypted(input_path)
        self.keypair = generate_crypt4gh_keypair()

    async def process_file(self):
        """Run upload/download/validation flow"""
        encrypted_file_loc = self._encrypt_file()
        file_secret, offset = self._read_envelope(encrypted_file_loc=encrypted_file_loc)
        file_size = encrypted_file_loc.stat().st_size - offset
        enc_md5sums, enc_sha256sums = await self._upload_file(
            encrypted_file_loc=encrypted_file_loc,
            file_size=file_size,
            offset=offset,
        )
        await self._download(
            file_size=file_size, destination=encrypted_file_loc, file_secret=file_secret
        )
        # only calculate the checksum after we have the complete file
        self._validate_checksum(destination=encrypted_file_loc)
        self._write_metadata(
            enc_md5sums=enc_md5sums,
            enc_sha256sums=enc_sha256sums,
            file_secret=file_secret,
        )

    def _encrypt_file(self):
        """Encrypt file using Crypt4GH"""
        LOGGER.info("(2/7) Encrypting file %s", self.input_path.resolve())
        tmp_dir = CONFIG.tmp_dir / self.alias
        if not tmp_dir.exists():
            tmp_dir.mkdir(parents=True)
        output_path = tmp_dir / self.file_id

        keys = [(0, self.keypair.private_key, self.keypair.public_key)]

        with self.input_path.open("rb") as infile:
            with output_path.open("wb") as outfile:
                crypt4gh.lib.encrypt(keys=keys, infile=infile, outfile=outfile)
        return output_path

    def _read_envelope(self, *, encrypted_file_loc: Path):
        """Get file encryption/decryption secret and file content offset"""
        LOGGER.info("(3/7) Extracting file secret and content offset")
        with encrypted_file_loc.open("rb") as file:
            keys = [(0, self.keypair.private_key, None)]
            session_keys, _ = crypt4gh.header.deconstruct(infile=file, keys=keys)

            file_secret = session_keys[0]
            offset = file.tell()

        return file_secret, offset

    async def _upload_file(
        self, *, encrypted_file_loc: Path, file_size: int, offset: int
    ):
        """Perform multipart upload and compute encrypted part checksums"""
        storage = objectstorage()
        upload_id = await storage.init_multipart_upload(
            bucket_id=CONFIG.bucket_id, object_id=self.file_id
        )

        enc_md5sums = []
        enc_sha256sums = []
        sum_bytes = 0

        with encrypted_file_loc.open("rb") as file:
            for part_number, part in enumerate(
                read_file(file=file, part_size=PART_SIZE, offset=offset), start=1
            ):
                sum_bytes += len(part)
                LOGGER.info(
                    "(4/7) Uploading part no. %i (%.2f%%)",
                    part_number,
                    sum_bytes / file_size * 100,
                )
                enc_md5sums.append(hashlib.md5(part, usedforsecurity=False).hexdigest())
                enc_sha256sums.append(hashlib.sha256(part).hexdigest())
                try:
                    upload_url = await storage.get_part_upload_url(
                        upload_id=upload_id,
                        bucket_id=CONFIG.bucket_id,
                        object_id=self.file_id,
                        part_number=part_number,
                    )
                    SESSION.put(url=upload_url, data=part)
                except (  # pylint: disable=broad-except
                    Exception,
                    KeyboardInterrupt,
                ) as exc:
                    LOGGER.error(
                        "Error occured during uplpload: %s\nCleaning up. Please retry.",
                        str(exc),
                    )
                    await storage.abort_multipart_upload(
                        upload_id=upload_id,
                        bucket_id=CONFIG.bucket_id,
                        object_id=self.file_id,
                    )
                    encrypted_file_loc.unlink()
                    sys.exit()

        try:
            await storage.complete_multipart_upload(
                upload_id=upload_id,
                bucket_id=CONFIG.bucket_id,
                object_id=self.file_id,
                anticipated_part_quantity=math.ceil(file_size / PART_SIZE),
                anticipated_part_size=PART_SIZE,
            )
        except (Exception, KeyboardInterrupt) as exc:  # pylint: disable=broad-except
            LOGGER.error(
                "Error occured during uplpload: %s\nCleaning up. Please retry.",
                str(exc),
            )
            await storage.abort_multipart_upload(
                upload_id=upload_id, bucket_id=CONFIG.bucket_id, object_id=self.file_id
            )
            encrypted_file_loc.unlink()
            sys.exit()

        encrypted_file_loc.unlink()
        return enc_md5sums, enc_sha256sums

    async def _download(
        self,
        *,
        file_size: int,
        destination: Path,
        file_secret: bytes,
    ):  # pylint: disable=too-many-arguments
        """Download uploaded file"""
        storage = objectstorage()
        download_url = await storage.get_object_download_url(
            bucket_id=CONFIG.bucket_id, object_id=self.file_id
        )
        with destination.open("wb") as local_file:
            envelope = prepare_envelope(keypair=self.keypair, file_secret=file_secret)
            local_file.write(envelope)

            for start, stop in get_ranges(file_size=file_size):
                headers = {"Range": f"bytes={start}-{stop}"}
                response = SESSION.get(download_url, timeout=60, headers=headers)
                chunk = response.content
                LOGGER.info(
                    "(5/7) Downloading file for validation (%.2f%%)",
                    stop / file_size * 100,
                )
                local_file.write(chunk)

    def _validate_checksum(self, destination: Path):
        """Decrypt downloaded file and compare checksum with original"""

        LOGGER.info("(6/7) Decrypting and validating checksum")
        keys = [(0, self.keypair.private_key, None)]
        name = destination.name
        decrypted = destination.with_name(name + "_decrypted")
        with destination.open("rb") as infile:
            with decrypted.open("wb") as outfile:
                crypt4gh.lib.decrypt(
                    keys=keys,
                    infile=infile,
                    outfile=outfile,
                    sender_pubkey=self.keypair.public_key,
                )
        dl_checksum = get_checksum_unencrypted(decrypted)
        # remove temporary files
        destination.unlink()
        decrypted.unlink()
        if dl_checksum != self.checksum:
            raise ValueError(
                f"Checksum mismatch:\nExpected: {self.checksum}\nActual: {dl_checksum}"
            )

    def _write_metadata(
        self,
        *,
        enc_md5sums: list[str],
        enc_sha256sums: list[str],
        file_secret: bytes,
    ):  # pylint: disable=too-many-arguments
        """Write all necessary data about the uploaded file"""
        output: dict[str, Any] = {}
        output["Alias"] = self.alias
        output["File UUID"] = self.file_id
        output["Original filesystem path"] = str(self.input_path.resolve())
        output["Unencrpted file checksum"] = self.checksum
        output["Encrypted file part checksums (MD5)"] = enc_md5sums
        output["Encrypted file part checksums (SHA256)"] = enc_sha256sums
        output["Symmetric file encryption secret"] = codecs.decode(
            base64.b64encode(file_secret), encoding="utf-8"
        )

        if not CONFIG.output_dir.exists():
            CONFIG.output_dir.mkdir(parents=True)

        output_path = CONFIG.output_dir / f"{self.alias}.json"
        LOGGER.info("(7/7) Writing file metadata to %s", output_path)
        # owner read-only
        with output_path.open("w") as file:
            json.dump(output, file, indent=2)
        os.chmod(path=output_path, mode=0o400)


def check_output_path(alias: str):
    """Check if we accidentally try to overwrite an alread existing metadata file"""
    output_path = CONFIG.output_dir / f"{alias}.json"
    if output_path.exists():
        msg = f"Output file {output_path.resolve()} already exists and cannot be overwritten."
        handle_superficial_error(msg=msg)


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


def get_checksum_unencrypted(file_location: Path) -> str:
    """Compute SHA256 checksum over unencrypted file content"""

    LOGGER.info("Computing checksum...\tThis might take a moment")
    sha256sum = hashlib.sha256()
    file_size = file_location.stat().st_size
    sum_bytes = 0
    with file_location.open("rb") as file:
        for part in read_file(file=file, part_size=PART_SIZE):
            sum_bytes += len(part)
            LOGGER.info("Computing checksum (%.2f%%)", sum_bytes / file_size * 100)
            sha256sum.update(part)

    return sha256sum.hexdigest()


def objectstorage():
    """Configure S3 and return S3 DAO"""
    s3_config = S3Config(
        s3_endpoint_url=CONFIG.s3_endpoint_url.get_secret_value(),
        s3_access_key_id=CONFIG.s3_access_key_id.get_secret_value(),
        s3_secret_access_key=CONFIG.s3_secret_access_key.get_secret_value(),
    )
    return S3ObjectStorage(config=s3_config)


def read_file(*, file: BufferedReader, part_size: int, offset: int = 0):
    """Read file content from offset in chunks"""
    file.seek(offset)
    while True:
        file_part = file.read(part_size)

        if len(file_part) == 0:
            return

        yield file_part


def prepare_envelope(keypair: Keypair, file_secret: bytes):
    """
    Create personalized envelope
    """
    keys = [(0, keypair.private_key, keypair.public_key)]
    header_content = crypt4gh.header.make_packet_data_enc(0, file_secret)
    header_packets = crypt4gh.header.encrypt(header_content, keys)
    header_bytes = crypt4gh.header.serialize(header_packets)
    return header_bytes


def get_ranges(file_size: int):
    """Calculate part ranges"""
    num_parts = file_size / PART_SIZE
    byte_ranges = [
        (PART_SIZE * part_no, PART_SIZE * (part_no + 1) - 1)
        for part_no in range(int(num_parts))
    ]
    if math.ceil(num_parts) != int(num_parts):
        byte_ranges.append((PART_SIZE * int(num_parts), file_size - 1))

    return byte_ranges


def handle_superficial_error(msg: str):
    """Don't want user dealing with stacktrace on simple input/output issues, log instead"""
    LOGGER.critical(msg)
    sys.exit(-1)


def main(
    input_path: Path = typer.Argument(..., help="Local path of the input file"),
    alias: str = typer.Argument(..., help="A human readable file alias"),
):
    """Delegate to async_main. typer.run is not async (yet)"""
    asyncio.run(async_main(input_path=input_path, alias=alias))


async def async_main(input_path: Path, alias: str):
    """
    Run encryption, upload and validation.
    Prints metadata to <alias>.json in the specified output directory
    """
    if not input_path.exists():
        msg = f"No such file: {input_path.resolve()}"
        handle_superficial_error(msg=msg)

    if input_path.is_dir():
        msg = f"File location points to a directory: {input_path.resolve()}"
        handle_superficial_error(msg=msg)

    check_output_path(alias=alias)
    upload = Upload(input_path=input_path, alias=alias)
    await upload.process_file()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    typer.run(main)
