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
Custom script to encrypt data using Crypt4GH and directly uploading it to S3
objectstorage.
"""

import asyncio
import logging
import math
import os
import subprocess  # nosec
import sys
from contextlib import contextmanager
from functools import partial
from io import BufferedReader
from pathlib import Path
from time import time
from typing import Generator, Iterator
from uuid import uuid4

import crypt4gh.header  # type: ignore
import crypt4gh.keys  # type: ignore
import crypt4gh.lib  # type: ignore
import httpx
from hexkit.providers.s3 import S3Config, S3ObjectStorage  # type: ignore
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_encrypt
from pydantic import BaseSettings, Field, SecretStr, validator

from ghga_datasteward_kit import models
from ghga_datasteward_kit.utils import load_config_yaml

LOGGER = logging.getLogger("s3_upload")
PART_SIZE = 16 * 1024**2


def expand_env_vars_in_path(path: Path) -> Path:
    """Expand environment variables in a Path."""

    with subprocess.Popen(  # nosec
        f"realpath {path}", shell=True, stdout=subprocess.PIPE
    ) as process:
        if process.wait() != 0 or not process.stdout:
            raise RuntimeError(f"Parsing of path failed: {path}")

        output = process.stdout.read().decode("utf-8").strip()

    return Path(output)


class Config(BaseSettings):
    """
    Required options for file uploads.
    """

    s3_endpoint_url: SecretStr = Field(..., description="URL of the S3 server")
    s3_access_key_id: SecretStr = Field(
        ..., description="Access key ID for the S3 server"
    )
    s3_secret_access_key: SecretStr = Field(
        ..., description="Secret access key for the S3 server"
    )
    bucket_id: str = Field(
        ..., description="Bucket id where the encrypted, uploaded file is stored"
    )
    part_size: int = Field(
        16, description="Upload part size in MiB. Has to be between 5 and 5120."
    )
    output_dir: Path = Field(
        ...,
        description="Directory for the output metadata file",
    )

    @validator("output_dir")
    def expand_env_vars_output_dir(
        cls, output_dir: Path
    ):  # pylint: disable=no-self-argument
        """Expand vars in path"""
        return expand_env_vars_in_path(output_dir)


class ChunkedUploader:
    """Handler class dealing with upload functionality"""

    def __init__(
        self, input_path: Path, alias: str, config: Config, unencrypted_file_size: int
    ) -> None:
        self.alias = alias
        self.config = config
        self.input_path = input_path
        self.encryptor = Encryptor(self.config.part_size)
        self.file_id = str(uuid4())
        self.unencrypted_file_size = unencrypted_file_size
        self.encrypted_file_size = 0

    async def encrypt_and_upload(self):
        """Delegate encryption and perform multipart upload"""

        # compute encrypted_file_size
        num_segments = math.ceil(self.unencrypted_file_size / crypt4gh.lib.SEGMENT_SIZE)
        encrypted_file_size = self.unencrypted_file_size + num_segments * 28
        num_parts = math.ceil(encrypted_file_size / self.config.part_size)

        start = time()

        with open(self.input_path, "rb") as file:
            async with MultipartUpload(
                config=self.config,
                file_id=self.file_id,
                encrypted_file_size=encrypted_file_size,
                part_size=self.config.part_size,
            ) as upload:
                LOGGER.info("(1/7) Initialized file uplod for %s.", upload.file_id)
                for part_number, part in enumerate(
                    self.encryptor.process_file(file=file), start=1
                ):
                    await upload.send_part(part_number=part_number, part=part)

                    delta = time() - start
                    avg_speed = (
                        part_number * (self.config.part_size / 1024**2) / delta
                    )
                    LOGGER.info(
                        "(2/7) Processing upload for file part %i/%i (%.2f MiB/s)",
                        part_number,
                        num_parts,
                        avg_speed,
                    )
                if encrypted_file_size != self.encryptor.encrypted_file_size:
                    raise ValueError(
                        "Mismatch between actual and theoretical encrypted part size:\n"
                        + f"Is: {self.encryptor.encrypted_file_size}\n"
                        + f"Should be: {encrypted_file_size}"
                    )
                LOGGER.info("(3/7) Finished upload for %s.", upload.file_id)


class ChunkedDownloader:
    """Handler class dealing with download functionality"""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        config: Config,
        file_id: str,
        encrypted_file_size: int,
        file_secret: bytes,
        part_size: int,
        target_checksums: models.Checksums,
    ) -> None:
        self.config = config
        self.storage = objectstorage(self.config)
        self.file_id = file_id
        self.file_size = encrypted_file_size
        self.file_secret = file_secret
        self.part_size = part_size
        self.target_checksums = target_checksums

    def _download_parts(self, download_url):
        """Download file parts"""

        for part_no, (start, stop) in enumerate(
            get_ranges(file_size=self.file_size, part_size=self.config.part_size),
            start=1,
        ):
            headers = {"Range": f"bytes={start}-{stop}"}
            LOGGER.debug("Downloading part number %i. %s", part_no, headers)
            with httpx_client() as client:
                response = client.get(download_url, timeout=60, headers=headers)
            yield response.content

    async def download(self):
        """Download file in parts and validate checksums"""
        LOGGER.info("(4/7) Downloading file %s for validation.", self.file_id)
        download_url = await self.storage.get_object_download_url(
            bucket_id=self.config.bucket_id, object_id=self.file_id
        )
        num_parts = math.ceil(self.file_size / self.part_size)
        decryptor = Decryptor(
            file_secret=self.file_secret, num_parts=num_parts, part_size=self.part_size
        )
        download_func = partial(self._download_parts, download_url=download_url)
        decryptor.process_parts(download_func)
        self.validate_checksums(checkums=decryptor.checksums)

    def validate_checksums(self, checkums: models.Checksums):
        """Confirm checksums for upload and download match"""
        if not self.target_checksums.get() == checkums.get():
            raise ValueError(
                f"Checksum mismatch:\nUpload:\n{checkums}\nDownload:\n{self.target_checksums}"
            )
        LOGGER.info("(6/7) Succesfully validated checksums for %s.", self.file_id)


class Decryptor:
    """Handles on the fly decryption and checksum calculation"""

    def __init__(self, file_secret: bytes, num_parts: int, part_size: int) -> None:
        self.checksums = models.Checksums()
        self.file_secret = file_secret
        self.num_parts = num_parts
        self.part_size = part_size

    def _decrypt(self, part: bytes):
        """Decrypt file part"""
        segments, incomplete_segment = get_segments(
            part=part, segment_size=crypt4gh.lib.CIPHER_SEGMENT_SIZE
        )

        decrypted_segments = []
        for segment in segments:
            decrypted_segments.append(self._decrypt_segment(segment))

        return b"".join(decrypted_segments), incomplete_segment

    def _decrypt_segment(self, segment: bytes):
        """Decrypt single ciphersegment"""
        return crypt4gh.lib.decrypt_block(
            ciphersegment=segment, session_keys=[self.file_secret]
        )

    def process_parts(self, download_files: partial[Generator[bytes, None, None]]):
        """Encrypt and upload file parts."""
        unprocessed_bytes = b""
        download_buffer = b""
        start = time()

        for part_number, file_part in enumerate(download_files()):
            # process unencrypted
            self.checksums.update_encrypted(file_part)
            unprocessed_bytes += file_part

            # encrypt in chunks
            decrypted_bytes, unprocessed_bytes = self._decrypt(unprocessed_bytes)
            download_buffer += decrypted_bytes

            # update checksums and yield if part size
            if len(download_buffer) >= self.part_size:
                current_part = download_buffer[: self.part_size]
                self.checksums.update_unencrypted(current_part)
                download_buffer = download_buffer[self.part_size :]

            delta = time() - start
            avg_speed = (part_number * (self.part_size / 1024**2)) / delta
            LOGGER.info(
                "(5/7) Downloading part %i/%i (%.2f MiB/s)",
                part_number,
                self.num_parts,
                avg_speed,
            )

        # process dangling bytes
        if unprocessed_bytes:
            download_buffer += self._decrypt_segment(unprocessed_bytes)

        while len(download_buffer) >= self.part_size:
            current_part = download_buffer[: self.part_size]
            self.checksums.update_unencrypted(current_part)
            download_buffer = download_buffer[self.part_size :]

        if download_buffer:
            self.checksums.update_unencrypted(download_buffer)


class Encryptor:
    """Handles on the fly encryption and checksum calculation"""

    def __init__(self, part_size: int):
        self.part_size = part_size
        self.checksums = models.Checksums()
        self.file_secret = os.urandom(32)
        self.encrypted_file_size = 0

    def _encrypt(self, part: bytes):
        """Encrypt file part using secret"""
        segments, incomplete_segment = get_segments(
            part=part, segment_size=crypt4gh.lib.SEGMENT_SIZE
        )

        encrypted_segments = []
        for segment in segments:
            encrypted_segments.append(self._encrypt_segment(segment))

        return b"".join(encrypted_segments), incomplete_segment

    def _encrypt_segment(self, segment=bytes):
        """Encrypt one single segment"""
        nonce = os.urandom(12)
        encrypted_data = crypto_aead_chacha20poly1305_ietf_encrypt(
            segment, None, nonce, self.file_secret
        )  # no aad
        return nonce + encrypted_data

    # type annotation for file parts, should be generator
    def process_file(self, file: BufferedReader):
        """Encrypt and upload file parts."""
        unprocessed_bytes = b""
        upload_buffer = b""

        for file_part in read_file_parts(file=file, part_size=self.part_size):
            # process unencrypted
            self.checksums.update_unencrypted(file_part)
            unprocessed_bytes += file_part

            # encrypt in chunks
            encrypted_bytes, unprocessed_bytes = self._encrypt(unprocessed_bytes)
            upload_buffer += encrypted_bytes

            # update checksums and yield if part size
            if len(upload_buffer) >= self.part_size:
                current_part = upload_buffer[: self.part_size]
                self.checksums.update_encrypted(current_part)
                self.encrypted_file_size += self.part_size
                yield current_part
                upload_buffer = upload_buffer[self.part_size :]

        # process dangling bytes
        if unprocessed_bytes:
            upload_buffer += self._encrypt_segment(unprocessed_bytes)

        while len(upload_buffer) >= self.part_size:
            current_part = upload_buffer[: self.part_size]
            self.checksums.update_encrypted(current_part)
            self.encrypted_file_size += self.part_size
            yield current_part
            upload_buffer = upload_buffer[self.part_size :]

        if upload_buffer:
            self.checksums.update_encrypted(upload_buffer)
            self.encrypted_file_size += len(upload_buffer)
            yield upload_buffer


class MultipartUpload:
    """Context manager to handle init + complete/abort for S3 multipart upload"""

    def __init__(
        self, config: Config, file_id: str, encrypted_file_size: int, part_size: int
    ) -> None:
        self.config = config
        self.storage = objectstorage(config=self.config)
        self.file_id = file_id
        self.file_size = encrypted_file_size
        self.part_size = part_size
        self.upload_id = ""

    async def __aenter__(self):
        """Start multipart upload"""
        self.upload_id = await self.storage.init_multipart_upload(
            bucket_id=self.config.bucket_id, object_id=self.file_id
        )
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        """Complete or clean up multipart upload"""
        try:
            await self.storage.complete_multipart_upload(
                upload_id=self.upload_id,
                bucket_id=self.config.bucket_id,
                object_id=self.file_id,
                anticipated_part_quantity=math.ceil(self.file_size / self.part_size),
                anticipated_part_size=self.part_size,
            )
        except (Exception, KeyboardInterrupt) as exc:  # pylint: disable=broad-except
            await self.storage.abort_multipart_upload(
                upload_id=self.upload_id,
                bucket_id=self.config.bucket_id,
                object_id=self.file_id,
            )
            raise exc

    async def send_part(self, part: bytes, part_number: int):
        """Handle upload of one file part"""
        try:
            upload_url = await self.storage.get_part_upload_url(
                upload_id=self.upload_id,
                bucket_id=self.config.bucket_id,
                object_id=self.file_id,
                part_number=part_number,
            )
            with httpx_client() as client:
                client.put(url=upload_url, content=part)
        except (  # pylint: disable=broad-except
            Exception,
            KeyboardInterrupt,
        ) as exc:
            await self.storage.abort_multipart_upload(
                upload_id=self.upload_id,
                bucket_id=self.config.bucket_id,
                object_id=self.file_id,
            )
            raise exc


class HttpxClientState:
    """Helper class to make max_retries user configurable"""

    max_retries: int

    @classmethod
    def configure(cls, max_retries: int):
        """Configure client with exponential backoff retry (using httpx's 0.5 default)"""

        # can't be negative - should we log this?
        cls.max_retries = max(0, max_retries)


@contextmanager
def httpx_client():
    """Yields a context manager httpx client and closes it afterward"""

    transport = httpx.HTTPTransport(retries=HttpxClientState.max_retries)

    with httpx.Client(transport=transport) as client:
        yield client


def read_file_parts(
    file: BufferedReader, *, part_size: int, from_part: int = 1
) -> Iterator[bytes]:
    """
    Returns an iterator to iterate through file parts of the given size (in bytes).

    By default it start with the first part but you may also start from a specific part
    in the middle of the file using the `from_part` argument. This might be useful to
    resume an interrupted reading process.

    Please note: opening and closing of the file MUST happen outside of this function.
    """

    initial_offset = part_size * (from_part - 1)
    file.seek(initial_offset)

    while True:
        file_part = file.read(part_size)

        if len(file_part) == 0:
            return

        yield file_part


def objectstorage(config: Config):
    """Configure S3 and return S3 DAO"""
    s3_config = S3Config(
        s3_endpoint_url=config.s3_endpoint_url.get_secret_value(),
        s3_access_key_id=config.s3_access_key_id.get_secret_value(),
        s3_secret_access_key=config.s3_secret_access_key.get_secret_value(),
    )
    return S3ObjectStorage(config=s3_config)


def get_segments(part: bytes, segment_size: int):
    """Chunk part into cipher segments"""
    num_segments = len(part) / segment_size
    full_segments = int(num_segments)
    segments = [
        part[i * segment_size : (i + 1) * segment_size] for i in range(full_segments)
    ]

    # check if we have a remainder of bytes that we need to handle,
    # i.e. non-matching boundaries between part and cipher segment size
    incomplete_segment = b""
    partial_segment_idx = math.ceil(num_segments)
    if partial_segment_idx != full_segments:
        incomplete_segment = part[full_segments * segment_size :]
    return segments, incomplete_segment


def get_ranges(file_size: int, part_size: int):
    """Calculate part ranges"""
    num_parts = file_size / part_size
    num_parts_floor = int(num_parts)

    byte_ranges = [
        (part_size * part_no, part_size * (part_no + 1) - 1)
        for part_no in range(num_parts_floor)
    ]
    if math.ceil(num_parts) != num_parts_floor:
        byte_ranges.append((part_size * num_parts_floor, file_size - 1))

    return byte_ranges


def handle_superficial_error(msg: str):
    """Don't want user dealing with stacktrace on simple input/output issues, log instead"""
    LOGGER.critical(msg)
    sys.exit(-1)


def check_adjust_part_size(config: Config, file_size: int):
    """
    Convert specified part size from MiB to bytes, check if it needs adjustment and
    adjust accordingly
    """
    lower_bound = 5 * 1024**2
    upper_bound = 5 * 1024**3
    part_size = config.part_size * 1024**2

    # clamp user input part sizes
    if part_size < lower_bound:
        part_size = lower_bound
    elif part_size > upper_bound:
        part_size = upper_bound

    # fixed list for now, maybe change to somthing more meaningful
    sizes_mib = [2**x for x in range(3, 13)]
    sizes = [size * 1024**2 for size in sizes_mib]

    # encryption will cause growth of ~ 0.0427%, so assume we might
    # need five more parts for this check
    if file_size / part_size > 9_995:
        for candidate_size in sizes:
            if candidate_size > part_size and file_size / candidate_size <= 9_995:
                part_size = candidate_size
                break
        else:
            raise ValueError(
                "Could not find a valid part size that would allow to upload all file parts"
            )

    if part_size != config.part_size:
        LOGGER.info(
            "Part size was adjusted from %iMiB to %iMiB.",
            config.part_size,
            part_size / 1024**2,
        )

    # need to set this either way as we convert MiB to bytes
    config.part_size = part_size


def check_output_path(output_path: Path):
    """Check if we accidentally try to overwrite an alread existing metadata file"""
    if output_path.exists():
        msg = f"Output file {output_path.resolve()} already exists and cannot be overwritten."
        handle_superficial_error(msg=msg)


async def async_main(input_path: Path, alias: str, config: Config):
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

    (
        unencrypted_checksum,
        encrypted_md5_checksums,
        encrypted_sha256_checksums,
    ) = uploader.encryptor.checksums.get()

    metadata = models.OutputMetadata(
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


def main(input_path, alias: str, config_path: Path):
    """
    Custom script to encrypt data using Crypt4GH and directly uploading it to S3
    objectstorage.
    """

    config = load_config_yaml(config_path, Config)
    asyncio.run(async_main(input_path=input_path, alias=alias, config=config))
