# Copyright 2021 - 2024 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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
#
"""Functionality to decrypt Crypt4GH encrypted files on-the-fly for validation purposes."""

import gc
import hashlib
from collections.abc import AsyncGenerator
from functools import partial
from time import time
from typing import Any

import crypt4gh.lib  # type: ignore

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.utils import LOG, get_segments

COLLECTION_LIMIT_MIB = 256 * 1024**2


class Decryptor:
    """Handles on the fly decryption and checksum calculation"""

    class FileChecksumValidationError(RuntimeError):
        """Raised when checksum validation failed and the uploaded file needs removal."""

        def __init__(self, *, current_checksum: str, upload_checksum: str):
            message = (
                "Checksum mismatch for file:\n"
                + f"Upload:\n{current_checksum}\nDownload:\n{upload_checksum}\n"
                + "Uploaded file was deleted due to validation failure."
            )
            self.current_checksum = current_checksum
            self.upload_checksum = upload_checksum
            super().__init__(message)

    class PartChecksumValidationError(RuntimeError):
        """Raised when checksum validation failed and the uploaded file needs removal."""

        def __init__(
            self,
            *,
            part_number: int,
            current_part_checksum: str,
            upload_part_checksum: str,
        ):
            message = (
                f"Checksum mismatch for part no. {part_number}:\n"
                + f"Upload:\n{current_part_checksum}\nDownload:\n{upload_part_checksum}\n"
                + "Uploaded file was deleted due to validation failure."
            )
            self.part_number = part_number
            self.current_part_checksum = current_part_checksum
            self.upload_part_checksum = upload_part_checksum
            super().__init__(message)

    def __init__(
        self,
        *,
        file_secret: bytes,
        num_parts: int,
        part_size: int,
        target_checksums: models.Checksums,
    ) -> None:
        self.file_secret = file_secret
        self.num_parts = num_parts
        self.part_size = part_size
        self.target_checksums = target_checksums

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

    def _validate_current_checksum(self, *, file_part: bytes, part_number: int):
        """Verify checksums match for the given file part."""
        current_part_md5 = hashlib.md5(file_part, usedforsecurity=False).hexdigest()
        current_part_sha256 = hashlib.sha256(file_part).hexdigest()

        upload_part_md5 = self.target_checksums.encrypted_md5[part_number - 1]
        upload_part_sha256 = self.target_checksums.encrypted_sha256[part_number - 1]

        if current_part_md5 != upload_part_md5:
            raise self.PartChecksumValidationError(
                part_number=part_number,
                current_part_checksum=current_part_md5,
                upload_part_checksum=upload_part_md5,
            )
        elif current_part_sha256 != upload_part_sha256:
            raise self.PartChecksumValidationError(
                part_number=part_number,
                current_part_checksum=current_part_sha256,
                upload_part_checksum=upload_part_sha256,
            )

    async def process_parts(self, download_files: partial[AsyncGenerator[bytes, Any]]):
        """Encrypt and upload file parts."""
        unprocessed_bytes = b""
        download_buffer = b""
        unencrypted_sha256 = hashlib.sha256()

        start = time()

        part_number = 1
        collection_tracker_mib = 0
        async for file_part in download_files():
            # process encrypted
            self._validate_current_checksum(
                file_part=file_part, part_number=part_number
            )
            unprocessed_bytes += file_part
            collection_tracker_mib += len(file_part)

            # decrypt in chunks
            decrypted_bytes, unprocessed_bytes = self._decrypt(unprocessed_bytes)
            download_buffer += decrypted_bytes

            unencrypted_sha256.update(download_buffer)
            download_buffer = b""

            delta = time() - start
            avg_speed = (part_number * (self.part_size / 1024**2)) / delta

            LOG.info(
                "(5/7) Downloading part %i/%i (%.2f MiB/s)",
                part_number,
                self.num_parts,
                avg_speed,
            )
            part_number += 1
            if collection_tracker_mib >= COLLECTION_LIMIT_MIB:
                collection_tracker_mib = 0
                gc.collect()

        # process dangling bytes
        if unprocessed_bytes:
            download_buffer += self._decrypt_segment(unprocessed_bytes)

        unencrypted_sha256.update(download_buffer)
        download_buffer = b""

        current_checksum = unencrypted_sha256.hexdigest()
        upload_checksum = self.target_checksums.unencrypted_sha256.hexdigest()
        if current_checksum != upload_checksum:
            raise self.FileChecksumValidationError(
                current_checksum=current_checksum, upload_checksum=upload_checksum
            )
