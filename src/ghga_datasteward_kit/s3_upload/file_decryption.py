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
#
"""Functionality to decrypt Crypt4GH encrypted files on-the-fly for validation purposes."""

from collections.abc import Generator
from functools import partial
from time import time

import crypt4gh.lib  # type: ignore

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.utils import LOGGER, get_segments


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
