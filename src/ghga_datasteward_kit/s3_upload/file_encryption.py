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
"""Functionality to encrypt files in chunks with Crypt4GH before upload."""

import os
from io import BufferedReader

import crypt4gh.lib  # type: ignore
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_encrypt

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.utils import get_segments, read_file_parts


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

    def _encrypt_segment(self, segment: bytes):
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
