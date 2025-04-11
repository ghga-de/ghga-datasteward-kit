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
#
"""Functionality to decrypt Crypt4GH encrypted files on-the-fly for validation purposes."""

import hashlib

import crypt4gh.lib  # type: ignore

from ghga_datasteward_kit.s3_upload.exceptions import ChecksumValidationError
from ghga_datasteward_kit.s3_upload.utils import get_segments


class Decryptor:
    """Handles on the fly decryption and checksum calculation"""

    def __init__(self, file_secret: bytes) -> None:
        self.file_secret = file_secret
        self.unencrypted_sha256 = hashlib.sha256()
        self.unprocessed_bytes = b""

    def decrypt_part(self, part: bytes):
        """Decrypt file part"""
        part_to_decrypt = self.unprocessed_bytes + part
        segments, self.unprocessed_bytes = get_segments(
            part=part_to_decrypt, segment_size=crypt4gh.lib.CIPHER_SEGMENT_SIZE
        )
        decrypted_segments = [self._decrypt_segment(segment) for segment in segments]
        self.unencrypted_sha256.update(b"".join(decrypted_segments))

    def _decrypt_segment(self, segment: bytes):
        """Decrypt single ciphersegment"""
        return crypt4gh.lib.decrypt_block(
            ciphersegment=segment, session_keys=[self.file_secret]
        )

    def complete_processing(
        self, *, bucket_id: str, object_id: str, encryption_file_sha256: str
    ):
        """Consume remaining bytes and compare checksums"""
        # process dangling bytes
        if self.unprocessed_bytes:
            last_segment = self._decrypt_segment(self.unprocessed_bytes)
            self.unencrypted_sha256.update(last_segment)

        decryption_file_sha256 = self.unencrypted_sha256.hexdigest()
        if decryption_file_sha256 != encryption_file_sha256:
            raise ChecksumValidationError(
                bucket_id=bucket_id,
                object_id=object_id,
                message=(
                    f"Checksum mismatch for file:\nDecryption:\n{decryption_file_sha256}\n"
                    + f"Encryption:\n{encryption_file_sha256}\n"
                    + "Uploaded file was deleted due to validation failure."
                ),
            )
