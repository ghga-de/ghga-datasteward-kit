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

import hashlib

import crypt4gh.lib  # type: ignore

from ghga_datasteward_kit.s3_upload.utils import get_segments


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

    def __init__(self, file_secret: bytes) -> None:
        self.file_secret = file_secret
        self.unencrypted_sha256 = hashlib.sha256()
        self.unprocessed_bytes = b""
        self.download_buffer = b""

    def _decrypt(self, part: bytes) -> tuple[bytes, bytes]:
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

    def process_part(self, file_part: bytes):
        """Decrypt current file part and compute checksum"""
        self.unprocessed_bytes += file_part

        # decrypt in chunks
        decrypted_bytes, self.unprocessed_bytes = self._decrypt(self.unprocessed_bytes)
        self.unencrypted_sha256.update(decrypted_bytes)

        self.unencrypted_sha256.update(self.download_buffer)
        self.download_buffer = b""

    def complete_processing(self, target_unencrypted_sha256: str):
        """Consume remaining bytes and compare checksums"""
        # process dangling bytes
        if self.unprocessed_bytes:
            last_segment = self._decrypt_segment(self.unprocessed_bytes)
            self.unencrypted_sha256.update(last_segment)

        current_checksum = self.unencrypted_sha256.hexdigest()
        if current_checksum != target_unencrypted_sha256:
            raise self.FileChecksumValidationError(
                current_checksum=current_checksum,
                upload_checksum=target_unencrypted_sha256,
            )
