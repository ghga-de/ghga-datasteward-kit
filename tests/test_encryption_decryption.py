# Copyright 2021 - 2026 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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
"""Test encryption/decryption functionality for file upload."""

import hashlib
from io import BytesIO

import crypt4gh.lib
import pytest
from ghga_service_commons.utils.temp_files import big_temp_file

from ghga_datasteward_kit.s3_upload.exceptions import ChecksumValidationError
from ghga_datasteward_kit.s3_upload.file_decryption import Decryptor
from ghga_datasteward_kit.s3_upload.file_encryption import Encryptor


def test_process_file_yields_sequential_part_numbers():
    """Regression test: process_file must yield sequential S3 part numbers (1, 2, 3, …).

    The bug: process_file used the plaintext-file-chunk index (from enumerate) as the
    S3 PartNumber.  When a trailing chunk is too small to push the upload buffer past
    part_size, that iteration's index is consumed without a yield.  The post-loop then
    does `part_number += 1` from that stale index, skipping a number, which causes S3
    to receive a part with a PartNumber higher than the total number of parts uploaded,
    ultimately causing multipart-upload validation to fail or, worse, silently assemble
    a corrupt object.

    How to reproduce:
    - part_size = 2 * ENCRYPTED_SEGMENT_SIZE (131 128 bytes)
    - file size  = part_size + 1            (131 129 bytes)

    Trace through the original code:
      Read 1 (131 128 bytes): 2 complete crypt4gh segments → 131 128 encrypted bytes
        → upload_buffer == part_size → yield (part_number=1, …) ✓
        → leftover buffer = 0 B, unprocessed remainder = 56 B
      Read 2 (1 byte): combined with 56 B remainder = 57 B < SEGMENT_SIZE
        → 0 complete segments → 0 encrypted bytes → buffer stays at 0
        → 0 < part_size → NO yield  (but part_number advances to 2!)
      Post-loop: encrypt the 57-B incomplete segment → 85 B
        → part_number += 1 → part_number = 3 → yield (3, 85 B)  ← BUG

    After the fix (sequential s3_part_number counter):
      Same reads, but the post-loop yields (s3_part_number=2, 85 B)  ← CORRECT
    """
    encrypted_segment_size = crypt4gh.lib.SEGMENT_SIZE + 28  # 65 564 bytes

    # part_size = exactly 2 encrypted segments so that the first read fills the buffer
    # to precisely part_size, and the one extra byte forces a second (partial) read.
    part_size = 2 * encrypted_segment_size  # 131 128 bytes
    file_size = part_size + 1  # 131 129 bytes

    encryptor = Encryptor(part_size=part_size)
    with BytesIO(b"x" * file_size) as file:
        yielded_part_numbers = [pn for pn, _ in encryptor.process_file(file)]  # type: ignore

    expected = list(range(1, len(yielded_part_numbers) + 1))
    assert yielded_part_numbers == expected, (
        f"process_file yielded non-sequential S3 part numbers {yielded_part_numbers} "
        f"(expected {expected}). Gaps in PartNumbers cause multipart-upload failures "
        "or silent data corruption."
    )


def test_encryption_decryption():
    """Test file encryption and decryption work as expected."""
    encryptor = Encryptor(part_size=8 * 1024**2)
    file_secret = encryptor.file_secret
    decryptor = Decryptor(file_secret)

    with big_temp_file(50 * 1024**2) as input_file:
        for _, part in encryptor.process_file(input_file):  # type: ignore
            decryptor.decrypt_part(part)

    bucket_id = "test"
    object_id = "test"
    # check positive case
    decryptor.complete_processing(
        bucket_id=bucket_id,
        object_id=object_id,
        encryption_file_sha256=encryptor.checksums.unencrypted_sha256.hexdigest(),
    )
    # check error is raised
    with pytest.raises(ChecksumValidationError):
        decryptor.complete_processing(
            bucket_id=bucket_id,
            object_id=object_id,
            encryption_file_sha256=hashlib.sha256(b"random").hexdigest(),
        )
