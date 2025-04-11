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
"""Test encryption/decryption functionality for file upload."""

import hashlib

import pytest
from ghga_service_commons.utils.temp_files import big_temp_file

from ghga_datasteward_kit.s3_upload.exceptions import ChecksumValidationError
from ghga_datasteward_kit.s3_upload.file_decryption import Decryptor
from ghga_datasteward_kit.s3_upload.file_encryption import Encryptor


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
