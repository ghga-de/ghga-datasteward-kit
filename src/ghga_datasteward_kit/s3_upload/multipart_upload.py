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
"""Multipart upload context manager dealing with initialization and cleanup."""

import hashlib
from uuid import uuid4

from ghga_datasteward_kit.s3_upload.config import LegacyConfig
from ghga_datasteward_kit.s3_upload.exceptions import (
    ChecksumValidationError,
    ShouldAbortUploadError,
    ShouldDeleteObjectError,
)
from ghga_datasteward_kit.s3_upload.utils import (
    get_bucket_id,
    get_encrypted_file_size_and_num_parts,
    get_object_storage,
)


class MultipartUpload:
    """Context manager to handle init + complete/abort for S3 multipart upload"""

    def __init__(self, *, file_size: int, config: LegacyConfig) -> None:
        self.config = config
        self.storage = get_object_storage(config=self.config)
        self.file_id = str(uuid4())
        self.bucket_id = get_bucket_id(self.config)
        self.part_size = config.part_size
        self.unencrypted_file_size = file_size
        self.encrypted_file_size, self.num_parts = (
            get_encrypted_file_size_and_num_parts(
                unencrypted_file_size=file_size, part_size=config.part_size
            )
        )
        self.upload_id = ""
        self.md5sums: list[str] = []

    async def __aenter__(self):
        """Start multipart upload"""
        self.upload_id = await self.storage.init_multipart_upload(
            bucket_id=self.bucket_id, object_id=self.file_id
        )
        self.md5sums = []
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        """Deal with errors"""
        # error handling while upload is still ongoing
        if isinstance(exc_v, ShouldAbortUploadError):
            await self.storage.abort_multipart_upload(
                upload_id=exc_v.upload_id,
                bucket_id=exc_v.bucket_id,
                object_id=exc_v.object_id,
            )
        # error handling after upload has been completed
        elif isinstance(
            exc_v,
            ShouldDeleteObjectError,
        ):
            await self.storage.delete_object(
                bucket_id=exc_v.bucket_id,
                object_id=exc_v.object_id,
            )
        raise exc_v

    async def check_md5_matches(self):
        """Calculate final object MD5 and check if the remote matches.

        The final object MD5 is equal to the MD5 of all the concatenated
        MD5s from the individual file parts, followed by a dash ("-") and
        the number of file parts.
        """
        concatenated_md5s = b"".join(bytes.fromhex(md5) for md5 in self.md5sums)
        object_md5 = hashlib.md5(concatenated_md5s, usedforsecurity=False).hexdigest()

        num_parts = len(self.md5sums)
        object_md5 += f"-{num_parts}"

        remote_md5 = await self.storage.get_object_etag(
            bucket_id=self.bucket_id, object_id=self.file_id
        )
        remote_md5 = remote_md5.strip('"')

        if object_md5 != remote_md5:
            raise ChecksumValidationError(
                bucket_id=self.bucket_id,
                object_id=self.file_id,
                message=f"Object MD5 {remote_md5} of the uploaded object does not match"
                f" the locally computed one: {object_md5}.",
            )
