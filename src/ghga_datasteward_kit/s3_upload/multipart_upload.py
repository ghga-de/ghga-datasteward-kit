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
"""Multipart upload context manager dealing with initialization and cleanup."""

import hashlib
import math
from pathlib import Path
from uuid import uuid4

from ghga_datasteward_kit import models

from .config import LegacyConfig
from .exceptions import (
    ChecksumValidationError,
    MultipartUploadCompletionError,
    ShouldAbortUploadError,
    ShouldDeleteObjectError,
)
from .file_decryption import Decryptor
from .file_encryption import Encryptor
from .uploader import ChunkedUploader
from .utils import (
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
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        """Deal with errors"""
        if exc_v == None:
            return
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

    async def validate_and_transfer_content(
        self, input_path: Path
    ) -> tuple[models.Checksums, bytes]:
        """
        Check and upload encrypted file content.

        This also includes a verification of the upload by calculating and supplying part MD5
        sums and checking the ETag of the uploaded object.
        Additionally the encrypted parts are decrypted locally and the checksum of the initial
        unencrypted and the decrypted file are compared.


        Returns:
            A tuple of the used uploader instance and the file size
        """
        encryptor = Encryptor(self.config.part_size)
        decryptor = Decryptor(file_secret=encryptor.file_secret)
        upload_params = models.UploadParameters(
            bucket_id=self.bucket_id,
            file_id=self.file_id,
            upload_id=self.upload_id,
            num_parts=self.num_parts,
        )

        uploader = ChunkedUploader(
            input_path=input_path,
            config=self.config,
            encryptor=encryptor,
            decryptor=decryptor,
            storage=self.storage,
            upload_params=upload_params,
        )
        self.md5sums = await uploader.encrypt_and_upload()
        try:
            await self.storage.complete_multipart_upload(
                upload_id=self.upload_id,
                bucket_id=self.bucket_id,
                object_id=self.file_id,
                anticipated_part_quantity=math.ceil(
                    self.encrypted_file_size / self.part_size
                ),
                anticipated_part_size=self.part_size,
            )
        except BaseException as exc:
            raise MultipartUploadCompletionError(
                cause=str(exc),
                bucket_id=self.bucket_id,
                object_id=self.file_id,
                upload_id=self.upload_id,
            ) from exc

        # Sanity checks
        if self.encrypted_file_size != uploader.encryptor.encrypted_file_size:
            raise ValueError(
                "Mismatch between actual and theoretical encrypted part size:\n"
                + f"Is: {uploader.encryptor.encrypted_file_size}\n"
                + f"Should be: {self.encrypted_file_size}"
            )
        # check local checksums of the unencrypted content
        uploader.decryptor.complete_processing(
            bucket_id=self.bucket_id,
            object_id=self.file_id,
            encryption_file_sha256=uploader.encryptor.checksums.unencrypted_sha256.hexdigest(),
        )
        # check remote md5 matches locally calculated one
        await self.check_md5_matches()

        return uploader.encryptor.checksums, uploader.encryptor.file_secret

    async def check_md5_matches(self):
        """Calculate final object MD5 and check if the remote matches.

        The final object MD5 is equal to the MD5 of all the concatenated
        MD5s from the individual file parts, followed by a dash ("-") and
        the number of file parts.
        """
        # concatenation needs the raw bytes, convert from hexdigest
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
