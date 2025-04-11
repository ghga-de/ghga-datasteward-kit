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
"""Common exception classes"""


class ShouldAbortUploadError(RuntimeError):
    """Base exception class for errors that are raised before a multipart upload is finished.

    All errors derived from this one result in the ongoing upload being cancelled.
    """

    def __init__(self, *, bucket_id: str, object_id: str, upload_id: str, message: str):
        self.bucket_id = bucket_id
        self.object_id = object_id
        self.upload_id = upload_id
        super().__init__(message)


class ShouldDeleteObjectError(RuntimeError):
    """Base exception class for errors that are raised after a multipart upload is finished.

    All errors derived from this one result in the uploaded object being deleted.
    """

    def __init__(self, *, bucket_id: str, object_id: str, message: str):
        self.bucket_id = bucket_id
        self.object_id = object_id
        super().__init__(message)


class ChecksumValidationError(ShouldDeleteObjectError):
    """Raised when checksum validation failed and the uploaded file needs removal."""

    def __init__(self, *, bucket_id: str, object_id: str, message: str):
        self.bucket_id = bucket_id
        self.object_id = object_id
        super().__init__(bucket_id=bucket_id, object_id=object_id, message=message)


class MultipartUploadCompletionError(ShouldAbortUploadError):
    """Raised when upload completion failed and the ongoing upload needs to be aborted."""

    def __init__(
        self, *, cause: str, bucket_id: str, object_id: str, upload_id: str
    ) -> None:
        self.bucket_id = bucket_id
        self.object_id = object_id
        self.upload_id = upload_id
        message = (
            f"Failed completing file upload for ''{object_id}'' due to:\n {cause}."
        )
        super().__init__(
            bucket_id=bucket_id,
            object_id=object_id,
            upload_id=upload_id,
            message=message,
        )


class PartUploadError(ShouldAbortUploadError):
    """Raised when uploading a file part failed and the ongoing upload needs to be aborted."""

    def __init__(
        self,
        *,
        cause: str,
        bucket_id: str,
        object_id: str,
        part_number: int,
        upload_id: str,
    ) -> None:
        self.bucket_id = bucket_id
        self.object_id = object_id
        self.part_number = part_number
        self.upload_id = upload_id
        message = f"Failed uploading file part {part_number} for ''{object_id}'' due to:\n {cause}."
        super().__init__(
            bucket_id=bucket_id,
            object_id=object_id,
            upload_id=upload_id,
            message=message,
        )


class SecretExchangeError(ShouldDeleteObjectError):
    """Raised when secret exchange failed and the uploaded file needs removal."""

    def __init__(self, *, bucket_id: str, object_id: str, message: str):
        self.bucket_id = bucket_id
        self.object_id = object_id
        super().__init__(bucket_id=bucket_id, object_id=object_id, message=message)


class WritingOutputError(ShouldDeleteObjectError):
    """Raised when output metadata could not be written and the uploaded file needs removal."""

    def __init__(self, *, bucket_id: str, object_id: str):
        self.bucket_id = bucket_id
        self.object_id = object_id
        message = f"Failed writing output file for ''{object_id}''."
        super().__init__(bucket_id=bucket_id, object_id=object_id, message=message)
