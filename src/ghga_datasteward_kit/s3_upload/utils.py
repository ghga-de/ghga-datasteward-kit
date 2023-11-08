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
"""Helper functions used across different modules in the s3_upload package."""

import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from io import BufferedReader
from pathlib import Path

import httpx
from hexkit.providers.s3 import S3Config, S3ObjectStorage  # type: ignore

from ghga_datasteward_kit.s3_upload.config import LegacyConfig

LOGGER = logging.getLogger("s3_upload")
PART_SIZE = 16 * 1024**2


class HttpxClientState:
    """Helper class to make max_retries user configurable"""

    max_retries: int

    @classmethod
    def configure(cls, max_retries: int):
        """Configure client with exponential backoff retry (using httpx's 0.5 default)"""
        # can't be negative - should we log this?
        cls.max_retries = max(0, max_retries)


@contextmanager
def httpx_client():
    """Yields a context manager httpx client and closes it afterward"""
    transport = httpx.HTTPTransport(retries=HttpxClientState.max_retries)

    with httpx.Client(transport=transport) as client:
        yield client


def read_file_parts(
    file: BufferedReader, *, part_size: int, from_part: int = 1
) -> Iterator[bytes]:
    """
    Returns an iterator to iterate through file parts of the given size (in bytes).

    By default it start with the first part but you may also start from a specific part
    in the middle of the file using the `from_part` argument. This might be useful to
    resume an interrupted reading process.

    Please note: opening and closing of the file MUST happen outside of this function.
    """
    initial_offset = part_size * (from_part - 1)
    file.seek(initial_offset)

    while True:
        file_part = file.read(part_size)

        if len(file_part) == 0:
            return

        yield file_part


def get_object_storage(config: LegacyConfig):
    """Configure S3 and return S3 DAO"""
    s3_config = S3Config(
        s3_endpoint_url=config.s3_endpoint_url.get_secret_value(),
        s3_access_key_id=config.s3_access_key_id.get_secret_value(),
        s3_secret_access_key=config.s3_secret_access_key.get_secret_value(),
    )
    return S3ObjectStorage(config=s3_config)


def get_segments(part: bytes, segment_size: int):
    """Chunk part into cipher segments"""
    full_segments = len(part) // segment_size
    segments = [
        part[i * segment_size : (i + 1) * segment_size] for i in range(full_segments)
    ]
    # get potential remainder of bytes that we need to handle
    # for non-matching boundaries between part and cipher segment size
    incomplete_segment = part[full_segments * segment_size :]
    return segments, incomplete_segment


def get_ranges(file_size: int, part_size: int):
    """Calculate part ranges"""
    num_parts = file_size // part_size
    byte_ranges = [
        (part_size * part_no, part_size * (part_no + 1) - 1)
        for part_no in range(num_parts)
    ]
    if part_size * num_parts != file_size:
        byte_ranges.append((part_size * num_parts, file_size - 1))
    return byte_ranges


def handle_superficial_error(msg: str):
    """Don't want user dealing with stacktrace on simple input/output issues, log instead"""
    LOGGER.critical(msg)
    sys.exit(-1)


def check_adjust_part_size(config: LegacyConfig, file_size: int):
    """
    Convert specified part size from MiB to bytes, check if it needs adjustment and
    adjust accordingly
    """
    lower_bound = 5 * 1024**2
    upper_bound = 5 * 1024**3
    part_size = config.part_size * 1024**2

    # clamp user input part sizes
    if part_size < lower_bound:
        part_size = lower_bound
    elif part_size > upper_bound:
        part_size = upper_bound

    # fixed list for now, maybe change to something more meaningful
    sizes_mib = [2**x for x in range(3, 13)]
    sizes = [size * 1024**2 for size in sizes_mib]

    # encryption will cause growth of ~ 0.0427%, so assume we might
    # need five more parts for this check
    if file_size / part_size > 9_995:
        for candidate_size in sizes:
            if candidate_size > part_size and file_size / candidate_size <= 9_995:
                part_size = candidate_size
                break
        else:
            raise ValueError(
                "Could not find a valid part size that would allow to upload all file parts"
            )

    if part_size != config.part_size * 1024**2:
        LOGGER.info(
            "Part size was adjusted from %iMiB to %iMiB.",
            config.part_size,
            part_size / 1024**2,
        )

    # need to set this either way as we convert MiB to bytes
    config.part_size = part_size


def check_output_path(output_path: Path):
    """Check if we accidentally try to overwrite an already existing metadata file"""
    if output_path.exists():
        msg = f"Output file {output_path.resolve()} already exists and cannot be overwritten."
        handle_superficial_error(msg=msg)


class StorageCleaner:
    """Async context manager to wrap full upload path and clean storage up if any
    exceptions were encountered along the way
    """

    class ChecksumValidationError(RuntimeError):
        """Raised when checksum validation failed and the uploaded file needs removal."""

        def __init__(self, *, bucket_id: str, object_id: str, message: str):
            self.bucket_id = bucket_id
            self.object_id = object_id
            super().__init__(message)

    class MultipartUploadCompletionError(RuntimeError):
        """Raised when upload completion failed and the ongoing upload needs to be aborted."""

        def __init__(self, *, bucket_id: str, object_id: str, upload_id: str) -> None:
            self.bucket_id = bucket_id
            self.object_id = object_id
            self.upload_id = upload_id
            message = f"Failed completing file upload for ''{object_id}''."
            super().__init__(message)

    class PartDownloadError(RuntimeError):
        """Raised when downloading a file part failed and the uploaded file needs removal."""

        def __init__(self, *, bucket_id: str, object_id: str):
            self.bucket_id = bucket_id
            self.object_id = object_id
            message = f"Failed downloading file part for ''{object_id}''."
            super().__init__(message)

    class PartUploadError(RuntimeError):
        """Raised when uploading a file part failed and the ongoing upload needs to be aborted."""

        def __init__(self, *, bucket_id: str, object_id: str, upload_id: str) -> None:
            self.bucket_id = bucket_id
            self.object_id = object_id
            self.upload_id = upload_id
            message = f"Failed uploading file part for ''{object_id}''."
            super().__init__(message)

    class SecretExchangeError(RuntimeError):
        """Raised when secret exchange failed and the uploaded file needs removal."""

        def __init__(self, *, bucket_id: str, object_id: str, message: str):
            self.bucket_id = bucket_id
            self.object_id = object_id
            super().__init__(message)

    class WritingOutputError(RuntimeError):
        """Raised when output metadata could not be written and the uploaded file needs removal."""

        def __init__(self, *, bucket_id: str, object_id: str):
            self.bucket_id = bucket_id
            self.object_id = object_id
            message = f"Failed writing output file for ''{object_id}''."
            super().__init__(message)

    def __init__(self, *, config: LegacyConfig) -> None:
        self.storage = get_object_storage(config=config)

    async def __aenter__(self):
        """The context manager enter function."""
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        """The context manager exit function."""
        # error handling while upload is still ongoing
        if isinstance(
            exc_v, (self.MultipartUploadCompletionError, self.PartUploadError)
        ):
            await self.storage.abort_multipart_upload(
                upload_id=exc_v.upload_id,
                bucket_id=exc_v.bucket_id,
                object_id=exc_v.object_id,
            )
            raise exc_v
        # error handling after upload has been completed
        if isinstance(
            exc_v,
            (
                self.ChecksumValidationError,
                self.PartDownloadError,
                self.SecretExchangeError,
                self.WritingOutputError,
            ),
        ):
            await self.storage.delete_object(
                bucket_id=exc_v.bucket_id,
                object_id=exc_v.object_id,
            )
            raise exc_v
        # simply reraise unhandled exceptions with unknown upload status
        if exc_v is not None:
            raise exc_v
