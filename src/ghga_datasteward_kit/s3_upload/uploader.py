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
"""Functionality to upload encrypted file chunks using multipart upload."""

import asyncio
import base64
import hashlib
import math
from collections.abc import Coroutine, Generator
from pathlib import Path
from time import time
from typing import Any
from uuid import uuid4

import crypt4gh.lib  # type: ignore
import httpx
from hexkit.providers.s3 import S3ObjectStorage
from httpx import Response

from ghga_datasteward_kit.s3_upload.config import LegacyConfig
from ghga_datasteward_kit.s3_upload.file_decryption import Decryptor
from ghga_datasteward_kit.s3_upload.file_encryption import Encryptor
from ghga_datasteward_kit.s3_upload.utils import (
    LOG,
    ChecksumValidationError,
    MultipartUploadCompletionError,
    PartUploadError,
    configure_retries,
    get_bucket_id,
    get_object_storage,
    httpx_client,
)


class MultipartUpload:
    """Context manager to handle init + complete/abort for S3 multipart upload"""

    def __init__(
        self,
        config: LegacyConfig,
        file_id: str,
        encrypted_file_size: int,
        part_size: int,
    ) -> None:
        self.config = config
        self.storage = get_object_storage(config=self.config)
        self.file_id = file_id
        self.bucket_id = get_bucket_id(self.config)
        self.file_size = encrypted_file_size
        self.part_size = part_size
        self.upload_id = ""
        self.md5sums: list[str]

    async def __aenter__(self):
        """Start multipart upload"""
        self.upload_id = await self.storage.init_multipart_upload(
            bucket_id=self.bucket_id, object_id=self.file_id
        )
        self.md5sums = []
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        """Complete or clean up multipart upload"""
        try:
            await self.storage.complete_multipart_upload(
                upload_id=self.upload_id,
                bucket_id=self.bucket_id,
                object_id=self.file_id,
                anticipated_part_quantity=math.ceil(self.file_size / self.part_size),
                anticipated_part_size=self.part_size,
            )
        except BaseException as exc:
            raise MultipartUploadCompletionError(
                cause=str(exc),
                bucket_id=self.bucket_id,
                object_id=self.file_id,
                upload_id=self.upload_id,
            ) from exc
        else:
            await self._check_md5_matches()

    async def _check_md5_matches(self):
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


class UploadTaskHandler:
    """Wraps task scheduling details."""

    def __init__(self):
        self._tasks: set[asyncio.Task] = set()

    async def schedule(self, fn: Coroutine[Any, Any, None]):
        """Create a task and register its callback."""
        task = asyncio.create_task(fn)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def gather(self):
        """Await all running tasks"""
        # Changed back to how it was before, as gather should take care of cancelling
        # all remaining tasks and correctly propagate the first error encounterd upwards.
        # The infinite loop when all tasks fail happened due to mistakenly converting
        # CancelledError into a PartUploadError previously.
        await asyncio.gather(*self._tasks)


class ChunkedUploader:
    """Handler class dealing with upload functionality"""

    def __init__(  # noqa: PLR0913
        self,
        *,
        input_path: Path,
        alias: str,
        config: LegacyConfig,
        unencrypted_file_size: int,
        encryptor: Encryptor,
        decryptor: Decryptor,
    ) -> None:
        self.alias = alias
        self.config = config
        self.input_path = input_path
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.file_id = str(uuid4())
        self.bucket_id = get_bucket_id(config)
        self.unencrypted_file_size = unencrypted_file_size
        self.encrypted_file_size = 0
        self.retry_handler = configure_retries(config)
        self._in_sequence_part_number = 1
        self._semaphore = asyncio.Semaphore(config.client_max_parallel_transfers)

    async def encrypt_and_upload(self):
        """Delegate encryption and perform multipart upload"""
        # compute encrypted_file_size
        num_segments = math.ceil(self.unencrypted_file_size / crypt4gh.lib.SEGMENT_SIZE)
        encrypted_file_size = self.unencrypted_file_size + num_segments * 28
        num_parts = math.ceil(encrypted_file_size / self.config.part_size)

        with open(self.input_path, "rb") as file:
            async with (
                MultipartUpload(
                    config=self.config,
                    file_id=self.file_id,
                    encrypted_file_size=encrypted_file_size,
                    part_size=self.config.part_size,
                ) as upload,
                httpx_client() as client,
            ):
                LOG.info("(1/4) Initialized file upload for %s.", upload.file_id)
                task_handler = UploadTaskHandler()

                start = time()
                file_processor = self.encryptor.process_file(file=file)
                for _ in range(num_parts):
                    await task_handler.schedule(
                        self.send_part(
                            client=client,
                            file_processor=file_processor,
                            num_parts=num_parts,
                            start=start,
                            upload=upload,
                        )
                    )
                # Wait for all upload tasks to finish
                await task_handler.gather()
                # assign md5 sums for content MD5 comparison of the assembled object
                upload.md5sums = self.encryptor.checksums.encrypted_md5
                if encrypted_file_size != self.encryptor.encrypted_file_size:
                    raise ValueError(
                        "Mismatch between actual and theoretical encrypted part size:\n"
                        + f"Is: {self.encryptor.encrypted_file_size}\n"
                        + f"Should be: {encrypted_file_size}"
                    )
                # Confirm local checksum to verify encryption/decryption works correctly
                self.decryptor.complete_processing(
                    self.encryptor.checksums.unencrypted_sha256.hexdigest()
                )
                LOG.info("(3/4) Finished upload for %s.", upload.file_id)

    async def send_part(
        self,
        *,
        client: httpx.AsyncClient,
        file_processor: Generator[tuple[int, bytes], Any, None],
        num_parts: int,
        start: float,
        upload: MultipartUpload,
    ):
        """Handle upload of one file part"""
        async with self._semaphore:
            try:
                part_number, part = next(file_processor)
                self.decryptor.decrypt_part(part)
                response = await self._prepare_and_send_request(
                    client=client,
                    storage=upload.storage,
                    upload_id=upload.upload_id,
                    part=part,
                    part_number=part_number,
                )
                # mask the actual current file part number and display an in sequence number instead
                delta = time() - start
                avg_speed = (
                    self._in_sequence_part_number
                    * (self.config.part_size / 1024**2)
                    / delta
                )
                LOG.info(
                    "(2/4) Processing upload for file part %i/%i (%.2f MiB/s)",
                    self._in_sequence_part_number,
                    num_parts,
                    avg_speed,
                )
                self._in_sequence_part_number += 1
                status_code = response.status_code
                if status_code != 200:
                    if status_code == 400:
                        raise ValueError(
                            f"Could not validate uploaded part {part_number}: Mismatched MD5 checksum."
                        )
                    raise ValueError(
                        f"Received unexpected status code {status_code} when trying to upload file part {part_number}."
                    )

            except BaseException as exc:
                # correctly reraise CancelledError, else this might get stuck waiting
                # on semaphore lock release
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise PartUploadError(
                    cause=str(exc),
                    bucket_id=self.bucket_id,
                    object_id=self.file_id,
                    part_number=part_number,
                    upload_id=upload.upload_id,
                ) from exc

    async def _prepare_and_send_request(
        self,
        *,
        client: httpx.AsyncClient,
        storage: S3ObjectStorage,
        upload_id: str,
        part: bytes,
        part_number: int,
    ) -> Response:
        """Calculate part MD5, get upload URL and send upload request.

        Exceptions arising during MD5 calculation, encoding or API calls need to be
        handled by the caller.
        """
        # calculate the hash again here.
        # Naively fetching from the encryptor is prone to errors
        part_md5 = hashlib.md5(part, usedforsecurity=False).digest()
        encoded_part_md5 = base64.b64encode(part_md5).decode("utf-8")
        upload_url = await storage.get_part_upload_url(
            upload_id=upload_id,
            bucket_id=self.bucket_id,
            object_id=self.file_id,
            part_number=part_number,
            part_md5=encoded_part_md5,
        )
        response: Response = await self.retry_handler(
            fn=client.put,
            url=upload_url,
            content=part,
            headers=httpx.Headers({"Content-MD5": encoded_part_md5}),
        )
        return response
