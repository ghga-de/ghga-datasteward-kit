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
"""Functionality to upload encrypted file chunks using multipart upload."""

import asyncio
import base64
import hashlib
from collections.abc import Coroutine, Generator
from pathlib import Path
from time import time
from typing import Any

import httpx
from hexkit.providers.s3 import S3ObjectStorage
from httpx import Response

from ghga_datasteward_kit.models import UploadParameters

from .config import LegacyConfig
from .exceptions import PartUploadError
from .file_decryption import Decryptor
from .file_encryption import Encryptor
from .http_client import configure_retries, httpx_client
from .utils import LOG


class UploadTaskHandler:
    """Wraps task scheduling details."""

    def __init__(self):
        self._tasks: set[asyncio.Task] = set()

    def schedule(self, fn: Coroutine[Any, Any, None]):
        """Create a task and register its callback."""
        task = asyncio.create_task(fn)
        self._tasks.add(task)

    async def gather(self):
        """Await all running tasks"""
        # Changed back to how it was before, as gather should take care of cancelling
        # all remaining tasks and correctly propagate the first error encounterd upwards.
        # The infinite loop when all tasks fail happened due to mistakenly converting
        # CancelledError into a PartUploadError inside the task.
        await asyncio.gather(*self._tasks)


class ChunkedUploader:
    """Handler class dealing with upload functionality"""

    def __init__(  # noqa: PLR0913
        self,
        *,
        input_path: Path,
        config: LegacyConfig,
        encryptor: Encryptor,
        decryptor: Decryptor,
        storage: S3ObjectStorage,
        upload_params: UploadParameters,
    ) -> None:
        self.config = config
        self.input_path = input_path
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.storage = storage
        self.upload_params = upload_params
        self.retry_handler = configure_retries(config)
        self._in_sequence_part_number = 1
        self._semaphore = asyncio.Semaphore(config.client_max_parallel_transfers)

    async def encrypt_and_upload(self) -> list[str]:
        """Delegate encryption and perform multipart upload

        Returns MD5 checksums of the encrypted parts.
        """
        with open(self.input_path, "rb") as file:
            async with httpx_client() as client:
                LOG.info(
                    "(1/4) Initialized file upload for %s.", self.upload_params.file_id
                )

                start = time()
                file_processor = self.encryptor.process_file(file=file)
                task_handler = UploadTaskHandler()
                for _ in range(self.upload_params.num_parts):
                    task_handler.schedule(
                        self.send_part(
                            client=client,
                            file_processor=file_processor,
                            start=start,
                        )
                    )
                # Wait for all upload tasks to finish
                await task_handler.gather()

        LOG.info("(3/4) Finished upload for %s.", self.upload_params.file_id)
        # return md5 sums for content MD5 comparison of the assembled object
        return self.encryptor.checksums.encrypted_md5

    async def send_part(
        self,
        *,
        client: httpx.AsyncClient,
        file_processor: Generator[tuple[int, bytes], Any, None],
        start: float,
    ):
        """Handle upload of one file part"""
        async with self._semaphore:
            part_number = 0  # defined here so it can be used in the exception
            try:
                part_number, part = next(file_processor)
                self.decryptor.decrypt_part(part)
                response = await self._prepare_and_send_request(
                    client=client,
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
                    self.upload_params.num_parts,
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
                    bucket_id=self.upload_params.bucket_id,
                    object_id=self.upload_params.file_id,
                    part_number=part_number,
                    upload_id=self.upload_params.upload_id,
                ) from exc

    async def _prepare_and_send_request(
        self,
        *,
        client: httpx.AsyncClient,
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
        upload_url = await self.storage.get_part_upload_url(
            upload_id=self.upload_params.upload_id,
            bucket_id=self.upload_params.bucket_id,
            object_id=self.upload_params.file_id,
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
