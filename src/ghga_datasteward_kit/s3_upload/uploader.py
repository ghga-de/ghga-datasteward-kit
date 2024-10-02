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
import math
from collections.abc import Coroutine, Generator
from pathlib import Path
from time import time
from typing import Any
from uuid import uuid4

import crypt4gh.lib  # type: ignore
import httpx
from httpx import Response

from ghga_datasteward_kit.s3_upload.config import LegacyConfig
from ghga_datasteward_kit.s3_upload.file_encryption import Encryptor
from ghga_datasteward_kit.s3_upload.utils import (
    LOG,
    StorageCleaner,
    configure_retries,
    get_bucket_id,
    get_object_storage,
    httpx_client,
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
        await asyncio.gather(*self._tasks)


class ChunkedUploader:
    """Handler class dealing with upload functionality"""

    def __init__(
        self,
        input_path: Path,
        alias: str,
        config: LegacyConfig,
        unencrypted_file_size: int,
        storage_cleaner: StorageCleaner,
    ) -> None:
        self.alias = alias
        self.config = config
        self.input_path = input_path
        self.encryptor = Encryptor(self.config.part_size)
        self.file_id = str(uuid4())
        self.unencrypted_file_size = unencrypted_file_size
        self.encrypted_file_size = 0
        self._storage_cleaner = storage_cleaner

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
                    storage_cleaner=self._storage_cleaner,
                ) as upload,
                httpx_client() as client,
            ):
                LOG.info("(1/7) Initialized file upload for %s.", upload.file_id)
                task_handler = UploadTaskHandler()

                start = time()
                file_processor = self.encryptor.process_file(file=file)
                for _ in range(num_parts):
                    await task_handler.schedule(
                        upload.send_part(
                            client=client,
                            file_processor=file_processor,
                            num_parts=num_parts,
                            start=start,
                        )
                    )
                # Wait for all upload tasks to finish
                await task_handler.gather()
                if encrypted_file_size != self.encryptor.encrypted_file_size:
                    raise ValueError(
                        "Mismatch between actual and theoretical encrypted part size:\n"
                        + f"Is: {self.encryptor.encrypted_file_size}\n"
                        + f"Should be: {encrypted_file_size}"
                    )
                LOG.info("(3/7) Finished upload for %s.", upload.file_id)


class MultipartUpload:
    """Context manager to handle init + complete/abort for S3 multipart upload"""

    def __init__(
        self,
        config: LegacyConfig,
        file_id: str,
        encrypted_file_size: int,
        part_size: int,
        storage_cleaner: StorageCleaner,
    ) -> None:
        self.config = config
        self.storage = get_object_storage(config=self.config)
        self.file_id = file_id
        self.file_size = encrypted_file_size
        self.part_size = part_size
        self.upload_id = ""
        self.storage_cleaner = storage_cleaner
        self.retry_handler = configure_retries(config)
        self._semaphore = asyncio.Semaphore(config.client_max_parallel_transfers)
        self._in_sequence_part_number = 1

    async def __aenter__(self):
        """Start multipart upload"""
        self.upload_id = await self.storage.init_multipart_upload(
            bucket_id=get_bucket_id(self.config), object_id=self.file_id
        )
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        """Complete or clean up multipart upload"""
        try:
            await self.storage.complete_multipart_upload(
                upload_id=self.upload_id,
                bucket_id=get_bucket_id(self.config),
                object_id=self.file_id,
                anticipated_part_quantity=math.ceil(self.file_size / self.part_size),
                anticipated_part_size=self.part_size,
            )
        except BaseException as exc:
            raise self.storage_cleaner.MultipartUploadCompletionError(
                cause=str(exc),
                bucket_id=get_bucket_id(self.config),
                object_id=self.file_id,
                upload_id=self.upload_id,
            ) from exc

    async def send_part(
        self,
        *,
        client: httpx.AsyncClient,
        file_processor: Generator[tuple[int, bytes], Any, None],
        num_parts: int,
        start: float,
    ):
        """Handle upload of one file part"""
        async with self._semaphore:
            part_number, part = next(file_processor)
            try:
                upload_url = await self.storage.get_part_upload_url(
                    upload_id=self.upload_id,
                    bucket_id=get_bucket_id(self.config),
                    object_id=self.file_id,
                    part_number=part_number,
                )
                response: Response = await self.retry_handler(
                    fn=client.put, url=upload_url, content=part
                )

                # mask the actual current file part number and display an in sequence number instead
                delta = time() - start
                avg_speed = (
                    self._in_sequence_part_number
                    * (self.config.part_size / 1024**2)
                    / delta
                )
                LOG.info(
                    "(2/7) Processing upload for file part %i/%i (%.2f MiB/s)",
                    self._in_sequence_part_number,
                    num_parts,
                    avg_speed,
                )
                self._in_sequence_part_number += 1

                status_code = response.status_code
                if status_code != 200:
                    raise ValueError(f"Received unexpected status code {
                        status_code} when trying to upload file part {part_number}.")

            except BaseException as exc:
                raise self.storage_cleaner.PartUploadError(
                    cause=str(exc),
                    bucket_id=get_bucket_id(self.config),
                    object_id=self.file_id,
                    part_number=part_number,
                    upload_id=self.upload_id,
                ) from exc
