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
"""Functionality related to downloading uploaded files for validation purposes."""

import math
from asyncio import PriorityQueue, Semaphore, Task, create_task
from collections.abc import Coroutine
from typing import Any

import httpx
from httpx import Response

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.config import LegacyConfig
from ghga_datasteward_kit.s3_upload.file_decryption import Decryptor
from ghga_datasteward_kit.s3_upload.utils import (
    LOG,
    StorageCleaner,
    configure_retries,
    get_bucket_id,
    get_object_storage,
    get_ranges,
    httpx_client,
)


class DownloadTaskHandler:
    """Wraps task scheduling details."""

    def __init__(self):
        self._tasks: set[Task] = set()

    async def schedule(self, fn: Coroutine[Any, Any, None]):
        """Create a task and register its callback."""
        task = create_task(fn)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)


class ChunkedDownloader:
    """Handler class dealing with download functionality"""

    def __init__(  # noqa: PLR0913
        self,
        config: LegacyConfig,
        file_id: str,
        encrypted_file_size: int,
        file_secret: bytes,
        part_size: int,
        target_checksums: models.Checksums,
        storage_cleaner: StorageCleaner,
    ) -> None:
        self.config = config
        self.storage = get_object_storage(self.config)
        self.file_id = file_id
        self.file_size = encrypted_file_size
        self.file_secret = file_secret
        self.part_size = part_size
        self.target_checksums = target_checksums
        self.storage_cleaner = storage_cleaner
        self.retry_handler = configure_retries(config)
        self._queue: PriorityQueue[tuple[int, bytes] | tuple[int, BaseException]] = (
            PriorityQueue(config.client_max_parallel_transfers)
        )
        self._semaphore = Semaphore(config.client_max_parallel_transfers)

    async def _download_part(
        self,
        *,
        client: httpx.AsyncClient,
        headers: httpx.Headers,
        part_number: int,
    ):
        """Download single file part to queue. This should be scheduled as a asyncio.Task."""
        async with self._semaphore:
            try:
                url = await self.storage.get_object_download_url(
                    bucket_id=get_bucket_id(self.config),
                    object_id=self.file_id,
                )
                response: Response = await self.retry_handler(
                    fn=client.get,
                    url=url,
                    headers=headers,
                )
                await self._queue.put((part_number, response.content))
            except BaseException as exception:
                await self._queue.put((part_number, exception))

    async def _drain_queue(self):
        """Fetch downloaded parts from queue and keep local queue to yield parts in order."""
        next_part_to_yield = 1
        parts_downloaded = 0
        num_parts = math.ceil(self.file_size / self.part_size)
        # Priority queue ensures we get the the part with the lowest part number on calling get
        # Due to out of order downloading, in the worst case the next part is fetched last in the
        # current batch of scheduled tasks and we keep around an additional max_parallel_tasks - 1
        # parts in the intermediary queue, assuming equal transfer speed for any single part.
        results: PriorityQueue[tuple[int, bytes]] = PriorityQueue()

        while next_part_to_yield <= num_parts:
            # if there are unprocessed results in the local queue, check if the correct one is among them
            if not results.empty():
                part_number, part = await results.get()
                if part_number == next_part_to_yield:
                    next_part_to_yield += 1
                    yield part
                else:
                    # if not, put it back
                    await results.put((part_number, part))

            if parts_downloaded < num_parts:
                # fetch next part from download queue
                part_number, part = await self._queue.get()  # type: ignore
                parts_downloaded += 1

                # raise exception immediately to abort download process
                if isinstance(part, BaseException):
                    raise self.storage_cleaner.PartDownloadError(
                        bucket_id=get_bucket_id(self.config),
                        object_id=self.file_id,
                        part_number=part_number,
                    ) from part

                # yield if it's the expected part, else put it into the local queue
                if part_number == next_part_to_yield:
                    next_part_to_yield += 1
                    yield part
                else:
                    await results.put((part_number, part))

    async def download(self):
        """Download file in parts and validate checksums"""
        LOG.info("(4/7) Downloading file %s for validation.", self.file_id)
        num_parts = math.ceil(self.file_size / self.part_size)
        decryptor = Decryptor(
            file_secret=self.file_secret,
            num_parts=num_parts,
            part_size=self.part_size,
            target_checksums=self.target_checksums,
        )
        # schedule and start download tasks

        task_handler = DownloadTaskHandler()
        async with httpx_client() as client:
            for part_number, (start, stop) in enumerate(
                get_ranges(file_size=self.file_size, part_size=self.config.part_size),
                start=1,
            ):
                headers = httpx.Headers({"Range": f"bytes={start}-{stop}"})
                await task_handler.schedule(
                    self._download_part(
                        client=client,
                        headers=headers,
                        part_number=part_number,
                    )
                )

            try:
                await decryptor.process_parts(self._drain_queue())

            except (
                decryptor.FileChecksumValidationError,
                decryptor.PartChecksumValidationError,
            ) as error:
                raise self.storage_cleaner.ChecksumValidationError(
                    bucket_id=get_bucket_id(self.config),
                    object_id=self.file_id,
                    message=str(error),
                ) from error

        LOG.info("(6/7) Successfully validated checksums for %s.", self.file_id)
