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
from collections.abc import Coroutine
from functools import partial
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

    async def _download_parts(self, fetch_url: partial[Coroutine[Any, Any, str]]):
        """Download file parts"""
        async with httpx_client() as client:
            for part_number, (start, stop) in enumerate(
                get_ranges(file_size=self.file_size, part_size=self.config.part_size),
                start=1,
            ):
                headers = {"Range": f"bytes={start}-{stop}"}
                LOG.debug("Downloading part number %i. %s", part_number, headers)
                try:
                    response: Response = await self.retry_handler(
                        fn=self._run_request,
                        client=client,
                        url=await fetch_url(),
                        headers=headers,
                    )
                    yield response.content
                except (
                    Exception,
                    KeyboardInterrupt,
                ) as exc:
                    raise self.storage_cleaner.PartDownloadError(
                        bucket_id=get_bucket_id(self.config),
                        object_id=self.file_id,
                        part_number=part_number,
                    ) from exc

    async def _run_request(
        self, *, client: httpx.AsyncClient, url: str, headers: dict[str, str]
    ) -> Response:
        """Request to be wrapped by retry handler."""
        response = await client.get(url, headers=headers)
        return response

    async def download(self):
        """Download file in parts and validate checksums"""
        LOG.info("(4/7) Downloading file %s for validation.", self.file_id)
        url_function = partial(
            self.storage.get_object_download_url,
            bucket_id=get_bucket_id(self.config),
            object_id=self.file_id,
        )
        num_parts = math.ceil(self.file_size / self.part_size)
        decryptor = Decryptor(
            file_secret=self.file_secret,
            num_parts=num_parts,
            part_size=self.part_size,
            target_checksums=self.target_checksums,
        )
        download_func = partial(self._download_parts, fetch_url=url_function)

        try:
            await decryptor.process_parts(download_func)
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
