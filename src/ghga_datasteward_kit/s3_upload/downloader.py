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
"""Functionality related to downloading uploaded files for validation purposes."""

import math
from functools import partial

from ghga_datasteward_kit import models
from ghga_datasteward_kit.s3_upload.config import LegacyConfig
from ghga_datasteward_kit.s3_upload.file_decryption import Decryptor
from ghga_datasteward_kit.s3_upload.utils import (
    LOGGER,
    StorageCleaner,
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

    def _download_parts(self, download_url):
        """Download file parts"""
        for part_no, (start, stop) in enumerate(
            get_ranges(file_size=self.file_size, part_size=self.config.part_size),
            start=1,
        ):
            headers = {"Range": f"bytes={start}-{stop}"}
            LOGGER.debug("Downloading part number %i. %s", part_no, headers)
            try:
                with httpx_client() as client:
                    response = client.get(download_url, timeout=60, headers=headers)
                    yield response.content
            except (
                Exception,
                KeyboardInterrupt,
            ) as exc:
                raise self.storage_cleaner.PartDownloadError(
                    bucket_id=self.config.bucket_id, object_id=self.file_id
                ) from exc

    async def download(self):
        """Download file in parts and validate checksums"""
        LOGGER.info("(4/7) Downloading file %s for validation.", self.file_id)
        download_url = await self.storage.get_object_download_url(
            bucket_id=self.config.bucket_id, object_id=self.file_id
        )
        num_parts = math.ceil(self.file_size / self.part_size)
        decryptor = Decryptor(
            file_secret=self.file_secret, num_parts=num_parts, part_size=self.part_size
        )
        download_func = partial(self._download_parts, download_url=download_url)
        decryptor.process_parts(download_func)
        await self.validate_checksums(checkums=decryptor.checksums)

    async def validate_checksums(self, checkums: models.Checksums):
        """Confirm checksums for upload and download match"""
        if self.target_checksums.get() != checkums.get():
            message = (
                "Checksum mismatch:\n"
                + f"Upload:\n{checkums}\nDownload:\n{self.target_checksums}\n"
                + "Uploaded file was deleted due to validation failure."
            )
            raise self.storage_cleaner.ChecksumValidationError(
                bucket_id=self.config.bucket_id, object_id=self.file_id, message=message
            )
        LOGGER.info("(6/7) Succesfully validated checksums for %s.", self.file_id)
