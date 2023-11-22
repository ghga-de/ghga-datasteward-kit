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

"""Testing the whole encryption, upload, validation flow"""

import sys
from pathlib import Path

import pytest
from ghga_service_commons.utils.temp_files import big_temp_file  # type: ignore
from hexkit.providers.s3.testutils import (  # type: ignore
    config_from_localstack_container,
)
from pydantic import SecretStr
from testcontainers.localstack import LocalStackContainer  # type: ignore

from ghga_datasteward_kit.s3_upload import Config, LegacyConfig
from ghga_datasteward_kit.s3_upload.entrypoint import async_main, legacy_async_main
from ghga_datasteward_kit.s3_upload.utils import StorageCleaner, get_object_storage
from tests.fixtures.config import config_fixture, legacy_config_fixture  # noqa: F401

ALIAS = "test_file"
BUCKET_ID = "test-bucket"


@pytest.mark.asyncio
async def test_legacy_process(legacy_config_fixture: LegacyConfig):  # noqa: F811
    """Test whole upload/download process for s3_upload script"""
    with LocalStackContainer(image="localstack/localstack:0.14.2").with_services(
        "s3"
    ) as localstack:
        s3_config = config_from_localstack_container(localstack)

        config = legacy_config_fixture.model_copy(
            update={
                "s3_endpoint_url": SecretStr(s3_config.s3_endpoint_url),
                "s3_access_key_id": SecretStr(s3_config.s3_access_key_id),
                "s3_secret_access_key": s3_config.s3_secret_access_key,
                "bucket_id": BUCKET_ID,
            }
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=config.bucket_id)
        sys.set_int_max_str_digits(50 * 1024**2)
        with big_temp_file(50 * 1024**2) as file:
            await legacy_async_main(
                input_path=Path(file.name), alias=ALIAS, config=config
            )
        # output file exists?
        assert (config.output_dir / ALIAS).with_suffix(".json").exists()


@pytest.mark.asyncio
async def test_process(config_fixture: Config, monkeypatch):  # noqa: F811
    """Test whole upload/download process for s3_upload script"""

    async def secret_exchange_dummy(
        *,
        file_id: str,
        secret: bytes,
        token: str,
        config: Config,
        storage_cleaner: StorageCleaner,
    ):
        return "test-secret-id"

    with LocalStackContainer(image="localstack/localstack:0.14.2").with_services(
        "s3"
    ) as localstack:
        s3_config = config_from_localstack_container(localstack)

        config = config_fixture.model_copy(
            update={
                "s3_endpoint_url": SecretStr(s3_config.s3_endpoint_url),
                "s3_access_key_id": SecretStr(s3_config.s3_access_key_id),
                "s3_secret_access_key": s3_config.s3_secret_access_key,
                "bucket_id": BUCKET_ID,
            }
        )
        storage = get_object_storage(config=config)
        await storage.create_bucket(bucket_id=config.bucket_id)
        sys.set_int_max_str_digits(50 * 1024**2)

        with big_temp_file(50 * 1024**2) as file:
            with monkeypatch.context() as patch:
                patch.setattr(
                    "ghga_datasteward_kit.s3_upload.entrypoint.exchange_secret_for_id",
                    secret_exchange_dummy,
                )
                await async_main(
                    input_path=Path(file.name),
                    alias=ALIAS,
                    config=config,
                    token="dummy-token",
                )
        # output file exists?
        assert (config.output_dir / ALIAS).with_suffix(".json").exists()
