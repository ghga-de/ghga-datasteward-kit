# Copyright 2021 Universität Tübingen, DKFZ and EMBL
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

import pytest  # type: ignore
from ghga_service_chassis_lib.utils import big_temp_file  # type: ignore
from hexkit.providers.s3.testutils import (  # type: ignore
    config_from_localstack_container,
)
from testcontainers.localstack import LocalStackContainer  # type: ignore

from src.s3_upload import Config, async_main, objectstorage

from ..fixtures.config import config_fixture  # noqa: F401

ALIAS = "test_file"
BUCKET_ID = "test-bucket"


@pytest.mark.asyncio
async def test_process(config_fixture: Config):  # noqa: F811
    """Test whole upload/download process for s3_upload script"""
    with LocalStackContainer(image="localstack/localstack:0.14.2").with_services(
        "s3"
    ) as localstack:
        s3_config = config_from_localstack_container(localstack)

        config = config_fixture.copy(
            update={
                "s3_endpoint_url": s3_config.s3_endpoint_url,
                "s3_access_key_id": s3_config.s3_access_key_id,
                "s3_secret_access_key": s3_config.s3_secret_access_key,
                "bucket_id": BUCKET_ID,
            }
        )
        storage = objectstorage(config=config)
        await storage.create_bucket(bucket_id=config.bucket_id)
        sys.set_int_max_str_digits(50 * 1024**2)  # type: ignore
        with big_temp_file(50 * 1024**2) as file:
            await async_main(input_path=Path(file.name), alias=ALIAS, config=config)
        # tmp dir empty and output file exists?
        assert not any(config.tmp_dir.iterdir())
        assert (config.output_dir / ALIAS).with_suffix(".json").exists()
