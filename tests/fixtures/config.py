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

"""A config fixture"""

from collections.abc import Generator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from ghga_service_commons.utils.crypt import encode_key, generate_key_pair
from pydantic import SecretStr

from ghga_datasteward_kit.s3_upload import Config, LegacyConfig
from ghga_datasteward_kit.s3_upload.config import (
    NoEndpointURLS3Config,
    S3ObjectStorageNodeConfig,
)


def storage_config(
    *,
    bucket_id: str = "test_bucket",
    s3_access_key_id: str = "test_access_key",
    s3_secret_access_key: str = "test_secret_key",
):
    """Create base storage config for both fixtures"""
    s3_config = NoEndpointURLS3Config(
        s3_access_key_id=SecretStr(s3_access_key_id),
        s3_secret_access_key=SecretStr(s3_secret_access_key),
    )
    node_config = S3ObjectStorageNodeConfig(bucket_id=bucket_id, credentials=s3_config)
    return {"test": node_config}


@pytest.fixture
def legacy_config_fixture() -> Generator[LegacyConfig, None, None]:
    """Generate a test Config file."""
    with TemporaryDirectory() as output_dir:
        yield LegacyConfig(
            object_storages=storage_config(),
            output_dir=Path(output_dir),
            selected_storage_alias="test",
        )


@pytest.fixture
def config_fixture() -> Generator[Config, None, None]:
    """Generate a test Config file."""
    public_key = encode_key(generate_key_pair().public)

    with TemporaryDirectory() as output_dir:
        yield Config(
            object_storages=storage_config(),
            output_dir=Path(output_dir),
            secret_ingest_pubkey=public_key,
            secret_ingest_baseurl="https://not-a-real-url",
            selected_storage_alias="test",
        )
