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

"""A config fixture"""

import os
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
from ghga_datasteward_kit.s3_upload.http_client import RequestConfigurator
from ghga_datasteward_kit.utils import TOKEN_PATH


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
        config = LegacyConfig(
            client_timeout=5,
            client_exponential_backoff_max=10,
            object_storages=storage_config(),
            output_dir=Path(output_dir),
            selected_storage_alias="test",
        )
        RequestConfigurator.configure(config)
        yield config


@pytest.fixture
def config_fixture() -> Generator[Config, None, None]:
    """Generate a test Config file."""
    public_key = encode_key(generate_key_pair().public)

    with TemporaryDirectory() as output_dir:
        config = Config(
            client_timeout=5,
            client_exponential_backoff_max=10,
            object_storages=storage_config(),
            output_dir=Path(output_dir),
            secret_ingest_pubkey=public_key,
            secret_ingest_baseurl="https://not-a-real-url",
            selected_storage_alias="test",
        )
        RequestConfigurator.configure(config)
        yield config


@pytest.fixture
def steward_token_fixture():
    """Generates a test file for the steward token.

    If a file already exists at that location, the file is temporarily renamed.
    When the test finishes, the temp data is removed.
    If applicable, the original filename is restored.
    """
    # Rename the existing file for a moment
    prior_token_exists = False
    real_token_path = TOKEN_PATH.with_name(".super-real-token123.txt")
    if TOKEN_PATH.exists():
        prior_token_exists = True
        os.rename(TOKEN_PATH, real_token_path)

    # Author the test token file
    with open(TOKEN_PATH, "w") as f:
        f.write("dummy-token")

    yield

    # Clean up by removing the test file and renaming the og file if applicable
    os.remove(TOKEN_PATH)
    if prior_token_exists:
        os.rename(real_token_path, TOKEN_PATH)
