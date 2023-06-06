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

"""A config fixture"""

from tempfile import TemporaryDirectory
from typing import Generator

import pytest
from pydantic import SecretStr

from ghga_datasteward_kit.s3_upload import Config


@pytest.fixture
def config_fixture() -> Generator[Config, None, None]:
    """Generate a test Config file."""

    with TemporaryDirectory() as output_dir:
        yield Config(
            s3_endpoint_url=SecretStr("s3://test_url"),
            s3_access_key_id=SecretStr("test_access_key"),
            s3_secret_access_key=SecretStr("test_secret_key"),
            bucket_id="test_bucket",
            output_dir=output_dir,
        )
