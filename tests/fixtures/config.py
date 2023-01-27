# Copyright 2023 Universität Tübingen, DKFZ and EMBL
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

from src.s3_upload import Config


@pytest.fixture
def config_fixture() -> Generator[Config, None, None]:
    """Generate a test Config file."""

    with TemporaryDirectory() as tmp_dir:
        with TemporaryDirectory() as output_dir:
            yield Config(
                s3_endpoint_url="s3://test_url",
                s3_access_key_id="test_access_key",
                s3_secret_access_key="test_secret_key",
                bucket_id="test_bucket",
                tmp_dir=tmp_dir,
                output_dir=output_dir,
            )
