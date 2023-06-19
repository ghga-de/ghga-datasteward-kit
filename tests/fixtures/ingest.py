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
"""TODO"""

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Generator

import pytest
from ghga_service_commons.utils.crypt import KeyPair, generate_key_pair
from ghga_service_commons.utils.simple_token import generate_token_and_hash

from ghga_datasteward_kit.file_ingest import IngestConfig


@dataclass
class IngestFixture:
    """Necessary data for ingest testing."""

    config: IngestConfig
    input_dir: Path
    token: str
    token_hash: str
    keypair: KeyPair


@pytest.fixture
def ingest_fixture() -> Generator[IngestFixture, None, None]:
    """Generate necessary data for file ingest."""

    with TemporaryDirectory() as input_dir:
        token, token_hash = generate_token_and_hash()
        keypair = generate_key_pair()
        config = IngestConfig(
            endpoint_base="https://test.ghga-file-ingest.de",
            pubkey=keypair.public,
            token=token,
        )
        yield IngestFixture(
            config=config,
            input_dir=Path(input_dir),
            token=token,
            token_hash=token_hash,
            keypair=keypair,
        )
