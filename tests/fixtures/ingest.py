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
"""FIS endpoint calling functionality"""

import os
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Generator

import pytest
from ghga_service_commons.utils.crypt import KeyPair, encode_key, generate_key_pair
from ghga_service_commons.utils.simple_token import generate_token_and_hash
from ghga_service_commons.utils.utc_dates import now_as_utc
from metldata.submission_registry.models import (
    StatusChange,
    Submission,
    SubmissionStatus,
)
from metldata.submission_registry.submission_store import SubmissionStore

from ghga_datasteward_kit.file_ingest import IngestConfig
from ghga_datasteward_kit.models import OutputMetadata

EXAMPLE_SUBMISSION = Submission(
    title="test",
    description="test",
    content={"test_class": [{"alias": "test_alias"}]},
    accession_map={"study_files": {"test_alias": "test_accession"}},
    id="testsubmission001",
    status_history=(
        StatusChange(
            timestamp=now_as_utc(),
            new_status=SubmissionStatus.COMPLETED,
        ),
    ),
)


@dataclass
class IngestFixture:
    """Necessary data for ingest testing."""

    config: IngestConfig
    file_path: Path
    token: str
    token_hash: str
    keypair: KeyPair


@pytest.fixture
def ingest_fixture() -> Generator[IngestFixture, None, None]:
    """Generate necessary data for file ingest."""

    with TemporaryDirectory() as input_dir:
        with TemporaryDirectory() as submission_store_dir:
            token, token_hash = generate_token_and_hash()
            keypair = generate_key_pair()

            file_path = Path(input_dir) / "test.json"

            metadata = OutputMetadata(
                alias="test_alias",
                file_uuid="happy_little_object",
                original_path=file_path,
                part_size=16 * 1024**2,
                unencrypted_size=50 * 1024**2,
                encrypted_size=50 * 1024**2 + 128,
                file_secret=os.urandom(32),
                unencrypted_checksum="def",
                encrypted_md5_checksums=["a", "b", "c"],
                encrypted_sha256_checksums=["a", "b", "c"],
            )

            metadata.serialize(file_path)

            config = IngestConfig(
                file_ingest_url="https://not-a-valid-url",
                file_ingest_pubkey=encode_key(keypair.public),
                input_dir=Path(input_dir),
                map_files_fields=["study_files"],
                submission_store_dir=Path(submission_store_dir),
            )

            submission_store = SubmissionStore(config=config)
            submission_store.insert_new(submission=EXAMPLE_SUBMISSION)

            yield IngestFixture(
                config=config,
                file_path=file_path,
                token=token,
                token_hash=token_hash,
                keypair=keypair,
            )
