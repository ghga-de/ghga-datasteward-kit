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

"""File ingest tests."""

import json

import pytest
import yaml
from ghga_service_commons.utils.simple_token import generate_token
from ghga_service_commons.utils.utc_dates import now_as_utc
from metldata.submission_registry.models import (
    StatusChange,
    Submission,
    SubmissionStatus,
)
from metldata.submission_registry.submission_store import SubmissionStore
from pytest_httpx import HTTPXMock

from ghga_datasteward_kit import models
from ghga_datasteward_kit.cli.file import ingest_upload_metadata
from ghga_datasteward_kit.exceptions import UnknownStorageAliasError
from ghga_datasteward_kit.file_ingest import alias_to_accession, file_ingest
from ghga_datasteward_kit.utils import path_join
from tests.fixtures.ingest import (  # noqa: F401
    EXAMPLE_SUBMISSION,
    IngestFixture,
    ingest_fixture,
    legacy_ingest_fixture,
)


@pytest.mark.asyncio
async def test_alias_to_accession(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
):
    """Test alias->accession mapping"""
    submission_store = SubmissionStore(config=legacy_ingest_fixture.config)
    storage_aliases = {
        legacy_ingest_fixture.config.selected_storage_alias: "http://example.com"
    }

    metadata = models.LegacyOutputMetadata.load(
        input_path=legacy_ingest_fixture.file_path,
        selected_alias=legacy_ingest_fixture.config.selected_storage_alias,
        fallback_bucket=legacy_ingest_fixture.config.fallback_bucket_id,
        storage_aliases=storage_aliases,
    )

    accession = alias_to_accession(
        alias=metadata.alias,
        map_fields=legacy_ingest_fixture.config.map_files_fields,
        submission_id=EXAMPLE_SUBMISSION.id,
        submission_store=submission_store,
    )
    example_accession = list(  # noqa: RUF015
        EXAMPLE_SUBMISSION.accession_map[
            legacy_ingest_fixture.config.map_files_fields[0]
        ].values()
    )[0]
    assert accession == example_accession

    with pytest.raises(ValueError):
        alias_to_accession(
            alias="invalid_alias",
            map_fields=legacy_ingest_fixture.config.map_files_fields,
            submission_id=EXAMPLE_SUBMISSION.id,
            submission_store=submission_store,
        )

    with pytest.raises(ValueError):
        alias_to_accession(
            alias=metadata.alias,
            map_fields=["study_files", "sample_files"],
            submission_id=EXAMPLE_SUBMISSION.id,
            submission_store=submission_store,
        )


@pytest.mark.asyncio
async def test_alias_to_accession_unknown_submission_id(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
):
    """Test alias->accession mapping with unknown submission ID"""
    submission_store = SubmissionStore(config=legacy_ingest_fixture.config)
    storage_aliases = {
        legacy_ingest_fixture.config.selected_storage_alias: "http://example.com"
    }

    metadata = models.LegacyOutputMetadata.load(
        input_path=legacy_ingest_fixture.file_path,
        selected_alias=legacy_ingest_fixture.config.selected_storage_alias,
        fallback_bucket=legacy_ingest_fixture.config.fallback_bucket_id,
        storage_aliases=storage_aliases,
    )

    # Try with a non-existent submission ID
    with pytest.raises(SubmissionStore.SubmissionDoesNotExistError):
        alias_to_accession(
            alias=metadata.alias,
            map_fields=legacy_ingest_fixture.config.map_files_fields,
            submission_id="unknown_submission_id",
            submission_store=submission_store,
        )


@pytest.mark.asyncio
async def test_alias_to_accession_missing_field(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
):
    """Test alias->accession mapping when configured field is missing in submission"""
    store = SubmissionStore(config=legacy_ingest_fixture.config)
    # Create a submission with only one field
    submission = Submission(
        title="test",
        description="test",
        content={"test_class": [{"alias": "test_alias"}]},
        accession_map={
            "study_files": {"alias1": "accession1"},
        },
        id="limited_field_submission",
        status_history=(
            StatusChange(
                timestamp=now_as_utc(),
                new_status=SubmissionStatus.COMPLETED,
            ),
        ),
    )
    store.insert_new(submission=submission)

    # Try to map accession with a field that doesn't exist in the submission
    with pytest.raises(
        ValueError, match=r"Configured accession map field .* is missing in submission"
    ):
        alias_to_accession(
            alias="alias1",
            map_fields=["study_files", "sample_files"],
            submission_id="limited_field_submission",
            submission_store=store,
        )


@pytest.mark.asyncio
async def test_alias_to_accession_no_accession_for_field(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
):
    """Test alias->accession mapping when no accession exists for the field"""
    store = SubmissionStore(config=legacy_ingest_fixture.config)
    # Create a submission with accessions only in one field
    submission = Submission(
        title="test",
        description="test",
        content={"test_class": [{"alias": "test_alias"}]},
        accession_map={
            "study_files": {"alias1": "accession1"},
        },
        id="single_field_submission",
        status_history=(
            StatusChange(
                timestamp=now_as_utc(),
                new_status=SubmissionStatus.COMPLETED,
            ),
        ),
    )
    store.insert_new(submission=submission)

    # Try to map an accession that doesn't exist in the requested field
    with pytest.raises(ValueError, match=r"No accession exists for file alias"):
        alias_to_accession(
            alias="missing_alias",
            map_fields=["study_files"],
            submission_id="single_field_submission",
            submission_store=store,
        )


@pytest.mark.asyncio
async def test_alias_to_accession_duplicate_alias_across_fields(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
):
    """Test alias->accession mapping when the same alias appears in multiple fields"""
    store = SubmissionStore(config=legacy_ingest_fixture.config)
    submission = Submission(
        title="test",
        description="test",
        content={"test_class": [{"alias": "test_alias"}]},
        accession_map={
            "study_files": {"dup_alias": "accession_study"},
            "sample_files": {"dup_alias": "accession_sample"},
        },
        id="duplicate_alias_submission",
        status_history=(
            StatusChange(
                timestamp=now_as_utc(),
                new_status=SubmissionStatus.COMPLETED,
            ),
        ),
    )
    store.insert_new(submission=submission)
    with pytest.raises(
        ValueError, match=r"Found aliases .* multiple times in accession map"
    ):
        alias_to_accession(
            alias="dup_alias",
            map_fields=["study_files", "sample_files"],
            submission_id="duplicate_alias_submission",
            submission_store=store,
        )


@pytest.mark.asyncio
async def test_alias_to_accession_multiple_submissions_shared_fields(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
):
    """Test correct accession retrieval when multiple submissions share field names and some alias keys with unique accessions"""
    store = SubmissionStore(config=legacy_ingest_fixture.config)

    # Create first submission with study_files
    submission1 = Submission(
        title="test_submission_1",
        description="first submission",
        content={"test_class": [{"alias": "alias_from_sub1"}]},
        accession_map={
            "study_files": {
                "file_alias_1a": "accession_sub1_1a",
                "shared_alias": "accession_sub1_shared",
            },
        },
        id="submission_001",
        status_history=(
            StatusChange(
                timestamp=now_as_utc(),
                new_status=SubmissionStatus.COMPLETED,
            ),
        ),
    )
    store.insert_new(submission=submission1)

    # Create second submission with same field name and a shared alias key but different accession values
    submission2 = Submission(
        title="test_submission_2",
        description="second submission",
        content={"test_class": [{"alias": "alias_from_sub2"}]},
        accession_map={
            "study_files": {
                "file_alias_2a": "accession_sub2_2a",
                "shared_alias": "accession_sub2_shared",
            },
        },
        id="submission_002",
        status_history=(
            StatusChange(
                timestamp=now_as_utc(),
                new_status=SubmissionStatus.COMPLETED,
            ),
        ),
    )
    store.insert_new(submission=submission2)

    # Verify we get the correct accession for submission 1's unique alias
    accession_1a = alias_to_accession(
        alias="file_alias_1a",
        map_fields=["study_files"],
        submission_id="submission_001",
        submission_store=store,
    )
    assert accession_1a == "accession_sub1_1a"

    # Verify we get the correct accession for submission 1's shared alias
    accession_1_shared = alias_to_accession(
        alias="shared_alias",
        map_fields=["study_files"],
        submission_id="submission_001",
        submission_store=store,
    )
    assert accession_1_shared == "accession_sub1_shared"

    # Verify we get the correct accession for submission 2's unique alias
    accession_2a = alias_to_accession(
        alias="file_alias_2a",
        map_fields=["study_files"],
        submission_id="submission_002",
        submission_store=store,
    )
    assert accession_2a == "accession_sub2_2a"

    # Verify we get the correct accession for submission 2's shared alias (different from submission 1)
    accession_2_shared = alias_to_accession(
        alias="shared_alias",
        map_fields=["study_files"],
        submission_id="submission_002",
        submission_store=store,
    )
    assert accession_2_shared == "accession_sub2_shared"

    # Verify that the shared alias returns different accessions for different submissions
    assert accession_1_shared != accession_2_shared

    # Verify that aliases from submission 1 are not found in submission 2
    with pytest.raises(ValueError, match=r"No accession exists for file alias"):
        alias_to_accession(
            alias="file_alias_1a",
            map_fields=["study_files"],
            submission_id="submission_002",
            submission_store=store,
        )


@pytest.mark.asyncio
async def test_legacy_ingest_directly(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test file_ingest function directly"""
    endpoint_url = path_join(
        legacy_ingest_fixture.config.file_ingest_baseurl,
        legacy_ingest_fixture.config.file_ingest_legacy_endpoint,
    )
    token = generate_token()

    httpx_mock.add_response(
        url=path_join(
            legacy_ingest_fixture.config.wkvs_api_url, "values/storage_aliases"
        ),
        json={"storage_aliases": {"test": "http://example.com"}},
        status_code=200,
        is_reusable=True,
    )

    httpx_mock.add_response(
        url=endpoint_url,
        status_code=202,
    )
    file_ingest(
        in_path=legacy_ingest_fixture.file_path,
        token=token,
        config=legacy_ingest_fixture.config,
        submission_id=EXAMPLE_SUBMISSION.id,
    )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Not authorized to access ingest endpoint."},
        status_code=403,
    )
    with pytest.raises(ValueError, match=r"Not authorized to access ingest endpoint."):
        file_ingest(
            in_path=legacy_ingest_fixture.file_path,
            token=token,
            config=legacy_ingest_fixture.config,
            submission_id=EXAMPLE_SUBMISSION.id,
        )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Could not decrypt received payload."},
        status_code=422,
    )
    with pytest.raises(ValueError, match=r"Could not decrypt received payload."):
        file_ingest(
            in_path=legacy_ingest_fixture.file_path,
            token=token,
            config=legacy_ingest_fixture.config,
            submission_id=EXAMPLE_SUBMISSION.id,
        )


@pytest.mark.asyncio
async def test_ingest_directly(
    ingest_fixture: IngestFixture,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test file_ingest function directly"""
    endpoint_url = path_join(
        ingest_fixture.config.file_ingest_baseurl,
        ingest_fixture.config.file_ingest_federated_endpoint,
    )
    token = generate_token()

    httpx_mock.add_response(
        url=path_join(ingest_fixture.config.wkvs_api_url, "values/storage_aliases"),
        json={"storage_aliases": {"test": "http://example.com"}},
        status_code=200,
        is_reusable=True,
    )

    httpx_mock.add_response(url=endpoint_url, status_code=202)
    file_ingest(
        in_path=ingest_fixture.file_path,
        token=token,
        config=ingest_fixture.config,
        submission_id=EXAMPLE_SUBMISSION.id,
    )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Not authorized to access ingest endpoint."},
        status_code=403,
    )
    with pytest.raises(ValueError, match=r"Not authorized to access ingest endpoint."):
        file_ingest(
            in_path=ingest_fixture.file_path,
            token=token,
            config=ingest_fixture.config,
            submission_id=EXAMPLE_SUBMISSION.id,
        )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Could not decrypt received payload."},
        status_code=422,
    )
    with pytest.raises(ValueError, match=r"Could not decrypt received payload."):
        file_ingest(
            in_path=ingest_fixture.file_path,
            token=token,
            config=ingest_fixture.config,
            submission_id=EXAMPLE_SUBMISSION.id,
        )


@pytest.mark.asyncio
async def test_legacy_main(
    capfd,
    monkeypatch,
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test if main file ingest function works correctly"""
    endpoint_url = path_join(
        legacy_ingest_fixture.config.file_ingest_baseurl,
        legacy_ingest_fixture.config.file_ingest_legacy_endpoint,
    )
    config_path = legacy_ingest_fixture.config.input_dir / "config.yaml"

    config = legacy_ingest_fixture.config.model_dump()
    config["input_dir"] = str(config["input_dir"])
    config["submission_store_dir"] = str(config["submission_store_dir"])

    with config_path.open("w") as config_file:
        yaml.safe_dump(config, config_file)

    with monkeypatch.context() as patch:
        patch.setattr(
            "ghga_datasteward_kit.utils.AuthorizationToken.read_token",
            lambda self: generate_token(),
        )

        httpx_mock.add_response(
            url=path_join(
                legacy_ingest_fixture.config.wkvs_api_url, "values/storage_aliases"
            ),
            json={"storage_aliases": {"test": "http://example.com"}},
            status_code=200,
            is_reusable=True,
        )

        httpx_mock.add_response(url=endpoint_url, status_code=202)
        ingest_upload_metadata(
            config_path=config_path, submission_id=EXAMPLE_SUBMISSION.id
        )
        out, _ = capfd.readouterr()

        assert "Successfully sent all file upload metadata for ingest" in out

        httpx_mock.add_response(
            url=endpoint_url,
            json={"detail": "Unauthorized"},
            status_code=403,
        )
        ingest_upload_metadata(
            config_path=config_path, submission_id=EXAMPLE_SUBMISSION.id
        )
        out, _ = capfd.readouterr()

        assert "Encountered 1 errors during processing" in out


def test_fallbacks(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
    ingest_fixture: IngestFixture,  # noqa: F811
    tmp_path,
):
    """Simulate loading old metadata files and test for newly populated fields"""
    bucket_id = ingest_fixture.config.fallback_bucket_id
    storage_alias = ingest_fixture.config.selected_storage_alias
    storage_aliases = {storage_alias: "http://example.com"}

    for fixture, metadata_model in zip(
        (legacy_ingest_fixture, ingest_fixture),
        (models.LegacyOutputMetadata, models.OutputMetadata),  # type: ignore[arg-type]
        strict=True,
    ):
        with fixture.file_path.open("r") as source:
            data = json.load(source)

        del data["Bucket ID"]
        del data["Storage alias"]

        modified_metadata_path = tmp_path / "old_metadata.txt"
        with modified_metadata_path.open("w") as target:
            json.dump(data, target)

        metadata = metadata_model.load(  # type: ignore[attr-defined]
            input_path=modified_metadata_path,
            selected_alias=storage_alias,
            fallback_bucket=bucket_id,
            storage_aliases=storage_aliases,
        )
        assert metadata.bucket_id == bucket_id
        assert metadata.storage_alias == storage_alias


def test_unknown_storage_alias(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
    ingest_fixture: IngestFixture,  # noqa: F811
    tmp_path,
    httpx_mock: HTTPXMock,
):
    """Simulate loading metadata with unknown storage alias and expect errors"""
    # Prepare metadata with an unknown storage alias

    token = generate_token()

    httpx_mock.add_response(
        url=path_join(
            legacy_ingest_fixture.config.wkvs_api_url, "values/storage_aliases"
        ),
        json={"storage_aliases": {"fake": "http://example.com"}},
        status_code=200,
        is_reusable=True,
    )

    with pytest.raises(
        UnknownStorageAliasError,
        match=r"Unknown storage alias 'test'. Please check your configuration or contact support.",
    ):
        file_ingest(
            in_path=legacy_ingest_fixture.file_path,
            token=token,
            config=legacy_ingest_fixture.config,
            submission_id=EXAMPLE_SUBMISSION.id,
        )
