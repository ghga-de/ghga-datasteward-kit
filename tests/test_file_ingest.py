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

"""File ingest tests."""

import urllib.parse

import pytest
import yaml
from ghga_service_commons.utils.simple_token import generate_token
from metldata.submission_registry.submission_store import SubmissionStore
from pytest_httpx import HTTPXMock

from ghga_datasteward_kit import models
from ghga_datasteward_kit.cli.file import ingest_upload_metadata
from ghga_datasteward_kit.file_ingest import alias_to_accession, file_ingest
from tests.fixtures.ingest import (  # noqa: F401
    EXAMPLE_SUBMISSION,
    IngestFixture,
    ingest_fixture,
    legacy_ingest_fixture,
)


@pytest.mark.asyncio
async def test_alias_to_accession(legacy_ingest_fixture: IngestFixture):  # noqa: F811
    """Test alias->accession mapping"""
    submission_store = SubmissionStore(config=legacy_ingest_fixture.config)
    metadata = models.LegacyOutputMetadata.load(
        input_path=legacy_ingest_fixture.file_path
    )

    accession = alias_to_accession(
        alias=metadata.alias,
        map_fields=legacy_ingest_fixture.config.map_files_fields,
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
            submission_store=submission_store,
        )

    with pytest.raises(ValueError):
        alias_to_accession(
            alias=metadata.alias,
            map_fields=["study_files", "sample_files"],
            submission_store=submission_store,
        )


@pytest.mark.asyncio
async def test_legacy_ingest_directly(
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test file_ingest function directly"""
    endpoint_url = urllib.parse.urljoin(
        base=legacy_ingest_fixture.config.file_ingest_baseurl,
        url=legacy_ingest_fixture.config.file_ingest_legacy_endpoint,
    )
    token = generate_token()

    httpx_mock.add_response(
        url=endpoint_url,
        status_code=202,
    )
    file_ingest(
        in_path=legacy_ingest_fixture.file_path,
        token=token,
        config=legacy_ingest_fixture.config,
    )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Not authorized to access ingest endpoint."},
        status_code=403,
    )
    with pytest.raises(ValueError, match="Not authorized to access ingest endpoint."):
        file_ingest(
            in_path=legacy_ingest_fixture.file_path,
            token=token,
            config=legacy_ingest_fixture.config,
        )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Could not decrypt received payload."},
        status_code=422,
    )
    with pytest.raises(ValueError, match="Could not decrypt received payload."):
        file_ingest(
            in_path=legacy_ingest_fixture.file_path,
            token=token,
            config=legacy_ingest_fixture.config,
        )


@pytest.mark.asyncio
async def test_ingest_directly(
    ingest_fixture: IngestFixture,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test file_ingest function directly"""
    endpoint_url = urllib.parse.urljoin(
        base=ingest_fixture.config.file_ingest_baseurl,
        url=ingest_fixture.config.file_ingest_federated_endpoint,
    )
    token = generate_token()

    httpx_mock.add_response(url=endpoint_url, status_code=202)
    file_ingest(
        in_path=ingest_fixture.file_path,
        token=token,
        config=ingest_fixture.config,
    )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Not authorized to access ingest endpoint."},
        status_code=403,
    )
    with pytest.raises(ValueError, match="Not authorized to access ingest endpoint."):
        file_ingest(
            in_path=ingest_fixture.file_path,
            token=token,
            config=ingest_fixture.config,
        )

    httpx_mock.add_response(
        url=endpoint_url,
        json={"detail": "Could not decrypt received payload."},
        status_code=422,
    )
    with pytest.raises(ValueError, match="Could not decrypt received payload."):
        file_ingest(
            in_path=ingest_fixture.file_path,
            token=token,
            config=ingest_fixture.config,
        )


@pytest.mark.asyncio
async def test_legacy_main(
    capfd,
    monkeypatch,
    legacy_ingest_fixture: IngestFixture,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test if main file ingest function works correctly"""
    endpoint_url = urllib.parse.urljoin(
        base=legacy_ingest_fixture.config.file_ingest_baseurl,
        url=legacy_ingest_fixture.config.file_ingest_legacy_endpoint,
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

        httpx_mock.add_response(url=endpoint_url, status_code=202)
        ingest_upload_metadata(config_path=config_path)
        out, _ = capfd.readouterr()

        assert "Successfully sent all file upload metadata for ingest" in out

        httpx_mock.add_response(
            url=endpoint_url,
            json={"detail": "Unauthorized"},
            status_code=403,
        )
        ingest_upload_metadata(config_path=config_path)
        out, _ = capfd.readouterr()

        assert "Encountered 1 errors during processing" in out
