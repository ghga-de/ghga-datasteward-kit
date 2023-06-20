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

import pytest
from pytest_httpx import HTTPXMock

from ghga_datasteward_kit.file_ingest import file_ingest
from tests.fixtures.ingest import IngestFixture, ingest_fixture  # noqa: F401


def id_generator():
    """Generate dummy IDs."""
    for i in [1, 2]:
        yield f"test_{i}"


@pytest.mark.asyncio
async def test_ingest_directly(
    ingest_fixture: IngestFixture, httpx_mock: HTTPXMock  # noqa: F811
):
    """TODO"""

    httpx_mock.add_response(url=ingest_fixture.config.endpoint_base, status_code=202)
    file_ingest(
        in_path=ingest_fixture.file_path, file_id="test", config=ingest_fixture.config
    )

    httpx_mock.add_response(
        url=ingest_fixture.config.endpoint_base,
        json={"detail": "Unauthorized"},
        status_code=403,
    )
    with pytest.raises(ValueError, match="Unauthorized"):
        file_ingest(
            in_path=ingest_fixture.file_path,
            file_id="test",
            config=ingest_fixture.config,
        )

    httpx_mock.add_response(
        url=ingest_fixture.config.endpoint_base,
        json={"detail": "Could not decrypt received payload with the given key."},
        status_code=422,
    )
    with pytest.raises(
        ValueError, match="Could not decrypt received payload with the given key."
    ):
        file_ingest(
            in_path=ingest_fixture.file_path,
            file_id="test",
            config=ingest_fixture.config,
        )


@pytest.mark.asyncio
async def test_main(ingest_fixture: IngestFixture, httpx_mock: HTTPXMock):  # noqa: F811
    """TODO"""
