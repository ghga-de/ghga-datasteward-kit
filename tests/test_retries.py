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
"""Test retry functionality for client requests in upload/download."""

import httpx
import pytest
from pytest_httpx import HTTPXMock
from tenacity import RetryError

from ghga_datasteward_kit.s3_upload import LegacyConfig
from ghga_datasteward_kit.s3_upload.http_client import RequestConfigurator, httpx_client
from tests.fixtures.config import legacy_config_fixture  # noqa: F401

EXCEPTIONS = [httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException]
STATUS_CODES = [408, 429, 500, 502, 503, 504]
URL = "http://not-a-real-url/test"


pytestmark = [
    pytest.mark.asyncio(),
    pytest.mark.httpx_mock(
        assert_all_responses_were_requested=False,
        can_send_already_matched_responses=True,
    ),
]


@pytest.mark.parametrize("status_code", STATUS_CODES)
async def test_retry_handling_retryable_status_codes(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
    httpx_mock: HTTPXMock,
    status_code: int,
):
    """Test if configuration is correctly applied to retry handler"""
    RequestConfigurator.configure(legacy_config_fixture)

    httpx_mock.add_response(url=URL, status_code=status_code)
    with pytest.raises(RetryError):
        await _run_request()


@pytest.mark.parametrize("exception", EXCEPTIONS)
@pytest.mark.parametrize("should_reraise", [True, False])
async def test_retry_handling_retryable_exceptions(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
    httpx_mock: HTTPXMock,
    exception: type[Exception],
    should_reraise: bool,
):
    """Test if configuration is correctly applied to retry handler"""
    RequestConfigurator.configure(
        legacy_config_fixture.model_copy(
            update={"client_reraise_from_retry_error": should_reraise}
        )
    )

    httpx_mock.reset()
    httpx_mock.add_exception(exception=exception("Expected exception"), url=URL)
    with pytest.raises(exception) if should_reraise else pytest.raises(RetryError):
        await _run_request()


async def test_retry_handling_edge_cases(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
    httpx_mock: HTTPXMock,
):
    """Test if configuration is correctly applied to retry handler"""
    RequestConfigurator.configure(legacy_config_fixture)

    httpx_mock.add_exception(exception=ValueError("Expected exception"), url=URL)
    with pytest.raises(ValueError):
        await _run_request()

    httpx_mock.reset()
    httpx_mock.add_response(url=URL, status_code=200)
    await _run_request()


async def _run_request():
    """Dummy request for testing"""
    async with httpx_client() as client:
        return await client.get(URL)
