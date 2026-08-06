# Copyright 2021 - 2026 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

import httpx2
import pytest
from tenacity import RetryError

from ghga_datasteward_kit.s3_upload import LegacyConfig
from ghga_datasteward_kit.s3_upload.http_client import RequestConfigurator, httpx_client
from tests.fixtures.config import legacy_config_fixture  # noqa: F401
from tests.fixtures.mock_api import (
    ApiMock,
    MockedEndpoint,
    ResponseHandler,
    fail_with,
    respond,
)

EXCEPTIONS = [httpx2.ConnectError, httpx2.ConnectTimeout, httpx2.TimeoutException]
STATUS_CODES = [408, 429, 500, 502, 503, 504]
PATH = "/test"
URL = f"http://not-a-real-url{PATH}"


pytestmark = pytest.mark.asyncio()


def _configure_client(config: LegacyConfig, handler: ResponseHandler) -> MockedEndpoint:
    """Point the client at a mocked endpoint answering with `handler`.

    The mock replaces only the innermost transport, so requests still pass through the
    rate limiting and retry layers under test.
    """
    api_mock = ApiMock()
    endpoint = api_mock.add(method="GET", path=PATH, handler=handler)
    RequestConfigurator.configure(config, base_transport=api_mock.as_transport())
    return endpoint


@pytest.mark.parametrize("status_code", STATUS_CODES)
async def test_retry_handling_retryable_status_codes(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
    status_code: int,
):
    """Test if configuration is correctly applied to retry handler"""
    endpoint = _configure_client(legacy_config_fixture, respond(status_code))

    with pytest.raises(RetryError):
        await _run_request()

    # the request was actually retried instead of failing on the first attempt
    assert endpoint.call_count > 1


@pytest.mark.parametrize("exception", EXCEPTIONS)
@pytest.mark.parametrize("should_reraise", [True, False])
async def test_retry_handling_retryable_exceptions(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
    exception: type[Exception],
    should_reraise: bool,
):
    """Test if configuration is correctly applied to retry handler"""
    config = legacy_config_fixture.model_copy(
        update={"client_reraise_from_retry_error": should_reraise}
    )
    _configure_client(config, fail_with(exception("Expected exception")))

    with pytest.raises(exception) if should_reraise else pytest.raises(RetryError):
        await _run_request()


async def test_retry_handling_edge_cases(
    legacy_config_fixture: LegacyConfig,  # noqa: F811
):
    """Test if configuration is correctly applied to retry handler"""
    endpoint = _configure_client(
        legacy_config_fixture, fail_with(ValueError("Expected exception"))
    )

    # a non-retryable exception propagates on the first attempt
    with pytest.raises(ValueError):
        await _run_request()

    # a successful response is passed through untouched
    endpoint.handler = respond(200)
    response = await _run_request()
    assert response.status_code == 200


async def _run_request():
    """Dummy request for testing"""
    async with httpx_client() as client:
        return await client.get(URL)
