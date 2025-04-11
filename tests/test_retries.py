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
from tenacity import RetryError

from ghga_datasteward_kit.s3_upload import LegacyConfig
from ghga_datasteward_kit.s3_upload.http_client import configure_retries, httpx_client
from tests.fixtures.config import legacy_config_fixture  # noqa: F401

EXCEPTIONS = [httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException]
STATUS_CODES = [408, 500, 502, 503, 504]
URL = "http://not-a-real-url/test"


@pytest.mark.httpx_mock(
    assert_all_responses_were_requested=False, can_send_already_matched_responses=True
)
@pytest.mark.asyncio
async def test_retry_handler(legacy_config_fixture: LegacyConfig, httpx_mock):  # noqa: F811
    """Test if configuration is correctly applied to retry handler"""
    retry_handler = configure_retries(legacy_config_fixture)

    for status_code in STATUS_CODES:
        httpx_mock.add_response(url=URL, status_code=status_code)
        with pytest.raises(RetryError):
            await retry_handler(fn=_run_request)

    httpx_mock.add_response(url=URL, status_code=200)
    for exception in EXCEPTIONS:
        with pytest.raises(RetryError):
            await retry_handler(
                fn=_run_request, exception=exception("Expected exception")
            )

    with pytest.raises(ValueError):
        await retry_handler(fn=_run_request, exception=ValueError("Expected exception"))

    await retry_handler(fn=_run_request)


async def _run_request(exception: Exception | None = None):
    """Dummy request for testing"""
    if exception:
        raise exception

    async with httpx_client() as client:
        return await client.get(URL)
