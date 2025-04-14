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
"""httpx client and retry functionality related code."""

import logging
from contextlib import asynccontextmanager

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    retry_if_result,
    stop_after_attempt,
    wait_exponential_jitter,
)

from ghga_datasteward_kit.s3_upload.config import LegacyConfig


class RequestConfigurator:
    """Helper for user configurable httpx request parameters."""

    timeout: int | None
    max_connections: int

    @classmethod
    def configure(cls, config: LegacyConfig):
        """Set timeout in seconds"""
        cls.timeout = config.client_timeout
        cls.max_connections = config.client_max_parallel_transfers
        # silence httpx messages on each request due to setting global level info before
        logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def httpx_client():
    """Yields a context manager httpx client and closes it afterward"""
    async with httpx.AsyncClient(
        timeout=RequestConfigurator.timeout,
        limits=httpx.Limits(
            max_connections=RequestConfigurator.max_connections,
            max_keepalive_connections=RequestConfigurator.max_connections,
        ),
    ) as client:
        yield client


def configure_retries(config: LegacyConfig):
    """Initialize retry handler from config"""
    return AsyncRetrying(
        retry=(
            retry_if_exception_type(
                (
                    httpx.ConnectError,
                    httpx.ConnectTimeout,
                    httpx.ReadError,
                    httpx.TimeoutException,
                )
            )
            | retry_if_result(
                lambda response: response.status_code
                in config.client_retry_status_codes
            )
        ),
        stop=stop_after_attempt(config.client_num_retries),
        wait=wait_exponential_jitter(max=config.client_exponential_backoff_max),
    )
