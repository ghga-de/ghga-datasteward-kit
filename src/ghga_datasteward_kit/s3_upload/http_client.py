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
"""httpx2 client and retry functionality related code."""

import logging
from contextlib import asynccontextmanager

import httpx2
from ghga_service_commons.transports import (
    AsyncRetryTransport,
    CompositeTransportFactory,
    ratelimiting_retry_proxies,
)

from ghga_datasteward_kit import __version__
from ghga_datasteward_kit.s3_upload.config import LegacyConfig

USER_AGENT = f"GHGADatastewardKit/{__version__}"


class RequestConfigurator:
    """Helper for user configurable httpx2 request parameters."""

    timeout: int | None
    transport: AsyncRetryTransport
    mounts: dict | None

    @classmethod
    def configure(
        cls,
        config: LegacyConfig,
        base_transport: httpx2.AsyncBaseTransport | None = None,
    ):
        """Set timeout in seconds

        `base_transport` replaces the innermost transport that actually performs the
        request. It is meant for tests, which can supply a mock transport that still
        gets exercised through the rate limiting and retry layers.
        """
        cls.timeout = config.client_timeout
        limits = httpx2.Limits(
            max_connections=config.client_max_parallel_transfers,
            max_keepalive_connections=config.client_max_parallel_transfers,
        )
        cls.transport = CompositeTransportFactory.create_ratelimiting_retry_transport(
            config, base_transport=base_transport, limits=limits
        )
        cls.mounts = ratelimiting_retry_proxies(config, limits)
        # silence httpx2 messages on each request due to setting global level info before
        logging.getLogger("httpx2").setLevel(logging.WARNING)


@asynccontextmanager
async def httpx_client():
    """Yields a context manager httpx2 client and closes it afterward"""
    async with httpx2.AsyncClient(
        headers=httpx2.Headers({"User-Agent": USER_AGENT}),
        timeout=RequestConfigurator.timeout,
        transport=RequestConfigurator.transport,
        mounts=RequestConfigurator.mounts,
    ) as client:
        yield client
