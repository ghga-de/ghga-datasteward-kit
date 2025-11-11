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
from ghga_service_commons.transports import (
    AsyncRetryTransport,
    CompositeTransportFactory,
)

from ghga_datasteward_kit import __version__
from ghga_datasteward_kit.s3_upload.config import LegacyConfig

USER_AGENT = f"GHGADatastewardKit/{__version__}"


class RequestConfigurator:
    """Helper for user configurable httpx request parameters."""

    timeout: int | None
    transport: AsyncRetryTransport

    @classmethod
    def configure(cls, config: LegacyConfig):
        """Set timeout in seconds"""
        cls.timeout = config.client_timeout
        cls.transport = CompositeTransportFactory.create_ratelimiting_retry_transport(
            config,
            limits=httpx.Limits(
                max_connections=config.client_max_parallel_transfers,
                max_keepalive_connections=config.client_max_parallel_transfers,
            ),
        )
        # silence httpx messages on each request due to setting global level info before
        logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def httpx_client():
    """Yields a context manager httpx client and closes it afterward"""
    async with httpx.AsyncClient(
        headers=httpx.Headers({"User-Agent": USER_AGENT}),
        timeout=RequestConfigurator.timeout,
        transport=RequestConfigurator.transport,
    ) as client:
        yield client
