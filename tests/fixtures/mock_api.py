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

"""Helpers for mocking HTTP endpoints with the service commons `MockRouter`.

Mocking works differently than with the previously used `httpx_mock` fixture: requests
are matched on the endpoint path, so each endpoint a test touches needs its own
registration. Anything that is not registered raises instead of reaching the network.
"""

__all__ = [
    "ApiMock",
    "MockedEndpoint",
    "ResponseHandler",
    "fail_with",
    "respond",
]

from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from ghga_service_commons.api.mock_router import MockRouter

ResponseHandler = Callable[[httpx2.Request], httpx2.Response]


def respond(status_code: int, json: Any = None) -> ResponseHandler:
    """Make a handler that always answers with the same status code and JSON body.

    A `json` of `None` means the response carries no body at all.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status_code=status_code, json=json)

    return handler


def fail_with(error: Exception) -> ResponseHandler:
    """Make a handler that raises `error` instead of answering.

    Used to simulate transport level failures. For `httpx2.RequestError` subclasses the
    client attaches the offending request to the exception on its way out.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise error

    return handler


class MockedEndpoint:
    """A single mocked endpoint that records the requests it receives.

    Responses come from `handler`, which tests can reassign at any point to change how
    the endpoint answers the calls that follow.
    """

    def __init__(self, handler: ResponseHandler) -> None:
        self.handler = handler
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        """Record the request and let the currently assigned handler answer it."""
        self.requests.append(request)
        return self.handler(request)

    @property
    def call_count(self) -> int:
        """The number of requests that reached this endpoint."""
        return len(self.requests)


class ApiMock:
    """A mock of the HTTP endpoints exercised by a test.

    Register the endpoints with `add()`, then either mount `as_transport()` on a client
    or, for the synchronous code paths that build their own client, redirect them with
    `patch_httpx()`.
    """

    def __init__(self) -> None:
        self._router: MockRouter = MockRouter()

    def add(
        self, *, method: str, path: str, handler: ResponseHandler | None = None
    ) -> MockedEndpoint:
        """Register an endpoint under `method` and `path` and return it.

        `path` is matched against the end of the request URL. It defaults to answering
        with a bare 200 response.
        """
        endpoint = MockedEndpoint(handler or respond(200))

        def mocked_endpoint(request: httpx2.Request) -> httpx2.Response:
            return endpoint(request)

        register = getattr(self._router, method.lower())
        register(path)(mocked_endpoint)
        return endpoint

    def as_transport(self) -> httpx2.MockTransport:
        """Return a transport answering the registered endpoints with this mock."""
        return self._router.as_transport()

    def patch_httpx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Route the clients that `httpx2` hands out through this mock.

        The synchronous ingest and deletion paths instantiate their own client and take
        no transport, so there is no way to inject one from the outside.
        """
        transport = self.as_transport()
        # bound before patching, so the replacements below don't call themselves
        real_client = httpx2.Client

        def mocked_client(**kwargs: Any) -> httpx2.Client:
            return real_client(transport=transport, **kwargs)

        def mocked_get(url: Any, **kwargs: Any) -> httpx2.Response:
            with mocked_client() as client:
                return client.get(url, **kwargs)

        monkeypatch.setattr(httpx2, "Client", mocked_client)
        monkeypatch.setattr(httpx2, "get", mocked_get)
