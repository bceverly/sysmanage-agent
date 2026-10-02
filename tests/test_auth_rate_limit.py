# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22.2: the agent's side of the identity-keyed connection limit.

The agent tells /agent/auth who it is (host id + token) so the server limits
it per host instead of per NAT address, and on a 429 it waits the server's
Retry-After -- jittered -- instead of its own back-off.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.core.auth_helper import (
    AuthenticationHelper,
    AuthRateLimited,
    _retry_after,
)


class _Response:
    def __init__(self, status, headers=None, body=None):
        self.status = status
        self.headers = headers or {}
        self._body = body or {}

    async def json(self):
        return self._body

    async def text(self):
        return "busy"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class _Session:
    def __init__(self, response, seen):
        self._response = response
        self._seen = seen

    def post(self, _url, headers=None, proxy=None):  # pylint: disable=unused-argument
        self._seen.update(headers or {})
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


def _helper(host_id="h-1", host_token="tok"):
    agent = MagicMock()
    agent.config.get_server_config.return_value = {"hostname": "srv", "port": 8080}
    agent.get_stored_host_id_sync.return_value = host_id
    agent.get_stored_host_token_sync.return_value = host_token
    return AuthenticationHelper(agent, MagicMock())


async def _fetch(helper, response):
    seen = {}
    with patch(
        "src.sysmanage_agent.core.auth_helper.aiohttp.ClientSession",
        return_value=_Session(response, seen),
    ):
        try:
            return await helper.get_auth_token(), seen
        except AuthRateLimited as error:
            return error, seen


@pytest.mark.asyncio
async def test_a_registered_agent_says_who_it_is():
    helper = _helper()
    token, seen = await _fetch(helper, _Response(200, body={"connection_token": "t"}))
    assert token == "t"
    assert seen["x-host-id"] == "h-1" and seen["x-host-token"] == "tok"


@pytest.mark.asyncio
async def test_an_unregistered_agent_sends_no_identity():
    helper = _helper(host_id=None, host_token=None)
    _token, seen = await _fetch(helper, _Response(200, body={"connection_token": "t"}))
    assert "x-host-id" not in seen and "x-host-token" not in seen


@pytest.mark.asyncio
async def test_a_429_sets_a_jittered_wait_from_retry_after():
    helper = _helper()
    error, _seen = await _fetch(helper, _Response(429, headers={"Retry-After": "120"}))
    assert isinstance(error, AuthRateLimited) and isinstance(error, ConnectionError)
    assert 120 <= error.retry_after <= 144
    assert 110 <= helper.wait_hint() <= 144


def test_no_wait_without_a_429():
    assert _helper().wait_hint() == 0.0


@pytest.mark.parametrize("header,expected", [("90", 90.0), ("junk", 60.0),
                                             ("0", 1.0)])  # fmt: skip
def test_retry_after_parsing(header, expected):
    assert _retry_after(_Response(429, headers={"Retry-After": header})) == expected


def test_an_identity_lookup_failure_sends_no_identity():
    helper = _helper()
    helper.agent.get_stored_host_id_sync.side_effect = RuntimeError("db locked")
    assert helper._identity_headers() == {}  # pylint: disable=protected-access
