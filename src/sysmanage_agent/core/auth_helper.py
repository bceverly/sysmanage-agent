# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Connection-token management for the agent's server transports.

Moved out of ``agent_utils`` (which re-exports it) when token caching pushed
that module past the 1000-line limit.
"""

import logging
import secrets
import socket
import time
from typing import Optional

import aiohttp

from src.i18n import _
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint


class AuthRateLimited(ConnectionError):
    """The server said "too many attempts; come back in ``retry_after`` s"."""

    def __init__(self, retry_after: float, detail: str):
        super().__init__(detail)
        self.retry_after = retry_after


def _retry_after(response, default: float = 60.0) -> float:
    try:
        return max(1.0, float(response.headers.get("Retry-After", default)))
    except (TypeError, ValueError):
        return default


class AuthenticationHelper:
    """Handles authentication token management."""

    # Refresh this long before the server's expiry, so a token is never used
    # in the last minutes of its life (clock skew, a slow poll).
    TOKEN_REFRESH_MARGIN = 300

    def __init__(self, agent, logger: logging.Logger):
        self.agent = agent
        self.logger = logger
        self._token: Optional[str] = None
        self._token_good_until = 0.0
        # Server Phase 22.2: after a 429 the reconnect waits at least this
        # long (the server's Retry-After plus jitter, so a refused crowd does
        # not come back in the same second).
        self._not_before = 0.0

    def wait_hint(self) -> float:
        """Seconds the server asked us to wait before the next attempt."""
        return max(0.0, self._not_before - time.monotonic())

    def _identity_headers(self) -> dict:
        """Who we are, for the server's per-host connection limit (Phase
        22.2): behind NAT every agent shares one address, so a per-address
        limit locked out the 21st.  Absent before registration."""
        headers = {}
        try:
            host_id = self.agent.get_stored_host_id_sync()
            host_token = self.agent.get_stored_host_token_sync()
        except Exception:  # pylint: disable=broad-exception-caught
            return headers
        if host_id and host_token:
            headers = {"x-host-id": str(host_id), "x-host-token": str(host_token)}
        return headers

    def invalidate_auth_token(self) -> None:
        """Forget the cached token (the server rejected it, or it rotated)."""
        self._token = None
        self._token_good_until = 0.0

    def build_auth_url(self) -> str:
        """Build authentication URL from server config."""
        return ServerEndpoint(self.agent.config).rest_url("/api/agent/auth")

    async def get_auth_token(self) -> str:
        """A connection token, reused until shortly before it expires.

        Fetched once per token lifetime, not once per use: the HTTP poll loop
        used to fetch one every 5 seconds, which tripped the server's
        20-per-15-minutes connection limit and then kept the agent locked out
        of the WebSocket too (found 2026-09-29).
        """
        now = time.monotonic()
        if self._token and now < self._token_good_until:
            return self._token
        endpoint = ServerEndpoint(self.agent.config)
        auth_url = endpoint.rest_url("/api/agent/auth")

        # Get hostname to send in header
        system_hostname = socket.gethostname()

        async with aiohttp.ClientSession(**endpoint.session_kwargs()) as session:
            headers = {"x-agent-hostname": system_hostname}
            headers.update(self._identity_headers())

            async with session.post(
                auth_url, headers=headers, proxy=endpoint.proxy()
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    token = data.get("connection_token")
                    if not token:
                        # An older server answers a rate limit with 200 and an
                        # error body.  Returning "" here opened a WebSocket with
                        # an empty token, whose rejection read as "this network
                        # blocks WebSockets" and demoted the agent to polling.
                        raise ConnectionError(
                            _("Auth refused by server: %s")
                            % data.get("error", _("no connection token"))
                        )
                    lifetime = int(data.get("expires_in") or 3600)
                    self._token = token
                    self._token_good_until = now + max(
                        0, lifetime - self.TOKEN_REFRESH_MARGIN
                    )
                    return token

                if response.status == 429:
                    spread = 1.0 + secrets.randbelow(201) / 1000.0  # 1.0 - 1.2
                    wait = _retry_after(response) * spread
                    self._not_before = time.monotonic() + wait
                    raise AuthRateLimited(
                        wait,
                        _("Auth failed with status %s: %s")
                        % (response.status, await response.text()),
                    )
                raise ConnectionError(
                    _("Auth failed with status %s: %s")
                    % (response.status, await response.text())
                )
