# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Connection-token management for the agent's server transports.

Moved out of ``agent_utils`` (which re-exports it) when token caching pushed
that module past the 1000-line limit.
"""

import logging
import socket
import time
from typing import Optional

import aiohttp

from src.i18n import _
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint


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

                raise ConnectionError(
                    _("Auth failed with status %s: %s")
                    % (response.status, await response.text())
                )
