# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Talk to the server over ordinary POSTs when a WebSocket cannot get through.

WHY
---
Some corporate proxies refuse to tunnel a WebSocket Upgrade.  Measured against a
real HTTP CONNECT proxy that answers the tunnel request with 403, the agent gets
``InvalidProxyStatus: proxy rejected connection: HTTP 403`` and has no connection
at all -- no commands, no inventory, no heartbeat, and a host that is simply
invisible until someone changes a proxy policy.

The port was never the problem there; the *protocol* was.  This module carries
the same traffic over the same origin using request/response POSTs, which is the
one shape middleboxes reliably pass.

HOW IT STAYS HONEST
-------------------
It is a transport, not a second implementation.  Received messages go through
``message_handler._dispatch_received_message`` -- the very function the
WebSocket receive loop calls -- so a command behaves identically no matter which
pipe delivered it.  Outbound messages come off the same local queue the
WebSocket sender drains.  Nothing downstream can tell the difference, which is
what stops the two paths from quietly diverging.

WHAT IT COSTS
-------------
Latency and requests.  A server-initiated command waits up to one poll interval
instead of arriving immediately, and an idle agent still talks every few seconds.
That is why this is a fallback rather than the default, why it is entered only
on repeated structural evidence (see ``transport_fallback``), and why it hands
control back periodically so a fixed proxy is noticed rather than silently
tolerated forever.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

import aiohttp

from src.i18n import _
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint

# Outbound messages sent per poll.  Matches the server's per-poll ceiling so a
# backlog drains at the same rate in both directions.
MAX_OUTBOUND_PER_POLL = 50

# Used when the server's response carries no interval (an older build, or a
# response that failed to parse).  Short enough to stay responsive, long enough
# not to hammer.
DEFAULT_POLL_INTERVAL = 5

# Back-off after a failed poll.  The server may be restarting; polling harder
# helps nobody.
ERROR_POLL_INTERVAL = 15


class HttpPollingTransport:
    """Drains both directions over ``POST /api/agent/poll``."""

    def __init__(self, agent):
        self.agent = agent
        self.logger = agent.logger

    def _host_id(self) -> str | None:
        """The host this agent registered as.

        Polling requires it: without a WebSocket there is no connection object
        for the server to associate messages with, so the host must name itself.
        An unregistered agent cannot poll -- but registration is plain REST and
        therefore already proxy-safe, so it can always get that far first.
        """
        try:
            return self.agent.registration_manager.get_stored_host_id_sync()
        except Exception:  # pylint: disable=broad-except
            self.logger.exception(_("Could not read the stored host_id for polling"))
            return None

    def _collect_outbound(self) -> List[Dict[str, Any]]:
        """Take queued agent->server messages off the local queue."""
        from src.database.queue_manager import (  # noqa: PLC0415
            QueueDirection,
        )

        try:
            queued = self.agent.queue_manager.dequeue_messages(
                direction=QueueDirection.OUTBOUND, limit=MAX_OUTBOUND_PER_POLL
            )
        except Exception:  # pylint: disable=broad-except
            self.logger.exception(_("Could not read the outbound queue for polling"))
            return []

        messages = []
        for item in queued:
            messages.append(
                {
                    "message_type": item.message_type,
                    "data": item.message_data,
                    "message_id": item.message_id,
                }
            )
        return messages

    def _mark_delivered(self, messages: List[Dict[str, Any]]) -> None:
        """Only after the server has accepted them.

        Marking before the POST would lose every message in a batch whenever a
        poll failed -- exactly when delivery matters most.
        """
        for message in messages:
            try:
                self.agent.queue_manager.mark_completed(message["message_id"])
            except Exception:  # pylint: disable=broad-except
                self.logger.exception(
                    _("Could not mark polled message %s delivered"),
                    message.get("message_id"),
                )

    async def _post(self, session, endpoint, host_id, outbound):
        url = endpoint.rest_url("/api/agent/poll")
        token = await self.agent.get_auth_token()
        payload = {"host_id": host_id, "messages": outbound}
        async with session.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            proxy=endpoint.proxy(),
        ) as response:
            if response.status != 200:
                body = (await response.text())[:200]
                raise ConnectionError(f"poll returned HTTP {response.status}: {body}")
            return await response.json()

    async def poll_once(self, session, endpoint, host_id) -> int:
        """One exchange.  Returns the interval the server asked us to wait."""
        outbound = self._collect_outbound()
        result = await self._post(session, endpoint, host_id, outbound)

        # The server accepted them; only now are they safely delivered.
        self._mark_delivered(outbound)

        for message in result.get("messages", []):
            # The SAME dispatcher the WebSocket receive loop uses, so a command
            # cannot behave differently for having arrived over HTTP.
            try:
                await self.agent.message_handler._dispatch_received_message(  # pylint: disable=protected-access
                    {
                        "message_type": message.get("message_type"),
                        "message_id": message.get("message_id"),
                        **(message.get("data") or {}),
                    }
                )
            except Exception:  # pylint: disable=broad-except
                self.logger.exception(
                    _("Error handling polled message %s"), message.get("message_id")
                )

        return int(result.get("poll_interval") or DEFAULT_POLL_INTERVAL)

    async def run_until_retest(self, state) -> None:
        """Poll until it is time to re-test whether the WebSocket works again.

        Returning rather than looping forever is deliberate: a proxy policy can
        be fixed, and an agent that never retried would stay on the slower
        transport indefinitely with nobody aware it had degraded.
        """
        host_id = self._host_id()
        if not host_id:
            self.logger.error(
                _(
                    "Cannot use the HTTP fallback: this agent has no stored host_id. "
                    "Registration must complete first."
                )
            )
            await asyncio.sleep(ERROR_POLL_INTERVAL)
            return

        endpoint = ServerEndpoint(self.agent.config)
        self.logger.warning(
            _(
                "Using HTTP polling instead of a WebSocket: this network refused the "
                "WebSocket upgrade. Commands will arrive with up to a few seconds of "
                "delay. Allow WebSocket upgrades to %s to restore immediate delivery."
            ),
            endpoint.base_url(),
        )
        self.agent.connected = True

        try:
            async with aiohttp.ClientSession(**endpoint.session_kwargs()) as session:
                while not state.should_retest_websocket(time.monotonic()):
                    try:
                        interval = await self.poll_once(session, endpoint, host_id)
                    except Exception as error:  # pylint: disable=broad-except
                        self.logger.warning(
                            _("Poll failed (%s); retrying in %ds"),
                            error,
                            ERROR_POLL_INTERVAL,
                        )
                        interval = ERROR_POLL_INTERVAL
                    await asyncio.sleep(interval)
        finally:
            self.agent.connected = False

        state.mark_retested(time.monotonic())
        self.logger.info(
            _("Re-testing whether this network now allows WebSocket connections")
        )
