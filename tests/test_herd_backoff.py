# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22.1: a fleet that fails together must not retry together.

* A 429 / 5xx on the WebSocket upgrade is the server saying "not now": it
  must not demote the agent to 15 minutes of HTTP polling, and its
  Retry-After is honored.
* Every retry path waits with full jitter: reconnect (wide first window after
  a clean close), registration (forever at startup), polling errors, the
  fallback re-test, outbound message retries.
* A failed health check goes through the backoff instead of a flat 5 s and is
  not recorded as a WebSocket success.

Real ``websockets`` exception objects, not mocks.
"""

# pylint: disable=protected-access

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosedError, InvalidStatus
from websockets.frames import Close
from websockets.http11 import Response

from src.sysmanage_agent.communication import transport_fallback as tf
from src.sysmanage_agent.core import backoff


def _rejected(status, retry_after=None):
    headers = Headers({"Retry-After": retry_after} if retry_after else {})
    return InvalidStatus(Response(status, "x", headers))


def _closed(code):
    return ConnectionClosedError(Close(code, "bye"), None)


# -- the WebSocket upgrade's status --------------------------------------------


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_a_busy_server_is_transient(status):
    assert tf.server_busy_status(_rejected(status)) == status
    assert not tf.is_structural_websocket_failure(_rejected(status))


@pytest.mark.parametrize("status", [400, 403, 404, 426])
def test_a_refusing_network_is_still_structural(status):
    assert tf.server_busy_status(_rejected(status)) is None
    assert tf.is_structural_websocket_failure(_rejected(status))


def test_overload_never_demotes_to_polling():
    state = tf.TransportState()
    for _ in range(10):
        assert state.record_websocket_failure(_rejected(503), now=0.0) is False
    assert not state.using_http_fallback
    for _ in range(2):  # a proxy that forbids WebSockets still falls back
        state.record_websocket_failure(_rejected(403), now=0.0)
    assert state.using_http_fallback


def test_retry_after_is_read_from_the_refusal():
    assert tf.retry_after_seconds(_rejected(503, "30")) == 30.0
    assert tf.retry_after_seconds(_rejected(429, "junk")) == 0.0
    assert tf.retry_after_seconds(_rejected(403, "30")) == 0.0  # not a busy server
    assert tf.retry_after_seconds(RuntimeError("boom")) == 0.0


def test_the_status_is_found_in_the_message_of_older_versions():
    assert tf.server_busy_status(Exception("server rejected ... HTTP 503")) == 503


def test_the_fallback_retest_is_jittered():
    retests = {tf.TransportState()._retest_after for _ in range(50)}
    assert len(retests) > 40
    base = tf.TransportState.RETEST_AFTER_SECONDS
    assert all(base * 0.8 <= r <= base * 1.2 for r in retests)


# -- the backoff ---------------------------------------------------------------


def test_full_jitter_spreads_over_the_window():
    waits = [backoff.full_jitter(5, 3) for _ in range(500)]
    assert all(1.0 <= w <= 40.0 for w in waits)
    assert min(waits) < 8 and max(waits) > 32


def test_a_clean_close_spreads_the_first_reconnect_wide():
    assert backoff.is_clean_close(_closed(1012))  # service restart
    assert backoff.is_clean_close(_closed(1001))  # going away
    assert not backoff.is_clean_close(_closed(1006))
    waits = [backoff.reconnect_delay(5, 1, clean_close=True) for _ in range(500)]
    assert max(waits) > 40 and all(
        w <= backoff.CLEAN_CLOSE_WINDOW_SECONDS for w in waits
    )


def test_a_server_hint_is_a_floor_with_jitter():
    waits = [backoff.reconnect_delay(5, 1, hint=120) for _ in range(200)]
    assert all(120 <= w <= 144 for w in waits)
    assert len(set(waits)) > 150


# -- the agent ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failed_health_check_is_a_failure_not_a_flat_retry(agent):
    with patch.object(agent, "_check_server_health", AsyncMock(return_value=False)):
        with pytest.raises(backoff.ServerUnavailable):
            await agent._establish_websocket_connection()


@pytest.mark.asyncio
async def test_a_503_is_backed_off_with_its_retry_after(agent):
    agent._note_websocket_failure(_rejected(503, "90"))
    assert not agent._transport_state.using_http_fallback
    with patch("main.asyncio.sleep", new_callable=AsyncMock) as sleep, patch.object(
        agent.config, "should_auto_reconnect", return_value=True
    ), patch.object(agent.message_handler, "on_connection_lost", AsyncMock()):
        await agent._handle_connection_error(base_reconnect_interval=5)
    assert 90 <= sleep.call_args.args[0] <= 108


@pytest.mark.asyncio
async def test_polling_errors_back_off_and_spread():
    from src.sysmanage_agent.communication import (  # pylint: disable=import-outside-toplevel
        http_polling,
    )

    transport = http_polling.HttpPollingTransport.__new__(
        http_polling.HttpPollingTransport
    )
    transport.agent = type("A", (), {"connected": False, "config": None})()
    transport.logger = __import__("logging").getLogger("t")
    transport._host_id = lambda: "h"
    transport.poll_once = AsyncMock(side_effect=RuntimeError("down"))
    state = tf.TransportState()
    state.using_http_fallback = True
    state._fell_back_at = __import__("time").monotonic()
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 6:
            state._fell_back_at = -(10**9)  # time to re-test: leave the loop

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

    with patch.object(http_polling.asyncio, "sleep", fake_sleep), patch.object(
        http_polling, "ServerEndpoint"
    ), patch.object(http_polling.aiohttp, "ClientSession", lambda **_: _Session()):
        await transport.run_until_retest(state)
    assert sleeps[0] <= http_polling.ERROR_POLL_INTERVAL
    assert max(sleeps) > http_polling.ERROR_POLL_INTERVAL  # grows
    assert len(set(sleeps)) == len(sleeps)  # jittered


def test_outbound_retries_are_jittered(tmp_path):
    """Messages that failed together (a server outage) must not all be
    retried in the same second."""
    from src.database.base import (
        DatabaseManager,
    )  # pylint: disable=import-outside-toplevel
    from src.database.queue_manager import (  # pylint: disable=import-outside-toplevel
        MessageQueueManager,
    )

    manager = MessageQueueManager()
    manager.db_manager = DatabaseManager(str(tmp_path / "q.db"))
    manager.db_manager.create_tables()
    ids = [manager.enqueue_message("hardware_update", {"n": i}, direction="outbound")
           for i in range(40)]  # fmt: skip
    before = datetime.now(timezone.utc).replace(tzinfo=None)
    for message_id in ids:
        assert manager.mark_failed(message_id, "server down")
    from src.database.models import (
        MessageQueue,
    )  # pylint: disable=import-outside-toplevel

    with manager.get_session() as session:
        waits = [
            (row.scheduled_at.replace(tzinfo=None) - before).total_seconds()
            for row in session.query(MessageQueue).all()
        ]
    manager.db_manager.close()
    assert all(0 <= w <= 61 for w in waits)  # first retry: within a minute
    assert len({round(w) for w in waits}) > 20  # spread, not all at 60 s
