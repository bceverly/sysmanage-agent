# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Integration tests for agent-side reconnect resilience.

Phase 7 hardened the SERVER's WebSocket handling under reconnect storms,
ordering, and back-pressure (sysmanage repo, tests/load/run.py).  This
file is the agent-side mirror:  does the agent itself recover gracefully
when the server goes away, and does its backoff actually follow an
exponential curve?

The tests target ``SysManageAgent._handle_connection_error()`` directly
because driving the full ``run()`` loop in a test would require booting
a real server, a real config, and a real DB -- too much surface for
what's fundamentally a "did the math change?" check.

Tagged ``@pytest.mark.integration`` so the existing CI workflow that
filters on that marker picks them up.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access,redefined-outer-name

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def reconnect_agent(agent):
    """Adapt the shared `agent` fixture for reconnect-resilience tests.

    Stubs out the message-handler hook so on_connection_lost() is a
    no-op -- we don't want to test message-pipeline cleanup here, just
    the backoff math and the loop-control return value.

    Also forces ``should_auto_reconnect()`` to True so the helper
    actually reaches the sleep / retry path (the test config defaults
    to False, which would short-circuit every backoff test).  Tests
    that need the False path patch it back individually."""
    agent.message_handler.on_connection_lost = AsyncMock()
    agent.connection_failures = 0
    agent.config.should_auto_reconnect = lambda: True
    return agent


@pytest.mark.integration
class TestReconnectBackoffMath:
    """Full jitter (server Phase 22.1, ``core/backoff.py``): each wait is
    uniform in [1 s, min(300 s, max(base, 1 s) x 2^failures)].  The old
    x U(0.5, 1.5) band kept a fleet that failed together in clumps."""

    @staticmethod
    async def _delays(agent, base, failures, samples=200):
        delays = []
        with patch("main.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
            for _ in range(samples):
                agent.connection_failures = failures - 1
                await agent._handle_connection_error(base_reconnect_interval=base)
                delays.append(sleep_mock.call_args.args[0])
        return delays

    @pytest.mark.asyncio
    async def test_first_failure_waits_within_the_first_window(self, reconnect_agent):
        delays = await self._delays(reconnect_agent, 5.0, 1)
        assert reconnect_agent.connection_failures == 1
        assert all(1.0 <= d <= 10.0 for d in delays)  # 5 x 2^1

    @pytest.mark.asyncio
    async def test_the_window_grows_exponentially(self, reconnect_agent):
        early = await self._delays(reconnect_agent, 5.0, 1)
        later = await self._delays(reconnect_agent, 5.0, 4)
        assert max(early) <= 10.0 < max(later) <= 80.0

    @pytest.mark.asyncio
    async def test_a_crowd_spreads_over_the_whole_window(self, reconnect_agent):
        """Agents that failed in the same second must not return together."""
        delays = await self._delays(reconnect_agent, 5.0, 4)
        assert min(delays) < 20.0 and max(delays) > 60.0

    @pytest.mark.asyncio
    async def test_capped_at_300_seconds(self, reconnect_agent):
        delays = await self._delays(reconnect_agent, 10000.0, 11, samples=50)
        assert all(1.0 <= d <= 300.0 for d in delays)


@pytest.mark.integration
class TestReconnectLoopControl:
    """Tests the OTHER signal _handle_connection_error returns:  False
    means "stop the loop"; True means "sleep and retry"."""

    @pytest.mark.asyncio
    async def test_auto_reconnect_disabled_returns_false(self, reconnect_agent):
        """If config.should_auto_reconnect() returns False, the helper
        must signal "give up" so the run loop exits cleanly."""
        with patch.object(
            reconnect_agent.config, "should_auto_reconnect", return_value=False
        ):
            with patch("main.asyncio.sleep", new_callable=AsyncMock):
                proceed = await reconnect_agent._handle_connection_error(
                    base_reconnect_interval=0.01
                )
        assert proceed is False
        # Failure counter still increments (bookkeeping is the same;
        # the only difference is the early-exit return).
        assert reconnect_agent.connection_failures == 1

    @pytest.mark.asyncio
    async def test_state_reset_on_failure(self, reconnect_agent):
        """Sanity: connected/running/websocket are all reset, regardless
        of whether we go on to retry."""
        reconnect_agent.connected = True
        reconnect_agent.running = True
        reconnect_agent.websocket = object()
        with patch("main.asyncio.sleep", new_callable=AsyncMock):
            await reconnect_agent._handle_connection_error(base_reconnect_interval=0.01)
        assert reconnect_agent.connected is False
        assert reconnect_agent.running is False
        assert reconnect_agent.websocket is None

    @pytest.mark.asyncio
    async def test_message_handler_notified_of_disconnect(self, reconnect_agent):
        """on_connection_lost must fire so the message pipeline can
        flush any in-flight outbound messages.  Failure to call it
        leaves the queue in an inconsistent state across reconnects."""
        with patch("main.asyncio.sleep", new_callable=AsyncMock):
            await reconnect_agent._handle_connection_error(base_reconnect_interval=0.01)
        reconnect_agent.message_handler.on_connection_lost.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_message_handler_failure_does_not_break_reconnect(
        self, reconnect_agent
    ):
        """If on_connection_lost itself raises, the reconnect path must
        still proceed -- losing the cleanup hook is bad, losing the
        whole agent is worse."""
        reconnect_agent.message_handler.on_connection_lost = AsyncMock(
            side_effect=RuntimeError("simulated cleanup failure")
        )
        with patch("main.asyncio.sleep", new_callable=AsyncMock):
            proceed = await reconnect_agent._handle_connection_error(
                base_reconnect_interval=0.01
            )
        # The helper logs the error and returns True so the loop retries.
        assert proceed is True
