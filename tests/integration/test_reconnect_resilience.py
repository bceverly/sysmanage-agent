"""
Integration tests for agent-side reconnect resilience.

Phase 7 hardened the SERVER's WebSocket handling under reconnect storms,
ordering, and back-pressure (sysmanage repo, tests/load/run.py).  This
file is the agent-side mirror:  does the agent itself recover gracefully
when the server goes away, and does its backoff actually follow an
exponential curve?

The tests target ``SysManageAgent._handle_connection_error()`` directly
because driving the full ``run()`` loop in a test would require booting
a real server, a real config, and a real DB — too much surface for
what's fundamentally a "did the math change?" check.

Tagged ``@pytest.mark.integration`` so the existing CI workflow that
filters on that marker picks them up.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,protected-access,redefined-outer-name

from unittest.mock import AsyncMock, patch

import pytest

# Acceptable jitter band:  the implementation multiplies the base
# exponential by a uniform [0.5, 1.5).  Tests assert the captured
# sleep duration falls inside [exp * 0.5, exp * 1.5].
_JITTER_LO = 0.5
_JITTER_HI = 1.5


@pytest.fixture
def reconnect_agent(agent):
    """Adapt the shared `agent` fixture for reconnect-resilience tests.

    Stubs out the message-handler hook so on_connection_lost() is a
    no-op — we don't want to test message-pipeline cleanup here, just
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
    """The backoff formula from main.py:732-737:

        interval = min(base * 2 ** min(failures, 6), 300) * jitter

    where jitter ∈ [0.5, 1.5).  These tests pin the contract."""

    @pytest.mark.asyncio
    async def test_first_failure_uses_short_delay(self, reconnect_agent):
        """1 failure → base * 2 * jitter ≈ 0.01 to 0.03 seconds."""
        with patch("main.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
            proceed = await reconnect_agent._handle_connection_error(
                base_reconnect_interval=0.01
            )
        assert proceed is True
        assert reconnect_agent.connection_failures == 1
        slept = sleep_mock.call_args.args[0]
        # failures=1 → exp = 0.01 * 2 = 0.02; with jitter [0.5, 1.5)
        # → expected ∈ [0.01, 0.03)
        assert _JITTER_LO * 0.02 <= slept < _JITTER_HI * 0.02

    @pytest.mark.asyncio
    async def test_backoff_grows_exponentially(self, reconnect_agent):
        """Walk the failure counter 1..6 and verify each step is
        roughly 2x the previous (modulo jitter)."""
        delays = []
        with patch("main.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
            for _ in range(6):
                await reconnect_agent._handle_connection_error(
                    base_reconnect_interval=0.01
                )
                delays.append(sleep_mock.call_args.args[0])
        assert reconnect_agent.connection_failures == 6
        # Each step's lower bound (delay * 0.5) must exceed the previous
        # step's upper bound (delay * 1.5 / 2) — IF the implementation is
        # truly exponential.  Express it without jitter assumptions:
        # successive expected values are 0.02, 0.04, 0.08, 0.16, 0.32, 0.64
        exp_centers = [0.02, 0.04, 0.08, 0.16, 0.32, 0.64]
        for actual, center in zip(delays, exp_centers):
            assert _JITTER_LO * center <= actual < _JITTER_HI * center, (
                f"step delay {actual:.4f}s not in jitter band around {center:.4f}s "
                f"— exponential backoff may have regressed"
            )

    @pytest.mark.asyncio
    async def test_exponent_caps_at_six(self, reconnect_agent):
        """failures=10 should yield the same expected delay as
        failures=6 (the implementation caps the exponent)."""
        # Drive failures up to 10 directly, then call once more.
        reconnect_agent.connection_failures = 10
        with patch("main.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
            await reconnect_agent._handle_connection_error(base_reconnect_interval=0.01)
        slept = sleep_mock.call_args.args[0]
        # Expected center: 0.01 * 2**6 = 0.64 (the cap).  Note:  the
        # 300-second outer cap doesn't engage here because base is small.
        assert _JITTER_LO * 0.64 <= slept < _JITTER_HI * 0.64

    @pytest.mark.asyncio
    async def test_outer_cap_at_300_seconds(self, reconnect_agent):
        """A pathologically large base must be capped at 300 s before
        jitter, so the post-jitter result is < 300 * 1.5 = 450 s."""
        reconnect_agent.connection_failures = 6
        with patch("main.asyncio.sleep", new_callable=AsyncMock) as sleep_mock:
            await reconnect_agent._handle_connection_error(
                base_reconnect_interval=10000.0
            )
        slept = sleep_mock.call_args.args[0]
        # Pre-jitter would be 10000 * 64 = 640000; capped at 300.
        # Post-jitter ∈ [150, 450].
        assert 150.0 <= slept < 450.0


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
        still proceed — losing the cleanup hook is bad, losing the
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
