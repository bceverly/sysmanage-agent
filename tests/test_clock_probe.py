# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent's half of the clock-offset measurement (Phase 23.3 S1)."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.communication import clock_probe as cp


def _heartbeat():
    return {"message_type": "heartbeat", "data": {}}


def test_a_heartbeat_carries_the_receipt_out_once():
    probe = cp.ClockProbe()
    probe.received({"clock": {"t1": 1000.0}}, t2=1000.5, mono=50.0)
    with patch.object(cp.time, "monotonic", return_value=52.0), patch.object(
        cp.time, "time", return_value=1002.5
    ):
        sent = probe.stamp(_heartbeat())
    assert sent["clock"] == {"t1": 1000.0, "t2": 1000.5, "t3": 1002.5, "hold": 2.0}
    # Used once: the next heartbeat has nothing fresh to echo.
    assert "clock" not in probe.stamp(_heartbeat())


def test_the_server_formula_recovers_the_offset_despite_queue_time():
    """Host 3.0 s ahead, 40 ms each way, heartbeat queued 7 s before sending."""
    server_t1 = 1000.0
    t2 = server_t1 + 0.040 + 3.0  # arrives 40 ms later, read on a clock 3 s fast
    probe = cp.ClockProbe()
    probe.received({"clock": {"t1": server_t1}}, t2=t2, mono=10.0)
    with patch.object(cp.time, "monotonic", return_value=17.0), patch.object(
        cp.time, "time", return_value=t2 + 7.0
    ):
        clock = probe.stamp(_heartbeat())["clock"]
    t4 = (clock["t3"] - 3.0) + 0.040  # server receive, on the server's clock
    offset = ((clock["t2"] - clock["t1"]) + (clock["t3"] - t4)) / 2
    assert offset == pytest.approx(3.0)


def test_other_message_types_are_never_touched():
    probe = cp.ClockProbe()
    probe.received({"clock": {"t1": 1.0}}, t2=2.0, mono=time.monotonic())
    message = {"message_type": "hardware_update"}
    assert "clock" not in probe.stamp(message)
    assert "clock" in probe.stamp(_heartbeat())  # the receipt is still waiting


def test_an_old_server_that_sends_no_t1_gets_no_clock_block():
    probe = cp.ClockProbe()
    probe.received({"message_type": "command"}, t2=2.0, mono=0.0)
    probe.received({"clock": {"t1": "not a number"}}, t2=2.0, mono=0.0)
    probe.received({"clock": {"t1": True}}, t2=2.0, mono=0.0)
    probe.received(["not", "a", "dict"], t2=2.0, mono=0.0)
    assert "clock" not in probe.stamp(_heartbeat())


def test_a_stale_receipt_is_dropped_not_echoed():
    probe = cp.ClockProbe()
    probe.received({"clock": {"t1": 1.0}}, t2=2.0, mono=0.0)
    with patch.object(cp.time, "monotonic", return_value=cp.MAX_AGE + 1):
        assert "clock" not in probe.stamp(_heartbeat())
    assert "clock" not in probe.stamp(_heartbeat())


def test_the_newest_receipt_wins():
    probe = cp.ClockProbe()
    probe.received({"clock": {"t1": 1.0}}, t2=2.0, mono=time.monotonic())
    probe.received({"clock": {"t1": 5.0}}, t2=6.0, mono=time.monotonic())
    assert probe.stamp(_heartbeat())["clock"]["t1"] == 5.0


@pytest.mark.asyncio
async def test_the_socket_write_is_where_t3_is_stamped():
    """send_message_direct stamps at the moment of the write."""
    from src.sysmanage_agent.communication.message_handler_queue import (  # pylint: disable=import-outside-toplevel
        MessageHandlerQueueMixin,
    )

    handler = MessageHandlerQueueMixin()
    handler.agent = MagicMock(connected=True)
    handler.agent.websocket.send = AsyncMock()
    handler.logger = MagicMock()
    handler.clock_probe = cp.ClockProbe()
    handler.clock_probe.received({"clock": {"t1": 1.0}}, t2=2.0, mono=time.monotonic())
    assert await handler.send_message_direct(_heartbeat())
    sent = handler.agent.websocket.send.call_args.args[0]
    assert '"clock"' in sent and '"t3"' in sent
