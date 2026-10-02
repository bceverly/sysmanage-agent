# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Send-on-change (server Phase 22.1): unchanged snapshot reports stay home."""

import asyncio
from unittest.mock import MagicMock

import pytest

from src.sysmanage_agent.communication import send_on_change as soc


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _report(kind="software_inventory_update", **data):
    payload = {"hostname": "h", "host_id": "1", "collection_timestamp": "t0"}
    payload.update(data)
    return {"message_type": kind, "message_id": "m", "data": payload}


def _send(gate, message):
    send, fingerprint = gate.decide(message)
    if send:
        gate.record(message["message_type"], fingerprint)
    return send


def test_an_unchanged_report_is_not_sent_again():
    gate = soc.SnapshotGate(Clock())
    assert _send(gate, _report(packages=["a"]))
    assert not _send(gate, _report(packages=["a"]))


def test_a_changed_report_is_sent():
    gate = soc.SnapshotGate(Clock())
    _send(gate, _report(packages=["a"]))
    assert _send(gate, _report(packages=["a", "b"]))


def test_timestamps_do_not_count_as_change():
    gate = soc.SnapshotGate(Clock())
    _send(gate, _report(packages=["a"], collection_timestamp="t0"))
    assert not _send(gate, _report(packages=["a"], collection_timestamp="t1"))


def test_an_unchanged_report_is_resent_after_a_day():
    clock = Clock()
    gate = soc.SnapshotGate(clock)
    _send(gate, _report(packages=["a"]))
    clock.now += soc.RESEND_AFTER - 1
    assert not _send(gate, _report(packages=["a"]))
    clock.now += 2
    assert _send(gate, _report(packages=["a"]))


def test_what_the_server_asks_for_is_always_sent():
    gate = soc.SnapshotGate(Clock())
    _send(gate, _report(packages=["a"]))
    with soc.forced():
        assert _send(gate, _report(packages=["a"]))
    assert not _send(gate, _report(packages=["a"]))


def test_forced_reaches_tasks_started_inside_it():
    gate = soc.SnapshotGate(Clock())
    _send(gate, _report(packages=["a"]))

    async def worker():
        return gate.decide(_report(packages=["a"]))[0]

    async def main():
        with soc.forced():
            task = asyncio.ensure_future(worker())
        return await task

    assert asyncio.run(main())


def test_reset_sends_everything_again():
    gate = soc.SnapshotGate(Clock())
    _send(gate, _report(packages=["a"]))
    gate.reset()
    assert _send(gate, _report(packages=["a"]))


def test_process_cpu_figures_alone_do_not_count_until_the_sample_interval():
    clock = Clock()
    gate = soc.SnapshotGate(clock)
    first = [{"pid": 1, "name": "sshd", "cpu_percent": 0.1}]
    busier = [{"pid": 1, "name": "sshd", "cpu_percent": 9.9}]
    _send(gate, _report("process_status_update", processes=first))
    assert not _send(gate, _report("process_status_update", processes=busier))
    clock.now += soc.SAMPLE_INTERVAL
    assert _send(gate, _report("process_status_update", processes=busier))


def test_a_new_process_counts_at_once():
    gate = soc.SnapshotGate(Clock())
    _send(gate, _report("process_status_update", processes=[{"pid": 1, "name": "a"}]))
    assert _send(gate, _report("process_status_update",
                               processes=[{"pid": 1, "name": "a"}, {"pid": 2, "name": "b"}]))  # fmt: skip


def test_metrics_are_samples_every_fifteen_minutes():
    clock = Clock()
    gate = soc.SnapshotGate(clock)
    assert _send(gate, _report("host_metrics", cpu=1))
    assert not _send(gate, _report("host_metrics", cpu=2))
    clock.now += soc.SAMPLE_INTERVAL
    assert _send(gate, _report("host_metrics", cpu=3))


def test_other_messages_are_never_held_back():
    gate = soc.SnapshotGate(Clock())
    for _ in range(3):
        assert _send(gate, {"message_type": "heartbeat", "data": {}})


@pytest.mark.asyncio
async def test_a_failed_queue_is_not_remembered():
    """Remembered only once queued: a failure must not suppress the retry."""
    from src.sysmanage_agent.communication.message_handler_queue import (
        MessageHandlerQueueMixin,
    )

    handler = MessageHandlerQueueMixin.__new__(MessageHandlerQueueMixin)
    handler.logger = MagicMock()
    handler.agent = MagicMock(connected=False)
    handler.queue_processor_running = False
    handler.queue_manager = MagicMock()
    handler.queue_manager.enqueue_message.side_effect = RuntimeError("disk full")
    with pytest.raises(RuntimeError):
        await handler.queue_outbound_message(_report(packages=["a"]))
    assert soc.gate.decide(_report(packages=["a"]))[0]
