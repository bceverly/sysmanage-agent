# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22.2: the send-on-change memory survives an agent restart.

It was in-process, so every agent restart -- a fleet-wide upgrade, a reboot --
sent every report again: the whole fleet's inventory at once.  Real database
(a temp SQLite file), not mocks.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from src.database import sent_reports
from src.database.base import DatabaseManager
from src.sysmanage_agent.communication.send_on_change import (
    RESEND_AFTER,
    SnapshotGate,
    forced,
)

REPORT = {"message_type": "hardware_update", "data": {"cpu": "x86_64", "ram": 8}}


@pytest.fixture
def dbm():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    manager = DatabaseManager(path)
    manager.create_tables()
    with patch("src.database.sent_reports.get_database_manager", return_value=manager):
        yield manager
    manager.close()
    os.unlink(path)


class _Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def _send(gate, report=None):
    report = report or REPORT
    send, fingerprint = gate.decide(report)
    if send:
        gate.record(report["message_type"], fingerprint)
    return send


def test_a_restarted_agent_does_not_resend_unchanged_reports(dbm):
    clock = _Clock()
    assert _send(SnapshotGate(clock=clock, store=sent_reports)) is True
    restarted = SnapshotGate(clock=clock, store=sent_reports)  # a new process
    assert _send(restarted) is False


def test_a_changed_report_is_still_sent_after_a_restart(dbm):
    clock = _Clock()
    _send(SnapshotGate(clock=clock, store=sent_reports))
    changed = {**REPORT, "data": {"cpu": "x86_64", "ram": 16}}
    assert _send(SnapshotGate(clock=clock, store=sent_reports), changed) is True


def test_the_daily_resend_still_happens_across_a_restart(dbm):
    clock = _Clock()
    _send(SnapshotGate(clock=clock, store=sent_reports))
    clock.now += RESEND_AFTER + 1
    assert _send(SnapshotGate(clock=clock, store=sent_reports)) is True


def test_a_clock_that_went_backwards_makes_the_report_due(dbm):
    clock = _Clock()
    _send(SnapshotGate(clock=clock, store=sent_reports))
    clock.now -= 3600
    assert _send(SnapshotGate(clock=clock, store=sent_reports)) is True


def test_reset_forgets_on_disk_too(dbm):
    clock = _Clock()
    gate = SnapshotGate(clock=clock, store=sent_reports)
    _send(gate)
    gate.reset()  # new identity / just approved
    assert sent_reports.load() == {}
    assert _send(SnapshotGate(clock=clock, store=sent_reports)) is True


def test_the_server_asking_always_gets_it(dbm):
    clock = _Clock()
    _send(SnapshotGate(clock=clock, store=sent_reports))
    with forced():
        assert _send(SnapshotGate(clock=clock, store=sent_reports)) is True


def test_an_unreadable_store_sends_everything():
    with patch(
        "src.database.sent_reports.get_database_manager",
        side_effect=RuntimeError("db locked"),
    ):
        gate = SnapshotGate(clock=_Clock(), store=sent_reports)
        assert _send(gate) is True  # fails open, and the record does not raise
        assert _send(gate) is False  # this process still remembers
