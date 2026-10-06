# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22.1: a newer full-snapshot report replaces a queued older
one, so an agent back from an outage sends the current state once instead of
every report it queued while away."""

import os
import tempfile

import pytest

from src.database.base import DatabaseManager
from src.database.models import MessageQueue, QueueDirection, QueueStatus
from src.database.queue_manager import MessageQueueManager
from src.sysmanage_agent.communication import send_on_change


@pytest.fixture
def queue_manager():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    manager = MessageQueueManager()
    manager.db_manager = DatabaseManager(path)
    manager.db_manager.create_tables()
    yield manager
    manager.db_manager.close()
    os.unlink(path)


def _pending(manager, message_type):
    with manager.get_session() as session:
        return [
            row.message_id
            for row in session.query(MessageQueue).filter(
                MessageQueue.message_type == message_type,
                MessageQueue.status == QueueStatus.PENDING.value,
            )
        ]


def _queue(manager, message_type, n, supersede=True, direction=QueueDirection.OUTBOUND):
    return manager.enqueue_message(
        message_type=message_type,
        message_data={"n": n},
        direction=direction,
        supersede=supersede,
    )


def test_newest_snapshot_replaces_pending_ones(queue_manager):
    for n in range(5):
        newest = _queue(queue_manager, "hardware_update", n)
    assert _pending(queue_manager, "hardware_update") == [newest]


def test_other_types_are_untouched(queue_manager):
    _queue(queue_manager, "software_inventory_update", 1)
    _queue(queue_manager, "hardware_update", 1)
    _queue(queue_manager, "hardware_update", 2)
    assert len(_pending(queue_manager, "software_inventory_update")) == 1


def test_without_supersede_everything_is_kept(queue_manager):
    for n in range(3):
        _queue(queue_manager, "command_result", n, supersede=False)
    assert len(_pending(queue_manager, "command_result")) == 3


def test_a_message_being_sent_is_not_dropped(queue_manager):
    first = _queue(queue_manager, "hardware_update", 1)
    queue_manager.mark_processing(first)
    second = _queue(queue_manager, "hardware_update", 2)
    assert queue_manager.get_message(first) is not None
    assert _pending(queue_manager, "hardware_update") == [second]


def test_inbound_rows_are_not_touched(queue_manager):
    _queue(queue_manager, "hardware_update", 1, direction=QueueDirection.INBOUND)
    _queue(queue_manager, "hardware_update", 2)
    with queue_manager.get_session() as session:
        assert session.query(MessageQueue).count() == 2


class TestWhichTypesSupersede:
    def test_snapshots_and_heartbeats_do(self):
        assert send_on_change.supersedes("hardware_update")
        assert send_on_change.supersedes("child_host_list_update")
        assert send_on_change.supersedes("heartbeat")

    def test_samples_results_and_batches_do_not(self):
        # host_metrics: every sample is a point on a chart.
        assert not send_on_change.supersedes("host_metrics")
        assert not send_on_change.supersedes("command_result")
        assert not send_on_change.supersedes("script_execution_result")
        assert not send_on_change.supersedes("available_packages_batch")
        assert not send_on_change.supersedes("system_info")
