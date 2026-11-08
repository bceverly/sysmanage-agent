# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Keep each message until the server says it is stored (2026-11-06).

The agent deleted a message once the WebSocket write succeeded, so one sent
while the server's database was down was lost from both ends.  Now, against
a server that confirms, a sent message waits as ``sent`` until
``message_stored`` names it, and goes back to pending -- without spending a
retry -- when no confirmation comes or the connection changes."""

# pylint: disable=redefined-outer-name,protected-access

import asyncio
import logging
import os
import tempfile
from types import SimpleNamespace

import pytest

from src.database.base import DatabaseManager
from src.database.models import MessageQueue, QueueDirection, QueueStatus
from src.database.queue_manager import MessageQueueManager
from src.sysmanage_agent.communication import delivery_confirmation as delivery
from src.sysmanage_agent.communication.message_handler_queue import (
    MessageHandlerQueueMixin,
)


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


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _Handler(MessageHandlerQueueMixin):
    def __init__(self, queue_manager, confirms=True):
        self.queue_manager = queue_manager
        self.logger = logging.getLogger("test")
        self.agent = SimpleNamespace(connected=True)
        self.clock = _Clock()
        self.delivery = delivery.Awaiting(clock=self.clock)
        self.delivery.server_says({delivery.FLAG: 1} if confirms else {})
        self.written = []

    async def send_message_direct(self, message):
        self.written.append(message)
        return True


def _queue(manager, wire_id="w-1", message_type="command_result"):
    return manager.enqueue_message(
        message_type=message_type,
        message_data={"message_type": message_type, "message_id": wire_id, "data": {}},
        direction=QueueDirection.OUTBOUND,
    )


def _row(manager, queue_id):
    with manager.get_session() as session:
        row = session.query(MessageQueue).filter_by(message_id=queue_id).first()
        return None if row is None else (row.status, row.retry_count)


def _send_next(handler):
    (message,) = handler.queue_manager.dequeue_messages(QueueDirection.OUTBOUND)
    assert asyncio.run(handler._process_single_outbound_message(message)) is False


def test_a_sent_message_is_kept_until_the_server_stores_it(queue_manager):
    handler = _Handler(queue_manager)
    queue_id = _queue(queue_manager)
    _send_next(handler)
    assert _row(queue_manager, queue_id) == (QueueStatus.SENT.value, 0)
    handler.delivery_confirmed({"data": {"message_id": "w-1", "status": "stored"}})
    assert _row(queue_manager, queue_id) is None


def test_no_confirmation_sends_it_again_without_spending_a_retry(queue_manager):
    """The database was down: the server stored nothing and said nothing."""
    handler = _Handler(queue_manager)
    queue_id = _queue(queue_manager)
    _send_next(handler)
    handler.clock.now += delivery.CONFIRM_TIMEOUT_SECONDS
    handler._resend_unconfirmed()
    assert _row(queue_manager, queue_id) == (QueueStatus.PENDING.value, 0)
    _send_next(handler)  # and once more, still waiting -- never expired
    assert len(handler.written) == 2


def test_a_new_connection_sends_everything_unconfirmed_again(queue_manager):
    handler = _Handler(queue_manager)
    queue_id = _queue(queue_manager)
    _send_next(handler)
    handler.delivery.reset()
    assert queue_manager.requeue_unconfirmed() == 1
    assert _row(queue_manager, queue_id) == (QueueStatus.PENDING.value, 0)


def test_rows_left_sent_by_an_earlier_run_are_sent_again(queue_manager):
    queue_id = _queue(queue_manager)
    _send_next(_Handler(queue_manager))
    handler = _Handler(queue_manager)  # a restarted agent: tracks nothing
    handler._resend_unconfirmed()
    assert _row(queue_manager, queue_id) == (QueueStatus.PENDING.value, 0)


def test_a_rejected_message_is_kept_as_failed_and_not_resent(queue_manager):
    handler = _Handler(queue_manager)
    queue_id = _queue(queue_manager)
    _send_next(handler)
    handler.delivery_confirmed({"data": {"message_id": "w-1", "status": "rejected"}})
    assert _row(queue_manager, queue_id)[0] == QueueStatus.FAILED.value
    assert queue_manager.dequeue_messages(QueueDirection.OUTBOUND) == []


def test_an_older_server_is_treated_as_before(queue_manager):
    handler = _Handler(queue_manager, confirms=False)
    queue_id = _queue(queue_manager)
    _send_next(handler)
    assert _row(queue_manager, queue_id) is None


def test_two_acknowledgments_of_one_command_are_both_confirmed(queue_manager):
    """A command acknowledgment carries the command's id on the wire."""
    handler = _Handler(queue_manager)
    first = _queue(queue_manager, "cmd-1", "command_acknowledgment")
    _send_next(handler)
    second = _queue(queue_manager, "cmd-1", "command_acknowledgment")
    _send_next(handler)
    handler.delivery_confirmed({"data": {"message_id": "cmd-1", "status": "stored"}})
    assert _row(queue_manager, first) is None and _row(queue_manager, second) is None


def test_a_server_that_stops_confirming_lets_waiting_rows_go():
    awaiting = delivery.Awaiting()
    awaiting.server_says({delivery.FLAG: 1})
    assert awaiting.sent("w", "q")
    awaiting.server_says({})
    assert not awaiting.enabled and awaiting.tracked() == []
    assert not awaiting.sent("w", "q")


def test_system_info_says_the_agent_waits_for_confirmation():
    from src.sysmanage_agent.communication.message_handler import (  # noqa: PLC0415
        MessageHandler,
    )

    handler = MessageHandler.__new__(MessageHandler)
    handler.logger = logging.getLogger("test")
    handler.agent = SimpleNamespace(
        registration=SimpleNamespace(get_system_info=lambda: {"hostname": "h"}),
        _logging_overrides=None,
    )
    handler.create_message = lambda kind, data=None: {
        "message_type": kind,
        "data": data,
    }
    assert handler.create_system_info_message()["data"][delivery.FLAG] == 1
