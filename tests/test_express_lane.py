# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The inbound express lane (Phase 23.3 follow-up, found by the skew proof).

The inbound queue runs one command at a time.  On the x13s a fresh agent's
first package collection ran 11 minutes and a clock resync queued behind it
timed out on the server.  Express commands are queued URGENT and also run by
a second lane, so they finish while the long command is still running --
and still run exactly once.
"""

import asyncio
import logging
import os
import tempfile

import pytest

from src.database.base import DatabaseManager
from src.database.models import MessageQueue, Priority, QueueDirection
from src.database.queue_manager import MessageQueueManager
from src.sysmanage_agent.communication.message_handler_queue import (
    EXPRESS_COMMANDS,
    MessageHandlerQueueMixin,
    is_express,
)


@pytest.fixture(name="queue_manager")
def fixture_queue_manager():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    manager = MessageQueueManager()
    manager.db_manager = DatabaseManager(path)
    manager.db_manager.create_tables()
    yield manager
    manager.db_manager.close()
    os.unlink(path)


class _Agent:  # pylint: disable=too-few-public-methods
    running = True


class _Handler(MessageHandlerQueueMixin):
    """The mixin with a command runner that records what ran, and when."""

    def __init__(self, queue_manager, long_seconds=1.0):
        self.queue_manager = queue_manager
        self.agent = _Agent()
        self.logger = logging.getLogger("express-lane-test")
        self.inbound_queue_processor_running = False
        self.express_queue_processor_running = False
        self.long_seconds = long_seconds
        self.started, self.finished = [], []

    async def handle_command(self, message):
        command = message["data"]["command_type"]
        self.started.append(command)
        if command == "collect_available_packages":
            await asyncio.sleep(self.long_seconds)
        self.finished.append(command)


def _command(command_type):
    return {"message_type": "command", "data": {"command_type": command_type}}


def test_is_express():
    assert "resync_clock" in EXPRESS_COMMANDS
    assert is_express(_command("resync_clock"))
    assert not is_express(_command("collect_available_packages"))
    assert not is_express({"data": None})
    assert not is_express("not a message")


def test_express_commands_are_queued_urgent(queue_manager):
    handler = _Handler(queue_manager)

    async def scenario():
        await handler.queue_inbound_message(_command("collect_available_packages"))
        await handler.queue_inbound_message(_command("resync_clock"))

    asyncio.run(scenario())
    with queue_manager.get_session() as session:
        priorities = sorted(r.priority for r in session.query(MessageQueue).all())
    assert priorities == sorted([Priority.URGENT.value, Priority.NORMAL.value])
    urgent = queue_manager.dequeue_messages(
        direction=QueueDirection.INBOUND, limit=5, priority=Priority.URGENT
    )
    assert len(urgent) == 1


def test_resync_finishes_while_a_long_command_runs(queue_manager):
    handler = _Handler(queue_manager, long_seconds=1.0)

    async def scenario():
        await handler.queue_inbound_message(_command("collect_available_packages"))
        main = asyncio.create_task(handler.process_inbound_queue())
        await asyncio.sleep(0.2)  # the long command is now running
        await handler.queue_inbound_message(_command("resync_clock"))
        express = asyncio.create_task(handler.process_express_queue())
        await asyncio.wait_for(express, timeout=0.6)
        # done well before the 1 s collection
        assert handler.finished == ["resync_clock"]
        await main

    asyncio.run(scenario())
    assert handler.finished == ["resync_clock", "collect_available_packages"]
    # exactly once each, whichever lane took it
    assert sorted(handler.started) == ["collect_available_packages", "resync_clock"]


def test_idle_main_lane_may_take_it_but_never_twice(queue_manager):
    handler = _Handler(queue_manager)

    async def scenario():
        await handler.queue_inbound_message(_command("resync_clock"))
        await asyncio.gather(
            handler.process_inbound_queue(), handler.process_express_queue()
        )

    asyncio.run(scenario())
    assert handler.started == ["resync_clock"]
    assert not handler.express_queue_processor_running
