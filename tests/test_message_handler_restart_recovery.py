# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A command cut off by an agent restart is run again on the new process's
first connection, whatever its age; later reconnects keep the 10 minutes
(a handler may still be running)."""

from unittest.mock import patch

import pytest

from src.sysmanage_agent.communication import message_handler_queue as mhq
from tests.message_handler_test_base import MessageHandlerTestBase


class TestRestartRecovery(MessageHandlerTestBase):
    """The first connection of a process recovers every orphan."""

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_first_connection_recovers_all_then_ten_minutes(self, _task):
        mhq._RECOVERED_SINCE_START.clear()  # pylint: disable=protected-access
        recover = self.handler.queue_manager.recover_stuck_messages
        recover.return_value = 0
        await self.handler.on_connection_established()
        await self.handler.on_connection_established()
        assert [c.kwargs["stale_minutes"] for c in recover.call_args_list] == [0, 10]
