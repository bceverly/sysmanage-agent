# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""After host_credential_required the agent asks again on its connection,
backing off, until registration is confirmed -- found 2026-10-15 on the T480,
which sat unregistered on an open connection after the operator removed the
old host as the server's own message advises."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.communication import message_handler as mh


def _handler(confirmed=False):
    agent = Mock(running=True, connected=True, registration_confirmed=confirmed)
    agent.registration_manager.get_stored_host_id_sync = Mock(return_value=None)
    agent.registration_manager.get_stored_host_token_sync = Mock(return_value=None)
    handler = mh.MessageHandler(agent)
    handler.send_message = AsyncMock(return_value=True)
    handler.create_system_info_message = Mock(
        return_value={"message_type": "system_info"}
    )
    return handler


@pytest.mark.asyncio
async def test_a_refusal_asks_again_until_registered():
    handler = _handler()
    with patch.object(mh, "REFUSAL_RETRY_SECONDS", (0,)):
        await handler._dispatch_server_error("host_credential_required", "refused")
        await handler.refusal_task
    handler.send_message.assert_awaited_once_with({"message_type": "system_info"})


@pytest.mark.asyncio
async def test_no_resend_once_registered_or_disconnected():
    for confirmed, connected in ((True, True), (False, False)):
        handler = _handler(confirmed)
        handler.agent.connected = connected
        with patch.object(mh, "REFUSAL_RETRY_SECONDS", (0,)):
            await handler._dispatch_server_error("host_credential_required", "x")
            await handler.refusal_task
        handler.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_one_retry_at_a_time_and_it_backs_off():
    handler = _handler()
    delays = []

    async def fake_sleep(seconds):
        delays.append(seconds)

    with patch.object(mh.asyncio, "sleep", fake_sleep):
        for _ in range(7):
            handler._retry_after_refusal()
            handler._retry_after_refusal()  # while one is pending: ignored
            await handler.refusal_task
    assert delays == [60, 120, 300, 600, 900, 900, 900]
    assert handler.send_message.await_count == 7


@pytest.mark.asyncio
async def test_other_errors_do_not_retry():
    handler = _handler()
    await handler._dispatch_server_error("queue_error", "x")
    assert handler.refusal_task is None
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_registration_pending_is_not_an_unknown_message(caplog):
    handler = _handler()
    with caplog.at_level("INFO"):
        await handler._dispatch_received_message(
            {"message_type": "registration_pending", "approved": False}
        )
    assert "pending approval" in caplog.text
    assert "Unknown message type" not in caplog.text
