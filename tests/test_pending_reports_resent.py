# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Reports sent while the host awaited approval were dropped by the server,
so they must not count as sent.  beast (2026-10-16) sent its hardware while
pending; the approval notice never arrived, the send-on-change memory still
called that hardware "sent and unchanged", and the server had no network
interfaces for it for a day -- network discovery showed it unmanaged."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.communication import message_handler as mh


def _handler():
    agent = Mock(running=True, connected=True, registration_confirmed=False)
    agent.registration_manager.get_stored_host_id_sync = Mock(return_value=None)
    agent.registration_manager.get_stored_host_token_sync = Mock(return_value=None)
    handler = mh.MessageHandler(agent)
    handler.send_message = AsyncMock(return_value=True)
    return handler


@pytest.mark.asyncio
async def test_a_registration_pending_reply_forgets_what_was_sent():
    handler = _handler()
    with patch.object(mh.send_on_change.gate, "reset") as reset:
        await handler._dispatch_received_message(
            {"message_type": "registration_pending", "approved": False}
        )
    reset.assert_called_once()


@pytest.mark.asyncio
async def test_a_host_not_approved_error_forgets_too():
    handler = _handler()
    with patch.object(mh.send_on_change.gate, "reset") as reset:
        await handler._dispatch_server_error("host_not_approved", "pending")
    reset.assert_called_once()


@pytest.mark.asyncio
async def test_other_server_errors_keep_the_memory():
    handler = _handler()
    with patch.object(mh.send_on_change.gate, "reset") as reset:
        await handler._dispatch_server_error("missing_hostname", "x")
    reset.assert_not_called()


def test_a_failed_reset_never_breaks_message_handling():
    handler = _handler()
    with patch.object(
        mh.send_on_change.gate, "reset", side_effect=RuntimeError("db locked")
    ):
        handler._forget_reports_sent_while_pending()  # does not raise


def _registration(previous_approved_id):
    from src.sysmanage_agent.registration import registration_manager as rm

    agent = Mock()
    manager = rm.RegistrationManager(agent)
    manager.get_stored_host_id_sync = Mock(return_value=previous_approved_id)
    manager._kept_token = Mock(return_value=None)  # pylint: disable=protected-access
    manager.clear_stored_host_id = AsyncMock()
    manager.store_host_approval = AsyncMock()
    manager._start_initial_data_updates = Mock()  # pylint: disable=protected-access
    return rm, manager


@pytest.mark.asyncio
async def test_first_approved_registration_resends_everything():
    """beast reconnected approved at 14:45:42 without ever receiving the
    approval notice: this is the moment its dropped reports must go again."""
    rm, manager = _registration(previous_approved_id=None)
    with patch.object(rm.send_on_change.gate, "reset") as reset:
        await manager.handle_registration_success(
            {"host_id": "61ea7160", "host_token": "t", "approved": True}
        )
    reset.assert_called_once()


@pytest.mark.asyncio
async def test_an_already_approved_host_reconnecting_keeps_the_memory():
    rm, manager = _registration(previous_approved_id="61ea7160")
    with patch.object(rm.send_on_change.gate, "reset") as reset:
        await manager.handle_registration_success(
            {"host_id": "61ea7160", "host_token": "t", "approved": True}
        )
    reset.assert_not_called()


@pytest.mark.asyncio
async def test_a_still_pending_registration_does_not_reset_here():
    rm, manager = _registration(previous_approved_id=None)
    with patch.object(rm.send_on_change.gate, "reset") as reset:
        await manager.handle_registration_success(
            {"host_id": "61ea7160", "host_token": "t", "approved": False}
        )
    reset.assert_not_called()
