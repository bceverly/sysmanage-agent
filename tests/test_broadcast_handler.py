"""
Tests for the Phase 8.5 broadcast-message handler in MessageHandler.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring,redefined-outer-name,protected-access,invalid-name

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.sysmanage_agent.communication.message_handler import MessageHandler


def _make_handler():
    """Build a MessageHandler with the agent dependencies stubbed.
    The handler's __init__ takes a sysmanage_agent reference; we mock
    everything it touches synchronously."""
    fake_agent = MagicMock()
    fake_agent.data_collector = MagicMock()
    fake_agent.data_collector.send_software_inventory_update = AsyncMock()
    return MessageHandler(fake_agent), fake_agent


@pytest.mark.asyncio
async def test_broadcast_refresh_inventory_calls_collector():
    handler, agent = _make_handler()
    await handler._handle_broadcast_message(
        {
            "broadcast_id": "b1",
            "broadcast_action": "refresh_inventory",
            "issued_by": "admin@sysmanage.org",
        }
    )
    agent.data_collector.send_software_inventory_update.assert_awaited_once()


@pytest.mark.asyncio
async def test_broadcast_banner_action_does_not_raise():
    handler, agent = _make_handler()
    # Banner action must NOT call send_software_inventory_update.
    await handler._handle_broadcast_message(
        {
            "broadcast_id": "b2",
            "broadcast_action": "banner",
            "message": "scheduled maintenance",
        }
    )
    agent.data_collector.send_software_inventory_update.assert_not_called()


@pytest.mark.asyncio
async def test_broadcast_unknown_action_does_not_raise():
    handler, _ = _make_handler()
    # Unknown action is logged as a warning but must not raise.
    await handler._handle_broadcast_message(
        {"broadcast_id": "b3", "broadcast_action": "do-the-hokey-pokey"}
    )


@pytest.mark.asyncio
async def test_broadcast_inventory_failure_logged_not_raised():
    """If the inventory collector raises, the broadcast handler must
    swallow the exception and log it — propagating would crash the
    receive loop and disconnect the agent."""
    handler, agent = _make_handler()
    agent.data_collector.send_software_inventory_update = AsyncMock(
        side_effect=RuntimeError("collector exploded")
    )
    # Should NOT raise.
    await handler._handle_broadcast_message(
        {"broadcast_id": "b4", "broadcast_action": "refresh_inventory"}
    )


@pytest.mark.asyncio
async def test_dispatch_routes_broadcast_to_handler():
    """Sanity:  the dispatcher must route ``message_type=broadcast``
    to the new handler — without that, the new code path is dead."""
    handler, _ = _make_handler()
    handler._handle_broadcast_message = AsyncMock()
    await handler._dispatch_received_message(
        {"message_type": "broadcast", "broadcast_action": "refresh_inventory"}
    )
    handler._handle_broadcast_message.assert_awaited_once()
