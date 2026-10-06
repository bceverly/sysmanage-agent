# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server Phase 22.2: a busy server asks connecting agents to spread their
first reports (``initial_report_window_seconds`` in ``registration_success``).

A fleet reconnecting at once queued its whole inventory in the same minute:
~300,000 messages at 10,000 agents.
"""

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.registration import registration_manager as rm


def test_no_window_means_now():
    for window in (0, None, -5, "junk"):
        assert rm._splay(window) == 0.0  # pylint: disable=protected-access


def test_the_moment_is_inside_the_window():
    moments = [rm._splay(120) for _ in range(500)]  # pylint: disable=protected-access
    assert all(0.0 <= m <= 120.0 for m in moments)
    assert max(moments) - min(moments) > 60  # spread, not one moment


def test_the_server_cannot_park_an_agent_forever():
    assert (
        rm._splay(10**9) <= rm.MAX_INITIAL_REPORT_WINDOW
    )  # pylint: disable=protected-access


def _manager():
    agent = MagicMock()
    agent.send_initial_data_updates = AsyncMock()
    manager = rm.RegistrationManager(agent)
    manager.clear_stored_host_id = AsyncMock()
    manager.store_host_approval = AsyncMock()
    manager.get_stored_host_id_sync = MagicMock(return_value=None)
    return manager, agent


def _approved(**extra):
    return {"host_id": str(uuid.uuid4()), "host_token": "t", "approved": True, **extra}


@pytest.mark.asyncio
async def test_a_busy_server_delays_the_first_reports():
    manager, agent = _manager()
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    with patch.object(rm.asyncio, "sleep", fake_sleep), patch.object(
        rm, "_splay", return_value=42.0
    ) as splay:
        await manager.handle_registration_success(
            _approved(initial_report_window_seconds=300)
        )
        await manager._initial_data_task  # pylint: disable=protected-access
    splay.assert_called_once_with(300)
    assert sleeps == [42.0]
    agent.send_initial_data_updates.assert_awaited_once()


@pytest.mark.asyncio
async def test_an_older_server_means_report_now():
    manager, agent = _manager()
    with patch.object(rm.asyncio, "sleep", AsyncMock()) as sleep:
        await manager.handle_registration_success(_approved())
        await manager._initial_data_task  # pylint: disable=protected-access
    sleep.assert_not_called()
    agent.send_initial_data_updates.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_waiting_send_is_not_doubled_by_a_reconnect():
    manager, agent = _manager()
    gate = asyncio.Event()

    async def slow_sleep(_seconds):
        await gate.wait()

    with patch.object(rm.asyncio, "sleep", slow_sleep), patch.object(
        rm, "_splay", return_value=10.0
    ):
        await manager.handle_registration_success(_approved())
        first = manager._initial_data_task  # pylint: disable=protected-access
        await manager.handle_registration_success(_approved())
        assert manager._initial_data_task is first  # pylint: disable=protected-access
        gate.set()
        await first
    agent.send_initial_data_updates.assert_awaited_once()


def test_the_hold_counts_down_and_resets():
    from src.sysmanage_agent.core import schedule_jitter as sj

    assert sj.initial_reports_wait() == 0.0
    sj.hold_initial_reports(30)
    # + 1e-6: Windows' coarse monotonic clock can leave (m + 30) - m a float
    # rounding above 30.
    assert 29 < sj.initial_reports_wait() <= 30 + 1e-6
    sj.hold_initial_reports(0)  # a quiet server on the next connect
    assert sj.initial_reports_wait() == 0.0


@pytest.mark.asyncio
async def test_registration_holds_the_post_connect_collection_too():
    """Not only the registration burst: the first post-connect collection
    sent the same inventory within a minute of connecting (10k run,
    2026-10-02: half the report types ignored the window)."""
    from src.sysmanage_agent.core import schedule_jitter as sj

    manager, _agent = _manager()
    with patch.object(rm.asyncio, "sleep", AsyncMock()), patch.object(
        rm, "_splay", return_value=500.0
    ):
        await manager.handle_registration_success(_approved())
        await manager._initial_data_task  # pylint: disable=protected-access
    assert 499 < sj.initial_reports_wait() <= 500 + 1e-6  # float slack, as above
