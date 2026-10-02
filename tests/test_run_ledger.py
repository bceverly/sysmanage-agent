# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The persisted last-run ledger (server Phase 22.1): a reconnect or restart
runs only what is overdue.  Real database (a temp SQLite file), not mocks."""

import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from src.database import run_ledger as ledger
from src.database.base import DatabaseManager


@pytest.fixture
def dbm():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    manager = DatabaseManager(path)
    manager.create_tables()
    with patch("src.database.run_ledger.get_database_manager", return_value=manager):
        yield manager
    manager.close()
    os.unlink(path)


def test_never_run_is_due(dbm):
    assert ledger.is_due("update_check", 3600)


def test_recent_run_is_not_due_and_an_old_one_is(dbm):
    now = datetime(2026, 10, 2, 12, 0, 0)
    ledger.mark_run("update_check", when=now - timedelta(minutes=10))
    assert not ledger.is_due("update_check", 3600, now=now)
    assert ledger.is_due("update_check", 600, now=now)


def test_marking_again_moves_the_time(dbm):
    ledger.mark_run("c", when=datetime(2026, 1, 1))
    ledger.mark_run("c", when=datetime(2026, 2, 1))
    assert ledger.last_run("c") == datetime(2026, 2, 1)


def test_forget_makes_it_due_at_once(dbm):
    ledger.mark_run("update_check")
    ledger.forget("update_check")
    assert ledger.is_due("update_check", 3600)


def test_a_clock_that_went_backwards_does_not_block(dbm):
    now = datetime(2026, 10, 2)
    ledger.mark_run("c", when=now + timedelta(days=1))
    assert ledger.is_due("c", 3600, now=now)


def test_an_unreadable_ledger_fails_open():
    with patch(
        "src.database.run_ledger.get_database_manager",
        side_effect=RuntimeError("db gone"),
    ):
        assert ledger.is_due("update_check", 3600)
        ledger.mark_run("update_check")  # logs, never raises


@pytest.mark.asyncio
async def test_a_reconnect_does_not_refetch_a_recent_package_catalog(dbm):
    """The scheduler restarts with every connection; 'at startup' must not
    mean 'after every reconnect'."""
    from unittest.mock import AsyncMock, MagicMock

    from src.sysmanage_agent.core.agent_utils import PackageCollectionScheduler

    ledger.mark_run(ledger.PACKAGE_COLLECTION)
    agent = MagicMock(running=False)
    agent.config.is_package_collection_enabled.return_value = True
    agent.config.is_package_collection_at_startup_enabled.return_value = True
    agent.config.get_package_collection_interval.return_value = 86400
    scheduler = PackageCollectionScheduler(agent, MagicMock())
    scheduler.perform_package_collection = AsyncMock(return_value=True)
    await scheduler.run_package_collection_loop()
    scheduler.perform_package_collection.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_connect_burst_skips_a_recent_update_check_unless_asked(dbm):
    from unittest.mock import AsyncMock, MagicMock

    from src.sysmanage_agent.communication import send_on_change
    from src.sysmanage_agent.communication.data_collector import DataCollector

    ledger.mark_run(ledger.UPDATE_CHECK)
    agent = MagicMock()
    agent.config.get_update_check_interval.return_value = 3600
    agent.check_updates = AsyncMock(return_value={})
    collector = DataCollector.__new__(DataCollector)
    collector.agent, collector.logger = agent, MagicMock()
    collector.collect_certificates = AsyncMock(return_value={})
    collector.collect_roles = AsyncMock(return_value={})
    with patch("asyncio.sleep", new=AsyncMock()):
        await collector._send_initial_update_check()
        agent.check_updates.assert_not_awaited()
        with send_on_change.forced():
            await collector._send_initial_update_check()
    agent.check_updates.assert_awaited_once()
