# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Bulk writes are one short transaction, and the receive path never waits on
the database (production, ubiquiti, 2026-11-01).

The agent's one SQLite connection runs with ``isolation_level=None``, so a
121,420-row catalog was ~120 separate synced commits while apt's catalog was
being parsed; the event loop's duplicate-command check waited behind it for
minutes, answered no pings, and the server dropped the websocket."""

# pylint: disable=protected-access

import asyncio
import threading
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.database.base import DatabaseManager, write_transaction
from src.database.models import AvailablePackage
from src.sysmanage_agent.collection import package_collector_base as pcb
from tests.message_handler_test_base import MessageHandlerTestBase

PACKAGES = [
    {"name": f"pkg{i}", "version": f"1.{i}", "description": "d"} for i in range(2500)
]


@pytest.fixture(name="manager")
def _manager(tmp_path):
    manager = DatabaseManager(str(tmp_path / "agent.db"))
    manager.create_tables()
    yield manager
    manager.close()


def _package():
    return AvailablePackage(
        package_manager="apt",
        package_name="a",
        package_version="1",
        collection_date=datetime.now(timezone.utc),
    )


def _raw(session):
    return session.connection().connection.driver_connection


def _count(manager):
    with manager.get_session() as session:
        return session.query(AvailablePackage).count()


def test_a_write_transaction_is_one_real_transaction(manager):
    seen = []
    with manager.get_session() as session:
        with write_transaction(session):
            seen.append(_raw(session).in_transaction)
            session.add(_package())
            session.flush()
            seen.append(_raw(session).in_transaction)
        seen.append(_raw(session).in_transaction)
        session.commit()
    assert seen == [True, True, False]
    assert _count(manager) == 1


def test_a_failed_write_is_rolled_back(manager):
    with pytest.raises(RuntimeError):
        with manager.get_session() as session:
            with write_transaction(session):
                session.add(_package())
                session.flush()
                raise RuntimeError("boom")
    assert _count(manager) == 0


def test_a_commit_by_another_user_of_the_connection_is_tolerated(manager):
    with manager.get_session() as session:
        with write_transaction(session):
            _raw(session).execute("COMMIT")  # another thread on the shared conn
        session.commit()  # no "cannot commit - no transaction is active"


def test_the_catalog_is_parsed_before_the_database_is_touched(manager):
    collector = pcb.BasePackageCollector.__new__(pcb.BasePackageCollector)
    collector.db_manager = manager
    events = []
    real_bulk_session = manager.bulk_session

    def bulk_session():
        events.append("session")
        return real_bulk_session()

    def packages():
        for package in PACKAGES:
            events.append("parse")
            yield package

    collector.db_manager = MagicMock(bulk_session=bulk_session)
    in_transaction = []
    real_insert = pcb._insert_rows

    def insert(session, model, rows):
        in_transaction.append(_raw(session).in_transaction)
        real_insert(session, model, rows)

    pcb_insert = pcb._insert_rows
    pcb._insert_rows = insert
    try:
        assert collector._store_packages_streaming("apt", packages(), 1000) == 2500
    finally:
        pcb._insert_rows = pcb_insert
    assert events.index("session") == len(PACKAGES)  # every parse came first
    assert in_transaction == [True, True, True]  # 3 batches, one transaction
    assert _count(manager) == 2500


def test_a_parse_failure_leaves_the_stored_catalog_alone(manager):
    collector = pcb.BasePackageCollector.__new__(pcb.BasePackageCollector)
    collector.db_manager = manager
    assert collector._store_packages_streaming("apt", iter(PACKAGES[:5]), 1000) == 5

    def broken():
        yield PACKAGES[0]
        raise OSError("apt-cache died")

    assert collector._store_packages_streaming("apt", broken(), 1000) == 0
    assert _count(manager) == 5  # the old catalog was not deleted


class TestDuplicateCheckOffTheLoop(MessageHandlerTestBase):
    """The receive path's duplicate check runs in a worker thread."""

    def test_the_duplicate_check_runs_off_the_event_loop(self):
        seen = {}

        def is_duplicate(_message_id):
            seen["thread"] = threading.get_ident()
            return True

        self.handler.queue_manager.is_duplicate_message = is_duplicate
        self.handler._send_command_acknowledgment = AsyncMock()

        async def run():
            seen["loop"] = threading.get_ident()
            await self.handler._handle_command_message(
                {"message_id": "m1", "data": {"command_type": "noop"}}
            )

        asyncio.run(run())
        assert seen["thread"] != seen["loop"]
        self.handler._send_command_acknowledgment.assert_awaited_once_with("m1")


def test_another_sessions_commit_cannot_end_a_bulk_transaction(manager):
    """On the one shared connection the event loop's commits ended the
    catalog's transaction early, and the rest of its rows went back to a sync
    each: over an hour on ubiquiti (production, 2026-11-02).  bulk_session has
    a connection of its own."""
    with manager.bulk_session() as bulk, write_transaction(bulk):
        bulk.add(_package())
        bulk.flush()
        with manager.get_session() as shared:
            assert _raw(shared) is not _raw(bulk)
            shared.query(AvailablePackage).count()
            shared.commit()  # what the event loop does all the time
        assert _raw(bulk).in_transaction
    assert _count(manager) == 1


def test_a_bulk_session_survives_its_own_commit(manager):
    """Its own session.commit() must not hand the connection back (and close
    it) before write_transaction's COMMIT."""
    with manager.bulk_session() as bulk, write_transaction(bulk):
        bulk.add(_package())
        bulk.commit()
    assert _count(manager) == 1


def test_an_early_exit_rolls_the_transaction_back(manager):
    """Closing the block early (GeneratorExit, as when the caller is torn
    down) ends the transaction with a rollback -- never left open, never
    committed half-way."""
    with manager.bulk_session() as bulk:
        block = write_transaction(bulk)
        block.__enter__()  # pylint: disable=unnecessary-dunder-call
        bulk.add(_package())
        bulk.flush()
        assert _raw(bulk).in_transaction
        block.gen.close()  # an early exit at the yield
        assert not _raw(bulk).in_transaction
    assert _count(manager) == 0
