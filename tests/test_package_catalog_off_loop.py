# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The package catalog never blocks the event loop (production, ubiquiti,
2026-10-31): its agent dropped its websocket about 49 times in a day because
reading, diffing and rewriting ~121,000 catalog rows ran on the loop, which
also answers the server's keepalive pings, and held SQLite's write lock for
seconds at a time."""

# pylint: disable=protected-access

import asyncio
import logging
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.database.base import DatabaseManager
from src.database.models import AvailablePackage, SentPackageSnapshot
from src.sysmanage_agent.collection import package_collector_base as pcb
from src.sysmanage_agent.communication.data_collector import DataCollector

CATALOG = {
    "apt": [
        {"name": f"pkg{i}", "version": f"1.{i}", "description": "d"}
        for i in range(2500)
    ]
}


@pytest.fixture(name="store")
def _store(tmp_path):
    manager = DatabaseManager(str(tmp_path / "agent.db"))
    manager.create_tables()
    collector = pcb.BasePackageCollector.__new__(pcb.BasePackageCollector)
    collector.db_manager = manager
    yield collector
    manager.close()


def _snapshot_ids(store):
    with store.db_manager.get_session() as session:
        return sorted(r.id for r in session.query(SentPackageSnapshot).all())


def test_an_unchanged_catalog_only_moves_the_delivery_time(store):
    assert store.replace_sent_snapshot(CATALOG, "fp1")
    first_ids = _snapshot_ids(store)
    _index, _fp, first_at = store.get_sent_snapshot()
    assert len(first_ids) == 2500

    assert store.replace_sent_snapshot(CATALOG, "fp1")
    assert _snapshot_ids(store) == first_ids  # not rewritten
    index, fingerprint, sent_at = store.get_sent_snapshot()
    assert fingerprint == "fp1" and len(index) == 2500 and sent_at >= first_at


def test_a_changed_catalog_is_rewritten(store):
    store.replace_sent_snapshot(CATALOG, "fp1")
    first_ids = _snapshot_ids(store)
    smaller = {"apt": CATALOG["apt"][:10]}
    assert store.replace_sent_snapshot(smaller, "fp2")
    index, fingerprint, _at = store.get_sent_snapshot()
    assert fingerprint == "fp2" and len(index) == 10
    assert not set(_snapshot_ids(store)) & set(first_ids)


def test_streamed_packages_are_stored_in_batches(store):
    stored = store._store_packages_streaming("apt", iter(CATALOG["apt"]), 1000)
    assert stored == 2500
    with store.db_manager.get_session() as session:
        assert session.query(AvailablePackage).count() == 2500
    assert store._store_packages("apt", CATALOG["apt"][:3]) == 3
    with store.db_manager.get_session() as session:
        assert session.query(AvailablePackage).count() == 3


def test_the_catalog_steps_run_off_the_event_loop_thread():
    loop_thread = []
    seen = {}

    def record(name, value):
        def call(*_args, **_kwargs):
            seen[name] = threading.get_ident()
            return value

        return call

    coll = DataCollector.__new__(DataCollector)
    coll.logger = logging.getLogger("test")
    coll._catalog_fingerprint = None
    coll._catalog_sent_at = None
    agent = MagicMock()
    agent.package_collection_scheduler.perform_package_collection = AsyncMock(
        return_value=True
    )
    collector = agent.package_collection_scheduler.package_collector
    collector.get_packages_for_transmission = record(
        "read", {"package_managers": CATALOG}
    )
    collector.get_sent_snapshot = record("snapshot", ({}, None, None))
    collector.replace_sent_snapshot = record("write", True)
    agent.registration.get_system_info = MagicMock(
        return_value={"os_info": {"distribution": "Ubuntu"}, "platform": "Linux"}
    )
    coll.agent = agent
    coll._send_available_packages_paginated = AsyncMock(return_value=True)

    async def run():
        loop_thread.append(threading.get_ident())
        return await coll.collect_available_packages({})

    result = asyncio.run(run())
    assert result["success"] is True
    assert set(seen) == {"read", "snapshot", "write"}
    assert loop_thread[0] not in seen.values()
