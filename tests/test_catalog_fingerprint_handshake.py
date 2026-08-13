# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The server tells the agent what it already has; the agent sends nothing.

The available-packages catalog is ~89k packages / ~11 MB and changes rarely,
yet it was retransmitted in full every collection cycle because neither side
could say "I already hold exactly this".

The fingerprint rides on the ``collect_available_packages`` COMMAND rather than
coming back as a reply, and that is not a stylistic choice:
``route_inbound_message`` on the server discards handler return values, so the
server has no working path to answer an agent mid-exchange.  That is how 1,023
payload messages were once shipped into a batch the server had already rejected
without ever being told.

What these tests pin, in order of importance:
  * a MATCHING fingerprint sends nothing at all;
  * a DIFFERING fingerprint always sends -- staleness must never be sticky;
  * an ABSENT fingerprint always sends, so a server that knows nothing about
    this host (or an older server that does not send the field) still gets a
    catalog.  Failing open is the safe direction: the expensive failure is a
    catalog that never arrives, which is precisely the 9.4 GB incident.
"""

import asyncio
import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.sysmanage_agent.communication.data_collector import DataCollector

CATALOG = {
    "apt": [
        {"name": "curl", "version": "8.5.0", "description": "transfer a URL"},
        {"name": "vim", "version": "9.1", "description": "editor"},
    ]
}


@pytest.fixture(name="collector")
def _collector():
    """A DataCollector wired to a stub agent, recording what it transmits."""
    coll = DataCollector.__new__(DataCollector)
    coll.logger = logging.getLogger("test")
    coll._catalog_fingerprint = None
    coll._catalog_sent_at = None

    agent = MagicMock()
    agent.package_collection_scheduler.perform_package_collection = AsyncMock(
        return_value=True
    )
    agent.package_collection_scheduler.package_collector.get_packages_for_transmission = MagicMock(
        return_value={"package_managers": CATALOG}
    )
    agent.registration.get_system_info = MagicMock(
        return_value={
            "os_info": {"distribution": "Ubuntu", "distribution_version": "26.04"},
            "platform": "Linux",
            "platform_release": "Ubuntu 26.04",
        }
    )
    # The send path now consults the delivered snapshot to decide between a
    # delta and a full send.  No snapshot => full send, which is what these
    # tests are about.
    collector = agent.package_collection_scheduler.package_collector
    collector.get_sent_snapshot = MagicMock(return_value=({}, None, None))
    collector.replace_sent_snapshot = MagicMock(return_value=True)

    coll.agent = agent

    coll.sent = []

    async def _record(
        pkg_managers, os_name, os_version, total, catalog_fingerprint=None
    ):
        coll.sent.append({"total": total, "fingerprint": catalog_fingerprint})
        return True

    coll._send_available_packages_paginated = _record
    return coll


def _run(coro):
    return asyncio.run(coro)


def _fingerprint():
    return DataCollector._catalog_fingerprint_of(CATALOG)


def test_matching_fingerprint_transmits_nothing(collector):
    """The whole point: the server already has it, so say nothing."""
    result = _run(
        collector.collect_available_packages({"known_fingerprint": _fingerprint()})
    )
    assert result["skipped"] is True
    assert result["reason"] == "server_already_current"
    assert collector.sent == []


def test_differing_fingerprint_transmits(collector):
    """A changed catalog must go, immediately -- staleness must not be sticky."""
    result = _run(
        collector.collect_available_packages({"known_fingerprint": "something-else"})
    )
    assert not result.get("skipped")
    assert len(collector.sent) == 1


@pytest.mark.parametrize(
    "parameters",
    [None, {}, {"known_fingerprint": None}, {"known_fingerprint": ""}],
    ids=["no-params", "empty", "explicit-null", "empty-string"],
)
def test_absent_fingerprint_always_transmits(collector, parameters):
    """Fail OPEN.

    A server that holds nothing for this host, or an older server that does not
    send the field at all, must still receive a catalog.  Skipping here would
    recreate the failure this whole line of work exists to remove: a catalog
    that is never delivered and never noticed.
    """
    result = _run(collector.collect_available_packages(parameters))
    assert not result.get("skipped")
    assert len(collector.sent) == 1


def test_the_fingerprint_sent_matches_the_catalog_sent(collector):
    """The server stores what we transmit; the two must describe the same thing.

    If these ever diverged the server would hand back a fingerprint that never
    matches, and the agent would resend for ever -- silently, and at full size.
    """
    _run(collector.collect_available_packages(None))
    assert collector.sent[0]["fingerprint"] == _fingerprint()


def test_skip_marks_the_catalog_as_delivered(collector):
    """A server-confirmed skip should satisfy the local guard too.

    The server demonstrably holds this catalog, so the in-memory cooldown must
    not turn around and force a send moments later.
    """
    _run(collector.collect_available_packages({"known_fingerprint": _fingerprint()}))
    assert collector._catalog_fingerprint == _fingerprint()
    assert collector._catalog_sent_at is not None


def test_a_failed_send_does_not_record_a_fingerprint(collector):
    """If transmission failed the server has nothing; we must retry, not skip."""

    async def _fail(*_args, **_kwargs):
        return False

    collector._send_available_packages_paginated = _fail
    result = _run(collector.collect_available_packages(None))
    assert result["success"] is False
    assert collector._catalog_fingerprint is None


def test_a_confirmed_skip_records_the_delivered_snapshot(collector):
    """A confirmed match is proof of what the server holds.

    Without this the first change after a skip has no base to diff against, so
    it goes as a full ~11 MB catalog purely to establish a base we already knew.
    """
    _run(collector.collect_available_packages({"known_fingerprint": _fingerprint()}))

    snapshot_writer = (
        collector.agent.package_collection_scheduler.package_collector.replace_sent_snapshot
    )
    snapshot_writer.assert_called_once()
    _, recorded_fingerprint = snapshot_writer.call_args[0]
    assert recorded_fingerprint == _fingerprint()


def test_the_local_cooldown_skip_does_NOT_record_a_snapshot(collector):
    """The cooldown means "we sent this recently", NOT "the server has it".

    Recording a snapshot here would let a later delta be computed against a base
    the server may never have received -- the exact desynchronisation the
    fingerprint check exists to prevent.
    """
    from datetime import timedelta

    collector._catalog_fingerprint = _fingerprint()
    collector._catalog_sent_at = datetime.now(timezone.utc) - timedelta(seconds=5)

    result = _run(collector.collect_available_packages(None))

    assert result["skipped"] is True
    snapshot_writer = (
        collector.agent.package_collection_scheduler.package_collector.replace_sent_snapshot
    )
    snapshot_writer.assert_not_called()
