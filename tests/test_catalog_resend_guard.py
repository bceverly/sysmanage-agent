# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent must not be drivable into re-shipping the same catalog for ever.

Sending the available-packages catalog is SERVER-commanded: the server issues
``collect_available_packages`` whenever an OS/version has no rows.  A
field-comparison bug on the server rejected every Linux batch, so the rows never
appeared, so the server asked again -- 78,979 messages / 9.4 GB in eight days,
83% of everything the agent sent, for a catalog that never landed.  Observed
live 2026-08-12: 1,023 batch payload messages against 0 accepted batch starts.

The server bug is fixed, but the agent should not depend on the server being
correct to avoid shipping gigabytes.  These tests pin the guard, and -- more
importantly -- pin the ways it must NOT misfire, because an over-eager
"already sent it" cache would have HIDDEN the original bug instead of exposing
it.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.sysmanage_agent.communication.data_collector import DataCollector

CATALOG = {
    "apt": [
        {"name": "curl", "version": "8.5.0", "description": "transfer a URL"},
        {"name": "vim", "version": "9.1", "description": "editor"},
    ],
    "snap": [{"name": "core22", "version": "20240111", "description": ""}],
}


@pytest.fixture(name="collector")
def _collector():
    """A DataCollector with no agent wiring -- the guard needs none."""
    return DataCollector.__new__(DataCollector)


def _armed(collector, fingerprint, age_seconds=0):
    collector._catalog_fingerprint = fingerprint
    collector._catalog_sent_at = datetime.now(timezone.utc) - timedelta(
        seconds=age_seconds
    )


def test_fingerprint_is_stable_across_orderings():
    """Dict/list order must not manufacture a 'change' and force a resend."""
    shuffled = {
        "snap": list(reversed(CATALOG["snap"])),
        "apt": list(reversed(CATALOG["apt"])),
    }
    assert DataCollector._catalog_fingerprint_of(
        CATALOG
    ) == DataCollector._catalog_fingerprint_of(shuffled)


def test_fingerprint_ignores_description_only_changes():
    """The server stores manager/name/version; a description edit is not a change."""
    tweaked = {
        "apt": [
            {"name": "curl", "version": "8.5.0", "description": "COMPLETELY DIFFERENT"},
            {"name": "vim", "version": "9.1", "description": "editor"},
        ],
        "snap": CATALOG["snap"],
    }
    assert DataCollector._catalog_fingerprint_of(
        CATALOG
    ) == DataCollector._catalog_fingerprint_of(tweaked)


@pytest.mark.parametrize(
    "mutation",
    [
        {
            "apt": CATALOG["apt"] + [{"name": "git", "version": "2.43"}],
            "snap": CATALOG["snap"],
        },
        {"apt": CATALOG["apt"][:1], "snap": CATALOG["snap"]},
        {
            "apt": [{"name": "curl", "version": "8.6.0"}, CATALOG["apt"][1]],
            "snap": CATALOG["snap"],
        },
        {"apt": CATALOG["apt"]},
    ],
    ids=["added", "removed", "version-changed", "manager-removed"],
)
def test_any_real_change_changes_the_fingerprint(mutation):
    """Added, removed, upgraded, or a whole manager going away must all resend."""
    assert DataCollector._catalog_fingerprint_of(
        mutation
    ) != DataCollector._catalog_fingerprint_of(CATALOG)


def test_first_send_is_never_skipped(collector):
    """A fresh process must always send once, whatever the server has."""
    collector._catalog_fingerprint = None
    collector._catalog_sent_at = None
    assert not collector._catalog_resend_is_pointless("anything")


def test_identical_catalog_within_cooldown_is_skipped(collector):
    """The storm case: same catalog, asked again moments later."""
    fingerprint = DataCollector._catalog_fingerprint_of(CATALOG)
    _armed(collector, fingerprint, age_seconds=60)
    assert collector._catalog_resend_is_pointless(fingerprint)


def test_changed_catalog_is_sent_even_within_cooldown(collector):
    """A real change must never wait out the cooldown."""
    _armed(collector, "OLD-FINGERPRINT", age_seconds=1)
    assert not collector._catalog_resend_is_pointless(
        DataCollector._catalog_fingerprint_of(CATALOG)
    )


def test_identical_catalog_after_cooldown_is_sent(collector):
    """The guard is time-bounded ON PURPOSE.

    An unbounded 'we already sent it' cache would have hidden the original bug
    for ever: the server genuinely had no rows, and the agent would have
    refused to help.  After the cooldown the agent always tries again.
    """
    fingerprint = DataCollector._catalog_fingerprint_of(CATALOG)
    _armed(
        collector,
        fingerprint,
        age_seconds=DataCollector.CATALOG_RESEND_COOLDOWN_SECONDS + 1,
    )
    assert not collector._catalog_resend_is_pointless(fingerprint)


def test_cooldown_is_shorter_than_a_collection_interval():
    """A guard longer than the scan interval would suppress normal traffic."""
    assert 0 < DataCollector.CATALOG_RESEND_COOLDOWN_SECONDS < 86400


def test_empty_catalog_still_fingerprints():
    """A host with no package managers must not crash the guard."""
    assert DataCollector._catalog_fingerprint_of({})
    assert DataCollector._catalog_fingerprint_of(
        {"apt": []}
    ) != DataCollector._catalog_fingerprint_of({"snap": []})
