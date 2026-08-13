# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A delta is only valid against a base BOTH sides agree on.

Sending "what changed" is easy; sending it safely is the whole problem.  A diff
computed against a base the server does not actually hold silently desynchronises
the two sides, and nothing detects it -- the server's catalog is simply wrong
from then on, and stays wrong, because every later delta is applied on top.

So most of these tests are about REFUSING to send a delta.  The agent sends one
only when its snapshot fingerprint matches what the server reports holding, and
falls back to a full catalog -- always correct, merely larger -- in every other
case.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.sysmanage_agent.collection.package_delta import (
    FULL_RECONCILE_AFTER_DAYS,
    MODE_DELTA,
    MODE_FULL,
    REASON_FINGERPRINT_MISMATCH,
    REASON_NO_SNAPSHOT,
    REASON_SNAPSHOT_STALE,
    REASON_TOO_LARGE,
    REASON_UNCHANGED,
    build_delta_plan,
    compute_delta,
)

FP = "cafebabe12345678"

CURRENT = {
    "apt": [
        {"name": "curl", "version": "8.5.0", "description": "transfer a URL"},
        {"name": "vim", "version": "9.1", "description": "editor"},
        {"name": "git", "version": "2.43", "description": "vcs"},
    ]
}
SNAPSHOT = {("apt", "curl"): "8.5.0", ("apt", "vim"): "9.1", ("apt", "git"): "2.43"}


def _plan(**kwargs):
    args = {
        "current": CURRENT,
        "snapshot": SNAPSHOT,
        "snapshot_fingerprint": FP,
        "server_fingerprint": FP,
        "snapshot_sent_at": datetime.now(timezone.utc),
    }
    args.update(kwargs)
    return build_delta_plan(**args)


# --------------------------------------------------------------------------
# the diff itself
# --------------------------------------------------------------------------


def test_added_package_is_a_put():
    current = {"apt": CURRENT["apt"] + [{"name": "nginx", "version": "1.24"}]}
    puts, takes = compute_delta(current, SNAPSHOT)
    assert takes == []
    assert [p["name"] for p in puts] == ["nginx"]


def test_removed_package_is_a_take():
    current = {"apt": CURRENT["apt"][:2]}
    puts, takes = compute_delta(current, SNAPSHOT)
    assert puts == []
    assert takes == [{"package_manager": "apt", "name": "git"}]


def test_version_change_is_a_put_not_a_take_and_a_put():
    """The server replaces the row, so one message does the job."""
    current = {
        "apt": [
            {"name": "curl", "version": "8.6.0"},
            *CURRENT["apt"][1:],
        ]
    }
    puts, takes = compute_delta(current, SNAPSHOT)
    assert takes == []
    assert len(puts) == 1
    assert puts[0]["name"] == "curl" and puts[0]["version"] == "8.6.0"


def test_no_changes_yields_nothing():
    puts, takes = compute_delta(CURRENT, SNAPSHOT)
    assert puts == [] and takes == []


def test_a_whole_manager_disappearing_is_all_takes():
    puts, takes = compute_delta({}, SNAPSHOT)
    assert puts == []
    assert len(takes) == len(SNAPSHOT)


def test_nameless_entries_are_ignored():
    """Malformed scan output must not produce a put with an empty name."""
    puts, _ = compute_delta({"apt": [{"name": "  ", "version": "1"}]}, {})
    assert puts == []


# --------------------------------------------------------------------------
# when a delta may be sent -- the part that matters
# --------------------------------------------------------------------------


def test_matching_fingerprints_allow_a_delta():
    current = {"apt": CURRENT["apt"] + [{"name": "nginx", "version": "1.24"}]}
    plan = _plan(current=current)
    assert plan["mode"] == MODE_DELTA
    assert len(plan["puts"]) == 1


def test_server_holding_a_different_catalog_forces_a_full_send():
    """The core safety property.

    The server's fingerprint disagrees with our snapshot, so we do not know
    what it holds.  Diffing against a base the other side does not have is
    exactly how a delta protocol corrupts the far end without anyone noticing.
    """
    plan = _plan(server_fingerprint="something-completely-different")
    assert plan["mode"] == MODE_FULL
    assert plan["reason"] == REASON_FINGERPRINT_MISMATCH


@pytest.mark.parametrize("server_fingerprint", [None, ""])
def test_a_silent_server_forces_a_full_send(server_fingerprint):
    """No claim from the server means no known base."""
    plan = _plan(server_fingerprint=server_fingerprint)
    assert plan["mode"] == MODE_FULL
    assert plan["reason"] == REASON_FINGERPRINT_MISMATCH


@pytest.mark.parametrize("snapshot,fingerprint", [({}, FP), (SNAPSHOT, None)])
def test_no_usable_snapshot_forces_a_full_send(snapshot, fingerprint):
    """First run, or a snapshot we cannot identify: nothing to diff against."""
    plan = _plan(snapshot=snapshot, snapshot_fingerprint=fingerprint)
    assert plan["mode"] == MODE_FULL
    assert plan["reason"] == REASON_NO_SNAPSHOT


def test_a_huge_diff_falls_back_to_a_full_send():
    """40k puts + 40k takes is worse than 89k entries sent once."""
    current = {"apt": [{"name": f"pkg{i}", "version": "1"} for i in range(100)]}
    snapshot = {("apt", f"old{i}"): "1" for i in range(100)}
    plan = _plan(current=current, snapshot=snapshot)
    assert plan["mode"] == MODE_FULL
    assert plan["reason"] == REASON_TOO_LARGE


def test_an_old_snapshot_forces_a_periodic_full_resync():
    """Deltas compound: an error in one is carried by every delta after it.

    A scheduled full send bounds how long undetected drift can persist.
    """
    stale = datetime.now(timezone.utc) - timedelta(days=FULL_RECONCILE_AFTER_DAYS + 1)
    plan = _plan(snapshot_sent_at=stale)
    assert plan["mode"] == MODE_FULL
    assert plan["reason"] == REASON_SNAPSHOT_STALE


def test_a_recent_snapshot_does_not_force_a_resync():
    fresh = datetime.now(timezone.utc) - timedelta(days=FULL_RECONCILE_AFTER_DAYS - 1)
    assert _plan(snapshot_sent_at=fresh)["mode"] == MODE_DELTA


def test_naive_timestamps_are_treated_as_utc():
    """SQLite hands back naive datetimes; comparing them must not explode."""
    naive = datetime.now(timezone.utc).replace(tzinfo=None)
    assert _plan(snapshot_sent_at=naive)["mode"] == MODE_DELTA


def test_unchanged_catalog_reports_an_empty_delta():
    """Nothing to send, but the base is agreed -- that is a valid delta of zero."""
    plan = _plan()
    assert plan["mode"] == MODE_DELTA
    assert plan["reason"] == REASON_UNCHANGED
    assert plan["puts"] == [] and plan["takes"] == []
