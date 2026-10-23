# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Seal retention (24.5): the storage host removes only its own seals older
than keep_days, never the newest, ZFS aged by its creation property, btrfs
by the agent's own ledger."""

import sys

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import seal_retention as r

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
U1 = "8b8d6018-656a-44ee-b08e-3075693fc2d1"
U2 = "6ed601a3-f093-4506-bc52-7a8ae504f03b"
U3 = "b4f0e030-409e-4861-b743-2e640a04e304"
DS = "zroot/sysmanage-backups/restate"
NOW = 1_800_000_000.0


def test_only_seals_past_the_age_go_and_the_newest_always_stays():
    seals = [("a", NOW - 30 * r.DAY), ("b", NOW - 20 * r.DAY), ("c", NOW - 1 * r.DAY)]
    assert r.expired(seals, 14, NOW) == ["a", "b"]
    assert r.expired([("only", NOW - 99 * r.DAY)], 14, NOW) == []  # the last one stays
    old_only = [("a", NOW - 30 * r.DAY), ("b", NOW - 20 * r.DAY)]
    assert r.expired(old_only, 14, NOW) == ["a"]  # b is the newest


def test_zfs_listing_keeps_only_this_agents_seals_of_this_dataset():
    listing = (
        f"{DS}@sysmanage-{U1}\t1700000000\n"
        f"{DS}@manual-before-upgrade\t1700000001\n"
        f"{DS}/t14-1@sysmanage-{U2}\t1700000002\n"
        f"zroot/other@sysmanage-{U3}\t1700000003\n"
        f"{DS}@sysmanage-not-a-uuid\t1700000004\n"
        f"{DS}@sysmanage-{U3}\tgarbage\n"
    )
    assert r.zfs_seals(listing, DS) == [(f"{DS}@sysmanage-{U1}", 1700000000.0)]


def test_btrfs_ledger_only_counts_seals_in_the_snapshot_dir():
    ledger = {f"/srv/.snapshots/sysmanage-{U1}": 1.0, f"/elsewhere/sysmanage-{U2}": 2.0,
              "/srv/.snapshots/hand-made": 3.0}  # fmt: skip
    assert r.btrfs_seals(ledger, "/srv/.snapshots") == [
        (f"/srv/.snapshots/sysmanage-{U1}", 1.0)
    ]


def test_delete_commands_are_exact():
    assert r.delete_argv("zfs_snapshot", "/sbin/zfs", f"{DS}@sysmanage-{U1}") == [
        "/sbin/zfs", "destroy", "-r", f"{DS}@sysmanage-{U1}"]  # fmt: skip
    assert r.delete_argv("btrfs_snapshot", "/usr/bin/btrfs", "/s/x") == [
        "/usr/bin/btrfs", "subvolume", "delete", "/s/x"]  # fmt: skip


@pytest.mark.parametrize("keep", [0, 3651, "7", True])
def test_a_bad_keep_days_is_refused(keep):
    with pytest.raises(v.PolicyError):
        v.check_seal({"mode": "zfs_snapshot", "dataset": DS, "keep_days": keep})


def test_keep_days_is_optional_and_carried():
    assert v.check_seal({"mode": "zfs_snapshot", "dataset": DS}) == {
        "mode": "zfs_snapshot",
        "dataset": DS,
    }
    assert (
        v.check_seal({"mode": "zfs_snapshot", "dataset": DS, "keep_days": 14})[
            "keep_days"
        ]
        == 14
    )
