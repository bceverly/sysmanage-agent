# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

""" "Prepare storage for this host" (24.1 / 24.5): what the storage host runs
to give one host its own filesystem and export -- planned from fake readings,
nothing touches the host."""

# pylint: disable=redefined-outer-name

import os
import re
import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import storage_prepare as p

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")
PID = "3f2a0000-0000-4000-8000-0000000000c1"
MOUNT = "/srv/backups"
REPO = "/srv/backups/t14-1"
POLICY = {"policy_id": PID, "repository": REPO, "mount_point": MOUNT,
          "client_address": "192.168.4.196", "service_account": "restate"}  # fmt: skip
SUDOERS = os.path.join(
    os.path.dirname(__file__), "..", "installer", "freebsd", "sysmanage-agent.sudoers"
)
PROTECT = [["chown", "root:restate", REPO], ["chmod", "1770", REPO]]
# FreeBSD: no sticky bit (its NFS server refuses creates in a sticky
# directory); the same rule as an NFSv4 ACL, as restate 2.1.0.2 protects.
PROTECT_FREEBSD = [
    ["chown", "root:restate", REPO],
    ["chmod", "0770", REPO],
    ["setfacl", "-a", "0", "group@:D::deny", REPO],
    ["setfacl", "-a", "0", "owner@:d:f:allow", REPO],
    ["setfacl", "-a", "0", "owner@:d:d:allow", REPO],
]


@pytest.fixture(autouse=True)
def account(monkeypatch):
    monkeypatch.setattr(p.pwd, "getpwnam", lambda n: SimpleNamespace(pw_uid=1002))
    monkeypatch.setattr(p.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=1003))


def _missing(path):
    raise FileNotFoundError(path)


def _plan(system, fstype, datasets=None, listdir=_missing, subvolume=False, **over):
    return p.plan(dict(POLICY, **over), system=system, fstype=fstype,
                  datasets=datasets or {}, is_subvolume=lambda _p: subvolume,
                  listdir=listdir)  # fmt: skip


def test_zfs_listing_maps_mountpoints_to_datasets():
    text = "tank\t/tank\ntank/backups\t/srv/backups\ntank/swap\tnone\n"
    assert p.zfs_datasets(text) == {"/tank": "tank", MOUNT: "tank/backups"}


def test_freebsd_zfs_creates_a_child_dataset_shared_to_the_host_only():
    steps = _plan("FreeBSD", "zfs", {MOUNT: "tank/backups"})
    assert steps["commands"] == [
        ["zfs", "create", "-o", "sharenfs=-mapall=restate:restate 192.168.4.196",
         "tank/backups/t14-1"],
    ]  # fmt: skip
    assert steps["protect"] == PROTECT_FREEBSD
    assert steps["export_file"] is None and steps["reload"] is False


def test_freebsd_sudoers_regex_accepts_exactly_the_planned_command():
    with open(SUDOERS, encoding="utf-8") as handle:
        rules = handle.read()
    patterns = re.findall(r"/sbin/zfs (\^\S.*\$)$", rules, re.M)
    patterns = [rx for rx in patterns if rx.startswith(("^create", "^set"))]
    assert len(patterns) == 2
    for steps in (_plan("FreeBSD", "zfs", {MOUNT: "tank/backups"}),
                  _plan("FreeBSD", "zfs", {REPO: "tank/backups/t14-1"})):  # fmt: skip
        line = " ".join(steps["commands"][0][1:])
        assert any(re.fullmatch(rx, line) for rx in patterns), line
    assert not any(re.fullmatch(rx, "set mountpoint=/ tank/x") for rx in patterns)


def test_an_existing_dataset_is_only_re_exported():
    steps = _plan(
        "FreeBSD", "zfs", {REPO: "tank/backups/t14-1"}, client_address="10.0.0.9"
    )
    assert steps["commands"][0] == [
        "zfs", "set", "sharenfs=-mapall=restate:restate 10.0.0.9", "tank/backups/t14-1"
    ]  # fmt: skip


def test_linux_zfs_exports_through_its_own_exports_d_file():
    steps = _plan("Linux", "zfs", {MOUNT: "tank/backups"})
    assert steps["commands"] == [["zfs", "create", "tank/backups/t14-1"]]
    assert steps["protect"] == PROTECT
    path, text = steps["export_file"]
    assert path == f"/etc/exports.d/sysmanage-{PID}.exports"
    assert text == (f"{REPO} 192.168.4.196(rw,sync,no_subtree_check,all_squash,"
                    "anonuid=1002,anongid=1003)\n")  # fmt: skip
    assert steps["reload"] is True


def test_btrfs_creates_a_subvolume_and_plain_creates_a_directory():
    assert _plan("Linux", "btrfs")["commands"][0] == [
        "btrfs",
        "subvolume",
        "create",
        REPO,
    ]
    plain = _plan("Linux", "ext4")
    assert plain["kind"] == p.PLAIN and plain["commands"][0][0] == "mkdir"
    again = _plan("Linux", "btrfs", listdir=lambda _p: ["packs"], subvolume=True)
    assert again["commands"] == [] and again["protect"] == PROTECT  # export + perms


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"system": "FreeBSD", "fstype": "ufs"}, "zfs_required"),
        ({"system": "OpenBSD", "fstype": "ffs"}, "unsupported"),
        ({"system": "FreeBSD", "fstype": "zfs"}, "mount_point_not_dataset"),
        ({"system": "FreeBSD", "fstype": "zfs", "datasets": {MOUNT: "tank/b"},
          "listdir": lambda _p: ["packs"]}, "not_empty"),
        ({"system": "Linux", "fstype": "btrfs", "listdir": lambda _p: ["x"]}, "not_empty"),
        ({"system": "Linux", "fstype": "btrfs", "listdir": lambda _p: []}, "not_subvolume"),
        ({"system": "Linux", "fstype": "ext4", "client_address": None}, "no_address"),
    ],
)  # fmt: skip
def test_what_cannot_be_prepared_is_refused_with_a_reason(kwargs, code):
    with pytest.raises(p.PrepareRefused) as refused:
        _plan(**kwargs)
    assert refused.value.code == code and str(refused.value)


def test_an_unreadable_repository_is_never_assumed_empty():
    def denied(path):
        raise PermissionError(path)

    with pytest.raises(p.PrepareRefused) as refused:
        _plan("FreeBSD", "zfs", {MOUNT: "tank/b"}, listdir=denied)
    assert refused.value.code == "unreadable"


def test_a_missing_account_is_refused(monkeypatch):
    def gone(_name):
        raise KeyError(_name)

    monkeypatch.setattr(p.pwd, "getpwnam", gone)
    with pytest.raises(p.PrepareRefused) as refused:
        _plan("Linux", "ext4")
    assert refused.value.code == "no_account"
