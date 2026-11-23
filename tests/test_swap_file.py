# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""SysManage's swap file for the antivirus memory floor: where it may go,
what it runs, and that every command it runs is exactly what sudoers allows."""

import pytest

from src.sysmanage_agent.collection.hardware_collector_bsd import parse_swapctl_total_kb
from src.sysmanage_agent.operations import swap_file as sw

GB = 1024


def _space(table):
    return lambda mount: table[mount]


def test_the_size_is_whole_gb_from_one_to_eight():
    assert sw.check_size(2048) == 2048
    assert sw.check_size("4096") == 4096
    for bad in (512, 1500, 9216, "x", None):
        with pytest.raises(sw.SwapRefused):
            sw.check_size(bad)


def test_it_goes_where_there_is_most_room_and_a_reserve_stays_free():
    mounts = {"/": "ext4", "/var": "ext4", "/boot": "vfat"}
    space = _space({"/": (20 * GB, 6 * GB), "/var": (50 * GB, 30 * GB)})
    assert sw.choose_mount("Linux", 2 * GB, mounts, space) == "/var"
    tight = _space({"/": (20 * GB, 3 * GB), "/var": (50 * GB, 7 * GB)})
    with pytest.raises(sw.SwapRefused) as refused:
        sw.choose_mount("Linux", 3 * GB, mounts, tight)  # /var would keep 4 < 5 GB
    assert refused.value.code == "no_room"


@pytest.mark.parametrize("fstype", ["btrfs", "zfs", "overlay", "tmpfs"])
def test_no_swap_file_on_filesystems_that_do_not_take_one(fstype):
    with pytest.raises(sw.SwapRefused) as refused:
        sw.choose_mount("Linux", GB, {"/": fstype}, _space({"/": (100 * GB, 90 * GB)}))
    assert refused.value.code == "unsupported_filesystem"
    assert fstype in str(refused.value)


def test_the_commands_per_os():
    assert sw.plan("Linux", "/sysmanage.swap", 2048, exists=False) == [
        ["dd", "bs=1048576", "count=2048", "if=/dev/zero", "of=/sysmanage.swap"],
        ["chmod", "600", "/sysmanage.swap"],
        ["mkswap", "/sysmanage.swap"],
        ["swapon", "/sysmanage.swap"],
    ]
    assert sw.plan("Linux", "/sysmanage.swap", 2048, exists=True) == [
        ["swapon", "/sysmanage.swap"]
    ]
    assert sw.plan("FreeBSD", "/usr/sysmanage.swap", 1024, False)[-1] == [
        "swapon",
        "-aL",
    ]
    assert sw.plan("NetBSD", "/sysmanage.swap", 1024, False)[-1] == [
        "swapctl",
        "-a",
        "/sysmanage.swap",
    ]
    assert sw.fstab_line("FreeBSD", "/usr/sysmanage.swap").startswith(
        "md99\tnone\tswap\tsw,file=/usr/sysmanage.swap,late"
    )
    assert sw.fstab_line("Linux", "/sysmanage.swap").split() == [
        "/sysmanage.swap",
        "none",
        "swap",
        "sw",
        "0",
        "0",
    ]


def test_dd_writes_only_the_swap_file_whatever_it_is_given():
    """if= and of= come LAST: dd honors the last of each."""
    argv = sw.plan("Linux", "/var/sysmanage.swap", 1024, False)[0]
    assert argv[-2:] == ["if=/dev/zero", "of=/var/sysmanage.swap"]


@pytest.mark.parametrize(
    "system,sudoers,dd",
    [
        ("Linux", "installer/ubuntu/sysmanage-agent.sudoers", "/usr/bin/dd"),
        ("Linux", "installer/centos/sysmanage-agent.sudoers", "/usr/bin/dd"),
        ("NetBSD", "installer/netbsd/sysmanage_agent.sudoers", "/bin/dd"),
    ],
)
def test_every_planned_dd_is_spelled_out_in_sudoers(system, sudoers, dd):
    with open(sudoers, encoding="utf-8") as handle:
        rules = handle.read()
    for mount in sw.CANDIDATES:
        for size in range(sw.MIN_SIZE_MB, sw.MAX_SIZE_MB + 1, 1024):
            argv = sw.plan(system, sw.swap_path(mount), size, False)[0]
            assert " ".join([dd] + argv[1:]) in rules, (mount, size)
    assert "count=*" not in rules  # sudo-rs refuses it, and it is unsafe


def test_listed_in_fstab():
    text = "UUID=x / ext4 defaults 0 1\n/sysmanage.swap none swap sw 0 0\n"
    assert sw.listed(text, "/sysmanage.swap")
    assert not sw.listed("# /sysmanage.swap none swap sw 0 0\n", "/sysmanage.swap")
    assert sw.listed(
        "md99 none swap sw,file=/usr/sysmanage.swap,late 0 0", "/usr/sysmanage.swap"
    )


def test_mount_tables():
    linux = (
        "/dev/vda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n/dev/vdb /var xfs rw 0 0\n"
    )
    assert sw.parse_linux_mounts(linux) == {"/": "ext4", "/proc": "proc", "/var": "xfs"}
    openbsd = (
        "/dev/sd0a on / type ffs (local)\n/dev/sd0e on /home type ffs (local, nodev)\n"
    )
    assert sw.parse_bsd_mounts(openbsd) == {"/": "ffs", "/home": "ffs"}
    freebsd = (
        "/dev/ada0p2 on / (ufs, local, soft-updates)\nzroot on /zroot (zfs, local)\n"
    )
    assert sw.parse_bsd_mounts(freebsd) == {"/": "ufs", "/zroot": "zfs"}


def test_bsd_swap_totals():
    assert (
        parse_swapctl_total_kb(
            "total: 1048576 1K-blocks allocated, 0 used, 1048576 available"
        )
        == 1048576
    )
    assert (
        parse_swapctl_total_kb("total: 524288K allocated, 0K used, 524288K available")
        == 524288
    )
    assert parse_swapctl_total_kb("no swap devices configured") is None


def test_refusals_say_why(monkeypatch):
    monkeypatch.setattr(sw.platform, "system", lambda: "Darwin")
    assert sw.ensure_swap({"size_mb": 2048})["reason"] == "unsupported_os"
    monkeypatch.setattr(sw.platform, "system", lambda: "OpenBSD")
    monkeypatch.setattr(sw, "_root", lambda: False)
    assert sw.ensure_swap({"size_mb": 2048})["reason"] == "needs_root"
    monkeypatch.setattr(sw.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sw, "in_container", lambda: True)
    assert sw.ensure_swap({"size_mb": 2048})["reason"] == "container"
    assert sw.ensure_swap({"size_mb": 100})["reason"] == "invalid_request"


def test_a_new_swap_file_is_made_turned_on_and_listed(monkeypatch, tmp_path):
    monkeypatch.setattr(sw.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sw, "in_container", lambda: False)
    monkeypatch.setattr(sw, "_mounts", lambda system: {"/": "ext4"})
    monkeypatch.setattr(sw, "_space", lambda mount: (40 * GB, 30 * GB))
    monkeypatch.setattr(sw.os.path, "exists", lambda path: False)
    ran, installed = [], []
    monkeypatch.setattr(
        sw, "_run", lambda argv, timeout=1800: (ran.append(argv), (0, ""))[1]
    )
    monkeypatch.setattr(sw, "_read", lambda path: "UUID=x / ext4 defaults 0 1\n")
    monkeypatch.setattr(sw, "_install_fstab", installed.append)
    result = sw.ensure_swap({"size_mb": 2048})
    assert (
        result["success"] and result["path"] == "/sysmanage.swap" and result["created"]
    )
    assert [a[0] for a in ran] == ["dd", "chmod", "mkswap", "swapon"]
    assert installed and "/sysmanage.swap\tnone\tswap\tsw\t0\t0" in installed[0]
