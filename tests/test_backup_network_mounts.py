# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A host's backup never carries another server's data (2026-11-01).

beast had an NFS share from the NAS, an SMB share over Tailscale and an
automounted NFS share; restate would have walked into all three (and the walk
itself would have mounted the automount).  The agent leaves them out with a
rules file of its own until restate does it natively."""

# pylint: disable=protected-access,redefined-outer-name

import sys

import pytest

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import network_mounts as nm
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    _host_policy,
    _touch_jobs,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")


def _line(point, fstype, source="x"):
    return f"36 35 98:0 / {point} rw,noatime master:1 - {fstype} {source} rw"


MOUNTINFO = "\n".join(
    [
        _line("/", "ext4", "/dev/mapper/vg-root"),
        _line("/boot", "ext4", "/dev/nvme0n1p2"),
        _line("/home/me/dev/productions", "nfs4", "nas:/zfs/productions"),
        _line("/home/me/rambo_forensic_copy", "cifs", "//100.78.140.20/rambo"),
        _line("/home/me/dev/RAMBOUILLET-backup", "autofs", "systemd-1"),
        _line("/var/lib/docker/overlay2/abc/merged", "overlay", "overlay"),
        _line("/mnt/sysmanage-backup/nas-1", "nfs4", "192.168.4.10:/restate/h-1"),
        _line("/run/user/1000/gvfs", "fuse.gvfsd-fuse", "gvfsd-fuse"),
        _line("/proc/sys/fs/binfmt_misc", "autofs", "systemd-1"),
        _line("/srv/with\\040space", "nfs", "nas:/srv"),
    ]
)


def test_network_and_automount_points_are_found_and_nothing_else():
    found = nm.scan(MOUNTINFO, repository_mount="/mnt/sysmanage-backup")
    assert found.excluded == [
        "/home/me/dev/RAMBOUILLET-backup",
        "/home/me/dev/productions",
        "/home/me/rambo_forensic_copy",
        "/srv/with space",
    ]
    assert found.kept == [] and found.native is False


def test_a_keep_path_inside_a_share_opts_that_share_in():
    found = nm.scan(MOUNTINFO, keep_paths=["/home/me/rambo_forensic_copy/case-12/**",
                                           "/home/me/**/.config", "*.db"])  # fmt: skip
    assert "/home/me/rambo_forensic_copy" in found.kept
    assert "/home/me/rambo_forensic_copy" not in found.excluded
    # A keep ABOVE a share (or one with no leading /) opts nothing in.
    assert "/home/me/dev/productions" in found.excluded


def test_rules_escape_glob_characters_and_refuse_what_a_line_cannot_hold():
    text, unexpressed = nm.rules_text(["/srv/a*b?", "/srv/x #1", "/srv/[y]", " /lead"])
    lines = [line for line in text.splitlines() if not line.startswith("#")]
    assert lines == [
        "ephemeral /srv/a\\*b\\?",
        "ephemeral /srv/x \\#1",
        "ephemeral /srv/\\[y]",
    ]
    assert unexpressed == [" /lead"]


def test_restate_that_skips_network_mounts_itself_is_left_to_it():
    assert nm.skips_network_mounts({"skips_network_mounts": True})
    assert not nm.skips_network_mounts({"version": "2.2.0.14"})
    assert not nm.skips_network_mounts(None)


def test_the_capture_reads_the_network_rules_before_the_operator_rules():
    policy = {"policy_id": PID, "repository": "/r",
              "jobs": {"capture": {"skip_paths": ["**/previews"]}, "snapshots": {}}}  # fmt: skip
    jobs = job_builder.build_jobs(policy, state_dir="/s", group="g",
                                  key_installed=False, network_rules=True)  # fmt: skip
    assert jobs["capture"]["rules"] == [job_builder.network_rules_path(PID),
                                        job_builder.rules_path(PID)]  # fmt: skip
    assert "rules" not in jobs["snapshots"]
    plain = job_builder.build_jobs(
        policy, state_dir="/s", group="g", key_installed=False
    )
    assert plain["capture"]["rules"] == [job_builder.rules_path(PID)]


@pytest.fixture
def written(ops, monkeypatch):
    """``{dest: content}`` of every root file the agent installs."""
    files = {}

    async def install(content, dest):
        files[dest] = content

    monkeypatch.setattr(ops, "_install_root_file", install)
    monkeypatch.setattr(
        nm, "read_host_mountinfo",
        lambda: MOUNTINFO,
    )  # fmt: skip
    return files


@pytest.mark.asyncio
async def test_configure_writes_the_rules_and_reports_what_it_left_out(ops, written):
    answer = await ops.backup_configure(_host_policy())
    assert answer["network_mounts"]["excluded"][:3] == [
        "/home/me/dev/RAMBOUILLET-backup",
        "/home/me/dev/productions",
        "/home/me/rambo_forensic_copy",
    ]
    rules = written[job_builder.network_rules_path(PID)]
    assert "ephemeral /home/me/dev/RAMBOUILLET-backup\n" in rules
    assert "/mnt/sysmanage-backup" not in rules  # the backup's own mount
    capture = written[contract.job_path(PID, "capture")]
    assert job_builder.network_rules_path(PID) in capture


@pytest.mark.asyncio
async def test_native_or_rule_less_restate_gets_no_rules_file(
    ops, written, monkeypatch
):
    native = dict(FEATURES, skips_network_mounts=True)
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: native))
    answer = await ops.backup_configure(_host_policy())
    assert answer["network_mounts"] == {"excluded": [], "kept": [], "native": True}
    assert job_builder.network_rules_path(PID) not in written
    old = dict(FEATURES, job_keys=[k for k in FEATURES["job_keys"] if k != "rules"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: old))
    answer = await ops.backup_configure(_host_policy())
    assert answer["network_mounts"] is None


@pytest.mark.asyncio
async def test_a_share_mounted_after_configure_is_left_out_of_the_next_capture(
    ops, written, monkeypatch, job_files
):
    monkeypatch.setattr(
        nm, "read_host_mountinfo",
        lambda: _line("/", "ext4"),
    )  # fmt: skip
    await ops.backup_configure(_host_policy())
    _touch_jobs(job_files, "capture")
    written.clear()
    later = "\n".join([_line("/", "ext4"), _line("/data/share", "nfs4", "nas:/d")])
    monkeypatch.setattr(
        nm, "read_host_mountinfo",
        lambda: later,
    )  # fmt: skip
    answer = await ops.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["success"], answer
    assert "ephemeral /data/share" in written[job_builder.network_rules_path(PID)]
    assert ops._load("policies.json")[PID]["network_excluded"] == ["/data/share"]
    written.clear()  # unchanged since: nothing rewritten
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "capture"})
    assert job_builder.network_rules_path(PID) not in written
