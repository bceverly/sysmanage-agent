# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate after 2.2.0.14: restores through symlinks, restore hooks and
network mounts left out natively (``restate features``).

A restate that announces ``skips_network_mounts`` is told which shares an
operator's keep path leads into (``include_mount``); one that does not is
handled exactly as before.  A restore's ``resolved``, ``unmatched`` and
``hooks`` reach the server as restate wrote them, and its exit 3 is
``incomplete``."""

# pylint: disable=protected-access,redefined-outer-name

import json
import sys

import pytest

from src.sysmanage_agent.backup import job_builder
from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import network_mounts as nm
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    _drain,
    _host_policy,
    _sent,
    _write,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")

SHARE = "/home/me/rambo_forensic_copy"
MOUNTINFO = "\n".join(
    [
        "36 35 98:0 / / rw - ext4 /dev/sda1 rw",
        f"37 35 98:0 / {SHARE} rw - cifs //100.78.140.20/rambo rw",
        "38 35 98:0 / /data/nfs rw - nfs4 nas:/d rw",
    ]
)
NATIVE = dict(
    FEATURES,
    skips_network_mounts=True,
    job_keys=sorted(set(FEATURES["job_keys"]) | {"rules", "include_mount"}),
)


def _keeping(*paths):
    return _host_policy(
        jobs={"capture": {"keep_paths": list(paths)}, "estimate": {}, "snapshots": {}}
    )


@pytest.fixture
def written(ops, monkeypatch):
    """``{dest: content}`` of every root file the agent installs."""
    files = {}

    async def install(content, dest):
        files[dest] = content

    monkeypatch.setattr(ops, "_install_root_file", install)
    monkeypatch.setattr(nm, "read_host_mountinfo", lambda: MOUNTINFO)
    return files


def test_include_mount_is_validated_like_the_other_job_keys():
    assert v.check_mount_points([SHARE]) == [SHARE]
    for bad in (["relative"], ["/a/../b"], ["/a\nb"], [" /a"], "/a", [7]):
        with pytest.raises(v.PolicyError):
            v.check_mount_points(bad)
    with pytest.raises(v.PolicyError):
        v.check_mount_points([f"/m{i}" for i in range(v.MAX_LIST + 1)])


def test_only_the_walks_get_include_mount():
    policy = {"policy_id": PID, "repository": "/r",
              "jobs": {"capture": {}, "estimate": {}, "snapshots": {}}}  # fmt: skip
    jobs = job_builder.build_jobs(policy, state_dir="/s", group="g",
                                  key_installed=False, include_mounts=[SHARE])  # fmt: skip
    assert jobs["capture"]["include_mount"] == [SHARE]
    assert jobs["estimate"]["include_mount"] == [SHARE]
    assert "include_mount" not in jobs["snapshots"]
    assert "include_mount = " + SHARE in contract.render_job(jobs["capture"])
    plain = job_builder.build_jobs(policy, state_dir="/s", group="g",
                                   key_installed=False)  # fmt: skip
    assert "include_mount" not in plain["capture"]
    with pytest.raises(v.PolicyError):
        job_builder.build_jobs(policy, state_dir="/s", group="g",
                               key_installed=False, include_mounts=["x"])  # fmt: skip


def test_a_status_job_inherits_what_the_capture_recorded():
    job = job_builder.build_status_job(
        {"policy_id": PID}, repository="/r", state_dir="/s", group="g"
    )
    assert "include_mount" not in job


@pytest.mark.asyncio
async def test_native_restate_walks_the_share_a_keep_path_leads_into(
    ops, written, monkeypatch
):
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: NATIVE))
    answer = await ops.backup_configure(_keeping(SHARE + "/case-12/**"))
    assert answer["success"], answer
    assert answer["network_mounts"] == {"excluded": [], "kept": [SHARE], "native": True}
    for action in ("capture", "estimate"):
        job = written[contract.job_path(PID, action)]
        assert f"include_mount = {SHARE}\n" in job
        assert "/data/nfs" not in job
    assert job_builder.network_rules_path(PID) not in written


@pytest.mark.asyncio
async def test_native_restate_without_include_mount_gets_no_such_key(
    ops, written, monkeypatch
):
    native = dict(
        NATIVE, job_keys=[k for k in NATIVE["job_keys"] if k != "include_mount"]
    )
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: native))
    answer = await ops.backup_configure(_keeping(SHARE + "/**"))
    assert answer["success"], answer
    assert answer["network_mounts"] == {"excluded": [], "kept": [], "native": True}
    assert "include_mount" not in written[contract.job_path(PID, "capture")]


@pytest.mark.asyncio
async def test_an_older_restate_keeps_the_rules_file_and_no_include_mount(
    ops, written, monkeypatch
):
    old = dict(FEATURES, job_keys=sorted(set(FEATURES["job_keys"]) | {"rules"}))
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: old))
    answer = await ops.backup_configure(_keeping(SHARE + "/**"))
    assert answer["success"], answer
    assert answer["network_mounts"]["kept"] == [SHARE]
    assert answer["network_mounts"]["native"] is False
    capture = written[contract.job_path(PID, "capture")]
    assert "include_mount" not in capture
    assert job_builder.network_rules_path(PID) in capture


@pytest.mark.asyncio
async def test_a_share_no_job_line_can_hold_is_left_out(ops, written, monkeypatch):
    odd = "/srv/odd\\040"  # mountinfo's escaped trailing space
    table = MOUNTINFO + f"\n39 35 98:0 / {odd} rw - nfs nas:/o rw"
    monkeypatch.setattr(nm, "read_host_mountinfo", lambda: table)
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: NATIVE))
    answer = await ops.backup_configure(_keeping("/srv/odd /x/**", SHARE + "/**"))
    assert answer["network_mounts"]["kept"] == [SHARE]


RESTORE = {
    "from": "repo::s1",
    "root": "/",
    "dry_run": False,
    "resolved": [{"include": "/var/snap/nextcloud/current/nextcloud/data",
                  "path": "/var/snap/nextcloud/54589/nextcloud/data",
                  "through": ["/var/snap/nextcloud/current"]}],  # fmt: skip
    "unmatched": ["/etc/nothing-here"],
    "hooks": [{"dump_dir": "/var/lib/restate/dumps/nextcloud", "kind": "nextcloud",
               "name": "nextcloud", "status": "failed"}],  # fmt: skip
}


@pytest.mark.asyncio
async def test_a_restore_result_reaches_the_server_whole_and_incomplete(
    ops, agent, monkeypatch
):
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: NATIVE))
    await ops.backup_configure(_host_policy())
    _write(
        job_builder.result_path(ops.state_dir, PID, "restore"),
        json.dumps({"schema": 1, "exit": 3, "status": "incomplete",
                    "restore": RESTORE}),
    )  # fmt: skip
    record = ops._new_record(PID, "restore")
    await ops._finish(RID, record, 3)
    await _drain(ops)
    report = _sent(agent, "backup_result")[-1]
    assert (report["status"], report["exit"]) == ("incomplete", 3)
    assert report["result"]["restore"] == RESTORE


@pytest.mark.asyncio
async def test_a_result_the_queue_refuses_is_retried_and_kept_in_flight(
    ops, agent, monkeypatch
):
    """A full disk refused the agent's queue and beast's capture result was
    dropped (production, 2026-11-01): it is retried, and the run stays in
    flight until it is queued, so a restart would report it again."""
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: NATIVE))
    monkeypatch.setattr(
        "src.sysmanage_agent.operations.backup_operations.RESEND_SECONDS", 0
    )
    await ops.backup_configure(_host_policy())
    _write(
        job_builder.result_path(ops.state_dir, PID, "capture"),
        json.dumps({"schema": 1, "exit": 0, "status": "ok"}),
    )
    record = ops._new_record(PID, "capture")
    ops._save("inflight.json", {RID: record})
    agent.send_message.side_effect = [False, False, True]
    await ops._finish(RID, record, 0)
    assert RID in ops._load("inflight.json")
    await _drain(ops)
    assert len(_sent(agent, "backup_result")) == 3
    assert RID not in ops._load("inflight.json")
