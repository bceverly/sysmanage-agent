# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Shared fakes and fixtures for the restate driver tests (Phase 24).

Every privileged step is a subprocess, so ``_run`` is replaced with a fake
that records argv and answers from a script; no sudo, systemctl or zfs runs.
"""

# pylint: disable=protected-access,redefined-outer-name

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations import backup_operations as ops_module
from src.sysmanage_agent.operations.backup_operations import BackupOperations

PID = "3f2a0000-0000-4000-8000-0000000000c1"
RID = "7b1c0000-0000-4000-8000-0000000000aa"
FEATURES = {
    "version": "2.0.0.0",
    "job_keys": sorted(
        {"command", "repository", "result", "progress", "report_group",
         "encrypt_to", "append_only", "quiesce", "keep_last", "restore_root",
         "dry_run", "check_first", "snapshot", "include", "allow_unverified",
         "read_all", "metadata_only", "record", "whole_packs", "rules"}
    ),
}  # fmt: skip
STORAGE_TARGET = {"mount_point": "/srv/backups/restate", "repo_dir": "h-1"}


class FakeRun:
    """Stands in for ``BackupOperations._run``: records argv, scripted answers."""

    def __init__(self):
        self.calls = []
        self.active = set()  # units systemctl show reports as active
        self.fail = {}  # argv[0..] prefix (tuple) -> (code, err)
        self.exit_status = "0"

    async def __call__(self, argv):
        self.calls.append(list(argv))
        bare = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
        for prefix, answer in self.fail.items():
            if tuple(bare[: len(prefix)]) == prefix:
                return answer[0], "", answer[1]
        if bare[:2] == ["systemctl", "show"]:
            state = "active" if bare[2] in self.active else "inactive"
            return (
                0,
                f"ActiveState={state}\nResult=success\nExecMainStatus={self.exit_status}\n",
                "",
            )
        return 0, "", ""

    def ran(self, *words):
        return [c for c in self.calls if all(w in c for w in words)]


@pytest.fixture
def agent():
    approval = SimpleNamespace(host_id="host-1")
    return SimpleNamespace(
        registration_manager=Mock(
            get_host_approval_from_db=Mock(return_value=approval)
        ),
        create_message=Mock(
            side_effect=lambda kind, data: {"message_type": kind, "data": data}
        ),
        send_message=AsyncMock(return_value=True),
    )


@pytest.fixture
def ops(agent, tmp_path, monkeypatch):
    backup = BackupOperations(agent, state_dir=str(tmp_path))
    # The runner comes from platform.system(); these tests are the Linux
    # (systemd) driver on every CI leg, macOS included.
    backup.runner = job_runner.SYSTEMD
    fake = FakeRun()
    monkeypatch.setattr(backup, "_run", fake)
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: FEATURES))
    monkeypatch.setattr(ops_module.restate_probe, "unavailable_reason", lambda *a: None)
    monkeypatch.setattr(ops_module, "_agent_group", lambda: "sysmanage-agent")
    monkeypatch.setattr(ops_module, "POLL_SECONDS", 0)
    monkeypatch.setattr(ops_module, "PROGRESS_EVERY_SECONDS", 0)
    monkeypatch.setattr(ops_module.validation, "check_target", _fake_target)
    # The storage takes the capture unless a test says otherwise.
    monkeypatch.setattr(ops_module.host_mount, "preflight", lambda where: None)
    # Plain mount(8) unless a test says otherwise (the systemd path has its
    # own tests in test_backup_operations_storage.py).
    monkeypatch.setattr(ops_module.host_mount, "systemd_running", lambda: False)
    # The host's repository is on NFS unless a test says otherwise.
    monkeypatch.setattr(BackupOperations, "_mounts",
                        staticmethod(lambda: {"/mnt/sysmanage-backup": "nfs4"}))  # fmt: skip
    backup.fake = fake
    return backup


def _fake_target(role, target, **_kw):
    del role
    return target["mount_point"], f"{target['mount_point']}/{target['repo_dir']}"


def _host_policy(**over):
    params = {
        "policy_id": PID,
        "role": "host",
        "target": {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1"},
        "jobs": {"capture": {"quiesce": True}, "snapshots": {}},
    }
    params.update(over)
    return params


def _sent(agent, kind):
    return [c.args[0]["data"] for c in agent.send_message.await_args_list
            if c.args[0]["message_type"] == kind]  # fmt: skip


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


async def _drain(backup):
    while backup._tasks:
        await asyncio.gather(*list(backup._tasks))


@pytest.fixture
def job_files(monkeypatch, tmp_path):
    jobs = tmp_path / "jobs.d"
    jobs.mkdir()
    monkeypatch.setattr(contract, "JOBS_DIR", str(jobs))
    return jobs


def _touch_jobs(job_files, *actions):
    for action in actions:
        (job_files / f"{PID}.{action}.conf").write_text("command = x\n")


def _storage_policy(seal):
    return {"policy_id": PID, "role": "storage", "target": STORAGE_TARGET,
            "jobs": {"check": {"read_all": True}, "seal": seal}}  # fmt: skip
