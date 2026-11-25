# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The storage host's ``offsite_cloud_run`` command (server ROADMAP 27.3).

What must hold:
  * a bad job is refused before anything is fetched or started;
  * the credentials and key reach the detached run on its standard input
    only -- never its argv, its files or its environment;
  * a second run of the same copy is refused while one holds the lock;
  * a result written while the agent was down is still reported;
  * every sudoers file admits exactly the zfs commands the copy builds.
"""

# pylint: disable=protected-access,redefined-outer-name
import asyncio
import json
import os
import re
import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.offsite_cloud import datasets as ds
from src.sysmanage_agent.offsite_cloud import operations as ops
from src.sysmanage_agent.offsite_cloud import runfiles

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRETS = {"access_key": "AKIDLAB", "secret_key": "s3cr3t-value", "key": "A" * 43 + "="}


def _params(**over):
    params = {"action": "upload", "run_id": str(uuid.uuid4()), "copy_id": str(uuid.uuid4()),
              "bucket": "acme-offsite", "region": "us-east-2", "storage_path": "/srv/backups",
              "retention": {"full_days": 241, "incremental_days": 210}}  # fmt: skip
    params.update(over)
    return params


@pytest.fixture
def agent():
    instance = MagicMock()
    instance.registration_manager.get_host_approval_from_db.return_value = MagicMock(
        host_id="h1"
    )
    instance.create_message = lambda kind, data: {"type": kind, "data": data}
    instance.send_message = AsyncMock(return_value=True)
    return instance


@pytest.fixture
def operations(agent, tmp_path):
    return ops.OffsiteCloudOperations(agent, str(tmp_path))


def test_a_bad_job_is_refused_before_anything_happens(operations):
    with patch.object(operations, "_secrets", AsyncMock()) as secrets:
        out = asyncio.run(operations.offsite_cloud_run(_params(bucket="No_Such")))
    assert out["success"] is False and out["reason"] == "invalid_request"
    secrets.assert_not_called()


def test_without_zfs_an_upload_is_refused(operations):
    with patch.object(ops, "zfs_path", return_value=None):
        out = asyncio.run(operations.offsite_cloud_run(_params()))
    assert out["reason"] == "no_zfs"


def test_the_secrets_go_to_the_runs_stdin_only(operations, tmp_path):
    params = _params()
    started = MagicMock()
    with patch.object(ops, "zfs_path", return_value="/sbin/zfs"), patch.object(
        operations, "_secrets", AsyncMock(return_value=SECRETS)
    ), patch.object(
        ops.subprocess, "Popen", return_value=started
    ) as popen, patch.object(
        operations, "watch"
    ):
        out = asyncio.run(operations.offsite_cloud_run(params))
    assert out == {"success": True, "started": True}
    argv = popen.call_args.args[0]
    assert argv[1:3] == ["-m", "src.sysmanage_agent.offsite_cloud.runner"]
    assert "s3cr3t-value" not in json.dumps(argv)
    assert popen.call_args.kwargs["start_new_session"] is True
    assert "env" not in popen.call_args.kwargs
    written = started.stdin.write.call_args.args[0].decode()
    assert json.loads(written) == SECRETS
    started.stdin.close.assert_called_once()
    directory = runfiles.run_dir(str(tmp_path), params["copy_id"])
    for name in os.listdir(directory):
        if os.path.isfile(os.path.join(directory, name)):
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                assert "s3cr3t-value" not in handle.read()


@pytest.mark.skipif(
    sys.platform == "win32", reason="flock is Unix only; so is the copy"
)
def test_a_second_run_of_a_copy_is_refused_while_one_runs(operations, tmp_path):
    params = _params()
    directory = runfiles.ensure(runfiles.run_dir(str(tmp_path), params["copy_id"]))
    held = runfiles.take_lock(directory)
    try:
        with patch.object(ops, "zfs_path", return_value="/sbin/zfs"):
            out = asyncio.run(operations.offsite_cloud_run(params))
    finally:
        held.close()
    assert out["reason"] == "busy"


def test_no_secrets_no_run(operations):
    with patch.object(ops, "zfs_path", return_value="/sbin/zfs"), patch.object(
        operations,
        "_secrets",
        AsyncMock(side_effect=PermissionError("HTTP 409: too old")),
    ), patch.object(ops.subprocess, "Popen") as popen:
        out = asyncio.run(operations.offsite_cloud_run(_params()))
    assert out["reason"] == "no_secrets" and "too old" in out["error"]
    popen.assert_not_called()


def test_a_check_runs_here_and_reports(operations, agent):
    async def go():
        with patch.object(
            operations, "_secrets", AsyncMock(return_value=SECRETS)
        ), patch.object(
            ops.runner,
            "check",
            return_value={"run_id": "r", "status": "ok", "object_lock": True},
        ):
            out = await operations.offsite_cloud_run(_params(action="check"))
            await asyncio.gather(*operations._tasks)
        return out

    assert asyncio.run(go())["started"] is True
    message = agent.send_message.call_args.args[0]
    assert message["type"] == "offsite_cloud_result"
    assert (
        message["data"]["action"] == "check" and message["data"]["object_lock"] is True
    )


def test_a_result_left_while_the_agent_was_down_is_reported(
    operations, agent, tmp_path
):
    directory = runfiles.ensure(runfiles.run_dir(str(tmp_path), "c1"))
    runfiles.write_json(
        os.path.join(directory, runfiles.JOB), {"action": "upload", "run_id": "r1"}
    )
    runfiles.write_json(
        os.path.join(directory, runfiles.RESULT), {"run_id": "r1", "status": "ok"}
    )
    asyncio.run(operations.resume_watching())
    message = agent.send_message.call_args.args[0]
    assert message["data"]["status"] == "ok" and message["data"]["action"] == "upload"
    assert not os.path.exists(os.path.join(directory, runfiles.RESULT))


def test_unavailable_without_zfs_or_off_linux_and_freebsd():
    assert ops.unavailable_reason(None, "Windows") == "wrong_platform"
    with patch.object(ops, "zfs_path", return_value=None):
        assert ops.unavailable_reason(None, "Linux") == "no_zfs"
    with patch.object(ops, "zfs_path", return_value="/sbin/zfs"):
        assert ops.unavailable_reason(None, "FreeBSD") is None


# --- sudoers ---------------------------------------------------------------------------

SNAP, BASE = "sysmanage-offsite-20261125T020000Z", "sysmanage-offsite-20261124T020000Z"
COMMANDS = [
    ds.send("tank/backups/web-1a2b3c4d", SNAP),
    ds.send("tank/backups/web-1a2b3c4d", SNAP, BASE),
    ds.destroy("tank/backups", BASE),
    ds.receive("tank/restored"),
    ds.take_snapshots(["tank/backups", "tank/backups/web-1a2b3c4d"], SNAP),
]


def _rules(path, zfs):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return [line.split(f"NOPASSWD: {zfs} ", 1)[1].strip() for line in handle
                if line.startswith("sysmanage-agent") and f"NOPASSWD: {zfs} " in line]  # fmt: skip


def _admits(rule, args):
    if rule.startswith("^"):
        return re.fullmatch(rule[1:].rstrip("$"), args) is not None
    if rule.endswith("*"):
        return args.startswith(rule[:-1])
    return args == rule


@pytest.mark.parametrize("path", ["installer/ubuntu/sysmanage-agent.sudoers",
                                  "installer/centos/sysmanage-agent.sudoers",
                                  "installer/opensuse/sysmanage-agent.sudoers"])  # fmt: skip
def test_linux_sudoers_admit_the_copys_commands(path):
    rules = _rules(path, "/usr/sbin/zfs")
    for argv in COMMANDS:
        assert any(_admits(r, " ".join(argv[1:])) for r in rules), argv
    assert not any("@sysmanage-offsite-*" in r for r in rules)  # sudo-rs refuses it


def test_freebsd_sudoers_admit_exactly_the_copys_commands():
    rules = _rules("installer/freebsd/sysmanage-agent.sudoers", "/sbin/zfs")
    for argv in COMMANDS:
        assert any(_admits(r, " ".join(argv[1:])) for r in rules), argv
    for bad in ("send -R tank@" + SNAP, "send tank@autosnap_2026", "destroy tank/backups",
                "destroy tank@autosnap_2026-11-01", "receive -F tank/x",
                "send tank@" + SNAP + " -o x"):  # fmt: skip
        assert not any(
            _admits(r, bad) for r in rules if not r.startswith("snapshot")
        ), bad
