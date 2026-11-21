# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Restoring from the off-site copy (server ROADMAP 27.3): a backed-up host's
read tokens for the copies of its repository on another storage host, and
restore and browse jobs that read one through that host's restate-proxy with
nothing mounted."""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import base64
import json
import sys

import pytest

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup import offsite
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import repository_choice
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup.mount_mixin import MOUNTS_FILE
from src.sysmanage_agent.operations.backup_operations import (
    INFLIGHT_FILE,
    BackupOperations,
)
from tests.backup_ops_support import (  # noqa: F401
    FEATURES,
    PID,
    RID,
    _host_policy,
    agent,
    ops,
)
from tests.test_backup_key_files import SECRET
from tests.test_backup_replicas import _pem

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

O1 = "6e000000-0000-4000-8000-0000000000f1"
O2 = "6e000000-0000-4000-8000-0000000000f2"
URL1 = "https://192.168.4.118:8443/v1/offsite-" + O1
URL2 = "https://far.example.com/v1/offsite-" + O2
PIN = "cd" * 32
LOCAL = "/mnt/sysmanage-backup/nas-1"
READING = {
    **FEATURES,
    "remote_repository": True,
    "job_commands": ["capture", "list", "status", "restore"],
    "job_keys": sorted(set(FEATURES["job_keys"]) | {
        "repository_token_file", "repository_ca_file", "repository_pin_sha256",
        "decrypt_with", "path",
    }),
}  # fmt: skip


@pytest.fixture
def host(ops, monkeypatch, tmp_path):
    """A backed-up host whose restate reads through a proxy, with the token
    and CA directories somewhere the test can see, and every job rendered
    kept."""
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: READING))
    for name in ("TOKEN_DIR", "CA_DIR"):
        path = tmp_path / name.lower()
        path.mkdir()
        monkeypatch.setattr(access, name, str(path))
    installed = {}
    real = ops._install_root_file

    async def install(content, dest, mode="644"):
        installed[dest] = (content, mode)
        await real(content, dest, mode)

    monkeypatch.setattr(ops, "_install_root_file", install)
    rendered = []
    real_render = contract.render_job
    monkeypatch.setattr(contract, "render_job",
                        lambda job: rendered.append(job) or real_render(job))  # fmt: skip
    ops.installed, ops.rendered = installed, rendered
    yield ops
    for task in list(ops._tasks):
        task.cancel()


def _policy(entries=None, **over):
    params = _host_policy(**over)
    if entries is not None:
        params["offsite"] = entries
    return params


def _touch(path, text="rsp_kept"):
    with open(path, "w", encoding="ascii") as out:
        out.write(text)


def _restore(**over):
    return {"run_id": RID, "policy_id": PID, "include": ["/etc/**"], **over}


# --- what the server sends -----------------------------------------------


def test_offsite_is_checked_exactly_as_replicas_are():
    checked = offsite.check_offsite(
        "host", [{"id": O1, "url": URL1, "pin_sha256": PIN.upper()}]
    )
    assert checked == [{"id": O1, "url": URL1, "pin_sha256": PIN}]
    assert offsite.check_offsite("host", None) is None
    assert offsite.check_offsite("host", []) == []
    for bad in (
        {"id": O1, "url": URL1},  # not a list
        [{"id": O1, "url": "http://far.example.com/v1/x"}],
        [{"id": O1, "url": URL1 + "/more"}],
        [{"id": "x", "url": URL1}],
        [{"id": O1, "url": URL1, "token": "rsp_x"}],
        [{"id": O1, "url": URL1, "pin_sha256": "ab"}],
        [{"id": O1, "url": URL1, "ca": "-----BEGIN PRIVATE KEY-----"}],
        [{"id": O1, "url": URL1}, {"id": O1, "url": URL2}],
        [{"id": f"6e000000-0000-4000-8000-0000000001{n:02d}", "url": URL1}
         for n in range(17)],
    ):  # fmt: skip
        with pytest.raises(v.PolicyError):
            offsite.check_offsite("host", bad)


@pytest.mark.asyncio
async def test_only_a_host_policy_may_have_offsite(host):
    params = {"policy_id": PID, "role": "storage",
              "target": {"mount_point": "/srv/backups/restate", "repo_dir": "h-1"},
              "jobs": {"check": {"read_all": False}, "seal": {"mode": "none"}},
              "offsite": [{"id": O1, "url": URL1}]}  # fmt: skip
    answer = await host.backup_configure(params)
    assert answer["success"] is False and answer["reason"] == "invalid_policy"


# --- the read tokens ------------------------------------------------------


@pytest.mark.asyncio
async def test_each_copy_gets_a_read_token_reported_only_as_its_hash(host):
    answer = await host.backup_configure(
        _policy([{"id": O1, "url": URL1}, {"id": O2, "url": URL2}])
    )
    assert answer["success"] is True, answer
    path = offsite.token_path(PID, O1)
    assert path == f"{access.TOKEN_DIR}/{PID}.offsite.{O1}.token"
    token, mode = host.installed[path]
    assert mode == "600" and token.startswith("rsp_")
    assert answer["offsite_tokens"][O1] == access.token_sha256(token)
    assert set(answer["offsite_tokens"]) == {O1, O2}
    assert answer["offsite_tokens"][O1] != answer["offsite_tokens"][O2]
    saved = host._policy(PID)
    assert saved["offsite_tokens"] == answer["offsite_tokens"]
    assert saved["offsite"] == [{"id": O1, "url": URL1}, {"id": O2, "url": URL2}]
    for text in (json.dumps(answer), json.dumps(saved)):
        assert token not in text


@pytest.mark.asyncio
async def test_a_read_token_is_made_once_and_reused(host):
    first = await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    _touch(offsite.token_path(PID, O1))  # what the install put there
    host.installed.clear()
    again = await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    assert again["offsite_tokens"] == first["offsite_tokens"]
    assert offsite.token_path(PID, O1) not in host.installed


@pytest.mark.asyncio
async def test_a_lost_read_token_file_is_made_again(host):
    first = await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    again = await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    assert again["offsite_tokens"][O1] != first["offsite_tokens"][O1]


@pytest.mark.asyncio
async def test_the_ca_is_installed_and_kept_only_as_a_flag(host):
    pem = _pem()
    await host.backup_configure(_policy([{"id": O1, "url": URL1, "ca": pem}]))
    content, mode = host.installed[offsite.ca_path(PID, O1)]
    assert content == pem.strip() + "\n" and mode == "644"
    assert offsite.ca_path(PID, O1).startswith(access.CA_DIR + "/")
    assert host._policy(PID)["offsite"] == [{"id": O1, "url": URL1, "ca": True}]


@pytest.mark.asyncio
async def test_a_copy_no_longer_listed_loses_its_token_and_ca(host):
    await host.backup_configure(
        _policy([{"id": O1, "url": URL1}, {"id": O2, "url": URL2, "ca": _pem()}])
    )
    for path in offsite.files_of(PID, O2) + [offsite.token_path(PID, O1)]:
        _touch(path)
    answer = await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    assert set(answer["offsite_tokens"]) == {O1}
    for path in offsite.files_of(PID, O2):
        assert host.fake.ran("rm", "-f", "--", path)
    assert not host.fake.ran("rm", "-f", "--", offsite.token_path(PID, O1))
    empty = await host.backup_configure(_policy([]))
    assert empty["offsite_tokens"] == {}
    assert host.fake.ran("rm", "-f", "--", offsite.token_path(PID, O1))
    assert host._policy(PID)["offsite"] == []


@pytest.mark.asyncio
async def test_an_older_server_sends_no_offsite_and_nothing_changes(host):
    first = await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    host.fake.calls.clear()
    answer = await host.backup_configure(_policy())
    assert "offsite_tokens" not in answer
    assert not host.fake.ran("rm", "-f", "--", offsite.token_path(PID, O1))
    saved = host._policy(PID)
    assert saved["offsite_tokens"] == first["offsite_tokens"]
    assert saved["offsite"] == [{"id": O1, "url": URL1}]


def test_the_stale_files_of_a_replica_are_not_an_offsite_copys():
    names = [f"{PID}.replica.{O1}.token", f"{PID}.offsite.{O2}.token"]
    assert offsite.stale_ids(PID, [], [], lambda _d: names) == [O2]


# --- restore and browse from the copy --------------------------------------


@pytest.mark.asyncio
async def test_a_restore_reads_the_copy_through_its_proxy_with_its_ca(host):
    await host.backup_configure(_policy([{"id": O1, "url": URL1, "ca": _pem()}]))
    host.fake.calls.clear()
    answer = await host.backup_restore(_restore(offsite=O1))
    assert answer["success"] is True, answer
    job = host.rendered[-1]
    assert job["command"] == "restore" and job["repository"] == URL1
    assert job["repository_token_file"] == offsite.token_path(PID, O1)
    assert job["repository_ca_file"] == offsite.ca_path(PID, O1)
    assert "repository_pin_sha256" not in job
    record = host._load(INFLIGHT_FILE)[RID]
    assert record["remote"] is True and record["offsite"] == O1
    assert "previous" not in record
    assert not host.fake.ran("mount") and not host.fake.ran("mkdir")
    assert host._load(MOUNTS_FILE) == {}


@pytest.mark.asyncio
async def test_a_restore_from_a_pinned_copy_pins_its_key(host):
    await host.backup_configure(_policy([{"id": O1, "url": URL1, "pin_sha256": PIN}]))
    answer = await host.backup_restore(_restore(offsite=O1))
    assert answer["success"] is True, answer
    job = host.rendered[-1]
    assert job["repository_pin_sha256"] == base64.b64encode(bytes.fromhex(PIN)).decode()
    assert "repository_ca_file" not in job


@pytest.mark.asyncio
async def test_an_encrypted_copy_is_restored_with_the_runs_keys(host, monkeypatch):
    async def fetch(_agent, run_id):
        assert run_id == RID
        return [SECRET]

    monkeypatch.setattr(key_files, "fetch", fetch)
    real_stage = key_files.stage
    monkeypatch.setattr(key_files, "stage",
                        lambda c: real_stage(c, dirs=(host.state_dir,)))  # fmt: skip
    await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    answer = await host.backup_restore(_restore(offsite=O1, needs_key=True))
    assert answer["success"] is True, answer
    job = host.rendered[-1]
    assert job["repository"] == URL1
    assert job["decrypt_with"] == [key_files.key_path(RID, 0)]


@pytest.mark.asyncio
async def test_a_snapshot_of_the_copy_is_browsed_through_its_proxy(host):
    await host.backup_configure(_policy([{"id": O1, "url": URL1, "pin_sha256": PIN}]))
    host.fake.calls.clear()
    answer = await host.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                    "snapshot": "20261120T010203Z", "offsite": O1})  # fmt: skip
    assert answer["status"] == "started", answer
    job = host.rendered[-1]
    assert job["command"] == "list"
    assert job["snapshot"] == f"{URL1}::20261120T010203Z"
    assert job["repository_token_file"] == offsite.token_path(PID, O1)
    assert "repository_pin_sha256" in job
    assert host._load(INFLIGHT_FILE)[RID]["offsite"] == O1
    assert not host.fake.ran("mount")


@pytest.mark.asyncio
async def test_a_job_on_the_copy_never_touches_a_local_mount(host):
    await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    host._save(MOUNTS_FILE, {LOCAL: {"runs": [RID]}})
    await host._release_mount(RID, PID, {"remote": True, "offsite": O1})
    assert not host.fake.ran("umount")
    assert host._load(MOUNTS_FILE) == {LOCAL: {"runs": [RID]}}
    await host._release_mount(RID, PID, {})  # a plain run's release still does
    assert host.fake.ran("umount")


@pytest.mark.asyncio
async def test_the_record_rederives_the_copys_url():
    policy = {"repository": LOCAL, "offsite": [{"id": O1, "url": URL1}]}
    record = {"remote": True, "offsite": O1}
    assert repository_choice.for_record(policy, record) == (URL1, None, False)
    assert repository_choice.for_record(policy, {})[0] == LOCAL


@pytest.mark.asyncio
async def test_a_restore_without_offsite_is_unchanged(host):
    await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    answer = await host.backup_restore(_restore())
    assert answer["success"] is True, answer
    job = host.rendered[-1]
    assert job["repository"] == LOCAL
    assert not {"repository_token_file", "repository_ca_file",
                "repository_pin_sha256"} & set(job)  # fmt: skip
    record = host._load(INFLIGHT_FILE)[RID]
    assert "remote" not in record and "offsite" not in record


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "over, reason",
    [
        ({"offsite": O2}, "not_configured"),
        ({"offsite": "not-a-uuid"}, "invalid_request"),
        ({"offsite": O1, "previous": True}, "invalid_request"),
    ],
)
async def test_a_bad_offsite_restore_is_refused_cleanly(host, over, reason):
    await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    host.installed.clear()
    answer = await host.backup_restore(_restore(**over))
    assert answer["success"] is False and answer["reason"] == reason, answer
    assert answer["error"]
    assert not host.installed and RID not in host._load(INFLIGHT_FILE)


@pytest.mark.asyncio
async def test_a_restate_that_cannot_read_a_proxy_is_outdated(host, monkeypatch):
    await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: FEATURES))
    answer = await host.backup_restore(_restore(offsite=O1))
    assert answer["reason"] == "tool_outdated", answer
    browse = dict(FEATURES, job_commands=["list"])
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: browse))
    answer = await host.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                    "snapshot": "s1", "offsite": O1})  # fmt: skip
    assert answer["reason"] == "tool_outdated", answer


@pytest.mark.asyncio
async def test_a_browse_of_an_unknown_copy_is_not_configured(host):
    await host.backup_configure(_policy([{"id": O1, "url": URL1}]))
    answer = await host.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                    "snapshot": "s1", "offsite": O2})  # fmt: skip
    assert answer["reason"] == "not_configured", answer


def test_the_host_says_it_reads_an_offsite_copy_only_when_restate_can():
    assert contract.OFFSITE_READ in contract.host_abilities(READING)
    assert contract.OFFSITE_READ not in contract.host_abilities(FEATURES)
    no_curl = dict(READING, programs={"curl": False})
    assert contract.OFFSITE_READ not in contract.host_abilities(no_curl)
