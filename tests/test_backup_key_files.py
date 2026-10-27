# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Decryption keys for one restate job (Pro+ backup_engine, 24.6 S4).

The key never comes in the command (the server's queue); the agent fetches
it over HTTPS for the run, installs it root-only on tmpfs, hands restate its
path with ``decrypt_with``, and removes it whatever happens."""

# pylint: disable=protected-access,redefined-outer-name

import os
import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import key_files
from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401  # pylint: disable=unused-import
    FEATURES,
    PID,
    RID,
    _host_policy,
    agent,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")
# A stand-in armored key, built from the marker check_keys() looks for.
SECRET = f"-----{key_files._ARMORED}-----\nsecret material\n"  # pylint: disable=protected-access
KEYED = dict(FEATURES, job_keys=FEATURES["job_keys"] + ["decrypt_with"],
             job_commands=["capture", "list", "status", "restore"])  # fmt: skip


def test_only_armored_secret_keys_are_accepted():
    assert key_files.check_keys({"keys": [SECRET]}) == [SECRET]
    for bad in ({}, {"keys": []}, {"keys": ["pub"]}, {"keys": [SECRET] * 17}, None):
        with pytest.raises(key_files.KeyFetchError):
            key_files.check_keys(bad)


def test_the_restate_decrypt_ability_follows_its_job_keys():
    assert "decrypt" in contract.host_abilities(KEYED)
    assert "decrypt" not in contract.host_abilities(FEATURES)


def test_stale_keys_are_those_no_running_job_owns():
    owned = key_files.key_path(RID, 0)
    names = [f"{RID}-0.key", f"{RID}-1.key", "notes.txt", "x-0.key"]
    assert key_files.stale(names, [owned]) == [key_files.key_path(RID, 1)]


@pytest.mark.asyncio
async def test_install_stages_on_tmpfs_installs_root_0600_and_cleans_up(tmp_path):
    calls = []

    async def run(argv):
        calls.append(list(argv))
        return 0, "", ""

    stage_dir = tmp_path / "shm"
    stage_dir.mkdir()
    real_stage = key_files.stage
    key_files.stage = lambda content: real_stage(content, dirs=(str(stage_dir),))
    try:
        paths = await key_files.install([SECRET, SECRET], RID, run, lambda a: a)
    finally:
        key_files.stage = real_stage
    assert paths == [key_files.key_path(RID, 0), key_files.key_path(RID, 1)]
    assert all(
        c[:8] == ["install", "-D", "-m", "600", "-o", "0", "-g", "0"] for c in calls
    )
    assert os.listdir(stage_dir) == []  # the staged copies are gone
    assert all(SECRET not in " ".join(c) for c in calls)  # never on a command line


@pytest.mark.asyncio
async def test_a_failed_install_removes_what_was_installed(tmp_path):
    calls = []

    async def run(argv):
        calls.append(list(argv))
        return (1, "", "denied") if len(calls) == 2 else (0, "", "")

    real_stage = key_files.stage
    key_files.stage = lambda content: real_stage(content, dirs=(str(tmp_path),))
    try:
        with pytest.raises(key_files.KeyFetchError):
            await key_files.install([SECRET, SECRET], RID, run, lambda a: a)
    finally:
        key_files.stage = real_stage
    assert calls[-1] == ["rm", "-f", "--", key_files.key_path(RID, 0)]
    assert os.listdir(tmp_path) == []


class _Response:
    def __init__(self, status, body):
        self.status, self.body = status, body

    async def json(self):
        return self.body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class _Session:
    def __init__(self, response):
        self.response, self.posted = response, []

    def post(self, url, **kwargs):
        self.posted.append((url, kwargs))
        return self.response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


def _agent(host_id="host-1"):
    async def token():
        return "conn-token"

    async def host_token():
        return "host-secret"

    return SimpleNamespace(
        config=SimpleNamespace(), get_auth_token=token, get_stored_host_token=host_token,
        registration_manager=SimpleNamespace(
            get_host_approval_from_db=lambda: SimpleNamespace(host_id=host_id)),
    )  # fmt: skip


@pytest.fixture
def endpoint(monkeypatch):
    from src.sysmanage_agent.core import server_endpoint  # noqa: PLC0415

    class Endpoint:
        def __init__(self, _config):
            pass

        def rest_url(self, path):
            return "https://server" + path

        def proxy(self):
            return None

        def session_kwargs(self):
            return {}

    monkeypatch.setattr(server_endpoint, "ServerEndpoint", Endpoint)


@pytest.mark.asyncio
async def test_the_key_is_fetched_over_https_with_the_hosts_credentials(endpoint):
    session = _Session(_Response(200, {"keys": [SECRET]}))
    assert await key_files.fetch(_agent(), RID, session_factory=lambda: session) == [
        SECRET
    ]
    url, kwargs = session.posted[0]
    assert url == "https://server/api/agent/backup-key"
    assert kwargs["json"] == {"host_id": "host-1", "run_id": RID}
    assert kwargs["headers"]["X-Host-Token"] == "host-secret"


@pytest.mark.asyncio
async def test_a_refused_fetch_says_why(endpoint):
    session = _Session(
        _Response(409, {"detail": "This backup run's key was already released"})
    )
    with pytest.raises(key_files.KeyFetchError, match="already released"):
        await key_files.fetch(_agent(), RID, session_factory=lambda: session)


@pytest.mark.asyncio
async def test_a_run_that_needs_no_key_fetches_none():
    assert await key_files.for_run(None, KEYED, RID, {}, None, None) == []
    with pytest.raises(v.PolicyError):
        await key_files.for_run(None, FEATURES, RID, {"needs_key": True}, None, None)


@pytest.fixture
def keyed_ops(ops, monkeypatch):
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: KEYED))

    async def fetch(_agent, run_id):
        assert run_id == RID
        return [SECRET]

    monkeypatch.setattr(key_files, "fetch", fetch)
    real_stage = key_files.stage
    monkeypatch.setattr(
        key_files, "stage", lambda c: real_stage(c, dirs=(ops.state_dir,))
    )
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(
        contract, "render_job", lambda job: rendered.append(job) or real(job)
    )
    ops.rendered = rendered
    return ops


@pytest.mark.asyncio
async def test_an_encrypted_restore_hands_restate_the_key_file_only(keyed_ops):
    ops = keyed_ops
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_restore({"run_id": RID, "policy_id": PID,
                                       "include": ["/etc/hosts"], "needs_key": True})  # fmt: skip
    assert answer["status"] == "started", answer
    job = ops.rendered[-1]
    assert job["decrypt_with"] == [key_files.key_path(RID, 0)]
    assert SECRET not in contract.render_job(job)  # the path, never the key
    assert ops.fake.ran("install", "600", key_files.key_path(RID, 0))
    record = ops._load("inflight.json")[RID]
    assert record["key_files"] == [key_files.key_path(RID, 0)]
    await ops._finish(RID, record, 0)
    assert ops.fake.ran("rm", "-f", key_files.key_path(RID, 0))
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_a_job_that_does_not_start_leaves_no_key(keyed_ops):
    ops = keyed_ops
    await ops.backup_configure(_host_policy())
    ops.fake.fail[("systemctl", "--no-block")] = (1, "unit failed")
    answer = await ops.backup_restore({"run_id": RID, "policy_id": PID,
                                       "include": ["/etc/hosts"], "needs_key": True})  # fmt: skip
    assert answer["success"] is False
    assert ops.fake.ran("rm", "-f", key_files.key_path(RID, 0))


@pytest.mark.asyncio
async def test_a_key_the_server_will_not_release_is_a_clear_refusal(
    keyed_ops, monkeypatch
):
    ops = keyed_ops

    async def refused(_agent, _run_id):
        raise key_files.KeyFetchError(
            "The server did not release the backup key: HTTP 409"
        )

    monkeypatch.setattr(key_files, "fetch", refused)
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_restore({"run_id": RID, "policy_id": PID,
                                       "include": ["/etc"], "needs_key": True})  # fmt: skip
    assert answer["reason"] == "key_unavailable" and "409" in answer["error"]


@pytest.mark.asyncio
async def test_an_encrypted_listing_gets_the_key_too(keyed_ops):
    ops = keyed_ops
    await ops.backup_configure(_host_policy())
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "list",
                                   "snapshot": "s1", "path": "/", "needs_key": True})  # fmt: skip
    assert answer["status"] == "started", answer
    assert ops.rendered[-1]["decrypt_with"] == [key_files.key_path(RID, 0)]
    for task in list(ops._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_leftover_keys_are_swept_at_start():
    calls = []

    async def run(argv):
        calls.append(list(argv))
        return 0, "", ""

    owned = {"r": {"key_files": [key_files.key_path(RID, 0)]}}
    await key_files.sweep(owned, run, lambda a: a,
                          listdir=lambda _d: [f"{RID}-0.key", f"{RID}-1.key"])  # fmt: skip
    assert calls == [["rm", "-f", "--", key_files.key_path(RID, 1)]]
