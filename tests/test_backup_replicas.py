# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Off-site copies (server ROADMAP 27.3): a storage host's replicas, its copy
tokens for them, and the copy run into one through its restate-proxy."""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import replicas
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401
    FEATURES,
    PID,
    RID,
    STORAGE_TARGET,
    agent,
    ops,
)

R1 = "4d000000-0000-4000-8000-0000000000e1"
R2 = "4d000000-0000-4000-8000-0000000000e2"
URL1 = "https://192.168.4.118:8443/v1/replica-" + R1
URL2 = "https://offsite.example.com/v1/replica-" + R2
PIN = "ab" * 32
SNAP = "20261120T212026Z"
REPOSITORY = f"{STORAGE_TARGET['mount_point']}/h-1"
COPYING = {
    **FEATURES,
    "version": "3.4.0.1",
    "remote_repository": True,
    "remote_capture": True,
    "commands": ["copy", "check"],
    "job_commands": ["copy", "check"],
    "job_keys": sorted(set(FEATURES["job_keys"]) | {
        "copy_to", "repository_token_file", "repository_ca_file",
        "repository_pin_sha256",
    }),
    "job_command_keys": {"copy": [
        "command", "repository", "snapshot", "copy_to", "syslog", "result",
        "progress", "report_group", "repository_token_file",
        "repository_ca_file", "repository_pin_sha256",
    ]},
}  # fmt: skip


def _pem(count: int = 1) -> str:
    out = []
    for serial in range(1, count + 1):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"ca{serial}")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .sign(key, hashes.SHA256())
        )  # fmt: skip
        out.append(cert.public_bytes(serialization.Encoding.PEM).decode())
    return "".join(out)


@pytest.fixture
def storage(ops, monkeypatch, tmp_path):
    """A storage host whose restate copies through a proxy, with the token
    and CA directories somewhere the test can see, and every job rendered
    kept."""
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: COPYING))
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
    return ops


def _policy(replica_list=None, **over):
    params = {"policy_id": PID, "role": "storage",
              "target": {**STORAGE_TARGET, "repo_dir": "h-1"},
              "jobs": {"check": {"read_all": False}, "seal": {"mode": "none"}}}  # fmt: skip
    if replica_list is not None:
        params["replicas"] = replica_list
    params.update(over)
    return params


def _touch(path, text="rsp_kept"):
    with open(path, "w", encoding="ascii") as out:
        out.write(text)


# --- what the server sends -----------------------------------------------


def test_a_replica_url_is_https_to_a_proxy_and_nothing_else():
    for good in (
        URL1,
        URL2,
        "https://nas/v1/a",
        "https://[fd00::12]:8443/v1/client.name_1-x",
        "https://nas.example.lan:1/v1/" + "c" * 128,
    ):
        assert replicas.check_url(good) == good
    for bad in (
        "http://nas/v1/x",
        "https://nas/v2/x",
        "https://nas/v1/",
        "https://nas/v1/x/y",
        "https://nas:0/v1/x",
        "https://nas:65536/v1/x",
        "https://user@nas/v1/x",
        "https://user:pw@nas/v1/x",
        "https://nas/v1/x?a=b",
        "https://nas/v1/x#frag",
        "https://nas/v1/.x",
        "https://nas/v1/-x",
        "https://nas/v1/" + "c" * 129,
        "https://-nas/v1/x",
        "https://nas_1/v1/x",
        "https://999.1.1.1/v1/x",
        "https://1.2.3/v1/x",
        "https://[1.2.3.4]/v1/x",
        "https://[fe80::1%eth0]/v1/x",
        "https://fd00::12/v1/x",
        "https://nas/v1/x\n",
        "file:///srv/x",
        "/srv/backups/offsite",
        None,
        42,
    ):
        with pytest.raises(v.PolicyError):
            replicas.check_url(bad)


def test_a_replica_ca_is_certificates_never_a_key():
    one, chain = _pem(), _pem(2)
    assert replicas.check_ca(one) == one.strip() + "\n"
    assert replicas.check_ca(chain) == chain.strip() + "\n"
    for bad in (
        one + "-----BEGIN PRIVATE KEY-----\n",
        "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
        "hello",
        "-----BEGIN CERTIFICATE-----\n" + "A" * (access.MAX_CA_BYTES + 1),
        7,
    ):
        with pytest.raises(v.PolicyError):
            replicas.check_ca(bad)


def test_replicas_are_checked_strictly():
    assert replicas.check_replicas(None) is None
    assert replicas.check_replicas([]) == []
    checked = replicas.check_replicas(
        [{"id": R1.upper(), "url": URL1, "pin_sha256": PIN.upper()}]
    )
    assert checked == [{"id": R1, "url": URL1, "pin_sha256": PIN}]
    for bad in (
        {"id": R1},
        [{"id": "not-a-uuid", "url": URL1}],
        [{"id": R1, "url": URL1, "token": "rsp_x"}],
        [{"id": R1, "url": URL1, "pin_sha256": "ab"}],
        [{"id": R1, "url": URL1, "pin_sha256": "zz" * 32}],
        [{"id": R1, "url": URL1}, {"id": R1, "url": URL2}],
        [{"id": R1, "url": "https://nas/v1/x?x"}],
        [{"id": R1, "url": URL1}] * (replicas.MAX_REPLICAS + 1),
        ["x"],
    ):
        with pytest.raises(v.PolicyError):
            replicas.check_replicas(bad)


@pytest.mark.asyncio
async def test_only_a_storage_policy_may_have_replicas(storage):
    host = {"policy_id": PID, "role": "host",
            "target": {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1"},
            "jobs": {"capture": {}}, "replicas": [{"id": R1, "url": URL1}]}  # fmt: skip
    answer = await storage.backup_configure(host)
    assert answer["success"] is False and answer["reason"] == "invalid_policy"
    assert "replicas" in answer["error"]


def test_a_configured_copy_stays_on_this_host():
    with pytest.raises(v.PolicyError):
        v.check_job("storage", "copy", {"copy_to": URL1})
    assert v.check_job("storage", "copy", {"copy_to": "/srv/offsite/r"}) == {
        "copy_to": "/srv/offsite/r"
    }


# --- copy tokens at configure --------------------------------------------


@pytest.mark.asyncio
async def test_each_replica_gets_a_copy_token_reported_only_as_its_hash(storage):
    answer = await storage.backup_configure(
        _policy([{"id": R1, "url": URL1}, {"id": R2, "url": URL2}])
    )
    assert answer["success"] is True, answer
    assert set(answer["copy_tokens"]) == {R1, R2}
    for replica_id in (R1, R2):
        path = replicas.token_path(PID, replica_id)
        assert path == f"{access.TOKEN_DIR}/{PID}.replica.{replica_id}.token"
        token, mode = storage.installed[path]
        assert mode == "600" and token.startswith("rsp_")
        assert answer["copy_tokens"][replica_id] == access.token_sha256(token)
        assert token not in json.dumps(answer)
        assert token not in json.dumps(storage._policy(PID))
        assert not any(token in " ".join(c) for c in storage.fake.calls)
    assert answer["copy_tokens"][R1] != answer["copy_tokens"][R2]
    saved = storage._policy(PID)
    assert saved["copy_tokens"] == answer["copy_tokens"]
    assert [r["id"] for r in saved["replicas"]] == [R1, R2]


@pytest.mark.asyncio
async def test_a_copy_token_is_made_once_and_reused(storage):
    first = await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    _touch(replicas.token_path(PID, R1))  # what the install put there
    storage.installed.clear()
    again = await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    assert again["copy_tokens"] == first["copy_tokens"]
    assert replicas.token_path(PID, R1) not in storage.installed


@pytest.mark.asyncio
async def test_a_lost_token_file_is_made_again(storage):
    first = await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    again = await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    # The file never landed (the fake install writes nothing): a new token.
    assert again["copy_tokens"][R1] != first["copy_tokens"][R1]


@pytest.mark.asyncio
async def test_the_ca_is_installed_and_kept_only_as_a_flag(storage):
    pem = _pem()
    await storage.backup_configure(_policy([{"id": R1, "url": URL1, "ca": pem}]))
    text, mode = storage.installed[replicas.ca_path(PID, R1)]
    assert text == pem.strip() + "\n" and mode == "644"
    assert replicas.ca_path(PID, R1) == f"{access.CA_DIR}/{PID}.replica.{R1}.pem"
    assert storage._policy(PID)["replicas"] == [{"id": R1, "url": URL1, "ca": True}]
    _touch(replicas.ca_path(PID, R1), pem)
    await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    assert storage.fake.ran("rm", "-f", "--", replicas.ca_path(PID, R1))


@pytest.mark.asyncio
async def test_a_replica_no_longer_listed_loses_its_token_and_ca(storage):
    await storage.backup_configure(
        _policy([{"id": R1, "url": URL1}, {"id": R2, "url": URL2, "ca": _pem()}])
    )
    for path in (replicas.token_path(PID, R1), replicas.token_path(PID, R2),
                 replicas.ca_path(PID, R2)):  # fmt: skip
        _touch(path)
    other = "3f2a0000-0000-4000-8000-0000000000c9"
    _touch(replicas.token_path(other, R2))  # another policy's: never touched
    _touch(f"{access.TOKEN_DIR}/{PID}.token")  # a host token: never touched
    answer = await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    assert set(answer["copy_tokens"]) == {R1}
    assert storage.fake.ran("rm", "-f", "--", replicas.token_path(PID, R2))
    assert storage.fake.ran("rm", "-f", "--", replicas.ca_path(PID, R2))
    assert not storage.fake.ran("rm", "-f", "--", replicas.token_path(PID, R1))
    assert not storage.fake.ran("rm", "-f", "--", replicas.token_path(other, R2))
    assert not storage.fake.ran("rm", "-f", "--", f"{access.TOKEN_DIR}/{PID}.token")
    storage.fake.calls.clear()
    empty = await storage.backup_configure(_policy([]))
    assert empty["copy_tokens"] == {}
    assert storage.fake.ran("rm", "-f", "--", replicas.token_path(PID, R1))


@pytest.mark.asyncio
async def test_a_token_file_the_agent_forgot_is_still_removed(storage):
    _touch(replicas.token_path(PID, R2))
    await storage.backup_configure(_policy([]))
    assert storage.fake.ran("rm", "-f", "--", replicas.token_path(PID, R2))


@pytest.mark.asyncio
async def test_an_older_server_sends_no_replicas_and_nothing_changes(storage):
    first = await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    _touch(replicas.token_path(PID, R1))
    storage.fake.calls.clear()
    answer = await storage.backup_configure(_policy())
    assert "copy_tokens" not in answer
    assert not storage.fake.ran("rm", "-f", "--", replicas.token_path(PID, R1))
    assert storage._policy(PID)["copy_tokens"] == first["copy_tokens"]


# --- the ability ---------------------------------------------------------


def test_the_storage_host_says_it_can_copy_to_a_replica():
    assert contract.REPLICA_COPY in contract.storage_abilities(COPYING)
    assert contract.copies_remote(COPYING)
    for gone in ("remote_capture", "remote_repository"):
        assert not contract.copies_remote({**COPYING, gone: False})
    assert not contract.copies_remote({**COPYING, "commands": ["check"]})
    assert not contract.copies_remote({**COPYING, "job_commands": ["check"]})
    assert not contract.copies_remote({**COPYING, "programs": {"curl": False}})
    no_token = sorted(set(COPYING["job_keys"]) - {"repository_token_file"})
    assert not contract.copies_remote({**COPYING, "job_keys": no_token})
    assert not contract.copies_remote(
        {**COPYING, "job_command_keys": {"copy": ["command", "copy_to"]}}
    )
    # A restate that does not list keys per command is taken at its job_keys.
    unlisted = {k: val for k, val in COPYING.items() if k != "job_command_keys"}
    assert contract.copies_remote(unlisted)
    assert contract.REPLICA_COPY not in contract.storage_abilities(FEATURES)
    assert not contract.copies_remote(None)


# --- the copy run --------------------------------------------------------


def _build(replica, **params):
    return replicas.build_copy_job(
        {"policy_id": PID, "replica_id": R1, "snapshot": SNAP, **params},
        repository=REPOSITORY, replicas=[replica], state_dir="/var/lib/sa",
        group="sysmanage-agent",
    )  # fmt: skip


def test_a_copy_job_names_the_snapshot_the_replica_and_its_token():
    job = _build({"id": R1, "url": URL1})
    assert job == {
        "command": "copy",
        "snapshot": f"{REPOSITORY}::{SNAP}",
        "copy_to": URL1,
        "repository_token_file": replicas.token_path(PID, R1),
        "result": f"/var/lib/sa/backup/{PID}.copy.result.json",
        "progress": f"/var/lib/sa/backup/{PID}.copy.progress.ndjson",
        "report_group": "sysmanage-agent",
    }


def test_a_copy_job_trusts_the_replicas_ca_or_pins_its_key():
    with_ca = _build({"id": R1, "url": URL1, "ca": True})
    assert with_ca["repository_ca_file"] == replicas.ca_path(PID, R1)
    assert "repository_pin_sha256" not in with_ca
    pinned = _build({"id": R1, "url": URL1, "pin_sha256": PIN})
    assert pinned["repository_pin_sha256"] == base64.b64encode(
        bytes.fromhex(PIN)
    ).decode("ascii")
    assert "repository_ca_file" not in pinned
    both = _build({"id": R1, "url": URL1, "ca": True, "pin_sha256": PIN})
    assert {"repository_ca_file", "repository_pin_sha256"} <= set(both)


def test_a_copy_job_refuses_what_it_was_not_configured_with():
    with pytest.raises(replicas.ReplicaUnknown):
        _build({"id": R2, "url": URL2})
    for bad in ({"snapshot": "../x"}, {"snapshot": ""}, {"replica_id": "x"},
                {"policy_id": "x"}):  # fmt: skip
        with pytest.raises(v.PolicyError):
            _build({"id": R1, "url": URL1}, **bad)
    # A saved URL is checked again as it is used.
    with pytest.raises(v.PolicyError):
        _build({"id": R1, "url": "/srv/elsewhere"})


def _run(**over):
    return {"run_id": RID, "policy_id": PID, "action": "copy",
            "replica_id": R1, "snapshot": SNAP, **over}  # fmt: skip


@pytest.mark.asyncio
async def test_a_copy_run_writes_its_job_and_starts_it(storage):
    await storage.backup_configure(
        _policy([{"id": R1, "url": URL1, "pin_sha256": PIN}])
    )
    answer = await storage.backup_run(_run())
    assert answer == {"success": True, "run_id": RID, "status": "started"}, answer
    job = storage.rendered[-1]
    assert job["command"] == "copy" and job["copy_to"] == URL1
    assert job["snapshot"].endswith(f"/h-1::{SNAP}")
    assert "repository" not in job  # restate refuses it beside REPO::NAME
    assert storage.installed[contract.job_path(PID, "copy")][1] == "644"
    assert storage.fake.ran("systemctl", "--no-block", "start",
                            contract.unit_name(PID, "copy"))  # fmt: skip
    record = storage._load("inflight.json")[RID]
    assert record["action"] == "copy"
    for task in list(storage._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_a_copy_run_is_refused_cleanly(storage, monkeypatch):
    await storage.backup_configure(_policy([{"id": R1, "url": URL1}]))
    unknown = await storage.backup_run(_run(replica_id=R2))
    assert unknown["success"] is False and unknown["reason"] == "not_configured"
    bad = await storage.backup_run(_run(snapshot="../../etc"))
    assert bad["success"] is False and bad["reason"] == "invalid_request"
    malformed = await storage.backup_run(_run(replica_id="nope"))
    assert malformed["reason"] == "invalid_request"
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: FEATURES))
    old = await storage.backup_run(_run())
    assert old["success"] is False and old["reason"] == "tool_outdated"
    assert not storage.fake.ran("systemctl", "--no-block", "start")


@pytest.mark.asyncio
async def test_no_copy_run_without_replicas_or_on_another_role(storage):
    await storage.backup_configure(_policy())
    answer = await storage.backup_run(_run())
    assert answer["reason"] == "not_configured"
    nothing = await storage.backup_run(
        _run(policy_id="3f2a0000-0000-4000-8000-0000000000c9")
    )
    assert nothing["reason"] == "not_configured"


@pytest.mark.asyncio
async def test_a_configured_copy_job_is_never_overwritten_by_a_run(storage):
    params = _policy([{"id": R1, "url": URL1}])
    params["jobs"]["copy"] = {"copy_to": "/srv/offsite/h-1"}
    await storage.backup_configure(params)
    answer = await storage.backup_run(_run())
    assert answer["success"] is False and answer["reason"] == "invalid_request"
    assert storage.rendered[-1].get("copy_to") == "/srv/offsite/h-1"


def test_the_storage_hosts_own_backup_may_have_replicas_too():
    """The server's own backup (``self``, 24.13) is the one a lost site needs
    most, so it is copied off-site as any repository on the storage host."""
    # pylint: disable-next=protected-access
    assert v._check_replicas(v.SELF, [{"id": R1, "url": URL1}])[0]["id"] == R1
    with pytest.raises(v.PolicyError):
        v._check_replicas(
            "host", [{"id": R1, "url": URL1}]
        )  # pylint: disable=protected-access
