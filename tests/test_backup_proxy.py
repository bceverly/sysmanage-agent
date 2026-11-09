# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate-proxy (server ROADMAP 25.5): the host's own tokens, read jobs
through the proxy, and the storage host's grants and audit."""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import hashlib
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import repository_choice
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup.job_validation import PolicyError
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401
    FEATURES,
    PID,
    RID,
    STORAGE_TARGET,
    _host_policy,
    agent,
    ops,
)

TID = "9a000000-0000-4000-8000-0000000000d1"
HOST = "5e000000-0000-4000-8000-0000000000b2"
URL = f"https://nas.example.lan:8443/v1/{HOST}"
HASH = "a" * 64
REMOTE = {
    **FEATURES,
    "remote_repository": True,
    "job_keys": sorted(set(FEATURES["job_keys"]) | {
        "repository_token_file", "repository_ca_file", "repository_pin_sha256"
    }),
}  # fmt: skip


def _cert(days: int) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proxy")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def remote(ops, monkeypatch, tmp_path):
    """A restate that reads through the proxy, and the token, CA and grant
    directories somewhere the test can see."""
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: REMOTE))
    for name in ("TOKEN_DIR", "CA_DIR", "GRANTS_DIR"):
        path = tmp_path / name.lower()
        path.mkdir()
        monkeypatch.setattr(access, name, str(path))
    installed = {}
    real = ops._install_root_file

    async def install(content, dest, mode="644"):
        installed[dest] = (content, mode)
        await real(content, dest, mode)

    monkeypatch.setattr(ops, "_install_root_file", install)
    ops.installed = installed
    return ops


# --- what the server sends -----------------------------------------------


def test_a_proxy_url_is_checked_whatever_the_server_checked():
    assert access.check_host_proxy({"url": URL})["url"] == URL
    assert access.check_host_proxy({"url": f"https://[::1]:8443/v1/{HOST}"})
    for bad in (
        "http://nas/v1/x",
        "https://nas/v2/x",
        "https://nas:99999/v1/x",
        "https://nas/v1/x/../y",
        "https://-nas/v1/x",
        "https://nas/v1/.x",
    ):
        with pytest.raises(PolicyError):
            access.check_host_proxy({"url": bad})
    with pytest.raises(PolicyError):
        access.check_host_proxy({"url": URL, "previous_url": URL + ".old"})
    with pytest.raises(PolicyError):
        access.check_host_proxy({"url": URL, "pin_sha256": "nothex"})
    with pytest.raises(PolicyError):
        access.check_host_proxy({"url": URL, "command": "rm"})


def test_a_proxy_ca_is_a_certificate_never_a_key():
    pem = _cert(90).decode()
    assert access.check_ca(pem) == pem.strip() + "\n"
    with pytest.raises(PolicyError):
        access.check_ca(pem + "-----BEGIN PRIVATE KEY-----\n")
    with pytest.raises(PolicyError):
        access.check_ca("-----BEGIN CERTIFICATE-----\nnot base64\n")


def _storage_proxy(**over):
    value = {"target_id": TID, "enabled": True, "clients": [HOST, HOST + ".previous"],
             "grants": [{"client": HOST, "token_sha256": [HASH],
                         "operations": ["append", "read"]}]}  # fmt: skip
    value.update(over)
    return value


def test_a_storage_grant_names_one_of_the_targets_clients():
    assert access.check_storage_proxy(_storage_proxy())["grants"][0]["client"] == HOST
    with pytest.raises(PolicyError):
        access.check_storage_proxy(_storage_proxy(clients=["someone-else"]))
    with pytest.raises(PolicyError):
        access.check_storage_proxy(
            _storage_proxy(
                grants=[
                    {"client": HOST, "token_sha256": [HASH], "operations": ["delete"]}
                ]
            )
        )
    with pytest.raises(PolicyError):
        access.check_storage_proxy(_storage_proxy(grants=[{
            "client": HOST, "token_sha256": [HASH, HASH, HASH],
            "operations": ["read"]}]))  # fmt: skip
    # Back on NFS: the grants go, whatever was sent.
    assert access.check_storage_proxy(_storage_proxy(enabled=False))["grants"] == []


def test_a_token_is_what_the_protocol_says_and_its_hash_what_sha256sum_says():
    token = access.new_token()
    assert token.startswith("rsp_") and len(token) == 47
    assert access.token_sha256(token) == hashlib.sha256(token.encode()).hexdigest()
    printed = subprocess.run(["sha256sum"], input=token.encode(), capture_output=True,
                             check=True).stdout.decode().split()[0]  # fmt: skip
    assert access.token_sha256(token) == printed


# --- the backed-up host --------------------------------------------------


def _proxy_policy(**proxy):
    params = _host_policy()
    params["target"] = {**params["target"], "proxy": {"url": URL, **proxy}}
    return params


@pytest.mark.asyncio
async def test_the_host_makes_its_own_token_and_reports_only_its_hash(remote):
    answer = await remote.backup_configure(_proxy_policy())
    path = access.token_path(PID)
    token, mode = remote.installed[path]
    assert mode == "600" and token.startswith("rsp_")
    assert answer["proxy_tokens"] == {"current": access.token_sha256(token)}
    assert token not in json.dumps(answer)
    saved = remote._policy(PID)
    assert saved["proxy_tokens"]["current"] == access.token_sha256(token)
    assert token not in json.dumps(saved)


@pytest.mark.asyncio
async def test_a_token_is_made_once_and_kept(remote):
    first = await remote.backup_configure(_proxy_policy())
    with open(access.token_path(PID), "w", encoding="ascii") as out:
        out.write("rsp_kept")  # what the install put there
    remote.installed.clear()
    again = await remote.backup_configure(_proxy_policy())
    assert again["proxy_tokens"] == first["proxy_tokens"]
    assert access.token_path(PID) not in remote.installed


@pytest.mark.asyncio
async def test_the_previous_repository_gets_a_token_of_its_own(remote):
    answer = await remote.backup_configure(
        _proxy_policy(previous_url=URL + ".previous")
    )
    assert set(answer["proxy_tokens"]) == {"current", "previous"}
    assert answer["proxy_tokens"]["current"] != answer["proxy_tokens"]["previous"]


@pytest.mark.asyncio
async def test_no_token_where_restate_cannot_read_through_a_proxy(ops):
    answer = await ops.backup_configure(_proxy_policy())
    assert "proxy_tokens" not in answer
    assert not ops.fake.ran("install", "600")


@pytest.mark.asyncio
async def test_back_on_nfs_the_token_goes(remote):
    await remote.backup_configure(_proxy_policy())
    with open(access.token_path(PID), "w", encoding="ascii") as out:
        out.write("rsp_x")
    await remote.backup_configure(_host_policy())
    assert remote.fake.ran("rm", "-f", "--", access.token_path(PID))


@pytest.mark.asyncio
async def test_a_restore_reads_through_the_proxy_with_no_mount(remote, monkeypatch):
    rendered = []
    real = contract.render_job
    monkeypatch.setattr(contract, "render_job",
                        lambda job: rendered.append(job) or real(job))  # fmt: skip
    await remote.backup_configure(_proxy_policy(pin_sha256=HASH))
    answer = await remote.backup_restore(
        {"run_id": RID, "policy_id": PID, "include": ["/etc/**"]}
    )
    assert answer["success"] is True
    job = rendered[-1]
    assert job["repository"] == URL
    assert job["repository_token_file"] == access.token_path(PID)
    assert job["repository_pin_sha256"] == HASH
    assert not remote.fake.ran("mount")
    for task in list(remote._tasks):
        task.cancel()


def test_a_capture_never_goes_through_the_proxy():
    """Capture through the proxy is restate 3.2.0.0: until then a host's
    configured jobs, and anything without ``remote``, use its mount."""
    policy = {"repository": "/mnt/b/h", "nfs": {"server": "10.0.0.2", "path": "/h"},
              "proxy": {"url": URL}, "proxy_tokens": {"current": HASH}}  # fmt: skip
    assert repository_choice.for_record(policy, {})[0] == "/mnt/b/h"
    assert repository_choice.for_record(policy, {"remote": True})[0] == URL
    assert repository_choice.reads_remote(policy, {}, REMOTE)
    assert not repository_choice.reads_remote(policy, {}, FEATURES)
    assert not repository_choice.reads_remote(
        {**policy, "proxy_tokens": {}}, {}, REMOTE
    )


# --- the storage host ----------------------------------------------------


def _storage(**proxy):
    return {"policy_id": PID, "role": "storage",
            "target": {**STORAGE_TARGET, "proxy": _storage_proxy(**proxy)},
            "jobs": {"check": {"read_all": False}, "seal": {"mode": "none"}}}  # fmt: skip


@pytest.mark.asyncio
async def test_the_storage_host_writes_the_hosts_grant(remote):
    answer = await remote.backup_configure(_storage())
    text, mode = remote.installed[access.grant_path(HOST)]
    assert mode == "644"
    assert f"repository = {STORAGE_TARGET['mount_point']}/h-1\n" in text
    assert "operations = append, read\n" in text
    assert f"token_sha256 = {HASH}\n" in text
    assert f"label = sysmanage-agent target {TID}\n" in text
    assert answer["proxy_grants"] == {"written": [HOST], "removed": []}


@pytest.mark.asyncio
async def test_the_previous_repository_is_granted_read_only_beside_it(remote):
    grants = [{"client": HOST + ".previous", "token_sha256": [HASH],
               "operations": ["read"], "repo_dir": "h-1-old"}]  # fmt: skip
    await remote.backup_configure(_storage(grants=grants))
    text, _mode = remote.installed[access.grant_path(HOST + ".previous")]
    assert f"repository = {STORAGE_TARGET['mount_point']}/h-1-old\n" in text
    assert "operations = read\n" in text


@pytest.mark.asyncio
async def test_a_grant_outlives_neither_its_host_nor_the_proxy(remote):
    gone = os.path.join(access.GRANTS_DIR, "deleted-host.conf")
    by_hand = os.path.join(access.GRANTS_DIR, "someone.conf")
    other = os.path.join(access.GRANTS_DIR, "other-target.conf")
    for path, label in ((gone, f"sysmanage-agent target {TID}"),
                        (by_hand, None),
                        (other, "sysmanage-agent target 9a000000-0000-4000-8000-000000000099")):  # fmt: skip
        with open(path, "w", encoding="utf-8") as out:
            out.write("repository = /srv/x\n" + (f"label = {label}\n" if label else ""))
    answer = await remote.backup_configure(_storage())
    assert answer["proxy_grants"]["removed"] == ["deleted-host"]
    assert remote.fake.ran("rm", "-f", "--", gone)
    assert not remote.fake.ran("rm", "-f", "--", by_hand)
    assert not remote.fake.ran("rm", "-f", "--", other)


def test_the_proxy_certificate_is_audited():
    assert access.certificate_finding(_cert(90))["level"] == "ok"
    assert access.certificate_finding(_cert(5))["params"]["problem"] == "expiring"
    assert access.certificate_finding(_cert(-3))["params"]["problem"] == "expired"
    assert access.certificate_finding(None)["params"]["problem"] == "missing"


def test_each_grant_is_audited_as_the_proxy_reads_it():
    grants = [{"client": HOST}, {"client": HOST + ".previous"}]
    checked = {"schema": 1, "grants": [
        {"file": "x", "client": HOST, "ok": True},
        {"file": "y", "client": HOST + ".previous", "ok": False, "error": "bad key"},
    ]}  # fmt: skip
    found = access.grant_findings(grants, checked)
    assert [f["level"] for f in found] == ["ok", "error"]
    assert found[1]["params"]["error"] == "bad key"
    assert (
        access.grant_findings(grants, {"grants": []})[0]["params"]["problem"]
        == "missing"
    )
    assert access.grant_findings(grants, None)[0]["level"] == "warning"


def test_the_agent_says_it_reads_through_a_proxy_only_when_restate_can():
    assert contract.REMOTE_ABILITY in contract.host_abilities(REMOTE)
    assert contract.REMOTE_ABILITY not in contract.host_abilities(FEATURES)
