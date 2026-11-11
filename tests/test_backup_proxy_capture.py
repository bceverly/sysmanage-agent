# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Backing up through restate-proxy (server ROADMAP 25.5, restate 3.2.0.0):
the capture and its snapshot listing name the proxy and nothing is mounted;
OpenBSD and NetBSD back up only that way; the storage host makes such a
host's repository instead of exporting it; and the reach check completes a
TLS handshake with the proxy as restate's curl will."""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import asyncio
import json
import platform
import ssl

import pytest

from src.sysmanage_agent.backup import job_runner
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import restate_probe
from src.sysmanage_agent.backup import self_backup
from src.sysmanage_agent.backup import storage_audit
from src.sysmanage_agent.backup import storage_prepare
from src.sysmanage_agent.backup import storage_reach
from src.sysmanage_agent.operations.backup_operations import BackupOperations
from tests.backup_ops_support import (  # noqa: F401
    FEATURES,
    PID,
    RID,
    STORAGE_TARGET,
    _host_policy,
    _touch_jobs,
    agent,
    job_files,
    ops,
)
from tests.test_backup_proxy import HOST, REMOTE, TID, URL, _cert, remote  # noqa: F401

CAPTURES = {**REMOTE, "remote_capture": True}
_PUBLIC_KEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----"
)


@pytest.fixture
def captures(remote, monkeypatch):
    """A restate that captures through the proxy too."""
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: CAPTURES))
    rendered = {}
    real = contract.render_job

    def render(job):
        rendered[job["command"]] = job
        return real(job)

    monkeypatch.setattr(contract, "render_job", render)
    remote.rendered = rendered
    return remote


def _captured(**proxy):
    params = _host_policy()
    params["target"] = {**params["target"],
                        "proxy": {"url": URL, "capture": True, **proxy}}  # fmt: skip
    return params


def test_the_host_says_its_restate_captures_through_a_proxy():
    assert "remote_capture" in contract.host_abilities(CAPTURES)
    assert "remote_capture" not in contract.host_abilities(REMOTE)


@pytest.mark.asyncio
async def test_the_capture_and_its_listing_name_the_proxy(captures):
    answer = await captures.backup_configure(_captured())
    assert answer["success"] is True
    for command in ("capture", "snapshots"):
        job = captures.rendered[command]
        assert job["repository"] == URL
        assert job["repository_token_file"] == access.token_path(PID)
        assert "create" not in job  # the storage host's prepare makes it
    assert captures._policy(PID)["remote_jobs"] == ["capture", "snapshots"]


@pytest.mark.asyncio
async def test_a_capture_through_the_proxy_mounts_nothing(
    captures, monkeypatch, job_files
):
    checked = []
    monkeypatch.setattr(
        "src.sysmanage_agent.backup.host_mount.preflight", checked.append
    )
    await captures.backup_configure(_captured())
    _touch_jobs(job_files, "capture")
    answer = await captures.backup_run(
        {"run_id": RID, "policy_id": PID, "action": "capture"}
    )
    assert answer["success"] is True, answer
    assert not captures.fake.ran("mount")
    assert not checked  # no NFS mount to check
    for task in list(captures._tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_without_the_servers_word_the_capture_stays_on_nfs(captures):
    params = _host_policy()
    params["target"] = {**params["target"], "proxy": {"url": URL}}
    await captures.backup_configure(params)
    assert captures.rendered["capture"]["repository"] != URL
    assert captures._policy(PID)["remote_jobs"] == []


@pytest.mark.asyncio
async def test_a_restate_that_only_reads_through_it_captures_over_nfs(remote):
    await remote.backup_configure(_captured())
    assert remote._policy(PID)["remote_jobs"] == []


def test_the_capture_flag_is_checked():
    with pytest.raises(access.PolicyError):
        access.check_host_proxy({"url": URL, "capture": "yes"})
    assert access.check_host_proxy({"url": URL, "capture": True})["capture"] is True


# --- OpenBSD and NetBSD --------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("system", ["OpenBSD", "NetBSD"])
async def test_a_host_with_no_nfsv4_client_refuses_an_nfs_policy(
    captures, monkeypatch, system
):
    monkeypatch.setattr(platform, "system", lambda: system)
    answer = await captures.backup_configure(_host_policy())
    assert answer["success"] is False
    assert answer["reason"] == restate_probe.REASON_NO_NFSV4_CLIENT
    answer = await captures.backup_configure(_captured())
    assert answer["success"] is True


@pytest.mark.parametrize("system", ["OpenBSD", "NetBSD"])
def test_they_can_back_up_once_restate_captures_through_a_proxy(system, tmp_path):
    # A real file: the probe stats the binary (its cache key) before it asks
    # restate anything, so a path that exists only on some machines made this
    # pass where restate was installed and fail on the BSD CI VMs.
    restate = tmp_path / "restate"
    restate.write_text("#!/bin/sh\n")

    def reason(features):
        return restate_probe.unavailable_reason(
            lookup=lambda name: str(restate),
            system=system,
            ask=lambda _exe: features,
            exists=lambda path: True,
        )

    restate_probe.forget()
    assert reason(REMOTE) == restate_probe.REASON_NO_NFSV4_CLIENT
    restate_probe.forget()
    assert reason(CAPTURES) is None
    assert job_runner.runner_for(system) == job_runner.DETACH
    restate_probe.forget()


def test_their_mount_table_is_read_from_mount_with_types():
    found = self_backup.typed_mounts(
        "/dev/sd0a on / type ffs (local)\n"
        "tmpfs on /tmp type tmpfs (local)\n"
        "nas:/srv/x on /mnt/a share type nfs (nodev)\n"
    )
    assert [(m.point, m.fstype) for m in found] == [
        ("/", "ffs"), ("/tmp", "tmpfs"), ("/mnt/a share", "nfs")
    ]  # fmt: skip


# --- the storage host ----------------------------------------------------


def _proxied(**over):
    policy = {"policy_id": PID, "role": "storage",
              "repository": "/srv/backups/restate/h-1",
              "mount_point": "/srv/backups/restate", "client_address": None,
              "service_account": "restate",
              "proxy": {"target_id": TID, "enabled": True, "grants": [],
                        "clients": [HOST], "export": False}}  # fmt: skip
    policy.update(over)
    return policy


def test_a_proxy_host_gets_no_export_and_its_repository_is_made(monkeypatch):
    monkeypatch.setattr(storage_prepare, "_ids", lambda account: (990, 990))
    steps = storage_prepare.plan(
        _proxied(), system="Linux", fstype="ext4", datasets={},
        is_subvolume=lambda path: False,
        listdir=lambda path: (_ for _ in ()).throw(FileNotFoundError()),
    )  # fmt: skip
    assert steps["export_file"] is None and steps["reload"] is False
    assert steps["init"] == {"repository": "/srv/backups/restate/h-1",
                             "owner": "restate:restate", "encrypt_to": None}  # fmt: skip
    assert storage_prepare.init_owner_argv(
        steps["init"]["repository"], steps["init"]["owner"]
    )[:3] == [
        "chown",
        "-R",
        "restate:restate",
    ]


def test_an_nfs_host_still_needs_its_address_and_gets_no_init(monkeypatch):
    monkeypatch.setattr(storage_prepare, "_ids", lambda account: (990, 990))
    nfs = _proxied(proxy={"target_id": TID, "enabled": True, "grants": [],
                          "clients": [HOST], "export": True})  # fmt: skip
    with pytest.raises(storage_prepare.PrepareRefused) as refused:
        storage_prepare.plan(nfs, system="Linux", fstype="ext4", datasets={},
                             is_subvolume=lambda path: False,
                             listdir=lambda path: [])  # fmt: skip
    assert refused.value.code == "no_address"


@pytest.mark.asyncio
async def test_init_leaves_a_repository_that_is_there_already(ops, monkeypatch):
    monkeypatch.setattr(restate_probe, "locate", lambda *a: "/usr/sbin/restate")

    async def run(argv):
        ops.fake.calls.append(argv)
        if "init" in argv:
            return 2, "", "restate: /srv/x: it is a repository already"
        return 0, "", ""

    monkeypatch.setattr(ops, "_run", run)
    await ops._init_repository("/srv/x", "restate:restate")
    assert not any(argv[0] == "chown" for argv in ops.fake.calls)


def test_the_storage_proxy_block_says_whether_a_host_needs_its_export():
    block = {"target_id": TID, "enabled": True, "grants": [], "clients": [HOST]}
    assert access.check_storage_proxy(block)["export"] is True  # an older server
    assert access.check_storage_proxy({**block, "export": False})["export"] is False
    off = {**block, "enabled": False, "export": False}
    assert access.check_storage_proxy(off)["export"] is True  # back on NFS
    assert not access.needs_export({"proxy": {**block, "export": False}})


def test_a_proxy_host_has_no_export_to_audit(monkeypatch):
    monkeypatch.setattr(storage_audit, "baseline", lambda *a, **k: [])
    monkeypatch.setattr(storage_audit, "layout_findings", lambda *a, **k: [])
    monkeypatch.setattr(storage_audit, "space_findings", lambda *a, **k: [])
    monkeypatch.setattr(storage_audit, "filesystem_findings",
                        lambda *a: [{"code": "own_filesystem", "level": "ok"}])  # fmt: skip
    called = []
    monkeypatch.setattr(storage_audit, "export_findings",
                        lambda *a, **k: called.append(1) or [])  # fmt: skip
    storage_audit.audit("/srv/x", client=None, account="restate",
                        read_text=lambda p: None, export=False)  # fmt: skip
    assert not called


# --- the reach check -----------------------------------------------------


class _Writer:
    def __init__(self, der=None):
        self.der = der
        self.closed = False

    def get_extra_info(self, name):
        if name == "ssl_object":
            return type("S", (), {"getpeercert": lambda _s, binary_form: self.der})()
        return ("192.168.4.50", 50000) if name == "sockname" else None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _der():
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    cert = x509.load_pem_x509_certificate(_cert(30))
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.asyncio
async def test_the_proxys_port_and_certificate_are_checked():
    der = _der()
    pin = storage_reach.spki_sha256(der)
    seen = []

    async def connect(address, port, **tls):
        seen.append((port, "ssl" in tls))
        return None, _Writer(der)

    answer = await storage_reach.check(
        {"address": "nas.example.lan", "proxy": {"port": 8443, "pin_sha256": pin}},
        connect=connect,
    )
    assert seen == [(8443, False), (8443, True)]
    assert answer["port"] == 8443 and answer["reachable"] is True
    assert answer["tls"] == {"ok": True, "error": None, "spki_sha256": pin}
    assert "local_port" not in answer  # NAT does not apply to the proxy


@pytest.mark.asyncio
async def test_another_key_than_the_pinned_one_is_said():
    async def connect(address, port, **tls):
        return None, _Writer(_der())

    answer = await storage_reach.check(
        {"address": "nas.example.lan", "proxy": {"port": 8443, "pin_sha256": "b" * 64}},
        connect=connect,
    )
    assert answer["reachable"] is True
    assert answer["tls"]["ok"] is False and answer["tls"]["error"] == "pin_mismatch"


@pytest.mark.asyncio
async def test_a_certificate_the_host_does_not_trust_is_said():
    async def connect(address, port, **tls):
        if tls:
            error = ssl.SSLCertVerificationError("certificate verify failed")
            error.verify_message = "self-signed certificate"
            raise error
        return None, _Writer()

    answer = await storage_reach.check(
        {"address": "nas.example.lan", "proxy": {"port": 8443}}, connect=connect
    )
    assert answer["tls"] == {"ok": False, "error": "self-signed certificate",
                             "spki_sha256": None}  # fmt: skip


@pytest.mark.asyncio
async def test_an_nfs_target_is_still_checked_on_2049():
    seen = []

    async def connect(address, port, **tls):
        seen.append(port)
        return None, _Writer()

    answer = await storage_reach.check({"address": "192.168.4.10"}, connect=connect)
    assert seen == [2049] and "tls" not in answer


@pytest.mark.asyncio
async def test_the_repository_is_made_before_its_ownership_and_append_rule(
    ops, monkeypatch
):
    # restate init leaves the directory 0700 and root's: the protect steps
    # after it give it back to root:<account> 0770 for the proxy's account.
    done = []

    async def checked(argv):
        done.append(argv[0])

    async def init(repository, owner, encrypt_to=None):
        done.append("init")

    monkeypatch.setattr(ops, "_checked", checked)
    monkeypatch.setattr(ops, "_init_repository", init)
    steps = {"kind": storage_prepare.PLAIN, "commands": [["mkdir", "-m", "700", "/srv/x"]],
             "export_file": None, "reload": False,
             "protect": [["chown", "root:restate", "/srv/x"], ["chmod", "0770", "/srv/x"]],
             "init": {"repository": "/srv/x", "owner": "restate:restate"}}  # fmt: skip
    await ops._prepare_steps(PID, steps)
    assert done == ["mkdir", "init", "chown", "chmod"]


def test_a_restate_that_cannot_find_curl_offers_no_proxy():
    # restate looks for curl in fixed places; its features say if it found it.
    without = {**CAPTURES, "programs": {"curl": False, "gpg": True}}
    assert not contract.reads_remote(without)
    assert not contract.captures_remote(without)
    assert "remote_capture" not in contract.host_abilities(without)
    assert contract.captures_remote({**CAPTURES, "programs": {"curl": True}})


def test_an_encrypted_policy_s_repository_is_made_encrypted(monkeypatch):
    monkeypatch.setattr(storage_prepare, "_ids", lambda account: (990, 990))
    key = f"/etc/restate/keys/{PID}.asc"
    steps = storage_prepare.plan(
        _proxied(encrypt_to=key), system="Linux", fstype="ext4", datasets={},
        is_subvolume=lambda path: False,
        listdir=lambda path: (_ for _ in ()).throw(FileNotFoundError()),
    )  # fmt: skip
    assert storage_prepare.init_argv("/usr/sbin/restate", **{
        k: v for k, v in steps["init"].items() if k != "owner"}) == [
        "/usr/sbin/restate", "init", "--encrypt-to", key, "/srv/backups/restate/h-1"
    ]  # fmt: skip
    assert storage_prepare.init_argv("/usr/sbin/restate", "/srv/x", None) == [
        "/usr/sbin/restate",
        "init",
        "/srv/x",
    ]


@pytest.mark.asyncio
async def test_an_encrypted_policy_is_refused_where_restate_finds_no_gpg(
    ops, monkeypatch
):
    no_gpg = {**FEATURES, "programs": {"gpg": False, "curl": True}}
    monkeypatch.setattr(BackupOperations, "_features", staticmethod(lambda: no_gpg))
    params = _host_policy(encrypt_key=_PUBLIC_KEY)
    answer = await ops.backup_configure(params)
    assert answer["success"] is False and answer["reason"] == "missing_tool"
    assert "gpg" in answer["error"]
    assert contract.can_encrypt(FEATURES)  # an older restate that does not say
