# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate-proxy as a service on a storage host (server ROADMAP 25.5):
Equip adds the package; the storage configure runs it as the repositories'
account, gets it a certificate from the SysManage CA for a key made here,
and enables and restarts it."""

# pylint: disable=protected-access,redefined-outer-name,unused-import

import os
import platform
import stat
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.sysmanage_agent.backup import equip
from src.sysmanage_agent.backup import equip_release as release
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import proxy_mixin
from src.sysmanage_agent.backup import proxy_service as service
from src.sysmanage_agent.backup.job_validation import PolicyError
from tests.backup_ops_support import STORAGE_TARGET, agent, ops  # noqa: F401
from tests.test_backup_proxy import HOST, TID, _storage_proxy, remote  # noqa: F401

# A storage host is never Windows (and Windows has no Unix file modes).
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

NAME = "backup.example.lan"


@pytest.fixture
def storage(remote, monkeypatch, tmp_path):
    """A storage host with restate-proxy installed, under systemd, whose
    root-owned installs land on disk where the test can see them."""
    monkeypatch.setattr(access, "PROXY_CERT", str(tmp_path / "proxy.crt"))
    monkeypatch.setattr(access, "PROXY_KEY", str(tmp_path / "proxy.key"))
    monkeypatch.setattr(service, "DROP_IN", str(tmp_path / "sysmanage.conf"))
    monkeypatch.setattr(proxy_mixin, "proxy_binary", lambda: "/usr/sbin/restate-proxy")
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(remote, "_proxy_systemd", lambda: True)
    real = remote._install_root_file

    async def install(content, dest, mode="644"):
        await real(content, dest, mode)
        with open(dest, "w", encoding="ascii") as out:
            out.write(content)

    monkeypatch.setattr(remote, "_install_root_file", install)
    return remote


def _policy(cert, enabled=True):
    proxy = _storage_proxy()
    proxy = {**proxy, "enabled": enabled, "cert": cert}
    return {"policy_id": "6b000000-0000-4000-8000-0000000000a1", "role": "storage",
            "repository": "/srv/backups/restate/h-1", "service_account": "restate",
            "proxy": proxy}  # fmt: skip


def _sign(csr_pem):
    """What the server does: a certificate for the request's key."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SysManage CA")])
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(csr.public_key()).serial_number(7)
        .not_valid_before(now).not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_the_certificate_block_is_checked():
    assert service.check_cert(None) is None
    assert (
        service.check_cert({"name": "BACKUP.example.lan", "pem": None, "renew": True})[
            "name"
        ]
        == "BACKUP.example.lan"
    )
    assert service.check_cert({"name": "192.168.4.10", "pem": None, "renew": True})
    for bad in ({"name": "x/y", "pem": None, "renew": True},
                {"name": NAME, "pem": "-----BEGIN PRIVATE KEY-----", "renew": True},
                {"name": NAME, "pem": None, "renew": "yes"},
                {"name": NAME, "pem": None}):  # fmt: skip
        with pytest.raises(PolicyError):
            service.check_cert(bad)


@pytest.mark.asyncio
async def test_a_key_is_made_here_and_only_a_request_leaves(storage):
    answer = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": None, "renew": True})
    )
    csr = x509.load_pem_x509_csr(answer["proxy_csr"].encode())
    assert csr.is_signature_valid
    pending = service.pending_path(storage._backup_dir())
    assert stat.S_IMODE(os.stat(pending).st_mode) == 0o600
    assert "PRIVATE KEY" not in answer["proxy_csr"]
    assert "proxy_service" not in answer  # no certificate yet: not started
    # The proxy runs as the repositories' account, group-writable.
    with open(service.DROP_IN, encoding="ascii") as handle:
        text = handle.read()
    assert "User=restate" in text and "Group=restate" in text and "UMask=0007" in text
    assert storage.fake.ran("systemctl", "daemon-reload")


@pytest.mark.asyncio
async def test_the_signed_certificate_is_installed_and_the_proxy_started(storage):
    first = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": None, "renew": True})
    )
    pem = _sign(first["proxy_csr"])
    answer = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": pem, "renew": False})
    )
    assert answer["proxy_service"] == "started" and "proxy_csr" not in answer
    assert storage.installed[access.PROXY_KEY][1] == "600"
    assert storage.fake.ran("chown", "restate:restate", access.PROXY_KEY)
    with open(access.PROXY_CERT, encoding="ascii") as handle:
        assert handle.read() == pem
    assert not os.path.exists(service.pending_path(storage._backup_dir()))
    assert storage.fake.ran("systemctl", "enable", service.UNIT)
    assert storage.fake.ran("systemctl", "restart", service.UNIT)  # read at start


@pytest.mark.asyncio
async def test_an_unchanged_certificate_does_not_restart_it(storage):
    first = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": None, "renew": True})
    )
    pem = _sign(first["proxy_csr"])
    await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": pem, "renew": False})
    )
    storage.fake.calls.clear()
    answer = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": pem, "renew": False})
    )
    assert "proxy_csr" not in answer
    assert storage.fake.ran("systemctl", "start", service.UNIT)
    assert not storage.fake.ran("systemctl", "restart", service.UNIT)


@pytest.mark.asyncio
async def test_a_certificate_for_a_key_this_host_lacks_asks_again(storage):
    # The server holds a certificate, but not for any key here: a request for
    # the key this host does hold (the server then issues it again).
    other = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)]))
        .sign(other, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    foreign = _sign(csr.public_bytes(serialization.Encoding.PEM).decode())
    answer = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": foreign, "renew": False})
    )
    assert answer.get("proxy_csr")
    assert not os.path.exists(access.PROXY_CERT)


@pytest.mark.asyncio
async def test_not_installed_says_so(storage, monkeypatch):
    monkeypatch.setattr(proxy_mixin, "proxy_binary", lambda: None)
    answer = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": None, "renew": True})
    )
    assert answer == {"proxy_service": "not_installed"}


@pytest.mark.asyncio
async def test_back_on_nfs_only_the_service_this_agent_turned_on_is_stopped(storage):
    await storage._apply_proxy_service(_policy(None, enabled=False))
    assert not storage.fake.ran("systemctl", "stop", service.UNIT)  # never ours
    await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": None, "renew": True})
    )
    await storage._apply_proxy_service(_policy(None, enabled=False))
    assert storage.fake.ran("systemctl", "disable", service.UNIT)
    assert storage.fake.ran("systemctl", "stop", service.UNIT)
    assert storage.fake.ran("rm", "-f", "--", service.DROP_IN)


@pytest.mark.asyncio
async def test_on_freebsd_the_rc_script_is_set_with_sysrc(storage, monkeypatch):
    monkeypatch.setattr(storage, "_proxy_systemd", lambda: False)
    monkeypatch.setattr(platform, "system", lambda: "FreeBSD")
    first = await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": None, "renew": True})
    )
    assert storage.fake.ran(
        "sysrc", "restate_proxy_user=restate", "restate_proxy_umask=007"
    )
    await storage._apply_proxy_service(
        _policy({"name": NAME, "pem": _sign(first["proxy_csr"]), "renew": False})
    )
    assert storage.fake.ran("sysrc", "restate_proxy_enable=YES")
    assert storage.fake.ran("service", "restate_proxy", "restart")


# --- Equip ---------------------------------------------------------------


def test_equip_adds_the_proxy_package_only_for_a_proxy_storage_host():
    assert equip.ubuntu_steps()[-1][-1] == equip.NFS_CLIENT_PACKAGE
    assert equip.ubuntu_steps(proxy=True)[-1][-1] == "restate-proxy"
    assert equip.fedora_steps(proxy=True)[-1][-1] == "restate-proxy"
    listed = {"restate-3.2.0.3-freebsd-15.0-amd64.pkg": "a",
              "restate-proxy-3.2.0.3-freebsd-15.0-amd64.pkg": "b"}  # fmt: skip
    assert release.asset_names(release.FREEBSD, "3.2.0.3", "15.0", "amd64", listed) == [
        "restate-3.2.0.3-freebsd-15.0-amd64.pkg"
    ]
    names = release.asset_names(
        release.FREEBSD, "3.2.0.3", "15.0", "amd64", listed, proxy=True
    )
    assert names == list(listed)
    steps = release.install_steps(release.FREEBSD, ["/x/a.pkg", "/x/b.pkg"])
    assert steps == [["pkg", "add", "-f", "/x/a.pkg"], ["pkg", "add", "-f", "/x/b.pkg"]]


def test_a_release_without_the_proxy_package_is_no_release():
    listed = {"restate-3.2.0.3-freebsd-15.0-amd64.pkg": "a"}
    assert (
        release.asset_names(release.FREEBSD, "3.2.0.3", "15.0", "amd64", listed, True)
        is None
    )


@pytest.mark.asyncio
async def test_the_server_flag_reaches_equip(monkeypatch):
    from src.sysmanage_agent.core import agent_delegators  # noqa: PLC0415

    seen = {}

    async def fake_equip(state_dir, **kwargs):
        seen.update(kwargs)
        return {"success": True}

    monkeypatch.setattr(equip, "equip", fake_equip)
    delegator = agent_delegators.AgentDelegatorMixin.equip_backup
    await delegator(object(), {"proxy": True})
    assert seen == {"proxy": True}
    await delegator(object(), {"proxy": "yes"})
    assert seen == {"proxy": False}
