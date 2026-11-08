# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Enrollment, storage, renewal timing and refusal handling (ROADMAP 25.10)."""

# pylint: disable=redefined-outer-name,protected-access

import asyncio
import os
import stat
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.security import client_tls
from src.security.certificate_store import CertificateStore
from src.sysmanage_agent.registration import host_certificate
from src.sysmanage_agent.registration.host_certificate import (
    HostCertificateManager,
    build_csr,
    generate_key,
)
from tests.mtls_support import NOW, Pki, key_pem, pem


@pytest.fixture(autouse=True)
def _isolated():
    client_tls._warned.clear()
    yield
    client_tls.set_listener(None)


@pytest.fixture
def pki():
    return Pki()


@pytest.fixture
def store(tmp_path):
    return CertificateStore(str(tmp_path / "certs"))


def _put(store, pki, **validity):
    cert, key = pki.issue("host", **validity)
    store.store_issued(pem(cert), key_pem(key), pem(pki.cert))
    return cert


# -- the CSR ------------------------------------------------------------------


def test_csr_is_well_formed_p256():
    key = generate_key()
    csr = x509.load_pem_x509_csr(build_csr(key).encode("ascii"))
    assert csr.is_signature_valid
    assert isinstance(csr.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(csr.public_key().curve, ec.SECP256R1)
    assert csr.public_key().public_numbers() == key.public_key().public_numbers()
    assert isinstance(csr.signature_hash_algorithm, hashes.SHA256)


# -- storage ------------------------------------------------------------------


def test_stored_files_round_trip(store, pki):
    cert = _put(store, pki)
    assert store.load_client_certificate() == cert
    assert store.presentable_paths() == (
        str(store.client_cert_path),
        str(store.client_key_path),
    )
    assert store.has_certificates()
    assert store.ca_certificate_der() is not None
    # Nothing left behind by the temp-file-and-replace writes.
    assert sorted(p.name for p in store.config_dir.iterdir()) == [
        "ca.crt",
        "client.crt",
        "client.key",
    ]


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_key_is_0600_and_certificates_0644(store, pki):
    _put(store, pki)
    assert stat.S_IMODE(store.client_key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.client_cert_path.stat().st_mode) == 0o644
    assert stat.S_IMODE(store.ca_cert_path.stat().st_mode) == 0o644
    store.save_pins(pki.sha256, ["a" * 64])
    assert stat.S_IMODE(store.pins_path.stat().st_mode) == 0o644


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_key_is_created_private_even_under_a_permissive_umask(store, pki):
    """0600 from creation: the mode is given to os.open, not chmod'ed later."""
    previous = os.umask(0)
    try:
        with patch("src.security.certificate_store.os.chmod") as chmod:
            _put(store, pki)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(store.client_key_path.stat().st_mode) == 0o600
    assert chmod.called  # the public files' chmod was skipped, not the key's


def test_a_failed_write_keeps_the_previous_pair(store, pki):
    first = _put(store, pki)
    second, second_key = pki.issue("host")
    with patch("src.security.certificate_store.os.replace", side_effect=OSError):
        with pytest.raises(OSError):
            store.store_issued(pem(second), key_pem(second_key), pem(pki.cert))
    assert store.load_client_certificate() == first
    assert store.has_certificates()
    assert not [p for p in store.config_dir.iterdir() if p.name.endswith(".tmp")]


def test_pins_keep_the_newest_three(store, pki):
    store.save_pins(pki.sha256, ["a" * 64])
    for spki in ("b" * 64, "c" * 64, "d" * 64):
        store.add_pin(spki)
    assert store.load_pins()["spki_sha256"] == ["d" * 64, "c" * 64, "b" * 64]
    assert store.clear_pins() is True
    assert store.load_pins() is None
    assert store.clear_pins() is False


def test_a_corrupt_pins_file_counts_as_none(store):
    store.pins_path.write_text("{not json", encoding="utf-8")
    assert store.load_pins() is None


# -- renewal timing -----------------------------------------------------------


def test_renewal_needed_without_a_certificate(store):
    assert store.needs_renewal() is True


def test_renewal_needed_when_expired(store, pki):
    _put(
        store,
        pki,
        not_before=NOW - timedelta(days=400),
        not_after=NOW - timedelta(minutes=1),
    )
    assert store.needs_renewal() is True
    assert store.presentable_paths() is None


def test_renewal_needed_inside_thirty_days(store, pki):
    _put(store, pki, not_after=NOW + timedelta(days=29))
    assert store.needs_renewal() is True
    assert store.presentable_paths() is not None, "still presented until it expires"


def test_no_renewal_outside_thirty_days(store, pki):
    _put(store, pki, not_after=NOW + timedelta(days=31))
    assert store.needs_renewal() is False


def test_certificate_without_its_key_needs_renewal(store, pki):
    _put(store, pki)
    other = ec.generate_private_key(ec.SECP256R1())
    store.client_key_path.write_bytes(key_pem(other))
    assert store.certificate_state()[0] == "none"
    assert store.needs_renewal() is True


# -- enrollment over (mocked) HTTP --------------------------------------------


class _Response:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    async def json(self, content_type=None):
        _ = content_type
        return self.body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


class _Session:
    """Stands in for aiohttp.ClientSession; the reply may sign the CSR."""

    def __init__(self, reply):
        self.reply = reply
        self.posts = []

    def post(self, url, json=None, headers=None, proxy=None):
        _ = proxy
        self.posts.append((url, json, headers))
        return _Response(*self.reply(json))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


def _agent(store, server=None, approved=True):
    registration = MagicMock()
    registration.get_host_approval_from_db.return_value = (
        SimpleNamespace(host_id="0b6f6c5e-1111-4222-8333-444455556666")
        if approved
        else None
    )
    registration.get_stored_host_token = AsyncMock(return_value="host-token")
    config = MagicMock()
    config.get_server_config.return_value = server or {
        "url": "https://sysmanage.example.com"
    }
    config.should_verify_ssl.return_value = True
    return SimpleNamespace(
        logger=MagicMock(),
        config=config,
        cert_store=store,
        registration_manager=registration,
        get_auth_token=AsyncMock(return_value="conn-token"),
        auth_helper=MagicMock(),
        websocket=None,
        running=True,
    )


def _issuing(pki):
    def reply(body):
        csr = x509.load_pem_x509_csr(body["csr"].encode("ascii"))
        cert, _key = pki.issue("host.example.com", key=_PublicOnly(csr))
        return 200, {
            "certificate": pem(cert),
            "ca_certificate": pem(pki.cert),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "renew_after": (cert.not_valid_after_utc - timedelta(days=30)).isoformat(),
        }

    return reply


class _PublicOnly:
    """Lets Pki.issue sign a certificate for a CSR's public key."""

    def __init__(self, csr):
        self._public = csr.public_key()

    def public_key(self):
        return self._public


def _run(manager, session, **kwargs):
    with patch.object(host_certificate.aiohttp, "ClientSession", return_value=session):
        with patch.object(host_certificate.server_identity, "first_pin") as first_pin:
            result = asyncio.run(manager.check(**kwargs))
    return result, first_pin


def test_enrollment_posts_a_csr_and_stores_the_result(store, pki):
    agent = _agent(store)
    manager = HostCertificateManager(agent)
    session = _Session(_issuing(pki))
    issued, first_pin = _run(manager, session)
    assert issued is True
    url, body, headers = session.posts[0]
    assert url == "https://sysmanage.example.com/api/agent/certificate"
    assert body["host_id"] == "0b6f6c5e-1111-4222-8333-444455556666"
    assert "BEGIN CERTIFICATE REQUEST" in body["csr"]
    assert headers == {
        "Authorization": "Bearer conn-token",
        "X-Host-Token": "host-token",
    }
    assert store.has_certificates()
    assert store.load_client_certificate().subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value == ("host.example.com")
    # First issuance, no pins yet: the server identity is pinned next.
    first_pin.assert_called_once()


def test_no_request_when_the_certificate_is_current(store, pki):
    _put(store, pki, not_after=NOW + timedelta(days=200))
    store.save_pins(pki.sha256, ["a" * 64])
    session = _Session(_issuing(pki))
    issued, first_pin = _run(HostCertificateManager(_agent(store)), session)
    assert issued is False
    assert not session.posts
    first_pin.assert_not_called()


def test_no_request_before_approval(store, pki):
    session = _Session(_issuing(pki))
    issued, _ = _run(HostCertificateManager(_agent(store, approved=False)), session)
    assert issued is False
    assert not session.posts


def test_no_request_over_plain_http(store, pki):
    session = _Session(_issuing(pki))
    agent = _agent(store, server={"url": "http://localhost:8080"})
    issued, _ = _run(HostCertificateManager(agent), session)
    assert issued is False
    assert not session.posts


@pytest.mark.parametrize(
    "status,code",
    [
        (403, "host_not_approved"),
        (403, "host_credential_invalid"),
        (409, "certificate_current"),
        (400, "csr_invalid"),
    ],
)
def test_refused_requests_store_nothing(store, pki, status, code):
    previous = _put(store, pki, not_after=NOW + timedelta(days=5))
    session = _Session(lambda _b: (status, {"detail": {"code": code, "message": "m"}}))
    agent = _agent(store)
    issued, _ = _run(HostCertificateManager(agent), session)
    assert issued is False
    assert session.posts
    assert store.load_client_certificate() == previous


def test_a_certificate_for_another_key_is_not_stored(store, pki):
    def reply(_body):
        cert, _key = pki.issue("host")
        return 200, {"certificate": pem(cert), "ca_certificate": pem(pki.cert)}

    issued, _ = _run(HostCertificateManager(_agent(store)), _Session(reply))
    assert issued is False
    assert not store.has_certificates()


# -- refusals trigger a request -----------------------------------------------


@pytest.mark.parametrize(
    "code", ["host_certificate_required", "host_certificate_expired"]
)
def test_websocket_refusal_requests_a_certificate(store, pki, code):
    """The SYSTEM_INFO error reply, through the real message handler."""
    from src.sysmanage_agent.communication.message_handler import (  # noqa: PLC0415
        MessageHandler,
    )

    _put(store, pki, not_after=NOW + timedelta(days=200))  # current, yet refused
    store.save_pins(pki.sha256, ["a" * 64])
    agent = _agent(store)
    agent.websocket = object()
    manager = HostCertificateManager(agent)
    session = _Session(_issuing(pki))

    async def scenario():
        handler = MessageHandler.__new__(MessageHandler)
        handler.agent = agent
        handler.logger = MagicMock()
        await handler._dispatch_server_error(code, "refused")
        await asyncio.gather(*list(manager._tasks))

    with patch.object(host_certificate.aiohttp, "ClientSession", return_value=session):
        asyncio.run(scenario())
    assert len(session.posts) == 1, "a refusal asks even for a current certificate"
    assert agent.running is False, "reconnects so the new certificate is presented"
    agent.logger.warning.assert_called()


def test_invalid_refusal_is_logged_and_requests_nothing(store, pki):
    agent = _agent(store)
    manager = HostCertificateManager(agent)
    session = _Session(_issuing(pki))

    async def scenario():
        client_tls.notify_refusal("host_certificate_invalid", "revoked")
        await asyncio.sleep(0)
        assert not manager._tasks

    with patch.object(host_certificate.aiohttp, "ClientSession", return_value=session):
        asyncio.run(scenario())
    assert not session.posts
    agent.logger.error.assert_called_once()


def test_refusal_requests_are_rate_limited(store, pki):
    manager = HostCertificateManager(_agent(store))
    with patch.object(manager, "kick") as kick:

        async def scenario():
            manager.certificate_refused("host_certificate_required", "x")
            manager.certificate_refused("host_certificate_required", "x")

        asyncio.run(scenario())
    kick.assert_called_once_with(True, True)


def test_rest_refusal_reaches_the_manager(store):
    manager = HostCertificateManager(_agent(store))
    with patch.object(manager, "_kick_threadsafe") as kick:
        client_tls.notify_refusal("host_certificate_expired", "old")
    kick.assert_called_once_with("refused", force=True, reconnect=True)
