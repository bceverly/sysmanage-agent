# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server pinning and the signed re-pin (ROADMAP 25.10).

The pin check lives in SSLSocket/SSLObject subclasses, so these tests make
real TLS connections to a loopback server rather than mocking ssl: a check
that only ran in a mock would protect nothing.
"""

# pylint: disable=redefined-outer-name,protected-access

import asyncio
import socket
import ssl
import time
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from src.security import client_tls, server_identity
from src.security.certificate_store import CertificateStore
from src.security.server_pinning import (
    IdentityError,
    PinChecker,
    PinMismatchError,
    install_pin_check,
    verify_statement,
)
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint
from tests.mtls_support import (
    NOW,
    LoopbackTlsServer,
    Pki,
    ServerConfig,
    identity_document,
    key_pem,
    pem,
    spki_of,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(name, raising=False)
    server_identity._repin_state["last"] = 0.0
    client_tls._warned.clear()
    client_tls.set_listener(None)
    yield
    client_tls.set_listener(None)


@pytest.fixture
def pki():
    return Pki()


@pytest.fixture
def tls_cert(pki):
    return pki.issue("localhost", server=True)


def _client_context(pki, tmp_path):
    return ssl.create_default_context(cafile=pki.write_ca(tmp_path))


def _blocking_connect(context, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as conn:
            return conn.getpeercert(binary_form=True)


async def _async_connect(context, port):
    _reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname="localhost"
    )
    writer.close()
    try:
        await writer.wait_closed()
    except (ssl.SSLError, ConnectionError):
        pass


# -- the pin check on real connections --------------------------------------


def test_matching_pin_passes_blocking_and_asyncio(pki, tls_cert, tmp_path):
    cert, key = tls_cert
    context = _client_context(pki, tmp_path)
    install_pin_check(context, PinChecker([spki_of(cert)]))
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        assert _blocking_connect(context, server.port)
        asyncio.run(_async_connect(context, server.port))


def test_different_spki_is_refused_blocking(pki, tls_cert, tmp_path):
    cert, key = tls_cert
    seen = []
    context = _client_context(pki, tmp_path)
    install_pin_check(context, PinChecker(["0" * 64], seen.append))
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        with pytest.raises(PinMismatchError) as excinfo:
            _blocking_connect(context, server.port)
    assert isinstance(excinfo.value, ssl.SSLCertVerificationError)
    assert "has not pinned" in str(excinfo.value)
    assert spki_of(cert) in str(excinfo.value)
    assert seen == [spki_of(cert)]


def test_different_spki_is_refused_asyncio(pki, tls_cert, tmp_path):
    """asyncio (aiohttp, websockets) goes through SSLObject, not SSLSocket."""
    cert, key = tls_cert
    seen = []
    context = _client_context(pki, tmp_path)
    install_pin_check(context, PinChecker(["0" * 64], seen.append))
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        with pytest.raises(ssl.SSLCertVerificationError) as excinfo:
            asyncio.run(_async_connect(context, server.port))
    assert "has not pinned" in str(excinfo.value)
    assert seen == [spki_of(cert)]


def _endpoint(pki, tmp_path, port, store, **server):
    settings = {"url": f"https://localhost:{port}", "ca_bundle": pki.write_ca(tmp_path)}
    settings.update(server)
    return ServerEndpoint(ServerConfig(settings), store)


def test_endpoint_context_enforces_pins(pki, tls_cert, tmp_path):
    cert, key = tls_cert
    store = CertificateStore(str(tmp_path / "certs"))
    store.save_pins(pki.sha256, ["1" * 64])
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        endpoint = _endpoint(pki, tmp_path, server.port, store)
        with pytest.raises(PinMismatchError):
            _blocking_connect(endpoint.ssl_context(), server.port)
        # The re-pin fetch must not pin, or it could never succeed.
        assert _blocking_connect(endpoint.ssl_context(pin=False), server.port)


def test_no_pins_file_means_no_pin_check(pki, tls_cert, tmp_path):
    cert, key = tls_cert
    store = CertificateStore(str(tmp_path / "certs"))
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        endpoint = _endpoint(pki, tmp_path, server.port, store)
        assert _blocking_connect(endpoint.ssl_context(), server.port)


def test_tls_inspection_turns_pinning_off_with_one_warning(
    pki, tls_cert, tmp_path, caplog
):
    cert, key = tls_cert
    store = CertificateStore(str(tmp_path / "certs"))
    store.save_pins(pki.sha256, ["1" * 64])
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        endpoint = _endpoint(pki, tmp_path, server.port, store, tls_inspection=True)
        with caplog.at_level("WARNING"):
            assert _blocking_connect(endpoint.ssl_context(), server.port)
            endpoint.ssl_context()
    warnings = [r for r in caplog.records if "tls_inspection" in r.getMessage()]
    assert len(warnings) == 1


# -- re-pin over the network --------------------------------------------------


def test_mismatch_schedules_a_repin_that_trusts_a_signed_new_certificate(
    pki, tls_cert, tmp_path, caplog
):
    cert, key = tls_cert
    store = CertificateStore(str(tmp_path / "certs"))
    store.save_pins(pki.sha256, ["1" * 64])
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        server.body = identity_document(pki, [spki_of(cert)])
        endpoint = _endpoint(pki, tmp_path, server.port, store)
        with caplog.at_level("INFO"):
            with pytest.raises(PinMismatchError):
                _blocking_connect(endpoint.ssl_context(), server.port)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if spki_of(cert) in store.load_pins()["spki_sha256"]:
                    break
                time.sleep(0.05)
        assert store.load_pins()["spki_sha256"] == [spki_of(cert), "1" * 64]
        # Now trusted: the same pinned context shape connects.
        assert _blocking_connect(endpoint.ssl_context(), server.port)
    assert any("is now trusted" in r.getMessage() for r in caplog.records)


def test_repin_refuses_a_statement_that_does_not_name_the_certificate(
    pki, tls_cert, tmp_path, caplog
):
    cert, key = tls_cert
    store = CertificateStore(str(tmp_path / "certs"))
    store.save_pins(pki.sha256, ["1" * 64])
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        server.body = identity_document(pki, ["2" * 64])
        endpoint = _endpoint(pki, tmp_path, server.port, store)
        assert server_identity.repin(endpoint, store) is False
    assert store.load_pins()["spki_sha256"] == ["1" * 64]
    error = [r for r in caplog.records if r.levelname == "ERROR"]
    assert error and "proxy" in error[0].getMessage()


def test_first_pin_pins_the_ca_and_the_observed_certificate(pki, tls_cert, tmp_path):
    cert, key = tls_cert
    store = CertificateStore(str(tmp_path / "certs"))
    client, client_key = pki.issue("host")
    store.store_issued(pem(client), key_pem(client_key), pem(pki.cert))
    with LoopbackTlsServer(cert, key, tmp_path) as server:
        server.body = identity_document(pki, [spki_of(cert)])
        endpoint = _endpoint(pki, tmp_path, server.port, store)
        assert server_identity.first_pin(endpoint, store) is True
    assert store.load_pins() == {
        "v": 1,
        "ca_sha256": pki.sha256,
        "spki_sha256": [spki_of(cert)],
    }


def test_repins_are_rate_limited():
    started = []
    original = server_identity.threading.Thread

    class _Recorder:
        def __init__(self, target, args, name):
            started.append(name)

        daemon = False

        def start(self):
            return None

    server_identity.threading.Thread = _Recorder
    try:
        assert server_identity.schedule_repin(None, None) is True
        assert server_identity.schedule_repin(None, None) is False
    finally:
        server_identity.threading.Thread = original
    assert started == ["server-repin"]


# -- verifying statements -----------------------------------------------------


def test_correct_statement_verifies_rsa_and_ec(pki):
    observed = "a" * 64
    assert verify_statement(identity_document(pki, [observed]), pki.sha256, observed)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ident, ident_key = pki.issue("sysmanage-server", key=ec_key)
    doc = identity_document(
        pki, [observed], identity_cert=ident, identity_key=ident_key
    )
    assert verify_statement(doc, pki.sha256, observed) == [observed]


def test_statement_signed_by_another_key_is_rejected(pki):
    other = ec.generate_private_key(ec.SECP256R1())
    doc = identity_document(pki, ["a" * 64], sign_with=other)
    with pytest.raises(IdentityError, match="not signed"):
        verify_statement(doc, pki.sha256, "a" * 64)


def test_identity_from_another_ca_is_rejected(pki):
    stranger = Pki("Some Other CA")
    ident, ident_key = stranger.issue("sysmanage-server")
    doc = identity_document(
        pki, ["a" * 64], identity_cert=ident, identity_key=ident_key
    )
    with pytest.raises(IdentityError, match="not issued by the pinned CA"):
        verify_statement(doc, pki.sha256, "a" * 64)


def test_a_different_ca_than_pinned_is_rejected(pki):
    stranger = Pki("Some Other CA")
    # Entirely self-consistent, but under a CA this agent never pinned.
    doc = identity_document(stranger, ["a" * 64])
    with pytest.raises(IdentityError, match="not the CA this agent has pinned"):
        verify_statement(doc, pki.sha256, "a" * 64)


def test_expired_statement_is_rejected(pki):
    doc = identity_document(pki, ["a" * 64], expires_at=NOW - timedelta(seconds=1))
    with pytest.raises(IdentityError, match="expired"):
        verify_statement(doc, pki.sha256, "a" * 64)


def test_observed_spki_not_listed_is_rejected(pki):
    doc = identity_document(pki, ["a" * 64, "b" * 64])
    with pytest.raises(IdentityError, match="not one the server"):
        verify_statement(doc, pki.sha256, "c" * 64)


def test_expired_identity_certificate_is_rejected(pki):
    ident, ident_key = pki.issue(
        "sysmanage-server",
        not_before=NOW - timedelta(days=10),
        not_after=NOW - timedelta(days=1),
    )
    doc = identity_document(
        pki, ["a" * 64], identity_cert=ident, identity_key=ident_key
    )
    with pytest.raises(IdentityError, match="validity"):
        verify_statement(doc, pki.sha256, "a" * 64)


@pytest.mark.parametrize("field", ["statement", "signature", "ca_certificate"])
def test_incomplete_documents_are_rejected(pki, field):
    doc = identity_document(pki, ["a" * 64])
    doc[field] = None
    with pytest.raises(IdentityError):
        verify_statement(doc, pki.sha256, "a" * 64)
