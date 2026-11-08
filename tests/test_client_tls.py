# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The client certificate on every TLS connection to the server (25.10).

Real loopback TLS: the server requests a client certificate and records what
it got, so "presented" means a server actually saw it.
"""

# pylint: disable=redefined-outer-name,protected-access

import socket
import time
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.security import client_tls
from src.security.certificate_store import CertificateStore
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint
from tests.mtls_support import (
    NOW,
    LoopbackTlsServer,
    Pki,
    ServerConfig,
    der,
    key_pem,
    pem,
)


@pytest.fixture(autouse=True)
def _isolated():
    client_tls._warned.clear()
    client_tls.set_listener(None)
    yield
    client_tls.set_listener(None)


@pytest.fixture
def pki():
    return Pki()


def _store(tmp_path, pki, **validity):
    store = CertificateStore(str(tmp_path / "certs"))
    cert, key = pki.issue("host.example.com", **validity)
    store.store_issued(pem(cert), key_pem(key), pem(pki.cert))
    return store, cert


def _connect(endpoint, port):
    context = endpoint.ssl_context()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as conn:
            conn.sendall(b"x")


def _endpoint(port, store):
    # No ca_bundle: the server's certificate verifies only because the
    # SysManage CA from the store was ADDED to the trust.
    return ServerEndpoint(ServerConfig({"url": f"https://localhost:{port}"}), store)


def test_unexpired_certificate_is_presented(pki, tmp_path):
    store, cert = _store(tmp_path, pki)
    server_cert, server_key = pki.issue("localhost", server=True)
    with LoopbackTlsServer(server_cert, server_key, tmp_path, client_ca=pki) as srv:
        _connect(_endpoint(srv.port, store), srv.port)
        for _ in range(50):
            if srv.peer_certs:
                break
            time.sleep(0.05)
    assert srv.peer_certs == [der(cert)]


def test_expired_certificate_is_not_presented_and_asks_for_renewal(
    pki, tmp_path, caplog
):
    store, _cert = _store(
        tmp_path,
        pki,
        not_before=NOW - timedelta(days=400),
        not_after=NOW - timedelta(days=1),
    )
    listener = MagicMock()
    client_tls.set_listener(listener)
    server_cert, server_key = pki.issue("localhost", server=True)
    with LoopbackTlsServer(server_cert, server_key, tmp_path, client_ca=pki) as srv:
        with caplog.at_level("WARNING"):
            _connect(_endpoint(srv.port, store), srv.port)
            _endpoint(srv.port, store).ssl_context()
        for _ in range(50):
            if srv.peer_certs:
                break
            time.sleep(0.05)
    assert srv.peer_certs == [None]
    expired = [r for r in caplog.records if "expired on" in r.getMessage()]
    assert len(expired) == 1, "logged once, not on every connection"
    assert listener.certificate_expired.call_count == 2


def test_system_trust_store_is_kept(pki, tmp_path):
    """The SysManage CA is added; the default trust is not replaced."""
    store, _cert = _store(tmp_path, pki)
    with patch(
        "src.sysmanage_agent.core.server_endpoint.ssl.create_default_context"
    ) as factory:
        context = MagicMock()
        factory.return_value = context
        _endpoint(443, store).ssl_context()
    factory.assert_called_once_with(cafile=None)
    context.load_verify_locations.assert_called_once_with(
        cafile=str(store.ca_cert_path)
    )


# -- refusals reported by REST 403s -------------------------------------------


class _Response:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def json(self, content_type=None):
        _ = content_type
        return self._body


@pytest.mark.asyncio
async def test_rest_403_with_a_certificate_code_reaches_the_listener():
    listener = MagicMock()
    client_tls.set_listener(listener)
    body = {"detail": {"code": "host_certificate_required", "message": "need one"}}
    params = SimpleNamespace(response=_Response(403, body))
    await client_tls._on_request_end(None, None, params)
    listener.certificate_refused.assert_called_once_with(
        "host_certificate_required", "need one"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,body",
    [
        (200, {"detail": {"code": "host_certificate_required"}}),
        (403, {"detail": {"code": "host_not_approved"}}),
        (403, {"detail": "plain"}),
        (403, None),
    ],
)
async def test_other_responses_are_ignored(status, body):
    listener = MagicMock()
    client_tls.set_listener(listener)
    await client_tls._on_request_end(
        None, None, SimpleNamespace(response=_Response(status, body))
    )
    listener.certificate_refused.assert_not_called()


def test_session_kwargs_install_the_refusal_trace():
    kwargs = _endpoint(443, None).session_kwargs()
    try:
        assert len(kwargs["trace_configs"]) == 1
    finally:
        kwargs["connector"].close()
