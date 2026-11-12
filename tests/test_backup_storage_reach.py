# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Can this host reach its backup storage? A TCP connection to the NFS port
of the address the server sent, and nothing else."""

# pylint: disable=protected-access

import asyncio
from unittest.mock import patch

import pytest

from src.sysmanage_agent.backup import storage_reach
from src.sysmanage_agent.communication import message_handler_queue
from src.sysmanage_agent.core import capabilities, capability_probes


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _check(address, connect, timeout=1.0):
    with patch.object(storage_reach, "CONNECT_SECONDS", timeout):
        return asyncio.run(storage_reach.check({"address": address}, connect))


def test_a_reachable_storage_host_is_connected_to_and_let_go():
    seen, writer = [], _Writer()

    async def connect(host, port):
        seen.append((host, port))
        return None, writer

    answer = _check("192.168.4.10", connect)
    assert answer == {"success": True, "reachable": True, "address": "192.168.4.10",
                      "port": 2049, "error": None}  # fmt: skip
    assert seen == [("192.168.4.10", 2049)] and writer.closed


def test_a_refused_or_unrouted_connection_is_unreachable():
    async def refused(_host, _port):
        raise ConnectionRefusedError(111, "Connection refused")

    answer = _check("nas.lab", refused)
    assert answer["success"] is True and answer["reachable"] is False
    assert answer["error"] == "Connection refused"


def test_no_answer_in_time_is_unreachable():
    async def hangs(_host, _port):
        await asyncio.sleep(10)

    answer = _check("192.168.4.10", hangs, timeout=0.05)
    assert answer["reachable"] is False and answer["error"] == "timeout"


@pytest.mark.parametrize(
    "address",
    [None, "", "http://nas", "nas:2049", "nas;rm -rf /", "-nas", 12, "a" * 300],
)
def test_only_an_ip_or_a_host_name_is_tried(address):
    async def never(_host, _port):
        raise AssertionError("must not connect")

    answer = _check(address, never)
    assert answer["success"] is False and answer["error"] == "invalid_address"


def test_ipv6_and_names_are_valid():
    assert storage_reach.valid_address("fd00::10")
    assert storage_reach.valid_address("nas.theeverlys.com")


def test_every_agent_but_windows_can_check():
    assert storage_reach.unavailable_reason(None, "Linux") is None
    assert storage_reach.unavailable_reason(None, "FreeBSD") is None
    assert storage_reach.unavailable_reason(None, "Windows") == "wrong_platform"


def test_the_check_is_its_own_capability_and_runs_in_the_express_lane():
    assert capabilities.CAPABILITY_GROUPS["backup_reach"] == ("check_backup_storage",)
    assert "check_backup_storage" in capability_probes._REASONED_LOCATORS
    assert message_handler_queue.is_express(
        {"data": {"command_type": "check_backup_storage"}}
    )


def _prod_like_chain(tmp_path):
    """A CA and a proxy certificate made as the SysManage CA made them before
    2026-11-12: no Subject Key Identifier on the CA, no Authority Key
    Identifier on the leaf -- which Python 3.13's strict default refuses."""
    # pylint: disable=import-outside-toplevel
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SysManage CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    cert = tmp_path / "proxy.crt"
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    keyfile = tmp_path / "proxy.key"
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))  # fmt: skip
    return ca.public_bytes(serialization.Encoding.PEM).decode(), cert, keyfile


def test_a_certificate_curl_accepts_is_accepted_on_strict_pythons(tmp_path):
    """The check verifies as restate's curl does: the SysManage CA's
    certificates without key identifiers, which Python 3.13 and later refuse
    by default, are reachable (prod, 2026-11-12)."""
    import ssl  # pylint: disable=import-outside-toplevel

    ca, cert, keyfile = _prod_like_chain(tmp_path)

    async def handshake(context):
        server_side = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_side.load_cert_chain(cert, keyfile)
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0,
                                            ssl=server_side)  # fmt: skip
        port = server.sockets[0].getsockname()[1]
        try:
            _r, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=context, server_hostname="localhost")  # fmt: skip
            writer.close()
            return True
        except ssl.SSLError:
            return False
        finally:
            server.close()
            await server.wait_closed()

    if (
        getattr(ssl, "VERIFY_X509_STRICT", 0)
        & ssl.create_default_context().verify_flags
    ):
        assert asyncio.run(handshake(ssl.create_default_context(cadata=ca))) is False
    assert asyncio.run(handshake(storage_reach._tls_context(ca))) is True
