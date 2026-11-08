# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Test PKI and a loopback TLS server for the mutual TLS / pinning tests.

Everything is generated with ``cryptography`` per test run: a CA, server TLS
certificates (SAN localhost + 127.0.0.1), host client certificates and a
server identity certificate that signs ``/api/agent/server-identity``
statements.
"""

import base64
import ipaddress
import json
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from src.security.certificate_store import sha256_hex
from src.security.server_pinning import spki_sha256

NOW = datetime.now(timezone.utc)


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


class Pki:
    """A CA plus helpers to issue certificates from it."""

    def __init__(self, name: str = "Test SysManage CA"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
                False,
            )
            .sign(self.key, hashes.SHA256())
        )

    @property
    def sha256(self) -> str:
        return sha256_hex(der(self.cert))

    def issue(
        self,
        common_name: str,
        key=None,
        server: bool = False,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
    ):
        """``(cert, key)`` issued by this CA."""
        key = key or ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or NOW - timedelta(days=1))
            .not_valid_after(not_after or NOW + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()
                ),
                False,
            )
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                False,
            ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                False,
            )
        else:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                False,
            )
        return builder.sign(self.key, hashes.SHA256()), key

    def write_ca(self, directory: Path) -> str:
        path = directory / f"ca-{id(self)}.pem"
        path.write_text(pem(self.cert), encoding="ascii")
        return str(path)


def spki_of(cert: x509.Certificate) -> str:
    return spki_sha256(der(cert))


def identity_document(
    ca: Pki,
    spkis: List[str],
    identity_cert=None,
    identity_key=None,
    expires_at: Optional[datetime] = None,
    sign_with=None,
    ca_cert=None,
) -> Dict[str, str]:
    """A server-identity response as the server would send it."""
    if identity_cert is None:
        identity_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        identity_cert, identity_key = ca.issue("sysmanage-server", key=identity_key)
    issued = NOW - timedelta(minutes=1)
    statement = json.dumps(
        {
            "v": 1,
            "spki_sha256": spkis,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": (expires_at or issued + timedelta(days=7))
            .isoformat()
            .replace("+00:00", "Z"),
        }
    ).encode("utf-8")
    signer = sign_with or identity_key
    if isinstance(signer, rsa.RSAPrivateKey):
        signature = signer.sign(statement, padding.PKCS1v15(), hashes.SHA256())
    else:
        signature = signer.sign(statement, ec.ECDSA(hashes.SHA256()))
    return {
        "ca_certificate": pem(ca_cert or ca.cert),
        "identity_certificate": pem(identity_cert),
        "statement": base64.b64encode(statement).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


class LoopbackTlsServer:
    """A TLS server on 127.0.0.1 that records what each client presented.

    ``client_ca`` set: client certificates are requested (CERT_OPTIONAL) and
    verified against it.  ``body`` set: each connection gets an HTTP 200 with
    that JSON body.
    """

    def __init__(self, cert, key, tmp: Path, client_ca: Optional[Pki] = None):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_path = tmp / f"server-{id(self)}.crt"
        key_path = tmp / f"server-{id(self)}.key"
        cert_path.write_text(pem(cert), encoding="ascii")
        key_path.write_bytes(key_pem(key))
        self.context.load_cert_chain(str(cert_path), str(key_path))
        if client_ca is not None:
            self.context.verify_mode = ssl.CERT_OPTIONAL
            self.context.load_verify_locations(cafile=client_ca.write_ca(tmp))
        self.body: Optional[dict] = None
        self.peer_certs: List[Optional[bytes]] = []
        self.handshakes = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(5)
        self._sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._handle(raw)

    def _handle(self, raw):
        raw.settimeout(5)
        try:
            with self.context.wrap_socket(raw, server_side=True) as conn:
                self.handshakes += 1
                self.peer_certs.append(conn.getpeercert(binary_form=True))
                if self.body is not None:
                    self._answer(conn)
                else:
                    try:
                        conn.recv(1)
                    except (OSError, ssl.SSLError):
                        pass
        except (OSError, ssl.SSLError):
            raw.close()

    def _answer(self, conn):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        payload = json.dumps(self.body).encode("utf-8")
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )


class ServerConfig:
    """ConfigManager stand-in: the endpoint needs these two methods."""

    def __init__(self, server: dict, verify_ssl: bool = True):
        self.server = server
        self.verify_ssl = verify_ssl

    def get_server_config(self):
        return self.server

    def should_verify_ssl(self):
        return self.verify_ssl
