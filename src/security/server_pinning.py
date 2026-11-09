# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server pinning: the TLS certificate the server presents must be one this
agent has pinned (ROADMAP 25.10).

WHAT IS PINNED
--------------
Two things, in ``server_pins.json``:

* the SysManage CA (SHA-256 of its DER) -- the root of this server's identity;
* the SubjectPublicKeyInfo SHA-256 of the TLS certificate(s) the server
  presents (the newest three).

The TLS certificate is usually a public one (Let's Encrypt) that changes every
60-90 days with a new key.  So a change is not, by itself, an attack: the agent
fetches ``/api/agent/server-identity``, a statement signed by the server's
identity certificate (issued by the pinned CA) that lists the SPKIs it serves
now, and trusts the new certificate only if the statement verifies and names
the certificate seen on that very connection.  A TLS-inspecting proxy, or a
different server, cannot produce such a statement.

HOW IT IS ENFORCED
------------------
An ``ssl.SSLContext`` whose ``sslobject_class`` (asyncio: aiohttp, websockets)
and ``sslsocket_class`` (blocking sockets) check the peer's certificate right
after the handshake, before a single byte of HTTP is exchanged.
"""

import base64
import binascii
import json
import ssl
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from src.i18n import _
from src.security.certificate_store import sha256_hex

STATEMENT_VERSION = 1


class PinMismatchError(ssl.SSLCertVerificationError):
    """The server presented a TLS certificate this agent has not pinned."""


class IdentityError(Exception):
    """A server-identity statement did not verify; the message says why."""


def spki_sha256(der_certificate: bytes) -> str:
    """Lowercase hex SHA-256 of a certificate's DER SubjectPublicKeyInfo."""
    cert = x509.load_der_x509_certificate(der_certificate)
    return sha256_hex(
        cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


class PinChecker:
    """Checks one peer certificate against a fixed set of pins.

    ``on_mismatch`` is told the SPKI that was refused (it schedules the
    background re-pin); it must not raise and must not block.
    """

    def __init__(
        self,
        pins: List[str],
        on_mismatch: Optional[Callable[[str], None]] = None,
    ):
        self.pins = frozenset(p.lower() for p in pins)
        self.on_mismatch = on_mismatch

    def check(self, der_certificate: Optional[bytes]) -> None:
        observed = spki_sha256(der_certificate) if der_certificate else ""
        if observed in self.pins:
            return
        if self.on_mismatch is not None:
            try:
                self.on_mismatch(observed)
            except Exception:  # pylint: disable=broad-except
                pass  # the refusal below matters more than the re-pin
        raise PinMismatchError(
            _(
                "The server presented a TLS certificate this agent has not pinned "
                "(SPKI SHA-256 %s). The connection was refused. The agent is "
                "checking whether the server has signed the new certificate."
            )
            % (observed or "none")
        )


class _PinnedSSLObject(ssl.SSLObject):
    """asyncio's TLS object, plus the pin check once the handshake is done."""

    pin_checker: Optional[PinChecker] = None

    def do_handshake(self):
        super().do_handshake()
        self.pin_checker.check(self.getpeercert(binary_form=True))


class _PinnedSSLSocket(ssl.SSLSocket):  # pylint: disable=abstract-method
    """A blocking TLS socket, plus the pin check once the handshake is done."""

    pin_checker: Optional[PinChecker] = None

    def do_handshake(self, block=False):
        super().do_handshake(block)
        self.pin_checker.check(self.getpeercert(binary_form=True))


def install_pin_check(context: ssl.SSLContext, checker: PinChecker) -> None:
    """Make every connection made with ``context`` check ``checker``'s pins.

    Fresh subclasses per context, so two contexts with different pins never
    share state.
    """
    context.sslobject_class = type(
        "PinnedSSLObject", (_PinnedSSLObject,), {"pin_checker": checker}
    )
    context.sslsocket_class = type(
        "PinnedSSLSocket", (_PinnedSSLSocket,), {"pin_checker": checker}
    )


# -- verifying a signed server-identity statement ---------------------------


def _parse_time(value: Any) -> datetime:
    """ISO-8601 to an aware UTC datetime.  Python 3.9's fromisoformat does
    not accept a trailing "Z", so it is rewritten first."""
    if not isinstance(value, str):
        raise IdentityError(_("The server identity statement has no valid expiry"))
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise IdentityError(
            _("The server identity statement has no valid expiry")
        ) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_pem(value: Any) -> x509.Certificate:
    if not isinstance(value, str):
        raise IdentityError(_("The server identity response is incomplete"))
    try:
        return x509.load_pem_x509_certificate(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise IdentityError(_("The server identity response is incomplete")) from error


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise IdentityError(_("The server identity response is incomplete"))
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise IdentityError(_("The server identity response is incomplete")) from error


def _check_identity_certificate(
    identity: x509.Certificate, ca: x509.Certificate, now: datetime
) -> None:
    try:
        identity.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature) as error:
        raise IdentityError(
            _("The server's identity certificate was not issued by the pinned CA")
        ) from error
    if not identity.not_valid_before_utc <= now <= identity.not_valid_after_utc:
        raise IdentityError(
            _("The server's identity certificate is outside its validity period")
        )


# The server signs with PSS (MGF1-SHA256, salt the digest's length).
_PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
)


def _check_signature(identity: x509.Certificate, statement: bytes, sig: bytes):
    key = identity.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, statement, _PSS, hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, statement, ec.ECDSA(hashes.SHA256()))
        else:
            raise IdentityError(
                _("The server's identity certificate uses an unsupported key type")
            )
    except InvalidSignature as error:
        raise IdentityError(
            _("The server identity statement is not signed by its identity certificate")
        ) from error


def _statement_spkis(statement: bytes, now: datetime) -> List[str]:
    try:
        body = json.loads(statement.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise IdentityError(
            _("The server identity statement is not readable")
        ) from error
    if not isinstance(body, dict) or body.get("v") != STATEMENT_VERSION:
        raise IdentityError(_("The server identity statement is not readable"))
    if now >= _parse_time(body.get("expires_at")):
        raise IdentityError(_("The server identity statement has expired"))
    spkis = body.get("spki_sha256")
    if not isinstance(spkis, list) or not all(isinstance(s, str) for s in spkis):
        raise IdentityError(_("The server identity statement is not readable"))
    return [s.lower() for s in spkis]


def verify_statement(
    document: Dict[str, Any],
    pinned_ca_sha256: str,
    observed_spki: str,
    now: Optional[datetime] = None,
) -> List[str]:
    """Verify a ``/api/agent/server-identity`` response; return its SPKIs.

    Raises :class:`IdentityError` unless every check passes:

    1. the response's CA is the pinned CA (same SHA-256 of its DER) -- a
       different CA is a different server, and only a deliberate re-pin
       accepts one;
    2. the identity certificate was issued by that CA and is in date;
    3. the statement is signed by the identity certificate's key;
    4. the statement has not expired;
    5. it names ``observed_spki``, the certificate seen on the connection
       that fetched it.
    """
    if not isinstance(document, dict):
        raise IdentityError(_("The server identity response is incomplete"))
    now = now or datetime.now(timezone.utc)
    ca = _load_pem(document.get("ca_certificate"))
    identity = _load_pem(document.get("identity_certificate"))
    statement = _b64(document.get("statement"))
    signature = _b64(document.get("signature"))

    if sha256_hex(ca.public_bytes(serialization.Encoding.DER)) != (
        pinned_ca_sha256.lower()
    ):
        raise IdentityError(_("The server's CA is not the CA this agent has pinned"))
    _check_identity_certificate(identity, ca, now)
    _check_signature(identity, statement, signature)
    spkis = _statement_spkis(statement, now)
    if observed_spki.lower() not in spkis:
        raise IdentityError(
            _(
                "The certificate on this connection is not one the server's "
                "signed statement lists"
            )
        )
    return spkis
