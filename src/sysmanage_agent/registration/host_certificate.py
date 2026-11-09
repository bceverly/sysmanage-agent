# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""This host's TLS client certificate: enrollment, renewal, refusals (25.10).

The agent generates its own EC P-256 key, sends only a CSR to
``POST /api/agent/certificate`` (connection token + host token, like every
other host-authenticated call), and stores what comes back.  The key never
leaves the host.

WHEN IT ASKS
------------
* at start-up and every 24 hours, once the host has an id and a host token
  and is approved;
* when a connection is confirmed (registration_success) or the host is
  approved, so a newly approved host does not wait a day;
* right after the server refuses it with ``host_certificate_required`` or
  ``host_certificate_expired`` (WebSocket or REST), and when the stored
  certificate is found expired while building a TLS context.

A scheduled check asks only when there is no certificate, it has expired, or
it is inside its last 30 days.  A refusal asks regardless: the server has just
said the certificate it holds for this host is not usable.

After a certificate is stored and no pins exist yet, the server's identity is
pinned (src/security/server_identity.first_pin).
"""

import asyncio
import platform
import time
from typing import Any, Dict, Optional, Tuple

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.i18n import _
from src.security import client_tls, server_identity
from src.security.certificate_store import sha256_hex
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint

CERTIFICATE_PATH = "/api/agent/certificate"
RENEWAL_CHECK_SECONDS = 24 * 3600
# A refusal or an expired certificate asks for a new one at most this often,
# so a server that keeps refusing is not asked on every reconnect.
TRIGGER_INTERVAL_SECONDS = 300.0
_SPKI = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def generate_key() -> ec.EllipticCurvePrivateKey:
    """A fresh EC P-256 key; it never leaves this host."""
    return ec.generate_private_key(ec.SECP256R1())


# X.509 (RFC 5280 ub-common-name): the most a common name may hold.
MAX_COMMON_NAME = 64


def build_csr(key: ec.EllipticCurvePrivateKey) -> str:
    """PEM PKCS#10 request for ``key``.  The server ignores the subject (it
    sets CN = the host's fqdn, OU = the host id); the node name is there only
    to make the request recognizable.  A common name is at most 64
    characters (X.509), and a machine's name can be longer -- GitHub's macOS
    runners have 67 -- so it is cut there."""
    name = (platform.node() or "sysmanage-agent")[:MAX_COMMON_NAME]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _detail_code(body: Any) -> Tuple[str, str]:
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict):
        return str(detail.get("code") or ""), str(detail.get("message") or "")
    return "", str(detail or "")


class HostCertificateManager:
    """Keeps this host's client certificate current."""

    def __init__(self, agent):
        self.agent = agent
        self.logger = agent.logger
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lock: Optional[asyncio.Lock] = None
        self._periodic: Optional[asyncio.Task] = None
        self._tasks = set()
        self._last_trigger: Dict[str, float] = {}
        client_tls.set_listener(self)

    @property
    def store(self):
        return self.agent.cert_store

    def _endpoint(self) -> ServerEndpoint:
        return ServerEndpoint(self.agent.config, self.store)

    # -- scheduling -------------------------------------------------------

    def start(self) -> None:
        """Start the 24-hour check (it runs once at once).  Idempotent."""
        self._loop = asyncio.get_running_loop()
        if self._periodic is None or self._periodic.done():
            self._periodic = self._loop.create_task(self._periodic_checks())

    async def _periodic_checks(self) -> None:
        while True:
            await self._safe_check()
            await asyncio.sleep(RENEWAL_CHECK_SECONDS)

    def kick(self, force: bool = False, reconnect: bool = False) -> None:
        """Run one check soon, on the agent's event loop."""
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            if self._loop is None:
                return
        task = self._loop.create_task(self._safe_check(force, reconnect))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _kick_threadsafe(self, reason: str, force: bool, reconnect: bool) -> bool:
        """``kick`` from any thread, at most once per TRIGGER_INTERVAL."""
        now = time.monotonic()
        last = self._last_trigger.get(reason)
        if last is not None and now - last < TRIGGER_INTERVAL_SECONDS:
            return False
        self._last_trigger[reason] = now
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            self.kick(force, reconnect)
        elif self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self.kick, force, reconnect)
        else:
            return False
        return True

    # -- listener (src/security/client_tls) -------------------------------

    def certificate_expired(self) -> None:
        """The stored certificate is expired (already logged once).

        Not forced: the check asks only while renewal is still due, so the
        notices raised by the request's own TLS context ask nothing twice."""
        self._kick_threadsafe("expired", force=False, reconnect=False)

    def certificate_refused(self, code: str, message: str) -> None:
        """The server refused this host for a certificate problem."""
        if code == "host_certificate_invalid":
            self.logger.error(
                _(
                    "The server refused this host's certificate as not valid for "
                    "this host (%s). The agent does not replace it on its own; an "
                    "administrator should check this host on the server."
                ),
                message,
            )
            return
        if code == "host_certificate_required":
            self.logger.warning(
                _(
                    "The server requires a certificate from this host and refused "
                    "the connection without one (%s); requesting a certificate now."
                ),
                message,
            )
        else:
            self.logger.warning(
                _(
                    "The server refused this host's certificate because it has "
                    "expired (%s); requesting a new certificate now."
                ),
                message,
            )
        if not self._kick_threadsafe("refused", force=True, reconnect=True):
            self.logger.debug("Certificate request already made recently")

    # -- the check --------------------------------------------------------

    async def _safe_check(self, force: bool = False, reconnect: bool = False):
        try:
            issued = await self.check(force)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Certificate check failed: %s"), error)
            return
        if issued and reconnect and getattr(self.agent, "websocket", None):
            # The refused connection was made without the new certificate;
            # reconnect so it is presented (as _handle_host_not_registered).
            self.logger.info("Reconnecting to present the new host certificate")
            self.agent.running = False

    async def check(self, force: bool = False) -> bool:
        """Request a certificate if one is due (or ``force``); pin if needed.

        True when a new certificate was stored.
        """
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            endpoint = self._endpoint()
            if not endpoint.uses_tls:
                self.logger.debug("Plain HTTP to the server: no host certificate")
                return False
            credentials = await self._credentials()
            if credentials is None:
                self.logger.debug("Host not approved yet: no certificate requested")
                return False
            issued = False
            if force or self.store.needs_renewal():
                issued = await self.request_certificate(endpoint, *credentials)
            await self._pin_if_missing(endpoint)
            return issued

    async def _credentials(self) -> Optional[Tuple[str, str]]:
        manager = self.agent.registration_manager
        approval = manager.get_host_approval_from_db()
        host_id = str(getattr(approval, "host_id", "") or "")
        if not host_id:
            return None
        host_token = await manager.get_stored_host_token()
        if not host_token:
            return None
        return host_id, host_token

    async def request_certificate(self, endpoint, host_id: str, host_token: str):
        """POST a CSR; store the certificate.  True on success."""
        key = generate_key()
        token = await self.agent.get_auth_token()
        async with aiohttp.ClientSession(
            **endpoint.session_kwargs()
        ) as session, session.post(
            endpoint.rest_url(CERTIFICATE_PATH),
            json={"host_id": host_id, "csr": build_csr(key)},
            headers={
                "Authorization": f"Bearer {token}",
                "X-Host-Token": host_token,
            },
            proxy=endpoint.proxy(),
        ) as response:
            status = response.status
            try:
                body = await response.json(content_type=None)
            except (aiohttp.ContentTypeError, ValueError):
                body = None
        if status == 200 and isinstance(body, dict):
            return self._store_issued(body, key)
        self._log_refused(status, body)
        return False

    def _store_issued(self, body: Dict[str, Any], key) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(body["certificate"].encode("ascii"))
            ca = x509.load_pem_x509_certificate(body["ca_certificate"].encode("ascii"))
        except (KeyError, AttributeError, ValueError):
            self.logger.error(_("The server's certificate response is not usable"))
            return False
        if cert.public_key().public_bytes(*_SPKI) != key.public_key().public_bytes(
            *_SPKI
        ):
            self.logger.error(_("The server issued a certificate for a different key"))
            return False
        pins = self.store.load_pins()
        ca_sha256 = sha256_hex(ca.public_bytes(serialization.Encoding.DER))
        if pins is not None and pins["ca_sha256"] != ca_sha256:
            self.logger.warning(
                _(
                    "The new host certificate was issued by a CA other than the "
                    "pinned one. A changed server TLS certificate will not be "
                    "accepted until the pins are reset deliberately."
                )
            )
        self.store.store_issued(
            body["certificate"], key_pem(key), body["ca_certificate"]
        )
        self.logger.info(
            _("This host's certificate was issued; it is valid until %s"),
            cert.not_valid_after_utc.strftime("%Y-%m-%d"),
        )
        return True

    def _log_refused(self, status: int, body: Any) -> None:
        code, message = _detail_code(body)
        if status == 401:
            self.agent.auth_helper.invalidate_auth_token()
        if status == 404:
            # A server that predates host certificates: nothing to report on
            # every reconnect.
            self.logger.debug("Server does not issue host certificates (HTTP 404)")
        elif code == "host_not_approved":
            self.logger.info(
                _("No certificate yet: this host is not approved (%s)"), message
            )
        elif code == "certificate_current":
            self.logger.warning(
                _(
                    "The server says this host's certificate is still current but "
                    "did not receive it (%s). Something between the agent and the "
                    "server may be removing it; the agent keeps the certificate "
                    "and asks again later."
                ),
                message,
            )
        else:
            self.logger.error(
                _("The server did not issue a certificate: HTTP %s, %s"),
                status,
                code or message or "-",
            )

    async def _pin_if_missing(self, endpoint) -> None:
        server = self.agent.config.get_server_config() or {}
        if client_tls.tls_inspection_enabled(server):
            return
        if self.store.load_pins() is not None:
            return
        if self.store.presentable_paths() is None:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, server_identity.first_pin, endpoint, self.store
        )
