# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Fetching the server's signed identity and (re-)pinning it (ROADMAP 25.10).

Both operations need the certificate observed ON THE SAME TLS connection that
fetched the statement, so this uses ``http.client`` directly: the peer
certificate is read from the socket before the request is sent.  It is
blocking on purpose -- the re-pin is started from inside a TLS handshake,
which may be on the event loop or on a worker thread, so it runs on a thread
of its own either way.
"""

import http.client
import json
import logging
import threading
import time
import urllib.request
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from src.i18n import _
from src.security.certificate_store import CertificateStore, sha256_hex
from src.security.server_pinning import IdentityError, spki_sha256, verify_statement

IDENTITY_PATH = "/api/agent/server-identity"
# At most one background re-pin attempt this often.
REPIN_INTERVAL_SECONDS = 60.0
FETCH_TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 256 * 1024

logger = logging.getLogger(__name__)

_repin_lock = threading.Lock()
_repin_state = {"last": 0.0}


class IdentityUnavailable(Exception):
    """The server could not say who it is right now (keep the pins; retry)."""


def _proxy_for(endpoint) -> Optional[Tuple[str, int]]:
    """``(host, port)`` of the HTTP proxy to tunnel through, or None.

    The same order the other transports use: an explicit ``server.proxy``,
    else ``HTTPS_PROXY`` from the environment unless ``NO_PROXY`` excludes
    the server.
    """
    proxy = endpoint.proxy()
    if not proxy:
        if urllib.request.proxy_bypass(endpoint.host):
            return None
        proxy = urllib.request.getproxies().get("https")
    if not proxy:
        return None
    split = urlsplit(proxy if "//" in proxy else f"//{proxy}")
    if not split.hostname:
        return None
    return split.hostname, split.port or 8080


def _connection(endpoint, context) -> http.client.HTTPSConnection:
    port = endpoint.port or 443
    proxy = _proxy_for(endpoint)
    if proxy is None:
        return http.client.HTTPSConnection(
            endpoint.host, port, context=context, timeout=FETCH_TIMEOUT_SECONDS
        )
    conn = http.client.HTTPSConnection(
        proxy[0], proxy[1], context=context, timeout=FETCH_TIMEOUT_SECONDS
    )
    conn.set_tunnel(endpoint.host, port)
    return conn


def fetch_identity(endpoint, context) -> Tuple[Dict[str, Any], str]:
    """GET the identity statement; return ``(document, observed_spki)``.

    ``context`` verifies the server normally but must not pin -- a pinned
    context would refuse exactly the connection a re-pin needs.
    """
    conn = _connection(endpoint, context)
    try:
        conn.connect()
        observed = spki_sha256(conn.sock.getpeercert(binary_form=True))
        conn.request("GET", IDENTITY_PATH, headers={"Accept": "application/json"})
        response = conn.getresponse()
        body = response.read(MAX_RESPONSE_BYTES)
        if response.status == 503:
            raise IdentityUnavailable(body[:200].decode("utf-8", "replace"))
        if response.status != 200:
            raise IdentityError(
                _("The server identity request failed: HTTP %s") % response.status
            )
        try:
            return json.loads(body.decode("utf-8")), observed
        except (UnicodeDecodeError, ValueError) as error:
            raise IdentityError(
                _("The server identity response is incomplete")
            ) from error
    finally:
        conn.close()


def first_pin(endpoint, store: CertificateStore) -> bool:
    """Pin the stored CA and the certificate seen while fetching the identity.

    Used after the first certificate issuance (the CA arrived over a verified
    TLS connection moments ago) and whenever a certificate exists but no pins
    do -- which is also how a deliberate reset takes effect.
    """
    ca_der = store.ca_certificate_der()
    if ca_der is None:
        return False
    ca_sha256 = sha256_hex(ca_der)
    context = endpoint.ssl_context(pin=False)
    try:
        document, observed = fetch_identity(endpoint, context)
        verify_statement(document, ca_sha256, observed)
    except IdentityUnavailable:
        logger.info(
            _("The server cannot state its TLS identity yet; pinning will be retried")
        )
        return False
    except (IdentityError, OSError, ValueError) as error:
        logger.error(
            _("Could not pin this server's identity: %s. Pinning will be retried."),
            error,
        )
        return False
    store.save_pins(ca_sha256, [observed])
    logger.info(_("Pinned this server's identity; its TLS certificate is now checked"))
    return True


def repin(endpoint, store: CertificateStore) -> bool:
    """Accept a changed server certificate if the server's identity signed it."""
    pins = store.load_pins()
    if pins is None:
        return False
    context = endpoint.ssl_context(pin=False)
    try:
        document, observed = fetch_identity(endpoint, context)
        verify_statement(document, pins["ca_sha256"], observed)
    except IdentityUnavailable:
        logger.warning(
            _(
                "The server's TLS certificate changed, but the server cannot state "
                "its TLS identity right now; keeping the current pins and trying "
                "again later"
            )
        )
        return False
    except (IdentityError, OSError, ValueError) as error:
        logger.error(
            _(
                "The server's TLS certificate changed and the change could not be "
                "verified (%s). The likely cause is a proxy, or another server, "
                "presenting a different certificate. If this server really was "
                "replaced, re-pin deliberately: delete %s or run the agent's "
                "reset command, then restart the agent."
            ),
            error,
            store.pins_path,
        )
        return False
    store.add_pin(observed)
    logger.info(
        _(
            "The server's TLS certificate changed; the new one is signed by this "
            "server's identity and is now trusted"
        )
    )
    return True


def schedule_repin(endpoint, store: CertificateStore) -> bool:
    """Start ONE background re-pin, at most once a minute.  True if started."""
    with _repin_lock:
        now = time.monotonic()
        if _repin_state["last"] and now - _repin_state["last"] < (
            REPIN_INTERVAL_SECONDS
        ):
            return False
        _repin_state["last"] = now
    thread = threading.Thread(
        target=_repin_quietly, args=(endpoint, store), name="server-repin"
    )
    thread.daemon = True
    thread.start()
    return True


def _repin_quietly(endpoint, store: CertificateStore) -> None:
    try:
        repin(endpoint, store)
    except Exception as error:  # pylint: disable=broad-except
        logger.error(_("Could not re-pin this server's identity: %s"), error)
