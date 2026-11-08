# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent's side of mutual TLS on every connection to the server (25.10).

``apply`` is called by ``ServerEndpoint.ssl_context()``, which builds the
context for every REST call and for the WebSocket, so there is one place that
decides:

* the client certificate is presented when the store holds an UNEXPIRED
  certificate and its key.  An expired one is never presented; that is logged
  once and a renewal is requested;
* the SysManage CA is ADDED to the trust (``load_verify_locations``).  The
  system trust store stays: the server's TLS certificate is usually a public
  one;
* when pins exist and ``server.tls_inspection`` is not true, the context
  refuses any server certificate that is not pinned.

The certificate manager (registration/host_certificate.py) registers itself as
the listener, so a refusal noticed here -- an expired local certificate, or a
REST 403 naming a certificate problem -- turns into a renewal there.
"""

import logging
import ssl
from typing import Any, Dict, Optional

from src.i18n import _
from src.security import server_identity
from src.security.certificate_store import CertificateStore
from src.security.server_pinning import PinChecker, install_pin_check

# The refusal codes the server uses for certificate problems (contract
# section 4), on the WebSocket and in REST 403 bodies alike.
REFUSAL_CODES = frozenset(
    (
        "host_certificate_required",
        "host_certificate_invalid",
        "host_certificate_expired",
    )
)

logger = logging.getLogger(__name__)

# Things logged once per process, not once per connection.
_warned = set()
_listener: Dict[str, Any] = {"target": None}


def set_listener(target) -> None:
    """Who hears about certificate problems: an object with
    ``certificate_expired()`` and ``certificate_refused(code, message)``.
    Both may be called from any thread."""
    _listener["target"] = target


def notify_refusal(code: str, message: str) -> None:
    target = _listener["target"]
    if target is None or code not in REFUSAL_CODES:
        return
    try:
        target.certificate_refused(code, message)
    except Exception as error:  # pylint: disable=broad-except
        logger.debug("Certificate refusal listener failed: %s", error)


def _notify_expired() -> None:
    target = _listener["target"]
    if target is None:
        return
    try:
        target.certificate_expired()
    except Exception as error:  # pylint: disable=broad-except
        logger.debug("Certificate expiry listener failed: %s", error)


def tls_inspection_enabled(server: Dict[str, Any]) -> bool:
    """``server.tls_inspection: true`` -- a TLS-inspecting proxy is expected."""
    return server.get("tls_inspection") is True


def _load_client_certificate(context: ssl.SSLContext, store: CertificateStore):
    state, not_after = store.certificate_state()
    if state == "expired":
        marker = ("expired", not_after)
        if marker not in _warned:
            _warned.add(marker)
            logger.warning(
                _("This host's certificate expired on %s; requesting a new one"),
                not_after.strftime("%Y-%m-%d %H:%M UTC"),
            )
        _notify_expired()
        return
    if state != "valid":
        return
    try:
        context.load_cert_chain(str(store.client_cert_path), str(store.client_key_path))
    except (ssl.SSLError, OSError) as error:
        logger.warning(
            _("This host's certificate could not be loaded and is not presented: %s"),
            error,
        )


def _install_pinning(
    context: ssl.SSLContext, endpoint, store: CertificateStore, server: Dict
):
    if tls_inspection_enabled(server):
        if "tls_inspection" not in _warned:
            _warned.add("tls_inspection")
            logger.warning(
                _(
                    "server.tls_inspection is true: the server's TLS certificate is "
                    "not pinned on this host. A TLS-inspecting proxy also removes "
                    "this host's client certificate, so the server must accept "
                    "this host without one."
                )
            )
        return
    pins = store.load_pins()
    if pins is None:
        return

    def _on_mismatch(_observed: str) -> None:
        server_identity.schedule_repin(endpoint, store)

    install_pin_check(context, PinChecker(pins["spki_sha256"], _on_mismatch))


def apply(
    context: ssl.SSLContext,
    endpoint,
    store: Optional[CertificateStore],
    server: Dict[str, Any],
    pin: bool = True,
) -> ssl.SSLContext:
    """Add the client certificate, the SysManage CA and the pin check."""
    if store is None:
        return context
    _load_client_certificate(context, store)
    if store.ca_cert_path.exists():
        try:
            context.load_verify_locations(cafile=str(store.ca_cert_path))
        except (ssl.SSLError, OSError) as error:
            logger.debug("SysManage CA not loaded: %s", error)
    if pin:
        _install_pinning(context, endpoint, store, server)
    return context


async def _on_request_end(_session, _ctx, params) -> None:
    """aiohttp trace hook: a REST 403 naming a certificate problem."""
    response = params.response
    if response.status != 403:
        return
    try:
        body = await response.json(content_type=None)
    except Exception:  # pylint: disable=broad-except
        return
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and detail.get("code") in REFUSAL_CODES:
        notify_refusal(str(detail["code"]), str(detail.get("message") or ""))


def refusal_trace_config():
    """An ``aiohttp.TraceConfig`` that reports certificate refusals.

    Installed on every server-bound session (ServerEndpoint.session_kwargs),
    so no REST caller has to remember to look for them.  The body is read
    only for a 403; aiohttp keeps it, so the caller can still read it.
    """
    import aiohttp  # noqa: PLC0415 - keeps this module importable without aiohttp

    trace = aiohttp.TraceConfig()
    trace.on_request_end.append(_on_request_end)
    return trace
