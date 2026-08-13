# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""One place that knows how to reach the SysManage server.

WHY THIS EXISTS
---------------
Eight separate call sites used to build the server URL by hand from
``hostname`` + ``port`` + ``use_https``, and two of them also hand-rolled an
identical SSL context.  They had drifted: every one of them defaulted the port
to ``8000``, while every shipped config template says ``8080``.  Nothing caught
it because no deployment ever omits the port -- the wrong default simply sat
there waiting.  That is the duplicated-table defect the Phase 19 roadmap calls
out, and the fix is the same one: one table, one reader.

ONE ORIGIN, ONE PORT
--------------------
The goal this serves is that an operator should not have to open anything for
SysManage to work.  Agents talk to exactly one origin over 443, and the API
already lives under ``/api`` on that origin -- the same origin the web UI is
served from.  The only reason agents ever needed a second port was that the
shipped defaults pointed at the backend directly instead of at the front door.

So the preferred configuration is a single URL::

    server:
      url: "https://sysmanage.example.com"

with no port at all, meaning 443.  A port is still accepted when one is
genuinely needed -- notably development, where the backend runs on 8080 with no
reverse proxy in front of it::

    server:
      url: "http://localhost:8080"

HOSTILE-BUT-NORMAL NETWORKS
---------------------------
"Just works" has to include the networks real companies run:

* **TLS-inspecting proxies** that re-sign traffic with a private CA.  Handled by
  TRUSTING that CA (``ca_bundle``), never by turning verification off.  The
  existing ``verify_ssl: false`` escape hatch stays for lab use, but it is the
  wrong answer to this problem and the config template says so.
* **HTTP CONNECT proxies.**  Honoured from the environment by default
  (``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``NO_PROXY``), because that is where a
  managed desktop already has them, with an explicit ``server.proxy`` override
  for hosts that have no such environment (a Windows service, for instance,
  does not inherit a user's shell).

BACKWARD COMPATIBILITY IS NOT OPTIONAL
--------------------------------------
Every agent already in the field has ``hostname`` / ``port`` / ``use_https`` in
its config.  An upgrade that ignored those would strand the entire fleet on the
next restart, so they remain fully supported and produce exactly the URLs they
always did.  ``url`` is simply preferred when present.
"""

from __future__ import annotations

import os
import ssl
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

# Ports that are implied by the scheme and therefore omitted from a URL.  Used
# to decide whether ":port" needs to appear at all -- an explicit ":443" in a
# WebSocket URL is harmless but noisy in logs, and some proxies key on the
# literal Host header.
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class ServerEndpoint:
    """Resolves the server origin, TLS settings and proxy from agent config.

    Deliberately a plain object over the config dict rather than something that
    caches: config is re-read on reload, and a stale endpoint pointing at an old
    server is a failure mode nobody would think to look for.
    """

    def __init__(self, config):
        self._config = config

    # -- resolution ---------------------------------------------------------

    def _server(self) -> Dict[str, Any]:
        return self._config.get_server_config() or {}

    def _parts(self) -> tuple:
        """Return ``(scheme, host, port_or_None)`` for the configured server.

        ``server.url`` wins when present.  Otherwise the legacy
        hostname/port/use_https triple is used, which is what every deployed
        agent has today.
        """
        server = self._server()

        url = (server.get("url") or "").strip()
        if url:
            split = urlsplit(url if "//" in url else f"//{url}")
            scheme = (split.scheme or "").lower()
            # ws:// and wss:// are accepted and normalised to their HTTP
            # equivalents.  This is not hypothetical: six of the seven shipped
            # config templates say ``url: "wss://sysmanage.example.com:8443"``.
            # Treating an unrecognised scheme as "fall back to use_https" would
            # silently downgrade every one of those installs to PLAINTEXT ws://,
            # which is far worse than failing to parse.
            scheme = {"ws": "http", "wss": "https"}.get(scheme, scheme)
            if scheme not in ("http", "https"):
                # A bare "host" or "host:port" with no scheme.  Fall back to
                # use_https rather than guessing, so the meaning of an existing
                # config never changes silently.
                scheme = "https" if server.get("use_https", False) else "http"
            host = split.hostname or "localhost"
            return scheme, host, split.port

        scheme = "https" if server.get("use_https", False) else "http"
        host = server.get("hostname", "localhost")
        # No port configured now means "the standard one for this scheme" --
        # 443, the whole point of the exercise.  The historical default here was
        # 8000, which matched no shipped template and was simply a latent bug.
        port = server.get("port")
        return scheme, host, port

    @property
    def scheme(self) -> str:
        return self._parts()[0]

    @property
    def host(self) -> str:
        return self._parts()[1]

    @property
    def port(self) -> Optional[int]:
        """The explicit port, or None when the scheme's default applies."""
        return self._parts()[2]

    @property
    def uses_tls(self) -> bool:
        return self.scheme == "https"

    def _authority(self) -> str:
        scheme, host, port = self._parts()
        if port is None or port == DEFAULT_PORTS.get(scheme):
            return host
        return f"{host}:{port}"

    # -- URLs ---------------------------------------------------------------

    def base_url(self) -> str:
        """``https://host[:port]`` with no trailing slash."""
        return f"{self.scheme}://{self._authority()}"

    def rest_url(self, path: str = "") -> str:
        """Absolute URL for a REST path.

        ``path`` is taken verbatim, including its ``/api`` prefix where the
        endpoint has one.  Some endpoints deliberately sit outside ``/api``
        (registration and health are unauthenticated), so this does not prepend
        anything -- callers say exactly what they mean.
        """
        if path and not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url()}{path}"

    def websocket_url(self, path: str = "/api/agent/connect") -> str:
        """Absolute ``ws://`` / ``wss://`` URL on the SAME origin as the REST API.

        Same host, same port, same TLS decision -- deliberately derived rather
        than separately configured, because a WebSocket on a different port is
        exactly the second hole in the firewall this work exists to remove.
        """
        ws_scheme = "wss" if self.uses_tls else "ws"
        if path and not path.startswith("/"):
            path = "/" + path
        return f"{ws_scheme}://{self._authority()}{path}"

    # -- transport security -------------------------------------------------

    def ssl_context(self) -> Optional[ssl.SSLContext]:
        """SSL context for this endpoint, or None for plain HTTP.

        Three cases, in the order an operator meets them:

        1. Ordinary TLS -- the system trust store, TLS 1.2 floor.
        2. A corporate CA (``ca_bundle``) -- the right answer for estates that
           terminate and re-sign TLS in the middle.  Verification stays ON; we
           simply also trust the root they gave us.
        3. ``verify_ssl: false`` -- verification off entirely.  Supported
           because labs need it, but it is not the fix for case 2 and the
           config template says as much.
        """
        if not self.uses_tls:
            return None

        server = self._server()
        ca_bundle = server.get("ca_bundle") or None

        if ca_bundle and not os.path.isfile(ca_bundle):
            # Fail loudly and attributably.  ssl.create_default_context raises a
            # bare FileNotFoundError from inside the stdlib, which tells an
            # operator nothing about WHICH setting is wrong.
            #
            # Deliberately NOT falling back to the system trust store: the
            # operator asked for a specific CA, almost certainly because a
            # TLS-inspecting proxy sits in the path.  Quietly ignoring it would
            # leave every connection failing certificate validation with a
            # confusing error somewhere else entirely -- and if it DID somehow
            # succeed, it would mean trusting a chain the operator did not ask
            # to trust.
            raise FileNotFoundError(
                f"server.ca_bundle points at {ca_bundle!r}, which does not exist. "
                "Fix the path, or remove the setting to use the system trust store."
            )

        context = ssl.create_default_context(cafile=ca_bundle)  # NOSONAR
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        if not self._config.should_verify_ssl():
            # NOSONAR - verification is disabled only when an administrator
            # explicitly sets verify_ssl: false.
            context.check_hostname = False  # NOSONAR
            context.verify_mode = ssl.CERT_NONE  # NOSONAR

        return context

    def session_kwargs(self) -> Dict[str, Any]:
        """Keyword arguments for an ``aiohttp.ClientSession`` talking to the server.

        Bundles the TLS context with ``trust_env=True`` so the session picks up
        ``HTTP_PROXY`` / ``HTTPS_PROXY`` / ``NO_PROXY`` from the environment.
        A fresh connector is built per call because aiohttp connectors are bound
        to one session and cannot be shared.

        Pair it with ``proxy=endpoint.proxy()`` on the request itself for the
        explicit override.  Unlike ``websockets``, aiohttp treats ``proxy=None``
        as "no per-request override" rather than "ignore the environment", so
        passing it unconditionally is safe.
        """
        import aiohttp  # noqa: PLC0415 - keeps this module importable without aiohttp

        return {
            "connector": aiohttp.TCPConnector(ssl=self.ssl_context()),
            "trust_env": True,
        }

    def proxy(self) -> Optional[str]:
        """Explicit proxy URL, or None to let the transport use the environment.

        Returning None is NOT "no proxy" -- both aiohttp (``trust_env``) and
        websockets read ``HTTPS_PROXY`` / ``NO_PROXY`` themselves.  This only
        overrides that, for hosts where the environment cannot carry it: a
        Windows service does not inherit a user's shell variables, and that is
        precisely the kind of host that ends up behind a mandatory proxy.
        """
        server = self._server()
        proxy = (server.get("proxy") or "").strip()
        return proxy or None
