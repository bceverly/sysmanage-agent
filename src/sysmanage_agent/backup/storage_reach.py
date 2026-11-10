# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Can this host reach its backup storage? (ROADMAP Phase 24)

A backed-up host mounts its repository from the storage host over NFSv4,
which is one TCP port: 2049.  The server sends the address it would have
this host mount from -- the storage host's, nothing else -- and the agent
tries to open a TCP connection to that port, briefly, and closes it.  No
NFS is spoken and nothing is mounted.  A host with no network path there
(production, 2026-10-30: the server's own cloud droplet and the home NAS)
is then not offered backups, rather than failing every night.

Behind NAT (25.8): a host on a private network behind another reaches port
2049 fine, but the storage host sees its traffic come from the gateway and
refuses the mount (its export names the host's own address).  So the answer
also carries this end of the connection (``local_address``/``local_port``),
and when the server asks (``hold_seconds``) the connection is kept open that
long, while the storage host's agent lists who it sees on port 2049
(backup/nfs_peers.py): the server finds this connection there by its source
port and compares the address the storage host sees.

Through restate-proxy (25.5) the server sends the proxy's port and how its
certificate is trusted instead (``proxy``: ``port``, and optionally ``ca``
and ``pin_sha256``).  The connection is then to that port, and a second one
completes a TLS handshake as restate's curl will: the certificate checked
against the site CA if one was sent, else the system's, for the proxy's
name, and its key against the pin.  ``tls`` says how that went, so a host
that reaches the port but would refuse the certificate is told before its
first backup fails.  NAT does not matter there: the proxy knows a host by its
token, not its address.
"""

import asyncio
import hashlib
import ipaddress
import platform
import re
import ssl
from typing import Any, Callable, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from src.sysmanage_agent.backup import restate_probe

NFS_PORT = 2049
CONNECT_SECONDS = 5.0
# How long the connection may be held open for the storage side to look.
MAX_HOLD_SECONDS = 120
# Held connections, kept referenced until they close (a bare task can be
# collected mid-run).
_HELD: set = set()
# A host name as DNS allows it: letters, digits and hyphens per label.
_HOST_NAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def valid_address(address: Any) -> bool:
    """An IP address or a host name -- never a URL, a port or anything else."""
    if not isinstance(address, str) or not address:
        return False
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return bool(_HOST_NAME.match(address))


def unavailable_reason(
    _lookup: Optional[Callable] = None, system: Optional[str] = None
) -> Optional[str]:
    """Windows never backs up (restate does not run there); everywhere else
    the check is a plain TCP connection, which every agent can make."""
    if (system or platform.system()) == "Windows":
        return restate_probe.REASON_WRONG_PLATFORM
    return None


async def _open(connect: Callable, address: str, port: int = NFS_PORT, **tls):
    """``connect`` to the port, given CONNECT_SECONDS at most -- inside a
    timeout context where Python has one (3.11+), ``wait_for`` on 3.9/3.10."""
    if hasattr(asyncio, "timeout"):
        async with asyncio.timeout(CONNECT_SECONDS):
            return await connect(address, port, **tls)
    return await asyncio.wait_for(connect(address, port, **tls), CONNECT_SECONDS)


def _proxy(parameters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The proxy part of the request, checked, or None (an NFS target)."""
    proxy = (parameters or {}).get("proxy")
    if not isinstance(proxy, dict):
        return None
    port = proxy.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return None
    pin = proxy.get("pin_sha256")
    pin = pin if isinstance(pin, str) and re.match(r"^[0-9a-f]{64}$", pin) else None
    ca = proxy.get("ca")
    ca = ca if isinstance(ca, str) and "-----BEGIN CERTIFICATE-----" in ca else None
    return {"port": port, "pin_sha256": pin, "ca": ca}


def spki_sha256(der: bytes) -> str:
    """The SHA-256 of a certificate's public key, in hex."""
    key = x509.load_der_x509_certificate(der).public_key()
    return hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()


def _tls_context(ca: Optional[str]) -> ssl.SSLContext:
    context = (
        ssl.create_default_context(cadata=ca) if ca else (ssl.create_default_context())
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


async def _tls(
    connect: Callable, address: str, proxy: Dict[str, Any]
) -> Dict[str, Any]:
    """``{"ok", "error", "spki_sha256"}``: a TLS handshake with the proxy as
    restate's curl makes it."""
    try:
        context = _tls_context(proxy["ca"])
        _reader, writer = await _open(
            connect, address, proxy["port"], ssl=context, server_hostname=address
        )
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout", "spki_sha256": None}
    except (ssl.SSLError, ssl.CertificateError, OSError, ValueError) as error:
        reason = (
            getattr(error, "verify_message", None)
            or getattr(error, "reason", None)
            or str(error)
        )
        return {"ok": False, "error": str(reason)[:200], "spki_sha256": None}
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        found = spki_sha256(der) if der else None
    except (AttributeError, ValueError):
        found = None
    await _close(writer, 0)
    if proxy["pin_sha256"] and found != proxy["pin_sha256"]:
        return {"ok": False, "error": "pin_mismatch", "spki_sha256": found}
    return {"ok": True, "error": None, "spki_sha256": found}


async def check(
    parameters: Dict[str, Any],
    connect: Callable = asyncio.open_connection,
) -> Dict[str, Any]:
    """``{"success", "reachable", "address", "port", "error"}`` for the
    address the server sent: port 2049, or the proxy's port and then
    ``tls`` as well."""
    address = (parameters or {}).get("address")
    proxy = _proxy(parameters)
    port = proxy["port"] if proxy else NFS_PORT
    if not valid_address(address):
        return {"success": False, "reachable": None, "address": None,
                "port": port, "error": "invalid_address"}  # fmt: skip
    try:
        _reader, writer = await _open(connect, address, port)
    except asyncio.TimeoutError:
        return _answer(address, False, "timeout", port)
    except OSError as error:
        return _answer(address, False, (error.strerror or str(error))[:200], port)
    answer = _answer(address, True, None, port)
    if proxy:
        await _close(writer, 0)
        answer["tls"] = await _tls(connect, address, proxy)
        return answer
    local = _local_end(writer)
    if local is not None:
        answer["local_address"], answer["local_port"] = local
    hold = _hold_seconds(parameters)
    if hold:
        task = asyncio.ensure_future(_close(writer, hold))
        _HELD.add(task)
        task.add_done_callback(_HELD.discard)
    else:
        await _close(writer, 0)
    return answer


def _hold_seconds(parameters: Dict[str, Any]) -> int:
    value = (parameters or {}).get("hold_seconds")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 0
    return min(value, MAX_HOLD_SECONDS)


def _local_end(writer) -> Optional[tuple]:
    """``(address, port)`` of this end of the connection, or None."""
    try:
        name = writer.get_extra_info("sockname")
    except AttributeError:
        return None
    if isinstance(name, tuple) and len(name) >= 2 and isinstance(name[1], int):
        return str(name[0]), name[1]
    return None


async def _close(writer, after: float) -> None:
    if after:
        await asyncio.sleep(after)
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass  # connected is what was asked; how it closed does not matter


def _answer(
    address: str, reachable: bool, error: Optional[str], port: int = NFS_PORT
) -> Dict[str, Any]:
    return {"success": True, "reachable": reachable, "address": address,
            "port": port, "error": error}  # fmt: skip
