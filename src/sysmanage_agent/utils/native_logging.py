# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Platform-native log handler selection for the SysManage agent.

Returns an OS-native ``logging.Handler`` so the agent integrates with the host's
logging system — systemd journal (``journalctl``), syslog, or the Windows Event
Log — in addition to its rotating file log.  Opt-in via config; returns ``None``
(the caller keeps file logging and prints a notice) when the requested sink is
unavailable, so a missing optional dependency never stops the agent.
"""

import logging
import logging.handlers
import os
import platform
import socket
from typing import Optional

# BSD variants whose syslog socket is /dev/log (like Linux).
_BSD_SYSTEMS = {"FreeBSD", "OpenBSD", "NetBSD", "DragonFly"}


def build_native_handler(  # pylint: disable=too-many-arguments,too-many-return-statements
    target: str = "auto",
    identifier: str = "sysmanage-agent",
    system: Optional[str] = None,
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    facility: Optional[str] = None,
    protocol: Optional[str] = None,
) -> Optional[logging.Handler]:
    """Build a platform-native log handler.

    ``target``: ``auto`` | ``journald`` | ``syslog`` | ``syslog_remote`` |
    ``eventlog`` | ``none``.  ``auto`` picks journald on Linux (falling back to
    syslog), the Windows Event Log on Windows, and syslog on macOS/BSD.
    ``syslog_remote`` forwards over the network to ``host``:``port`` (Phase 14.5)
    and uses ``facility`` / ``protocol`` (udp|tcp).  Returns ``None`` if the sink
    can't be created (missing ``systemd``/``pywin32``, no syslog socket, or —
    for ``syslog_remote`` — no host).
    """
    system = system or platform.system()
    target = (target or "auto").lower()

    if target in ("none", "off", ""):
        return None
    if target == "auto":
        target = _auto_target(system)

    if target == "journald":
        # Fall back to syslog on a Linux box without python3-systemd.
        return _journald_handler(identifier) or _syslog_handler(identifier, system)
    if target == "syslog":
        return _syslog_handler(identifier, system)
    if target == "syslog_remote":
        return _syslog_remote_handler(identifier, host, port, facility, protocol)
    if target == "eventlog":
        return _eventlog_handler(identifier, system)
    return None


def _syslog_remote_handler(
    identifier: str,
    host: Optional[str],
    port: Optional[int],
    facility: Optional[str],
    protocol: Optional[str],
) -> Optional[logging.Handler]:
    """SysLogHandler forwarding to a REMOTE host:port over UDP/TCP (Phase 14.5).

    ``None`` when no host is configured or the socket can't be created — the
    caller keeps file logging, so a bad remote target never stops the agent.
    """
    if not host:
        return None
    try:
        port_num = int(port) if port else 514
    except (TypeError, ValueError):
        port_num = 514
    socktype = (
        socket.SOCK_STREAM
        if (protocol or "udp").lower() == "tcp"
        else socket.SOCK_DGRAM
    )
    facility_val = logging.handlers.SysLogHandler.LOG_USER
    if facility:
        facility_val = logging.handlers.SysLogHandler.facility_names.get(
            facility.lower(), logging.handlers.SysLogHandler.LOG_USER
        )
    try:
        handler = logging.handlers.SysLogHandler(
            address=(host, port_num), facility=facility_val, socktype=socktype
        )
    except OSError:  # ConnectionError is an OSError subclass (TCP connect fail)
        return None
    handler.setFormatter(
        logging.Formatter(f"{identifier}[%(process)d]: %(levelname)s %(message)s")
    )
    return handler


def _auto_target(system: str) -> str:
    """Choose the natural native sink for the platform."""
    if system == "Windows":
        return "eventlog"
    if system == "Linux":
        return "journald"
    return "syslog"  # Darwin + BSDs


def _journald_handler(identifier: str) -> Optional[logging.Handler]:
    """systemd journal handler, or None if python3-systemd isn't installed."""
    try:
        # pylint: disable=import-outside-toplevel
        from systemd.journal import JournalHandler  # type: ignore
    except ImportError:
        return None
    try:
        return JournalHandler(SYSLOG_IDENTIFIER=identifier)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _syslog_address(system: str):
    """Return the platform's syslog socket path (or a UDP fallback tuple)."""
    if system == "Darwin":
        return "/var/run/syslog"
    if system == "Linux" or system in _BSD_SYSTEMS:
        return "/dev/log"
    return ("localhost", 514)


def _syslog_handler(identifier: str, system: str) -> Optional[logging.Handler]:
    """SysLogHandler bound to the local syslog socket (UDP 514 fallback)."""
    address = _syslog_address(system)
    if isinstance(address, str) and not os.path.exists(address):
        address = ("localhost", 514)
    try:
        handler = logging.handlers.SysLogHandler(address=address)
    except OSError:  # ConnectionError is a subclass of OSError
        return None
    # syslog convention: "ident[pid]: message"
    handler.setFormatter(
        logging.Formatter(f"{identifier}[%(process)d]: %(levelname)s %(message)s")
    )
    return handler


def _eventlog_handler(identifier: str, system: str) -> Optional[logging.Handler]:
    """Windows Event Log handler, or None off-Windows / without pywin32."""
    if system != "Windows":
        return None
    try:
        handler = logging.handlers.NTEventLogHandler(identifier)
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    # NTEventLogHandler doesn't raise when pywin32 is missing — it warns and
    # leaves ``_welu`` as None (a non-functional handler).  Reject that.
    if getattr(handler, "_welu", None) is None:
        return None
    return handler
