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
from typing import Optional

# BSD variants whose syslog socket is /dev/log (like Linux).
_BSD_SYSTEMS = {"FreeBSD", "OpenBSD", "NetBSD", "DragonFly"}


def build_native_handler(
    target: str = "auto",
    identifier: str = "sysmanage-agent",
    system: Optional[str] = None,
) -> Optional[logging.Handler]:
    """Build a platform-native log handler.

    ``target``: ``auto`` | ``journald`` | ``syslog`` | ``eventlog`` | ``none``.
    ``auto`` picks journald on Linux (falling back to syslog), the Windows Event
    Log on Windows, and syslog on macOS/BSD.  Returns ``None`` if the sink can't
    be created (e.g. missing ``systemd``/``pywin32``, no syslog socket).
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
    if target == "eventlog":
        return _eventlog_handler(identifier, system)
    return None


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
    except (OSError, ConnectionError):
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
