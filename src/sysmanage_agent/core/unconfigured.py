# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Refuse to run against a server that was never configured.

The deb and rpm packages install the example config and start the service at
once, so a fresh agent used to retry ``sysmanage.example.com`` forever --
found while auditing the install docs, 2026-10-17.  At startup the agent now
checks for that and, instead of connecting:

* under systemd, exits with ``EX_CONFIG`` (78); the units carry
  ``RestartPreventExitStatus=78``, so ``systemctl status`` shows the reason
  once, as ``status=78/CONFIG``, with no restart loop;
* under any other supervisor (rc.d, launchd, a Windows service, a shell),
  waits quietly, re-reading the config file every minute, and starts as soon
  as a real server is set -- those supervisors would respawn an exiting
  process just as hard.
"""

import os
import sys
import time
from typing import Callable, Optional

from src.i18n import _
from src.sysmanage_agent.core.server_endpoint import ServerEndpoint

EX_CONFIG = 78
RECHECK_SECONDS = 60
# RFC 2606 / 6761 names that can never be a real server.
_RESERVED_SUFFIXES = (
    "example.com",
    "example.net",
    "example.org",
    ".example",
    ".invalid",
)


def unconfigured_reason(config) -> Optional[str]:
    """Why ``config`` names no real server, or None if it does."""
    server = config.get_server_config() or {}
    if not (server.get("url") or "").strip() and not server.get("hostname"):
        return _("no server is configured (server.url is not set)")
    host = (ServerEndpoint(config).host or "").lower().rstrip(".")
    if _is_reserved(host):
        return _("server.url still points at the example host %s") % host
    return None


def _is_reserved(host: str) -> bool:
    """``host`` is, or is under, a name reserved for documentation."""
    for suffix in _RESERVED_SUFFIXES:
        name = suffix.lstrip(".")
        if host == name or host.endswith("." + name):
            return True
    return False


def _hint(config_file: str) -> str:
    return (
        _(
            "Edit %s: set server.url to your SysManage server and, for a "
            "multi-tenant server, security.enrollment_token; then restart the "
            "sysmanage-agent service."
        )
        % config_file
    )


def ensure_configured(
    config,
    logger,
    under_systemd: Optional[bool] = None,
    sleep: Callable[[float], None] = time.sleep,
    restart: Optional[Callable[[], None]] = None,
) -> None:
    """Return if ``config`` names a real server; otherwise exit or wait.

    Under systemd: log the reason and exit ``EX_CONFIG``.  Elsewhere: log it,
    re-read the file every ``RECHECK_SECONDS``, and once a real server is set
    restart the process (``restart``, default re-exec) so every component is
    built from the new configuration.
    """
    reason = unconfigured_reason(config)
    if reason is None:
        return
    if under_systemd is None:
        under_systemd = bool(os.environ.get("INVOCATION_ID"))
    message = _("SysManage agent not started: %s. %s") % (
        reason,
        _hint(config.config_file),
    )
    logger.error("%s", message)
    print(message, file=sys.stderr)
    if under_systemd:
        sys.exit(EX_CONFIG)
    from src.sysmanage_agent.core.config import ConfigManager  # noqa: PLC0415

    while True:
        sleep(RECHECK_SECONDS)
        try:
            fresh = ConfigManager(config.config_file)
        except Exception:  # pylint: disable=broad-except
            continue  # mid-edit or unreadable: try again next minute
        if unconfigured_reason(fresh) is None:
            if restart is None and os.name == "nt":
                # Re-exec under the Windows service manager would orphan the
                # service; let the operator restart it, which they must do
                # anyway after editing the config.
                logger.info(
                    _(
                        "Configuration found; restart the SysManage Agent service to apply it"
                    )
                )
                while True:
                    sleep(RECHECK_SECONDS * 60)
            logger.info(_("Configuration found; restarting the agent"))
            (restart or _reexec)()
            return


def _reexec() -> None:
    os.execv(sys.executable, [sys.executable] + sys.argv)  # nosec B606
