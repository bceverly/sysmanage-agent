# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Spot resynchronization of the host's clock (Phase 23.3 S5).

The server asks; this steps the clock NOW through whichever time service the
host runs, then reports the service's state afterwards:

* chrony ............ ``chronyc makestep``; with chronyd stopped,
                      ``chronyd -q`` (sets the clock once and exits)
* systemd-timesyncd . restart the service (it steps on start)
* ntpd .............. ``ntpdate -b -u <server>`` where it exists (FreeBSD and
                      NetBSD ship it), else restart ntpd (which steps a large
                      offset at start) -- always leaving ntpd running
* OpenNTPD .......... ``rdate -ncv <server>`` (OpenBSD base)
* Windows Time ...... start the service when it is stopped (the S0 laptop),
                      then ``w32tm /resync /force``
* macOS ............. ``sntp -sS <server>``
* no time service ... the first of sntp / ntpdate / rdate that exists

``server`` comes from the SysManage server: its own verified reference, so the
host is pulled to the clock it is judged against.  Without one, the host's own
configured source, then ``pool.ntp.org`` (``time.apple.com`` on macOS).

Root is required everywhere but Windows (where the service runs as SYSTEM):
an unprivileged agent says so (``not_privileged``) instead of failing halfway.
Every step is a fixed argv, no shell; the server name is validated first, as
it lands on a command line.
"""

from __future__ import annotations

import logging
import os
import platform
import re
from typing import Dict, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.collection import time_service as ts
from src.sysmanage_agent.collection.hardware_identity import _tool

logger = logging.getLogger(__name__)

# A hostname or an IPv4/IPv6 address -- nothing a command line could misread.
_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
DEFAULT_SERVER = "pool.ntp.org"
MACOS_DEFAULT_SERVER = "time.apple.com"

Step = Tuple[List[str], bool]  # argv, must succeed


def _privileged(system: str) -> bool:
    if system == "Windows":
        return True
    geteuid = getattr(os, "geteuid", None)
    return geteuid is None or geteuid() == 0


def _server(parameters: Dict, status: Dict, system: str) -> Optional[str]:
    candidates = (
        parameters.get("server"),
        status.get("source"),
        MACOS_DEFAULT_SERVER if system == "Darwin" else DEFAULT_SERVER,
    )
    for candidate in candidates:
        if isinstance(candidate, str) and _SERVER_RE.match(candidate.strip()):
            return candidate.strip()
    return None


def _ntpd_unit(run) -> str:
    """The ntpd unit name differs by distribution."""
    for unit in ("ntpd", "ntp", "ntpsec"):
        rc, _out = run(["systemctl", "is-active", unit])
        if rc == 0:
            return unit
    return "ntpd"


def _restart_ntpd(system: str, run) -> List[Step]:
    if system == "Linux":
        return [(["systemctl", "restart", _ntpd_unit(run)], True)]
    return [(["service", "ntpd", "restart"], True)]


def _has(tool: str) -> bool:
    """Installed?  A path lookup, never an execution."""
    return os.path.isabs(_tool(tool))


def _fallback(server: str, has) -> List[Step]:
    if has("sntp"):
        return [(["sntp", "-sS", server], True)]
    if has("ntpdate"):
        return [(["ntpdate", "-b", "-u", server], True)]
    if has("rdate"):
        return [(["rdate", "-ncv", server], True)]
    return []


def plan(  # pylint: disable=too-many-return-statements,too-many-arguments
    system: str,
    service: Optional[str],
    server: str,
    run,
    has=_has,
    running: Optional[bool] = None,
) -> List[Step]:
    """The steps for this host.  An empty plan means no tool can do it."""
    if service == ts.CHRONY:
        if running is False:
            # No daemon to ask: chronyd itself, once -- set the clock from
            # the server and exit (it does not stay running).
            return [(["chronyd", "-q", f"server {server} iburst"], True)]
        return [(["chronyc", "makestep"], True)]
    if service == ts.TIMESYNCD:
        return [(["systemctl", "restart", "systemd-timesyncd"], True)]
    if service == ts.NTPD:
        if has("ntpdate"):
            return [(["ntpdate", "-b", "-u", server], True)]
        return _restart_ntpd(system, run)
    if service == ts.OPENNTPD:
        return [(["rdate", "-ncv", server], True)]
    if service == ts.W32TIME:
        return [
            # Fails harmlessly when it is already running (2182).
            (["net", "start", "w32time"], False),
            # A just-started service has no time data until it re-reads its
            # configuration: "did not resync because no time data was
            # available" otherwise.
            (["w32tm", "/config", "/update"], False),
            (["w32tm", "/resync", "/force"], True),
        ]
    if system == "Darwin":
        return [(["sntp", "-sS", server], True)]
    return _fallback(server, has)


def resync(
    parameters: Optional[Dict] = None,
    system: Optional[str] = None,
    run=None,
    has=_has,
):
    """Step this host's clock.  Never raises; the result says what happened."""
    parameters = parameters if isinstance(parameters, dict) else {}
    system = system or platform.system()
    run = run or ts._run  # pylint: disable=protected-access
    before = ts.collect_time_status(system, run)
    result = {
        "success": False,
        "service": before.get("service"),
        "method": None,
        "error": None,
        "detail": None,
        "status_before": before,
        "status_after": None,
    }
    if not _privileged(system):
        result["error"] = "not_privileged"
        return result
    server = _server(parameters, before, system)
    if server is None:
        result["error"] = "bad_server"
        return result
    steps = plan(system, before.get("service"), server, run, has, before.get("running"))
    if not steps:
        result["error"] = "no_tool"
        return result
    result["method"] = " ".join(steps[-1][0][:2])
    _run_steps(steps, run, result)
    result["status_after"] = ts.collect_time_status(system, run)
    return result


def _run_steps(steps, run, result: Dict) -> None:
    """Run the plan in order; a REQUIRED step that fails ends it."""
    for argv, required in steps:
        rc, out = run(argv)
        if rc != 0 and required:
            result["error"] = "command_failed" if rc != -1 else "no_tool"
            result["detail"] = (out or "")[-500:]
            logger.warning(
                _("Clock resync: %s failed (%s): %s"), argv[0], rc, (out or "")[-200:]
            )
            return
    result["success"] = True
    logger.info(_("Clock resync: %s succeeded"), result["method"])
