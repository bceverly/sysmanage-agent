# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Service control on FreeBSD, OpenBSD and NetBSD.

Before 2026-09-30 the agent's service control knew systemd, OpenRC, launchd
and Windows only, so every ``enable``/``start`` a deployment plan sent to a
BSD host failed with "no service manager" -- ClamAV installed, its updater
never ran.  Each BSD does it differently:

* FreeBSD: ``sysrc <svc>_enable=YES`` to enable, ``service <svc> <action>``.
* OpenBSD: ``rcctl <action> <svc>`` covers all five actions.
* NetBSD: ``<svc>=YES`` in /etc/rc.conf (no sysrc in base), and a pkgsrc
  package's rc.d script is only an EXAMPLE under
  /usr/pkg/share/examples/rc.d until it is copied to /etc/rc.d.
"""

import os
import platform
import posixpath
import re
import shutil
from typing import List, Optional, Tuple

BSD_SYSTEMS = ("FreeBSD", "OpenBSD", "NetBSD")
RC_CONF = "/etc/rc.conf"
NETBSD_RC_D = "/etc/rc.d"
NETBSD_PKG_RC_EXAMPLES = "/usr/pkg/share/examples/rc.d"

# A service name becomes an rc.conf variable and a path under /etc/rc.d, so
# it is held to what rc.d names actually look like.
_SERVICE_NAME = re.compile(r"^\w[\w.-]{0,63}$", re.ASCII)


def bsd_system() -> Optional[str]:
    """``FreeBSD``/``OpenBSD``/``NetBSD`` on a BSD host, else None."""
    system = platform.system()
    return system if system in BSD_SYSTEMS else None


def valid_service(service: str) -> bool:
    return bool(_SERVICE_NAME.match(service or "")) and ".." not in service


def _tool(name: str) -> str:
    """Absolute path: a non-login NetBSD PATH omits /usr/sbin."""
    found = shutil.which(name)
    if found:
        return found
    for directory in ("/usr/sbin", "/sbin", "/usr/bin"):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return name


def build_command(system: str, action: str, service: str) -> Optional[List[str]]:
    """argv for ``action`` on ``service``; None when the action is done in
    process instead (NetBSD enable/disable edits /etc/rc.conf)."""
    if system == "OpenBSD":
        return [_tool("rcctl"), action, service]
    if system == "FreeBSD":
        if action in ("enable", "disable"):
            value = "YES" if action == "enable" else "NO"
            return [_tool("sysrc"), f"{service}_enable={value}"]
        return [_tool("service"), service, action]
    if action in ("enable", "disable"):
        return None
    # BSD paths are POSIX paths whatever the platform this code is built on.
    return [posixpath.join(NETBSD_RC_D, service), action]


# rc.subr's own words (FreeBSD and NetBSD) when the service is already where
# the action would put it -- "clamd already running? (pid=123)." / "clamd not
# running? (check /var/run/clamd.pid)." -- and it exits non-zero.  A plan that
# is re-sent to a host that already runs everything must not fail on that.
_ALREADY = {"start": "already running", "stop": "not running"}


def already_in_state(action: str, output: str) -> bool:
    """Whether a failed ``action`` failed only because it was already done."""
    marker = _ALREADY.get(action)
    return bool(marker) and marker in (output or "")


def _install_netbsd_rc_script(
    service: str, rc_d: str, examples: str
) -> Tuple[bool, str]:
    target = os.path.join(rc_d, service)
    if os.path.isfile(target):
        return True, ""
    example = os.path.join(examples, service)
    if not os.path.isfile(example):
        return False, f"no rc.d script for {service} in {rc_d} or {examples}"
    shutil.copyfile(example, target)
    # Root runs rc.d scripts; nobody else needs to read or run this one.
    # 0o700 is owner-only -- the restrictive end of what the rule looks for.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(target, 0o700)
    return True, ""


def _set_rc_conf_var(name: str, value: str, rc_conf: str) -> None:
    """Set ``name=value`` in rc.conf, replacing any existing assignment."""
    try:
        with open(rc_conf, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []
    pattern = re.compile(rf"^\s*{re.escape(name)}=")
    kept = [line for line in lines if not pattern.match(line)]
    kept.append(f"{name}={value}")
    with open(rc_conf, "w", encoding="utf-8") as handle:
        handle.write("\n".join(kept) + "\n")


def netbsd_set_enabled(
    service: str,
    enabled: bool,
    rc_conf: str = RC_CONF,
    rc_d: str = NETBSD_RC_D,
    examples: str = NETBSD_PKG_RC_EXAMPLES,
) -> Tuple[bool, str]:
    """Enable or disable a NetBSD service; ``(ok, error)``."""
    try:
        if enabled:
            ok, error = _install_netbsd_rc_script(service, rc_d, examples)
            if not ok:
                return False, error
        _set_rc_conf_var(service, "YES" if enabled else "NO", rc_conf)
        return True, ""
    except OSError as error:
        return False, str(error)
