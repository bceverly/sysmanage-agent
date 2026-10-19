# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
How the host's time service is CONFIGURED (Phase 23.3 S5b).

Beside what the service says about itself (``time_service.py``): which NTP
servers it is configured to use, whether it is enabled at boot, the real unit
name and the config file in use.  The server compares this with the fleet NTP
policy, and builds that policy's plan against the unit and path the host
really has -- ``chrony`` on Debian is ``chronyd`` on RHEL, and the file is
``/etc/chrony/chrony.conf`` on one and ``/etc/chrony.conf`` on the other --
instead of guessing them from a distribution table.

Every value the host could not read is ``None`` ("not reported", never "not
configured").  Parsers are pure functions of the text.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

Runner = Callable[[list], Tuple[int, str]]
Reader = Callable[[str], Optional[str]]

CHRONY_PATHS = ("/etc/chrony/chrony.conf", "/etc/chrony.conf")
NTPD_PATHS = ("/etc/ntpsec/ntp.conf", "/etc/ntp.conf")
OPENNTPD_PATH = "/etc/ntpd.conf"
RC_CONF = "/etc/rc.conf"

_SERVER_LINE = re.compile(r"^\s*(?:server|servers|pool|peer)\s+(\S+)", re.M)


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def parse_server_lines(text: str) -> List[str]:
    """``server``/``pool``/``servers`` entries of a chrony / ntpd / OpenNTPD
    configuration, in order, without duplicates."""
    seen: List[str] = []
    for name in _SERVER_LINE.findall(text or ""):
        if name not in seen:
            seen.append(name)
    return seen


def parse_w32tm_configuration(text: str) -> List[str]:
    """``NtpServer: a,0x8 b,0x9 (Local)`` -> ``["a", "b"]``."""
    # (\S.*), not (.+): \s* and .+ overlapped (Sonar S5852).
    match = re.search(r"^\s*NtpServer:\s*(\S.*)$", text or "", re.M)
    if not match:
        return []
    value = match.group(1).rstrip()
    for marker in ("(Local)", "(Policy)"):  # w32tm's trailing source tag
        if value.endswith(marker):
            value = value[: -len(marker)]
            break
    value = value.strip()
    return [entry.split(",")[0] for entry in value.split() if entry.split(",")[0]]


def parse_sc_qc_start(text: str) -> Optional[bool]:
    """``sc qc w32time``: AUTO_START (or a trigger start) -> enabled."""
    match = re.search(r"START_TYPE\s*:\s*\d+\s+(\w+)", text or "")
    if not match:
        return None
    return match.group(1).upper() in ("AUTO_START", "DEMAND_START")


def parse_timesync_servers(text: str) -> List[str]:
    """``timedatectl show-timesync --all``: the servers in use."""
    servers: List[str] = []
    for key in ("SystemNTPServers", "LinkNTPServers", "FallbackNTPServers"):
        match = re.search(rf"^{key}=(.*)$", text or "", re.M)
        if match and match.group(1).strip():
            servers = match.group(1).split()
            break
    return servers


def _first_existing(paths, read: Reader) -> Tuple[Optional[str], Optional[str]]:
    for path in paths:
        text = read(path)
        if text is not None:
            return path, text
    return None, None


def _systemd_enabled(run: Runner, units) -> Tuple[Optional[str], Optional[bool]]:
    """The first unit systemd knows, and whether it is enabled at boot."""
    for unit in units:
        rc, out = run(["systemctl", "is-enabled", unit])
        state = (out or "").strip().splitlines()[-1:] or [""]
        if rc == -1:
            return None, None  # no systemd
        if state[0] in ("enabled", "enabled-runtime", "static", "alias"):
            return unit, True
        if state[0] in ("disabled", "masked", "indirect"):
            return unit, False
    return None, None


def _rc_conf_enabled(read: Reader, name: str) -> Optional[bool]:
    text = read(RC_CONF)
    if text is None:
        return None
    # the LAST assignment wins, as in rc.subr
    matches = list(re.finditer(rf'^\s*{name}=["\']?(\w+)', text, re.M))
    return bool(matches) and matches[-1].group(1).upper() == "YES"


def _chrony(system, run, read) -> Dict[str, object]:
    path, text = _first_existing(CHRONY_PATHS, read)
    unit, enabled = _systemd_enabled(run, ("chronyd", "chrony"))
    return _config(unit or "chronyd", path, text, enabled)


def _ntpd(system, run, read) -> Dict[str, object]:
    path, text = _first_existing(NTPD_PATHS, read)
    if system == "Linux":
        unit, enabled = _systemd_enabled(run, ("ntpsec", "ntp", "ntpd"))
        return _config(unit or "ntpd", path, text, enabled)
    if system == "FreeBSD":
        rc, out = run(["sysrc", "-n", "ntpd_enable"])
        enabled = None if rc != 0 else out.strip().upper() == "YES"
        return _config("ntpd", path, text, enabled)
    return _config("ntpd", path, text, _rc_conf_enabled(read, "ntpd"))


def _timesyncd(_system, run, _read) -> Dict[str, object]:
    unit, enabled = _systemd_enabled(run, ("systemd-timesyncd",))
    rc, out = run(["timedatectl", "show-timesync", "--all"])
    servers = parse_timesync_servers(out) if rc == 0 else None
    return {
        "unit": unit or "systemd-timesyncd",
        "config_path": "/etc/systemd/timesyncd.conf.d",
        "configured_servers": servers,
        "enabled": enabled,
    }


def _openntpd(_system, run, read) -> Dict[str, object]:
    text = read(OPENNTPD_PATH)
    rc, out = run(["rcctl", "ls", "on"])
    enabled = None if rc != 0 else "ntpd" in out.split()
    return _config("ntpd", OPENNTPD_PATH if text is not None else None, text, enabled)


def _w32time(_system, run, _read) -> Dict[str, object]:
    rc, out = run(["w32tm", "/query", "/configuration"])
    servers = parse_w32tm_configuration(out) if rc == 0 else None
    rc, qc = run(["sc", "qc", "w32time"])
    return {
        "unit": "w32time",
        "config_path": None,
        "configured_servers": servers,
        "enabled": parse_sc_qc_start(qc) if rc == 0 else None,
    }


def _timed(_system, run, _read) -> Dict[str, object]:
    rc, out = run(["systemsetup", "-getnetworktimeserver"])
    servers = None
    if rc == 0 and ":" in out:
        servers = [s for s in [out.split(":", 1)[1].strip()] if s]
    rc, on = run(["systemsetup", "-getusingnetworktime"])
    enabled = ("Network Time: On" in on) if rc == 0 and "Network Time" in on else None
    return {
        "unit": "timed",
        "config_path": None,
        "configured_servers": servers,
        "enabled": enabled,
    }


def _config(unit, path, text, enabled) -> Dict[str, object]:
    return {
        "unit": unit,
        "config_path": path,
        "configured_servers": parse_server_lines(text) if text is not None else None,
        "enabled": enabled,
    }


_READERS = {
    "chrony": _chrony,
    "ntpd": _ntpd,
    "timesyncd": _timesyncd,
    "openntpd": _openntpd,
    "w32time": _w32time,
    "timed": _timed,
}


def collect_time_config(
    system: str, service: Optional[str], run: Runner, read: Reader = _read
) -> Dict[str, object]:
    """The configuration of ``service`` on this host.  Never raises."""
    empty = {
        "unit": None,
        "config_path": None,
        "configured_servers": None,
        "enabled": None,
    }
    reader = _READERS.get(service or "")
    if reader is None:
        return empty
    try:
        return reader(system, run, read)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("time service: could not read configuration: %s", exc)
        return empty
