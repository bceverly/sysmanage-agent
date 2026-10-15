# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
What the host's own time service says about itself (Phase 23.3 S1).

Which service runs (chrony, ntpd, systemd-timesyncd, OpenNTPD, Windows Time,
macOS timed), whether it is running and synchronized, its source and stratum,
and its own estimate of the clock offset.  This is the host's CLAIM: the
server measures the offset independently from timestamped heartbeats
(``communication/clock_probe.py``), so a time service that is broken -- or
lying -- is still caught.

"Not measured" is never "in sync": every field the host could not read is
``None``, and a host with no time service reports ``service: "none"``.  The
S0 spike found a Windows laptop 1.33 s off because Windows Time was simply
not running; that is ``running: False``, not a missing report.

Offsets are reported as LOCAL minus TRUE time, in milliseconds: positive means
the host's clock is ahead.  That is the sign the server's own measurement
uses, so the two can be compared directly.  Each tool reports its own sign;
the parsers convert.  Parsers are pure functions of the command output, tested
against real recordings in ``tests/fixtures/time_service/``.
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess  # nosec B404
from typing import Callable, Dict, Optional, Tuple

from src.sysmanage_agent.collection.hardware_identity import _tool
from src.sysmanage_agent.collection.time_service_config import (
    _read as _read_file,
    collect_time_config,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 15

# service names, as the server stores them
CHRONY = "chrony"
NTPD = "ntpd"
TIMESYNCD = "timesyncd"
OPENNTPD = "openntpd"
W32TIME = "w32time"
TIMED = "timed"  # macOS
NONE = "none"

# Windows: "The service has not been started. (0x80070426)"
_W32_NOT_STARTED = "0x80070426"
# w32tm sources that mean "not synchronized to anything"
_W32_FREE_RUNNING = ("local cmos clock", "free-running system clock", "vm ic time")

Runner = Callable[[list], Tuple[int, str]]


def _run(argv) -> Tuple[int, str]:
    """``(returncode, stdout + stderr)``; -1 when the tool is not there.

    Both streams together: the interesting part of a failure ("service has
    not been started", "connect: No such file") is usually on stderr."""
    try:
        result = subprocess.run(  # nosec B603
            [_tool(argv[0]), *argv[1:]],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
            creationflags=(
                subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            ),
        )
    except FileNotFoundError:
        return -1, ""
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("time service: %s failed: %s", argv[0], exc)
        return -2, str(exc)
    return result.returncode, f"{result.stdout}\n{result.stderr}".strip()


def _status(service, running, synchronized, source=None, stratum=None, offset=None):
    return {
        "service": service,
        "running": running,
        "synchronized": synchronized,
        "source": source,
        "stratum": stratum,
        "reported_offset_ms": offset,
    }


def _number(pattern: str, text: str) -> Optional[float]:
    match = re.search(pattern, text, re.MULTILINE)
    return float(match.group(1)) if match else None


# --------------------------------------------------------------------------
# parsers: command output -> status (pure; tested on recordings)
# --------------------------------------------------------------------------


def parse_chrony_tracking(text: str) -> Dict[str, object]:
    """``chronyc -n tracking``."""
    stratum = _number(r"^Stratum\s*:\s*(\d+)", text)
    source = re.search(r"^Reference ID\s*:\s*\S+\s*\(([^)]*)\)", text, re.MULTILINE)
    fast = re.search(
        r"^System time\s*:\s*([\d.]+) seconds (fast|slow)", text, re.MULTILINE
    )
    offset = None
    if fast:
        offset = float(fast.group(1)) * 1000 * (1 if fast.group(2) == "fast" else -1)
    leap = re.search(r"^Leap status\s*:\s*(.+)$", text, re.MULTILINE)
    synced = bool(leap) and "not synchronised" not in leap.group(1).lower()
    # Stratum 0 / reference 0.0.0.0 is chrony not yet locked to anything.
    if stratum == 0:
        synced = False
    return _status(
        CHRONY,
        True,
        synced,
        source.group(1) if source and source.group(1) else None,
        int(stratum) if stratum is not None else None,
        round(offset, 3) if offset is not None else None,
    )


def parse_ntpq_rv(text: str) -> Dict[str, object]:
    """``ntpq -n -c rv`` (classic ntpd: FreeBSD, NetBSD, older Linux).

    ntpq's ``offset`` is the time SOURCE relative to this host, so the host's
    clock offset is its negation."""
    stratum = _number(r"\bstratum=(\d+)", text)
    offset = _number(r"\boffset=([-+]?[\d.]+)", text)
    refid = re.search(r"\brefid=([^,\s]+)", text)
    synced = "sync_ntp" in text or "sync_pps" in text or "sync_lf_radio" in text
    if stratum is not None and stratum >= 16:
        synced = False
    return _status(
        NTPD,
        True,
        synced,
        refid.group(1) if refid else None,
        int(stratum) if stratum is not None else None,
        round(-offset, 3) if offset is not None else None,
    )


def _key_values(text: str) -> Dict[str, str]:
    """``KEY=value`` lines as a dict."""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def parse_timedatectl(show: str, timesync: str = "") -> Dict[str, object]:
    """``timedatectl show`` (+ ``show-timesync --all`` for the source).

    systemd-timesyncd does not publish an offset estimate; that stays None."""
    values = _key_values(show)
    sync = _key_values(timesync)
    running = values.get("NTP") == "yes"
    stratum = _number(r"Stratum=(\d+)", sync.get("NTPMessage", ""))
    return _status(
        TIMESYNCD,
        running,
        values.get("NTPSynchronized") == "yes",
        sync.get("ServerName") or None,
        int(stratum) if stratum is not None else None,
        None,
    )


def parse_ntpctl(status: str, peers: str = "") -> Dict[str, object]:
    """``ntpctl -s status`` (+ ``-s peers`` for the selected source), OpenNTPD.

    The selected peer is the row marked ``*``; its offset is the peer relative
    to this host, so the host's offset is its negation."""
    synced = "clock synced" in status
    stratum = _number(r"stratum (\d+)", status)
    source = offset = None
    lines = peers.splitlines()
    for index, line in enumerate(lines):
        if line.lstrip().startswith("*") and index > 0:
            source = lines[index - 1].split()[0]
            fields = line.split()
            # " *  1 10  2  687s 1566s  0.480ms  131.419ms  3.062ms"
            ms = [f for f in fields if f.endswith("ms")]
            if ms:
                offset = -float(ms[0][:-2])
            break
    return _status(
        OPENNTPD,
        True,
        synced,
        source,
        int(stratum) if stratum is not None else None,
        round(offset, 3) if offset is not None else None,
    )


def parse_w32tm_status(text: str) -> Dict[str, object]:
    """``w32tm /query /status``.  No offset estimate is published."""
    if _W32_NOT_STARTED in text:
        return _status(W32TIME, False, False)
    source = re.search(r"^Source:\s*(.+?)\s*$", text, re.MULTILINE)
    stratum = _number(r"^Stratum:\s*(\d+)", text)
    src = source.group(1) if source else None
    synced = bool(src) and src.lower() not in _W32_FREE_RUNNING
    if stratum is not None and stratum in (0, 16):
        synced = False
    # "time.windows.com,0x9" -> the host name the operator configured
    if src and "," in src:
        src = src.split(",", 1)[0]
    return _status(
        W32TIME,
        True,
        synced,
        src,
        int(stratum) if stratum is not None else None,
        None,
    )


def parse_sntp(text: str) -> Optional[float]:
    """``sntp <server>``: the server's time relative to this host, so the
    host's offset is its negation.  macOS prints the bare line; FreeBSD's
    sntp prefixes a timestamp."""
    match = re.search(r"([-+]\d+\.\d+)\s+\+/-\s+[\d.]+\s+\S+", text)
    return round(-float(match.group(1)) * 1000, 3) if match else None


# --------------------------------------------------------------------------
# collection per OS
# --------------------------------------------------------------------------


def _ntp_family(run: Runner) -> Optional[Dict[str, object]]:
    """chrony, then classic ntpd -- whichever answers.  A client that is
    installed but finds no daemon means that service is STOPPED, not absent:
    reporting the next service down the list instead would aim a resync (or
    a policy) at a service the host does not use."""
    rc, out = run(["chronyc", "-n", "tracking"])
    if rc == 0 and out:
        return parse_chrony_tracking(out)
    chrony_stopped = rc not in (0, -1) and "Cannot talk to daemon" in (out or "")
    rc, out = run(["ntpq", "-n", "-c", "rv"])
    if rc == 0 and "stratum=" in out:
        return parse_ntpq_rv(out)
    if chrony_stopped:
        return _status(CHRONY, False, False)
    if rc not in (-1,) and "Connection refused" in (out or ""):
        return _status(NTPD, False, False)
    return None


def _linux(run: Runner) -> Dict[str, object]:
    found = _ntp_family(run)
    if found:
        return found
    rc, show = run(["timedatectl", "show"])
    if rc == 0 and "NTP=" in show:
        _, timesync = run(["timedatectl", "show-timesync", "--all"])
        return parse_timedatectl(show, timesync)
    return _status(NONE, False, False)


def _bsd(run: Runner) -> Dict[str, object]:
    found = _ntp_family(run)
    return found or _status(NONE, False, False)


def _openbsd(run: Runner) -> Dict[str, object]:
    rc, status = run(["ntpctl", "-s", "status"])
    if rc != 0:
        # "ntpctl: connect: /var/run/ntpd.sock: No such file" -- ntpd is off.
        return _status(OPENNTPD, False, False) if rc != -1 else _bsd(run)
    _, peers = run(["ntpctl", "-s", "peers"])
    return parse_ntpctl(status, peers)


def _windows(run: Runner) -> Dict[str, object]:
    rc, out = run(["w32tm", "/query", "/status"])
    if rc == -1:
        return _status(NONE, False, False)
    return parse_w32tm_status(out)


def _macos(run: Runner) -> Dict[str, object]:
    """``systemsetup`` needs root; unprivileged, the service state is unknown
    and only ``sntp``'s offset estimate is available."""
    rc, out = run(["systemsetup", "-getusingnetworktime"])
    running = None
    if rc == 0 and "Network Time:" in out:
        running = "Network Time: On" in out
    server = None
    rc, conf = run(["systemsetup", "-getnetworktimeserver"])
    if rc == 0 and ":" in conf:
        server = conf.split(":", 1)[1].strip() or None
    _, sntp = run(["sntp", "-t", "3", server or "time.apple.com"])
    offset = parse_sntp(sntp)
    synced = None if running is None else bool(running and offset is not None)
    return _status(TIMED, running, synced, server, None, offset)


def collect_time_status(
    system: Optional[str] = None, run: Runner = _run, read=None
) -> Dict[str, object]:
    """The host's time service, as it reports itself.  Never raises."""
    system = system or platform.system()
    readers = {
        "Linux": _linux,
        "FreeBSD": _bsd,
        "NetBSD": _bsd,
        "DragonFly": _bsd,
        "OpenBSD": _openbsd,
        "Windows": _windows,
        "Darwin": _macos,
    }
    reader = readers.get(system)
    if reader is None:
        return _status(None, None, None)
    try:
        status = reader(run)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("time service: could not read status: %s", exc)
        return _status(None, None, None)
    # S5b: how it is configured -- servers, enabled at boot, unit, file.
    status.update(
        collect_time_config(system, status.get("service"), run, read or _read_file)
    )
    return status
