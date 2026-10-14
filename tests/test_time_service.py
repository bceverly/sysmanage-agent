# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The host's own time service, read per OS (Phase 23.3 S1).

Every fixture is a REAL recording from the S0 spike (2026-10-12) except the
running-Windows-Time one, which is marked synthetic: the lab's only Windows
box had Windows Time stopped -- itself the case worth testing.
"""

import re
from pathlib import Path

import pytest

from src.sysmanage_agent.collection import time_service as ts

FIXTURES = Path(__file__).parent / "fixtures" / "time_service"
_HEADER = re.compile(r"^\$ (.+?)\s+\(rc=(-?\d+)\)\s*$")


def _recording(name):
    """``{command: (rc, output)}`` from a ``services``-mode recording."""
    out, command, rc, lines = {}, None, 0, []
    for line in (FIXTURES / f"{name}.txt").read_text().splitlines():
        match = _HEADER.match(line)
        if match:
            if command:
                out[command] = (rc, "\n".join(lines).strip())
            command, rc, lines = match.group(1), int(match.group(2)), []
        elif command:
            lines.append(line)
    if command:
        out[command] = (rc, "\n".join(lines).strip())
    return out


def _runner(name, extra=None):
    """A runner that answers from a recording; anything unrecorded is absent."""
    table = {**_recording(name), **(extra or {})}

    def run(argv):
        key = " ".join(argv)
        if key in table:
            return table[key]
        # sntp is recorded against a different server than the reader asks.
        if argv[0] == "sntp":
            for command, result in table.items():
                if command.split()[0] == "sntp":
                    return result
        return (-1, "")

    return run


CLAIM = (
    "service",
    "running",
    "synchronized",
    "source",
    "stratum",
    "reported_offset_ms",
)


def _status(system, name, extra=None):
    # No config files: the test must not read the machine it runs on.
    return ts.collect_time_status(system, _runner(name, extra), read=lambda _p: None)


def _claim(status):
    return {key: status[key] for key in CLAIM}


def test_linux_chrony():
    status = _status("Linux", "linux_chrony")
    assert status["service"] == "chrony"
    assert status["synchronized"] is True
    assert status["stratum"] == 3
    assert status["source"] == "91.189.91.113"
    # "0.000204694 seconds fast of NTP time" -> host AHEAD by 0.2 ms
    assert status["reported_offset_ms"] == pytest.approx(0.205, abs=0.001)


def test_linux_timesyncd_when_no_ntp_daemon_answers():
    status = _status("Linux", "linux_timesyncd")
    assert status["unit"] == "systemd-timesyncd"
    assert status["configured_servers"] == ["ntp.ubuntu.com"]
    assert _claim(status) == {
        "service": "timesyncd",
        "running": True,
        "synchronized": True,
        "source": "ntp.ubuntu.com",
        "stratum": 2,
        "reported_offset_ms": None,  # timesyncd publishes no estimate
    }


def test_freebsd_classic_ntpd():
    status = _status("FreeBSD", "freebsd_ntpd")
    assert status["service"] == "ntpd"
    assert status["synchronized"] is True
    assert status["stratum"] == 2
    assert status["source"] == "45.83.233.200"
    # ntpq offset=+1.088953: the SOURCE is ahead, so the host is behind.
    assert status["reported_offset_ms"] == pytest.approx(-1.089, abs=0.001)


def test_openbsd_openntpd():
    status = _status("OpenBSD", "openbsd_openntpd")
    assert status["service"] == "openntpd"
    assert status["synchronized"] is True
    assert status["stratum"] == 3
    assert status["source"] == "46.22.24.205"  # the "*" peer
    assert status["reported_offset_ms"] == pytest.approx(-0.48)


def test_openbsd_with_ntpd_stopped():
    stopped = {
        "ntpctl -s status": (
            1,
            "ntpctl: connect: /var/run/ntpd.sock: No such file or directory",
        )
    }
    status = _status("OpenBSD", "openbsd_openntpd", stopped)
    assert (status["service"], status["running"], status["synchronized"]) == (
        "openntpd",
        False,
        False,
    )


def test_windows_time_not_started_is_reported_not_missing():
    """The S0 finding: an x13s 1.33 s off because w32time was not running."""
    status = _status("Windows", "windows_w32time_stopped")
    assert status["unit"] == "w32time"
    assert _claim(status) == {
        "service": "w32time",
        "running": False,
        "synchronized": False,
        "source": None,
        "stratum": None,
        "reported_offset_ms": None,
    }


# SYNTHETIC: the shape of `w32tm /query /status` on a synchronized host.
W32TM_SYNCED = """Leap Indicator: 0(no warning)
Stratum: 4 (secondary reference - syncd by (S)NTP)
Precision: -23 (119.209ns per tick)
Root Delay: 0.0312500s
Root Dispersion: 7.7759234s
ReferenceId: 0x14650B39 (source IP:  20.101.57.9)
Last Successful Sync Time: 10/12/2026 8:00:00 AM
Source: time.windows.com,0x9
Poll Interval: 10 (1024s)"""


def test_windows_time_synchronized():
    status = ts.parse_w32tm_status(W32TM_SYNCED)
    assert (status["running"], status["synchronized"]) == (True, True)
    assert (status["source"], status["stratum"]) == ("time.windows.com", 4)


def test_windows_time_free_running_is_not_synchronized():
    free = W32TM_SYNCED.replace("time.windows.com,0x9", "Local CMOS Clock")
    assert ts.parse_w32tm_status(free)["synchronized"] is False


def test_macos_unprivileged_reports_only_an_offset():
    """systemsetup needs root; sntp still gives the offset estimate."""
    status = _status("Darwin", "macos_unprivileged")
    assert status["service"] == "timed"
    assert status["running"] is None  # unknown is not "on"
    assert status["synchronized"] is None
    # "+0.210165 +/- ..." -> the server is ahead -> the host is 210 ms BEHIND
    assert status["reported_offset_ms"] == pytest.approx(-210.165)


def test_macos_as_root():
    root = {
        "systemsetup -getusingnetworktime": (0, "Network Time: On"),
        "systemsetup -getnetworktimeserver": (0, "Network Time Server: time.apple.com"),
    }
    status = _status("Darwin", "macos_unprivileged", root)
    assert (status["running"], status["synchronized"], status["source"]) == (
        True,
        True,
        "time.apple.com",
    )


def test_freebsd_sntp_line_with_timestamp_prefix():
    line = "2026-10-12 08:02:53.568494 (+0400) +0.000694 +/- 0.008545 time.cloudflare.com 162.159.200.123 s3 no-leap"
    assert ts.parse_sntp(line) == pytest.approx(-0.694)


def test_chrony_not_yet_locked_is_not_synchronized():
    text = (
        "Reference ID    : 00000000 ()\nStratum         : 0\n"
        "System time     : 0.000000000 seconds slow of NTP time\n"
        "Leap status     : Not synchronised\n"
    )
    status = ts.parse_chrony_tracking(text)
    assert (status["synchronized"], status["source"]) == (False, None)


def test_no_time_service_at_all_says_so():
    status = ts.collect_time_status("Linux", lambda argv: (-1, ""))
    assert status["service"] == "none"
    assert status["synchronized"] is False


def test_an_unknown_platform_reports_nothing_rather_than_guessing():
    assert ts.collect_time_status("Plan9", lambda argv: (0, ""))["service"] is None


def test_a_reader_that_raises_never_takes_the_agent_down():
    def boom(argv):
        raise RuntimeError("unexpected")

    assert ts.collect_time_status("Linux", boom)["service"] is None


def test_a_stopped_daemon_is_stopped_not_absent():
    def chrony_down(argv):
        if argv[0] == "chronyc":
            return 1, "506 Cannot talk to daemon"
        return -1, ""

    status = ts.collect_time_status("Linux", chrony_down, read=lambda _p: None)
    assert (status["service"], status["running"]) == ("chrony", False)

    def ntpd_down(argv):
        if argv[0] == "ntpq":
            return 1, "ntpq: read: Connection refused"
        return -1, ""

    status = ts.collect_time_status("FreeBSD", ntpd_down, read=lambda _p: None)
    assert (status["service"], status["running"]) == ("ntpd", False)
