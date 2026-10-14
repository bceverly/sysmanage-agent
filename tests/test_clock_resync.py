# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Spot resynchronization (Phase 23.3 S5): the right step per time service,
privileges, server validation, and an honest result."""

from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection import time_service as ts
from src.sysmanage_agent.operations import clock_resync as cr


class Fake:
    """A runner that records argv and answers from a table of prefixes."""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    def __call__(self, argv):
        self.calls.append(argv)
        key = " ".join(argv)
        for prefix, answer in self.answers.items():
            if key.startswith(prefix):
                return answer
        return 0, ""


def _status(service, source="ntp.lab"):
    return {
        "service": service,
        "running": True,
        "synchronized": False,
        "source": source,
        "stratum": 2,
        "reported_offset_ms": 1330.0,
    }


def _resync(service, system="Linux", has=lambda _t: False, answers=None, params=None):
    run = Fake(answers)
    with patch.object(
        ts, "collect_time_status", return_value=_status(service)
    ), patch.object(cr, "_privileged", return_value=True):
        result = cr.resync(params or {"server": "time.lab"}, system, run, has)
    return result, run.calls


@pytest.mark.parametrize(
    "service, system, has, expected",
    [
        (ts.CHRONY, "Linux", set(), [["chronyc", "makestep"]]),
        (ts.TIMESYNCD, "Linux", set(), [["systemctl", "restart", "systemd-timesyncd"]]),
        (ts.NTPD, "FreeBSD", {"ntpdate"}, [["ntpdate", "-b", "-u", "time.lab"]]),
        (ts.NTPD, "FreeBSD", set(), [["service", "ntpd", "restart"]]),
        (ts.OPENNTPD, "OpenBSD", set(), [["rdate", "-ncv", "time.lab"]]),
        (ts.TIMED, "Darwin", set(), [["sntp", "-sS", "time.lab"]]),
        (ts.NONE, "NetBSD", {"ntpdate"}, [["ntpdate", "-b", "-u", "time.lab"]]),
        (ts.NONE, "Linux", {"sntp", "ntpdate"}, [["sntp", "-sS", "time.lab"]]),
    ],
)
def test_the_step_for_each_time_service(service, system, has, expected):
    result, calls = _resync(service, system, has=lambda t: t in has)
    assert result["success"] is True
    assert [
        c for c in calls if c not in (["systemctl", "is-active", "ntpd"],)
    ] == expected


def test_linux_ntpd_restarts_the_unit_the_distribution_uses():
    result, calls = _resync(
        ts.NTPD,
        answers={
            "systemctl is-active ntpd": (3, ""),
            "systemctl is-active ntp": (0, ""),
        },
    )
    assert result["success"] and calls[-1] == ["systemctl", "restart", "ntp"]


def test_a_stopped_windows_time_service_is_started_first():
    result, calls = _resync(
        ts.W32TIME, "Windows", answers={"net start": (2, "already started")}
    )
    assert result["success"] is True
    assert calls == [
        ["net", "start", "w32time"],
        ["w32tm", "/config", "/update"],
        ["w32tm", "/resync", "/force"],
    ]
    assert result["method"] == "w32tm /resync"


def test_a_failed_step_is_reported_with_its_output():
    result, _ = _resync(
        ts.CHRONY, answers={"chronyc makestep": (1, "501 Not authorised")}
    )
    assert result["success"] is False
    assert result["error"] == "command_failed"
    assert "Not authorised" in result["detail"]


def test_no_tool_says_so():
    result, calls = _resync(ts.NONE, "Linux")
    assert (result["error"], calls) == ("no_tool", [])


def test_an_unprivileged_agent_does_nothing():
    run = Fake()
    with patch.object(
        ts, "collect_time_status", return_value=_status(ts.CHRONY)
    ), patch.object(cr.os, "geteuid", return_value=1000, create=True):
        result = cr.resync({}, "Linux", run)
    assert result["error"] == "not_privileged"
    assert run.calls == []


@pytest.mark.parametrize(
    "param, source, expected",
    [
        ("time.lab", "ntp.lab", "time.lab"),
        ("bad; rm -rf /", "ntp.lab", "ntp.lab"),  # never onto a command line
        (None, "time.windows.com,0x9", "pool.ntp.org"),
        ("", None, "pool.ntp.org"),
    ],
)
def test_the_server_is_validated_with_fallbacks(param, source, expected):
    assert cr._server({"server": param}, {"source": source}, "Linux") == expected


def test_macos_falls_back_to_apples_server():
    assert cr._server({}, {}, "Darwin") == "time.apple.com"


def test_the_status_after_is_reported():
    run = Fake()
    after = _status(ts.CHRONY)
    after["synchronized"] = True
    with patch.object(
        ts, "collect_time_status", side_effect=[_status(ts.CHRONY), after]
    ), patch.object(cr, "_privileged", return_value=True):
        result = cr.resync({}, "Linux", run)
    assert result["status_after"]["synchronized"] is True
    assert result["status_before"]["synchronized"] is False


def test_a_stopped_chronyd_is_run_once_instead():
    run = Fake()
    stopped = _status(ts.CHRONY)
    stopped["running"] = False
    with patch.object(ts, "collect_time_status", return_value=stopped), patch.object(
        cr, "_privileged", return_value=True
    ):
        result = cr.resync({"server": "time.lab"}, "Linux", run, lambda _t: False)
    assert result["success"] is True
    assert run.calls == [["chronyd", "-q", "server time.lab iburst"]]
