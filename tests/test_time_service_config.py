# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""How the time service is configured (Phase 23.3 S5b)."""

from src.sysmanage_agent.collection import time_service_config as tc

CHRONY_DEBIAN = """# Welcome to the chrony configuration file.
pool ntp.ubuntu.com        iburst maxsources 4
pool 0.ubuntu.pool.ntp.org iburst maxsources 1
server 192.168.4.1 iburst
keyfile /etc/chrony/chrony.keys
"""
OPENNTPD = (
    'servers pool.ntp.org\nserver 192.168.4.1\nconstraints from "https://9.9.9.9"\n'
)
W32TM_CONFIG = """[TimeProviders]
NtpClient (Local)
DllName: C:\\WINDOWS\\system32\\w32time.dll (Local)
NtpServer: time.windows.com,0x9 ntp.lab,0x8 (Local)
Type: NTP (Local)
"""
SC_QC = """SERVICE_NAME: w32time
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
"""
SC_QC_DISABLED = "        START_TYPE         : 4   DISABLED\n"
TIMESYNC = "SystemNTPServers=time.lab other.lab\nFallbackNTPServers=ntp.ubuntu.com\n"


class Run:
    def __init__(self, answers):
        self.answers = answers

    def __call__(self, argv):
        return self.answers.get(" ".join(argv), (1, ""))


def files(mapping):
    return mapping.get


def test_server_lines_in_order_without_duplicates():
    assert tc.parse_server_lines(CHRONY_DEBIAN) == [
        "ntp.ubuntu.com",
        "0.ubuntu.pool.ntp.org",
        "192.168.4.1",
    ]
    assert tc.parse_server_lines(OPENNTPD) == ["pool.ntp.org", "192.168.4.1"]
    assert tc.parse_server_lines("") == []


def test_windows_configuration():
    assert tc.parse_w32tm_configuration(W32TM_CONFIG) == ["time.windows.com", "ntp.lab"]
    assert tc.parse_sc_qc_start(SC_QC) is True  # trigger-started counts
    assert tc.parse_sc_qc_start(SC_QC_DISABLED) is False
    assert tc.parse_sc_qc_start("") is None


def test_timesyncd_prefers_the_system_servers():
    assert tc.parse_timesync_servers(TIMESYNC) == ["time.lab", "other.lab"]
    assert tc.parse_timesync_servers("FallbackNTPServers=a b\n") == ["a", "b"]


def test_chrony_on_debian_finds_its_unit_and_file():
    run = Run(
        {
            "systemctl is-enabled chronyd": (
                1,
                "Failed to get unit file state for chronyd.service",
            ),
            "systemctl is-enabled chrony": (0, "enabled"),
        }
    )
    config = tc.collect_time_config(
        "Linux", "chrony", run, files({"/etc/chrony/chrony.conf": CHRONY_DEBIAN})
    )
    assert config["unit"] == "chrony"
    assert config["config_path"] == "/etc/chrony/chrony.conf"
    assert config["enabled"] is True
    assert config["configured_servers"][0] == "ntp.ubuntu.com"


def test_chrony_on_rhel():
    run = Run({"systemctl is-enabled chronyd": (1, "disabled")})
    config = tc.collect_time_config(
        "Linux", "chrony", run, files({"/etc/chrony.conf": "server a.lab iburst\n"})
    )
    assert (config["unit"], config["config_path"], config["enabled"]) == (
        "chronyd",
        "/etc/chrony.conf",
        False,
    )


def test_bsd_ntpd_enablement():
    freebsd = tc.collect_time_config(
        "FreeBSD",
        "ntpd",
        Run({"sysrc -n ntpd_enable": (0, "YES\n")}),
        files({"/etc/ntp.conf": "pool 0.freebsd.pool.ntp.org iburst\n"}),
    )
    assert (freebsd["enabled"], freebsd["configured_servers"]) == (
        True,
        ["0.freebsd.pool.ntp.org"],
    )
    netbsd = tc.collect_time_config(
        "NetBSD",
        "ntpd",
        Run({}),
        files({"/etc/ntp.conf": "", "/etc/rc.conf": "ntpd=YES\nntpd=NO\n"}),
    )
    assert netbsd["enabled"] is False  # the last assignment wins, as rc.conf does


def test_openntpd_and_windows_and_macos():
    openbsd = tc.collect_time_config(
        "OpenBSD",
        "openntpd",
        Run({"rcctl ls on": (0, "cron\nntpd\nsshd\n")}),
        files({"/etc/ntpd.conf": OPENNTPD}),
    )
    assert openbsd["enabled"] is True and openbsd["unit"] == "ntpd"
    windows = tc.collect_time_config(
        "Windows",
        "w32time",
        Run(
            {
                "w32tm /query /configuration": (0, W32TM_CONFIG),
                "sc qc w32time": (0, SC_QC),
            }
        ),
    )
    assert windows["configured_servers"] == ["time.windows.com", "ntp.lab"]
    assert windows["enabled"] is True
    macos = tc.collect_time_config(
        "Darwin",
        "timed",
        Run(
            {
                "systemsetup -getnetworktimeserver": (
                    0,
                    "Network Time Server: time.apple.com",
                ),
                "systemsetup -getusingnetworktime": (0, "Network Time: On"),
            }
        ),
    )
    assert (macos["configured_servers"], macos["enabled"]) == (["time.apple.com"], True)


def test_unreadable_is_not_reported_never_not_configured():
    config = tc.collect_time_config("Linux", "chrony", Run({}), files({}))
    assert config["configured_servers"] is None and config["config_path"] is None
    assert tc.collect_time_config("Linux", "none", Run({}))["unit"] is None


def test_a_reader_that_breaks_never_raises():
    def boom(_argv):
        raise RuntimeError("no")

    assert tc.collect_time_config("Windows", "w32time", boom)["enabled"] is None
