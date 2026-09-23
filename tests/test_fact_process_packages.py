# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""``sysmanage_process_packages``: pid -> executable -> owning package.

The property that matters most is the ``state`` column: "the agent could not
see this executable" (unreadable) and "no package manager to ask"
(unresolved) must never collapse into "no package owns it" (unowned) -- a
rule reading them the same way reports a clean host it never inspected.
"""

# pylint: disable=protected-access,redefined-outer-name

import sys
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

from src.sysmanage_agent.collection import fact_process_packages as fpp
from src.sysmanage_agent.core import fact_schema


class _Proc:
    def __init__(self, pid, exe=None, error=None):
        self.info = {"pid": pid}
        self._exe = exe
        self._error = error

    def exe(self):
        if self._error:
            raise self._error
        return self._exe


def _build(procs, owners, manager):
    with patch.object(psutil, "process_iter", return_value=procs), patch.object(
        fpp, "resolve_owners", return_value=(owners, manager)
    ):
        return {r["pid"]: r for r in fpp.build_process_packages()}


def test_the_four_states_stay_apart():
    procs = [
        _Proc(1, "/usr/sbin/sshd"),
        _Proc(2, "/usr/local/bin/handbuilt"),
        _Proc(3, error=psutil.AccessDenied(3)),
        _Proc(4, ""),  # kernel thread: no executable, not a row
        _Proc(5, error=psutil.NoSuchProcess(5)),  # exited mid-walk
    ]
    rows = _build(
        procs, {"/usr/sbin/sshd": ("openssh-server", "1:9.6", "dpkg")}, "dpkg"
    )
    assert rows[1]["state"] == fpp.OWNED and rows[1]["package"] == "openssh-server"
    assert rows[1]["version"] == "1:9.6" and rows[1]["package_manager"] == "dpkg"
    assert rows[2]["state"] == fpp.UNOWNED and rows[2]["package"] is None
    assert rows[3]["state"] == fpp.UNREADABLE and rows[3]["path"] is None
    assert set(rows) == {1, 2, 3}


def test_no_package_manager_is_unresolved_not_unowned():
    rows = _build([_Proc(1, "/usr/bin/thing")], {}, None)
    assert rows[1]["state"] == fpp.UNRESOLVED


@pytest.fixture
def dpkg(tmp_path, monkeypatch):
    info = tmp_path / "info"
    info.mkdir()
    (info / "openssh-server.list").write_text("/.\n/usr\n/usr/sbin/sshd\n")
    # Pre-merged-/usr package that still records /bin.
    (info / "coreutils.list").write_text("/bin/ls\n")
    (tmp_path / "status").write_text(
        "Package: openssh-server\nVersion: 1:9.6p1-3\n\n"
        "Package: coreutils\nVersion: 9.4-3\n\n"
        "Package: libfoo\nVersion: 2.0\n"
    )
    monkeypatch.setattr(fpp, "_DPKG_INFO", str(info))
    monkeypatch.setattr(fpp, "_DPKG_STATUS", str(tmp_path / "status"))


def test_dpkg_owners_with_versions_arch_suffix_and_usrmerge(dpkg):  # noqa: ARG001
    owners = fpp._dpkg_owners({"/usr/sbin/sshd", "/usr/bin/ls", "/opt/x"})
    assert owners["/usr/sbin/sshd"] == ("openssh-server", "1:9.6p1-3", "dpkg")
    # The process runs as /usr/bin/ls; the package recorded /bin/ls.
    assert owners["/usr/bin/ls"] == ("coreutils", "9.4-3", "dpkg")
    assert "/opt/x" not in owners


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="NTFS cannot name a file 'libfoo:amd64.list' (the colon starts an "
    "alternate data stream); dpkg only ever runs on Linux",
)
def test_dpkg_multiarch_list_names_drop_the_arch(dpkg):  # noqa: ARG001
    (Path(fpp._DPKG_INFO) / "libfoo:amd64.list").write_text(
        "/usr/lib/x86_64-linux-gnu/foo\n"
    )
    owners = fpp._dpkg_owners({"/usr/lib/x86_64-linux-gnu/foo"})
    assert owners["/usr/lib/x86_64-linux-gnu/foo"] == ("libfoo", "2.0", "dpkg")


def test_snaps_are_owned_by_their_snap_not_by_nobody():
    owners = fpp._snap_owners(
        {"/snap/firefox/6565/usr/lib/firefox/firefox", "/usr/bin/x"}
    )
    assert owners == {
        "/snap/firefox/6565/usr/lib/firefox/firefox": ("firefox", None, "snap")
    }


def test_bsd_contents_follow_cwd(tmp_path, monkeypatch):
    pkg = tmp_path / "curl-8.20.0"
    pkg.mkdir()
    (pkg / "+CONTENTS").write_text(
        "@name curl-8.20.0\nbin/curl\n@cwd /etc\ncurlrc\n@comment x\n"
    )
    monkeypatch.setattr(fpp, "_BSD_PKG_DB", str(tmp_path))
    owners = fpp._bsd_contents_owners(
        {"/usr/local/bin/curl", "/etc/curlrc", "/usr/local/bin/other"}, "/usr/local"
    )
    assert owners["/usr/local/bin/curl"] == ("curl", "8.20.0", "pkg_info")
    assert owners["/etc/curlrc"][0] == "curl"
    assert "/usr/local/bin/other" not in owners


def test_rpm_and_freebsd_parse_their_tools_output():
    with patch.object(fpp, "_run", return_value="openssh-server\t9.6p1-1.el9\n"):
        assert fpp._rpm_owners({"/usr/sbin/sshd"}) == {
            "/usr/sbin/sshd": ("openssh-server", "9.6p1-1.el9", "rpm")
        }
    with patch.object(fpp, "_run", return_value="curl-8.21.0\n"):
        assert fpp._freebsd_owners({"/usr/local/bin/curl"}) == {
            "/usr/local/bin/curl": ("curl", "8.21.0", "pkg")
        }
    with patch.object(fpp, "_run", return_value=None):  # not owned / tool failed
        assert fpp._rpm_owners({"/x"}) == {} and fpp._freebsd_owners({"/x"}) == {}


def test_homebrew_owner_is_read_from_the_cellar_path():
    with patch(
        "os.path.realpath",
        side_effect=lambda p: {
            "/opt/homebrew/bin/wget": "/opt/homebrew/Cellar/wget/1.24.5/bin/wget",
        }.get(p, p),
    ):
        owners = fpp._homebrew_owners({"/opt/homebrew/bin/wget", "/usr/bin/ssh"})
    assert owners == {"/opt/homebrew/bin/wget": ("wget", "1.24.5", "homebrew")}


def test_linux_without_a_package_database_reports_no_manager(monkeypatch):
    monkeypatch.setattr(fpp.platform, "system", lambda: "Linux")
    monkeypatch.setattr(fpp.os.path, "isdir", lambda _p: False)
    monkeypatch.setattr(fpp.shutil, "which", lambda _c: None)
    assert fpp.resolve_owners({"/usr/bin/x"}) == ({}, None)


def test_contract_declares_the_table_everywhere_but_windows():
    source, platforms = fact_schema.FACT_TABLES["sysmanage_process_packages"]
    assert source == "sysmanage" and "windows" not in platforms and platforms
    assert fact_schema.columns("sysmanage_process_packages") == (
        "pid",
        "path",
        "package",
        "version",
        "package_manager",
        "state",
    )
    assert fact_schema.FACT_CONTRACT_VERSION >= 3


def test_native_provider_registers_it():
    from src.sysmanage_agent.collection import fact_native as fn  # noqa: PLC0415

    fn.register_native_provider()
    assert "sysmanage_process_packages" in fn.NATIVE_TABLES
    with patch.object(fpp, "build_process_packages", return_value=[{"pid": 1}]):
        assert fn.collect(["sysmanage_process_packages"])["sysmanage_process_packages"]
