# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Equip for backup on each platform restate is packaged for: the commands
run, the release files named, downloaded, checked and removed."""

# pylint: disable=redefined-outer-name

import asyncio
import hashlib
import sys
from types import SimpleNamespace

import pytest

from src.sysmanage_agent.backup import equip
from src.sysmanage_agent.backup import equip_release as release

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

V = "2.2.0.13"
FILES = [
    f"restate-{V}-1.el10.x86_64.rpm",
    f"restate-{V}-1.el9.aarch64.rpm",
    f"restate-{V}-1.opensuseleap16.0.x86_64.rpm",
    f"restate-{V}-1.opensusetumbleweed20261020.x86_64.rpm",
    f"restate-{V}-1.opensusetumbleweed20261026.x86_64.rpm",
    f"restate-{V}-netbsd-11.0-amd64.tgz",
    f"restate-{V}-openbsd-8.0-amd64.tgz",
    f"restate-{V}-r0-alpine3.24-aarch64.apk",
    f"restate-doc-{V}-r0-alpine3.24-aarch64.apk",
    f"restate-{V}-freebsd-15.1-amd64.pkg",
]


def _body(name):
    return f"package {name}".encode()


SUMS = "".join(f"{hashlib.sha256(_body(n)).hexdigest()}  ./{n}\n" for n in FILES)


def _bare(argv):
    for prefix in (["sudo", "-n"], ["doas", "-n"]):
        if argv[: len(prefix)] == prefix:
            return argv[len(prefix) :]
    return argv


@pytest.fixture
def host(monkeypatch, tmp_path):
    """Run equip as a non-root agent with a fake network and fake tools."""
    monkeypatch.setattr(equip.os, "geteuid", lambda: 1000)
    ran, fetched, seen = [], [], {}

    async def run(argv):
        ran.append(argv)
        for arg in argv:  # what was on disk while the tool ran
            if str(tmp_path) in arg:
                with open(arg, "rb") as handle:
                    seen[arg] = handle.read()
        return 0, "ok"

    def fetch(url, _limit):
        fetched.append(url)
        if url.endswith("/latest"):
            return f"{release.RELEASES_URL}/tag/v{V}", b""
        if url.endswith("SHA256SUMS"):
            return url, SUMS.encode()
        return url, _body(url.rsplit("/", 1)[1])

    def go(system, info=None, machine="x86_64", release_text=None):
        if info is not None:
            monkeypatch.setattr(equip, "_os_release", lambda path="": info)
        monkeypatch.setattr(equip.platform, "machine", lambda: machine)
        return asyncio.run(equip.equip(str(tmp_path), run=run, fetch=fetch,
                                       system=system, release_text=release_text))  # fmt: skip

    return SimpleNamespace(go=go, ran=ran, fetched=fetched, seen=seen,
                           folder=tmp_path / "equip")  # fmt: skip


def test_fedora_enables_the_copr_then_installs_restate_and_nfs_utils(host):
    result = host.go("Linux", {"ID": "fedora", "VERSION_ID": "44"})
    assert result == {"success": True, "installed": "copr"}
    assert [_bare(a) for a in host.ran] == equip.fedora_steps()
    assert host.ran[-1][-2:] == ["restate", "nfs-utils"] and not host.fetched


def test_el_installs_the_release_rpm_with_nfs_utils(host):
    result = host.go("Linux", {"ID": "almalinux", "VERSION_ID": "10.0"})
    assert result == {"success": True, "installed": V}
    path = str(host.folder / f"restate-{V}-1.el10.x86_64.rpm")
    assert _bare(host.ran[-1]) == ["dnf", "install", "-y", path, "nfs-utils"]
    assert host.seen[path] == _body(f"restate-{V}-1.el10.x86_64.rpm")
    assert not list(host.folder.iterdir())  # removed afterwards


def test_el_without_a_package_for_its_processor_says_which_exist(host):
    result = host.go("Linux", {"ID": "rocky", "VERSION_ID": "10.0"}, machine="aarch64")
    assert result["reason"] == "no_release"
    assert "el9.aarch64" in result["detail"] and "freebsd" not in result["detail"]
    assert host.ran == []


def test_leap_installs_the_rpm_with_the_nfs_client(host):
    host.go("Linux", {"ID": "opensuse-leap", "VERSION_ID": "16.0"})
    path = str(host.folder / f"restate-{V}-1.opensuseleap16.0.x86_64.rpm")
    assert _bare(host.ran[-1]) == ["zypper", "--non-interactive", "install",
                                   "--allow-unsigned-rpm", path, "nfs-client"]  # fmt: skip


def test_tumbleweed_takes_the_newest_snapshots_rpm(host):
    host.go("Linux", {"ID": "opensuse-tumbleweed", "VERSION_ID": "20261029"})
    assert host.ran[-1][-2].endswith(
        f"restate-{V}-1.opensusetumbleweed20261026.x86_64.rpm"
    )


def test_alpine_adds_nfs_utils_then_both_checked_packages(host):
    result = host.go(
        "Linux", {"ID": "alpine", "VERSION_ID": "3.24.1"}, machine="aarch64"
    )
    assert result["success"] is True
    names = [f"restate-{V}-r0-alpine3.24-aarch64.apk",
             f"restate-doc-{V}-r0-alpine3.24-aarch64.apk"]  # fmt: skip
    assert [_bare(a) for a in host.ran] == [
        ["apk", "add", "nfs-utils"],
        ["apk", "add", "--allow-untrusted", *[str(host.folder / n) for n in names]],
    ]


def test_openbsd_saves_the_package_under_its_own_name_and_uses_doas(host):
    result = host.go("OpenBSD", machine="amd64", release_text="8.0")
    assert result["success"] is True
    path = str(host.folder / f"restate-{V}.tgz")
    assert host.ran[-1] == ["doas", "-n", "/usr/sbin/pkg_add", "-D", "unsigned", path]
    assert host.seen[path] == _body(f"restate-{V}-openbsd-8.0-amd64.tgz")


def test_netbsd_adds_the_release_package(host):
    host.go("NetBSD", machine="amd64", release_text="11.0")
    path = str(host.folder / f"restate-{V}-netbsd-11.0-amd64.tgz")
    assert host.ran[-1] == ["sudo", "-n", "/usr/sbin/pkg_add", path]


def test_netbsd_on_a_release_restate_does_not_build_for(host):
    result = host.go("NetBSD", machine="amd64", release_text="9.4")
    assert result["reason"] == "no_release" and "netbsd-11.0" in result["detail"]


def test_a_tampered_package_installs_nothing(host, monkeypatch):
    monkeypatch.setattr(release, "parse_sums",
                        lambda _t: {f: "0" * 64 for f in FILES})  # fmt: skip
    result = host.go(
        "Linux", {"ID": "alpine", "VERSION_ID": "3.24.0"}, machine="aarch64"
    )
    assert result["reason"] == "checksum_mismatch" and host.ran == []


def test_a_failing_install_step_is_reported_and_the_files_removed(host, tmp_path):
    async def failing(argv):
        host.ran.append(argv)
        return 1, "error: nothing provides libfoo"

    result = asyncio.run(equip.equip(str(tmp_path), run=failing, fetch=lambda u, l: (
        (f"{release.RELEASES_URL}/tag/v{V}", b"") if u.endswith("/latest") else
        (u, SUMS.encode()) if u.endswith("SHA256SUMS") else
        (u, _body(u.rsplit("/", 1)[1]))), system="NetBSD", release_text="11.0"))  # fmt: skip
    assert result["reason"] == "install_failed" and "libfoo" in result["detail"]
    assert not list((tmp_path / "equip").iterdir())


def _stat(uid):
    return lambda _path: SimpleNamespace(st_uid=uid)


def test_macos_runs_brew_as_homebrews_owner_when_root(monkeypatch):
    monkeypatch.setattr(equip.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        equip.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="bryan")
    )
    ran = []

    async def run(argv):
        ran.append(argv)
        return 0, ""

    result = asyncio.run(equip.equip("/x", run=run, system="Darwin",
                                     exists=lambda p: p == "/opt/homebrew/bin/brew",
                                     stat=_stat(501)))  # fmt: skip
    assert result == {"success": True, "installed": "homebrew"}
    assert ran == [["sudo", "-u", "bryan", "-H", "/opt/homebrew/bin/brew", "install",
                    "bceverly/tap/restate"]]  # fmt: skip


def test_macos_never_runs_brew_as_root(monkeypatch):
    monkeypatch.setattr(equip.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        equip.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="root")
    )
    assert equip.homebrew_argv(lambda p: p == "/usr/local/bin/brew", _stat(0)) is None


def test_macos_as_its_own_user_runs_brew_directly(monkeypatch):
    monkeypatch.setattr(equip.os, "geteuid", lambda: 501)
    assert equip.homebrew_argv(lambda p: p == "/usr/local/bin/brew", _stat(501)) == [
        "/usr/local/bin/brew", "install", "bceverly/tap/restate"]  # fmt: skip


def test_the_package_names_come_only_from_the_host():
    listed = {n: "x" for n in FILES}
    assert release.asset_names(release.EL, V, "10", "x86_64", listed) == [
        f"restate-{V}-1.el10.x86_64.rpm"]  # fmt: skip
    assert release.asset_names(release.EL, V, "10", "aarch64", listed) is None
    assert release.asset_names("anything", V, "1", "x", listed) is None
    assert release.local_name(release.OPENBSD, V, "x.tgz") == f"restate-{V}.tgz"


def _rules(system):
    import os  # pylint: disable=import-outside-toplevel

    name = (
        "sysmanage_agent.sudoers" if system == "netbsd" else "sysmanage-agent.sudoers"
    )
    path = os.path.join(os.path.dirname(__file__), "..", "installer", system, name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


@pytest.mark.parametrize(
    "system,rule",
    [
        ("centos", "NOPASSWD: /usr/bin/dnf *"),
        ("opensuse", "NOPASSWD: /usr/bin/zypper *"),
        ("alpine", "NOPASSWD: /sbin/apk add *"),
        ("netbsd", "NOPASSWD: /usr/sbin/pkg_add *"),
    ],
)
def test_each_systems_sudoers_admits_its_equip_commands(system, rule):
    """Fedora and EL (centos), openSUSE, Alpine and NetBSD install with rules
    the agent's package already grants; a narrower rule would break Equip."""
    assert rule in _rules(system)


def test_openbsds_doas_admits_pkg_add_by_its_absolute_path():
    import os  # pylint: disable=import-outside-toplevel

    path = os.path.join(os.path.dirname(__file__), "..", "installer", "openbsd",
                        "files", "sysmanage_agent.doas")  # fmt: skip
    with open(path, encoding="utf-8") as handle:
        assert (
            "permit nopass _sysmanage as root cmd /usr/sbin/pkg_add\n" in handle.read()
        )
    assert release.install_steps(release.OPENBSD, ["/p"])[0][0] == "/usr/sbin/pkg_add"
