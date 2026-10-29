# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Equip for backup: install restate and the NFS client wherever restate is
packaged (Ubuntu's PPA, Fedora's COPR, Homebrew on macOS, and the checked
release packages for EL, openSUSE, Alpine and the BSDs), and refuse with a
reason code everywhere else.  The server sends nothing but the request."""

import asyncio
import hashlib
import sys

import pytest

from src.sysmanage_agent.backup import equip

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix-only feature")

UBUNTU = {"ID": "ubuntu", "VERSION_ID": "24.04"}
PACKAGE = b"a restate package"
NAME = "restate-2.2.0.6-freebsd-14.4-amd64.pkg"
SUMS = (
    f"{hashlib.sha256(PACKAGE).hexdigest()}  ./{NAME}\n"
    f"{'0' * 64}  ./restate-2.2.0.6-freebsd-15.1-amd64.pkg\n"
    f"{'1' * 64}  ./restate-2.2.0.6-openbsd-8.0-amd64.tgz\n"
)


@pytest.mark.parametrize(
    "system,info,machine,expected",
    [
        ("Linux", UBUNTU, "x86_64", None),
        ("Linux", {"ID": "ubuntu", "VERSION_ID": "20.04"}, "x86_64", "wrong_platform"),
        ("Linux", {"ID": "debian", "VERSION_ID": "13"}, "x86_64", "wrong_platform"),
        ("Linux", {"ID": "fedora", "VERSION_ID": "44"}, "x86_64", None),
        ("Linux", {"ID": "rocky", "VERSION_ID": "9.6"}, "aarch64", None),
        ("Linux", {"ID": "rhel", "VERSION_ID": "8.10"}, "x86_64", "wrong_platform"),
        (
            "Linux",
            {"ID": "opensuse-tumbleweed", "VERSION_ID": "20261026"},
            "x86_64",
            None,
        ),
        ("Linux", {"ID": "opensuse-leap", "VERSION_ID": "16.0"}, "x86_64", None),
        (
            "Linux",
            {"ID": "opensuse-leap", "VERSION_ID": "15.6"},
            "x86_64",
            "wrong_platform",
        ),
        ("Linux", {"ID": "alpine", "VERSION_ID": "3.24.1"}, "aarch64", None),
        ("Linux", {"ID": "alpine", "VERSION_ID": "3.20.3"}, "x86_64", "wrong_platform"),
        ("Linux", {"ID": "fedora", "VERSION_ID": "44"}, "riscv64", "wrong_platform"),
        ("FreeBSD", {}, "amd64", None),
        ("FreeBSD", {}, "arm64", "wrong_platform"),
        ("OpenBSD", {}, "amd64", None),
        ("NetBSD", {}, "amd64", None),
        ("Windows", {}, "AMD64", "wrong_platform"),
    ],
)
def test_where_equip_is_offered(system, info, machine, expected):
    assert equip.unavailable_reason(None, system, info, machine) == expected


def test_macos_is_offered_only_with_homebrew():
    def brew(path):
        return path == "/opt/homebrew/bin/brew"

    assert equip.unavailable_reason(None, "Darwin", {}, "arm64", exists=brew) is None
    assert (
        equip.unavailable_reason(None, "Darwin", {}, "arm64", exists=lambda _p: False)
        == "wrong_platform"
    )


def test_the_release_parts():
    assert equip.freebsd_release("14.4-RELEASE-p8") == "14.4"
    assert equip.freebsd_release("bogus") is None
    assert equip.version_from_url(f"{equip.RELEASES_URL}/tag/v2.2.0.6") == "2.2.0.6"
    assert equip.version_from_url(f"{equip.RELEASES_URL}/tag/latest") is None
    assert equip.parse_sums(SUMS)[NAME] == hashlib.sha256(PACKAGE).hexdigest()


def _runner(code=0):
    ran = []

    async def run(argv):
        ran.append(argv)
        return code, "the tool's output"

    return ran, run


def test_ubuntu_adds_the_ppa_then_installs(monkeypatch):
    monkeypatch.setattr(equip, "_os_release", lambda path="": UBUNTU)
    ran, run = _runner()
    result = asyncio.run(equip.equip("/var/lib/x", run=run, system="Linux"))
    assert result == {"success": True, "installed": "ppa"}
    bare = [a[2:] if a[:2] == ["sudo", "-n"] else a for a in ran]
    assert bare == equip.ubuntu_steps()
    assert bare[-1] == ["apt-get", "install", "-y", "restate", "nfs-common"]


def test_a_failing_apt_step_reports_install_failed(monkeypatch):
    monkeypatch.setattr(equip, "_os_release", lambda path="": UBUNTU)
    _ran, run = _runner(code=100)
    result = asyncio.run(equip.equip("/var/lib/x", run=run, system="Linux"))
    assert result["success"] is False and result["reason"] == "install_failed"


def _fetcher(package=PACKAGE, sums=SUMS, latest="v2.2.0.6"):
    fetched = []

    def fetch(url, _limit):
        fetched.append(url)
        if url.endswith("/latest"):
            return f"{equip.RELEASES_URL}/tag/{latest}", b"<html>"
        if url.endswith("SHA256SUMS"):
            return url, sums.encode()
        return url, package

    return fetched, fetch


def test_freebsd_downloads_checks_and_adds_the_package(monkeypatch, tmp_path):
    monkeypatch.setattr(equip.platform, "machine", lambda: "amd64")
    ran, run = _runner()
    fetched, fetch = _fetcher()
    result = asyncio.run(equip.equip(str(tmp_path), run=run, fetch=fetch,
                                     system="FreeBSD", release_text="14.4-RELEASE-p8"))  # fmt: skip
    assert result == {"success": True, "installed": "2.2.0.6"}
    assert fetched[-1] == f"{equip.RELEASES_URL}/download/v2.2.0.6/{NAME}"
    bare = ran[-1][2:] if ran[-1][:2] == ["sudo", "-n"] else ran[-1]
    assert bare == ["pkg", "add", "-f", str(tmp_path / "equip" / NAME)]
    assert not (tmp_path / "equip" / NAME).exists()  # removed after pkg add


def test_freebsd_refuses_a_package_whose_checksum_differs(monkeypatch, tmp_path):
    monkeypatch.setattr(equip.platform, "machine", lambda: "amd64")
    ran, run = _runner()
    _fetched, fetch = _fetcher(package=b"tampered")
    result = asyncio.run(equip.equip(str(tmp_path), run=run, fetch=fetch,
                                     system="FreeBSD", release_text="14.4-RELEASE"))  # fmt: skip
    assert result["reason"] == "checksum_mismatch"
    assert ran == []  # nothing installed


def test_freebsd_without_a_package_for_this_release_says_which_exist(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(equip.platform, "machine", lambda: "amd64")
    _ran, run = _runner()
    _fetched, fetch = _fetcher()
    result = asyncio.run(equip.equip(str(tmp_path), run=run, fetch=fetch,
                                     system="FreeBSD", release_text="13.5-RELEASE"))  # fmt: skip
    assert result["reason"] == "no_release"
    assert "freebsd-14.4" in result["detail"] and "openbsd" not in result["detail"]


def test_a_download_error_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(equip.platform, "machine", lambda: "amd64")
    _ran, run = _runner()

    def fetch(_url, _limit):
        raise OSError("network unreachable")

    result = asyncio.run(equip.equip(str(tmp_path), run=run, fetch=fetch,
                                     system="FreeBSD", release_text="14.4-RELEASE"))  # fmt: skip
    assert result["reason"] == "download_failed" and "unreachable" in result["detail"]


def test_an_unsupported_host_is_refused_before_anything_runs(monkeypatch):
    monkeypatch.setattr(equip, "_os_release", lambda path="": {"ID": "debian"})
    ran, run = _runner()
    result = asyncio.run(equip.equip("/x", run=run, system="Linux"))
    assert result["reason"] == "unsupported" and ran == []
    result = asyncio.run(equip.equip("/x", run=run, system="Windows"))
    assert result["reason"] == "unsupported" and ran == []


def test_the_freebsd_sudoers_rule_admits_exactly_the_equip_command():
    import os  # pylint: disable=import-outside-toplevel
    import re  # pylint: disable=import-outside-toplevel

    path = os.path.join(os.path.dirname(__file__), "..", "installer", "freebsd",
                        "sysmanage-agent.sudoers")  # fmt: skip
    with open(path, encoding="utf-8") as handle:
        rules = re.findall(r"/usr/sbin/pkg (\^add.*\$)$", handle.read(), re.M)
    assert len(rules) == 1
    good = f"add -f /var/db/sysmanage-agent/equip/{NAME}"
    assert re.fullmatch(rules[0], good)
    for bad in ("add -f /tmp/evil.pkg", f"add -f /var/db/sysmanage-agent/equip/{NAME} /tmp/x",
                "add -f /var/db/sysmanage-agent/equip/../evil.pkg"):  # fmt: skip
        assert not re.fullmatch(rules[0], bad), bad
