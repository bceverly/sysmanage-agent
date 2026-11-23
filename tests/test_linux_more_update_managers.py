# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Updates applied on openSUSE (zypper), Arch (pacman) and Alpine (apk), and
detected on Alpine (2026-11-23: zypper and pacman updates were detected and
never applied; apk updates were not even detected).  Proven against the real
package managers in containers the same day (Leap 16.0, Arch from January
2025, Alpine 3.21.0)."""

import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from src.sysmanage_agent.collection import linux_update_applicators as apply_mod
from src.sysmanage_agent.collection.linux_update_detectors import (
    LinuxUpdateDetector as LinuxPkgDetector,
)
from src.sysmanage_agent.collection.update_detection_linux import LinuxUpdateDetector

APK_VERSION = """Installed:                                Available:
busybox-1.37.0-r8                       < 1.37.0-r14
libcrypto3-3.3.2-r4                     < 3.3.7-r2
alpine-release-3.21.0-r0                < 3.21.10-r0
"""


def _ran(argvs, code=0):
    calls = []

    def run(argv, **_kw):
        calls.append(argv)
        return SimpleNamespace(
            returncode=code, stdout="", stderr="boom" if code else ""
        )

    return calls, run


def _pkgs(manager, *names):
    return [{"package_name": n, "package_manager": manager, "current_version": "1",
             "available_version": "2"} for n in names]  # fmt: skip


def test_apk_updates_are_parsed_from_apk_version():
    found = LinuxPkgDetector(lambda _name: False).parse_apk_version(APK_VERSION)
    assert [(u["package_name"], u["current_version"], u["available_version"]) for u in found] == [
        ("busybox", "1.37.0-r8", "1.37.0-r14"),
        ("libcrypto3", "3.3.2-r4", "3.3.7-r2"),
        ("alpine-release", "3.21.0-r0", "3.21.10-r0"),
    ]  # fmt: skip
    assert all(u["package_manager"] == "apk" for u in found)


def test_zypper_updates_only_the_packages_asked_for():
    calls, run = _ran(None)
    results = {}
    with patch.object(apply_mod, "_sudo_prefix", return_value=["sudo", "-n"]), \
            patch.object(subprocess, "run", side_effect=run):  # fmt: skip
        apply_mod.LinuxUpdateApplicator.apply_zypper_updates(
            _pkgs("zypper", "a", "b"), results
        )
    assert calls == [["sudo", "-n", "zypper", "--non-interactive", "update",
                      "--auto-agree-with-licenses", "a", "b"]]  # fmt: skip
    assert [u["package_name"] for u in results["updated_packages"]] == ["a", "b"]


def test_pacman_takes_the_keyring_first_then_the_whole_system():
    calls, run = _ran(None)
    results = {}
    with patch.object(apply_mod, "_sudo_prefix", return_value=[]), \
            patch.object(subprocess, "run", side_effect=run):  # fmt: skip
        apply_mod.LinuxUpdateApplicator.apply_pacman_updates(
            _pkgs("pacman", "acl"), results
        )
    assert calls == [["pacman", "-Sy", "--noconfirm", "--needed", "archlinux-keyring"],
                     ["pacman", "-Su", "--noconfirm"]]  # fmt: skip
    assert "whole system" in results["updated_packages"][0]["note"]


def test_a_failed_step_fails_the_batch_and_stops():
    calls, run = _ran(None, code=1)
    results = {}
    with patch.object(apply_mod, "_sudo_prefix", return_value=[]), \
            patch.object(subprocess, "run", side_effect=run):  # fmt: skip
        apply_mod.LinuxUpdateApplicator.apply_pacman_updates(
            _pkgs("pacman", "acl"), results
        )
    assert len(calls) == 1 and results["failed_packages"][0]["error"] == "boom"
    assert not results.get("updated_packages")


def test_apk_upgrades_only_the_packages_asked_for():
    calls, run = _ran(None)
    results = {}
    with patch.object(apply_mod, "_sudo_prefix", return_value=[]), \
            patch.object(subprocess, "run", side_effect=run):  # fmt: skip
        apply_mod.LinuxUpdateApplicator.apply_apk_updates(
            _pkgs("apk", "busybox"), results
        )
    assert calls == [["apk", "add", "--upgrade", "busybox"]]


def test_the_linux_detector_routes_each_manager_to_its_applicator():
    detector = LinuxUpdateDetector()
    for manager, method in (("zypper", "apply_zypper_updates"),
                            ("pacman", "apply_pacman_updates"),
                            ("apk", "apply_apk_updates")):  # fmt: skip
        with patch.object(apply_mod.LinuxUpdateApplicator, method) as handler:
            detector.apply_updates(packages=_pkgs(manager, "x"))
        assert handler.called, manager
