# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Applying updates on macOS (2026-11-23: the macOS detector had no
apply_updates at all, so every update applied to a Mac failed -- Homebrew's
too; MacPorts, Software Update items and App Store apps were never applied)."""

from types import SimpleNamespace
from unittest.mock import patch

from src.sysmanage_agent.collection import update_apply_batch
from src.sysmanage_agent.collection import update_detection_macos_apply as mac_apply
from src.sysmanage_agent.collection.update_detection_macos import MacOSUpdateDetector

MAS = """497799835 Xcode (15.0 -> 15.1)
1295203466 Microsoft Remote Desktop (10.9.3 -> 10.9.4)
"""


def test_the_mac_detector_can_apply_at_all():
    assert (
        MacOSUpdateDetector.apply_updates.__qualname__
        == "MacOSApplyMixin.apply_updates"
    )


def test_mas_outdated_is_parsed_with_the_app_id():
    found = mac_apply.parse_mas_outdated(MAS)
    assert [(u["package_name"], u["bundle_id"], u["current_version"], u["available_version"])
            for u in found] == [
        ("Xcode", "497799835", "15.0", "15.1"),
        ("Microsoft Remote Desktop", "1295203466", "10.9.3", "10.9.4"),
    ]  # fmt: skip


def _capture():
    calls = []

    def run(argv, **_kw):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return calls, run


def test_each_manager_runs_its_own_command_as_root():
    calls, run = _capture()
    detector = MacOSUpdateDetector()
    with patch.object(mac_apply.os, "geteuid", return_value=0), \
            patch.object(update_apply_batch.subprocess, "run", side_effect=run):  # fmt: skip
        result = detector.apply_updates(packages=[
            {"package_name": "Safari", "package_manager": "mac_app_store",
             "bundle_id": "Safari18.1VenturaAuto-18.1"},
            {"package_name": "curl", "package_manager": "macports"},
            {"package_name": "Xcode", "package_manager": "mas", "bundle_id": "497799835"},
        ])  # fmt: skip
    assert calls == [
        [
            "softwareupdate",
            "--install",
            "Safari18.1VenturaAuto-18.1",
            "--agree-to-license",
        ],
        ["port", "-N", "upgrade", "curl"],
        ["mas", "upgrade", "497799835"],
    ]
    assert len(result["updated_packages"]) == 3 and not result["failed_packages"]


def test_a_software_update_item_without_its_label_is_looked_up_by_title():
    calls, run = _capture()
    detector = MacOSUpdateDetector()
    with patch.object(detector, "_softwareupdate_labels",
                      return_value={"Command Line Tools for Xcode": "CLT-16.0"}), \
            patch.object(mac_apply.os, "geteuid", return_value=0), \
            patch.object(update_apply_batch.subprocess, "run", side_effect=run):  # fmt: skip
        result = detector.apply_updates(packages=[
            {"package_name": "Command Line Tools for Xcode", "package_manager": "mac_app_store"},
            {"package_name": "Gone", "package_manager": "mac_app_store"},
        ])  # fmt: skip
    assert calls == [["softwareupdate", "--install", "CLT-16.0", "--agree-to-license"]]
    assert [f["package_name"] for f in result["failed_packages"]] == ["Gone"]


def test_homebrew_goes_to_its_existing_applier():
    detector = MacOSUpdateDetector()
    with patch.object(MacOSUpdateDetector, "_apply_homebrew_updates") as brew:
        detector.apply_updates(
            packages=[{"package_name": "wget", "package_manager": "homebrew"}]
        )
    assert brew.called
