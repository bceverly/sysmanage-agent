"""
Tests for sysmanage_agent.collection.linux_update_applicators.LinuxUpdateApplicator.

Each applicator method shells out to a package manager and partitions packages
into `updated_packages` / `failed_packages` (or `successful_updates` /
`failed_updates`) on the results dict. We mock subprocess.run and verify
both outcome buckets per applicator, plus the exception-recovery arm.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.collection import linux_update_applicators
from src.sysmanage_agent.collection.linux_update_applicators import (
    LinuxUpdateApplicator,
)


@pytest.fixture(autouse=True)
def _no_sudo_prefix(request):
    """Force ``_sudo_prefix()`` to return ``[]`` for every test in this file
    except those in ``TestSudoPrefix``, which verify the helper itself.

    The applicators add ``["sudo", "-n"]`` when the process isn't running
    as root, but every assertion below was written against the bare
    package-manager command.  Patching the helper to no-op keeps those
    assertions stable regardless of the test runner's EUID.
    """
    if request.cls is not None and request.cls.__name__ == "TestSudoPrefix":
        yield
        return
    with patch(
        "src.sysmanage_agent.collection.linux_update_applicators._sudo_prefix",
        return_value=[],
    ):
        yield


def _completed(returncode=0, stdout="", stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _pkg(name, current="1.0", available="1.1", **extras):
    return {
        "package_name": name,
        "current_version": current,
        "available_version": available,
        **extras,
    }


# ---------------------------------------------------------------------------
# apply_apt_updates
# ---------------------------------------------------------------------------


class TestApplyAptUpdates:
    def test_success_records_each_package(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ):
            LinuxUpdateApplicator.apply_apt_updates(
                [_pkg("nginx"), _pkg("curl")], results
            )
        assert len(results["updated_packages"]) == 2
        assert all(p["package_manager"] == "apt" for p in results["updated_packages"])

    def test_nonzero_exit_records_failures_for_all_packages(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr="held back"),
        ):
            LinuxUpdateApplicator.apply_apt_updates(
                [_pkg("nginx"), _pkg("curl")], results
            )
        assert "updated_packages" not in results
        assert len(results["failed_packages"]) == 2
        assert all(p["error"] == "held back" for p in results["failed_packages"])

    def test_subprocess_exception_records_failures(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("apt died"),
        ):
            LinuxUpdateApplicator.apply_apt_updates([_pkg("nginx")], results)
        assert results["failed_packages"][0]["error"] == "apt died"

    def test_called_with_install_only_upgrade_flags(self):
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ) as run:
            LinuxUpdateApplicator.apply_apt_updates([_pkg("nginx")], {})
        argv = run.call_args.args[0]
        assert argv[:4] == ["apt-get", "install", "--only-upgrade", "-y"]
        assert "nginx" in argv


# ---------------------------------------------------------------------------
# apply_snap_updates  (per-package iteration)
# ---------------------------------------------------------------------------


class TestApplySnapUpdates:
    def test_success_per_package(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ):
            LinuxUpdateApplicator.apply_snap_updates(
                [_pkg("firefox"), _pkg("vlc")], results
            )
        assert len(results["updated_packages"]) == 2

    def test_partial_failure_buckets_correctly(self):
        results = {}
        # First call ok, second fails.
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=[_completed(0), _completed(1, stderr="locked")],
        ):
            LinuxUpdateApplicator.apply_snap_updates(
                [_pkg("firefox"), _pkg("vlc")], results
            )
        assert len(results["updated_packages"]) == 1
        assert results["failed_packages"][0]["error"] == "locked"

    def test_exception_records_failure(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("snap died"),
        ):
            LinuxUpdateApplicator.apply_snap_updates([_pkg("firefox")], results)
        assert results["failed_packages"][0]["error"] == "snap died"


# ---------------------------------------------------------------------------
# apply_flatpak_updates
# ---------------------------------------------------------------------------


class TestApplyFlatpakUpdates:
    def test_uses_bundle_id_when_provided(self):
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ) as run:
            LinuxUpdateApplicator.apply_flatpak_updates(
                [_pkg("VLC", bundle_id="org.videolan.VLC")], {}
            )
        argv = run.call_args.args[0]
        assert argv == ["flatpak", "update", "-y", "org.videolan.VLC"]

    def test_falls_back_to_package_name_when_no_bundle_id(self):
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ) as run:
            LinuxUpdateApplicator.apply_flatpak_updates([_pkg("vlc")], {})
        assert run.call_args.args[0][-1] == "vlc"

    def test_failure_bucket(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr="not found"),
        ):
            LinuxUpdateApplicator.apply_flatpak_updates([_pkg("missing")], results)
        assert results["failed_packages"][0]["error"] == "not found"

    def test_exception_bucket(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=OSError("flatpak missing"),
        ):
            LinuxUpdateApplicator.apply_flatpak_updates([_pkg("x")], results)
        assert "flatpak missing" in results["failed_packages"][0]["error"]


# ---------------------------------------------------------------------------
# apply_dnf_updates
# ---------------------------------------------------------------------------


class TestApplyDnfUpdates:
    def test_success_marks_all_packages(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ):
            LinuxUpdateApplicator.apply_dnf_updates(
                [_pkg("kernel"), _pkg("glibc")], results
            )
        assert len(results["updated_packages"]) == 2
        assert all(p["package_manager"] == "dnf" for p in results["updated_packages"])

    def test_failure_marks_all_packages(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr="conflict"),
        ):
            LinuxUpdateApplicator.apply_dnf_updates([_pkg("kernel")], results)
        assert results["failed_packages"][0]["error"] == "conflict"

    def test_exception_records_failures(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("dnf timeout"),
        ):
            LinuxUpdateApplicator.apply_dnf_updates([_pkg("kernel")], results)
        assert results["failed_packages"][0]["error"] == "dnf timeout"


# ---------------------------------------------------------------------------
# apply_fwupd_updates  (firmware — special: skips when no device_id)
# ---------------------------------------------------------------------------


class TestApplyFwupdUpdates:
    def test_missing_device_id_records_failure_without_running(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run"
        ) as run:
            LinuxUpdateApplicator.apply_fwupd_updates([_pkg("nvme-fw")], results)
        run.assert_not_called()
        assert "device ID" in results["failed_packages"][0]["error"]

    def test_success_marks_requires_reboot(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ):
            LinuxUpdateApplicator.apply_fwupd_updates(
                [_pkg("nvme-fw", device_id="dev-1")], results
            )
        entry = results["updated_packages"][0]
        assert entry["device_id"] == "dev-1"
        assert entry["requires_reboot"] is True

    def test_failure_records_stderr_or_default(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr=""),
        ):
            LinuxUpdateApplicator.apply_fwupd_updates(
                [_pkg("nvme-fw", device_id="dev-1")], results
            )
        # Empty stderr → falls back to the localised default message.
        assert results["failed_packages"][0]["error"]

    def test_exception_records_failure(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("fwupdmgr crashed"),
        ):
            LinuxUpdateApplicator.apply_fwupd_updates(
                [_pkg("nvme-fw", device_id="dev-1")], results
            )
        assert results["failed_packages"][0]["error"] == "fwupdmgr crashed"


# ---------------------------------------------------------------------------
# Release upgrade applicators (Ubuntu / Fedora / openSUSE)
# ---------------------------------------------------------------------------


class TestApplyUbuntuReleaseUpdates:
    def test_success(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ):
            LinuxUpdateApplicator.apply_ubuntu_release_updates(
                [_pkg("ubuntu", available="24.04")], results
            )
        assert "Ubuntu Release Upgrade" in results["successful_updates"]

    def test_failure(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr="no upgrade"),
        ):
            LinuxUpdateApplicator.apply_ubuntu_release_updates(
                [_pkg("ubuntu", available="24.04")], results
            )
        assert "Ubuntu Release Upgrade" in results["failed_updates"]
        assert "no upgrade" in results["errors"][0]

    def test_exception(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("blew up"),
        ):
            LinuxUpdateApplicator.apply_ubuntu_release_updates(
                [_pkg("ubuntu")], results
            )
        assert "blew up" in results["errors"][0]


class TestApplyFedoraReleaseUpdates:
    def test_success_invokes_reboot_step(self):
        results = {}
        # Two subprocess calls: 'system-upgrade download' then 'system-upgrade reboot'.
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=[_completed(0), _completed(0)],
        ) as run:
            LinuxUpdateApplicator.apply_fedora_release_updates(
                [_pkg("fedora", available="Fedora 41")], results
            )
        assert "Fedora Release Upgrade" in results["successful_updates"]
        # Two calls confirms the reboot step actually fired.
        assert run.call_count == 2

    def test_download_failure_skips_reboot(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr="repo missing"),
        ) as run:
            LinuxUpdateApplicator.apply_fedora_release_updates(
                [_pkg("fedora", available="Fedora 41")], results
            )
        assert "Fedora Release Upgrade" in results["failed_updates"]
        # Only one subprocess call (download) — reboot was skipped.
        assert run.call_count == 1

    def test_exception(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("dnf wedged"),
        ):
            LinuxUpdateApplicator.apply_fedora_release_updates(
                [_pkg("fedora")], results
            )
        assert "dnf wedged" in results["errors"][0]


class TestApplyOpensuseReleaseUpdates:
    def test_success(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ):
            LinuxUpdateApplicator.apply_opensuse_release_updates(
                [_pkg("opensuse")], results
            )
        assert "openSUSE Release Upgrade" in results["successful_updates"]

    def test_failure(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(1, stderr="zypper conflict"),
        ):
            LinuxUpdateApplicator.apply_opensuse_release_updates(
                [_pkg("opensuse")], results
            )
        assert "openSUSE Release Upgrade" in results["failed_updates"]

    def test_exception(self):
        results = {}
        with patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            side_effect=RuntimeError("zypper crashed"),
        ):
            LinuxUpdateApplicator.apply_opensuse_release_updates(
                [_pkg("opensuse")], results
            )
        assert "zypper crashed" in results["errors"][0]


# ---------------------------------------------------------------------------
# _sudo_prefix — privilege-escalation helper
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not hasattr(os, "geteuid"),
    reason="os.geteuid is POSIX-only; _sudo_prefix() is a no-op on Windows",
)
class TestSudoPrefix:
    """Verify the applicators add ``sudo -n`` when not running as root, and
    don't when they are.  Skipping sudo for EUID 0 is what keeps the
    Alpine path (OpenRC runs the agent as root, no sudo installed) from
    breaking.
    """

    # pylint: disable=protected-access

    def test_returns_empty_when_euid_zero(self):
        with patch.object(linux_update_applicators.os, "geteuid", return_value=0):
            assert not linux_update_applicators._sudo_prefix()

    def test_returns_sudo_when_non_root(self):
        with patch.object(linux_update_applicators.os, "geteuid", return_value=1000):
            assert linux_update_applicators._sudo_prefix() == ["sudo", "-n"]

    def test_apt_invocation_uses_sudo_when_non_root(self):
        """Regression guard for the test2404 dpkg-lock-permission incident:
        apply_apt_updates' argv must begin with ``sudo -n`` when EUID != 0."""
        with patch.object(
            linux_update_applicators.os, "geteuid", return_value=1000
        ), patch(
            "src.sysmanage_agent.collection.linux_update_applicators.subprocess.run",
            return_value=_completed(0),
        ) as run:
            LinuxUpdateApplicator.apply_apt_updates([_pkg("nginx")], {})
        argv = run.call_args.args[0]
        assert argv[:2] == ["sudo", "-n"]
        assert argv[2:6] == ["apt-get", "install", "--only-upgrade", "-y"]
        assert "nginx" in argv
