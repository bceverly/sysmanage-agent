# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for antivirus platform-specific detection methods.
Tests detection of antivirus software on Linux, macOS, Windows, and BSD platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector


@pytest.fixture
def collector():
    """Create an AntivirusCollector instance for testing."""
    return AntivirusCollector()


class TestDetectLinuxAntivirus:
    """Tests for _detect_linux_antivirus method."""

    def test_detect_linux_clamav(self, collector):
        """Test detection of ClamAV on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/usr/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector._detect_linux_antivirus()

        assert result["software_name"] == "clamav"

    def test_detect_linux_chkrootkit(self, collector):
        """Test detection of chkrootkit on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_chkrootkit",
                return_value={
                    "software_name": "chkrootkit",
                    "install_path": "/usr/bin/chkrootkit",
                    "version": "0.55",
                    "enabled": True,
                },
            ):
                result = collector._detect_linux_antivirus()

        assert result["software_name"] == "chkrootkit"

    def test_detect_linux_rkhunter(self, collector):
        """Test detection of rkhunter on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_chkrootkit",
                return_value={
                    "software_name": None,
                    "install_path": None,
                    "version": None,
                    "enabled": None,
                },
            ):
                with patch.object(
                    collector,
                    "_check_rkhunter",
                    return_value={
                        "software_name": "rkhunter",
                        "install_path": "/usr/bin/rkhunter",
                        "version": "1.4.6",
                        "enabled": True,
                    },
                ):
                    result = collector._detect_linux_antivirus()

        assert result["software_name"] == "rkhunter"

    def test_detect_linux_none_found(self, collector):
        """Test detection when no antivirus is found on Linux."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_chkrootkit",
                return_value={
                    "software_name": None,
                    "install_path": None,
                    "version": None,
                    "enabled": None,
                },
            ):
                with patch.object(
                    collector,
                    "_check_rkhunter",
                    return_value={
                        "software_name": None,
                        "install_path": None,
                        "version": None,
                        "enabled": None,
                    },
                ):
                    result = collector._detect_linux_antivirus()

        assert result["software_name"] is None


class TestDetectMacosAntivirus:
    """Tests for _detect_macos_antivirus method."""

    def test_detect_macos_clamav_with_brew_service(self, collector):
        """Test detection of ClamAV on macOS with brew service running."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/opt/homebrew/bin/clamscan",
                "version": "1.0.0",
                "enabled": False,
            },
        ):
            with patch.object(
                collector,
                "_is_brew_service_running",
                return_value=True,
            ):
                result = collector._detect_macos_antivirus()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_detect_macos_clamav_without_brew_service(self, collector):
        """Test detection of ClamAV on macOS without brew service running."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/opt/homebrew/bin/clamscan",
                "version": "1.0.0",
                "enabled": False,
            },
        ):
            with patch.object(
                collector,
                "_is_brew_service_running",
                return_value=False,
            ):
                result = collector._detect_macos_antivirus()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is False

    def test_detect_macos_none_found(self, collector):
        """Test detection when no antivirus is found on macOS."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector._detect_macos_antivirus()

        assert result["software_name"] is None


class TestDetectWindowsAntivirus:
    """Tests for _detect_windows_antivirus method."""

    def test_detect_windows_clamav(self, collector):
        """Test detection of ClamAV on Windows."""
        with patch.object(
            collector,
            "_check_clamav_windows",
            return_value={
                "software_name": "clamav",
                "install_path": "C:\\Program Files\\ClamAV\\clamscan.exe",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector._detect_windows_antivirus()

        assert result["software_name"] == "clamav"

    def test_detect_windows_none_found(self, collector):
        """Test detection when no antivirus is found on Windows."""
        with patch.object(
            collector,
            "_check_clamav_windows",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector._detect_windows_antivirus()

        assert result["software_name"] is None


class TestDetectBsdAntivirus:
    """Tests for _detect_bsd_antivirus method."""

    def test_detect_bsd_clamav(self, collector):
        """Test detection of ClamAV on BSD."""
        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": "clamav",
                "install_path": "/usr/local/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector._detect_bsd_antivirus()

        assert result["software_name"] == "clamav"

    def test_detect_freebsd_rkhunter(self, collector):
        """Test detection of rkhunter on FreeBSD."""
        collector.system = "FreeBSD"

        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_rkhunter",
                return_value={
                    "software_name": "rkhunter",
                    "install_path": "/usr/local/bin/rkhunter",
                    "version": "1.4.6",
                    "enabled": True,
                },
            ):
                result = collector._detect_bsd_antivirus()

        assert result["software_name"] == "rkhunter"

    def test_detect_netbsd_rkhunter(self, collector):
        """Test detection of rkhunter on NetBSD."""
        collector.system = "NetBSD"

        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            with patch.object(
                collector,
                "_check_rkhunter",
                return_value={
                    "software_name": "rkhunter",
                    "install_path": "/usr/pkg/bin/rkhunter",
                    "version": "1.4.6",
                    "enabled": True,
                },
            ):
                result = collector._detect_bsd_antivirus()

        assert result["software_name"] == "rkhunter"

    def test_detect_openbsd_no_rkhunter_check(self, collector):
        """Test that rkhunter is not checked on OpenBSD."""
        collector.system = "OpenBSD"

        with patch.object(
            collector,
            "_check_clamav",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector._detect_bsd_antivirus()

        # OpenBSD doesn't check rkhunter, so should return empty
        assert result["software_name"] is None


class TestDeployedUpdatersCountAsEnabled:
    """2026-09-30: SysManage's deploy plan keeps signatures current with a
    launchd job (macOS) and a scheduled task (Windows) -- neither is the
    Homebrew service or Windows service detection used to look for, so a
    working install reported "not enabled"."""

    def test_macos_launchd_job_means_enabled(self, collector):
        found = {"software_name": "clamav", "enabled": False}
        with patch.object(
            collector, "_check_clamav", return_value=dict(found)
        ), patch.object(
            collector, "_is_launchd_job_loaded", return_value=True
        ) as loaded, patch.object(
            collector, "_is_brew_service_running", return_value=False
        ):
            assert collector._detect_macos_antivirus()["enabled"] is True
        loaded.assert_called_once_with("org.sysmanage.freshclam")

    def test_windows_update_task_means_enabled(self, collector):
        with patch("os.path.exists", return_value=True), patch.object(
            collector, "_get_clamav_windows_version", return_value="1.5.4"
        ), patch.object(
            collector, "_is_windows_task_enabled", return_value=True
        ) as task, patch.object(
            collector, "_is_windows_service_running", return_value=False
        ):
            info = collector._check_clamav_windows()
        assert info["software_name"] == "clamav" and info["enabled"] is True
        task.assert_called_once_with("SysManage ClamAV Update")

    def test_a_disabled_task_is_not_enabled(self, collector):
        ready = type(
            "R",
            (),
            {
                "returncode": 0,
                "stdout": '"\\\\SysManage ClamAV Update","N/A","Disabled"',
            },
        )
        with patch("subprocess.run", return_value=ready):
            assert (
                collector._is_windows_task_enabled("SysManage ClamAV Update") is False
            )

    def test_missing_task_or_job_is_not_enabled(self, collector):
        missing = type("R", (), {"returncode": 1, "stdout": ""})
        with patch("subprocess.run", return_value=missing):
            assert (
                collector._is_windows_task_enabled("SysManage ClamAV Update") is False
            )
            assert collector._is_launchd_job_loaded("org.sysmanage.freshclam") is False


def test_freebsd_freshclam_alone_means_enabled(collector):
    # FreeBSD's port names its updater clamav_freshclam; with clamd down (or
    # invisible to rc) a running updater still keeps signatures current.
    with patch("shutil.which", return_value="/usr/local/bin/clamscan"), patch.object(
        collector,
        "_is_service_running",
        side_effect=lambda name: name == "clamav_freshclam",
    ), patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "ClamAV 1.5.2/28139"
        info = collector._check_clamav()
    assert info["software_name"] == "clamav" and info["enabled"] is True
