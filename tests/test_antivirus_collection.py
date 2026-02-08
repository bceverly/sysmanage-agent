"""
Tests for antivirus collection module.
Tests detection of antivirus software (ClamAV, chkrootkit, rkhunter) on various platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

import os
from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.collection.antivirus_collection import AntivirusCollector


@pytest.fixture
def collector():
    """Create an AntivirusCollector instance for testing."""
    return AntivirusCollector()


class TestAntivirusCollectorInit:
    """Tests for AntivirusCollector initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None

    def test_init_detects_system(self, collector):
        """Test that __init__ detects system."""
        assert collector.system is not None


class TestCollectAntivirusStatus:
    """Tests for collect_antivirus_status method."""

    def test_collect_status_linux(self, collector):
        """Test status collection on Linux."""
        collector.system = "Linux"

        with patch.object(
            collector,
            "_detect_linux_antivirus",
            return_value={
                "software_name": "clamav",
                "install_path": "/usr/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector.collect_antivirus_status()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_collect_status_macos(self, collector):
        """Test status collection on macOS."""
        collector.system = "Darwin"

        with patch.object(
            collector,
            "_detect_macos_antivirus",
            return_value={
                "software_name": "clamav",
                "install_path": "/opt/homebrew/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector.collect_antivirus_status()

        assert result["software_name"] == "clamav"

    def test_collect_status_windows(self, collector):
        """Test status collection on Windows."""
        collector.system = "Windows"

        with patch.object(
            collector,
            "_detect_windows_antivirus",
            return_value={
                "software_name": "clamav",
                "install_path": "C:\\Program Files\\ClamAV\\clamscan.exe",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector.collect_antivirus_status()

        assert result["software_name"] == "clamav"

    def test_collect_status_bsd(self, collector):
        """Test status collection on BSD."""
        collector.system = "FreeBSD"

        with patch.object(
            collector,
            "_detect_bsd_antivirus",
            return_value={
                "software_name": "clamav",
                "install_path": "/usr/local/bin/clamscan",
                "version": "1.0.0",
                "enabled": True,
            },
        ):
            result = collector.collect_antivirus_status()

        assert result["software_name"] == "clamav"

    def test_collect_status_no_antivirus(self, collector):
        """Test status collection when no antivirus is found."""
        collector.system = "Linux"

        with patch.object(
            collector,
            "_detect_linux_antivirus",
            return_value={
                "software_name": None,
                "install_path": None,
                "version": None,
                "enabled": None,
            },
        ):
            result = collector.collect_antivirus_status()

        assert result["software_name"] is None

    def test_collect_status_exception(self, collector):
        """Test status collection handles exceptions."""
        collector.system = "Linux"

        with patch.object(
            collector,
            "_detect_linux_antivirus",
            side_effect=Exception("Detection failed"),
        ):
            result = collector.collect_antivirus_status()

        assert result["software_name"] is None


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


class TestCheckClamav:
    """Tests for _check_clamav method."""

    def test_check_clamav_installed_and_running(self, collector):
        """Test ClamAV check when installed and running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0/26853/Mon Jan 1 00:00:00 2024\n"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(collector, "_is_service_running", return_value=True):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["version"] == "1.0.0"
        assert result["enabled"] is True

    def test_check_clamav_installed_not_running(self, collector):
        """Test ClamAV check when installed but not running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0/26853/Mon Jan 1 00:00:00 2024\n"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(collector, "_is_service_running", return_value=False):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is False

    def test_check_clamav_not_installed(self, collector):
        """Test ClamAV check when not installed."""
        which_result = Mock()
        which_result.returncode = 1
        which_result.stdout = ""

        with patch("subprocess.run", return_value=which_result):
            result = collector._check_clamav()

        assert result["software_name"] is None

    def test_check_clamav_version_parsing_error(self, collector):
        """Test ClamAV check with version parsing error."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 1
        version_result.stdout = ""

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(collector, "_is_service_running", return_value=False):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["version"] is None

    def test_check_clamav_exception(self, collector):
        """Test ClamAV check handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = collector._check_clamav()

        assert result["software_name"] is None


class TestCheckClamavWindows:
    """Tests for _check_clamav_windows method."""

    def test_check_clamav_windows_installed(self, collector):
        """Test ClamAV check on Windows when installed."""
        with patch("os.path.exists", side_effect=[True]):
            with patch.object(
                collector,
                "_get_clamav_windows_version",
                return_value="1.0.0",
            ):
                with patch.object(
                    collector,
                    "_is_windows_service_running",
                    return_value=True,
                ):
                    result = collector._check_clamav_windows()

        assert result["software_name"] == "clamav"
        assert result["version"] == "1.0.0"
        assert result["enabled"] is True

    def test_check_clamav_windows_second_path(self, collector):
        """Test ClamAV check on Windows in x86 path."""
        with patch("os.path.exists", side_effect=[False, True]):
            with patch.object(
                collector,
                "_get_clamav_windows_version",
                return_value="1.0.0",
            ):
                with patch.object(
                    collector,
                    "_is_windows_service_running",
                    return_value=False,
                ):
                    result = collector._check_clamav_windows()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is False

    def test_check_clamav_windows_not_installed(self, collector):
        """Test ClamAV check on Windows when not installed."""
        with patch("os.path.exists", return_value=False):
            result = collector._check_clamav_windows()

        assert result["software_name"] is None

    def test_check_clamav_windows_exception(self, collector):
        """Test ClamAV check on Windows handles exceptions."""
        with patch("os.path.exists", side_effect=Exception("Access denied")):
            result = collector._check_clamav_windows()

        assert result["software_name"] is None


class TestCheckChkrootkit:
    """Tests for _check_chkrootkit method."""

    def test_check_chkrootkit_installed(self, collector):
        """Test chkrootkit check when installed."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/chkrootkit\n"

        with patch("subprocess.run", return_value=which_result):
            with patch.object(
                collector,
                "_get_chkrootkit_version",
                return_value="0.55",
            ):
                with patch.object(collector, "_is_in_cron", return_value=True):
                    result = collector._check_chkrootkit()

        assert result["software_name"] == "chkrootkit"
        assert result["version"] == "0.55"
        assert result["enabled"] is True

    def test_check_chkrootkit_not_in_cron(self, collector):
        """Test chkrootkit check when not in cron."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/chkrootkit\n"

        with patch("subprocess.run", return_value=which_result):
            with patch.object(
                collector,
                "_get_chkrootkit_version",
                return_value="0.55",
            ):
                with patch.object(collector, "_is_in_cron", return_value=False):
                    result = collector._check_chkrootkit()

        assert result["software_name"] == "chkrootkit"
        # enabled defaults to False when not in cron
        assert result["enabled"] is False

    def test_check_chkrootkit_cron_unknown(self, collector):
        """Test chkrootkit check when cron status is unknown."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/chkrootkit\n"

        with patch("subprocess.run", return_value=which_result):
            with patch.object(
                collector,
                "_get_chkrootkit_version",
                return_value="0.55",
            ):
                with patch.object(collector, "_is_in_cron", return_value=None):
                    result = collector._check_chkrootkit()

        # enabled defaults to True when cron check returns None
        assert result["enabled"] is True

    def test_check_chkrootkit_not_installed(self, collector):
        """Test chkrootkit check when not installed."""
        which_result = Mock()
        which_result.returncode = 1
        which_result.stdout = ""

        with patch("subprocess.run", return_value=which_result):
            result = collector._check_chkrootkit()

        assert result["software_name"] is None

    def test_check_chkrootkit_exception(self, collector):
        """Test chkrootkit check handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = collector._check_chkrootkit()

        assert result["software_name"] is None


class TestCheckRkhunter:
    """Tests for _check_rkhunter method."""

    def test_check_rkhunter_installed(self, collector):
        """Test rkhunter check when installed."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/rkhunter\n"

        with patch("subprocess.run", return_value=which_result):
            with patch.object(
                collector,
                "_get_rkhunter_version",
                return_value="1.4.6",
            ):
                with patch.object(collector, "_is_in_cron", return_value=True):
                    result = collector._check_rkhunter()

        assert result["software_name"] == "rkhunter"
        assert result["version"] == "1.4.6"
        assert result["enabled"] is True

    def test_check_rkhunter_not_installed(self, collector):
        """Test rkhunter check when not installed."""
        which_result = Mock()
        which_result.returncode = 1
        which_result.stdout = ""

        with patch("subprocess.run", return_value=which_result):
            result = collector._check_rkhunter()

        assert result["software_name"] is None

    def test_check_rkhunter_exception(self, collector):
        """Test rkhunter check handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = collector._check_rkhunter()

        assert result["software_name"] is None


class TestIsServiceRunning:
    """Tests for _is_service_running method."""

    def test_service_running_rcctl_openbsd(self, collector):
        """Test service running check with rcctl on OpenBSD."""
        rcctl_result = Mock()
        rcctl_result.returncode = 0

        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run", return_value=rcctl_result):
                result = collector._is_service_running("clamd")

        assert result is True

    def test_service_not_running_rcctl(self, collector):
        """Test service not running with rcctl."""
        rcctl_result = Mock()
        rcctl_result.returncode = 1

        systemctl_result = Mock()
        systemctl_result.returncode = 1
        systemctl_result.stdout = ""

        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run", side_effect=[rcctl_result, systemctl_result]):
                result = collector._is_service_running("clamd")

        assert result is False

    def test_service_running_systemctl(self, collector):
        """Test service running check with systemctl."""
        systemctl_result = Mock()
        systemctl_result.returncode = 0
        systemctl_result.stdout = "active\n"

        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run", return_value=systemctl_result):
                result = collector._is_service_running("clamd")

        assert result is True

    def test_service_running_sysv_init(self, collector):
        """Test service running check with SysV init."""
        systemctl_result = Mock()
        systemctl_result.returncode = 1
        systemctl_result.stdout = ""

        service_result = Mock()
        service_result.returncode = 0

        with patch("os.path.exists", return_value=False):
            with patch(
                "subprocess.run",
                side_effect=[
                    FileNotFoundError(),  # systemctl not found
                    service_result,
                ],
            ):
                result = collector._is_service_running("clamd")

        assert result is True

    def test_service_check_exception(self, collector):
        """Test service check handles exceptions."""
        with patch("os.path.exists", side_effect=Exception("Access denied")):
            result = collector._is_service_running("clamd")

        assert result is False


class TestIsWindowsServiceRunning:
    """Tests for _is_windows_service_running method."""

    def test_windows_service_running(self, collector):
        """Test Windows service running check."""
        sc_result = Mock()
        sc_result.returncode = 0
        sc_result.stdout = "STATE: RUNNING"

        with patch("subprocess.run", return_value=sc_result):
            result = collector._is_windows_service_running("ClamAV")

        assert result is True

    def test_windows_service_stopped(self, collector):
        """Test Windows service stopped check."""
        sc_result = Mock()
        sc_result.returncode = 0
        sc_result.stdout = "STATE: STOPPED"

        with patch("subprocess.run", return_value=sc_result):
            result = collector._is_windows_service_running("ClamAV")

        assert result is False

    def test_windows_service_not_found(self, collector):
        """Test Windows service not found."""
        sc_result = Mock()
        sc_result.returncode = 1060  # Service not found
        sc_result.stdout = ""

        with patch("subprocess.run", return_value=sc_result):
            result = collector._is_windows_service_running("ClamAV")

        assert result is False

    def test_windows_service_exception(self, collector):
        """Test Windows service check handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Access denied")):
            result = collector._is_windows_service_running("ClamAV")

        assert result is False


class TestIsInCron:
    """Tests for _is_in_cron method."""

    def test_is_in_cron_user_crontab(self, collector):
        """Test cron check finds entry in user crontab."""
        crontab_result = Mock()
        crontab_result.returncode = 0
        crontab_result.stdout = "0 0 * * * /usr/bin/chkrootkit\n"

        with patch("subprocess.run", return_value=crontab_result):
            result = collector._is_in_cron("chkrootkit")

        assert result is True

    def test_is_in_cron_not_in_user_crontab(self, collector):
        """Test cron check when not in user crontab."""
        crontab_result = Mock()
        crontab_result.returncode = 0
        crontab_result.stdout = "0 0 * * * /usr/bin/other\n"

        with patch("subprocess.run", return_value=crontab_result):
            with patch("os.path.exists", return_value=False):
                result = collector._is_in_cron("chkrootkit")

        assert result is False

    def test_is_in_cron_system_cron_d(self, collector):
        """Test cron check finds entry in /etc/cron.d."""
        crontab_result = Mock()
        crontab_result.returncode = 0
        crontab_result.stdout = ""

        with patch("subprocess.run", return_value=crontab_result):
            with patch.object(
                collector,
                "_check_cron_directory",
                side_effect=[True, False, False, False],
            ):
                result = collector._is_in_cron("chkrootkit")

        assert result is True

    def test_is_in_cron_system_daily(self, collector):
        """Test cron check finds entry in /etc/cron.daily."""
        crontab_result = Mock()
        crontab_result.returncode = 0
        crontab_result.stdout = ""

        with patch("subprocess.run", return_value=crontab_result):
            with patch.object(
                collector,
                "_check_cron_directory",
                side_effect=[False, True, False, False],
            ):
                result = collector._is_in_cron("chkrootkit")

        assert result is True

    def test_is_in_cron_exception(self, collector):
        """Test cron check handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = collector._is_in_cron("chkrootkit")

        assert result is None


class TestCheckCronFile:
    """Tests for _check_cron_file method."""

    def test_check_cron_file_found(self, collector):
        """Test cron file check when command is found."""
        cron_content = "0 0 * * * /usr/bin/chkrootkit -q"

        with patch("builtins.open", mock_open(read_data=cron_content)):
            result = collector._check_cron_file("/etc/cron.d/chkrootkit", "chkrootkit")

        assert result is True

    def test_check_cron_file_not_found(self, collector):
        """Test cron file check when command is not found."""
        cron_content = "0 0 * * * /usr/bin/other-command"

        with patch("builtins.open", mock_open(read_data=cron_content)):
            result = collector._check_cron_file("/etc/cron.d/other", "chkrootkit")

        assert result is False

    def test_check_cron_file_exception(self, collector):
        """Test cron file check handles exceptions."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = collector._check_cron_file("/etc/cron.d/chkrootkit", "chkrootkit")

        assert result is False


class TestCheckCronDirectory:
    """Tests for _check_cron_directory method."""

    def test_check_cron_directory_found(self, collector):
        """Test cron directory check when command is found."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["chkrootkit", "other"]):
                with patch("os.path.isfile", return_value=True):
                    with patch.object(
                        collector,
                        "_check_cron_file",
                        side_effect=[True, False],
                    ):
                        result = collector._check_cron_directory(
                            "/etc/cron.daily", "chkrootkit"
                        )

        assert result is True

    def test_check_cron_directory_not_found(self, collector):
        """Test cron directory check when command is not found."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", return_value=["other"]):
                with patch("os.path.isfile", return_value=True):
                    with patch.object(
                        collector,
                        "_check_cron_file",
                        return_value=False,
                    ):
                        result = collector._check_cron_directory(
                            "/etc/cron.daily", "chkrootkit"
                        )

        assert result is False

    def test_check_cron_directory_does_not_exist(self, collector):
        """Test cron directory check when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = collector._check_cron_directory("/etc/cron.daily", "chkrootkit")

        assert result is False


class TestIsBrewServiceRunning:
    """Tests for _is_brew_service_running method."""

    def test_brew_service_running_opt_homebrew(self, collector):
        """Test brew service running check with /opt/homebrew."""
        brew_result = Mock()
        brew_result.returncode = 0
        brew_result.stdout = "clamav  started  user  /path/to/plist"

        with patch("os.path.exists", side_effect=[True]):
            with patch("subprocess.run", return_value=brew_result):
                result = collector._is_brew_service_running("clamav")

        assert result is True

    def test_brew_service_running_usr_local(self, collector):
        """Test brew service running check with /usr/local."""
        brew_result = Mock()
        brew_result.returncode = 0
        brew_result.stdout = "clamav  started  user  /path/to/plist"

        with patch("os.path.exists", side_effect=[False]):
            with patch("subprocess.run", return_value=brew_result):
                result = collector._is_brew_service_running("clamav")

        assert result is True

    def test_brew_service_not_running(self, collector):
        """Test brew service not running."""
        brew_result = Mock()
        brew_result.returncode = 0
        brew_result.stdout = "clamav  stopped  user  /path/to/plist"

        with patch("os.path.exists", side_effect=[True]):
            with patch("subprocess.run", return_value=brew_result):
                result = collector._is_brew_service_running("clamav")

        assert result is False

    def test_brew_service_not_found(self, collector):
        """Test brew service when service not in list."""
        brew_result = Mock()
        brew_result.returncode = 0
        brew_result.stdout = "other-service  started  user  /path/to/plist"

        with patch("os.path.exists", side_effect=[True]):
            with patch("subprocess.run", return_value=brew_result):
                result = collector._is_brew_service_running("clamav")

        assert result is False

    def test_brew_command_failure(self, collector):
        """Test brew service when command fails."""
        brew_result = Mock()
        brew_result.returncode = 1
        brew_result.stdout = ""

        with patch("os.path.exists", side_effect=[True]):
            with patch("subprocess.run", return_value=brew_result):
                result = collector._is_brew_service_running("clamav")

        assert result is False

    def test_brew_service_exception(self, collector):
        """Test brew service handles exceptions."""
        with patch("os.path.exists", side_effect=Exception("Access denied")):
            result = collector._is_brew_service_running("clamav")

        assert result is False


class TestVersionParsing:
    """Tests for version parsing methods."""

    def test_get_chkrootkit_version(self, collector):
        """Test chkrootkit version parsing."""
        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "chkrootkit version 0.55\n"

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_chkrootkit_version()

        assert result == "0.55"

    def test_get_chkrootkit_version_failure(self, collector):
        """Test chkrootkit version parsing when command fails."""
        version_result = Mock()
        version_result.returncode = 1
        version_result.stdout = ""

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_chkrootkit_version()

        assert result is None

    def test_get_chkrootkit_version_no_match(self, collector):
        """Test chkrootkit version parsing when no match."""
        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "unexpected output"

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_chkrootkit_version()

        assert result is None

    def test_get_rkhunter_version(self, collector):
        """Test rkhunter version parsing."""
        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "Rkhunter version 1.4.6\n"

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_rkhunter_version()

        assert result == "1.4.6"

    def test_get_rkhunter_version_failure(self, collector):
        """Test rkhunter version parsing when command fails."""
        version_result = Mock()
        version_result.returncode = 1
        version_result.stdout = ""

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_rkhunter_version()

        assert result is None

    def test_parse_rkhunter_version(self, collector):
        """Test rkhunter version parsing."""
        # The parser looks for lines containing "rkhunter" and finds first digit part
        output = "Rkhunter version 1.4.6\nSome other line"
        result = collector._parse_rkhunter_version(output)
        assert result == "1.4.6"

    def test_parse_rkhunter_version_no_match(self, collector):
        """Test rkhunter version parsing with no match."""
        output = "Some random output"
        result = collector._parse_rkhunter_version(output)
        assert result is None

    def test_get_clamav_windows_version(self, collector):
        """Test ClamAV Windows version parsing."""
        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0/26853/Mon Jan 1 00:00:00 2024"

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_clamav_windows_version(
                "C:\\Program Files\\ClamAV\\clamscan.exe"
            )

        assert result == "1.0.0"

    def test_get_clamav_windows_version_failure(self, collector):
        """Test ClamAV Windows version parsing when command fails."""
        version_result = Mock()
        version_result.returncode = 1
        version_result.stdout = ""

        with patch("subprocess.run", return_value=version_result):
            result = collector._get_clamav_windows_version(
                "C:\\Program Files\\ClamAV\\clamscan.exe"
            )

        assert result is None

    def test_get_clamav_windows_version_exception(self, collector):
        """Test ClamAV Windows version parsing handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Access denied")):
            result = collector._get_clamav_windows_version(
                "C:\\Program Files\\ClamAV\\clamscan.exe"
            )

        assert result is None


class TestMultipleServiceChecks:
    """Tests for checking multiple service names for ClamAV."""

    def test_check_clamav_clamd_running(self, collector):
        """Test ClamAV check when clamd is running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0\n"

        def is_service_running_side_effect(name):
            return name == "clamd"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(
                collector,
                "_is_service_running",
                side_effect=is_service_running_side_effect,
            ):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_check_clamav_freshclamd_running(self, collector):
        """Test ClamAV check when freshclamd is running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0\n"

        def is_service_running_side_effect(name):
            return name == "freshclamd"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(
                collector,
                "_is_service_running",
                side_effect=is_service_running_side_effect,
            ):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_check_clamav_debian_service_running(self, collector):
        """Test ClamAV check when Debian clamav-daemon is running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0\n"

        def is_service_running_side_effect(name):
            return name == "clamav-daemon"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(
                collector,
                "_is_service_running",
                side_effect=is_service_running_side_effect,
            ):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_check_clamav_rhel_service_running(self, collector):
        """Test ClamAV check when RHEL clamd@scan is running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0\n"

        def is_service_running_side_effect(name):
            return name == "clamd@scan"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(
                collector,
                "_is_service_running",
                side_effect=is_service_running_side_effect,
            ):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True

    def test_check_clamav_freebsd_service_running(self, collector):
        """Test ClamAV check when FreeBSD clamav_clamd is running."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/bin/clamscan\n"

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "ClamAV 1.0.0\n"

        def is_service_running_side_effect(name):
            return name == "clamav_clamd"

        with patch("subprocess.run", side_effect=[which_result, version_result]):
            with patch.object(
                collector,
                "_is_service_running",
                side_effect=is_service_running_side_effect,
            ):
                result = collector._check_clamav()

        assert result["software_name"] == "clamav"
        assert result["enabled"] is True
