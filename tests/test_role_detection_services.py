# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for role detection package/service status methods.
Split from test_role_detection.py to satisfy the 1000-line file limit.
"""

# pylint: disable=protected-access,unused-argument

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.role_detection import RoleDetector


class TestWindowsPackageMethods:
    """Test Windows-specific package methods."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        with patch("src.sysmanage_agent.collection.role_detection.platform.system"):
            detector = RoleDetector()
            detector.system = "windows"
            return detector

    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_windows_installed_programs"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_python_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_winget_packages"
    )
    def test_get_windows_packages_all_sources(
        self,
        mock_winget,
        mock_cmd_exists,
        mock_python,
        mock_installed,
        detector,
    ):
        """Test getting Windows packages from all sources."""
        mock_installed.return_value = {"postgresql": "14.5"}
        mock_python.return_value = {"sqlite3": "3.36.0"}
        mock_cmd_exists.return_value = True
        mock_winget.return_value = {"mysql": "8.0.30"}

        result = detector.package_detector._get_windows_packages()

        assert "postgresql" in result
        assert "sqlite3" in result
        assert "mysql" in result

    @patch("os.path.isdir")
    @patch("os.path.exists")
    @patch("os.listdir")
    def test_get_windows_installed_programs_postgresql(
        self, mock_listdir, mock_exists, mock_isdir, detector
    ):
        """Test detection of PostgreSQL in Windows."""
        mock_exists.side_effect = lambda path: "PostgreSQL" in path
        mock_listdir.return_value = ["14", "15"]
        mock_isdir.return_value = True

        result = detector.package_detector._get_windows_installed_programs()

        assert "postgresql" in result

    @patch("os.path.exists")
    @patch("os.listdir")
    def test_get_windows_installed_programs_mysql(
        self, mock_listdir, mock_exists, detector
    ):
        """Test detection of MySQL in Windows."""

        def exists_side_effect(path):
            if "PostgreSQL" in path:
                return False
            if "MySQL" in path:
                return True
            return False

        mock_exists.side_effect = exists_side_effect
        mock_listdir.return_value = ["MySQL Server 8.0"]

        result = detector.package_detector._get_windows_installed_programs()

        assert "mysql-server" in result
        assert result["mysql-server"] == "8.0"

    @patch("os.path.exists")
    @patch("os.listdir")
    def test_get_windows_installed_programs_exception(
        self, mock_listdir, mock_exists, detector
    ):
        """Test exception handling in Windows program detection."""
        mock_exists.return_value = True
        mock_listdir.side_effect = Exception("Test error")

        result = detector.package_detector._get_windows_installed_programs()

        assert result == {}

    @patch("subprocess.run")
    def test_get_python_packages_success(self, mock_run, detector):
        """Test successful Python SQLite detection."""
        mock_run.return_value = Mock(returncode=0, stdout="3.36.0\n")

        result = detector.package_detector._get_python_packages()

        assert result == {"sqlite3": "3.36.0"}

    @patch("subprocess.run")
    def test_get_python_packages_failure(self, mock_run, detector):
        """Test Python SQLite detection failure."""
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_python_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_winget_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful winget package retrieval."""
        mock_cmd_path.return_value = "winget"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Name  Id  Version  Available  Source\n-----\nPostgreSQL postgresql 14.5 14.6 winget\n",
        )

        result = detector.package_detector._get_winget_packages()

        assert "postgresql" in result

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_winget_packages_filters_databases(
        self, mock_cmd_path, mock_run, detector
    ):
        """Test winget package filtering for databases."""
        mock_cmd_path.return_value = "winget"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Name  Id  Version\n-----\nMySQL mysql 8.0\nSomeApp app 1.0\n",
        )

        result = detector.package_detector._get_winget_packages()

        assert "mysql" in result
        assert "someapp" not in result


class TestServiceStatusMethods:
    """Test service status detection methods."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_linux_service_status"
    )
    def test_get_service_status_linux(self, mock_linux_status, detector):
        """Test service status on Linux."""
        detector.system = "linux"
        detector.service_detector.system = "linux"
        mock_linux_status.return_value = "running"

        result = detector.service_detector.get_service_status("nginx")

        assert result == "running"
        mock_linux_status.assert_called_once_with("nginx")

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_macos_service_status"
    )
    def test_get_service_status_macos(self, mock_macos_status, detector):
        """Test service status on macOS."""
        detector.system = "darwin"
        detector.service_detector.system = "darwin"
        mock_macos_status.return_value = "running"

        result = detector.service_detector.get_service_status("nginx")

        assert result == "running"
        mock_macos_status.assert_called_once_with("nginx")

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_bsd_service_status"
    )
    def test_get_service_status_bsd(self, mock_bsd_status, detector):
        """Test service status on BSD."""
        detector.system = "freebsd"
        detector.service_detector.system = "freebsd"
        mock_bsd_status.return_value = "running"

        result = detector.service_detector.get_service_status("nginx")

        assert result == "running"
        mock_bsd_status.assert_called_once_with("nginx")

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_windows_service_status"
    )
    def test_get_service_status_windows(self, mock_windows_status, detector):
        """Test service status on Windows."""
        detector.system = "windows"
        detector.service_detector.system = "windows"
        mock_windows_status.return_value = "running"

        result = detector.service_detector.get_service_status("nginx")

        assert result == "running"
        mock_windows_status.assert_called_once_with("nginx")

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_linux_service_status"
    )
    def test_get_service_status_exception(self, mock_linux_status, detector):
        """Test service status with exception."""
        detector.system = "linux"
        detector.service_detector.system = "linux"
        mock_linux_status.side_effect = Exception("Test error")

        result = detector.service_detector.get_service_status("nginx")

        assert result == "unknown"


class TestLinuxServiceStatus:
    """Test Linux service status detection."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        detector = RoleDetector()
        detector.system = "linux"
        return detector

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._command_exists"
    )
    def test_linux_service_status_systemctl_running(
        self, mock_cmd_exists, mock_cmd_path, mock_run, detector
    ):
        """Test Linux service status with systemctl - running."""
        mock_cmd_exists.return_value = False
        mock_cmd_path.return_value = "/usr/bin/systemctl"
        mock_run.return_value = Mock(returncode=0, stdout="active\n")

        result = detector.service_detector._get_linux_service_status("nginx")

        assert result == "running"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._command_exists"
    )
    def test_linux_service_status_systemctl_stopped(
        self, mock_cmd_exists, mock_cmd_path, mock_run, detector
    ):
        """Test Linux service status with systemctl - stopped."""
        mock_cmd_exists.return_value = False
        mock_cmd_path.return_value = "/usr/bin/systemctl"
        mock_run.return_value = Mock(returncode=3, stdout="inactive\n")

        result = detector.service_detector._get_linux_service_status("nginx")

        assert result == "stopped"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._command_exists"
    )
    def test_linux_service_status_service_command(
        self, mock_cmd_exists, mock_cmd_path, mock_run, detector
    ):
        """Test Linux service status with service command."""
        mock_cmd_exists.return_value = False

        def cmd_path_side_effect(cmd):
            if cmd == "systemctl":
                return None
            if cmd == "service":
                return "/usr/sbin/service"
            return None

        mock_cmd_path.side_effect = cmd_path_side_effect
        mock_run.return_value = Mock(returncode=0)

        result = detector.service_detector._get_linux_service_status("nginx")

        assert result == "running"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_snap_service_status"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._command_exists"
    )
    def test_linux_service_status_snap(
        self, mock_cmd_exists, mock_cmd_path, mock_snap_status, mock_run, detector
    ):
        """Test Linux service status with snap services."""
        mock_cmd_exists.return_value = True
        mock_snap_status.return_value = "running"

        result = detector.service_detector._get_linux_service_status("nginx")

        assert result == "running"
        mock_snap_status.assert_called_once_with("nginx")


class TestMacOSServiceStatus:
    """Test macOS service status detection."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        detector = RoleDetector()
        detector.system = "darwin"
        return detector

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._check_brew_services"
    )
    def test_macos_service_status_brew_running(self, mock_brew_services, detector):
        """Test macOS service status with brew services - running."""
        mock_brew_services.return_value = "running"

        result = detector.service_detector._get_macos_service_status("nginx")

        assert result == "running"

    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._check_brew_services"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._check_process_status"
    )
    def test_macos_service_status_fallback_to_process(
        self, mock_process_status, mock_brew_services, detector
    ):
        """Test macOS service status fallback to process check."""
        mock_brew_services.return_value = "unknown"
        mock_process_status.return_value = "running"

        result = detector.service_detector._get_macos_service_status("nginx")

        assert result == "running"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.os.getuid",
        create=True,
    )
    @patch("os.environ.get")
    def test_check_brew_services_as_root(
        self, mock_env_get, mock_getuid, mock_cmd_path, mock_run, detector
    ):
        """Test brew services check as root user."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_getuid.return_value = 0
        mock_env_get.return_value = "testuser"
        mock_run.return_value = Mock(
            returncode=0, stdout="Name  Status\nnginx started\n"
        )

        result = detector.service_detector._check_brew_services("nginx")

        assert result == "running"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.os.getuid",
        return_value=1000,
        create=True,
    )
    def test_check_brew_services_stopped(
        self, mock_getuid, mock_cmd_path, mock_run, detector
    ):
        """Test brew services check - stopped."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_run.return_value = Mock(
            returncode=0, stdout="Name  Status\nnginx stopped\n"
        )

        result = detector.service_detector._check_brew_services("nginx")

        assert result == "stopped"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_check_brew_services_not_found(self, mock_cmd_path, mock_run, detector):
        """Test brew services check - service not found."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_run.return_value = Mock(
            returncode=0, stdout="Name  Status\napache started\n"
        )

        result = detector.service_detector._check_brew_services("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    def test_check_process_status_running(self, mock_run, detector):
        """Test process status check - running."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="user  1234  0.0  0.1  12345  6789  ?  S  10:00  0:00 nginx: master process\n",
        )

        result = detector.service_detector._check_process_status("nginx")

        assert result == "running"

    @patch("subprocess.run")
    def test_check_process_status_postgresql_variant(self, mock_run, detector):
        """Test process status check for PostgreSQL variant."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="user  1234  0.0  0.1  12345  6789  ?  S  10:00  0:00 postgres: master process\n",
        )

        result = detector.service_detector._check_process_status("postgresql")

        assert result == "running"

    @patch("subprocess.run")
    def test_check_process_status_not_running(self, mock_run, detector):
        """Test process status check - not running."""
        mock_run.return_value = Mock(returncode=0, stdout="user  1234  apache\n")

        result = detector.service_detector._check_process_status("nginx")

        assert result == "stopped"

    @patch("subprocess.run")
    def test_check_process_status_filters_grep(self, mock_run, detector):
        """Test process status check filters out grep processes."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="user  1234  0.0  0.1  12345  6789  ?  S  10:00  0:00 grep nginx\n",
        )

        result = detector.service_detector._check_process_status("nginx")

        assert result == "stopped"


class TestBSDServiceStatus:
    """Test BSD service status detection."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        detector = RoleDetector()
        detector.system = "freebsd"
        return detector

    @patch("subprocess.run")
    def test_bsd_service_status_process_running(self, mock_run, detector):
        """Test BSD service status via process check - running."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="user  1234  0.0  0.1  12345  6789  ?  S  10:00  0:00 nginx: master\n",
        )

        result = detector.service_detector._get_bsd_service_status("nginx")

        assert result == "running"

    @patch("subprocess.run")
    def test_bsd_service_status_service_command(self, mock_run, detector):
        """Test BSD service status with service command as fallback."""
        # First call is ps aux which fails (returncode != 0)
        # This triggers the fallback to service command
        ps_result = Mock(returncode=1, stdout="")
        service_result = Mock(returncode=0)
        mock_run.side_effect = [ps_result, service_result]

        with patch.object(
            detector.service_detector,
            "_get_command_path",
            return_value="/usr/sbin/service",
        ):
            result = detector.service_detector._get_bsd_service_status("nginx")

        # Service command returns success, so service is running
        assert result == "running"

    @patch("subprocess.run")
    def test_bsd_service_status_stopped(self, mock_run, detector):
        """Test BSD service status - stopped."""
        mock_run.return_value = Mock(returncode=0, stdout="other process\n")

        result = detector.service_detector._get_bsd_service_status("nginx")

        assert result == "stopped"


class TestSnapServiceStatus:
    """Test snap service status detection."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_snap_service_status_active(self, mock_cmd_path, mock_run, detector):
        """Test snap service status - active."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Service  Startup  Current  Notes\nnginx.nginx  enabled  active  -\n",
        )

        result = detector.service_detector._get_snap_service_status("nginx")

        assert result == "running"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_snap_service_status_inactive(self, mock_cmd_path, mock_run, detector):
        """Test snap service status - inactive."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Service  Startup  Current  Notes\nnginx.nginx  disabled  inactive  -\n",
        )

        result = detector.service_detector._get_snap_service_status("nginx")

        assert result == "stopped"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_snap_service_status_error(self, mock_cmd_path, mock_run, detector):
        """Test snap service status - command error."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.service_detector._get_snap_service_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_snap_service_status_exception(self, mock_cmd_path, mock_run, detector):
        """Test snap service status - exception."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.side_effect = Exception("Test error")

        result = detector.service_detector._get_snap_service_status("nginx")

        assert result == "unknown"

    def test_is_snap_service_match_exact(self, detector):
        """Test snap service name matching - exact match."""
        assert (
            detector.service_detector._is_snap_service_match("nginx", "nginx") is True
        )

    def test_is_snap_service_match_contains(self, detector):
        """Test snap service name matching - contains."""
        assert (
            detector.service_detector._is_snap_service_match("nginx.service", "nginx")
            is True
        )

    def test_is_snap_service_match_dotted(self, detector):
        """Test snap service name matching - dotted notation."""
        assert (
            detector.service_detector._is_snap_service_match("snap.nginx", "nginx")
            is True
        )

    def test_is_snap_service_match_no_match(self, detector):
        """Test snap service name matching - no match."""
        assert (
            detector.service_detector._is_snap_service_match("apache", "nginx") is False
        )
