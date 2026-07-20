# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for role detection Windows service status, utility, and edge cases.
Split from test_role_detection.py to satisfy the 1000-line file limit.
"""

# pylint: disable=protected-access,unused-argument

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.role_detection import RoleDetector


class TestWindowsServiceStatus:
    """Test Windows service status detection."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        detector = RoleDetector()
        detector.system = "windows"
        return detector

    @patch("subprocess.run")
    def test_windows_service_status_postgresql_running(self, mock_run, detector):
        """Test Windows service status - PostgreSQL running."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="SERVICE_NAME: postgresql-x64-14\n        STATE              : 4  RUNNING\n",
        )

        result = detector.service_detector._get_windows_service_status("postgresql")

        assert result == "running"

    @patch("subprocess.run")
    def test_windows_service_status_mysql_stopped(self, mock_run, detector):
        """Test Windows service status - MySQL stopped."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="SERVICE_NAME: MySQL80\n        STATE              : 1  STOPPED\n",
        )

        result = detector.service_detector._get_windows_service_status("mysql")

        assert result == "stopped"

    @patch("subprocess.run")
    def test_windows_service_status_not_found(self, mock_run, detector):
        """Test Windows service status - service not found."""
        mock_run.return_value = Mock(returncode=0, stdout="SERVICE_NAME: other\n")

        result = detector.service_detector._get_windows_service_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    def test_windows_service_status_exception(self, mock_run, detector):
        """Test Windows service status - exception."""
        mock_run.side_effect = Exception("Test error")

        result = detector.service_detector._get_windows_service_status("nginx")

        assert result == "unknown"

    def test_matches_service_pattern_exact(self, detector):
        """Test Windows service pattern matching - exact."""
        assert (
            detector.service_detector._matches_service_pattern("MySQL80", "MySQL80")
            is True
        )

    def test_matches_service_pattern_wildcard(self, detector):
        """Test Windows service pattern matching - wildcard."""
        assert (
            detector.service_detector._matches_service_pattern("MySQL80", "MySQL*")
            is True
        )

    def test_matches_service_pattern_substring(self, detector):
        """Test Windows service pattern matching - substring."""
        assert (
            detector.service_detector._matches_service_pattern(
                "postgresql-x64-14", "postgresql"
            )
            is True
        )

    def test_matches_service_pattern_no_match(self, detector):
        """Test Windows service pattern matching - no match."""
        assert (
            detector.service_detector._matches_service_pattern("Apache", "nginx")
            is False
        )


class TestUtilityMethods:
    """Test utility methods."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch("shutil.which")
    def test_command_exists_true(self, mock_which, detector):
        """Test command exists check - command found."""
        mock_which.return_value = "/usr/bin/nginx"

        result = detector.package_detector._command_exists("nginx")

        assert result is True

    @patch("shutil.which")
    def test_command_exists_false(self, mock_which, detector):
        """Test command exists check - command not found."""
        mock_which.return_value = None

        result = detector.package_detector._command_exists("nonexistent")

        assert result is False

    @patch("shutil.which")
    def test_get_command_path_found(self, mock_which, detector):
        """Test get command path - found."""
        mock_which.return_value = "/usr/bin/nginx"

        result = detector.package_detector._get_command_path("nginx")

        assert result == "/usr/bin/nginx"

    @patch("shutil.which")
    def test_get_command_path_not_found(self, mock_which, detector):
        """Test get command path - not found."""
        mock_which.return_value = None

        result = detector.package_detector._get_command_path("nonexistent")

        assert result is None

    def test_find_package_version_exact_match(self, detector):
        """Test finding package version - exact match."""
        packages = {"nginx": "1.18.0", "apache2": "2.4.41"}

        result = detector.package_detector.find_package_version("nginx", packages)

        assert result == "1.18.0"

    def test_find_package_version_pattern_match(self, detector):
        """Test finding package version - pattern match."""
        packages = {"postgresql14-server": "14.5", "postgresql15-server": "15.2"}

        result = detector.package_detector.find_package_version("postgresql", packages)

        assert result in ["14.5", "15.2"]

    def test_find_package_version_not_found(self, detector):
        """Test finding package version - not found."""
        packages = {"nginx": "1.18.0"}

        result = detector.package_detector.find_package_version("apache", packages)

        assert result is None


class TestAdditionalCoverage:
    """Additional tests to increase coverage."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_dpkg_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_snap_packages"
    )
    def test_get_installed_packages_linux_with_snap(
        self, mock_snap, mock_dpkg, mock_cmd_exists, detector
    ):
        """Test getting packages on Linux with both dpkg and snap."""
        detector.system = "linux"
        detector.package_detector.system = "linux"
        mock_cmd_exists.side_effect = lambda cmd: cmd in ["dpkg", "snap"]
        mock_dpkg.return_value = {"nginx": "1.18.0"}
        mock_snap.return_value = {"grafana": "9.3.2"}

        result = detector.package_detector.get_installed_packages()

        assert "nginx" in result
        assert "grafana" in result

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkgin_packages_error(self, mock_cmd_path, mock_run, detector):
        """Test pkgin package retrieval with error."""
        mock_cmd_path.return_value = "/usr/pkg/bin/pkgin"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_pkgin_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkgin_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test pkgin package retrieval with exception."""
        mock_cmd_path.return_value = "/usr/pkg/bin/pkgin"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_pkgin_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkg_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test pkg package retrieval with exception."""
        mock_cmd_path.return_value = "/usr/sbin/pkg"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_pkg_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_snap_packages_error(self, mock_cmd_path, mock_run, detector):
        """Test snap package retrieval with error."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_snap_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_snap_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test snap package retrieval with exception."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_snap_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_homebrew_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test Homebrew package retrieval with exception."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_homebrew_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pacman_packages_error(self, mock_cmd_path, mock_run, detector):
        """Test pacman package retrieval with error."""
        mock_cmd_path.return_value = "/usr/bin/pacman"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_pacman_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pacman_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test pacman package retrieval with exception."""
        mock_cmd_path.return_value = "/usr/bin/pacman"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_pacman_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._command_exists"
    )
    def test_linux_service_status_no_commands(
        self, mock_cmd_exists, mock_cmd_path, mock_run, detector
    ):
        """Test Linux service status when no service commands exist."""
        detector.system = "linux"
        mock_cmd_exists.return_value = False
        mock_cmd_path.return_value = None

        result = detector.service_detector._get_linux_service_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._check_brew_services"
    )
    def test_macos_service_status_process_exception(
        self, mock_brew_services, mock_run, detector
    ):
        """Test macOS service status with process check exception."""
        detector.system = "darwin"
        mock_brew_services.return_value = "unknown"
        # Process check should raise exception
        mock_run.side_effect = Exception("Test error")

        result = detector.service_detector._get_macos_service_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_check_brew_services_exception(self, mock_cmd_path, mock_run, detector):
        """Test brew services check with exception."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_run.side_effect = Exception("Test error")

        result = detector.service_detector._check_brew_services("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    def test_check_process_status_exception(self, mock_run, detector):
        """Test process status check with exception."""
        mock_run.side_effect = Exception("Test error")

        result = detector.service_detector._check_process_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    def test_check_process_status_error(self, mock_run, detector):
        """Test process status check with command error."""
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.service_detector._check_process_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_snap_service_status_empty_lines(self, mock_cmd_path, mock_run, detector):
        """Test snap service status with empty lines."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Service  Startup  Current\n\n\n",
        )

        result = detector.service_detector._get_snap_service_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector._get_command_path"
    )
    def test_snap_service_status_disabled(self, mock_cmd_path, mock_run, detector):
        """Test snap service status - disabled."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Service  Startup  Current  Notes\nnginx.nginx  disabled  disabled  -\n",
        )

        result = detector.service_detector._get_snap_service_status("nginx")

        assert result == "stopped"

    @patch("subprocess.run")
    def test_bsd_service_status_unknown_fallback(self, mock_run, detector):
        """Test BSD service status when ps fails and no service command."""
        detector.system = "freebsd"
        # ps returns non-zero and no service command is available
        mock_run.return_value = Mock(returncode=1, stdout="")

        with patch.object(
            detector.service_detector, "_get_command_path", return_value=None
        ):
            result = detector.service_detector._get_bsd_service_status("nginx")

        assert result == "unknown"

    @patch("subprocess.run")
    def test_bsd_service_status_service_stopped(self, mock_run, detector):
        """Test BSD service status with service command - stopped."""
        detector.system = "freebsd"
        # First call is ps which fails
        ps_result = Mock(returncode=1, stdout="")
        # Second call is service which returns non-zero (stopped)
        service_result = Mock(returncode=1)
        mock_run.side_effect = [ps_result, service_result]

        with patch.object(
            detector.service_detector,
            "_get_command_path",
            return_value="/usr/sbin/service",
        ):
            result = detector.service_detector._get_bsd_service_status("nginx")

        assert result == "stopped"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_winget_packages_no_command(self, mock_cmd_path, mock_run, detector):
        """Test winget package retrieval when command not found."""
        mock_cmd_path.return_value = None

        result = detector.package_detector._get_winget_packages()

        assert result == {}
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_winget_packages_error(self, mock_cmd_path, mock_run, detector):
        """Test winget package retrieval with error."""
        mock_cmd_path.return_value = "winget"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_winget_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_winget_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test winget package retrieval with exception."""
        mock_cmd_path.return_value = "winget"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_winget_packages()

        assert result == {}

    @patch("subprocess.run")
    def test_python_packages_exception(self, mock_run, detector):
        """Test Python SQLite detection with exception."""
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_python_packages()

        assert result == {}


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_multiple_service_names_first_running(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test when first service name is running."""
        mock_get_packages.return_value = {"apache2": "2.4.41"}
        mock_service_status.side_effect = lambda name: (
            "running" if name == "apache2" else "stopped"
        )

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["service_name"] == "apache2"
        assert result[0]["service_status"] == "running"

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_multiple_service_names_second_running(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test when second service name is running."""
        mock_get_packages.return_value = {"apache2": "2.4.41"}
        mock_service_status.side_effect = lambda name: (
            "running" if name == "httpd" else "unknown"
        )

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["service_name"] == "httpd"
        assert result[0]["service_status"] == "running"

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_service_status_unknown_then_stopped(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test service status when all service names return unknown, then one returns stopped."""
        mock_get_packages.return_value = {"apache2": "2.4.41"}
        # apache2 package has service_names: ["apache2", "httpd"]
        # First service check returns "unknown", second returns "stopped"
        call_count = [0]

        def status_side_effect(name):
            call_count[0] += 1
            if call_count[0] == 1:
                return "unknown"
            return "stopped"

        mock_service_status.side_effect = status_side_effect

        result = detector.detect_roles()

        assert len(result) == 1
        # When first service is unknown and second is stopped, it should use the stopped status
        assert result[0]["service_status"] == "stopped"

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_subprocess_timeout(self, mock_cmd_path, mock_run, detector):
        """Test subprocess timeout handling."""
        mock_cmd_path.return_value = "/usr/bin/dpkg-query"
        mock_run.side_effect = Exception("Timeout")

        result = detector.package_detector._get_dpkg_packages()

        assert result == {}

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_empty_service_names_list(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test package with empty service names list."""
        mock_get_packages.return_value = {"sqlite3": "3.36.0"}

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["service_status"] == "installed"
        # Service status should not be called for packages without services
        mock_service_status.assert_not_called()
