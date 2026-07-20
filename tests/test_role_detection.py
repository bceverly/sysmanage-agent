# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive tests for the role detection module.
"""

# pylint: disable=protected-access,unused-argument

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.role_detection import RoleDetector


class TestRoleDetectorInitialization:
    """Test RoleDetector initialization."""

    def test_role_detector_initialization(self):
        """Test that RoleDetector initializes correctly."""
        detector = RoleDetector()
        assert detector is not None
        assert hasattr(detector, "logger")
        assert hasattr(detector, "system")
        assert hasattr(detector, "role_mappings")
        assert "web_server" in detector.role_mappings
        assert "database_server" in detector.role_mappings
        assert "monitoring_server" in detector.role_mappings

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    def test_system_detection(self, mock_system):
        """Test that system is detected correctly."""
        mock_system.return_value = "Linux"
        detector = RoleDetector()
        assert detector.system == "linux"

        mock_system.return_value = "Darwin"
        detector = RoleDetector()
        assert detector.system == "darwin"

        mock_system.return_value = "Windows"
        detector = RoleDetector()
        assert detector.system == "windows"


class TestDetectRoles:
    """Test the main detect_roles method."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    def test_detect_roles_no_packages(
        self, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detect_roles when no packages are found."""
        mock_get_packages.return_value = {}

        result = detector.detect_roles()

        assert result == []
        mock_get_packages.assert_called_once()

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_web_server_nginx(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of Nginx web server."""
        mock_get_packages.return_value = {"nginx": "1.18.0"}
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["role"] == "Web Server"
        assert result[0]["package_name"] == "nginx"
        assert result[0]["package_version"] == "1.18.0"
        assert result[0]["service_name"] == "nginx"
        assert result[0]["service_status"] == "running"
        assert result[0]["is_active"] is True

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_web_server_apache(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of Apache web server."""
        mock_get_packages.return_value = {"apache2": "2.4.41"}
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["role"] == "Web Server"
        assert result[0]["package_name"] == "apache2"
        assert result[0]["service_name"] in ["apache2", "httpd"]

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_database_postgresql(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of PostgreSQL database."""
        mock_get_packages.return_value = {"postgresql": "14.5"}
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["role"] == "Database Server"
        assert result[0]["package_name"] == "postgresql"
        assert result[0]["service_name"] in ["postgresql", "postgres"]

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_database_mysql(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of MySQL database."""
        mock_get_packages.return_value = {"mysql-server": "8.0.30"}
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["role"] == "Database Server"
        assert result[0]["service_name"] in ["mysql", "mysqld"]

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    def test_detect_roles_database_sqlite(
        self, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of SQLite database (no service)."""
        mock_get_packages.return_value = {"sqlite3": "3.36.0"}

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["role"] == "Database Server"
        assert result[0]["package_name"] == "sqlite3"
        assert result[0]["service_status"] == "installed"
        assert result[0]["service_name"] is None

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_monitoring_grafana(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of Grafana monitoring server."""
        mock_get_packages.return_value = {"grafana": "9.3.2"}
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["role"] == "Monitoring Server"
        assert result[0]["package_name"] == "grafana"
        assert result[0]["service_name"] in ["grafana-server", "grafana"]

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_multiple_roles(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection of multiple server roles."""
        mock_get_packages.return_value = {
            "nginx": "1.18.0",
            "postgresql": "14.5",
            "redis": "6.0.9",
        }
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        assert len(result) == 3
        roles = {r["role"] for r in result}
        assert "Web Server" in roles
        assert "Database Server" in roles

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_service_stopped(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test detection when service is stopped."""
        mock_get_packages.return_value = {"nginx": "1.18.0"}
        mock_service_status.return_value = "stopped"

        result = detector.detect_roles()

        assert len(result) == 1
        assert result[0]["service_status"] == "stopped"
        assert result[0]["is_active"] is False

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_service_status.ServiceStatusDetector.get_service_status"
    )
    def test_detect_roles_duplicate_prevention(
        self, mock_service_status, mock_get_packages, mock_detect_virt, detector
    ):
        """Test that duplicate roles are prevented."""
        # PostgreSQL has multiple package patterns that could match
        mock_get_packages.return_value = {
            "postgresql": "14.5",
            "postgresql14-server": "14.5",
        }
        mock_service_status.return_value = "running"

        result = detector.detect_roles()

        # Should only return one Database Server role for PostgreSQL
        db_roles = [r for r in result if r["role"] == "Database Server"]
        postgres_services = {
            r["service_name"]
            for r in db_roles
            if r["service_name"] in ["postgresql", "postgres"]
        }
        assert len(postgres_services) <= 1

    @patch.object(RoleDetector, "_detect_virtualization_host_roles")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    def test_detect_roles_exception_handling(
        self, mock_get_packages, mock_detect_virt, detector
    ):
        """Test exception handling in detect_roles."""
        mock_get_packages.side_effect = Exception("Test error")

        result = detector.detect_roles()

        assert result == []


class TestGetInstalledPackages:
    """Test the _get_installed_packages method."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_dpkg_packages"
    )
    def test_get_installed_packages_linux_dpkg(
        self, mock_dpkg, mock_cmd_exists, mock_system, detector
    ):
        """Test getting packages on Linux with dpkg."""
        mock_system.return_value = "Linux"
        mock_cmd_exists.side_effect = lambda cmd: cmd == "dpkg"
        mock_dpkg.return_value = {"nginx": "1.18.0"}

        detector.system = "linux"
        detector.package_detector.system = "linux"
        result = detector.package_detector.get_installed_packages()

        assert result == {"nginx": "1.18.0"}
        mock_dpkg.assert_called_once()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_rpm_packages"
    )
    def test_get_installed_packages_linux_rpm(
        self, mock_rpm, mock_cmd_exists, mock_system, detector
    ):
        """Test getting packages on Linux with RPM."""
        mock_system.return_value = "Linux"
        mock_cmd_exists.side_effect = lambda cmd: cmd == "rpm"
        mock_rpm.return_value = {"httpd": "2.4.41"}

        detector.system = "linux"
        detector.package_detector.system = "linux"
        result = detector.package_detector.get_installed_packages()

        assert result == {"httpd": "2.4.41"}
        mock_rpm.assert_called_once()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_pacman_packages"
    )
    def test_get_installed_packages_linux_pacman(
        self, mock_pacman, mock_cmd_exists, mock_system, detector
    ):
        """Test getting packages on Linux with pacman."""
        mock_system.return_value = "Linux"
        mock_cmd_exists.side_effect = lambda cmd: cmd == "pacman"
        mock_pacman.return_value = {"nginx": "1.18.0"}

        detector.system = "linux"
        detector.package_detector.system = "linux"
        result = detector.package_detector.get_installed_packages()

        assert result == {"nginx": "1.18.0"}
        mock_pacman.assert_called_once()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_homebrew_packages"
    )
    def test_get_installed_packages_macos(
        self, mock_brew, mock_cmd_exists, mock_system, detector
    ):
        """Test getting packages on macOS with Homebrew."""
        mock_system.return_value = "Darwin"
        mock_cmd_exists.side_effect = lambda cmd: cmd == "brew"
        mock_brew.return_value = {"nginx": "1.18.0"}

        detector.system = "darwin"
        detector.package_detector.system = "darwin"
        result = detector.package_detector.get_installed_packages()

        assert result == {"nginx": "1.18.0"}
        mock_brew.assert_called_once()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_pkgin_packages"
    )
    def test_get_installed_packages_netbsd(
        self, mock_pkgin, mock_cmd_exists, mock_system, detector
    ):
        """Test getting packages on NetBSD with pkgin."""
        mock_system.return_value = "NetBSD"
        mock_cmd_exists.side_effect = lambda cmd: cmd == "pkgin"
        mock_pkgin.return_value = {"nginx": "1.18.0"}

        detector.system = "netbsd"
        detector.package_detector.system = "netbsd"
        result = detector.package_detector.get_installed_packages()

        assert result == {"nginx": "1.18.0"}
        mock_pkgin.assert_called_once()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._command_exists"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_pkg_packages"
    )
    def test_get_installed_packages_freebsd(
        self, mock_pkg, mock_cmd_exists, mock_system, detector
    ):
        """Test getting packages on FreeBSD with pkg."""
        mock_system.return_value = "FreeBSD"
        mock_cmd_exists.side_effect = lambda cmd: cmd == "pkg"
        mock_pkg.return_value = {"nginx": "1.18.0"}

        detector.system = "freebsd"
        detector.package_detector.system = "freebsd"
        result = detector.package_detector.get_installed_packages()

        assert result == {"nginx": "1.18.0"}
        mock_pkg.assert_called_once()

    @patch("src.sysmanage_agent.collection.role_detection.platform.system")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_windows_packages"
    )
    def test_get_installed_packages_windows(self, mock_windows, mock_system, detector):
        """Test getting packages on Windows."""
        mock_system.return_value = "Windows"
        mock_windows.return_value = {"postgresql": "14.5"}

        detector.system = "windows"
        detector.package_detector.system = "windows"
        result = detector.package_detector.get_installed_packages()

        assert result == {"postgresql": "14.5"}
        mock_windows.assert_called_once()

    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector.get_installed_packages"
    )
    def test_get_installed_packages_exception(self, mock_get_packages, detector):
        """Test exception handling in get_installed_packages."""
        mock_get_packages.side_effect = Exception("Test error")

        result = detector.detect_roles()

        assert result == []


class TestPackageManagerMethods:
    """Test individual package manager methods."""

    @pytest.fixture
    def detector(self):
        """Create a RoleDetector instance for testing."""
        return RoleDetector()

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_dpkg_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful dpkg package retrieval."""
        mock_cmd_path.return_value = "/usr/bin/dpkg-query"
        mock_run.return_value = Mock(
            returncode=0, stdout="nginx\t1.18.0\npostgresql\t14.5\n"
        )

        result = detector.package_detector._get_dpkg_packages()

        assert result == {"nginx": "1.18.0", "postgresql": "14.5"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_dpkg_packages_no_command(self, mock_cmd_path, mock_run, detector):
        """Test dpkg package retrieval when command not found."""
        mock_cmd_path.return_value = None

        result = detector.package_detector._get_dpkg_packages()

        assert result == {}
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_dpkg_packages_error(self, mock_cmd_path, mock_run, detector):
        """Test dpkg package retrieval with command error."""
        mock_cmd_path.return_value = "/usr/bin/dpkg-query"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_dpkg_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_rpm_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful RPM package retrieval."""
        mock_cmd_path.return_value = "/usr/bin/rpm"
        mock_run.return_value = Mock(
            returncode=0, stdout="httpd\t2.4.41\nmysql-server\t8.0.30\n"
        )

        result = detector.package_detector._get_rpm_packages()

        assert result == {"httpd": "2.4.41", "mysql-server": "8.0.30"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_rpm_packages_exception(self, mock_cmd_path, mock_run, detector):
        """Test RPM package retrieval with exception."""
        mock_cmd_path.return_value = "/usr/bin/rpm"
        mock_run.side_effect = Exception("Test error")

        result = detector.package_detector._get_rpm_packages()

        assert result == {}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pacman_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful pacman package retrieval."""
        mock_cmd_path.return_value = "/usr/bin/pacman"
        mock_run.return_value = Mock(
            returncode=0, stdout="nginx 1.18.0\npostgresql 14.5\n"
        )

        result = detector.package_detector._get_pacman_packages()

        assert result == {"nginx": "1.18.0", "postgresql": "14.5"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_snap_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful snap package retrieval."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Name  Version  Rev  Tracking  Publisher  Notes\nnginx 1.18.0   123  stable    nginx      -\n",
        )

        result = detector.package_detector._get_snap_packages()

        assert result == {"nginx": "1.18.0"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_snap_packages_empty_lines(self, mock_cmd_path, mock_run, detector):
        """Test snap package retrieval with empty lines."""
        mock_cmd_path.return_value = "/usr/bin/snap"
        mock_run.return_value = Mock(
            returncode=0, stdout="Name  Version\n\n\nnginx 1.18.0\n"
        )

        result = detector.package_detector._get_snap_packages()

        assert "nginx" in result

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.os.getuid",
        create=True,
    )
    @patch("os.environ.get")
    def test_get_homebrew_packages_as_root(
        self, mock_env_get, mock_getuid, mock_cmd_path, mock_run, detector
    ):
        """Test Homebrew package retrieval as root user."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_getuid.return_value = 0
        mock_env_get.return_value = "testuser"
        mock_run.return_value = Mock(
            returncode=0, stdout="nginx 1.18.0\npostgresql@14 14.5\n"
        )

        result = detector.package_detector._get_homebrew_packages()

        assert result == {"nginx": "1.18.0", "postgresql@14": "14.5"}
        # Verify sudo command was used
        call_args = mock_run.call_args[0][0]
        assert "sudo" in call_args

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.os.getuid",
        create=True,
    )
    def test_get_homebrew_packages_as_regular_user(
        self, mock_getuid, mock_cmd_path, mock_run, detector
    ):
        """Test Homebrew package retrieval as regular user."""
        mock_cmd_path.return_value = "/usr/local/bin/brew"
        mock_getuid.return_value = 1000
        mock_run.return_value = Mock(returncode=0, stdout="nginx 1.18.0 1.18.1\n")

        result = detector.package_detector._get_homebrew_packages()

        assert result == {"nginx": "1.18.0"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkgin_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful pkgin package retrieval."""
        mock_cmd_path.return_value = "/usr/pkg/bin/pkgin"
        mock_run.return_value = Mock(
            returncode=0,
            stdout="nginx-1.18.0 Web server\npostgresql14-server-14.5 Database\n",
        )

        result = detector.package_detector._get_pkgin_packages()

        assert result == {"nginx": "1.18.0", "postgresql14-server": "14.5"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkgin_packages_invalid_format(self, mock_cmd_path, mock_run, detector):
        """Test pkgin package retrieval with invalid format."""
        mock_cmd_path.return_value = "/usr/pkg/bin/pkgin"
        mock_run.return_value = Mock(
            returncode=0, stdout="invalid\nnginx-1.18.0\nnoversion\n"
        )

        result = detector.package_detector._get_pkgin_packages()

        assert result == {"nginx": "1.18.0"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkg_packages_success(self, mock_cmd_path, mock_run, detector):
        """Test successful pkg package retrieval."""
        mock_cmd_path.return_value = "/usr/sbin/pkg"
        mock_run.return_value = Mock(
            returncode=0, stdout="nginx-1.18.0 Web server\npostgresql14-14.5 Database\n"
        )

        result = detector.package_detector._get_pkg_packages()

        assert result == {"nginx": "1.18.0", "postgresql14": "14.5"}

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.role_detection_package_managers.PackageManagerDetector._get_command_path"
    )
    def test_get_pkg_packages_error(self, mock_cmd_path, mock_run, detector):
        """Test pkg package retrieval with error."""
        mock_cmd_path.return_value = "/usr/sbin/pkg"
        mock_run.return_value = Mock(returncode=1, stdout="")

        result = detector.package_detector._get_pkg_packages()

        assert result == {}
