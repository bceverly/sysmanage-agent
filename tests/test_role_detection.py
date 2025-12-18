"""
Comprehensive tests for the role detection module.
"""

# pylint: disable=protected-access,too-many-lines,unused-argument

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
