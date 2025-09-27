"""
Unit tests for package collection functionality.
Tests the PackageCollector class and related methods.
"""

# pylint: disable=wrong-import-position,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.package_collection import PackageCollector


class TestPackageCollector:  # pylint: disable=too-many-public-methods
    """Test cases for the PackageCollector class."""

    @pytest.fixture
    def mock_db_manager(self):
        """Create a mock database manager."""
        db_manager = Mock()
        mock_session = Mock()
        # Create a proper context manager mock
        context_manager = Mock()
        context_manager.__enter__ = Mock(return_value=mock_session)
        context_manager.__exit__ = Mock(return_value=None)
        db_manager.get_session.return_value = context_manager
        return db_manager, mock_session

    @pytest.fixture
    def package_collector(self, mock_db_manager):
        """Create a PackageCollector instance with mocked dependencies."""
        db_manager, _ = mock_db_manager
        with patch(
            "src.sysmanage_agent.collection.package_collection.get_database_manager",
            return_value=db_manager,
        ):
            collector = PackageCollector()
        return collector

    def test_init(self, package_collector):
        """Test PackageCollector initialization."""
        assert package_collector is not None
        assert hasattr(package_collector, "db_manager")

    @patch("platform.system")
    @patch("subprocess.run")
    def test_collect_all_available_packages_linux(
        self, mock_run, mock_system, package_collector, mock_db_manager
    ):
        """Test package collection on Linux systems."""
        mock_system.return_value = "Linux"
        _, mock_session = mock_db_manager

        # Mock subprocess.run to handle different commands
        def mock_subprocess_run(cmd, **kwargs):
            result = Mock()
            if cmd == ["which", "apt"]:
                # "which apt" succeeds - apt is available
                result.returncode = 0
                result.stdout = "/usr/bin/apt"
            elif cmd == ["apt", "update"]:
                # apt update succeeds
                result.returncode = 0
                result.stdout = ""
            elif cmd == ["apt-cache", "dumpavail"]:
                # apt-cache dumpavail returns package data in dumpavail format
                result.returncode = 0
                result.stdout = """Package: nginx
Version: 1.18.0-6ubuntu14.4
Description: small, powerful, scalable web/proxy server

Package: python3
Version: 3.10.6-1~22.04
Description: interactive high-level object-oriented language

"""
            elif cmd[0] == "which":
                # Other package managers not available
                result.returncode = 1
                result.stdout = ""
            else:
                # Default: command not found
                result.returncode = 1
                result.stdout = ""
            return result

        mock_run.side_effect = mock_subprocess_run

        result = package_collector.collect_all_available_packages()

        assert result is True
        # Verify database operations - should have called query for delete, add for inserts, and commit
        assert mock_session.query.called  # For deleting existing packages
        assert mock_session.add.called  # For adding new packages
        assert mock_session.commit.called  # For committing transaction

    @patch("platform.system")
    def test_collect_all_available_packages_unsupported_os(
        self, mock_system, package_collector
    ):
        """Test package collection on unsupported OS."""
        mock_system.return_value = "UnsupportedOS"

        result = package_collector.collect_all_available_packages()

        assert result is False  # Should return False for unsupported OS

    @patch("subprocess.run")
    def test_collect_apt_packages_success(
        self, mock_run, package_collector, mock_db_manager
    ):
        """Test successful APT package collection."""
        _, mock_session = mock_db_manager

        # Mock subprocess calls for apt update and apt list
        def mock_subprocess_run(cmd, **kwargs):
            result = Mock()
            if cmd == ["apt", "update"]:
                result.returncode = 0
                result.stdout = ""
            elif cmd == ["apt-cache", "dumpavail"]:
                result.returncode = 0
                result.stdout = """Package: nginx
Version: 1.18.0-6ubuntu14.4
Description: small, powerful, scalable web/proxy server

Package: python3
Version: 3.10.6-1~22.04
Description: interactive high-level object-oriented language

"""
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        mock_run.side_effect = mock_subprocess_run

        count = (
            package_collector._collect_apt_packages()
        )  # pylint: disable=protected-access

        # Should return count of packages stored (2)
        assert count == 2
        # Verify database operations occurred
        assert mock_session.query.called
        assert mock_session.add.called
        assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_apt_packages_command_failure(self, mock_run, package_collector):
        """Test APT package collection when command fails."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Package list error"

        count = (
            package_collector._collect_apt_packages()
        )  # pylint: disable=protected-access

        assert count == 0

    @patch("subprocess.run")
    def test_collect_yum_packages_success(
        self, mock_run, package_collector, mock_db_manager
    ):
        """Test successful YUM package collection."""
        _, mock_session = mock_db_manager

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = """Available Packages
httpd.x86_64 2.4.37-62.module+el8.9.0+19699+7a7c1871 appstream
nginx.x86_64 1:1.20.1-1.el8 epel
"""

        count = (
            package_collector._collect_yum_packages()
        )  # pylint: disable=protected-access

        assert count == 2
        assert mock_session.query.called
        assert mock_session.add.called
        assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_snap_packages_success(
        self, mock_run, package_collector, mock_db_manager
    ):
        """Test successful Snap package collection."""
        _, mock_session = mock_db_manager

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = """
Name      Version    Rev  Tracking  Publisher   Notes
docker    24.0.5     2915 latest/stable docker✓   -
code      1.82.2     148  latest/stable vscode✓    classic
"""

        count = (
            package_collector._collect_snap_packages()
        )  # pylint: disable=protected-access

        assert count == 2
        assert mock_session.query.called
        assert mock_session.add.called
        assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_homebrew_packages_success(
        self, mock_run, package_collector, mock_db_manager
    ):
        """Test successful Homebrew package collection."""
        _, mock_session = mock_db_manager

        # Mock multiple subprocess calls:
        # 1. brew --version (to check if brew exists)
        # 2. brew list --formulae --versions (formulae)
        # 3. brew list --casks --versions (casks - no output expected)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Homebrew 4.0.0"),  # brew --version
            Mock(
                returncode=0,
                stdout="""
git 2.42.0
nginx 1.25.1
python@3.11 3.11.5
""",
            ),  # formulae
            Mock(returncode=0, stdout=""),  # casks (empty)
        ]

        count = (
            package_collector._collect_homebrew_packages()
        )  # pylint: disable=protected-access

        assert count == 3
        assert mock_session.query.called
        assert mock_session.add.called
        assert mock_session.commit.called

    def test_store_packages_success(self, package_collector, mock_db_manager):
        """Test successful package storage."""
        _, mock_session = mock_db_manager

        packages = [
            {"name": "nginx", "version": "1.18.0", "description": "Web server"},
            {
                "name": "python3",
                "version": "3.10.12",
                "description": "Programming language",
            },
        ]

        package_collector._store_packages(
            "apt", packages
        )  # pylint: disable=protected-access

        # Verify database operations
        assert mock_session.query.called  # DELETE operation
        assert mock_session.add.call_count == 2  # Two packages added
        assert mock_session.commit.called

    def test_store_packages_empty_list(self, package_collector, mock_db_manager):
        """Test package storage with empty package list."""
        _, mock_session = mock_db_manager

        result = package_collector._store_packages(
            "apt", []
        )  # pylint: disable=protected-access

        # Should return 0 for empty list and not perform any database operations
        assert result == 0
        assert not mock_session.query.called  # No operations when empty
        assert not mock_session.add.called  # No packages to add
        assert not mock_session.commit.called  # No commit when no operations

    def test_store_packages_database_error(self, package_collector, mock_db_manager):
        """Test package storage with database error."""
        _, mock_session = mock_db_manager
        mock_session.commit.side_effect = Exception("Database error")

        packages = [{"name": "nginx", "version": "1.18.0", "description": "Web server"}]

        # Should not raise exception, just log error and return 0
        result = package_collector._store_packages(
            "apt", packages
        )  # pylint: disable=protected-access

        # Should return 0 when database error occurs
        assert result == 0
        # Should still attempt to commit before error
        assert mock_session.commit.called

    def test_get_all_packages(self, package_collector, mock_db_manager):
        """Test retrieval of all stored packages."""
        _, mock_session = mock_db_manager

        # Mock database query result
        mock_packages = [
            Mock(
                id=1,
                package_manager="apt",
                package_name="nginx",
                package_version="1.18.0",
                package_description="Web server",
                collection_date=None,
                created_at=None,
            ),
            Mock(
                id=2,
                package_manager="snap",
                package_name="docker",
                package_version="24.0.5",
                package_description="Container platform",
                collection_date=None,
                created_at=None,
            ),
        ]
        mock_session.query.return_value.all.return_value = mock_packages

        result = package_collector.get_all_packages()

        assert len(result) == 2
        assert result[0].package_manager == "apt"
        assert result[0].package_name == "nginx"
        assert result[1].package_manager == "snap"
        assert result[1].package_name == "docker"

    def test_get_packages_for_transmission(self, package_collector, mock_db_manager):
        """Test getting packages organized for transmission to server."""
        _, mock_session = mock_db_manager

        # Mock database query result
        mock_packages = [
            Mock(
                package_manager="apt",
                package_name="nginx",
                package_version="1.18.0",
                package_description="Web server",
            ),
            Mock(
                package_manager="apt",
                package_name="python3",
                package_version="3.10.12",
                package_description="Language",
            ),
            Mock(
                package_manager="snap",
                package_name="docker",
                package_version="24.0.5",
                package_description="Container platform",
            ),
        ]
        mock_session.query.return_value.all.return_value = mock_packages

        result = package_collector.get_packages_for_transmission()

        # Check top-level structure includes OS information
        assert "os_name" in result
        assert "os_version" in result
        assert "package_managers" in result

        # Check OS information is present (will vary by platform)
        assert result["os_name"] is not None
        assert result["os_version"] is not None

        package_managers = result["package_managers"]
        assert "apt" in package_managers
        assert "snap" in package_managers
        assert len(package_managers["apt"]) == 2
        assert len(package_managers["snap"]) == 1

        # Check structure
        apt_nginx = package_managers["apt"][0]
        assert apt_nginx["name"] == "nginx"
        assert apt_nginx["version"] == "1.18.0"
        assert apt_nginx["description"] == "Web server"

    def test_get_package_managers(self, package_collector, mock_db_manager):
        """Test retrieval of available package managers."""
        _, mock_session = mock_db_manager

        # Mock database query result
        mock_managers = [("apt",), ("snap",), ("yum",)]
        mock_session.query.return_value.distinct.return_value.all.return_value = (
            mock_managers
        )

        result = package_collector.get_package_managers()

        assert len(result) == 3
        assert "apt" in result
        assert "snap" in result
        assert "yum" in result

    def test_parse_apt_output_complex(self, package_collector):
        """Test parsing complex APT output with various formats."""
        output = """
nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 all
  small, powerful, scalable web/proxy server

python3/jammy-updates 3.10.6-1~22.04 amd64
  interactive high-level object-oriented language (default python3 version)

package-without-description/jammy 1.0.0 all

malformed-line-without-slash 1.0.0
"""

        packages = package_collector._parse_apt_output(
            output
        )  # pylint: disable=protected-access

        # Should parse valid packages and skip malformed ones
        assert len(packages) >= 2

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.18.0-6ubuntu14.4"

    def test_parse_yum_output_formats(self, package_collector):
        """Test parsing different YUM output formats."""
        output = """Available Packages
httpd.x86_64                    2.4.37-62.module+el8             appstream
nginx.x86_64                    1:1.20.1-1.el8                   epel
package-with-long-name.x86_64   1.0.0-1.el8.very.long.version   extras
"""

        packages = package_collector._parse_yum_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        httpd_pkg = next(pkg for pkg in packages if pkg["name"] == "httpd")
        assert httpd_pkg["version"] == "2.4.37-62.module+el8"

    def test_error_handling_in_collection_methods(self, package_collector):
        """Test error handling in various collection methods."""
        # Test with subprocess that raises exception
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            count = (
                package_collector._collect_apt_packages()
            )  # pylint: disable=protected-access
            assert count == 0

            count = (
                package_collector._collect_yum_packages()
            )  # pylint: disable=protected-access
            assert count == 0

            count = (
                package_collector._collect_snap_packages()
            )  # pylint: disable=protected-access
            assert count == 0

    @patch("platform.system")
    @patch("subprocess.run")
    def test_package_manager_detection(self, mock_run, mock_system, package_collector):
        """Test package manager detection based on system and available commands."""
        mock_system.return_value = "Linux"

        # Test APT detection - mock subprocess.run for "which" command
        def mock_subprocess_run(cmd, **kwargs):
            result = Mock()
            if cmd == ["which", "apt"]:
                result.returncode = 0  # apt is available
            else:
                result.returncode = 1  # other package managers not available
            return result

        mock_run.side_effect = mock_subprocess_run

        with patch.object(
            package_collector, "_collect_apt_packages", return_value=5
        ) as mock_apt:
            with patch.object(package_collector, "_store_packages"):
                package_collector.collect_all_available_packages()
                mock_apt.assert_called_once()

    def test_collection_with_network_timeout(self, package_collector):
        """Test package collection with network timeout scenarios."""
        with patch("subprocess.run") as mock_run:
            # Simulate timeout
            mock_run.side_effect = Exception("Timeout")

            result = package_collector.collect_all_available_packages()
            # Should handle timeout gracefully
            assert result is True
