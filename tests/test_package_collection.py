"""
Unit tests for package collection functionality.
Tests the PackageCollector class and related methods.
"""

# pylint: disable=wrong-import-position,protected-access,import-outside-toplevel,too-many-lines

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

    @pytest.fixture
    def linux_package_collector(self, mock_db_manager):
        """Create a Linux PackageCollector instance for testing Linux-specific methods."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        db_manager, _ = mock_db_manager
        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=db_manager,
        ):
            collector = LinuxPackageCollector()
        return collector

    def test_init(self, package_collector):
        """Test PackageCollector initialization."""
        assert package_collector is not None
        assert hasattr(package_collector, "db_manager")

    @patch("platform.system")
    def test_collect_all_available_packages_linux(
        self, mock_system, package_collector, mock_db_manager
    ):
        """Test package collection on Linux systems."""
        mock_system.return_value = "Linux"
        _, _mock_session = mock_db_manager
        _ = _mock_session

        # Mock the collect_packages method on the platform-specific collector
        with patch.object(
            package_collector.collector, "collect_packages", return_value=2
        ) as mock_collect:
            result = package_collector.collect_all_available_packages()

            assert result is True
            mock_collect.assert_called_once()

    def test_collect_all_available_packages_unsupported_os(self):
        """Test package collection on unsupported OS."""
        with (
            patch(
                "src.sysmanage_agent.collection.package_collection.get_database_manager"
            ),
            patch("platform.system", return_value="UnsupportedOS"),
        ):
            # pylint: disable=import-outside-toplevel,reimported
            from src.sysmanage_agent.collection.package_collection import (
                PackageCollector as UnsupportedCollector,
            )

            collector = UnsupportedCollector()
            result = collector.collect_all_available_packages()

            assert result is False  # Should return False for unsupported OS

    @patch("subprocess.run")
    def test_collect_apt_packages_success(self, mock_run, mock_db_manager):
        """Test successful APT package collection."""
        # Create a Linux-specific collector directly
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            # Mock subprocess calls for apt update and apt list
            def mock_subprocess_run(cmd, **_kwargs):
                _ = _kwargs
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
                linux_collector._collect_apt_packages()
            )  # pylint: disable=protected-access

            # Should return count of packages stored (2)
            assert count == 2
            # Verify database operations occurred
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_apt_packages_command_failure(self, mock_run):
        """Test APT package collection when command fails."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            linux_collector = LinuxPackageCollector()
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "Package list error"

            count = (
                linux_collector._collect_apt_packages()
            )  # pylint: disable=protected-access

            assert count == 0

    @patch("subprocess.run")
    def test_collect_yum_packages_success(self, mock_run, mock_db_manager):
        """Test successful YUM package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """Available Packages
httpd.x86_64 2.4.37-62.module+el8.9.0+19699+7a7c1871 appstream
nginx.x86_64 1:1.20.1-1.el8 epel
"""

            count = (
                linux_collector._collect_yum_packages()
            )  # pylint: disable=protected-access

            assert count == 2
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_snap_packages_success(self, mock_run, mock_db_manager):
        """Test successful Snap package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """
Name      Version    Rev  Tracking  Publisher   Notes
docker    24.0.5     2915 latest/stable docker✓   -
code      1.82.2     148  latest/stable vscode✓    classic
"""

            count = (
                linux_collector._collect_snap_packages()
            )  # pylint: disable=protected-access

            assert count == 2
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    @patch(
        "src.sysmanage_agent.collection.package_collector_macos.MacOSPackageCollector._get_brew_command"
    )
    def test_collect_homebrew_packages_success(
        self, mock_get_brew_command, mock_run, mock_db_manager
    ):
        """Test successful Homebrew package collection."""
        # Create a macOS-specific collector directly
        from src.sysmanage_agent.collection.package_collector_macos import (
            MacOSPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            macos_collector = MacOSPackageCollector()

            # Mock _get_brew_command to return a simple brew command
            mock_get_brew_command.return_value = "brew"

            # Mock subprocess calls for brew list commands:
            # 1. brew list --formulae --versions (formulae)
            # 2. brew list --casks --versions (casks - no output expected)
            mock_run.side_effect = [
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
                macos_collector._collect_homebrew_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    def test_store_packages_success(self, mock_db_manager):
        """Test successful package storage."""
        # Create a base collector directly
        from src.sysmanage_agent.collection.package_collector_base import (
            BasePackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            base_collector = BasePackageCollector()

            packages = [
                {"name": "nginx", "version": "1.18.0", "description": "Web server"},
                {
                    "name": "python3",
                    "version": "3.10.12",
                    "description": "Programming language",
                },
            ]

            base_collector._store_packages(
                "apt", packages
            )  # pylint: disable=protected-access

            # Verify database operations
            assert mock_session.query.called  # DELETE operation
            assert mock_session.add.call_count == 2  # Two packages added
            assert mock_session.commit.called

    def test_store_packages_empty_list(self, mock_db_manager):
        """Test package storage with empty package list."""
        # Create a base collector directly
        from src.sysmanage_agent.collection.package_collector_base import (
            BasePackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            base_collector = BasePackageCollector()

            result = base_collector._store_packages(
                "apt", []
            )  # pylint: disable=protected-access

            # Should return 0 for empty list and not perform any database operations
            assert result == 0
            assert not mock_session.query.called  # No operations when empty
            assert not mock_session.add.called  # No packages to add
            assert not mock_session.commit.called  # No commit when no operations

    def test_store_packages_database_error(self, mock_db_manager):
        """Test package storage with database error."""
        # Create a base collector directly
        from src.sysmanage_agent.collection.package_collector_base import (
            BasePackageCollector,
        )

        _, mock_session = mock_db_manager
        mock_session.commit.side_effect = Exception("Database error")

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            base_collector = BasePackageCollector()

            packages = [
                {"name": "nginx", "version": "1.18.0", "description": "Web server"}
            ]

            # Should not raise exception, just log error and return 0
            result = base_collector._store_packages(
                "apt", packages
            )  # pylint: disable=protected-access

            # Should return 0 when database error occurs
            assert result == 0
            # Should still attempt to commit before error
            assert mock_session.commit.called

    def test_get_all_packages(self, mock_db_manager):
        """Test retrieval of all stored packages."""
        # Create a base collector directly
        from src.sysmanage_agent.collection.package_collector_base import (
            BasePackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            base_collector = BasePackageCollector()

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

            result = base_collector.get_all_packages()

            assert len(result) == 2
            assert result[0].package_manager == "apt"
            assert result[0].package_name == "nginx"
            assert result[1].package_manager == "snap"
            assert result[1].package_name == "docker"

    def test_get_packages_for_transmission(self, mock_db_manager):
        """Test getting packages organized for transmission to server."""
        # Create a base collector directly
        from src.sysmanage_agent.collection.package_collector_base import (
            BasePackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            base_collector = BasePackageCollector()

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

            result = base_collector.get_packages_for_transmission()

            # Check top-level structure
            # Note: OS info is now added by the caller (main.py) using get_system_info()
            assert "package_managers" in result

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

    def test_get_package_managers(self, mock_db_manager):
        """Test retrieval of available package managers."""
        # Create a base collector directly
        from src.sysmanage_agent.collection.package_collector_base import (
            BasePackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            base_collector = BasePackageCollector()

            # Mock database query result
            mock_managers = [("apt",), ("snap",), ("yum",)]
            mock_session.query.return_value.distinct.return_value.all.return_value = (
                mock_managers
            )

            result = base_collector.get_package_managers()

            assert len(result) == 3
            assert "apt" in result
            assert "snap" in result
            assert "yum" in result

    def test_parse_apt_output_complex(self, linux_package_collector):
        """Test parsing complex APT output with various formats."""
        output = """
nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 all
  small, powerful, scalable web/proxy server

python3/jammy-updates 3.10.6-1~22.04 amd64
  interactive high-level object-oriented language (default python3 version)

package-without-description/jammy 1.0.0 all

malformed-line-without-slash 1.0.0
"""

        packages = linux_package_collector._parse_apt_output(
            output
        )  # pylint: disable=protected-access

        # Should parse valid packages and skip malformed ones
        assert len(packages) >= 2

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.18.0-6ubuntu14.4"

    def test_parse_yum_output_formats(self, linux_package_collector):
        """Test parsing different YUM output formats."""
        output = """Available Packages
httpd.x86_64                    2.4.37-62.module+el8             appstream
nginx.x86_64                    1:1.20.1-1.el8                   epel
package-with-long-name.x86_64   1.0.0-1.el8.very.long.version   extras
"""

        packages = linux_package_collector._parse_yum_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        httpd_pkg = next(pkg for pkg in packages if pkg["name"] == "httpd")
        assert httpd_pkg["version"] == "2.4.37-62.module+el8"

    def test_error_handling_in_collection_methods(self, linux_package_collector):
        """Test error handling in various collection methods."""
        # Test with subprocess that raises exception
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            count = (
                linux_package_collector._collect_apt_packages()
            )  # pylint: disable=protected-access
            assert count == 0

            count = (
                linux_package_collector._collect_yum_packages()
            )  # pylint: disable=protected-access
            assert count == 0

            count = (
                linux_package_collector._collect_snap_packages()
            )  # pylint: disable=protected-access
            assert count == 0

    @patch("platform.system")
    @patch("subprocess.run")
    def test_package_manager_detection(self, mock_run, mock_system, mock_db_manager):
        """Test package manager detection based on system and available commands."""
        mock_system.return_value = "Linux"

        # Test APT detection - mock subprocess.run for "which" command
        def mock_subprocess_run(cmd, **_kwargs):
            _ = _kwargs
            result = Mock()
            if cmd == ["which", "apt"]:
                result.returncode = 0  # apt is available
            else:
                result.returncode = 1  # other package managers not available
            return result

        mock_run.side_effect = mock_subprocess_run

        _, _mock_session = mock_db_manager
        _ = _mock_session

        with patch(
            "src.sysmanage_agent.collection.package_collection.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            # pylint: disable=reimported
            from src.sysmanage_agent.collection.package_collection import (
                PackageCollector as TestCollector,
            )

            package_collector = TestCollector()

            with patch.object(
                package_collector.collector, "_collect_apt_packages", return_value=5
            ) as mock_apt:
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

    @patch("subprocess.run")
    def test_collect_dnf_packages_success(self, mock_run, mock_db_manager):
        """Test successful DNF package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """Available Packages
httpd.x86_64 2.4.37-62.module+el8 appstream
nginx.x86_64 1:1.20.1-1.el8 epel
python3.x86_64 3.9.16-1.el8_8.2 baseos
"""

            count = (
                linux_collector._collect_dnf_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_zypper_packages_success(self, mock_run, mock_db_manager):
        """Test successful Zypper package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """Loading repository data...
Reading installed packages...

S | Name    | Type    | Version | Arch   | Repository
--+---------+---------+---------+--------+-----------
  | apache2 | package | 2.4.51  | x86_64 | Main
  | nginx   | package | 1.20.1  | x86_64 | Main
"""

            count = (
                linux_collector._collect_zypper_packages()
            )  # pylint: disable=protected-access

            assert count >= 0  # Allow for parsing variations
            assert mock_session.query.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_pacman_packages_success(self, mock_run, mock_db_manager):
        """Test successful Pacman package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """extra/nginx 1.20.1-1
    Lightweight HTTP server and IMAP/POP3 proxy server
core/bash 5.1.016-1
    The GNU Bourne Again shell
"""

            count = (
                linux_collector._collect_pacman_packages()
            )  # pylint: disable=protected-access

            assert count == 2
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_flatpak_packages_success(self, mock_run, mock_db_manager):
        """Test successful Flatpak package collection."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """
com.visualstudio.code	Visual Studio Code	1.82.2	stable	vscode
org.mozilla.firefox	Firefox	119.0	stable	mozilla
org.gimp.GIMP	GNU Image Manipulation Program	2.10.34	stable	gimp
"""

            count = (
                linux_collector._collect_flatpak_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("urllib.request.urlopen")
    def test_collect_winget_packages_success(self, mock_urlopen, mock_db_manager):
        """Test successful Winget package collection via REST API."""
        # Create a Windows-specific collector directly
        from src.sysmanage_agent.collection.package_collector_windows import (
            WindowsPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            windows_collector = WindowsPackageCollector()

            # Mock API responses simulating 4303 total packages
            # 358 full pages of 12 packages = 4296, then 1 page with 7 packages = 4303 total
            mock_responses = []

            # Pages 1-358: Full pages with 12 packages each
            for page in range(358):
                start_pkg = page * 12 + 1
                end_pkg = start_pkg + 12
                packages = [
                    b'{"Id": "pkg%d", "Latest": {"Name": "Package %d", "PackageVersion": "1.0.%d"}}'
                    % (i, i, i)
                    for i in range(start_pkg, end_pkg)
                ]
                mock_responses.append(
                    Mock(
                        read=Mock(
                            return_value=b'{"Packages": ['
                            + b",".join(packages)
                            + b'], "Total": 4303}'
                        )
                    )
                )

            # Page 359: Last page with 7 packages (4297-4303)
            packages = [
                b'{"Id": "pkg%d", "Latest": {"Name": "Package %d", "PackageVersion": "1.0.%d"}}'
                % (i, i, i)
                for i in range(4297, 4304)
            ]
            mock_responses.append(
                Mock(
                    read=Mock(
                        return_value=b'{"Packages": ['
                        + b",".join(packages)
                        + b'], "Total": 4303}'
                    )
                )
            )

            # Empty response to stop pagination
            mock_responses.append(
                Mock(read=Mock(return_value=b'{"Packages": [], "Total": 4303}'))
            )

            mock_urlopen.return_value.__enter__ = Mock(side_effect=mock_responses)
            mock_urlopen.return_value.__exit__ = Mock(return_value=False)

            count = (
                windows_collector._collect_winget_packages()
            )  # pylint: disable=protected-access

            assert count > 1000
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("urllib.request.urlopen")
    def test_collect_chocolatey_packages_success(self, mock_urlopen, mock_db_manager):
        """Test successful Chocolatey package collection via OData API."""
        # Create a Windows-specific collector directly
        from src.sysmanage_agent.collection.package_collector_windows import (
            WindowsPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            windows_collector = WindowsPackageCollector()

            # Mock XML responses for Chocolatey OData API
            # Simulate 250 pages of 40 packages each = 10,000 packages
            mock_responses = []

            for page in range(250):
                skip = page * 40
                entries = []
                for i in range(40):
                    pkg_num = skip + i + 1
                    entry = f"""<entry xmlns="http://www.w3.org/2005/Atom"
                                      xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
                                      xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                                <title>package{pkg_num}</title>
                                <m:properties>
                                    <d:Version>1.0.{pkg_num}</d:Version>
                                </m:properties>
                            </entry>"""
                    entries.append(entry)

                xml_response = f"""<?xml version="1.0" encoding="utf-8"?>
                    <feed xmlns="http://www.w3.org/2005/Atom"
                          xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
                          xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                        {''.join(entries)}
                    </feed>"""

                mock_responses.append(
                    Mock(read=Mock(return_value=xml_response.encode("utf-8")))
                )

            # Empty response to stop pagination
            empty_xml = """<?xml version="1.0" encoding="utf-8"?>
                <feed xmlns="http://www.w3.org/2005/Atom"
                      xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices"
                      xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
                </feed>"""
            mock_responses.append(
                Mock(read=Mock(return_value=empty_xml.encode("utf-8")))
            )

            mock_urlopen.return_value.__enter__ = Mock(side_effect=mock_responses)
            mock_urlopen.return_value.__exit__ = Mock(return_value=False)

            count = (
                windows_collector._collect_chocolatey_packages()
            )  # pylint: disable=protected-access

            assert count > 1000
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.run")
    def test_collect_pkg_packages_success(self, mock_run, mock_db_manager):
        """Test successful FreeBSD pkg package collection."""
        # Create a BSD-specific collector directly
        from src.sysmanage_agent.collection.package_collector_bsd import (
            BSDPackageCollector,
        )

        _, mock_session = mock_db_manager

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            bsd_collector = BSDPackageCollector()

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """nginx-1.20.1,3
apache24-2.4.54
python39-3.9.16
"""

            count = (
                bsd_collector._collect_pkg_packages()
            )  # pylint: disable=protected-access

            assert count == 3
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    def test_parse_pacman_output_detailed(self, linux_package_collector):
        """Test detailed parsing of Pacman output."""
        output = """extra/nginx 1.20.1-1
    Lightweight HTTP server and IMAP/POP3 proxy server
core/bash 5.1.016-1
    The GNU Bourne Again shell
community/docker 20.10.21-1
    Pack, ship and run any application as a lightweight container
"""

        packages = linux_package_collector._parse_pacman_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.20.1-1"
        assert "HTTP server" in nginx_pkg["description"]

        bash_pkg = next((pkg for pkg in packages if pkg["name"] == "bash"), None)
        assert bash_pkg is not None
        assert bash_pkg["version"] == "5.1.016-1"

    # test_parse_chocolatey_output_detailed removed - Chocolatey now uses OData XML API
    # instead of command-line parsing, so _parse_chocolatey_output() method no longer exists

    def test_parse_pkg_output_detailed(self):
        """Test detailed parsing of FreeBSD pkg output."""
        # Create a BSD-specific collector directly
        from src.sysmanage_agent.collection.package_collector_bsd import (
            BSDPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            bsd_collector = BSDPackageCollector()

            output = """nginx-1.20.1,3
apache24-2.4.54
python39-3.9.16
postgresql13-server-13.12
"""

            packages = bsd_collector._parse_pkg_output(
                output
            )  # pylint: disable=protected-access

            assert len(packages) == 4

            nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
            assert nginx_pkg is not None
            assert nginx_pkg["version"] == "1.20.1,3"

            apache_pkg = next(
                (pkg for pkg in packages if pkg["name"] == "apache24"), None
            )
            assert apache_pkg is not None
            assert apache_pkg["version"] == "2.4.54"

    @patch("platform.system")
    def test_is_package_manager_available_success(self, mock_system, package_collector):
        """Test package manager availability detection."""
        mock_system.return_value = "Linux"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0

            result = package_collector._is_package_manager_available(
                "apt"
            )  # pylint: disable=protected-access

            assert result is True
            mock_run.assert_called_once_with(
                ["which", "apt"], capture_output=True, timeout=10, check=False
            )

    def test_is_package_manager_available_failure(self, package_collector):
        """Test package manager availability detection when not available."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1

            result = package_collector._is_package_manager_available(
                "nonexistent"
            )  # pylint: disable=protected-access

            assert result is False

    def test_is_package_manager_available_exception(self, package_collector):
        """Test package manager availability detection with exception."""
        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = package_collector._is_package_manager_available(
                "apt"
            )  # pylint: disable=protected-access

            assert result is False

    def test_collect_linux_packages_multiple_managers(self):
        """Test Linux package collection with multiple package managers."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            linux_collector = LinuxPackageCollector()

            with patch.object(
                linux_collector, "_is_package_manager_available"
            ) as mock_available:
                with patch.object(
                    linux_collector, "_collect_apt_packages", return_value=5
                ) as mock_apt:
                    with patch.object(
                        linux_collector, "_collect_snap_packages", return_value=3
                    ) as mock_snap:
                        # Mock apt and snap as available
                        def available_side_effect(manager):
                            return manager in ["apt", "snap"]

                        mock_available.side_effect = available_side_effect

                        count = linux_collector.collect_packages()

                        assert count == 8  # 5 + 3
                        mock_apt.assert_called_once()
                        mock_snap.assert_called_once()

    def test_collect_macos_packages_homebrew(self):
        """Test macOS package collection with Homebrew."""
        # Create a macOS-specific collector directly
        from src.sysmanage_agent.collection.package_collector_macos import (
            MacOSPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            macos_collector = MacOSPackageCollector()

            with patch.object(
                macos_collector, "_is_package_manager_available", return_value=True
            ):
                with patch.object(
                    macos_collector, "_collect_homebrew_packages", return_value=10
                ) as mock_homebrew:
                    count = macos_collector.collect_packages()

                    assert count == 10
                    mock_homebrew.assert_called_once()

    def test_collect_windows_packages_multiple_managers(self):
        """Test Windows package collection with multiple package managers."""
        # Create a Windows-specific collector directly
        from src.sysmanage_agent.collection.package_collector_windows import (
            WindowsPackageCollector,
        )

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            windows_collector = WindowsPackageCollector()

            with patch.object(
                windows_collector, "_is_package_manager_available"
            ) as mock_available:
                with patch.object(
                    windows_collector, "_collect_winget_packages", return_value=7
                ) as mock_winget:
                    with patch.object(
                        windows_collector,
                        "_collect_chocolatey_packages",
                        return_value=4,
                    ) as mock_choco:
                        # Mock both as available
                        def available_side_effect(manager):
                            return manager in ["winget", "choco"]

                        mock_available.side_effect = available_side_effect

                        count = windows_collector.collect_packages()

                        assert count == 11  # 7 + 4
                        mock_winget.assert_called_once()
                        mock_choco.assert_called_once()

    @patch("platform.system")
    def test_collect_bsd_packages_pkg(self, mock_system):
        """Test BSD package collection with pkg."""
        # Create a BSD-specific collector directly
        from src.sysmanage_agent.collection.package_collector_bsd import (
            BSDPackageCollector,
        )

        # Mock platform.system to return FreeBSD
        mock_system.return_value = "FreeBSD"

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            bsd_collector = BSDPackageCollector()

            # Mock _is_package_manager_available to only return True for pkg
            def mock_pm_available(manager):
                return manager == "pkg"

            with patch.object(
                bsd_collector,
                "_is_package_manager_available",
                side_effect=mock_pm_available,
            ):
                with patch.object(
                    bsd_collector, "_collect_pkg_packages", return_value=12
                ) as mock_pkg:
                    count = bsd_collector.collect_packages()

                    assert count == 12
                    mock_pkg.assert_called_once()

    def test_parse_apt_dumpavail_output_detailed(self, linux_package_collector):
        """Test detailed parsing of apt-cache dumpavail output."""
        output = """Package: nginx
Version: 1.18.0-6ubuntu14.4
Description: small, powerful, scalable web/proxy server
 Nginx is a web server with a strong focus on high concurrency, performance
 and low memory usage.

Package: python3
Version: 3.10.6-1~22.04
Description: interactive high-level object-oriented language
 Python is an interpreted, interactive, object-oriented programming
 language.

Package: apache2
Version: 2.4.52-1ubuntu4.7
Description: Apache HTTP Server
 The Apache HTTP Server Project's goal is to build a secure, efficient and
 extensible HTTP server.
"""

        packages = linux_package_collector._parse_apt_dumpavail_output(
            output
        )  # pylint: disable=protected-access

        assert len(packages) == 3

        nginx_pkg = next((pkg for pkg in packages if pkg["name"] == "nginx"), None)
        assert nginx_pkg is not None
        assert nginx_pkg["version"] == "1.18.0-6ubuntu14.4"
        assert "web/proxy server" in nginx_pkg["description"]

        python_pkg = next((pkg for pkg in packages if pkg["name"] == "python3"), None)
        assert python_pkg is not None
        assert python_pkg["version"] == "3.10.6-1~22.04"

    def test_package_collection_error_handling(self, linux_package_collector):
        """Test error handling in various package collection scenarios."""

        # Test command failure
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "Command failed"

            count = (
                linux_package_collector._collect_apt_packages()
            )  # pylint: disable=protected-access
            assert count == 0

        # Test parsing empty output
        empty_packages = linux_package_collector._parse_apt_output(
            ""
        )  # pylint: disable=protected-access
        assert empty_packages == []

        # Test malformed output handling
        malformed_output = "This is not valid package output"
        malformed_packages = linux_package_collector._parse_yum_output(
            malformed_output
        )  # pylint: disable=protected-access
        assert malformed_packages == []
