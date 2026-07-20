# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for package collection functionality.
Tests the PackageCollector class and related methods.
"""

# pylint: disable=wrong-import-position,protected-access,import-outside-toplevel

from unittest.mock import MagicMock, Mock, patch

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

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_collect_apt_packages_success(self, mock_run, mock_popen, mock_db_manager):
        """Test successful APT package collection (streamed dumpavail)."""
        # Create a Linux-specific collector directly
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        _, mock_session = mock_db_manager

        # ``apt update`` still goes through subprocess.run; the dumpavail dump
        # is now STREAMED through subprocess.Popen.
        mock_run.return_value = Mock(returncode=0, stdout="")

        dumpavail = (
            "Package: nginx\n"
            "Version: 1.18.0-6ubuntu14.4\n"
            "Description: small, powerful, scalable web/proxy server\n"
            "\n"
            "Package: python3\n"
            "Version: 3.10.6-1~22.04\n"
            "Description: interactive high-level object-oriented language\n"
            "\n"
        )
        proc = MagicMock()
        proc.__enter__.return_value = proc
        proc.__exit__.return_value = False
        proc.stdout = iter(dumpavail.splitlines(keepends=True))
        proc.returncode = 0
        mock_popen.return_value = proc

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager",
            return_value=mock_db_manager[0],
        ):
            linux_collector = LinuxPackageCollector()

            count = (
                linux_collector._collect_apt_packages()
            )  # pylint: disable=protected-access

            # Should return count of packages stored (2)
            assert count == 2
            # Verify database operations occurred
            assert mock_session.query.called
            assert mock_session.add.called
            assert mock_session.commit.called

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    def test_collect_apt_packages_command_failure(self, mock_run, mock_popen):
        """Test APT package collection when dumpavail fails (no output)."""
        # Create a Linux-specific collector directly
        from src.sysmanage_agent.collection.package_collector_linux import (
            LinuxPackageCollector,
        )

        mock_run.return_value = Mock(returncode=0, stdout="")
        proc = MagicMock()
        proc.__enter__.return_value = proc
        proc.__exit__.return_value = False
        proc.stdout = iter([])  # dumpavail produced nothing
        proc.returncode = 1  # ...and exited non-zero
        mock_popen.return_value = proc

        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ):
            linux_collector = LinuxPackageCollector()

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
