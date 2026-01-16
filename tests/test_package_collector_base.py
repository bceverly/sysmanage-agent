"""
Tests for base package collector module.
Tests common functionality for package collection.
"""

# pylint: disable=redefined-outer-name,protected-access,unused-argument

from unittest.mock import Mock, patch
from datetime import datetime, timezone

import pytest

from src.sysmanage_agent.collection.package_collector_base import BasePackageCollector


@pytest.fixture
def mock_db_manager():
    """Create a mock database manager."""
    mock_manager = Mock()
    mock_session = Mock()
    mock_manager.get_session.return_value.__enter__ = Mock(return_value=mock_session)
    mock_manager.get_session.return_value.__exit__ = Mock(return_value=False)
    return mock_manager


@pytest.fixture
def collector(mock_db_manager):
    """Create a package collector for testing."""
    with patch(
        "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
    ) as mock_get_db:
        mock_get_db.return_value = mock_db_manager
        return BasePackageCollector()


class TestBasePackageCollectorInit:
    """Tests for BasePackageCollector initialization."""

    def test_init_gets_db_manager(self, mock_db_manager):
        """Test that __init__ gets database manager."""
        with patch(
            "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
        ) as mock_get_db:
            mock_get_db.return_value = mock_db_manager
            collector = BasePackageCollector()

        assert collector.db_manager is not None


class TestIsPackageManagerAvailable:
    """Tests for _is_package_manager_available method."""

    def test_package_manager_available(self, collector):
        """Test package manager is available."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with patch("platform.system", return_value="Linux"):
                result = collector._is_package_manager_available("apt")

        assert result is True

    def test_package_manager_not_available(self, collector):
        """Test package manager is not available."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            with patch("platform.system", return_value="Linux"):
                result = collector._is_package_manager_available("nonexistent")

        assert result is False

    def test_package_manager_available_windows(self, collector):
        """Test package manager availability on Windows."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch("platform.system", return_value="Windows"):
                _ = collector._is_package_manager_available("choco")

        # Should use 'where' on Windows
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0][0] == "where"

    def test_package_manager_exception(self, collector):
        """Test package manager check with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            with patch("platform.system", return_value="Linux"):
                result = collector._is_package_manager_available("apt")

        assert result is False

    def test_brew_check_uses_dedicated_method(self, collector):
        """Test that brew uses dedicated check method."""
        with patch.object(collector, "_check_homebrew_available") as mock_brew:
            mock_brew.return_value = True
            result = collector._is_package_manager_available("brew")

        mock_brew.assert_called_once()
        assert result is True

    def test_winget_check_uses_dedicated_method(self, collector):
        """Test that winget uses dedicated check method on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(collector, "_check_winget_available") as mock_winget:
                mock_winget.return_value = True
                result = collector._is_package_manager_available("winget")

        mock_winget.assert_called_once()
        assert result is True


class TestCheckHomebrewAvailable:
    """Tests for _check_homebrew_available method."""

    def test_homebrew_apple_silicon_path(self, collector):
        """Test Homebrew detection on Apple Silicon."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = collector._check_homebrew_available()

        assert result is True

    def test_homebrew_not_available(self, collector):
        """Test Homebrew not available."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            result = collector._check_homebrew_available()

        assert result is False

    def test_homebrew_exception(self, collector):
        """Test Homebrew check with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = collector._check_homebrew_available()

        assert result is False


class TestCheckWingetAvailable:
    """Tests for _check_winget_available method."""

    def test_winget_found_in_localappdata(self, collector):
        """Test winget found in LocalAppData."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run", return_value=mock_result):
                result = collector._check_winget_available()

        assert result is True

    def test_winget_not_found(self, collector):
        """Test winget not found."""
        with patch("os.path.exists", return_value=False):
            with patch("glob.glob", return_value=[]):
                result = collector._check_winget_available()

        assert result is False


class TestGetHomebrewOwner:
    """Tests for _get_homebrew_owner method."""

    def test_get_homebrew_owner_apple_silicon(self, collector):
        """Test getting Homebrew owner on Apple Silicon."""
        mock_stat = Mock()
        mock_stat.st_uid = 501

        with patch("os.path.exists", return_value=True):
            with patch("os.stat", return_value=mock_stat):
                with patch("pwd.getpwuid") as mock_pwd:
                    mock_pwd.return_value = Mock(pw_name="testuser")
                    result = collector._get_homebrew_owner()

        assert result == "testuser"

    def test_get_homebrew_owner_not_found(self, collector):
        """Test getting Homebrew owner when not found."""
        with patch("os.path.exists", return_value=False):
            result = collector._get_homebrew_owner()

        assert result == ""


class TestGetBrewCommand:
    """Tests for _get_brew_command method."""

    def test_get_brew_command_normal_user(self, collector):
        """Test getting brew command as normal user."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with patch("os.geteuid", return_value=1000):  # Not root
                result = collector._get_brew_command()

        assert result in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew", "brew"]

    def test_get_brew_command_as_root(self, collector):
        """Test getting brew command as root."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with patch("os.geteuid", return_value=0):  # Root
                with patch.object(
                    collector, "_get_homebrew_owner", return_value="testuser"
                ):
                    result = collector._get_brew_command()

        assert "sudo -u testuser" in result

    def test_get_brew_command_not_found(self, collector):
        """Test getting brew command when not found."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            result = collector._get_brew_command()

        assert result == ""


class TestStorePackages:
    """Tests for _store_packages method."""

    def test_store_packages_success(self, collector, mock_db_manager):
        """Test successful package storage."""
        packages = [
            {"name": "pkg1", "version": "1.0", "description": "Package 1"},
            {"name": "pkg2", "version": "2.0", "description": "Package 2"},
        ]

        mock_session = Mock()
        mock_query = Mock()
        mock_query.filter.return_value.delete.return_value = None
        mock_session.query.return_value = mock_query

        with patch.object(collector.db_manager, "get_session") as mock_get_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_session)
            mock_context.__exit__ = Mock(return_value=False)
            mock_get_session.return_value = mock_context

            result = collector._store_packages("apt", packages)

        assert result == 2
        assert mock_session.add.call_count == 2
        mock_session.commit.assert_called_once()

    def test_store_packages_empty(self, collector):
        """Test storing empty package list."""
        result = collector._store_packages("apt", [])

        assert result == 0

    def test_store_packages_exception(self, collector, mock_db_manager):
        """Test package storage with exception."""
        packages = [{"name": "pkg1", "version": "1.0", "description": "Package 1"}]

        with patch.object(collector.db_manager, "get_session") as mock_get_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(side_effect=Exception("database error"))
            mock_context.__exit__ = Mock(return_value=False)
            mock_get_session.return_value = mock_context

            result = collector._store_packages("apt", packages)

        assert result == 0


class TestGetPackagesForManager:
    """Tests for get_packages_for_manager method."""

    def test_get_packages_for_manager_success(self, collector):
        """Test successful package retrieval for manager."""
        mock_packages = [
            Mock(
                id="1",
                package_manager="apt",
                package_name="pkg1",
                package_version="1.0",
                package_description="Package 1",
                collection_date=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
            ),
        ]

        mock_session = Mock()
        mock_query = Mock()
        mock_query.filter.return_value.all.return_value = mock_packages
        mock_session.query.return_value = mock_query

        with patch.object(collector.db_manager, "get_session") as mock_get_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_session)
            mock_context.__exit__ = Mock(return_value=False)
            mock_get_session.return_value = mock_context

            result = collector.get_packages_for_manager("apt")

        assert len(result) == 1
        assert result[0].package_name == "pkg1"


class TestGetAllPackages:
    """Tests for get_all_packages method."""

    def test_get_all_packages_success(self, collector):
        """Test successful retrieval of all packages."""
        mock_packages = [
            Mock(
                id="1",
                package_manager="apt",
                package_name="pkg1",
                package_version="1.0",
                package_description="Package 1",
                collection_date=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
            ),
        ]

        mock_session = Mock()
        mock_session.query.return_value.all.return_value = mock_packages

        with patch.object(collector.db_manager, "get_session") as mock_get_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_session)
            mock_context.__exit__ = Mock(return_value=False)
            mock_get_session.return_value = mock_context

            result = collector.get_all_packages()

        assert len(result) == 1


class TestGetPackageManagers:
    """Tests for get_package_managers method."""

    def test_get_package_managers_success(self, collector):
        """Test successful retrieval of package managers."""
        mock_session = Mock()
        mock_session.query.return_value.distinct.return_value.all.return_value = [
            ("apt",),
            ("yum",),
        ]

        with patch.object(collector.db_manager, "get_session") as mock_get_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_session)
            mock_context.__exit__ = Mock(return_value=False)
            mock_get_session.return_value = mock_context

            result = collector.get_package_managers()

        assert result == ["apt", "yum"]


class TestGetPackagesForTransmission:
    """Tests for get_packages_for_transmission method."""

    def test_get_packages_for_transmission_success(self, collector):
        """Test successful package transmission data retrieval."""
        mock_packages = [
            Mock(
                package_manager="apt",
                package_name="pkg1",
                package_version="1.0",
                package_description="Package 1",
            ),
            Mock(
                package_manager="apt",
                package_name="pkg2",
                package_version="2.0",
                package_description="Package 2",
            ),
        ]

        mock_session = Mock()
        mock_session.query.return_value.all.return_value = mock_packages

        with patch.object(collector.db_manager, "get_session") as mock_get_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_session)
            mock_context.__exit__ = Mock(return_value=False)
            mock_get_session.return_value = mock_context

            result = collector.get_packages_for_transmission()

        assert "package_managers" in result
        assert "apt" in result["package_managers"]
        assert len(result["package_managers"]["apt"]) == 2
