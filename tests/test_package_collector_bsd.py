"""
Tests for BSD package collector module.
Tests package collection from BSD package managers (pkg, pkg_info, pkgin).
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.package_collector_bsd import BSDPackageCollector


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
    """Create a BSD package collector for testing."""
    with patch(
        "src.sysmanage_agent.collection.package_collector_base.get_database_manager"
    ) as mock_get_db:
        mock_get_db.return_value = mock_db_manager
        return BSDPackageCollector()


class TestBSDPackageCollectorInit:
    """Tests for BSDPackageCollector initialization."""

    def test_inherits_from_base(self, collector):
        """Test that collector inherits from BasePackageCollector."""
        assert hasattr(collector, "db_manager")


class TestCollectPackages:
    """Tests for collect_packages method."""

    def test_collect_packages_openbsd(self, collector):
        """Test package collection on OpenBSD."""
        with patch("platform.system", return_value="OpenBSD"):
            with patch.object(
                collector, "_is_package_manager_available"
            ) as mock_available:
                mock_available.side_effect = lambda m: m == "pkg_info"
                with patch.object(collector, "_collect_pkg_packages", return_value=100):
                    result = collector.collect_packages()

        assert result == 100

    def test_collect_packages_freebsd(self, collector):
        """Test package collection on FreeBSD."""
        with patch("platform.system", return_value="FreeBSD"):
            with patch.object(
                collector, "_is_package_manager_available"
            ) as mock_available:
                mock_available.side_effect = lambda m: m == "pkg"
                with patch.object(collector, "_collect_pkg_packages", return_value=150):
                    result = collector.collect_packages()

        assert result == 150

    def test_collect_packages_netbsd_pkgin(self, collector):
        """Test package collection on NetBSD with pkgin."""
        with patch("platform.system", return_value="NetBSD"):
            with patch.object(
                collector, "_is_package_manager_available"
            ) as mock_available:
                mock_available.side_effect = lambda m: m == "pkgin"
                with patch.object(
                    collector, "_collect_pkgin_packages", return_value=200
                ):
                    result = collector.collect_packages()

        assert result == 200

    def test_collect_packages_exception(self, collector):
        """Test package collection with exception."""
        with patch("platform.system", return_value="FreeBSD"):
            with patch.object(
                collector, "_is_package_manager_available", return_value=True
            ):
                with patch.object(
                    collector, "_collect_pkg_packages", side_effect=Exception("test")
                ):
                    result = collector.collect_packages()

        assert result == 0


class TestCollectPkgPackages:
    """Tests for _collect_pkg_packages method."""

    def test_collect_pkg_packages_freebsd(self, collector):
        """Test FreeBSD pkg package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """bash-5.2.15 GNU Project's Bourne Again SHell
vim-9.0 Vi Improved - highly configurable text editor
python39-3.9.18 Interpreted object-oriented programming language
"""

        with patch("platform.system", return_value="FreeBSD"):
            with patch("subprocess.run", return_value=mock_result):
                with patch.object(
                    collector, "_store_packages", return_value=3
                ) as mock_store:
                    result = collector._collect_pkg_packages()

        assert result == 3
        mock_store.assert_called_once()
        packages = mock_store.call_args[0][1]
        assert len(packages) == 3

    def test_collect_pkg_packages_openbsd(self, collector):
        """Test OpenBSD pkg_info package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """bash-5.2.15
vim-9.0.1000
python-3.9.18
"""

        with patch("platform.system", return_value="OpenBSD"):
            with patch("subprocess.run", return_value=mock_result):
                with patch.object(
                    collector, "_store_packages", return_value=3
                ) as mock_store:
                    result = collector._collect_pkg_packages()

        assert result == 3
        mock_store.assert_called_once_with("pkg_add", mock_store.call_args[0][1])

    def test_collect_pkg_packages_failure(self, collector):
        """Test pkg package collection failure."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("platform.system", return_value="FreeBSD"):
            with patch("subprocess.run", return_value=mock_result):
                result = collector._collect_pkg_packages()

        assert result == 0


class TestCollectPkginPackages:
    """Tests for _collect_pkgin_packages method."""

    def test_collect_pkgin_packages_success(self, collector):
        """Test pkgin package collection success."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """bash-5.2.15;GNU Project's Bourne Again SHell
vim-9.0;Vi Improved
python39-3.9.18;Interpreted programming language
"""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(
                collector, "_store_packages", return_value=3
            ) as mock_store:
                result = collector._collect_pkgin_packages()

        assert result == 3
        mock_store.assert_called_once_with("pkgin", mock_store.call_args[0][1])

    def test_collect_pkgin_packages_failure(self, collector):
        """Test pkgin package collection failure."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            result = collector._collect_pkgin_packages()

        assert result == 0

    def test_collect_pkgin_packages_exception(self, collector):
        """Test pkgin package collection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = collector._collect_pkgin_packages()

        assert result == 0


class TestParsePkgOutput:
    """Tests for _parse_pkg_output method."""

    def test_parse_pkg_output_with_description(self, collector):
        """Test parsing pkg output with description."""
        output = """bash-5.2.15 GNU Project's Bourne Again SHell
vim-9.0.1000 Vi Improved
"""
        packages = collector._parse_pkg_output(output)

        assert len(packages) == 2
        assert packages[0]["name"] == "bash"
        assert packages[0]["version"] == "5.2.15"
        assert packages[0]["description"] == "GNU Project's Bourne Again SHell"

    def test_parse_pkg_output_no_description(self, collector):
        """Test parsing pkg output without description."""
        output = """bash-5.2.15
vim-9.0.1000
"""
        packages = collector._parse_pkg_output(output)

        assert len(packages) == 2
        assert packages[0]["description"] == ""

    def test_parse_pkg_output_empty(self, collector):
        """Test parsing empty pkg output."""
        packages = collector._parse_pkg_output("")

        assert len(packages) == 0

    def test_parse_pkg_output_no_version(self, collector):
        """Test parsing pkg output with no version separator."""
        output = "packagename Some description\n"
        packages = collector._parse_pkg_output(output)

        assert len(packages) == 1
        assert packages[0]["name"] == "packagename"
        assert packages[0]["version"] == "unknown"


class TestParsePkgRqueryOutput:
    """Tests for _parse_pkg_rquery_output method."""

    def test_parse_pkg_rquery_output_success(self, collector):
        """Test parsing pkg rquery output."""
        output = """bash-5.2.15 GNU Project's Bourne Again SHell
python39-3.9.18 Interpreted programming language
"""
        packages = collector._parse_pkg_rquery_output(output)

        assert len(packages) == 2
        assert packages[0]["name"] == "bash"
        assert packages[0]["version"] == "5.2.15"
        assert packages[1]["name"] == "python39"
        assert packages[1]["version"] == "3.9.18"


class TestParsePkginOutput:
    """Tests for _parse_pkgin_output method."""

    def test_parse_pkgin_output_with_semicolon(self, collector):
        """Test parsing pkgin output with semicolon separator."""
        output = """bash-5.2.15;GNU Project's Bourne Again SHell
vim-9.0;Vi Improved editor
"""
        packages = collector._parse_pkgin_output(output)

        assert len(packages) == 2
        assert packages[0]["name"] == "bash"
        assert packages[0]["version"] == "5.2.15"
        assert packages[0]["description"] == "GNU Project's Bourne Again SHell"

    def test_parse_pkgin_output_without_semicolon(self, collector):
        """Test parsing pkgin output without semicolon."""
        output = """bash-5.2.15
vim-9.0
"""
        packages = collector._parse_pkgin_output(output)

        assert len(packages) == 2
        assert packages[0]["name"] == "bash"
        assert packages[0]["description"] == ""

    def test_parse_pkgin_output_skips_pkg_summary(self, collector):
        """Test that pkg_summary lines are skipped."""
        output = """pkg_summary.bz2
bash-5.2.15;Bourne Again SHell
"""
        packages = collector._parse_pkgin_output(output)

        assert len(packages) == 1
        assert packages[0]["name"] == "bash"


class TestParseOpenBsdPkgInfoOutput:
    """Tests for _parse_openbsd_pkg_info_output method."""

    def test_parse_openbsd_pkg_info_output_success(self, collector):
        """Test parsing OpenBSD pkg_info output."""
        output = """bash-5.2.15
vim-9.0.1000
python-3.9.18
"""
        packages = collector._parse_openbsd_pkg_info_output(output)

        assert len(packages) == 3
        assert packages[0]["name"] == "bash"
        assert packages[0]["version"] == "5.2.15"
        assert packages[1]["name"] == "vim"
        assert packages[1]["version"] == "9.0.1000"

    def test_parse_openbsd_pkg_info_output_complex_name(self, collector):
        """Test parsing OpenBSD pkg_info output with complex package name."""
        output = """node-gyp-9.4.0
python3-pip-23.1.2
"""
        packages = collector._parse_openbsd_pkg_info_output(output)

        assert len(packages) == 2
        assert packages[0]["name"] == "node-gyp"
        assert packages[0]["version"] == "9.4.0"
        assert packages[1]["name"] == "python3-pip"
        assert packages[1]["version"] == "23.1.2"

    def test_parse_openbsd_pkg_info_output_no_version(self, collector):
        """Test parsing OpenBSD pkg_info output when version can't be determined."""
        output = """package-with-no-version-number
"""
        packages = collector._parse_openbsd_pkg_info_output(output)

        assert len(packages) == 1
        # When the last part after dash is not a version number, whole thing is name
        assert packages[0]["name"] == "package-with-no-version-number"
        assert packages[0]["version"] == "unknown"

    def test_parse_openbsd_pkg_info_output_empty(self, collector):
        """Test parsing empty OpenBSD pkg_info output."""
        packages = collector._parse_openbsd_pkg_info_output("")

        assert len(packages) == 0

    def test_parse_openbsd_pkg_info_output_version_starts_with_digit(self, collector):
        """Test that version detection requires digit after dash."""
        output = """firefox-117.0
chromium-119.0.6045.105
"""
        packages = collector._parse_openbsd_pkg_info_output(output)

        assert packages[0]["name"] == "firefox"
        assert packages[0]["version"] == "117.0"
        assert packages[1]["name"] == "chromium"
        assert packages[1]["version"] == "119.0.6045.105"
