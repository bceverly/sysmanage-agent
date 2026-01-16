"""
Tests for BSD software inventory collection module.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.software_inventory_bsd import (
    BSDSoftwareInventoryCollector,
)


@pytest.fixture
def collector():
    """Create a BSDSoftwareInventoryCollector for testing."""
    return BSDSoftwareInventoryCollector()


class TestBSDSoftwareInventoryCollectorInit:
    """Tests for BSDSoftwareInventoryCollector initialization."""

    def test_init_sets_empty_collected_packages(self, collector):
        """Test that __init__ sets empty collected_packages list."""
        assert collector.collected_packages == []

    def test_init_sets_package_managers_to_none(self, collector):
        """Test that __init__ sets _package_managers to None."""
        assert collector._package_managers is None


class TestDetectPackageManagers:
    """Tests for detect_package_managers method."""

    def test_detect_pkg_available(self, collector):
        """Test detection when pkg is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "pkg"
            result = collector.detect_package_managers()

        assert "pkg" in result

    def test_detect_pkg_info_available(self, collector):
        """Test detection when pkg_info is available."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "pkg_info"
            result = collector.detect_package_managers()

        assert "pkg_info" in result

    def test_detect_ports_available(self, collector):
        """Test detection when make is available (ports)."""
        with patch.object(collector, "_command_exists") as mock_exists:
            mock_exists.side_effect = lambda cmd: cmd == "make"
            result = collector.detect_package_managers()

        assert "ports" in result

    def test_detect_multiple_managers(self, collector):
        """Test detection when multiple managers available."""
        with patch.object(collector, "_command_exists", return_value=True):
            result = collector.detect_package_managers()

        assert "pkg" in result
        assert "pkg_info" in result
        assert "ports" in result

    def test_detect_no_managers(self, collector):
        """Test detection when no managers available."""
        with patch.object(collector, "_command_exists", return_value=False):
            result = collector.detect_package_managers()

        assert result == []

    def test_detect_managers_cached(self, collector):
        """Test that package managers are cached after first detection."""
        collector._package_managers = ["pkg"]
        result = collector.detect_package_managers()

        assert result == ["pkg"]


class TestCollectPackages:
    """Tests for collect_packages method."""

    def test_collect_packages_with_pkg(self, collector):
        """Test collecting packages when pkg is available."""
        with patch.object(collector, "detect_package_managers", return_value=["pkg"]):
            with patch.object(collector, "_collect_pkg_packages") as mock_collect:
                collector.collect_packages()

        mock_collect.assert_called_once()

    def test_collect_packages_with_pkg_info(self, collector):
        """Test collecting packages when pkg_info is available."""
        with patch.object(
            collector, "detect_package_managers", return_value=["pkg_info"]
        ):
            with patch.object(collector, "_collect_pkg_info_packages") as mock_collect:
                collector.collect_packages()

        mock_collect.assert_called_once()

    def test_collect_packages_with_ports(self, collector):
        """Test collecting packages when ports is available."""
        with patch.object(collector, "detect_package_managers", return_value=["ports"]):
            with patch.object(collector, "_collect_ports_packages") as mock_collect:
                collector.collect_packages()

        mock_collect.assert_called_once()

    def test_collect_packages_with_all_managers(self, collector):
        """Test collecting packages when all managers are available."""
        with patch.object(
            collector,
            "detect_package_managers",
            return_value=["pkg", "pkg_info", "ports"],
        ):
            with patch.object(collector, "_collect_pkg_packages") as mock_pkg:
                with patch.object(collector, "_collect_pkg_info_packages") as mock_info:
                    with patch.object(
                        collector, "_collect_ports_packages"
                    ) as mock_ports:
                        collector.collect_packages()

        mock_pkg.assert_called_once()
        mock_info.assert_called_once()
        mock_ports.assert_called_once()


class TestCollectPkgPackages:
    """Tests for _collect_pkg_packages method."""

    def test_collect_pkg_packages_success(self, collector):
        """Test successful pkg package collection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "nginx-1.24.0 Web server\npython311-3.11.6 Python interpreter\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_pkg_packages()

        assert len(collector.collected_packages) >= 2

    def test_collect_pkg_packages_empty_output(self, collector):
        """Test pkg package collection with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_pkg_packages()

        assert len(collector.collected_packages) == 0

    def test_collect_pkg_packages_failure(self, collector):
        """Test pkg package collection with command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            collector._collect_pkg_packages()

        # Should not add any packages on failure
        assert len(collector.collected_packages) == 0

    def test_collect_pkg_packages_exception(self, collector):
        """Test pkg package collection with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            # Should not raise, just log error
            collector._collect_pkg_packages()

        assert len(collector.collected_packages) == 0


class TestCollectPkgInfoPackages:
    """Tests for _collect_pkg_info_packages method."""

    def test_collect_pkg_info_packages_openbsd(self, collector):
        """Test pkg_info package collection on OpenBSD."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "vim-9.0 Text editor\nbash-5.2 Shell\n"

        with patch("platform.system", return_value="OpenBSD"):
            with patch("subprocess.run", return_value=mock_result):
                collector._collect_pkg_info_packages()

        # Check that packages were collected with openbsd source
        for pkg in collector.collected_packages:
            assert pkg["source"] == "openbsd_packages"

    def test_collect_pkg_info_packages_netbsd(self, collector):
        """Test pkg_info package collection on NetBSD."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "vim-9.0 Text editor\n"

        with patch("platform.system", return_value="NetBSD"):
            with patch("subprocess.run", return_value=mock_result):
                collector._collect_pkg_info_packages()

        for pkg in collector.collected_packages:
            assert pkg["source"] == "netbsd_packages"

    def test_collect_pkg_info_packages_failure(self, collector):
        """Test pkg_info package collection with failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"

        with patch("platform.system", return_value="OpenBSD"):
            with patch("subprocess.run", return_value=mock_result):
                collector._collect_pkg_info_packages()

        assert len(collector.collected_packages) == 0


class TestParsePkgOutput:
    """Tests for _parse_pkg_output method."""

    def test_parse_pkg_output_simple_package(self, collector):
        """Test parsing simple package output."""
        output = "nginx-1.24.0 Robust and small WWW server\n"
        collector._parse_pkg_output(output, "freebsd_packages")

        assert len(collector.collected_packages) == 1
        pkg = collector.collected_packages[0]
        assert pkg["package_name"] == "nginx"
        assert pkg["version"] == "1.24.0"
        assert "WWW server" in pkg["description"]

    def test_parse_pkg_output_package_with_hyphen(self, collector):
        """Test parsing package with hyphen in name."""
        output = "py311-pip-23.0.1 Python package installer\n"
        collector._parse_pkg_output(output, "freebsd_packages")

        assert len(collector.collected_packages) == 1
        pkg = collector.collected_packages[0]
        assert pkg["package_name"] == "py311-pip"
        assert pkg["version"] == "23.0.1"

    def test_parse_pkg_output_multiple_packages(self, collector):
        """Test parsing multiple packages."""
        output = """nginx-1.24.0 Web server
python311-3.11.6 Python interpreter
vim-9.0 Text editor
"""
        collector._parse_pkg_output(output, "test_source")

        assert len(collector.collected_packages) == 3

    def test_parse_pkg_output_empty(self, collector):
        """Test parsing empty output."""
        collector._parse_pkg_output("", "test_source")

        assert len(collector.collected_packages) == 0


class TestIsBsdSystemPackage:
    """Tests for _is_bsd_system_package method."""

    def test_is_system_package_base(self, collector):
        """Test base package is detected as system package."""
        result = collector._is_bsd_system_package("base-comp")
        assert result is True

    def test_is_system_package_lib(self, collector):
        """Test lib package is detected as system package."""
        result = collector._is_bsd_system_package("libxml2")
        assert result is True

    def test_is_system_package_perl(self, collector):
        """Test perl package is detected as system package."""
        result = collector._is_bsd_system_package("perl-5.36")
        assert result is True

    def test_is_system_package_python(self, collector):
        """Test python package is detected as system package."""
        result = collector._is_bsd_system_package("python311")
        assert result is True

    def test_is_system_package_openssl(self, collector):
        """Test openssl is detected as system package."""
        result = collector._is_bsd_system_package("openssl")
        assert result is True

    def test_is_not_system_package_nginx(self, collector):
        """Test nginx is not detected as system package."""
        result = collector._is_bsd_system_package("nginx")
        assert result is False

    def test_is_not_system_package_user_app(self, collector):
        """Test user application is not detected as system package."""
        result = collector._is_bsd_system_package("myapp")
        assert result is False

    def test_is_system_package_case_insensitive(self, collector):
        """Test detection is case insensitive."""
        result = collector._is_bsd_system_package("LIBXML2")
        assert result is True


class TestCollectPortsPackages:
    """Tests for _collect_ports_packages method."""

    def test_collect_ports_packages_not_implemented(self, collector):
        """Test that ports collection logs but doesn't fail."""
        # Should not raise any exception
        collector._collect_ports_packages()

        # Should not add any packages (not implemented)
        assert len(collector.collected_packages) == 0
