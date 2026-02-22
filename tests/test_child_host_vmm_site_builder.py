"""
Unit tests for VMM site tarball builder.
Tests the SiteTarballBuilder class for building OpenBSD site77.tgz.
"""

# pylint: disable=protected-access,redefined-outer-name

import hashlib
import os
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_vmm_site_builder import (
    SiteTarballBuilder,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return Mock()


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    return Mock()


@pytest.fixture
def builder(mock_logger, mock_db_session):
    """Create a SiteTarballBuilder for testing."""
    return SiteTarballBuilder(mock_logger, mock_db_session)


class TestSiteTarballBuilderInit:
    """Tests for SiteTarballBuilder initialization."""

    def test_init_sets_logger(self, mock_logger, mock_db_session):
        """Test that __init__ sets logger."""
        builder = SiteTarballBuilder(mock_logger, mock_db_session)
        assert builder.logger == mock_logger

    def test_init_sets_db_session(self, mock_logger, mock_db_session):
        """Test that __init__ sets db_session."""
        builder = SiteTarballBuilder(mock_logger, mock_db_session)
        assert builder.db_session == mock_db_session

    def test_pkg_url_template(self, builder):
        """Test PKG_URL_TEMPLATE format."""
        assert "ftp.openbsd.org" in builder.PKG_URL_TEMPLATE
        assert "{version}" in builder.PKG_URL_TEMPLATE
        assert "amd64" in builder.PKG_URL_TEMPLATE

    def test_github_release_url_template(self, builder):
        """Test GITHUB_RELEASE_URL_TEMPLATE format."""
        assert "github.com" in builder.GITHUB_RELEASE_URL_TEMPLATE
        assert "sysmanage-agent" in builder.GITHUB_RELEASE_URL_TEMPLATE
        assert "{agent_version}" in builder.GITHUB_RELEASE_URL_TEMPLATE
        assert "{openbsd_nodot}" in builder.GITHUB_RELEASE_URL_TEMPLATE


class TestGetAgentPackagePath:
    """Tests for _get_agent_package_path static method."""

    def test_returns_correct_path_format(self, builder):
        """Test the path format returned."""
        with patch.object(Path, "mkdir"):
            path = builder._get_agent_package_path("7.7", "1.0.0")
        assert "sysmanage-agent-1.0.0-obsd7.7.tgz" in path
        assert "/var/vmm/agent-packages/" in path

    def test_different_versions(self, builder):
        """Test with different version combinations."""
        with patch.object(Path, "mkdir"):
            path1 = builder._get_agent_package_path("7.6", "2.0.0")
            path2 = builder._get_agent_package_path("7.5", "1.5.0")

        assert "sysmanage-agent-2.0.0-obsd7.6.tgz" in path1
        assert "sysmanage-agent-1.5.0-obsd7.5.tgz" in path2


class TestGetDependencyCacheDir:
    """Tests for _get_dependency_cache_dir method."""

    def test_returns_path_with_version(self, builder):
        """Test path includes version."""
        with patch.object(Path, "mkdir"):
            path = builder._get_dependency_cache_dir("7.7")
        assert "7.7" in str(path)
        assert "/var/vmm/package-cache" in str(path)

    def test_creates_directory(self, builder):
        """Test that directory is created."""
        with patch(
            "src.sysmanage_agent.operations.child_host_vmm_site_builder.Path"
        ) as mock_path:
            mock_cache_dir = MagicMock()
            mock_path.return_value.__truediv__.return_value = mock_cache_dir
            builder._get_dependency_cache_dir("7.7")
            mock_cache_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)


class TestCalculateChecksum:
    """Tests for _calculate_checksum static method."""

    def test_calculates_sha256(self, builder, tmp_path):
        """Test SHA256 checksum calculation."""
        test_file = tmp_path / "test.txt"
        test_content = b"Hello, World!"
        test_file.write_bytes(test_content)

        expected = hashlib.sha256(test_content).hexdigest()
        result = builder._calculate_checksum(str(test_file))

        assert result == expected

    def test_handles_large_file(self, builder, tmp_path):
        """Test checksum for larger files."""
        test_file = tmp_path / "large.bin"
        # Create a file larger than the 8192 chunk size
        test_content = b"x" * 20000
        test_file.write_bytes(test_content)

        expected = hashlib.sha256(test_content).hexdigest()
        result = builder._calculate_checksum(str(test_file))

        assert result == expected

    def test_empty_file(self, builder, tmp_path):
        """Test checksum for empty file."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        expected = hashlib.sha256(b"").hexdigest()
        result = builder._calculate_checksum(str(test_file))

        assert result == expected


class TestDownloadPortTarball:
    """Tests for _download_port_tarball method."""

    def test_successful_download(self, builder, tmp_path):
        """Test successful port tarball download."""
        # Create a mock tarball with a Makefile inside
        tar_content = b"mock content"

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = Mock()
            mock_response.read.return_value = tar_content
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            with patch("shutil.copyfileobj"):
                with patch("tarfile.open") as mock_tarfile:
                    mock_tar = Mock()
                    mock_tarfile.return_value.__enter__ = Mock(return_value=mock_tar)
                    mock_tarfile.return_value.__exit__ = Mock(return_value=False)

                    # Make Path.exists() return True for tarball
                    with patch.object(Path, "exists", return_value=True):
                        with patch.object(Path, "stat") as mock_stat:
                            mock_stat.return_value.st_size = 1000
                            with patch.object(Path, "iterdir", return_value=[]):
                                result = builder._download_port_tarball(
                                    "https://example.com/port.tar.gz", tmp_path
                                )

        assert result["success"] is True
        assert result["port_dir"] is not None
        assert result["error"] is None

    def test_http_error(self, builder, tmp_path):
        """Test handling of HTTP errors."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "https://example.com", 404, "Not Found", {}, None
            )

            result = builder._download_port_tarball(
                "https://example.com/port.tar.gz", tmp_path
            )

        assert result["success"] is False
        assert "HTTP error" in result["error"]
        assert result["port_dir"] is None

    def test_url_error(self, builder, tmp_path):
        """Test handling of URL/network errors."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

            result = builder._download_port_tarball(
                "https://example.com/port.tar.gz", tmp_path
            )

        assert result["success"] is False
        assert "Network error" in result["error"]
        assert result["port_dir"] is None

    def test_unexpected_error(self, builder, tmp_path):
        """Test handling of unexpected errors."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("Unexpected error")

            result = builder._download_port_tarball(
                "https://example.com/port.tar.gz", tmp_path
            )

        assert result["success"] is False
        assert "Download failed" in result["error"]
        assert result["port_dir"] is None

    def test_missing_tarball_after_download(self, builder, tmp_path):
        """Test when downloaded tarball is not found."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = Mock()
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            with patch("shutil.copyfileobj"):
                with patch.object(Path, "exists", return_value=False):
                    result = builder._download_port_tarball(
                        "https://example.com/port.tar.gz", tmp_path
                    )

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_missing_makefile_after_extraction(self, builder, tmp_path):
        """Test when Makefile is not found after extraction."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = Mock()
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            with patch("shutil.copyfileobj"):
                with patch("tarfile.open") as mock_tarfile:
                    mock_tar = Mock()
                    mock_tarfile.return_value.__enter__ = Mock(return_value=mock_tar)
                    mock_tarfile.return_value.__exit__ = Mock(return_value=False)

                    # First exists() for tarball, second for Makefile
                    with patch.object(Path, "exists", side_effect=[True, False]):
                        with patch.object(Path, "stat") as mock_stat:
                            mock_stat.return_value.st_size = 1000
                            with patch.object(Path, "iterdir", return_value=[]):
                                result = builder._download_port_tarball(
                                    "https://example.com/port.tar.gz", tmp_path
                                )

        assert result["success"] is False
        assert "Makefile not found" in result["error"]


class TestDownloadPrebuiltAgentPackage:
    """Tests for _download_prebuilt_agent_package method."""

    def test_unsupported_openbsd_version(self, builder, tmp_path):
        """Test with unsupported OpenBSD version."""
        result = builder._download_prebuilt_agent_package("6.9", "1.0.0", tmp_path)

        assert result["success"] is False
        assert "not supported" in result["error"]
        assert result["package_path"] is None

    def test_successful_download(self, builder, tmp_path):
        """Test successful package download."""
        # Create a gzip magic bytes response
        mock_content = b"\x1f\x8b" + b"fake gzip content" * 100

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = Mock()
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            with patch("shutil.copyfileobj"):
                with patch.object(Path, "exists", return_value=True):
                    with patch.object(Path, "stat") as mock_stat:
                        mock_stat.return_value.st_size = 5000
                        with patch("builtins.open", mock_open(read_data=mock_content)):
                            with patch.object(Path, "rename"):
                                result = builder._download_prebuilt_agent_package(
                                    "7.7", "1.0.0", tmp_path
                                )

        assert result["success"] is True
        assert result["error"] is None

    def test_404_error_no_retry(self, builder, tmp_path):
        """Test that 404 errors don't retry."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "https://github.com", 404, "Not Found", {}, None
            )

            result = builder._download_prebuilt_agent_package("7.7", "1.0.0", tmp_path)

        assert result["success"] is False
        assert "not found" in result["error"].lower()
        # Should only be called once for 404 (no retries)
        assert mock_urlopen.call_count == 1

    def test_network_error_retries(self, builder, tmp_path):
        """Test that network errors trigger retries."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

            with patch("time.sleep"):  # Skip actual delays
                result = builder._download_prebuilt_agent_package(
                    "7.7", "1.0.0", tmp_path
                )

        assert result["success"] is False
        assert "Failed to download" in result["error"]
        # Should retry 5 times
        assert mock_urlopen.call_count == 5

    def test_file_too_small(self, builder, tmp_path):
        """Test rejection of too-small downloaded files."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = Mock()
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            with patch("shutil.copyfileobj"):
                with patch.object(Path, "exists", return_value=True):
                    with patch.object(Path, "stat") as mock_stat:
                        mock_stat.return_value.st_size = 100  # Too small
                        with patch("time.sleep"):
                            result = builder._download_prebuilt_agent_package(
                                "7.7", "1.0.0", tmp_path
                            )

        assert result["success"] is False

    def test_invalid_gzip_file(self, builder, tmp_path):
        """Test rejection of non-gzip files."""
        # Non-gzip magic bytes
        non_gzip_content = b"not a gzip file"

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = Mock()
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            with patch("shutil.copyfileobj"):
                with patch.object(Path, "exists", return_value=True):
                    with patch.object(Path, "stat") as mock_stat:
                        mock_stat.return_value.st_size = 5000
                        with patch(
                            "builtins.open", mock_open(read_data=non_gzip_content)
                        ):
                            with patch("time.sleep"):
                                result = builder._download_prebuilt_agent_package(
                                    "7.7", "1.0.0", tmp_path
                                )

        assert result["success"] is False


class TestValidateAndRenamePackage:
    """Tests for _validate_and_rename_package method."""

    def test_file_not_found(self, builder, tmp_path):
        """Test handling of missing file."""
        pkg_path = tmp_path / "nonexistent.tgz"

        with pytest.raises(FileNotFoundError):
            builder._validate_and_rename_package(
                pkg_path, "test.tgz", "1.0.0", tmp_path
            )

    def test_file_too_small(self, builder, tmp_path):
        """Test rejection of too-small files."""
        pkg_path = tmp_path / "small.tgz"
        pkg_path.write_bytes(b"tiny")

        with pytest.raises(ValueError, match="too small"):
            builder._validate_and_rename_package(
                pkg_path, "small.tgz", "1.0.0", tmp_path
            )

    def test_invalid_gzip(self, builder, tmp_path):
        """Test rejection of non-gzip files."""
        pkg_path = tmp_path / "invalid.tgz"
        pkg_path.write_bytes(b"x" * 2000)  # Large enough but not gzip

        with pytest.raises(ValueError, match="not a valid gzip"):
            builder._validate_and_rename_package(
                pkg_path, "invalid.tgz", "1.0.0", tmp_path
            )

    def test_successful_validation_and_rename(self, builder, tmp_path):
        """Test successful validation and rename."""
        pkg_path = tmp_path / "test.tgz"
        # Write valid gzip magic bytes + padding
        content = b"\x1f\x8b" + b"x" * 2000
        pkg_path.write_bytes(content)

        result = builder._validate_and_rename_package(
            pkg_path, "test.tgz", "1.0.0", tmp_path
        )

        assert result["success"] is True
        assert "sysmanage-agent-1.0.0p0.tgz" in result["package_path"]


class TestHandleDownloadError:
    """Tests for _handle_download_error method."""

    def test_http_404_error(self, builder):
        """Test handling of 404 HTTP error."""
        error = urllib.error.HTTPError(
            "https://example.com", 404, "Not Found", {}, None
        )

        result = builder._handle_download_error(error, 1, "7.7", "1.0.0")

        assert result is not None
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_http_other_error(self, builder):
        """Test handling of non-404 HTTP error."""
        error = urllib.error.HTTPError(
            "https://example.com", 500, "Server Error", {}, None
        )

        result = builder._handle_download_error(error, 1, "7.7", "1.0.0")

        # Should return None to signal retry
        assert result is None

    def test_url_error(self, builder):
        """Test handling of URL error."""
        error = urllib.error.URLError("Connection refused")

        result = builder._handle_download_error(error, 1, "7.7", "1.0.0")

        # Should return None to signal retry
        assert result is None

    def test_generic_error(self, builder):
        """Test handling of generic error."""
        error = Exception("Something went wrong")

        result = builder._handle_download_error(error, 1, "7.7", "1.0.0")

        # Should return None to signal retry
        assert result is None


class TestDownloadDependencies:
    """Tests for _download_dependencies method."""

    def test_uses_cached_packages(self, builder, tmp_path):
        """Test that cached packages are used."""
        _packages_dir = tmp_path / "packages"

        with patch.object(builder, "_get_dependency_cache_dir") as mock_cache_dir:
            mock_cache = tmp_path / "cache"
            mock_cache.mkdir()
            # Create a cached package
            cached_pkg = mock_cache / "python-3.12.9.tgz"
            cached_pkg.write_bytes(b"cached content")
            mock_cache_dir.return_value = mock_cache

            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_site_builder.REQUIRED_PACKAGES_BY_VERSION",
                {"7.7": ["python-3.12.9"]},
            ):
                result = builder._download_dependencies("7.7", tmp_path)

        assert result["success"] is True
        assert result["packages_dir"] is not None

    def test_downloads_missing_packages(self, builder, tmp_path):
        """Test that missing packages are downloaded."""
        with patch.object(builder, "_get_dependency_cache_dir") as mock_cache_dir:
            mock_cache = tmp_path / "cache"
            mock_cache.mkdir()
            mock_cache_dir.return_value = mock_cache

            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                with patch("shutil.copyfileobj"):
                    with patch("shutil.copy2"):
                        with patch(
                            "src.sysmanage_agent.operations.child_host_vmm_site_builder.REQUIRED_PACKAGES_BY_VERSION",
                            {"7.7": ["test-pkg-1.0"]},
                        ):
                            # Mock glob to return enough packages
                            with patch.object(
                                Path, "glob", return_value=[Path("pkg1.tgz")]
                            ):
                                result = builder._download_dependencies("7.7", tmp_path)

        assert result["success"] is True

    def test_fallback_to_default_packages(self, builder, tmp_path):
        """Test fallback to default package list."""
        with patch.object(builder, "_get_dependency_cache_dir") as mock_cache_dir:
            mock_cache = tmp_path / "cache"
            mock_cache.mkdir()
            mock_cache_dir.return_value = mock_cache

            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                with patch("shutil.copyfileobj"):
                    with patch("shutil.copy2"):
                        # Mock glob to return enough packages
                        with patch.object(
                            Path,
                            "glob",
                            return_value=[Path(f"pkg{i}.tgz") for i in range(20)],
                        ):
                            # Use a version not in REQUIRED_PACKAGES_BY_VERSION
                            result = builder._download_dependencies("9.9", tmp_path)

        assert result["success"] is True

    def test_too_few_packages_downloaded(self, builder, tmp_path):
        """Test failure when too few packages are downloaded."""
        with patch.object(builder, "_get_dependency_cache_dir") as mock_cache_dir:
            mock_cache = tmp_path / "cache"
            mock_cache.mkdir()
            mock_cache_dir.return_value = mock_cache

            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = Exception("Download failed")

                with patch(
                    "src.sysmanage_agent.operations.child_host_vmm_site_builder.REQUIRED_PACKAGES_BY_VERSION",
                    {"7.7": ["pkg1", "pkg2", "pkg3", "pkg4", "pkg5", "pkg6"]},
                ):
                    with patch.object(Path, "glob", return_value=[]):
                        result = builder._download_dependencies("7.7", tmp_path)

        assert result["success"] is False
        assert "Too few packages" in result["error"]

    def test_exception_during_download(self, builder, tmp_path):
        """Test exception handling during download."""
        with patch.object(builder, "_get_dependency_cache_dir") as mock_cache_dir:
            mock_cache_dir.side_effect = Exception("Cache error")

            result = builder._download_dependencies("7.7", tmp_path)

        assert result["success"] is False
        assert "Dependency download failed" in result["error"]


class TestCreateSiteStructure:
    """Tests for _create_site_structure method."""

    def test_creates_directory_structure(self, builder, tmp_path):
        """Test that directory structure is created."""
        # Create packages directory with a test package
        packages_dir = tmp_path / "packages"
        packages_dir.mkdir()
        (packages_dir / "test.tgz").write_bytes(b"test")

        # Create agent package
        agent_pkg = tmp_path / "agent.tgz"
        agent_pkg.write_bytes(b"agent")

        result = builder._create_site_structure(
            tmp_path,
            str(agent_pkg),
            packages_dir,
            "server.example.com",
            8443,
            True,
            "test-token-uuid",
        )

        assert result["success"] is True
        assert result["error"] is None

        # Verify structure
        site_dir = tmp_path / "site77"
        assert site_dir.exists()
        assert (site_dir / "root").exists()
        assert (site_dir / "etc").exists()
        assert (site_dir / "install.site").exists()

    def test_creates_config_file(self, builder, tmp_path):
        """Test that config file is created."""
        packages_dir = tmp_path / "packages"
        packages_dir.mkdir()

        agent_pkg = tmp_path / "agent.tgz"
        agent_pkg.write_bytes(b"agent")

        builder._create_site_structure(
            tmp_path,
            str(agent_pkg),
            packages_dir,
            "server.example.com",
            8443,
            True,
            None,
        )

        config_path = tmp_path / "site77" / "etc" / "sysmanage-agent.yaml"
        assert config_path.exists()
        content = config_path.read_text()
        assert "server.example.com" in content
        assert "8443" in content

    def test_creates_firsttime_script(self, builder, tmp_path):
        """Test that rc.firsttime script is created."""
        packages_dir = tmp_path / "packages"
        packages_dir.mkdir()

        agent_pkg = tmp_path / "agent.tgz"
        agent_pkg.write_bytes(b"agent")

        builder._create_site_structure(
            tmp_path,
            str(agent_pkg),
            packages_dir,
            "server.example.com",
            8443,
            True,
            None,
        )

        firsttime_path = tmp_path / "site77" / "etc" / "rc.firsttime"
        assert firsttime_path.exists()
        # Check it's executable
        assert os.access(firsttime_path, os.X_OK)

    def test_creates_install_site_script(self, builder, tmp_path):
        """Test that install.site script is created."""
        packages_dir = tmp_path / "packages"
        packages_dir.mkdir()

        agent_pkg = tmp_path / "agent.tgz"
        agent_pkg.write_bytes(b"agent")

        builder._create_site_structure(
            tmp_path,
            str(agent_pkg),
            packages_dir,
            "server.example.com",
            8443,
            True,
            None,
        )

        install_site_path = tmp_path / "site77" / "install.site"
        assert install_site_path.exists()
        assert os.access(install_site_path, os.X_OK)

    def test_handles_exception(self, builder, tmp_path):
        """Test exception handling."""
        with patch("shutil.copy2", side_effect=Exception("Copy failed")):
            result = builder._create_site_structure(
                tmp_path,
                "/nonexistent/path",
                tmp_path,
                "server.example.com",
                8443,
                True,
                None,
            )

        assert result["success"] is False
        assert "Site structure creation failed" in result["error"]


class TestCreateTarball:
    """Tests for _create_tarball method."""

    def test_site_directory_not_found(self, builder, tmp_path):
        """Test error when site directory doesn't exist."""
        result = builder._create_tarball(tmp_path, "7.7")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_creates_tarball_successfully(self, builder, tmp_path):
        """Test successful tarball creation."""
        # Create site directory
        site_dir = tmp_path / "site77"
        site_dir.mkdir()
        (site_dir / "test.txt").write_text("test content")

        with patch.object(Path, "mkdir"):
            with patch("tarfile.open") as mock_tarfile:
                mock_tar = Mock()
                mock_tarfile.return_value.__enter__ = Mock(return_value=mock_tar)
                mock_tarfile.return_value.__exit__ = Mock(return_value=False)

                result = builder._create_tarball(tmp_path, "7.7")

        assert result["success"] is True
        assert "site77.tgz" in result["tarball_path"]

    def test_handles_tarball_creation_error(self, builder, tmp_path):
        """Test error handling during tarball creation."""
        site_dir = tmp_path / "site77"
        site_dir.mkdir()

        with patch("os.makedirs"):
            with patch("tarfile.open", side_effect=Exception("Tarball error")):
                result = builder._create_tarball(tmp_path, "7.7")

        assert result["success"] is False
        assert "Tarball creation failed" in result["error"]


class TestBuildAgentPackage:
    """Tests for _build_agent_package method."""

    def test_delegates_to_package_builder(self, builder, tmp_path):
        """Test that build is delegated to PackageBuilder."""
        with patch(
            "src.sysmanage_agent.operations.child_host_vmm_site_builder.PackageBuilder"
        ) as mock_builder_class:
            mock_pkg_builder = Mock()
            mock_pkg_builder.build_agent_package.return_value = {
                "success": True,
                "package_path": "/path/to/pkg.tgz",
                "error": None,
            }
            mock_builder_class.return_value = mock_pkg_builder

            result = builder._build_agent_package(tmp_path, "1.0.0")

        assert result["success"] is True
        mock_pkg_builder.build_agent_package.assert_called_once_with(tmp_path, "1.0.0")


class TestBuildSiteTarball:
    """Tests for build_site_tarball method."""

    def test_uses_cached_agent_package(self, builder):
        """Test using cached agent package."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=True):
                with patch.object(builder, "_download_dependencies") as mock_deps:
                    mock_deps.return_value = {
                        "success": True,
                        "packages_dir": Path("/packages"),
                        "error": None,
                    }
                    with patch.object(
                        builder, "_create_site_structure"
                    ) as mock_structure:
                        mock_structure.return_value = {"success": True, "error": None}
                        with patch.object(builder, "_create_tarball") as mock_tarball:
                            mock_tarball.return_value = {
                                "success": True,
                                "tarball_path": "/site77.tgz",
                                "error": None,
                            }
                            with patch.object(
                                builder, "_calculate_checksum", return_value="abc123"
                            ):
                                with patch("os.makedirs"):
                                    with patch("shutil.copy2"):
                                        with patch(
                                            "tempfile.TemporaryDirectory"
                                        ) as mock_tmpdir:
                                            mock_tmpdir.return_value.__enter__ = Mock(
                                                return_value="/tmp/build"
                                            )
                                            mock_tmpdir.return_value.__exit__ = Mock(
                                                return_value=False
                                            )

                                            result = builder.build_site_tarball(
                                                "7.7",
                                                "1.0.0",
                                                "https://example.com/agent.tar.gz",
                                                "server.example.com",
                                                8443,
                                                True,
                                            )

        assert result["success"] is True
        assert result["site_tgz_path"] == "/site77.tgz"

    def test_downloads_prebuilt_for_supported_version(self, builder):
        """Test downloading pre-built package for supported version."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=False):  # Not cached
                with patch.object(
                    builder, "_download_prebuilt_agent_package"
                ) as mock_prebuilt:
                    mock_prebuilt.return_value = {
                        "success": True,
                        "package_path": "/prebuilt/agent.tgz",
                        "error": None,
                    }
                    with patch.object(builder, "_download_dependencies") as mock_deps:
                        mock_deps.return_value = {
                            "success": True,
                            "packages_dir": Path("/packages"),
                            "error": None,
                        }
                        with patch.object(
                            builder, "_create_site_structure"
                        ) as mock_structure:
                            mock_structure.return_value = {
                                "success": True,
                                "error": None,
                            }
                            with patch.object(
                                builder, "_create_tarball"
                            ) as mock_tarball:
                                mock_tarball.return_value = {
                                    "success": True,
                                    "tarball_path": "/site77.tgz",
                                    "error": None,
                                }
                                with patch.object(
                                    builder,
                                    "_calculate_checksum",
                                    return_value="abc123",
                                ):
                                    with patch("os.makedirs"):
                                        with patch("shutil.copy2"):
                                            with patch(
                                                "tempfile.TemporaryDirectory"
                                            ) as mock_tmpdir:
                                                mock_tmpdir.return_value.__enter__ = (
                                                    Mock(return_value="/tmp/build")
                                                )
                                                mock_tmpdir.return_value.__exit__ = (
                                                    Mock(return_value=False)
                                                )

                                                result = builder.build_site_tarball(
                                                    "7.7",
                                                    "1.0.0",
                                                    "https://example.com/agent.tar.gz",
                                                    "server.example.com",
                                                    8443,
                                                    True,
                                                )

        assert result["success"] is True
        mock_prebuilt.assert_called_once()

    def test_falls_back_to_building_from_ports(self, builder):
        """Test fallback to building from ports when pre-built not available."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=False):  # Not cached
                with patch.object(
                    builder, "_download_prebuilt_agent_package"
                ) as mock_prebuilt:
                    mock_prebuilt.return_value = {
                        "success": False,
                        "package_path": None,
                        "error": "Not found",
                    }
                    with patch.object(builder, "_download_port_tarball") as mock_port:
                        mock_port.return_value = {
                            "success": True,
                            "port_dir": Path("/port"),
                            "error": None,
                        }
                        with patch.object(
                            builder, "_build_agent_package"
                        ) as mock_build:
                            mock_build.return_value = {
                                "success": True,
                                "package_path": "/built/agent.tgz",
                                "error": None,
                            }
                            with patch.object(
                                builder, "_download_dependencies"
                            ) as mock_deps:
                                mock_deps.return_value = {
                                    "success": True,
                                    "packages_dir": Path("/packages"),
                                    "error": None,
                                }
                                with patch.object(
                                    builder, "_create_site_structure"
                                ) as mock_structure:
                                    mock_structure.return_value = {
                                        "success": True,
                                        "error": None,
                                    }
                                    with patch.object(
                                        builder, "_create_tarball"
                                    ) as mock_tarball:
                                        mock_tarball.return_value = {
                                            "success": True,
                                            "tarball_path": "/site77.tgz",
                                            "error": None,
                                        }
                                        with patch.object(
                                            builder,
                                            "_calculate_checksum",
                                            return_value="abc123",
                                        ):
                                            with patch("os.makedirs"):
                                                with patch("shutil.copy2"):
                                                    with patch(
                                                        "tempfile.TemporaryDirectory"
                                                    ) as mock_tmpdir:
                                                        mock_tmpdir.return_value.__enter__ = Mock(
                                                            return_value="/tmp/build"
                                                        )
                                                        mock_tmpdir.return_value.__exit__ = Mock(
                                                            return_value=False
                                                        )

                                                        result = builder.build_site_tarball(
                                                            "7.7",
                                                            "1.0.0",
                                                            "https://example.com/agent.tar.gz",
                                                            "server.example.com",
                                                            8443,
                                                            True,
                                                        )

        assert result["success"] is True
        mock_port.assert_called_once()
        mock_build.assert_called_once()

    def test_port_download_failure(self, builder):
        """Test handling of port download failure."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=False):
                with patch.object(
                    builder, "_download_prebuilt_agent_package"
                ) as mock_prebuilt:
                    mock_prebuilt.return_value = {
                        "success": False,
                        "package_path": None,
                        "error": "Not found",
                    }
                    with patch.object(builder, "_download_port_tarball") as mock_port:
                        mock_port.return_value = {
                            "success": False,
                            "port_dir": None,
                            "error": "Download failed",
                        }
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/build"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)

                            result = builder.build_site_tarball(
                                "7.7",
                                "1.0.0",
                                "https://example.com/agent.tar.gz",
                                "server.example.com",
                                8443,
                                True,
                            )

        assert result["success"] is False
        assert result["error"] == "Download failed"

    def test_package_build_failure(self, builder):
        """Test handling of package build failure."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=False):
                with patch.object(
                    builder, "_download_prebuilt_agent_package"
                ) as mock_prebuilt:
                    mock_prebuilt.return_value = {
                        "success": False,
                        "package_path": None,
                        "error": "Not found",
                    }
                    with patch.object(builder, "_download_port_tarball") as mock_port:
                        mock_port.return_value = {
                            "success": True,
                            "port_dir": Path("/port"),
                            "error": None,
                        }
                        with patch.object(
                            builder, "_build_agent_package"
                        ) as mock_build:
                            mock_build.return_value = {
                                "success": False,
                                "package_path": None,
                                "error": "Build failed",
                            }
                            with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                                mock_tmpdir.return_value.__enter__ = Mock(
                                    return_value="/tmp/build"
                                )
                                mock_tmpdir.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = builder.build_site_tarball(
                                    "7.7",
                                    "1.0.0",
                                    "https://example.com/agent.tar.gz",
                                    "server.example.com",
                                    8443,
                                    True,
                                )

        assert result["success"] is False
        assert result["error"] == "Build failed"

    def test_dependency_download_failure(self, builder):
        """Test handling of dependency download failure."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=True):  # Cached
                with patch.object(builder, "_download_dependencies") as mock_deps:
                    mock_deps.return_value = {
                        "success": False,
                        "packages_dir": None,
                        "error": "Dependency download failed",
                    }
                    with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                        mock_tmpdir.return_value.__enter__ = Mock(
                            return_value="/tmp/build"
                        )
                        mock_tmpdir.return_value.__exit__ = Mock(return_value=False)

                        result = builder.build_site_tarball(
                            "7.7",
                            "1.0.0",
                            "https://example.com/agent.tar.gz",
                            "server.example.com",
                            8443,
                            True,
                        )

        assert result["success"] is False

    def test_site_structure_creation_failure(self, builder):
        """Test handling of site structure creation failure."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=True):
                with patch.object(builder, "_download_dependencies") as mock_deps:
                    mock_deps.return_value = {
                        "success": True,
                        "packages_dir": Path("/packages"),
                        "error": None,
                    }
                    with patch.object(
                        builder, "_create_site_structure"
                    ) as mock_structure:
                        mock_structure.return_value = {
                            "success": False,
                            "error": "Structure creation failed",
                        }
                        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                            mock_tmpdir.return_value.__enter__ = Mock(
                                return_value="/tmp/build"
                            )
                            mock_tmpdir.return_value.__exit__ = Mock(return_value=False)

                            result = builder.build_site_tarball(
                                "7.7",
                                "1.0.0",
                                "https://example.com/agent.tar.gz",
                                "server.example.com",
                                8443,
                                True,
                            )

        assert result["success"] is False

    def test_tarball_creation_failure(self, builder):
        """Test handling of tarball creation failure."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=True):
                with patch.object(builder, "_download_dependencies") as mock_deps:
                    mock_deps.return_value = {
                        "success": True,
                        "packages_dir": Path("/packages"),
                        "error": None,
                    }
                    with patch.object(
                        builder, "_create_site_structure"
                    ) as mock_structure:
                        mock_structure.return_value = {"success": True, "error": None}
                        with patch.object(builder, "_create_tarball") as mock_tarball:
                            mock_tarball.return_value = {
                                "success": False,
                                "tarball_path": None,
                                "error": "Tarball creation failed",
                            }
                            with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                                mock_tmpdir.return_value.__enter__ = Mock(
                                    return_value="/tmp/build"
                                )
                                mock_tmpdir.return_value.__exit__ = Mock(
                                    return_value=False
                                )

                                result = builder.build_site_tarball(
                                    "7.7",
                                    "1.0.0",
                                    "https://example.com/agent.tar.gz",
                                    "server.example.com",
                                    8443,
                                    True,
                                )

        assert result["success"] is False

    def test_exception_handling(self, builder):
        """Test exception handling in build_site_tarball."""
        with patch("tempfile.TemporaryDirectory", side_effect=Exception("Temp error")):
            result = builder.build_site_tarball(
                "7.7",
                "1.0.0",
                "https://example.com/agent.tar.gz",
                "server.example.com",
                8443,
                True,
            )

        assert result["success"] is False
        assert "Temp error" in result["error"]

    def test_with_auto_approve_token(self, builder):
        """Test build with auto-approve token."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=True):
                with patch.object(builder, "_download_dependencies") as mock_deps:
                    mock_deps.return_value = {
                        "success": True,
                        "packages_dir": Path("/packages"),
                        "error": None,
                    }
                    with patch.object(
                        builder, "_create_site_structure"
                    ) as mock_structure:
                        mock_structure.return_value = {"success": True, "error": None}
                        with patch.object(builder, "_create_tarball") as mock_tarball:
                            mock_tarball.return_value = {
                                "success": True,
                                "tarball_path": "/site77.tgz",
                                "error": None,
                            }
                            with patch.object(
                                builder, "_calculate_checksum", return_value="abc123"
                            ):
                                with patch("os.makedirs"):
                                    with patch("shutil.copy2"):
                                        with patch(
                                            "tempfile.TemporaryDirectory"
                                        ) as mock_tmpdir:
                                            mock_tmpdir.return_value.__enter__ = Mock(
                                                return_value="/tmp/build"
                                            )
                                            mock_tmpdir.return_value.__exit__ = Mock(
                                                return_value=False
                                            )

                                            result = builder.build_site_tarball(
                                                "7.7",
                                                "1.0.0",
                                                "https://example.com/agent.tar.gz",
                                                "server.example.com",
                                                8443,
                                                True,
                                                auto_approve_token="test-uuid-token",
                                            )

        assert result["success"] is True
        # Verify auto_approve_token was passed to _create_site_structure
        mock_structure.assert_called_once()
        call_args = mock_structure.call_args
        assert call_args[0][6] == "test-uuid-token"


class TestGetOrBuildSiteTarball:
    """Tests for get_or_build_site_tarball method."""

    def test_always_builds_fresh(self, builder):
        """Test that get_or_build_site_tarball always builds fresh."""
        with patch.object(builder, "build_site_tarball") as mock_build:
            mock_build.return_value = {
                "success": True,
                "site_tgz_path": "/site77.tgz",
                "site_tgz_checksum": "abc123",
                "agent_package_path": "/agent.tgz",
                "error": None,
            }

            result = builder.get_or_build_site_tarball(
                "7.7",
                "1.0.0",
                "https://example.com/agent.tar.gz",
                "server.example.com",
                8443,
                True,
            )

        assert result["success"] is True
        assert result["from_cache"] is False
        mock_build.assert_called_once()

    def test_returns_build_failure(self, builder):
        """Test that build failure is propagated."""
        with patch.object(builder, "build_site_tarball") as mock_build:
            mock_build.return_value = {
                "success": False,
                "site_tgz_path": None,
                "site_tgz_checksum": None,
                "agent_package_path": None,
                "error": "Build failed",
            }

            result = builder.get_or_build_site_tarball(
                "7.7",
                "1.0.0",
                "https://example.com/agent.tar.gz",
                "server.example.com",
                8443,
                True,
            )

        assert result["success"] is False
        assert result["error"] == "Build failed"

    def test_exception_handling(self, builder):
        """Test exception handling."""
        with patch.object(
            builder, "build_site_tarball", side_effect=Exception("Unexpected error")
        ):
            result = builder.get_or_build_site_tarball(
                "7.7",
                "1.0.0",
                "https://example.com/agent.tar.gz",
                "server.example.com",
                8443,
                True,
            )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        assert result["from_cache"] is False

    def test_with_auto_approve_token(self, builder):
        """Test with auto-approve token."""
        with patch.object(builder, "build_site_tarball") as mock_build:
            mock_build.return_value = {
                "success": True,
                "site_tgz_path": "/site77.tgz",
                "site_tgz_checksum": "abc123",
                "agent_package_path": "/agent.tgz",
                "error": None,
            }

            result = builder.get_or_build_site_tarball(
                "7.7",
                "1.0.0",
                "https://example.com/agent.tar.gz",
                "server.example.com",
                8443,
                True,
                auto_approve_token="unique-token",
            )

        assert result["success"] is True
        # Verify token was passed
        mock_build.assert_called_once_with(
            "7.7",
            "1.0.0",
            "https://example.com/agent.tar.gz",
            "server.example.com",
            8443,
            True,
            "unique-token",
        )


class TestIntegrationScenarios:
    """Integration-like tests for common scenarios."""

    def test_full_build_flow_with_cached_agent(self, builder, tmp_path):
        """Test the full build flow when agent is cached."""
        # This simulates a complete build with cached agent
        with patch.object(builder, "_get_agent_package_path") as mock_get_path:
            mock_get_path.return_value = str(tmp_path / "cached_agent.tgz")

            # Create the cached agent file
            (tmp_path / "cached_agent.tgz").write_bytes(b"cached agent")

            with patch("os.path.exists", return_value=True):
                with patch.object(builder, "_download_dependencies") as mock_deps:
                    mock_deps.return_value = {
                        "success": True,
                        "packages_dir": tmp_path / "packages",
                        "error": None,
                    }
                    with patch.object(
                        builder, "_create_site_structure"
                    ) as mock_structure:
                        mock_structure.return_value = {"success": True, "error": None}
                        with patch.object(builder, "_create_tarball") as mock_tarball:
                            mock_tarball.return_value = {
                                "success": True,
                                "tarball_path": str(tmp_path / "site77.tgz"),
                                "error": None,
                            }
                            with patch.object(
                                builder, "_calculate_checksum", return_value="checksum"
                            ):
                                with patch("os.makedirs"):
                                    with patch("shutil.copy2"):
                                        with patch(
                                            "tempfile.TemporaryDirectory"
                                        ) as mock_tmpdir:
                                            mock_tmpdir.return_value.__enter__ = Mock(
                                                return_value=str(tmp_path / "build")
                                            )
                                            mock_tmpdir.return_value.__exit__ = Mock(
                                                return_value=False
                                            )

                                            result = builder.build_site_tarball(
                                                "7.7",
                                                "1.0.0",
                                                "https://example.com/agent.tar.gz",
                                                "server.example.com",
                                                8443,
                                                True,
                                            )

        assert result["success"] is True
        assert result["site_tgz_checksum"] == "checksum"

    def test_unsupported_openbsd_version_builds_from_ports(self, builder):
        """Test that unsupported version falls back to building from ports."""
        with patch.object(
            builder, "_get_agent_package_path", return_value="/cached/agent.tgz"
        ):
            with patch("os.path.exists", return_value=False):  # Not cached
                # For unsupported version, should not try prebuilt
                with patch.object(builder, "_download_port_tarball") as mock_port:
                    mock_port.return_value = {
                        "success": True,
                        "port_dir": Path("/port"),
                        "error": None,
                    }
                    with patch.object(builder, "_build_agent_package") as mock_build:
                        mock_build.return_value = {
                            "success": True,
                            "package_path": "/built/agent.tgz",
                            "error": None,
                        }
                        with patch.object(
                            builder, "_download_dependencies"
                        ) as mock_deps:
                            mock_deps.return_value = {
                                "success": True,
                                "packages_dir": Path("/packages"),
                                "error": None,
                            }
                            with patch.object(
                                builder, "_create_site_structure"
                            ) as mock_structure:
                                mock_structure.return_value = {
                                    "success": True,
                                    "error": None,
                                }
                                with patch.object(
                                    builder, "_create_tarball"
                                ) as mock_tarball:
                                    mock_tarball.return_value = {
                                        "success": True,
                                        "tarball_path": "/site99.tgz",
                                        "error": None,
                                    }
                                    with patch.object(
                                        builder,
                                        "_calculate_checksum",
                                        return_value="abc",
                                    ):
                                        with patch("os.makedirs"):
                                            with patch("shutil.copy2"):
                                                with patch(
                                                    "tempfile.TemporaryDirectory"
                                                ) as mock_tmpdir:
                                                    mock_tmpdir.return_value.__enter__ = Mock(
                                                        return_value="/tmp/build"
                                                    )
                                                    mock_tmpdir.return_value.__exit__ = Mock(
                                                        return_value=False
                                                    )

                                                    # Use unsupported version 9.9
                                                    result = builder.build_site_tarball(
                                                        "9.9",
                                                        "1.0.0",
                                                        "https://example.com/agent.tar.gz",
                                                        "server.example.com",
                                                        8443,
                                                        True,
                                                    )

        assert result["success"] is True
        # Should have tried to build from ports
        mock_port.assert_called_once()
        mock_build.assert_called_once()
