"""
Comprehensive unit tests for child_host_debian_agent_download module.
Tests the AgentPackageDownloader class for downloading and serving .deb packages.
"""

# pylint: disable=protected-access,redefined-outer-name

import json
import socket
import urllib.error

from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_debian_agent_download import (
    AgentPackageDownloader,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return Mock()


@pytest.fixture
def downloader(mock_logger):
    """Create an AgentPackageDownloader instance for testing."""
    return AgentPackageDownloader(mock_logger)


@pytest.fixture
def sample_release_info():
    """Sample GitHub release info."""
    return {
        "tag_name": "v1.2.3",
        "assets": [
            {
                "name": "sysmanage-agent_debian12_amd64.deb",
                "browser_download_url": "https://github.com/bceverly/sysmanage-agent/releases/download/v1.2.3/sysmanage-agent_debian12_amd64.deb",
            },
            {
                "name": "sysmanage-agent_debian11_amd64.deb",
                "browser_download_url": "https://github.com/bceverly/sysmanage-agent/releases/download/v1.2.3/sysmanage-agent_debian11_amd64.deb",
            },
            {
                "name": "sysmanage-agent.sha256",
                "browser_download_url": "https://github.com/bceverly/sysmanage-agent/releases/download/v1.2.3/sysmanage-agent.sha256",
            },
        ],
    }


class TestAgentPackageDownloaderInit:
    """Tests for AgentPackageDownloader initialization."""

    def test_init_sets_logger(self, mock_logger):
        """Test that __init__ sets logger."""
        downloader = AgentPackageDownloader(mock_logger)
        assert downloader.logger == mock_logger

    def test_class_constants(self, downloader):
        """Test class constants are properly defined."""
        assert downloader.AGENT_CACHE_DIR == "/var/vmm/agent-packages"
        assert downloader.HTTPD_ROOT == "/var/www/htdocs"
        assert "github.com" in downloader.GITHUB_API_URL
        assert "sysmanage-agent" in downloader.GITHUB_API_URL


class TestGetCachedAgentVersion:
    """Tests for _get_cached_agent_version method."""

    def test_get_cached_version_exists(self, downloader, tmp_path):
        """Test getting cached version when version file exists."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            version_file = tmp_path / "debian12.version"
            version_file.write_text("1.2.3\n")

            result = downloader._get_cached_agent_version("12")

            assert result == "1.2.3"

    def test_get_cached_version_not_exists(self, downloader, tmp_path):
        """Test getting cached version when version file doesn't exist."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            result = downloader._get_cached_agent_version("12")

            assert result is None

    def test_get_cached_version_different_debian_versions(self, downloader, tmp_path):
        """Test getting cached version for different Debian versions."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            # Create version files for different Debian versions
            (tmp_path / "debian11.version").write_text("1.1.0")
            (tmp_path / "debian12.version").write_text("1.2.0")

            assert downloader._get_cached_agent_version("11") == "1.1.0"
            assert downloader._get_cached_agent_version("12") == "1.2.0"
            assert downloader._get_cached_agent_version("13") is None

    def test_get_cached_version_strips_whitespace(self, downloader, tmp_path):
        """Test that version is stripped of whitespace."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            version_file = tmp_path / "debian12.version"
            version_file.write_text("  1.2.3  \n\n")

            result = downloader._get_cached_agent_version("12")

            assert result == "1.2.3"


class TestGetLatestAgentRelease:
    """Tests for _get_latest_agent_release method."""

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.Request"
    )
    def test_get_latest_release_success(
        self, _mock_request, mock_urlopen, downloader, sample_release_info
    ):
        """Test successfully getting latest release from GitHub."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(sample_release_info).encode(
            "utf-8"
        )
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = downloader._get_latest_agent_release()

        assert result is not None
        assert result["tag_name"] == "v1.2.3"
        assert len(result["assets"]) == 3

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.Request"
    )
    def test_get_latest_release_network_error(
        self, _mock_request, mock_urlopen, downloader
    ):
        """Test handling network error when getting release."""
        mock_urlopen.side_effect = Exception("Network unreachable")

        result = downloader._get_latest_agent_release()

        assert result is None
        downloader.logger.warning.assert_called_once()

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.Request"
    )
    def test_get_latest_release_timeout(self, _mock_request, mock_urlopen, downloader):
        """Test handling timeout when getting release."""
        mock_urlopen.side_effect = socket.timeout("Connection timed out")

        result = downloader._get_latest_agent_release()

        assert result is None
        downloader.logger.warning.assert_called_once()

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.Request"
    )
    def test_get_latest_release_invalid_json(
        self, _mock_request, mock_urlopen, downloader
    ):
        """Test handling invalid JSON response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not valid json"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = downloader._get_latest_agent_release()

        assert result is None
        downloader.logger.warning.assert_called_once()

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.Request"
    )
    def test_get_latest_release_http_error(
        self, _mock_request, mock_urlopen, downloader
    ):
        """Test handling HTTP error from GitHub."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://api.github.com/repos/...", 404, "Not Found", {}, None
        )

        result = downloader._get_latest_agent_release()

        assert result is None
        downloader.logger.warning.assert_called_once()


class TestFindDebAsset:
    """Tests for _find_deb_asset method."""

    def test_find_deb_asset_exact_match(self, downloader, sample_release_info):
        """Test finding exact Debian version match."""
        result = downloader._find_deb_asset(sample_release_info, "12")

        assert result is not None
        url, filename = result
        assert "debian12" in url
        assert "debian12" in filename

    def test_find_deb_asset_different_version(self, downloader, sample_release_info):
        """Test finding different Debian version."""
        result = downloader._find_deb_asset(sample_release_info, "11")

        assert result is not None
        url, filename = result
        assert "debian11" in url
        assert "debian11" in filename

    def test_find_deb_asset_fallback_to_generic_debian(self, downloader):
        """Test falling back to generic debian package."""
        release_info = {
            "assets": [
                {
                    "name": "sysmanage-agent_debian_all.deb",
                    "browser_download_url": "https://example.com/sysmanage-agent_debian_all.deb",
                },
            ]
        }

        result = downloader._find_deb_asset(release_info, "13")

        assert result is not None
        _url, filename = result
        assert "debian" in filename.lower()

    def test_find_deb_asset_fallback_to_any_deb(self, downloader):
        """Test falling back to any .deb file."""
        release_info = {
            "assets": [
                {
                    "name": "sysmanage-agent_all.deb",
                    "browser_download_url": "https://example.com/sysmanage-agent_all.deb",
                },
            ]
        }

        result = downloader._find_deb_asset(release_info, "12")

        assert result is not None
        _url, filename = result
        assert filename.endswith(".deb")

    def test_find_deb_asset_no_match(self, downloader):
        """Test when no .deb asset is found."""
        release_info = {
            "assets": [
                {
                    "name": "sysmanage-agent.tar.gz",
                    "browser_download_url": "https://example.com/sysmanage-agent.tar.gz",
                },
                {
                    "name": "sysmanage-agent.rpm",
                    "browser_download_url": "https://example.com/sysmanage-agent.rpm",
                },
            ]
        }

        result = downloader._find_deb_asset(release_info, "12")

        assert result is None

    def test_find_deb_asset_empty_assets(self, downloader):
        """Test with empty assets list."""
        release_info = {"assets": []}

        result = downloader._find_deb_asset(release_info, "12")

        assert result is None

    def test_find_deb_asset_excludes_sha256(self, downloader):
        """Test that .sha256 files are excluded."""
        release_info = {
            "assets": [
                {
                    "name": "sysmanage-agent.deb.sha256",
                    "browser_download_url": "https://example.com/sysmanage-agent.deb.sha256",
                },
            ]
        }

        result = downloader._find_deb_asset(release_info, "12")

        assert result is None

    def test_find_deb_asset_missing_keys(self, downloader):
        """Test handling assets with missing keys."""
        release_info = {
            "assets": [
                {
                    "name": "sysmanage-agent_debian12.deb"
                },  # Missing browser_download_url
            ]
        }

        result = downloader._find_deb_asset(release_info, "12")

        assert result is not None
        url, filename = result
        assert url is None  # Returns None for missing key
        assert "debian12" in filename


class TestHandleNoGithubAccess:
    """Tests for _handle_no_github_access method."""

    def test_handle_no_github_with_cached_deb(self, downloader, tmp_path):
        """Test fallback to cached .deb when GitHub is unavailable."""
        # Create cached .deb file
        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"
        cached_deb.write_text("fake deb content")

        result = downloader._handle_no_github_access(tmp_path, "12", "1.0.0")

        assert result["success"] is True
        assert result["deb_path"] == str(cached_deb)
        assert result["version"] == "1.0.0"
        assert result["from_cache"] is True

    def test_handle_no_github_without_cached_deb(self, downloader, tmp_path):
        """Test error when GitHub unavailable and no cached .deb."""
        result = downloader._handle_no_github_access(tmp_path, "12", None)

        assert result["success"] is False
        assert "error" in result
        assert "GitHub" in result["error"] or "cached" in result["error"]

    def test_handle_no_github_logs_info(self, downloader, tmp_path):
        """Test that info is logged when using cached package."""
        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"
        cached_deb.write_text("fake deb content")

        downloader._handle_no_github_access(tmp_path, "12", "1.0.0")

        downloader.logger.info.assert_called()


class TestDownloadDebAsset:
    """Tests for _download_deb_asset method."""

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.shutil.copyfileobj"
    )
    def test_download_deb_asset_success(
        self, _mock_copyfileobj, mock_urlopen, downloader, tmp_path, sample_release_info
    ):
        """Test successful .deb download."""
        mock_response = MagicMock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"

        with patch("builtins.open", mock_open()):
            with patch.object(Path, "rename"):
                with patch.object(Path, "write_text"):
                    with patch.object(Path, "exists", return_value=False):
                        result = downloader._download_deb_asset(
                            sample_release_info,
                            "12",
                            tmp_path,
                            cached_deb,
                            "1.0.0",
                            "1.2.3",
                        )

        assert result["success"] is True
        assert result["version"] == "1.2.3"
        assert result["from_cache"] is False

    def test_download_deb_asset_no_asset_found_with_cache(self, downloader, tmp_path):
        """Test fallback to cache when no asset found in release."""
        release_info = {"assets": []}  # No assets
        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"
        cached_deb.write_text("cached deb content")

        result = downloader._download_deb_asset(
            release_info,
            "12",
            tmp_path,
            cached_deb,
            "1.0.0",
            "1.2.3",
        )

        assert result["success"] is True
        assert result["version"] == "1.0.0"
        assert result["from_cache"] is True

    def test_download_deb_asset_no_asset_no_cache(self, downloader, tmp_path):
        """Test error when no asset found and no cache."""
        release_info = {"assets": []}
        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"
        # Don't create cached_deb, so it doesn't exist

        result = downloader._download_deb_asset(
            release_info,
            "12",
            tmp_path,
            cached_deb,
            None,
            "1.2.3",
        )

        assert result["success"] is False
        assert "error" in result
        assert "Debian 12" in result["error"] or "12" in result["error"]

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    def test_download_deb_asset_cleans_up_temp_file_on_error(
        self, mock_urlopen, downloader, tmp_path, sample_release_info
    ):
        """Test that temp file is cleaned up on download error."""
        mock_urlopen.side_effect = Exception("Download failed")

        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"

        # This should raise but temp file cleanup happens in finally
        with pytest.raises(Exception):
            downloader._download_deb_asset(
                sample_release_info,
                "12",
                tmp_path,
                cached_deb,
                None,
                "1.2.3",
            )

    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.urllib.request.urlopen"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_debian_agent_download.shutil.copyfileobj"
    )
    def test_download_deb_asset_cleans_up_temp_file_when_exists(
        self, _mock_copyfileobj, mock_urlopen, downloader, tmp_path, sample_release_info
    ):
        """Test that temp file is cleaned up when it exists after rename failure."""
        mock_response = MagicMock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        cached_deb = tmp_path / "sysmanage-agent_debian12.deb"

        # Create the temp file to simulate it existing after an error
        temp_filename = "sysmanage-agent_debian12_amd64.deb.downloading"
        temp_file = tmp_path / temp_filename
        temp_file.write_text("temp content")

        # Mock rename to fail so the finally block is triggered with temp file existing
        with patch("builtins.open", mock_open()):
            with patch.object(Path, "rename", side_effect=OSError("Rename failed")):
                with pytest.raises(OSError):
                    downloader._download_deb_asset(
                        sample_release_info,
                        "12",
                        tmp_path,
                        cached_deb,
                        "1.0.0",
                        "1.2.3",
                    )

        # Verify temp file was cleaned up
        assert not temp_file.exists()


class TestDownloadAgentDeb:
    """Tests for download_agent_deb method."""

    def test_download_agent_deb_cached_up_to_date(self, downloader, tmp_path):
        """Test when cached version is up to date."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            # Create version file and cached deb
            (tmp_path / "debian12.version").write_text("1.2.3")
            (tmp_path / "sysmanage-agent_debian12.deb").write_text("cached content")

            # Mock GitHub response with same version
            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value={"tag_name": "v1.2.3", "assets": []},
            ):
                result = downloader.download_agent_deb("12")

            assert result["success"] is True
            assert result["version"] == "1.2.3"
            assert result["from_cache"] is True

    def test_download_agent_deb_creates_cache_dir(self, downloader, tmp_path):
        """Test that cache directory is created if it doesn't exist."""
        new_cache_dir = tmp_path / "new_cache" / "agent-packages"

        with patch.object(downloader, "AGENT_CACHE_DIR", str(new_cache_dir)):
            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value=None,
            ):
                downloader.download_agent_deb("12")

            assert new_cache_dir.exists()

    def test_download_agent_deb_github_unavailable(self, downloader, tmp_path):
        """Test handling when GitHub is unavailable."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value=None,
            ):
                result = downloader.download_agent_deb("12")

            assert result["success"] is False

    def test_download_agent_deb_github_unavailable_with_cache(
        self, downloader, tmp_path
    ):
        """Test fallback to cache when GitHub unavailable."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            # Create cached deb
            (tmp_path / "debian12.version").write_text("1.0.0")
            (tmp_path / "sysmanage-agent_debian12.deb").write_text("cached content")

            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value=None,
            ):
                result = downloader.download_agent_deb("12")

            assert result["success"] is True
            assert result["from_cache"] is True

    def test_download_agent_deb_exception(self, downloader, tmp_path):
        """Test handling unexpected exceptions."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            with patch.object(
                downloader,
                "_get_cached_agent_version",
                side_effect=Exception("Unexpected error"),
            ):
                result = downloader.download_agent_deb("12")

            assert result["success"] is False
            assert "error" in result

    def test_download_agent_deb_new_version_available(
        self, downloader, tmp_path, sample_release_info
    ):
        """Test downloading when new version is available."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            # Create old version file
            (tmp_path / "debian12.version").write_text("1.0.0")
            (tmp_path / "sysmanage-agent_debian12.deb").write_text("old content")

            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value=sample_release_info,
            ):
                with patch.object(
                    downloader,
                    "_download_deb_asset",
                    return_value={
                        "success": True,
                        "deb_path": str(tmp_path / "sysmanage-agent_debian12.deb"),
                        "version": "1.2.3",
                        "from_cache": False,
                    },
                ) as mock_download:
                    result = downloader.download_agent_deb("12")

                    mock_download.assert_called_once()

            assert result["success"] is True
            assert result["version"] == "1.2.3"

    def test_download_agent_deb_logs_versions(self, downloader, tmp_path):
        """Test that versions are logged."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            (tmp_path / "debian12.version").write_text("1.0.0")
            (tmp_path / "sysmanage-agent_debian12.deb").write_text("content")

            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value={"tag_name": "v1.0.0", "assets": []},
            ):
                downloader.download_agent_deb("12")

            # Should log cached version and latest version
            assert downloader.logger.info.call_count >= 2


class TestServeAgentDebViaHttpd:
    """Tests for serve_agent_deb_via_httpd method."""

    def test_serve_deb_success(self, downloader, tmp_path):
        """Test successfully serving .deb via httpd."""
        # Create source .deb file
        source_deb = tmp_path / "source" / "sysmanage-agent.deb"
        source_deb.parent.mkdir(parents=True)
        source_deb.write_bytes(b"fake deb content")

        httpd_root = tmp_path / "htdocs"

        with patch.object(downloader, "HTTPD_ROOT", str(httpd_root)):
            result = downloader.serve_agent_deb_via_httpd(str(source_deb), "test-vm")

        assert result["success"] is True
        assert "deb_url" in result
        assert "test-vm" in result["deb_url"]
        assert "deb_path" in result

        # Verify file was copied
        expected_path = httpd_root / "debian" / "test-vm" / "sysmanage-agent.deb"
        assert expected_path.exists()

    def test_serve_deb_creates_directories(self, downloader, tmp_path):
        """Test that necessary directories are created."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"deb content")

        httpd_root = tmp_path / "httpd"  # Doesn't exist yet

        with patch.object(downloader, "HTTPD_ROOT", str(httpd_root)):
            result = downloader.serve_agent_deb_via_httpd(str(source_deb), "new-vm")

        assert result["success"] is True
        assert (httpd_root / "debian" / "new-vm").is_dir()

    def test_serve_deb_url_format(self, downloader, tmp_path):
        """Test that URL format is correct."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"deb content")

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            result = downloader.serve_agent_deb_via_httpd(str(source_deb), "my-vm")

        assert result["deb_url"] == "http://100.64.0.1/debian/my-vm/sysmanage-agent.deb"

    def test_serve_deb_permission_error(self, downloader, tmp_path):
        """Test handling permission error when copying file."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"deb content")

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            with patch(
                "src.sysmanage_agent.operations.child_host_debian_agent_download.shutil.copy2",
                side_effect=PermissionError("Permission denied"),
            ):
                result = downloader.serve_agent_deb_via_httpd(
                    str(source_deb), "test-vm"
                )

        assert result["success"] is False
        assert "error" in result

    def test_serve_deb_source_not_found(self, downloader, tmp_path):
        """Test handling when source .deb doesn't exist."""
        nonexistent_deb = tmp_path / "nonexistent.deb"

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            result = downloader.serve_agent_deb_via_httpd(
                str(nonexistent_deb), "test-vm"
            )

        assert result["success"] is False
        assert "error" in result

    def test_serve_deb_sets_permissions(self, downloader, tmp_path):
        """Test that file permissions are set correctly."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"deb content")

        httpd_root = tmp_path / "htdocs"

        with patch.object(downloader, "HTTPD_ROOT", str(httpd_root)):
            result = downloader.serve_agent_deb_via_httpd(str(source_deb), "test-vm")

        assert result["success"] is True

        # Check permissions (0o644 = 420 in decimal)
        dest_path = httpd_root / "debian" / "test-vm" / "sysmanage-agent.deb"
        permissions = dest_path.stat().st_mode & 0o777
        assert permissions == 0o644

    def test_serve_deb_logs_url(self, downloader, tmp_path):
        """Test that URL is logged."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"deb content")

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            downloader.serve_agent_deb_via_httpd(str(source_deb), "test-vm")

        downloader.logger.info.assert_called()

    def test_serve_deb_different_vm_names(self, downloader, tmp_path):
        """Test serving to different VM names creates separate directories."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"deb content")

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            result1 = downloader.serve_agent_deb_via_httpd(str(source_deb), "vm1")
            result2 = downloader.serve_agent_deb_via_httpd(str(source_deb), "vm2")

        assert result1["success"] is True
        assert result2["success"] is True
        assert "vm1" in result1["deb_url"]
        assert "vm2" in result2["deb_url"]

        assert (tmp_path / "debian" / "vm1" / "sysmanage-agent.deb").exists()
        assert (tmp_path / "debian" / "vm2" / "sysmanage-agent.deb").exists()


class TestIntegration:
    """Integration-style tests for AgentPackageDownloader."""

    def test_full_download_and_serve_workflow(self, downloader, tmp_path):
        """Test complete workflow: download and serve."""
        cache_dir = tmp_path / "cache"
        httpd_dir = tmp_path / "httpd"
        cache_dir.mkdir()

        with patch.object(downloader, "AGENT_CACHE_DIR", str(cache_dir)):
            with patch.object(downloader, "HTTPD_ROOT", str(httpd_dir)):
                # Simulate cached package exists
                (cache_dir / "debian12.version").write_text("1.0.0")
                cached_deb = cache_dir / "sysmanage-agent_debian12.deb"
                cached_deb.write_bytes(b"deb content")

                # Download (will use cache)
                with patch.object(
                    downloader,
                    "_get_latest_agent_release",
                    return_value={"tag_name": "v1.0.0", "assets": []},
                ):
                    download_result = downloader.download_agent_deb("12")

                assert download_result["success"] is True

                # Serve
                serve_result = downloader.serve_agent_deb_via_httpd(
                    download_result["deb_path"], "production-vm"
                )

                assert serve_result["success"] is True
                assert "production-vm" in serve_result["deb_url"]

    def test_multiple_debian_versions(self, downloader, tmp_path):
        """Test handling multiple Debian versions."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        with patch.object(downloader, "AGENT_CACHE_DIR", str(cache_dir)):
            # Create cached packages for different versions
            for version in ["11", "12"]:
                (cache_dir / f"debian{version}.version").write_text(f"1.{version}.0")
                (cache_dir / f"sysmanage-agent_debian{version}.deb").write_bytes(
                    f"content for debian {version}".encode()
                )

            with patch.object(
                downloader, "_get_latest_agent_release", return_value=None
            ):
                result_11 = downloader.download_agent_deb("11")
                result_12 = downloader.download_agent_deb("12")

            assert result_11["success"] is True
            assert result_12["success"] is True
            assert "debian11" in result_11["deb_path"]
            assert "debian12" in result_12["deb_path"]


class TestEdgeCases:
    """Edge case tests for AgentPackageDownloader."""

    def test_empty_tag_name(self, downloader, tmp_path):
        """Test handling release with empty tag name."""
        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value={"tag_name": "", "assets": []},
            ):
                result = downloader.download_agent_deb("12")

            # Should handle gracefully
            assert result is not None

    def test_tag_name_without_v_prefix(self, downloader, tmp_path):
        """Test handling tag name without 'v' prefix."""
        release_info = {
            "tag_name": "1.2.3",  # No 'v' prefix
            "assets": [],
        }

        with patch.object(downloader, "AGENT_CACHE_DIR", str(tmp_path)):
            (tmp_path / "debian12.version").write_text("1.2.3")
            (tmp_path / "sysmanage-agent_debian12.deb").write_text("content")

            with patch.object(
                downloader,
                "_get_latest_agent_release",
                return_value=release_info,
            ):
                result = downloader.download_agent_deb("12")

            assert result["success"] is True
            assert result["version"] == "1.2.3"

    def test_release_info_missing_assets_key(self, downloader):
        """Test handling release info without assets key."""
        release_info = {"tag_name": "v1.0.0"}  # No 'assets' key

        result = downloader._find_deb_asset(release_info, "12")

        assert result is None

    def test_asset_with_empty_name(self, downloader):
        """Test handling asset with empty name."""
        release_info = {
            "assets": [
                {"name": "", "browser_download_url": "https://example.com/file.deb"},
            ]
        }

        result = downloader._find_deb_asset(release_info, "12")

        # Empty name should not match
        assert result is None

    def test_special_characters_in_vm_name(self, downloader, tmp_path):
        """Test VM name with special characters."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"content")

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            result = downloader.serve_agent_deb_via_httpd(
                str(source_deb), "vm-test_123"
            )

        assert result["success"] is True
        assert "vm-test_123" in result["deb_url"]

    def test_very_long_vm_name(self, downloader, tmp_path):
        """Test with very long VM name."""
        source_deb = tmp_path / "source.deb"
        source_deb.write_bytes(b"content")
        long_name = "a" * 100

        with patch.object(downloader, "HTTPD_ROOT", str(tmp_path)):
            result = downloader.serve_agent_deb_via_httpd(str(source_deb), long_name)

        assert result["success"] is True
        assert long_name in result["deb_url"]
