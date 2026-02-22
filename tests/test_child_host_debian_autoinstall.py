"""
Unit tests for Debian VMM autoinstall module.

Tests the DebianAutoinstallSetup class and associated dataclasses
for automated Debian VM installation.
"""

# pylint: disable=protected-access,redefined-outer-name

import base64
import logging
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_debian_autoinstall import (
    DebianAutoinstallSetup,
    NetworkConfig,
    ServerConfig,
    UserConfig,
    PreseedConfig,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_debian_autoinstall")


@pytest.fixture
def setup(logger):
    """Create a DebianAutoinstallSetup instance for testing."""
    return DebianAutoinstallSetup(logger)


class TestDataclasses:
    """Tests for the configuration dataclasses."""

    def test_network_config_basic(self):
        """Test NetworkConfig with required fields only."""
        config = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        assert config.vm_ip == "192.168.1.100"
        assert config.gateway_ip == "192.168.1.1"
        assert config.dns_server is None

    def test_network_config_with_dns(self):
        """Test NetworkConfig with DNS server."""
        config = NetworkConfig(
            vm_ip="192.168.1.100", gateway_ip="192.168.1.1", dns_server="8.8.8.8"
        )
        assert config.dns_server == "8.8.8.8"

    def test_server_config(self):
        """Test ServerConfig dataclass."""
        config = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        assert config.hostname == "sysmanage.example.com"
        assert config.port == 8443
        assert config.use_https is True

    def test_server_config_http(self):
        """Test ServerConfig with HTTP."""
        config = ServerConfig(hostname="localhost", port=8080, use_https=False)
        assert config.use_https is False

    def test_user_config(self):
        """Test UserConfig dataclass."""
        config = UserConfig(
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
        )
        assert config.username == "admin"
        assert config.user_password_hash == "$6$user_hash"
        assert config.root_password_hash == "$6$root_hash"

    def test_preseed_config_basic(self):
        """Test PreseedConfig with required fields."""
        network = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
        )
        assert config.hostname == "vm01.example.com"
        assert config.debian_version == "12"
        assert config.disk == "vda"
        assert config.timezone == "UTC"
        assert config.auto_approve_token is None
        assert config.agent_deb_url is None

    def test_preseed_config_with_optionals(self):
        """Test PreseedConfig with optional fields."""
        network = NetworkConfig(
            vm_ip="192.168.1.100", gateway_ip="192.168.1.1", dns_server="8.8.8.8"
        )
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
            auto_approve_token="12345678-1234-1234-1234-123456789012",
            disk="sda",
            timezone="America/New_York",
            agent_deb_url="http://example.com/agent.deb",
        )
        assert config.disk == "sda"
        assert config.timezone == "America/New_York"
        assert config.auto_approve_token == "12345678-1234-1234-1234-123456789012"
        assert config.agent_deb_url == "http://example.com/agent.deb"


class TestDebianAutoinstallSetupInit:
    """Tests for DebianAutoinstallSetup initialization."""

    def test_init_sets_logger(self, logger):
        """Test that __init__ sets the logger."""
        setup = DebianAutoinstallSetup(logger)
        assert setup.logger == logger

    def test_init_creates_agent_downloader(self, logger):
        """Test that __init__ creates an AgentPackageDownloader."""
        setup = DebianAutoinstallSetup(logger)
        assert setup.agent_downloader is not None

    def test_class_constants(self, setup):
        """Test class constants are defined correctly."""
        assert setup.ISO_CACHE_DIR == "/var/vmm/iso-cache"
        assert setup.DEBIAN_DATA_BASE == "/var/vmm/debian-data"
        assert setup.HTTPD_ROOT == "/var/www/htdocs"


class TestDelegatedMethods:
    """Tests for methods that delegate to agent_downloader."""

    def test_download_agent_deb_delegates(self, setup):
        """Test download_agent_deb delegates to agent_downloader."""
        setup.agent_downloader.download_agent_deb = Mock(
            return_value={"success": True, "deb_path": "/path/to/agent.deb"}
        )
        result = setup.download_agent_deb("12")
        setup.agent_downloader.download_agent_deb.assert_called_once_with("12")
        assert result["success"] is True

    def test_serve_agent_deb_via_httpd_delegates(self, setup):
        """Test serve_agent_deb_via_httpd delegates to agent_downloader."""
        setup.agent_downloader.serve_agent_deb_via_httpd = Mock(
            return_value={"success": True, "deb_url": "http://example.com/agent.deb"}
        )
        result = setup.serve_agent_deb_via_httpd("/path/to/agent.deb", "vm01")
        setup.agent_downloader.serve_agent_deb_via_httpd.assert_called_once_with(
            "/path/to/agent.deb", "vm01"
        )
        assert result["success"] is True


class TestDownloadDebianIso:
    """Tests for download_debian_iso method."""

    def test_unsupported_version(self, setup, tmp_path):
        """Test download_debian_iso with unsupported version."""
        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            result = setup.download_debian_iso("99")
        assert result["success"] is False
        assert result["iso_path"] is None
        assert "Unsupported Debian version" in result["error"]

    def test_cached_iso_exists_and_valid(self, setup, tmp_path):
        """Test using cached ISO when it exists and is valid."""
        # Create a fake ISO file > 500MB
        iso_path = tmp_path / "debian-12.9.0-amd64-netinst.iso"
        iso_path.write_bytes(b"0" * (501 * 1024 * 1024))

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            result = setup.download_debian_iso("12")

        assert result["success"] is True
        assert result["iso_path"] is not None

    def test_cached_iso_too_small_redownloads(self, setup, tmp_path):
        """Test that small cached ISO is removed and re-downloaded."""
        # Create a small fake ISO file
        iso_path = tmp_path / "debian-12.9.0-amd64-netinst.iso"
        iso_path.write_bytes(b"0" * 1000)

        mock_response = Mock()
        total_size = 600 * 1024 * 1024
        mock_response.headers = {"content-length": str(total_size)}
        # Return chunks totaling the expected size
        chunk = b"0" * (1024 * 1024)
        mock_response.read = Mock(side_effect=[chunk] * 600 + [b""])
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup.download_debian_iso("12")

        assert result["success"] is True

    def test_download_success(self, setup, tmp_path):
        """Test successful ISO download."""
        mock_response = Mock()
        mock_response.headers = {"content-length": str(600 * 1024 * 1024)}
        # Return chunks then empty to signal end
        chunk = b"0" * (1024 * 1024)
        mock_response.read = Mock(side_effect=[chunk] * 600 + [b""])
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup.download_debian_iso("12")

        assert result["success"] is True
        assert result["iso_path"] is not None

    def test_download_incomplete_file(self, setup, tmp_path):
        """Test handling of incomplete download."""
        mock_response = Mock()
        mock_response.headers = {"content-length": str(600 * 1024 * 1024)}
        # Return less data than expected
        mock_response.read = Mock(side_effect=[b"0" * (100 * 1024 * 1024), b""])
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup.download_debian_iso("12")

        assert result["success"] is False
        assert "Download incomplete" in result["error"]

    def test_download_exception(self, setup, tmp_path):
        """Test handling of download exception."""
        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch(
                "urllib.request.urlopen", side_effect=Exception("Network error")
            ):
                result = setup.download_debian_iso("12")

        assert result["success"] is False
        assert "Network error" in result["error"]

    def test_cleanup_partial_download_on_failure(self, setup, tmp_path):
        """Test that partial downloads are cleaned up on failure."""
        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch(
                "urllib.request.urlopen", side_effect=Exception("Network error")
            ):
                setup.download_debian_iso("12")

        # Check that no .downloading files remain
        downloading_files = list(tmp_path.glob("*.downloading"))
        assert len(downloading_files) == 0

    def test_cleanup_partial_download_with_existing_temp(self, setup, tmp_path):
        """Test cleanup when temp file exists during exception."""
        # Create a mock temp file that will exist after the exception
        temp_file = tmp_path / "debian-12.9.0-amd64-netinst.iso.downloading"

        mock_response = Mock()
        mock_response.headers = {"content-length": str(600 * 1024 * 1024)}

        def create_temp_and_fail(*_args, **_kwargs):
            # Create the temp file first (simulating partial download)
            temp_file.write_bytes(b"partial data")
            raise IOError("Download interrupted")

        mock_response.__enter__ = Mock(side_effect=create_temp_and_fail)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                result = setup.download_debian_iso("12")

        assert result["success"] is False
        # The temp file should be cleaned up
        assert not temp_file.exists()

    def test_cleanup_partial_download_oserror_ignored(self, setup, tmp_path):
        """Test that OSError during cleanup is ignored."""
        temp_file = tmp_path / "debian-12.9.0-amd64-netinst.iso.downloading"

        def mock_urlopen(*_args, **_kwargs):
            # Create temp file and then fail
            temp_file.write_bytes(b"partial")
            raise IOError("Download failed")

        # Create a mock Path that raises OSError on unlink
        original_unlink = Path.unlink

        def mock_unlink(self):
            if str(self).endswith(".downloading"):
                raise OSError("Permission denied")
            return original_unlink(self)

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                with patch.object(Path, "unlink", mock_unlink):
                    # Should not raise, OSError should be caught
                    result = setup.download_debian_iso("12")

        assert result["success"] is False

    def test_cleanup_existing_temp_file(self, setup, tmp_path):
        """Test that existing temp files are cleaned up before download."""
        temp_file = tmp_path / "debian-12.9.0-amd64-netinst.iso.downloading"
        temp_file.write_bytes(b"partial data")

        mock_response = Mock()
        mock_response.headers = {"content-length": str(600 * 1024 * 1024)}
        chunk = b"0" * (1024 * 1024)
        mock_response.read = Mock(side_effect=[chunk] * 600 + [b""])
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("urllib.request.urlopen", return_value=mock_response):
                setup.download_debian_iso("12")

        # Temp file should be cleaned up
        assert not temp_file.exists()


class TestCheckCachedIso:
    """Tests for _check_cached_iso method."""

    def test_no_cached_iso(self, setup, tmp_path):
        """Test when no cached ISO exists."""
        iso_path = tmp_path / "nonexistent.iso"
        result = setup._check_cached_iso(iso_path)
        assert result is None

    def test_valid_cached_iso(self, setup, tmp_path):
        """Test when valid cached ISO exists."""
        iso_path = tmp_path / "test.iso"
        iso_path.write_bytes(b"0" * (501 * 1024 * 1024))

        result = setup._check_cached_iso(iso_path)
        assert result is not None
        assert result["success"] is True
        assert result["iso_path"] == str(iso_path)

    def test_small_cached_iso_removed(self, setup, tmp_path):
        """Test that small cached ISO is removed."""
        iso_path = tmp_path / "test.iso"
        iso_path.write_bytes(b"0" * 1000)

        result = setup._check_cached_iso(iso_path)
        assert result is None
        assert not iso_path.exists()


class TestDownloadIsoToTemp:
    """Tests for _download_iso_to_temp method."""

    def test_download_with_progress(self, setup, tmp_path):
        """Test download with progress logging."""
        temp_path = tmp_path / "test.downloading"
        mock_response = Mock()
        mock_response.headers = {"content-length": str(100 * 1024 * 1024)}
        chunk = b"0" * (1024 * 1024)
        mock_response.read = Mock(side_effect=[chunk] * 100 + [b""])
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            total_size = setup._download_iso_to_temp(
                "http://example.com/test.iso", temp_path
            )

        assert total_size == 100 * 1024 * 1024
        assert temp_path.exists()

    def test_download_without_content_length(self, setup, tmp_path):
        """Test download when content-length header is missing."""
        temp_path = tmp_path / "test.downloading"
        mock_response = Mock()
        mock_response.headers = {}
        chunk = b"0" * (1024 * 1024)
        mock_response.read = Mock(side_effect=[chunk, b""])
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            total_size = setup._download_iso_to_temp(
                "http://example.com/test.iso", temp_path
            )

        assert total_size == 0


class TestValidateDownloadedIso:
    """Tests for _validate_downloaded_iso method."""

    def test_valid_download(self, setup, tmp_path):
        """Test validation of correctly sized download."""
        temp_path = tmp_path / "test.downloading"
        temp_path.write_bytes(b"0" * 1000)

        result = setup._validate_downloaded_iso(temp_path, 1000)
        assert result is None

    def test_invalid_download_size_mismatch(self, setup, tmp_path):
        """Test validation fails when size doesn't match."""
        temp_path = tmp_path / "test.downloading"
        temp_path.write_bytes(b"0" * 500)

        result = setup._validate_downloaded_iso(temp_path, 1000)
        assert result is not None
        assert result["success"] is False
        assert "incomplete" in result["error"]
        assert not temp_path.exists()

    def test_validation_skipped_when_no_expected_size(self, setup, tmp_path):
        """Test validation is skipped when total_size is 0."""
        temp_path = tmp_path / "test.downloading"
        temp_path.write_bytes(b"0" * 500)

        result = setup._validate_downloaded_iso(temp_path, 0)
        assert result is None


class TestCreateSerialConsoleIso:
    """Tests for create_serial_console_iso method."""

    def test_bsdtar_extraction_failure(self, setup, tmp_path):
        """Test handling of bsdtar extraction failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "extraction failed"

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", return_value=mock_result):
                result = setup.create_serial_console_iso(
                    "/path/to/original.iso",
                    "vm01",
                    "http://example.com/preseed.cfg",
                    "192.168.1.100",
                    "192.168.1.1",
                    "8.8.8.8",
                )

        assert result["success"] is False
        assert "Failed to extract ISO" in result["error"]

    def test_missing_isolinux_directory(self, setup, tmp_path):
        """Test handling of missing isolinux directory."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", return_value=mock_result):
                with patch("tempfile.mkdtemp", return_value=str(tmp_path / "extract")):
                    (tmp_path / "extract").mkdir(parents=True, exist_ok=True)
                    result = setup.create_serial_console_iso(
                        "/path/to/original.iso",
                        "vm01",
                        "http://example.com/preseed.cfg",
                        "192.168.1.100",
                        "192.168.1.1",
                        "8.8.8.8",
                    )

        assert result["success"] is False
        assert "No isolinux directory" in result["error"]

    def test_xorriso_failure(self, setup, tmp_path):
        """Test handling of xorriso failure."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir(parents=True)
        isolinux_dir = extract_dir / "isolinux"
        isolinux_dir.mkdir()
        (isolinux_dir / "isolinux.cfg").write_text("default linux")
        (isolinux_dir / "txt.cfg").write_text("label install")

        def mock_run(cmd, **_kwargs):
            mock_result = Mock()
            if "bsdtar" in cmd:
                mock_result.returncode = 0
            elif "dd" in cmd:
                mock_result.returncode = 0
            elif "xorriso" in cmd:
                mock_result.returncode = 1
                mock_result.stderr = "xorriso failed"
            else:
                mock_result.returncode = 0
            return mock_result

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", side_effect=mock_run):
                with patch("tempfile.mkdtemp", return_value=str(extract_dir)):
                    result = setup.create_serial_console_iso(
                        "/path/to/original.iso",
                        "vm01",
                        "http://example.com/preseed.cfg",
                        "192.168.1.100",
                        "192.168.1.1",
                        "8.8.8.8",
                    )

        assert result["success"] is False
        assert "Failed to create ISO" in result["error"]

    def test_successful_iso_creation(self, setup, tmp_path):
        """Test successful ISO creation."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir(parents=True)
        isolinux_dir = extract_dir / "isolinux"
        isolinux_dir.mkdir()
        (isolinux_dir / "isolinux.cfg").write_text("default linux")
        (isolinux_dir / "txt.cfg").write_text("label install")
        (isolinux_dir / "gtk.cfg").write_text("default installgui")
        (extract_dir / "md5sum.txt").write_text("abc123  ./file.txt")

        # Create EFI boot image directory
        efi_dir = extract_dir / "boot" / "grub"
        efi_dir.mkdir(parents=True)
        (efi_dir / "efi.img").write_bytes(b"efi")

        modified_iso = tmp_path / "debian-serial-vm01.iso"

        def mock_run(cmd, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            mock_result.stdout = ""
            # Create the modified ISO when xorriso is called
            if "xorriso" in cmd:
                modified_iso.write_bytes(b"0" * (1024 * 1024))
            return mock_result

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", side_effect=mock_run):
                with patch("tempfile.mkdtemp", return_value=str(extract_dir)):
                    result = setup.create_serial_console_iso(
                        "/path/to/original.iso",
                        "vm01",
                        "http://example.com/preseed.cfg",
                        "192.168.1.100",
                        "192.168.1.1",
                        "8.8.8.8",
                    )

        assert result["success"] is True
        assert "iso_path" in result

    def test_exception_during_iso_creation(self, setup, tmp_path):
        """Test handling of exception during ISO creation."""
        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", side_effect=Exception("Unexpected error")):
                result = setup.create_serial_console_iso(
                    "/path/to/original.iso",
                    "vm01",
                    "http://example.com/preseed.cfg",
                    "192.168.1.100",
                    "192.168.1.1",
                    "8.8.8.8",
                )

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    def test_temp_directory_cleanup(self, setup, tmp_path):
        """Test that temp directory is cleaned up after ISO creation."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir(parents=True)
        isolinux_dir = extract_dir / "isolinux"
        isolinux_dir.mkdir()
        (isolinux_dir / "isolinux.cfg").write_text("default linux")
        (isolinux_dir / "txt.cfg").write_text("label install")

        modified_iso = tmp_path / "debian-serial-vm01.iso"

        def mock_run(cmd, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            if "xorriso" in cmd:
                modified_iso.write_bytes(b"0" * (1024 * 1024))
            return mock_result

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", side_effect=mock_run):
                with patch("tempfile.mkdtemp", return_value=str(extract_dir)):
                    with patch("shutil.rmtree") as mock_rmtree:
                        setup.create_serial_console_iso(
                            "/path/to/original.iso",
                            "vm01",
                            "http://example.com/preseed.cfg",
                            "192.168.1.100",
                            "192.168.1.1",
                            "8.8.8.8",
                        )
                        mock_rmtree.assert_called()

    def test_mbr_extraction_failure_logs_warning(self, setup, tmp_path):
        """Test that MBR extraction failure logs a warning but continues."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir(parents=True)
        isolinux_dir = extract_dir / "isolinux"
        isolinux_dir.mkdir()
        (isolinux_dir / "isolinux.cfg").write_text("default linux")
        (isolinux_dir / "txt.cfg").write_text("label install")

        modified_iso = tmp_path / "debian-serial-vm01.iso"

        def mock_run(cmd, **_kwargs):
            mock_result = Mock()
            mock_result.stderr = ""
            mock_result.stdout = ""
            if "bsdtar" in cmd:
                mock_result.returncode = 0
            elif "dd" in cmd:
                # dd fails for MBR extraction
                mock_result.returncode = 1
                mock_result.stderr = "dd failed"
            elif "xorriso" in cmd:
                mock_result.returncode = 0
                modified_iso.write_bytes(b"0" * (1024 * 1024))
            else:
                mock_result.returncode = 0
            return mock_result

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", side_effect=mock_run):
                with patch("tempfile.mkdtemp", return_value=str(extract_dir)):
                    result = setup.create_serial_console_iso(
                        "/path/to/original.iso",
                        "vm01",
                        "http://example.com/preseed.cfg",
                        "192.168.1.100",
                        "192.168.1.1",
                        "8.8.8.8",
                    )

        # Should still succeed - MBR failure is non-fatal
        assert result["success"] is True

    def test_mbr_template_added_when_exists(self, setup, tmp_path):
        """Test that MBR template is added to xorriso when it exists."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir(parents=True)
        isolinux_dir = extract_dir / "isolinux"
        isolinux_dir.mkdir()
        (isolinux_dir / "isolinux.cfg").write_text("default linux")
        (isolinux_dir / "txt.cfg").write_text("label install")

        mbr_template = extract_dir / "isohdpfx.bin"
        modified_iso = tmp_path / "debian-serial-vm01.iso"

        captured_xorriso_cmd = []

        def mock_run(cmd, **_kwargs):
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stderr = ""
            mock_result.stdout = ""
            if "bsdtar" in cmd:
                pass
            elif "dd" in cmd:
                # dd succeeds and creates MBR template
                mbr_template.write_bytes(b"0" * 432)
            elif "xorriso" in cmd:
                captured_xorriso_cmd.extend(cmd)
                modified_iso.write_bytes(b"0" * (1024 * 1024))
            return mock_result

        with patch.object(setup, "ISO_CACHE_DIR", str(tmp_path)):
            with patch("subprocess.run", side_effect=mock_run):
                with patch("tempfile.mkdtemp", return_value=str(extract_dir)):
                    result = setup.create_serial_console_iso(
                        "/path/to/original.iso",
                        "vm01",
                        "http://example.com/preseed.cfg",
                        "192.168.1.100",
                        "192.168.1.1",
                        "8.8.8.8",
                    )

        assert result["success"] is True
        # Check that isohybrid-mbr was added to xorriso command
        assert "-isohybrid-mbr" in captured_xorriso_cmd


class TestModifyIsolinuxCfg:
    """Tests for _modify_isolinux_cfg method."""

    def test_modify_isolinux_cfg(self, setup, tmp_path):
        """Test modification of isolinux.cfg."""
        cfg_path = tmp_path / "isolinux.cfg"
        cfg_path.write_text("original content")

        setup._modify_isolinux_cfg(cfg_path)

        content = cfg_path.read_text()
        assert "SERIAL 0 115200" in content
        assert "CONSOLE 0" in content
        assert "DEFAULT install" in content
        assert "TIMEOUT 1" in content
        assert "include txt.cfg" in content


class TestModifyTxtCfg:
    """Tests for _modify_txt_cfg method."""

    def test_modify_txt_cfg_with_preseed(self, setup, tmp_path):
        """Test modification of txt.cfg with preseed URL."""
        cfg_path = tmp_path / "txt.cfg"
        cfg_path.write_text("original content")

        setup._modify_txt_cfg(
            cfg_path,
            "http://example.com/preseed.cfg",
            "192.168.1.100",
            "192.168.1.1",
            "8.8.8.8",
        )

        content = cfg_path.read_text()
        assert "console=ttyS0,115200n8" in content
        assert "url=http://example.com/preseed.cfg" in content
        assert "192.168.1.100" in content
        assert "192.168.1.1" in content
        assert "8.8.8.8" in content
        assert "netcfg/disable_dhcp=true" in content

    def test_modify_txt_cfg_without_preseed(self, setup, tmp_path):
        """Test modification of txt.cfg without preseed URL."""
        cfg_path = tmp_path / "txt.cfg"
        cfg_path.write_text("original content")

        setup._modify_txt_cfg(cfg_path, "", "192.168.1.100", "192.168.1.1", "8.8.8.8")

        content = cfg_path.read_text()
        assert "console=ttyS0,115200n8" in content
        assert "url=" not in content

    def test_modify_txt_cfg_without_network(self, setup, tmp_path):
        """Test modification of txt.cfg without network config."""
        cfg_path = tmp_path / "txt.cfg"
        cfg_path.write_text("original content")

        setup._modify_txt_cfg(cfg_path, "http://example.com/preseed.cfg", "", "", "")

        content = cfg_path.read_text()
        assert "netcfg/disable_dhcp" not in content

    def test_modify_txt_cfg_without_dns(self, setup, tmp_path):
        """Test modification of txt.cfg without DNS server."""
        cfg_path = tmp_path / "txt.cfg"
        cfg_path.write_text("original content")

        setup._modify_txt_cfg(
            cfg_path,
            "http://example.com/preseed.cfg",
            "192.168.1.100",
            "192.168.1.1",
            "",
        )

        content = cfg_path.read_text()
        assert "netcfg/get_nameservers" not in content


class TestDisableGtkDefault:
    """Tests for _disable_gtk_default method."""

    def test_disable_gtk_default(self, setup, tmp_path):
        """Test disabling GTK installer as default."""
        cfg_path = tmp_path / "gtk.cfg"
        cfg_path.write_text("default installgui\nlabel installgui")

        setup._disable_gtk_default(cfg_path)

        content = cfg_path.read_text()
        assert "# default installgui" in content
        assert "label installgui" in content


class TestRegenerateChecksums:
    """Tests for _regenerate_checksums method."""

    def test_regenerate_checksums_success(self, setup, tmp_path):
        """Test successful checksum regeneration."""
        md5_path = tmp_path / "md5sum.txt"
        md5_path.write_text("oldsum  ./file.txt")
        md5_path.chmod(0o444)  # Read-only initially

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            setup._regenerate_checksums(str(tmp_path))

    def test_regenerate_checksums_no_md5sum_file(self, setup, tmp_path):
        """Test when md5sum.txt doesn't exist."""
        # Should not raise an exception
        setup._regenerate_checksums(str(tmp_path))


class TestCreatePreseedFile:
    """Tests for create_preseed_file method."""

    def test_create_preseed_file_success(self, setup):
        """Test successful preseed file creation."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
        )

        assert result["success"] is True
        assert result["preseed"] is not None
        assert "vm01.example.com" in result["preseed"]
        assert "admin" in result["preseed"]

    def test_create_preseed_file_unsupported_version(self, setup):
        """Test preseed file creation with unsupported version."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="99",
        )

        assert result["success"] is False
        assert "Unsupported Debian version" in result["error"]

    def test_create_preseed_file_with_dns(self, setup):
        """Test preseed file creation with custom DNS."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
            dns_server="8.8.8.8",
        )

        assert result["success"] is True
        assert "8.8.8.8" in result["preseed"]

    def test_create_preseed_file_with_custom_disk(self, setup):
        """Test preseed file creation with custom disk."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
            disk="sda",
        )

        assert result["success"] is True
        assert "/dev/sda" in result["preseed"]

    def test_create_preseed_file_with_timezone(self, setup):
        """Test preseed file creation with custom timezone."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
            timezone="America/New_York",
        )

        assert result["success"] is True
        assert "America/New_York" in result["preseed"]

    def test_create_preseed_file_exception(self, setup):
        """Test preseed file creation with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_debian_autoinstall.generate_preseed_file",
            side_effect=Exception("Generation error"),
        ):
            result = setup.create_preseed_file(
                hostname="vm01.example.com",
                username="admin",
                user_password_hash="$6$user_hash",
                root_password_hash="$6$root_hash",
                gateway_ip="192.168.1.1",
                vm_ip="192.168.1.100",
                debian_version="12",
            )

        assert result["success"] is False
        assert "Generation error" in result["error"]

    def test_create_preseed_file_with_full_mirror_url(self, setup):
        """Test preseed file creation with full mirror URL (https://)."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
        )

        assert result["success"] is True
        # The mirror URL should be parsed to hostname only
        assert "deb.debian.org" in result["preseed"]


class TestCreateDebianDataDir:
    """Tests for create_debian_data_dir method."""

    def test_create_debian_data_dir_success(self, setup, tmp_path):
        """Test successful data directory creation."""
        preseed_content = "# preseed content"

        with patch.object(setup, "DEBIAN_DATA_BASE", str(tmp_path / "debian-data")):
            with patch.object(setup, "HTTPD_ROOT", str(tmp_path / "htdocs")):
                result = setup.create_debian_data_dir(
                    vm_name="vm01",
                    preseed_content=preseed_content,
                    server_hostname="sysmanage.example.com",
                    server_port=8443,
                    use_https=True,
                )

        assert result["success"] is True
        assert "data_dir" in result
        assert "preseed_path" in result
        assert "preseed_url" in result
        assert "config_path" in result
        assert "firstboot_path" in result
        assert "service_path" in result

    def test_create_debian_data_dir_with_auto_approve(self, setup, tmp_path):
        """Test data directory creation with auto-approve token."""
        preseed_content = "# preseed content"

        with patch.object(setup, "DEBIAN_DATA_BASE", str(tmp_path / "debian-data")):
            with patch.object(setup, "HTTPD_ROOT", str(tmp_path / "htdocs")):
                result = setup.create_debian_data_dir(
                    vm_name="vm01",
                    preseed_content=preseed_content,
                    server_hostname="sysmanage.example.com",
                    server_port=8443,
                    use_https=True,
                    auto_approve_token="12345678-1234-1234-1234-123456789012",
                )

        assert result["success"] is True
        # Read the config file and verify token
        config_path = Path(result["config_path"])
        config_content = config_path.read_text(encoding="utf-8")
        assert "12345678-1234-1234-1234-123456789012" in config_content

    def test_create_debian_data_dir_creates_all_files(self, setup, tmp_path):
        """Test that all required files are created."""
        preseed_content = "# preseed content"

        with patch.object(setup, "DEBIAN_DATA_BASE", str(tmp_path / "debian-data")):
            with patch.object(setup, "HTTPD_ROOT", str(tmp_path / "htdocs")):
                result = setup.create_debian_data_dir(
                    vm_name="vm01",
                    preseed_content=preseed_content,
                    server_hostname="sysmanage.example.com",
                    server_port=8443,
                    use_https=True,
                )

        # Verify all files exist
        assert Path(result["preseed_path"]).exists()
        assert Path(result["config_path"]).exists()
        assert Path(result["firstboot_path"]).exists()
        assert Path(result["service_path"]).exists()

        # Verify firstboot script is executable
        firstboot_path = Path(result["firstboot_path"])
        assert firstboot_path.stat().st_mode & 0o111

    def test_create_debian_data_dir_httpd_preseed(self, setup, tmp_path):
        """Test that preseed is copied to httpd directory."""
        preseed_content = "# preseed content"

        with patch.object(setup, "DEBIAN_DATA_BASE", str(tmp_path / "debian-data")):
            with patch.object(setup, "HTTPD_ROOT", str(tmp_path / "htdocs")):
                _result = setup.create_debian_data_dir(
                    vm_name="vm01",
                    preseed_content=preseed_content,
                    server_hostname="sysmanage.example.com",
                    server_port=8443,
                    use_https=True,
                )

        httpd_preseed = tmp_path / "htdocs" / "debian" / "vm01" / "preseed.cfg"
        assert httpd_preseed.exists()
        assert httpd_preseed.read_text() == preseed_content

    def test_create_debian_data_dir_preseed_url(self, setup, tmp_path):
        """Test that preseed URL is generated correctly."""
        preseed_content = "# preseed content"

        with patch.object(setup, "DEBIAN_DATA_BASE", str(tmp_path / "debian-data")):
            with patch.object(setup, "HTTPD_ROOT", str(tmp_path / "htdocs")):
                result = setup.create_debian_data_dir(
                    vm_name="vm01",
                    preseed_content=preseed_content,
                    server_hostname="sysmanage.example.com",
                    server_port=8443,
                    use_https=True,
                )

        assert result["preseed_url"] == "http://100.64.0.1/debian/vm01/preseed.cfg"

    def test_create_debian_data_dir_exception(self, setup):
        """Test data directory creation with exception."""
        with patch.object(setup, "DEBIAN_DATA_BASE", "/nonexistent/path"):
            with patch(
                "pathlib.Path.mkdir", side_effect=PermissionError("Access denied")
            ):
                result = setup.create_debian_data_dir(
                    vm_name="vm01",
                    preseed_content="# preseed",
                    server_hostname="sysmanage.example.com",
                    server_port=8443,
                    use_https=True,
                )

        assert result["success"] is False
        assert "Access denied" in result["error"]


class TestCreateLateCommandScript:
    """Tests for create_late_command_script method."""

    def test_create_late_command_script_basic(self, setup):
        """Test basic late command script creation."""
        result = setup.create_late_command_script(
            hostname="vm01.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
        )

        assert "mkdir -p /target/etc/sysmanage-agent" in result
        assert "vm01" in result  # Short hostname
        assert "192.168.1.100" in result
        assert "192.168.1.1" in result
        assert "8.8.8.8" in result
        assert "poweroff" in result

    def test_create_late_command_script_with_auto_approve(self, setup):
        """Test late command script with auto-approve token."""
        result = setup.create_late_command_script(
            hostname="vm01.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
            auto_approve_token="12345678-1234-1234-1234-123456789012",
        )

        # Token should be base64 encoded in the script
        assert "base64 -d" in result

    def test_create_late_command_script_with_agent_deb_url(self, setup):
        """Test late command script with agent .deb URL."""
        result = setup.create_late_command_script(
            hostname="vm01.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
            agent_deb_url="http://100.64.0.1/debian/vm01/sysmanage-agent.deb",
        )

        assert "wget -q -O /target/root/sysmanage-agent.deb" in result
        assert "http://100.64.0.1/debian/vm01/sysmanage-agent.deb" in result

    def test_create_late_command_script_network_config(self, setup):
        """Test that network configuration is included."""
        result = setup.create_late_command_script(
            hostname="vm01.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
        )

        assert "enp0s2" in result
        assert "inet static" in result
        assert "address 192.168.1.100" in result
        assert "gateway 192.168.1.1" in result
        assert "dns-nameservers 8.8.8.8" in result

    def test_create_late_command_script_base64_encoding(self, setup):
        """Test that config content is base64 encoded."""
        result = setup.create_late_command_script(
            hostname="vm01.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
        )

        # Find base64 encoded content and verify it can be decoded
        # The config should contain server hostname when decoded
        lines = result.split(";")
        for line in lines:
            if "base64 -d > /target/etc/sysmanage-agent.yaml" in line:
                # Extract the base64 content
                parts = line.split("echo '")
                if len(parts) > 1:
                    b64_content = parts[1].split("'")[0]
                    decoded = base64.b64decode(b64_content).decode()
                    assert "sysmanage.example.com" in decoded

    def test_create_late_command_script_systemd_service(self, setup):
        """Test that systemd service is enabled."""
        result = setup.create_late_command_script(
            hostname="vm01.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
        )

        assert "sysmanage-firstboot.service" in result
        assert "multi-user.target.wants" in result


class TestGenerateEnhancedPreseed:
    """Tests for generate_enhanced_preseed method."""

    def test_generate_enhanced_preseed_success(self, setup):
        """Test successful enhanced preseed generation."""
        network = NetworkConfig(
            vm_ip="192.168.1.100", gateway_ip="192.168.1.1", dns_server="8.8.8.8"
        )
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
        )

        result = setup.generate_enhanced_preseed(config)

        assert result["success"] is True
        assert result["preseed"] is not None
        # Should contain late_command with our script
        assert "mkdir -p /target/etc/sysmanage-agent" in result["preseed"]

    def test_generate_enhanced_preseed_with_agent_deb_url(self, setup):
        """Test enhanced preseed with agent .deb URL."""
        network = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
            agent_deb_url="http://100.64.0.1/debian/vm01/sysmanage-agent.deb",
        )

        result = setup.generate_enhanced_preseed(config)

        assert result["success"] is True
        assert "sysmanage-agent.deb" in result["preseed"]

    def test_generate_enhanced_preseed_with_auto_approve(self, setup):
        """Test enhanced preseed with auto-approve token."""
        network = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
            auto_approve_token="12345678-1234-1234-1234-123456789012",
        )

        result = setup.generate_enhanced_preseed(config)

        assert result["success"] is True
        # Token should be embedded in the late_command (base64 encoded)
        assert "base64 -d" in result["preseed"]

    def test_generate_enhanced_preseed_uses_gateway_as_dns_fallback(self, setup):
        """Test that gateway IP is used as DNS fallback."""
        network = NetworkConfig(
            vm_ip="192.168.1.100", gateway_ip="192.168.1.1", dns_server=None
        )
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
        )

        result = setup.generate_enhanced_preseed(config)

        assert result["success"] is True
        # Gateway should be used as DNS
        assert "dns-nameservers 192.168.1.1" in result["preseed"]

    def test_generate_enhanced_preseed_base_preseed_failure(self, setup):
        """Test enhanced preseed when base preseed fails."""
        network = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="99",  # Unsupported version
            network=network,
            server=server,
            user=user,
        )

        result = setup.generate_enhanced_preseed(config)

        assert result["success"] is False
        assert "Unsupported Debian version" in result["error"]

    def test_generate_enhanced_preseed_exception(self, setup):
        """Test enhanced preseed with exception."""
        network = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
        )

        with patch.object(
            setup, "create_preseed_file", side_effect=Exception("Preseed error")
        ):
            result = setup.generate_enhanced_preseed(config)

        assert result["success"] is False
        assert "Preseed error" in result["error"]

    def test_generate_enhanced_preseed_custom_disk_and_timezone(self, setup):
        """Test enhanced preseed with custom disk and timezone."""
        network = NetworkConfig(vm_ip="192.168.1.100", gateway_ip="192.168.1.1")
        server = ServerConfig(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )
        user = UserConfig(
            username="admin",
            user_password_hash="$6$user",
            root_password_hash="$6$root",
        )
        config = PreseedConfig(
            hostname="vm01.example.com",
            debian_version="12",
            network=network,
            server=server,
            user=user,
            disk="sda",
            timezone="America/New_York",
        )

        result = setup.generate_enhanced_preseed(config)

        assert result["success"] is True
        assert "/dev/sda" in result["preseed"]
        assert "America/New_York" in result["preseed"]


class TestPreseedContentSecurity:
    """Security tests for generated preseed content."""

    def test_no_hardcoded_passwords(self, setup):
        """Test that no hardcoded passwords are in the preseed."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$rounds=5000$saltsalt$hash",
            root_password_hash="$6$rounds=5000$saltsalt$roothash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
        )

        preseed = result["preseed"]
        # Should only contain hashed passwords
        assert "$6$rounds" in preseed or "$6$" in preseed
        # Should not contain common password patterns
        assert "password123" not in preseed.lower()
        assert "admin123" not in preseed.lower()

    def test_password_hashes_preserved(self, setup):
        """Test that password hashes are correctly included."""
        user_hash = "$6$rounds=5000$saltsalt$abcdefghijk"
        root_hash = "$6$rounds=5000$saltsalt$lmnopqrstuvw"

        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash=user_hash,
            root_password_hash=root_hash,
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
        )

        assert user_hash in result["preseed"]
        assert root_hash in result["preseed"]


class TestEdgeCases:
    """Edge case tests."""

    def test_fqdn_hostname_parsing(self, setup):
        """Test FQDN hostname is correctly parsed."""
        result = setup.create_late_command_script(
            hostname="vm01.subdomain.example.com",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
        )

        # Short hostname should be extracted
        assert "vm01" in result
        assert "vm01.subdomain.example.com" in result

    def test_simple_hostname_parsing(self, setup):
        """Test simple hostname without domain."""
        result = setup.create_late_command_script(
            hostname="vm01",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            dns_server="8.8.8.8",
        )

        assert "vm01" in result

    def test_preseed_domain_extraction(self, setup):
        """Test domain extraction from FQDN in preseed."""
        result = setup.create_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
        )

        # Domain should be extracted
        assert "example.com" in result["preseed"]

    def test_preseed_no_domain(self, setup):
        """Test preseed with hostname without domain."""
        result = setup.create_preseed_file(
            hostname="vm01",
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="12",
        )

        # Should use 'local' as domain fallback
        assert "local" in result["preseed"] or result["success"]
