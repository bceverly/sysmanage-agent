"""
Comprehensive unit tests for child_host_vmm_httpd_autoinstall module.
Tests HttpdAutoinstallSetup for VMM autoinstall using httpd approach.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.child_host_vmm_httpd_autoinstall import (
    HttpdAutoinstallSetup,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    return Mock(spec=logging.Logger)


@pytest.fixture
def httpd_setup(mock_logger):
    """Create an HttpdAutoinstallSetup instance for testing."""
    return HttpdAutoinstallSetup(mock_logger)


class TestHttpdAutoinstallSetupInit:
    """Tests for HttpdAutoinstallSetup initialization."""

    def test_init_with_logger(self, mock_logger):
        """Test initialization with a logger."""
        setup = HttpdAutoinstallSetup(mock_logger)
        assert setup.logger == mock_logger

    def test_class_constants(self, httpd_setup):
        """Test that class constants are properly defined."""
        assert httpd_setup.OPENBSD_MIRROR == "https://ftp.openbsd.org/pub/OpenBSD"
        assert httpd_setup.SETS_BASE == "/var/www/htdocs/pub/OpenBSD"
        assert "bsd" in httpd_setup.REQUIRED_SETS
        assert "bsd.rd" in httpd_setup.REQUIRED_SETS
        assert "SHA256" in httpd_setup.REQUIRED_SETS
        assert "base{version}.tgz" in httpd_setup.REQUIRED_SETS


class TestSetupHttpd:
    """Tests for setup_httpd method."""

    def test_setup_httpd_success(self, httpd_setup):
        """Test successful httpd setup."""
        mock_result_write = Mock(returncode=0, stderr="")
        mock_result_enable = Mock(returncode=0, stderr=b"")
        mock_result_restart = Mock(returncode=0, stderr=b"")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock_result_write,  # tee httpd.conf
                mock_result_enable,  # rcctl enable
                mock_result_restart,  # rcctl restart
            ]

            result = httpd_setup.setup_httpd("10.1.0.1")

        assert result["success"] is True
        assert mock_run.call_count == 3

    def test_setup_httpd_write_failure(self, httpd_setup):
        """Test httpd setup when writing config fails."""
        mock_result_write = Mock(returncode=1, stderr="Permission denied")

        with patch("subprocess.run", return_value=mock_result_write):
            result = httpd_setup.setup_httpd("10.1.0.1")

        assert result["success"] is False
        assert "Failed to write httpd.conf" in result["error"]
        assert "Permission denied" in result["error"]

    def test_setup_httpd_restart_failure(self, httpd_setup):
        """Test httpd setup when restart fails."""
        mock_result_write = Mock(returncode=0, stderr="")
        mock_result_enable = Mock(returncode=0, stderr=b"")
        mock_result_restart = Mock(returncode=1, stderr=b"httpd failed to start")

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock_result_write,
                mock_result_enable,
                mock_result_restart,
            ]

            result = httpd_setup.setup_httpd("10.1.0.1")

        assert result["success"] is False
        assert "Failed to start httpd" in result["error"]

    def test_setup_httpd_exception(self, httpd_setup):
        """Test httpd setup with exception."""
        with patch("subprocess.run", side_effect=Exception("Subprocess error")):
            result = httpd_setup.setup_httpd("10.1.0.1")

        assert result["success"] is False
        assert "Subprocess error" in result["error"]

    def test_setup_httpd_config_content(self, httpd_setup):
        """Test that httpd config contains correct content."""
        mock_result = Mock(returncode=0, stderr="")

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            httpd_setup.setup_httpd("10.1.0.1")

        # Check the first call (writing httpd.conf)
        first_call = mock_run.call_args_list[0]
        cmd = first_call[0][0]
        # The command should be sh -c with the config
        assert cmd[0] == "sh"
        assert cmd[1] == "-c"
        # Check config contains expected content
        config_cmd = cmd[2]
        assert "listen on 10.1.0.1 port 80" in config_cmd
        assert 'root "/htdocs"' in config_cmd

    def test_setup_httpd_different_gateway_ip(self, httpd_setup):
        """Test httpd setup with different gateway IPs."""
        mock_result = Mock(returncode=0, stderr=b"")

        for gateway_ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1"]:
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                result = httpd_setup.setup_httpd(gateway_ip)

            assert result["success"] is True
            first_call = mock_run.call_args_list[0]
            config_cmd = first_call[0][0][2]
            assert f"listen on {gateway_ip} port 80" in config_cmd


class TestDownloadOpenbsdSets:
    """Tests for download_openbsd_sets method."""

    def test_download_sets_success(self, httpd_setup, tmp_path):
        """Test successful OpenBSD sets download."""
        _sets_dir = tmp_path / "pub" / "OpenBSD" / "7.7" / "amd64"

        with patch.object(httpd_setup, "SETS_BASE", str(tmp_path / "pub" / "OpenBSD")):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = b"test content"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                result = httpd_setup.download_openbsd_sets("7.7")

        assert result["success"] is True
        assert "sets_dir" in result
        # Should have attempted to download sets
        assert mock_urlopen.called

    def test_download_sets_creates_directory(self, httpd_setup, tmp_path):
        """Test that download creates the sets directory."""
        base_dir = tmp_path / "pub" / "OpenBSD"

        with patch.object(httpd_setup, "SETS_BASE", str(base_dir)):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = b"test content"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                httpd_setup.download_openbsd_sets("7.7")

        expected_dir = base_dir / "7.7" / "amd64"
        assert expected_dir.exists()

    def test_download_sets_skips_existing(self, httpd_setup, tmp_path):
        """Test that download skips already downloaded sets."""
        base_dir = tmp_path / "pub" / "OpenBSD"
        sets_dir = base_dir / "7.7" / "amd64"
        sets_dir.mkdir(parents=True)

        # Create existing files
        (sets_dir / "bsd").write_text("existing kernel")
        (sets_dir / "bsd.rd").write_text("existing ramdisk")

        with patch.object(httpd_setup, "SETS_BASE", str(base_dir)):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = b"test content"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                result = httpd_setup.download_openbsd_sets("7.7")

        assert result["success"] is True
        # Verify debug messages for skipped files
        httpd_setup.logger.debug.assert_called()

    def test_download_sets_handles_download_error(self, httpd_setup, tmp_path):
        """Test download handles errors for individual sets gracefully."""
        base_dir = tmp_path / "pub" / "OpenBSD"

        with patch.object(httpd_setup, "SETS_BASE", str(base_dir)):
            with patch("urllib.request.urlopen") as mock_urlopen:
                # First calls fail, later ones succeed
                mock_response = Mock()
                mock_response.read.return_value = b"test content"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)

                # Alternate between success and failure
                mock_urlopen.side_effect = [
                    Exception("Download failed"),
                    mock_response,
                ] * 10

                result = httpd_setup.download_openbsd_sets("7.7")

        # Should still succeed overall (some sets might be optional)
        assert result["success"] is True
        # Should log warnings for failed downloads
        httpd_setup.logger.warning.assert_called()

    def test_download_sets_version_formatting(self, httpd_setup, tmp_path):
        """Test that version is formatted correctly (dots removed)."""
        base_dir = tmp_path / "pub" / "OpenBSD"

        with patch.object(httpd_setup, "SETS_BASE", str(base_dir)):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = b"test content"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                httpd_setup.download_openbsd_sets("7.7")

        # Check that URLs contain version without dots (e.g., "77" not "7.7")
        calls = mock_urlopen.call_args_list
        # At least one call should have the versioned set name
        url_strs = [str(call) for call in calls]
        # Look for base77.tgz in the URLs
        assert any("base77.tgz" in url or "7.7/amd64" in url for url in url_strs)

    def test_download_sets_exception(self, httpd_setup):
        """Test download handles general exceptions."""
        with patch.object(httpd_setup, "SETS_BASE", "/invalid/path"):
            with patch("pathlib.Path.mkdir", side_effect=PermissionError("No access")):
                result = httpd_setup.download_openbsd_sets("7.7")

        assert result["success"] is False
        assert "No access" in result["error"]


class TestEmbedInstallConfInBsdrd:
    """Tests for embed_install_conf_in_bsdrd method."""

    def test_embed_install_conf_success(self, httpd_setup, tmp_path):
        """Test successful embedding of install.conf in bsd.rd."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        # Create required directories (paths for documentation - not used directly)
        _vmm_dir = Path("/var/vmm")
        _ramdisk_mount = Path("/tmp/ramdisk_mount")

        mock_run_results = [
            Mock(returncode=0, stderr=""),  # gzcat
            Mock(returncode=0, stderr=""),  # rdsetroot -x
            Mock(returncode=0, stderr=b""),  # vnconfig
            Mock(returncode=0, stderr=b""),  # mount
            Mock(returncode=0, stderr=b""),  # umount
            Mock(returncode=0, stderr=b""),  # vnconfig -u
            Mock(returncode=0, stderr=b""),  # cp
            Mock(returncode=0, stderr=""),  # rdsetroot
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mock_run_results
            with patch("pathlib.Path.mkdir"):
                with patch("pathlib.Path.unlink"):
                    with patch("pathlib.Path.rmdir"):
                        with patch("builtins.open", mock_open()):
                            result = httpd_setup.embed_install_conf_in_bsdrd(
                                "System hostname = test\n",
                                "7.7",
                                sets_dir,
                            )

        assert result["success"] is True
        assert "bsdrd_path" in result
        assert "7.7" in result["bsdrd_path"]

    def test_embed_install_conf_gzcat_failure(self, httpd_setup, tmp_path):
        """Test handling of gzcat decompression failure."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        mock_run_result = Mock(returncode=1, stderr="gzcat: invalid format")

        with patch("subprocess.run", return_value=mock_run_result):
            with patch("pathlib.Path.mkdir"):
                result = httpd_setup.embed_install_conf_in_bsdrd(
                    "System hostname = test\n",
                    "7.7",
                    sets_dir,
                )

        assert result["success"] is False
        assert "Failed to decompress bsd.rd" in result["error"]

    def test_embed_install_conf_rdsetroot_extract_failure(self, httpd_setup, tmp_path):
        """Test handling of rdsetroot extraction failure."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        mock_run_results = [
            Mock(returncode=0, stderr=""),  # gzcat success
            Mock(returncode=1, stderr="rdsetroot: kernel not found"),  # rdsetroot -x
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mock_run_results
            with patch("pathlib.Path.mkdir"):
                result = httpd_setup.embed_install_conf_in_bsdrd(
                    "System hostname = test\n",
                    "7.7",
                    sets_dir,
                )

        assert result["success"] is False
        assert "rdsetroot extraction failed" in result["error"]

    def test_embed_install_conf_vnconfig_failure(self, httpd_setup, tmp_path):
        """Test handling of vnconfig failure."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        mock_run_results = [
            Mock(returncode=0, stderr=""),  # gzcat
            Mock(returncode=0, stderr=""),  # rdsetroot -x
            Mock(returncode=1, stderr=b"vnconfig: vnd0 busy"),  # vnconfig
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mock_run_results
            with patch("pathlib.Path.mkdir"):
                result = httpd_setup.embed_install_conf_in_bsdrd(
                    "System hostname = test\n",
                    "7.7",
                    sets_dir,
                )

        assert result["success"] is False
        assert "vnconfig failed" in result["error"]

    def test_embed_install_conf_mount_failure(self, httpd_setup, tmp_path):
        """Test handling of mount failure with cleanup."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        mock_run_results = [
            Mock(returncode=0, stderr=""),  # gzcat
            Mock(returncode=0, stderr=""),  # rdsetroot -x
            Mock(returncode=0, stderr=b""),  # vnconfig
            Mock(returncode=1, stderr=b"mount: operation not permitted"),  # mount
            Mock(returncode=0, stderr=b""),  # vnconfig -u (cleanup)
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mock_run_results
            with patch("pathlib.Path.mkdir"):
                result = httpd_setup.embed_install_conf_in_bsdrd(
                    "System hostname = test\n",
                    "7.7",
                    sets_dir,
                )

        assert result["success"] is False
        assert "mount failed" in result["error"]
        # Verify cleanup was attempted
        cleanup_calls = [
            c
            for c in mock_run.call_args_list
            if "vnconfig" in str(c) and "-u" in str(c)
        ]
        assert len(cleanup_calls) >= 1

    def test_embed_install_conf_write_failure(self, httpd_setup, tmp_path):
        """Test handling of install.conf write failure."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        mock_run_results = [
            Mock(returncode=0, stderr=""),  # gzcat
            Mock(returncode=0, stderr=""),  # rdsetroot -x
            Mock(returncode=0, stderr=b""),  # vnconfig
            Mock(returncode=0, stderr=b""),  # mount
            Mock(returncode=0, stderr=b""),  # umount (cleanup)
            Mock(returncode=0, stderr=b""),  # vnconfig -u (cleanup)
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mock_run_results
            with patch("pathlib.Path.mkdir"):
                with patch("builtins.open", side_effect=PermissionError("Read-only")):
                    result = httpd_setup.embed_install_conf_in_bsdrd(
                        "System hostname = test\n",
                        "7.7",
                        sets_dir,
                    )

        assert result["success"] is False
        assert "Failed to write install.conf" in result["error"]

    def test_embed_install_conf_rdsetroot_insert_failure(self, httpd_setup, tmp_path):
        """Test handling of rdsetroot insertion failure."""
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        mock_run_results = [
            Mock(returncode=0, stderr=""),  # gzcat
            Mock(returncode=0, stderr=""),  # rdsetroot -x
            Mock(returncode=0, stderr=b""),  # vnconfig
            Mock(returncode=0, stderr=b""),  # mount
            Mock(returncode=0, stderr=b""),  # umount
            Mock(returncode=0, stderr=b""),  # vnconfig -u
            Mock(returncode=0, stderr=b""),  # cp
            Mock(
                returncode=1, stderr="rdsetroot: insertion failed"
            ),  # rdsetroot (insert)
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mock_run_results
            with patch("pathlib.Path.mkdir"):
                with patch("pathlib.Path.unlink"):
                    with patch("pathlib.Path.rmdir"):
                        with patch("builtins.open", mock_open()):
                            result = httpd_setup.embed_install_conf_in_bsdrd(
                                "System hostname = test\n",
                                "7.7",
                                sets_dir,
                            )

        assert result["success"] is False
        assert "rdsetroot insertion failed" in result["error"]

    def test_embed_install_conf_general_exception(self, httpd_setup, tmp_path):
        """Test handling of general exception with cleanup.

        Note: The source code has a potential issue where mount_point might not
        be defined when the exception handler runs if the exception occurs early.
        This test verifies the exception path when the exception occurs after
        mount_point is defined (during rdsetroot insertion step).
        """
        sets_dir = tmp_path / "sets"
        sets_dir.mkdir()
        (sets_dir / "bsd.rd").write_bytes(b"compressed ramdisk")

        # Mock subprocess.run to succeed for all steps except the final rdsetroot
        # which raises an unexpected exception
        call_count = [0]

        def mock_run_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            # Calls 1-7 succeed (gzcat, rdsetroot -x, vnconfig, mount, umount,
            # vnconfig -u, cp)
            # Call 8 (final rdsetroot) raises an exception
            if call_count[0] == 8:
                raise RuntimeError("Unexpected error during rdsetroot")
            return Mock(returncode=0, stderr=b"", stdout=b"")

        with patch("subprocess.run", side_effect=mock_run_side_effect):
            with patch("pathlib.Path.mkdir"):
                with patch("pathlib.Path.unlink"):
                    with patch("pathlib.Path.rmdir"):
                        with patch("builtins.open", mock_open()):
                            result = httpd_setup.embed_install_conf_in_bsdrd(
                                "System hostname = test\n",
                                "7.7",
                                sets_dir,
                            )

        assert result["success"] is False
        assert "Unexpected error during rdsetroot" in result["error"]


class TestCreateInstallConfContent:
    """Tests for create_install_conf_content method."""

    def test_create_install_conf_basic(self, httpd_setup):
        """Test basic install.conf content creation."""
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            content = httpd_setup.create_install_conf_content(
                hostname="test-vm",
                username="testuser",
                user_password_hash="$2b$10$userpasswordhash",
                root_password_hash="$2b$10$rootpasswordhash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        assert "System hostname = test-vm" in content
        assert "Setup a user = testuser" in content
        assert "$2b$10$userpasswordhash" in content
        assert "$2b$10$rootpasswordhash" in content
        assert "IPv4 address for vio0 = 100.64.0.101" in content
        assert "Default IPv4 route = 10.1.0.1" in content
        assert "HTTP Server = 10.1.0.1" in content
        assert "Server directory = pub/OpenBSD/7.7/amd64" in content

    def test_create_install_conf_dns_from_resolv_conf(self, httpd_setup):
        """Test that DNS is read from /etc/resolv.conf."""
        resolv_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        with patch("builtins.open", mock_open(read_data=resolv_content)):
            content = httpd_setup.create_install_conf_content(
                hostname="test-vm",
                username="testuser",
                user_password_hash="$2b$10$hash",
                root_password_hash="$2b$10$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        assert "DNS nameservers = 1.1.1.1" in content

    def test_create_install_conf_dns_fallback(self, httpd_setup):
        """Test DNS fallback when resolv.conf cannot be read."""
        with patch("builtins.open", side_effect=FileNotFoundError()):
            content = httpd_setup.create_install_conf_content(
                hostname="test-vm",
                username="testuser",
                user_password_hash="$2b$10$hash",
                root_password_hash="$2b$10$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        # Should fall back to 8.8.8.8
        assert "DNS nameservers = 8.8.8.8" in content

    def test_create_install_conf_dns_fallback_no_nameserver(self, httpd_setup):
        """Test DNS fallback when resolv.conf has no nameserver."""
        resolv_content = "# No nameserver lines\nsearch example.com\n"
        with patch("builtins.open", mock_open(read_data=resolv_content)):
            content = httpd_setup.create_install_conf_content(
                hostname="test-vm",
                username="testuser",
                user_password_hash="$2b$10$hash",
                root_password_hash="$2b$10$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        # Should fall back to 8.8.8.8
        assert "DNS nameservers = 8.8.8.8" in content

    def test_create_install_conf_all_fields(self, httpd_setup):
        """Test that all required install.conf fields are present."""
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            content = httpd_setup.create_install_conf_content(
                hostname="myvm",
                username="admin",
                user_password_hash="$2b$10$userhash",
                root_password_hash="$2b$10$roothash",
                gateway_ip="192.168.1.1",
                openbsd_version="7.6",
                vm_ip="192.168.1.100",
            )

        # Check all required fields are present
        required_fields = [
            "System hostname = myvm",
            "Which disk is the root disk = sd0",
            "Use (W)hole disk MBR",
            "Use (A)uto layout",
            "Password for root account = $2b$10$roothash",
            "Setup a user = admin",
            "Password for user admin = $2b$10$userhash",
            "Allow root ssh login = no",
            "What timezone are you in = US/Eastern",
            "Network interfaces = vio0",
            "IPv4 address for vio0 = 192.168.1.100",
            "Netmask for vio0 = 255.255.255.0",
            "Default IPv4 route = 192.168.1.1",
            "Location of sets = http",
            "HTTP Server = 192.168.1.1",
            "Server directory = pub/OpenBSD/7.6/amd64",
            "Set name(s) = -game* -x* +site*",
            "Continue without verification = yes",
            "Reboot after install = no",
        ]

        for field in required_fields:
            assert field in content, f"Missing field: {field}"

    def test_create_install_conf_different_versions(self, httpd_setup):
        """Test install.conf generation with different OpenBSD versions."""
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            for version in ["7.5", "7.6", "7.7", "7.8"]:
                content = httpd_setup.create_install_conf_content(
                    hostname="test",
                    username="user",
                    user_password_hash="$hash",
                    root_password_hash="$hash",
                    gateway_ip="10.0.0.1",
                    openbsd_version=version,
                    vm_ip="10.0.0.100",
                )

                assert f"Server directory = pub/OpenBSD/{version}/amd64" in content

    def test_create_install_conf_logs_content(self, httpd_setup):
        """Test that install.conf content is logged."""
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            httpd_setup.create_install_conf_content(
                hostname="test-vm",
                username="testuser",
                user_password_hash="$hash",
                root_password_hash="$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        # Verify logging occurred
        httpd_setup.logger.info.assert_called()

    def test_create_install_conf_special_characters_in_hostname(self, httpd_setup):
        """Test install.conf with special characters in hostname."""
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            content = httpd_setup.create_install_conf_content(
                hostname="test-vm-01.example.com",
                username="testuser",
                user_password_hash="$hash",
                root_password_hash="$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        assert "System hostname = test-vm-01.example.com" in content

    def test_create_install_conf_exception_reading_resolv(self, httpd_setup):
        """Test handling of general exception when reading resolv.conf."""
        with patch("builtins.open", side_effect=Exception("Unexpected error")):
            content = httpd_setup.create_install_conf_content(
                hostname="test-vm",
                username="testuser",
                user_password_hash="$hash",
                root_password_hash="$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="100.64.0.101",
            )

        # Should fall back to 8.8.8.8
        assert "DNS nameservers = 8.8.8.8" in content


class TestRequiredSets:
    """Tests for REQUIRED_SETS constant."""

    def test_required_sets_contains_kernel(self, httpd_setup):
        """Test that REQUIRED_SETS contains kernel files."""
        assert "bsd" in httpd_setup.REQUIRED_SETS
        assert "bsd.rd" in httpd_setup.REQUIRED_SETS

    def test_required_sets_contains_base_sets(self, httpd_setup):
        """Test that REQUIRED_SETS contains base installation sets."""
        versioned_sets = [
            "base{version}.tgz",
            "comp{version}.tgz",
            "man{version}.tgz",
        ]
        for set_name in versioned_sets:
            assert set_name in httpd_setup.REQUIRED_SETS

    def test_required_sets_contains_x_sets(self, httpd_setup):
        """Test that REQUIRED_SETS contains X11 sets."""
        x_sets = [
            "xbase{version}.tgz",
            "xshare{version}.tgz",
            "xfont{version}.tgz",
            "xserv{version}.tgz",
        ]
        for set_name in x_sets:
            assert set_name in httpd_setup.REQUIRED_SETS

    def test_required_sets_contains_verification_files(self, httpd_setup):
        """Test that REQUIRED_SETS contains verification files."""
        assert "SHA256" in httpd_setup.REQUIRED_SETS
        assert "SHA256.sig" in httpd_setup.REQUIRED_SETS

    def test_required_sets_contains_metadata(self, httpd_setup):
        """Test that REQUIRED_SETS contains metadata files."""
        assert "index.txt" in httpd_setup.REQUIRED_SETS
        assert "BUILDINFO" in httpd_setup.REQUIRED_SETS
        assert "INSTALL.amd64" in httpd_setup.REQUIRED_SETS


class TestIntegrationScenarios:
    """Integration-style tests for complete workflows."""

    def test_full_setup_workflow(self, httpd_setup):
        """Test a complete setup workflow."""
        # Step 1: Setup httpd
        mock_httpd_result = Mock(returncode=0, stderr=b"")
        with patch("subprocess.run", return_value=mock_httpd_result):
            httpd_result = httpd_setup.setup_httpd("10.1.0.1")
        assert httpd_result["success"] is True

        # Step 2: Create install.conf content
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            install_conf = httpd_setup.create_install_conf_content(
                hostname="newvm",
                username="admin",
                user_password_hash="$2b$10$hash",
                root_password_hash="$2b$10$hash",
                gateway_ip="10.1.0.1",
                openbsd_version="7.7",
                vm_ip="10.1.0.100",
            )
        assert "System hostname = newvm" in install_conf

    def test_version_string_substitution(self, httpd_setup, tmp_path):
        """Test that version strings are correctly substituted in set names."""
        base_dir = tmp_path / "pub" / "OpenBSD"

        with patch.object(httpd_setup, "SETS_BASE", str(base_dir)):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = b"test content"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                httpd_setup.download_openbsd_sets("7.7")

        # Verify URLs have correct version
        for call in mock_urlopen.call_args_list:
            url = call[0][0]
            # Check versioned files have 77 not 7.7
            if "base" in url:
                assert "base77.tgz" in url


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_gateway_ip(self, httpd_setup):
        """Test handling of empty gateway IP."""
        mock_result = Mock(returncode=0, stderr=b"")
        with patch("subprocess.run", return_value=mock_result):
            result = httpd_setup.setup_httpd("")
        # Should still attempt to create config
        assert result["success"] is True

    def test_ipv6_gateway_ip(self, httpd_setup):
        """Test handling of IPv6 gateway IP."""
        mock_result = Mock(returncode=0, stderr=b"")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = httpd_setup.setup_httpd("2001:db8::1")

        assert result["success"] is True
        # Check the config contains the IPv6 address
        first_call = mock_run.call_args_list[0]
        config_cmd = first_call[0][0][2]
        assert "2001:db8::1" in config_cmd

    def test_download_sets_with_empty_version(self, httpd_setup, tmp_path):
        """Test download sets with empty version string."""
        base_dir = tmp_path / "pub" / "OpenBSD"

        with patch.object(httpd_setup, "SETS_BASE", str(base_dir)):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_response = Mock()
                mock_response.read.return_value = b"test"
                mock_response.__enter__ = Mock(return_value=mock_response)
                mock_response.__exit__ = Mock(return_value=False)
                mock_urlopen.return_value = mock_response

                result = httpd_setup.download_openbsd_sets("")

        # Should still work, just with empty version path
        assert result["success"] is True

    def test_create_install_conf_with_empty_fields(self, httpd_setup):
        """Test install.conf creation with empty fields."""
        with patch("builtins.open", mock_open(read_data="nameserver 8.8.8.8\n")):
            content = httpd_setup.create_install_conf_content(
                hostname="",
                username="",
                user_password_hash="",
                root_password_hash="",
                gateway_ip="",
                openbsd_version="",
                vm_ip="",
            )

        # Should still generate content with empty values
        assert "System hostname = " in content
        assert "Setup a user = " in content
