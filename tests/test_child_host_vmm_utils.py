"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm_utils module.
Tests VMM utility functions for VM creation including existence checks,
metadata handling, and hostname parsing.
"""

# pylint: disable=protected-access,redefined-outer-name,attribute-defined-outside-init

import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

from src.sysmanage_agent.operations.child_host_vmm_utils import (
    VMM_DISK_DIR,
    VMM_METADATA_DIR,
    ensure_vmm_directories,
    extract_openbsd_version,
    get_fqdn_hostname,
    save_vm_metadata,
    vm_exists,
)


class TestVmExists:
    """Tests for vm_exists function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_vm_exists_metadata_file_found(self):
        """Test VM exists when metadata file is found."""
        with patch.object(Path, "exists", return_value=True):
            result = vm_exists("test-vm", self.mock_logger)

        assert result is True
        self.mock_logger.info.assert_called()

    def test_vm_exists_metadata_file_not_found_check_vmconf(self):
        """Test VM check falls through to vm.conf when metadata not found."""
        vm_conf_content = 'vm "test-vm" {\n    memory 512M\n}'

        with patch.object(Path, "exists", return_value=False):
            with patch(
                "builtins.open", mock_open(read_data=vm_conf_content)
            ) as mock_file:
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is True
        mock_file.assert_called_once_with("/etc/vm.conf", "r", encoding="utf-8")

    def test_vm_exists_not_in_vmconf(self):
        """Test VM not found in vm.conf."""
        vm_conf_content = 'vm "other-vm" {\n    memory 512M\n}'

        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", mock_open(read_data=vm_conf_content)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False

    def test_vm_exists_vmconf_file_not_found(self):
        """Test VM check when /etc/vm.conf doesn't exist."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False
        # Check that appropriate log message was generated
        log_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("vm.conf doesn't exist" in str(call) for call in log_calls)

    def test_vm_exists_vmconf_read_error(self):
        """Test VM check when there's an error reading vm.conf."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=PermissionError("Access denied")):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False
        self.mock_logger.warning.assert_called()

    def test_vm_exists_vmctl_status_found(self):
        """Test VM found via vmctl status."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(
                        returncode=0, stdout="1  test-vm  512M  running"
                    )
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is True
        mock_run.assert_called_once_with(
            ["vmctl", "status", "test-vm"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_vm_exists_vmctl_status_not_found(self):
        """Test VM not found in vmctl status."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False

    def test_vm_exists_vmctl_status_nonzero_returncode(self):
        """Test VM check when vmctl returns non-zero but VM name in output."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    # Non-zero return code means VM not found
                    mock_run.return_value = Mock(returncode=1, stdout="test-vm")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False

    def test_vm_exists_vmctl_file_not_found(self):
        """Test VM check when vmctl command is not found."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = FileNotFoundError("vmctl not found")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False
        self.mock_logger.warning.assert_called()

    def test_vm_exists_vmctl_timeout(self):
        """Test VM check when vmctl times out."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = subprocess.TimeoutExpired(
                        cmd="vmctl", timeout=5
                    )
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False
        self.mock_logger.warning.assert_called()


class TestExtractOpenbsdVersion:
    """Tests for extract_openbsd_version function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_extract_version_standard_format(self):
        """Test extracting version from standard format."""
        result = extract_openbsd_version("OpenBSD 7.7", self.mock_logger)
        assert result == "7.7"

    def test_extract_version_with_extra_text(self):
        """Test extracting version with extra text."""
        result = extract_openbsd_version(
            "OpenBSD 7.5 (GENERIC) amd64", self.mock_logger
        )
        assert result == "7.5"

    def test_extract_version_older_version(self):
        """Test extracting older version number."""
        result = extract_openbsd_version("OpenBSD 6.9", self.mock_logger)
        assert result == "6.9"

    def test_extract_version_no_match(self):
        """Test extracting version when no version number found."""
        result = extract_openbsd_version("OpenBSD", self.mock_logger)
        assert result is None

    def test_extract_version_empty_string(self):
        """Test extracting version from empty string."""
        result = extract_openbsd_version("", self.mock_logger)
        assert result is None

    def test_extract_version_invalid_format(self):
        """Test extracting version from invalid format."""
        result = extract_openbsd_version("Not a version string", self.mock_logger)
        assert result is None

    def test_extract_version_exception_handling(self):
        """Test version extraction with exception during regex."""
        # Force an exception by passing something that would cause regex issues
        with patch("re.search", side_effect=Exception("Regex error")):
            result = extract_openbsd_version("OpenBSD 7.7", self.mock_logger)

        assert result is None
        self.mock_logger.error.assert_called()


class TestGetFqdnHostname:
    """Tests for get_fqdn_hostname function."""

    def test_hostname_already_fqdn(self):
        """Test when hostname is already FQDN."""
        result = get_fqdn_hostname("vm01.example.com", "https://sysmanage.example.com")
        assert result == "vm01.example.com"

    def test_short_hostname_with_server_url(self):
        """Test deriving FQDN from server URL for short hostname."""
        result = get_fqdn_hostname("vm01", "https://sysmanage.example.com")
        assert result == "vm01.example.com"

    def test_short_hostname_with_subdomain_server(self):
        """Test deriving FQDN from server URL with subdomain."""
        result = get_fqdn_hostname("vm01", "https://sysmanage.sub.example.com")
        assert result == "vm01.example.com"

    def test_short_hostname_with_port(self):
        """Test deriving FQDN from server URL with port."""
        result = get_fqdn_hostname("vm01", "https://sysmanage.example.com:8443")
        assert result == "vm01.example.com"

    def test_short_hostname_with_path(self):
        """Test deriving FQDN from server URL with path."""
        result = get_fqdn_hostname("vm01", "https://sysmanage.example.com/api")
        assert result == "vm01.example.com"

    def test_short_hostname_server_no_domain(self):
        """Test short hostname when server URL has no domain."""
        result = get_fqdn_hostname("vm01", "https://localhost:8443")
        # Should return original hostname since server has no proper domain
        assert result == "vm01"

    def test_short_hostname_invalid_url(self):
        """Test short hostname with invalid server URL."""
        result = get_fqdn_hostname("vm01", "not-a-valid-url")
        # Should return original hostname on parsing failure
        assert result == "vm01"

    def test_short_hostname_empty_server_url(self):
        """Test short hostname with empty server URL."""
        result = get_fqdn_hostname("vm01", "")
        assert result == "vm01"

    def test_hostname_with_single_dot(self):
        """Test hostname that has a dot (considered FQDN)."""
        result = get_fqdn_hostname("vm01.internal", "https://sysmanage.example.com")
        assert result == "vm01.internal"

    def test_http_server_url(self):
        """Test with HTTP (not HTTPS) server URL."""
        result = get_fqdn_hostname("vm01", "http://sysmanage.example.com")
        assert result == "vm01.example.com"

    def test_exception_during_url_parsing(self):
        """Test that exceptions during URL parsing are handled gracefully."""
        with patch(
            "src.sysmanage_agent.operations.child_host_vmm_utils.urlparse",
            side_effect=Exception("Parse error"),
        ):
            result = get_fqdn_hostname("vm01", "https://sysmanage.example.com")

        # Should return original hostname on exception
        assert result == "vm01"


class TestEnsureVmmDirectories:
    """Tests for ensure_vmm_directories function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_directory_already_exists(self):
        """Test when VMM directory already exists."""
        with patch("os.path.exists", return_value=True):
            with patch("os.makedirs") as mock_makedirs:
                ensure_vmm_directories(self.mock_logger)

        mock_makedirs.assert_not_called()

    def test_create_directory(self):
        """Test creating VMM directory when it doesn't exist."""
        with patch("os.path.exists", return_value=False):
            with patch("os.makedirs") as mock_makedirs:
                ensure_vmm_directories(self.mock_logger)

        mock_makedirs.assert_called_once_with(VMM_DISK_DIR, mode=0o755)
        self.mock_logger.info.assert_called()

    def test_vmm_disk_dir_constant(self):
        """Test that VMM_DISK_DIR is correctly defined."""
        assert VMM_DISK_DIR == "/var/vmm"

    def test_vmm_metadata_dir_constant(self):
        """Test that VMM_METADATA_DIR is correctly defined."""
        assert VMM_METADATA_DIR == "/var/vmm/metadata"


class TestSaveVmMetadata:
    """Tests for save_vm_metadata function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_save_metadata_success(self):
        """Test successfully saving VM metadata."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_utils.VMM_METADATA_DIR",
                temp_dir,
            ):
                result = save_vm_metadata(
                    vm_name="test-vm",
                    hostname="test-vm.example.com",
                    distribution="OpenBSD 7.7",
                    openbsd_version="7.7",
                    vm_ip="192.168.1.100",
                    logger=self.mock_logger,
                )

                assert result is True
                self.mock_logger.info.assert_called()

                # Verify file contents
                metadata_file = Path(temp_dir) / "test-vm.json"
                assert metadata_file.exists()

                with open(metadata_file, "r", encoding="utf-8") as file_handle:
                    metadata = json.load(file_handle)

                assert metadata["vm_name"] == "test-vm"
                assert metadata["hostname"] == "test-vm.example.com"
                assert metadata["vm_ip"] == "192.168.1.100"
                assert metadata["distribution"]["distribution_name"] == "OpenBSD"
                assert metadata["distribution"]["distribution_version"] == "7.7"
                assert metadata["distribution_string"] == "OpenBSD 7.7"

    def test_save_metadata_creates_directory(self):
        """Test that save_vm_metadata creates the metadata directory."""
        with tempfile.TemporaryDirectory() as temp_base:
            metadata_dir = os.path.join(temp_base, "metadata")
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_utils.VMM_METADATA_DIR",
                metadata_dir,
            ):
                result = save_vm_metadata(
                    vm_name="test-vm",
                    hostname="test-vm.example.com",
                    distribution="OpenBSD 7.7",
                    openbsd_version="7.7",
                    vm_ip="192.168.1.100",
                    logger=self.mock_logger,
                )

                assert result is True
                assert os.path.isdir(metadata_dir)

    def test_save_metadata_overwrite_existing(self):
        """Test overwriting existing metadata file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_utils.VMM_METADATA_DIR",
                temp_dir,
            ):
                # Create initial metadata
                save_vm_metadata(
                    vm_name="test-vm",
                    hostname="old-hostname.example.com",
                    distribution="OpenBSD 7.5",
                    openbsd_version="7.5",
                    vm_ip="192.168.1.50",
                    logger=self.mock_logger,
                )

                # Overwrite with new metadata
                result = save_vm_metadata(
                    vm_name="test-vm",
                    hostname="new-hostname.example.com",
                    distribution="OpenBSD 7.7",
                    openbsd_version="7.7",
                    vm_ip="192.168.1.100",
                    logger=self.mock_logger,
                )

                assert result is True

                # Verify new contents
                metadata_file = Path(temp_dir) / "test-vm.json"
                with open(metadata_file, "r", encoding="utf-8") as file_handle:
                    metadata = json.load(file_handle)

                assert metadata["hostname"] == "new-hostname.example.com"
                assert metadata["vm_ip"] == "192.168.1.100"
                assert metadata["distribution"]["distribution_version"] == "7.7"

    def test_save_metadata_permission_error(self):
        """Test saving metadata with permission error."""
        with patch("pathlib.Path.mkdir", side_effect=PermissionError("Access denied")):
            result = save_vm_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="OpenBSD 7.7",
                openbsd_version="7.7",
                vm_ip="192.168.1.100",
                logger=self.mock_logger,
            )

        assert result is False
        self.mock_logger.error.assert_called()

    def test_save_metadata_write_error(self):
        """Test saving metadata with write error."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_utils.VMM_METADATA_DIR",
                temp_dir,
            ):
                with patch("builtins.open", side_effect=IOError("Write error")):
                    result = save_vm_metadata(
                        vm_name="test-vm",
                        hostname="test-vm.example.com",
                        distribution="OpenBSD 7.7",
                        openbsd_version="7.7",
                        vm_ip="192.168.1.100",
                        logger=self.mock_logger,
                    )

        assert result is False
        self.mock_logger.error.assert_called()

    def test_save_metadata_special_characters_in_name(self):
        """Test saving metadata with special characters in VM name."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_utils.VMM_METADATA_DIR",
                temp_dir,
            ):
                result = save_vm_metadata(
                    vm_name="test-vm_01",
                    hostname="test-vm-01.example.com",
                    distribution="OpenBSD 7.7",
                    openbsd_version="7.7",
                    vm_ip="192.168.1.100",
                    logger=self.mock_logger,
                )

                assert result is True

                metadata_file = Path(temp_dir) / "test-vm_01.json"
                assert metadata_file.exists()


class TestVmExistsIntegration:
    """Integration-style tests for vm_exists function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_vm_exists_checks_all_sources(self):
        """Test that vm_exists checks all sources in order."""
        call_order = []

        def mock_path_exists(_self_path):
            call_order.append("metadata")
            return False

        original_open = open

        def mock_open_vmconf(*args, **kwargs):
            if args[0] == "/etc/vm.conf":
                call_order.append("vmconf")
                raise FileNotFoundError()
            return original_open(*args, **kwargs)

        def mock_subprocess_run(*_args, **_kwargs):
            call_order.append("vmctl")
            return Mock(returncode=0, stdout="")

        with patch.object(Path, "exists", mock_path_exists):
            with patch("builtins.open", side_effect=mock_open_vmconf):
                with patch("subprocess.run", side_effect=mock_subprocess_run):
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is False
        assert call_order == ["metadata", "vmconf", "vmctl"]

    def test_vm_exists_stops_on_first_match(self):
        """Test that vm_exists stops checking when VM is found."""
        with patch.object(Path, "exists", return_value=True):
            with patch("builtins.open") as mock_open_call:
                with patch("subprocess.run") as mock_run:
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is True
        # Should not have checked vm.conf or vmctl
        mock_open_call.assert_not_called()
        mock_run.assert_not_called()


class TestVmExistsLogging:
    """Tests for logging behavior in vm_exists function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_logging_when_vm_found_via_metadata(self):
        """Test logging messages when VM found via metadata."""
        with patch.object(Path, "exists", return_value=True):
            vm_exists("test-vm", self.mock_logger)

        # Check for specific log messages
        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("VM_EXISTS_CHECK" in str(call) for call in info_calls)
        assert any("metadata file found" in str(call) for call in info_calls)

    def test_logging_when_vm_not_found(self):
        """Test logging messages when VM not found."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    vm_exists("test-vm", self.mock_logger)

        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("does NOT exist" in str(call) for call in info_calls)

    def test_logging_vmctl_returncode(self):
        """Test that vmctl returncode is logged."""
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=1, stdout="error")
                    vm_exists("test-vm", self.mock_logger)

        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("returncode" in str(call) for call in info_calls)


class TestEdgeCases:
    """Edge case tests for VMM utils functions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()

    def test_vm_name_with_quotes(self):
        """Test VM name that contains quotes."""
        vm_conf_content = 'vm "vm-with-quote\\"s" {\n    memory 512M\n}'

        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", mock_open(read_data=vm_conf_content)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    # This VM name shouldn't match
                    result = vm_exists("vm-with-quotes", self.mock_logger)

        assert result is False

    def test_empty_vm_name(self):
        """Test with empty VM name.

        Note: The code checks if empty string is in vm.conf content.
        Since 'vm ""' pattern would match in an empty config, the behavior
        is to return True when the pattern is found.
        """
        # Empty VM name with vm.conf that has 'vm ""' pattern
        vm_conf_content = 'vm "" {\n    memory 512M\n}'
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", mock_open(read_data=vm_conf_content)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("", self.mock_logger)

        # Found 'vm ""' in config
        assert result is True

    def test_empty_vm_name_not_in_vmconf(self):
        """Test with empty VM name not found in vm.conf but found via vmctl.

        Note: Empty string is always contained in any string, so even when
        'vm ""' is not in vm.conf, the vmctl check will return True because
        empty string is "in" the vmctl stdout.
        """
        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", mock_open(read_data="other content")):
                with patch("subprocess.run") as mock_run:
                    # Even with returncode 0 and empty stdout,
                    # "" in "" is True
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("", self.mock_logger)

        # Empty string is always in any string, so vmctl check passes
        assert result is True

    def test_version_extraction_multiple_versions(self):
        """Test version extraction when string has multiple version patterns."""
        result = extract_openbsd_version("OpenBSD 7.7 kernel 7.5", self.mock_logger)
        # Should return first match
        assert result == "7.7"

    def test_fqdn_with_many_subdomains(self):
        """Test FQDN derivation with many subdomains in server URL."""
        result = get_fqdn_hostname(
            "vm01", "https://sysmanage.sub1.sub2.sub3.example.com"
        )
        # Should use last two parts as domain
        assert result == "vm01.example.com"

    def test_version_with_leading_zeros(self):
        """Test version extraction with leading zeros."""
        result = extract_openbsd_version("OpenBSD 07.07", self.mock_logger)
        assert result == "07.07"

    def test_save_metadata_empty_strings(self):
        """Test saving metadata with empty string values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_utils.VMM_METADATA_DIR",
                temp_dir,
            ):
                result = save_vm_metadata(
                    vm_name="test-vm",
                    hostname="",
                    distribution="",
                    openbsd_version="",
                    vm_ip="",
                    logger=self.mock_logger,
                )

                assert result is True

                metadata_file = Path(temp_dir) / "test-vm.json"
                with open(metadata_file, "r", encoding="utf-8") as file_handle:
                    metadata = json.load(file_handle)

                assert metadata["hostname"] == ""
                assert metadata["vm_ip"] == ""

    def test_vm_exists_vmconf_unicode_content(self):
        """Test vm.conf with unicode content."""
        vm_conf_content = 'vm "test-vm" {\n    # Comment with unicode: \u00e9\n}'

        with patch.object(Path, "exists", return_value=False):
            with patch("builtins.open", mock_open(read_data=vm_conf_content)):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="")
                    result = vm_exists("test-vm", self.mock_logger)

        assert result is True

    def test_get_fqdn_hostname_ip_address_server(self):
        """Test FQDN derivation when server URL uses IP address.

        Note: The code treats IP addresses like hostnames and extracts
        the last two parts. For '192.168.1.1', it takes '1.1' as domain.
        This is the actual behavior of the code.
        """
        result = get_fqdn_hostname("vm01", "https://192.168.1.1:8443")
        # The code extracts last two parts of IP as "domain"
        assert result == "vm01.1.1"

    def test_get_fqdn_hostname_single_part_server(self):
        """Test FQDN derivation when server has single-part hostname."""
        result = get_fqdn_hostname("vm01", "https://localhost:8443")
        # No domain derivable from single-part hostname
        assert result == "vm01"
