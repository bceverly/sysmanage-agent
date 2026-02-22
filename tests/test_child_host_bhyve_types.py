"""
Comprehensive unit tests for bhyve VM type definitions.

Tests cover:
- BhyveVmConfig dataclass initialization and validation
- Required field validation
- Memory format parsing and validation
- Disk size format parsing and validation
- CPU count validation
- Helper methods for memory and disk size conversion
"""

# pylint: disable=redefined-outer-name,protected-access

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig


@pytest.fixture
def valid_config_kwargs():
    """Provide valid kwargs for creating a BhyveVmConfig."""
    return {
        "distribution": "ubuntu",
        "vm_name": "test-vm",
        "hostname": "test-hostname",
        "username": "testuser",
        "password_hash": "$6$rounds=4096$somesalt$somehash",
        "server_url": "https://sysmanage.example.com",
        "agent_install_commands": ["apt-get update", "apt-get install -y agent"],
    }


@pytest.fixture
def sample_vm_config(valid_config_kwargs):
    """Create a sample BhyveVmConfig for testing."""
    return BhyveVmConfig(**valid_config_kwargs)


class TestBhyveVmConfigInit:
    """Tests for BhyveVmConfig initialization with valid parameters."""

    def test_init_with_required_fields_only(self, valid_config_kwargs):
        """Test initialization with only required fields."""
        config = BhyveVmConfig(**valid_config_kwargs)

        assert config.distribution == "ubuntu"
        assert config.vm_name == "test-vm"
        assert config.hostname == "test-hostname"
        assert config.username == "testuser"
        assert config.password_hash == "$6$rounds=4096$somesalt$somehash"
        assert config.server_url == "https://sysmanage.example.com"
        assert config.agent_install_commands == [
            "apt-get update",
            "apt-get install -y agent",
        ]

    def test_init_default_values(self, sample_vm_config):
        """Test default values are set correctly."""
        assert sample_vm_config.memory == "1G"
        assert sample_vm_config.disk_size == "20G"
        assert sample_vm_config.cpus == 1
        assert sample_vm_config.server_port == 8443
        assert sample_vm_config.use_https is True
        assert sample_vm_config.cloud_image_url == ""
        assert sample_vm_config.iso_url == ""
        assert sample_vm_config.use_cloud_init is True
        assert sample_vm_config.use_uefi is True
        assert sample_vm_config.auto_approve_token is None
        assert sample_vm_config.child_host_id is None
        assert sample_vm_config.vm_dir == "/vm"
        assert sample_vm_config.zvol_parent == "zroot/vm"
        assert sample_vm_config.use_zvol is False

    def test_init_computed_paths_empty(self, sample_vm_config):
        """Test computed paths are initialized to empty strings."""
        assert sample_vm_config.disk_path == ""
        assert sample_vm_config.cloud_init_iso_path == ""
        assert sample_vm_config.cloud_image_path == ""

    def test_init_with_custom_memory(self, valid_config_kwargs):
        """Test initialization with custom memory."""
        valid_config_kwargs["memory"] = "4G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "4G"

    def test_init_with_custom_disk_size(self, valid_config_kwargs):
        """Test initialization with custom disk size."""
        valid_config_kwargs["disk_size"] = "100G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "100G"

    def test_init_with_custom_cpus(self, valid_config_kwargs):
        """Test initialization with custom CPU count."""
        valid_config_kwargs["cpus"] = 8
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.cpus == 8

    def test_init_with_cloud_image_url(self, valid_config_kwargs):
        """Test initialization with cloud image URL."""
        valid_config_kwargs["cloud_image_url"] = "https://example.com/image.qcow2"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.cloud_image_url == "https://example.com/image.qcow2"

    def test_init_with_iso_url(self, valid_config_kwargs):
        """Test initialization with ISO URL."""
        valid_config_kwargs["iso_url"] = "https://example.com/install.iso"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.iso_url == "https://example.com/install.iso"

    def test_init_with_uefi_disabled(self, valid_config_kwargs):
        """Test initialization with UEFI disabled."""
        valid_config_kwargs["use_uefi"] = False
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.use_uefi is False

    def test_init_with_cloud_init_disabled(self, valid_config_kwargs):
        """Test initialization with cloud-init disabled."""
        valid_config_kwargs["use_cloud_init"] = False
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.use_cloud_init is False

    def test_init_with_auto_approve_token(self, valid_config_kwargs):
        """Test initialization with auto-approve token."""
        valid_config_kwargs["auto_approve_token"] = "secret-token-123"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.auto_approve_token == "secret-token-123"

    def test_init_with_child_host_id(self, valid_config_kwargs):
        """Test initialization with child host ID."""
        valid_config_kwargs["child_host_id"] = "host-uuid-456"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.child_host_id == "host-uuid-456"

    def test_init_with_zvol_settings(self, valid_config_kwargs):
        """Test initialization with ZFS zvol settings."""
        valid_config_kwargs["use_zvol"] = True
        valid_config_kwargs["zvol_parent"] = "tank/bhyve"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.use_zvol is True
        assert config.zvol_parent == "tank/bhyve"

    def test_init_with_custom_vm_dir(self, valid_config_kwargs):
        """Test initialization with custom VM directory."""
        valid_config_kwargs["vm_dir"] = "/data/vms"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.vm_dir == "/data/vms"


class TestBhyveVmConfigRequiredFieldValidation:
    """Tests for required field validation in __post_init__."""

    def test_missing_vm_name_raises_error(self, valid_config_kwargs):
        """Test that missing VM name raises ValueError."""
        valid_config_kwargs["vm_name"] = ""
        with pytest.raises(ValueError, match="VM name is required"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_missing_hostname_raises_error(self, valid_config_kwargs):
        """Test that missing hostname raises ValueError."""
        valid_config_kwargs["hostname"] = ""
        with pytest.raises(ValueError, match="Hostname is required"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_missing_username_raises_error(self, valid_config_kwargs):
        """Test that missing username raises ValueError."""
        valid_config_kwargs["username"] = ""
        with pytest.raises(ValueError, match="Username is required"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_missing_password_hash_raises_error(self, valid_config_kwargs):
        """Test that missing password hash raises ValueError."""
        valid_config_kwargs["password_hash"] = ""
        with pytest.raises(ValueError, match="Password hash is required"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_missing_distribution_raises_error(self, valid_config_kwargs):
        """Test that missing distribution raises ValueError."""
        valid_config_kwargs["distribution"] = ""
        with pytest.raises(ValueError, match="Distribution is required"):
            BhyveVmConfig(**valid_config_kwargs)


class TestBhyveVmConfigMemoryValidation:
    """Tests for memory format validation."""

    def test_valid_memory_gigabytes_g_suffix(self, valid_config_kwargs):
        """Test valid memory with G suffix."""
        valid_config_kwargs["memory"] = "2G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "2G"

    def test_valid_memory_gigabytes_gb_suffix(self, valid_config_kwargs):
        """Test valid memory with GB suffix."""
        valid_config_kwargs["memory"] = "4GB"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "4GB"

    def test_valid_memory_megabytes_m_suffix(self, valid_config_kwargs):
        """Test valid memory with M suffix."""
        valid_config_kwargs["memory"] = "2048M"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "2048M"

    def test_valid_memory_megabytes_mb_suffix(self, valid_config_kwargs):
        """Test valid memory with MB suffix."""
        valid_config_kwargs["memory"] = "4096MB"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "4096MB"

    def test_valid_memory_no_suffix(self, valid_config_kwargs):
        """Test valid memory without suffix (assumed MB)."""
        valid_config_kwargs["memory"] = "1024"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "1024"

    def test_valid_memory_lowercase(self, valid_config_kwargs):
        """Test valid memory with lowercase suffix."""
        valid_config_kwargs["memory"] = "2g"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "2g"

    def test_valid_memory_with_spaces(self, valid_config_kwargs):
        """Test valid memory with surrounding spaces."""
        valid_config_kwargs["memory"] = " 2G "
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == " 2G "

    def test_valid_memory_fractional_gigabytes(self, valid_config_kwargs):
        """Test valid fractional memory (e.g., 1.5G)."""
        valid_config_kwargs["memory"] = "1.5G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.memory == "1.5G"

    def test_invalid_memory_format_raises_error(self, valid_config_kwargs):
        """Test that invalid memory format raises ValueError."""
        valid_config_kwargs["memory"] = "invalid"
        with pytest.raises(ValueError, match="Invalid memory format: invalid"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_invalid_memory_empty_string_raises_error(self, valid_config_kwargs):
        """Test that empty memory string raises ValueError."""
        valid_config_kwargs["memory"] = ""
        with pytest.raises(ValueError, match="Invalid memory format:"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_negative_memory_parses_to_negative_value(self, valid_config_kwargs):
        """Test that negative memory values parse to negative MB values.

        Note: The parser does not validate against negative values,
        it just converts the numeric portion. This is acceptable
        because negative values would be caught by other validation.
        """
        valid_config_kwargs["memory"] = "-1G"
        config = BhyveVmConfig(**valid_config_kwargs)
        # -1G parses to -1024 MB
        assert config.get_memory_mb() == -1024

    def test_invalid_memory_text_with_suffix_raises_error(self, valid_config_kwargs):
        """Test that text followed by suffix raises ValueError."""
        valid_config_kwargs["memory"] = "abcG"
        with pytest.raises(ValueError, match="Invalid memory format: abcG"):
            BhyveVmConfig(**valid_config_kwargs)


class TestBhyveVmConfigDiskSizeValidation:
    """Tests for disk size format validation."""

    def test_valid_disk_size_gigabytes_g_suffix(self, valid_config_kwargs):
        """Test valid disk size with G suffix."""
        valid_config_kwargs["disk_size"] = "50G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "50G"

    def test_valid_disk_size_gigabytes_gb_suffix(self, valid_config_kwargs):
        """Test valid disk size with GB suffix."""
        valid_config_kwargs["disk_size"] = "100GB"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "100GB"

    def test_valid_disk_size_terabytes_t_suffix(self, valid_config_kwargs):
        """Test valid disk size with T suffix."""
        valid_config_kwargs["disk_size"] = "1T"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "1T"

    def test_valid_disk_size_terabytes_tb_suffix(self, valid_config_kwargs):
        """Test valid disk size with TB suffix."""
        valid_config_kwargs["disk_size"] = "2TB"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "2TB"

    def test_valid_disk_size_no_suffix(self, valid_config_kwargs):
        """Test valid disk size without suffix (assumed GB)."""
        valid_config_kwargs["disk_size"] = "50"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "50"

    def test_valid_disk_size_lowercase(self, valid_config_kwargs):
        """Test valid disk size with lowercase suffix."""
        valid_config_kwargs["disk_size"] = "50g"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "50g"

    def test_valid_disk_size_with_spaces(self, valid_config_kwargs):
        """Test valid disk size with surrounding spaces."""
        valid_config_kwargs["disk_size"] = " 50G "
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == " 50G "

    def test_valid_disk_size_fractional_terabytes(self, valid_config_kwargs):
        """Test valid fractional disk size (e.g., 0.5T)."""
        valid_config_kwargs["disk_size"] = "0.5T"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.disk_size == "0.5T"

    def test_invalid_disk_size_format_raises_error(self, valid_config_kwargs):
        """Test that invalid disk size format raises ValueError."""
        valid_config_kwargs["disk_size"] = "invalid"
        with pytest.raises(ValueError, match="Invalid disk size format: invalid"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_invalid_disk_size_empty_string_raises_error(self, valid_config_kwargs):
        """Test that empty disk size string raises ValueError."""
        valid_config_kwargs["disk_size"] = ""
        with pytest.raises(ValueError, match="Invalid disk size format:"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_invalid_disk_size_text_with_suffix_raises_error(self, valid_config_kwargs):
        """Test that text followed by suffix raises ValueError."""
        valid_config_kwargs["disk_size"] = "xyzG"
        with pytest.raises(ValueError, match="Invalid disk size format: xyzG"):
            BhyveVmConfig(**valid_config_kwargs)


class TestBhyveVmConfigCpuValidation:
    """Tests for CPU count validation."""

    def test_valid_cpu_count_minimum(self, valid_config_kwargs):
        """Test valid minimum CPU count of 1."""
        valid_config_kwargs["cpus"] = 1
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.cpus == 1

    def test_valid_cpu_count_maximum(self, valid_config_kwargs):
        """Test valid maximum CPU count of 64."""
        valid_config_kwargs["cpus"] = 64
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.cpus == 64

    def test_valid_cpu_count_middle(self, valid_config_kwargs):
        """Test valid CPU count in middle of range."""
        valid_config_kwargs["cpus"] = 16
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.cpus == 16

    def test_invalid_cpu_count_zero_raises_error(self, valid_config_kwargs):
        """Test that zero CPUs raises ValueError."""
        valid_config_kwargs["cpus"] = 0
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_invalid_cpu_count_negative_raises_error(self, valid_config_kwargs):
        """Test that negative CPUs raises ValueError."""
        valid_config_kwargs["cpus"] = -1
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_invalid_cpu_count_exceeds_maximum_raises_error(self, valid_config_kwargs):
        """Test that CPUs exceeding 64 raises ValueError."""
        valid_config_kwargs["cpus"] = 65
        with pytest.raises(ValueError, match="CPUs cannot exceed 64"):
            BhyveVmConfig(**valid_config_kwargs)

    def test_invalid_cpu_count_very_large_raises_error(self, valid_config_kwargs):
        """Test that very large CPU count raises ValueError."""
        valid_config_kwargs["cpus"] = 1000
        with pytest.raises(ValueError, match="CPUs cannot exceed 64"):
            BhyveVmConfig(**valid_config_kwargs)


class TestParseMemoryMb:
    """Tests for _parse_memory_mb method."""

    def test_parse_memory_mb_with_g_suffix(self, sample_vm_config):
        """Test parsing memory with G suffix."""
        result = sample_vm_config._parse_memory_mb("2G")
        assert result == 2048

    def test_parse_memory_mb_with_gb_suffix(self, sample_vm_config):
        """Test parsing memory with GB suffix."""
        result = sample_vm_config._parse_memory_mb("4GB")
        assert result == 4096

    def test_parse_memory_mb_with_m_suffix(self, sample_vm_config):
        """Test parsing memory with M suffix."""
        result = sample_vm_config._parse_memory_mb("512M")
        assert result == 512

    def test_parse_memory_mb_with_mb_suffix(self, sample_vm_config):
        """Test parsing memory with MB suffix."""
        result = sample_vm_config._parse_memory_mb("1024MB")
        assert result == 1024

    def test_parse_memory_mb_no_suffix(self, sample_vm_config):
        """Test parsing memory without suffix (assumed MB)."""
        result = sample_vm_config._parse_memory_mb("256")
        assert result == 256

    def test_parse_memory_mb_lowercase(self, sample_vm_config):
        """Test parsing memory with lowercase suffix."""
        result = sample_vm_config._parse_memory_mb("2g")
        assert result == 2048

    def test_parse_memory_mb_with_whitespace(self, sample_vm_config):
        """Test parsing memory with surrounding whitespace."""
        result = sample_vm_config._parse_memory_mb("  2G  ")
        assert result == 2048

    def test_parse_memory_mb_fractional(self, sample_vm_config):
        """Test parsing fractional memory (e.g., 1.5G)."""
        result = sample_vm_config._parse_memory_mb("1.5G")
        assert result == 1536  # 1.5 * 1024

    def test_parse_memory_mb_invalid_string_returns_zero(self, sample_vm_config):
        """Test that invalid string returns 0."""
        result = sample_vm_config._parse_memory_mb("invalid")
        assert result == 0

    def test_parse_memory_mb_empty_string_returns_zero(self, sample_vm_config):
        """Test that empty string returns 0."""
        result = sample_vm_config._parse_memory_mb("")
        assert result == 0

    def test_parse_memory_mb_none_raises_error(self, sample_vm_config):
        """Test that None raises AttributeError.

        Note: The method expects a string input. Passing None will
        raise an AttributeError when trying to call .upper() on None.
        """
        with pytest.raises(AttributeError):
            sample_vm_config._parse_memory_mb(None)

    def test_parse_memory_mb_mixed_case(self, sample_vm_config):
        """Test parsing memory with mixed case suffix."""
        result = sample_vm_config._parse_memory_mb("2Gb")
        assert result == 2048


class TestParseDiskGb:
    """Tests for _parse_disk_gb method."""

    def test_parse_disk_gb_with_g_suffix(self, sample_vm_config):
        """Test parsing disk size with G suffix."""
        result = sample_vm_config._parse_disk_gb("50G")
        assert result == 50

    def test_parse_disk_gb_with_gb_suffix(self, sample_vm_config):
        """Test parsing disk size with GB suffix."""
        result = sample_vm_config._parse_disk_gb("100GB")
        assert result == 100

    def test_parse_disk_gb_with_t_suffix(self, sample_vm_config):
        """Test parsing disk size with T suffix."""
        result = sample_vm_config._parse_disk_gb("1T")
        assert result == 1024

    def test_parse_disk_gb_with_tb_suffix(self, sample_vm_config):
        """Test parsing disk size with TB suffix."""
        result = sample_vm_config._parse_disk_gb("2TB")
        assert result == 2048

    def test_parse_disk_gb_no_suffix(self, sample_vm_config):
        """Test parsing disk size without suffix (assumed GB)."""
        result = sample_vm_config._parse_disk_gb("50")
        assert result == 50

    def test_parse_disk_gb_lowercase(self, sample_vm_config):
        """Test parsing disk size with lowercase suffix."""
        result = sample_vm_config._parse_disk_gb("50g")
        assert result == 50

    def test_parse_disk_gb_with_whitespace(self, sample_vm_config):
        """Test parsing disk size with surrounding whitespace."""
        result = sample_vm_config._parse_disk_gb("  50G  ")
        assert result == 50

    def test_parse_disk_gb_fractional_terabytes(self, sample_vm_config):
        """Test parsing fractional terabytes (e.g., 0.5T)."""
        result = sample_vm_config._parse_disk_gb("0.5T")
        assert result == 512  # 0.5 * 1024

    def test_parse_disk_gb_invalid_string_returns_zero(self, sample_vm_config):
        """Test that invalid string returns 0."""
        result = sample_vm_config._parse_disk_gb("invalid")
        assert result == 0

    def test_parse_disk_gb_empty_string_returns_zero(self, sample_vm_config):
        """Test that empty string returns 0."""
        result = sample_vm_config._parse_disk_gb("")
        assert result == 0

    def test_parse_disk_gb_none_raises_error(self, sample_vm_config):
        """Test that None raises AttributeError.

        Note: The method expects a string input. Passing None will
        raise an AttributeError when trying to call .upper() on None.
        """
        with pytest.raises(AttributeError):
            sample_vm_config._parse_disk_gb(None)

    def test_parse_disk_gb_mixed_case(self, sample_vm_config):
        """Test parsing disk size with mixed case suffix."""
        result = sample_vm_config._parse_disk_gb("1Tb")
        assert result == 1024


class TestGetMemoryMb:
    """Tests for get_memory_mb method."""

    def test_get_memory_mb_default(self, sample_vm_config):
        """Test get_memory_mb with default memory (1G)."""
        result = sample_vm_config.get_memory_mb()
        assert result == 1024

    def test_get_memory_mb_custom(self, valid_config_kwargs):
        """Test get_memory_mb with custom memory."""
        valid_config_kwargs["memory"] = "4G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_memory_mb() == 4096

    def test_get_memory_mb_megabytes(self, valid_config_kwargs):
        """Test get_memory_mb with megabyte input."""
        valid_config_kwargs["memory"] = "2048M"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_memory_mb() == 2048


class TestGetMemoryGb:
    """Tests for get_memory_gb method."""

    def test_get_memory_gb_default(self, sample_vm_config):
        """Test get_memory_gb with default memory (1G)."""
        result = sample_vm_config.get_memory_gb()
        assert result == 1.0

    def test_get_memory_gb_custom(self, valid_config_kwargs):
        """Test get_memory_gb with custom memory."""
        valid_config_kwargs["memory"] = "4G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_memory_gb() == 4.0

    def test_get_memory_gb_fractional(self, valid_config_kwargs):
        """Test get_memory_gb with memory that results in fractional GB."""
        valid_config_kwargs["memory"] = "512M"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_memory_gb() == 0.5

    def test_get_memory_gb_returns_float(self, sample_vm_config):
        """Test that get_memory_gb returns a float."""
        result = sample_vm_config.get_memory_gb()
        assert isinstance(result, float)


class TestGetDiskGb:
    """Tests for get_disk_gb method."""

    def test_get_disk_gb_default(self, sample_vm_config):
        """Test get_disk_gb with default disk size (20G)."""
        result = sample_vm_config.get_disk_gb()
        assert result == 20

    def test_get_disk_gb_custom(self, valid_config_kwargs):
        """Test get_disk_gb with custom disk size."""
        valid_config_kwargs["disk_size"] = "100G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_disk_gb() == 100

    def test_get_disk_gb_terabytes(self, valid_config_kwargs):
        """Test get_disk_gb with terabyte input."""
        valid_config_kwargs["disk_size"] = "1T"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_disk_gb() == 1024

    def test_get_disk_gb_returns_int(self, sample_vm_config):
        """Test that get_disk_gb returns an int."""
        result = sample_vm_config.get_disk_gb()
        assert isinstance(result, int)


class TestBhyveVmConfigEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_agent_install_commands(self, valid_config_kwargs):
        """Test with empty agent install commands list."""
        valid_config_kwargs["agent_install_commands"] = []
        config = BhyveVmConfig(**valid_config_kwargs)
        assert not config.agent_install_commands

    def test_special_characters_in_vm_name(self, valid_config_kwargs):
        """Test VM name with hyphens and underscores."""
        valid_config_kwargs["vm_name"] = "test-vm_123"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.vm_name == "test-vm_123"

    def test_special_characters_in_hostname(self, valid_config_kwargs):
        """Test hostname with hyphens."""
        valid_config_kwargs["hostname"] = "my-test-host"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.hostname == "my-test-host"

    def test_https_disabled(self, valid_config_kwargs):
        """Test with HTTPS disabled."""
        valid_config_kwargs["use_https"] = False
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.use_https is False

    def test_custom_server_port(self, valid_config_kwargs):
        """Test with custom server port."""
        valid_config_kwargs["server_port"] = 9443
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.server_port == 9443

    def test_very_large_disk_size(self, valid_config_kwargs):
        """Test with very large disk size (10TB)."""
        valid_config_kwargs["disk_size"] = "10T"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_disk_gb() == 10240

    def test_very_large_memory(self, valid_config_kwargs):
        """Test with large memory (128G)."""
        valid_config_kwargs["memory"] = "128G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_memory_gb() == 128.0

    def test_minimum_memory(self, valid_config_kwargs):
        """Test with minimum practical memory (64M)."""
        valid_config_kwargs["memory"] = "64M"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_memory_mb() == 64

    def test_minimum_disk_size(self, valid_config_kwargs):
        """Test with minimum practical disk size (1G)."""
        valid_config_kwargs["disk_size"] = "1G"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.get_disk_gb() == 1

    def test_long_password_hash(self, valid_config_kwargs):
        """Test with a long SHA-512 password hash."""
        long_hash = "$6$rounds=10000$verylongsalt$" + "a" * 86
        valid_config_kwargs["password_hash"] = long_hash
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.password_hash == long_hash

    def test_multiple_agent_install_commands(self, valid_config_kwargs):
        """Test with multiple agent install commands."""
        commands = [
            "apt-get update",
            "apt-get install -y python3",
            "pip3 install sysmanage-agent",
            "systemctl enable sysmanage-agent",
            "systemctl start sysmanage-agent",
        ]
        valid_config_kwargs["agent_install_commands"] = commands
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.agent_install_commands == commands
        assert len(config.agent_install_commands) == 5


class TestBhyveVmConfigDistributions:
    """Tests for various distribution names."""

    def test_ubuntu_distribution(self, valid_config_kwargs):
        """Test with Ubuntu distribution."""
        valid_config_kwargs["distribution"] = "ubuntu"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "ubuntu"

    def test_debian_distribution(self, valid_config_kwargs):
        """Test with Debian distribution."""
        valid_config_kwargs["distribution"] = "debian"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "debian"

    def test_freebsd_distribution(self, valid_config_kwargs):
        """Test with FreeBSD distribution."""
        valid_config_kwargs["distribution"] = "freebsd"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "freebsd"

    def test_openbsd_distribution(self, valid_config_kwargs):
        """Test with OpenBSD distribution."""
        valid_config_kwargs["distribution"] = "openbsd"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "openbsd"

    def test_centos_distribution(self, valid_config_kwargs):
        """Test with CentOS distribution."""
        valid_config_kwargs["distribution"] = "centos"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "centos"

    def test_fedora_distribution(self, valid_config_kwargs):
        """Test with Fedora distribution."""
        valid_config_kwargs["distribution"] = "fedora"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "fedora"

    def test_rocky_distribution(self, valid_config_kwargs):
        """Test with Rocky Linux distribution."""
        valid_config_kwargs["distribution"] = "rocky"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "rocky"

    def test_alma_distribution(self, valid_config_kwargs):
        """Test with AlmaLinux distribution."""
        valid_config_kwargs["distribution"] = "almalinux"
        config = BhyveVmConfig(**valid_config_kwargs)
        assert config.distribution == "almalinux"


class TestBhyveVmConfigComputedPaths:
    """Tests for computed path attributes."""

    def test_disk_path_can_be_set(self, sample_vm_config):
        """Test that disk_path can be set after creation."""
        sample_vm_config.disk_path = "/vm/test-vm/disk.raw"
        assert sample_vm_config.disk_path == "/vm/test-vm/disk.raw"

    def test_cloud_init_iso_path_can_be_set(self, sample_vm_config):
        """Test that cloud_init_iso_path can be set after creation."""
        sample_vm_config.cloud_init_iso_path = "/vm/test-vm/cloud-init.iso"
        assert sample_vm_config.cloud_init_iso_path == "/vm/test-vm/cloud-init.iso"

    def test_cloud_image_path_can_be_set(self, sample_vm_config):
        """Test that cloud_image_path can be set after creation."""
        sample_vm_config.cloud_image_path = "/vm/test-vm/image.raw"
        assert sample_vm_config.cloud_image_path == "/vm/test-vm/image.raw"


class TestBhyveVmConfigDataclassBehavior:
    """Tests for dataclass behavior."""

    def test_config_is_mutable(self, sample_vm_config):
        """Test that config fields can be modified after creation."""
        sample_vm_config.vm_name = "new-vm-name"
        assert sample_vm_config.vm_name == "new-vm-name"

    def test_config_equality(self, valid_config_kwargs):
        """Test that two configs with same values are equal."""
        config1 = BhyveVmConfig(**valid_config_kwargs)
        config2 = BhyveVmConfig(**valid_config_kwargs)
        assert config1 == config2

    def test_config_inequality(self, valid_config_kwargs):
        """Test that two configs with different values are not equal."""
        config1 = BhyveVmConfig(**valid_config_kwargs)
        valid_config_kwargs["vm_name"] = "different-vm"
        config2 = BhyveVmConfig(**valid_config_kwargs)
        assert config1 != config2
