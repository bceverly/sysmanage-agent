"""
Comprehensive unit tests for KVM/libvirt VM type definitions.

Tests cover:
- KvmVmConfig dataclass initialization and validation
- Required field validation
- Memory format parsing and validation
- Disk size format parsing and validation
- CPU count validation
- Helper methods for memory and disk size conversion
"""

# pylint: disable=redefined-outer-name,protected-access

import pytest

from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig


@pytest.fixture
def valid_config_kwargs():
    """Provide valid kwargs for creating a KvmVmConfig."""
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
    """Create a sample KvmVmConfig for testing."""
    return KvmVmConfig(**valid_config_kwargs)


class TestKvmVmConfigInit:
    """Tests for KvmVmConfig initialization with valid parameters."""

    def test_init_with_required_fields_only(self, valid_config_kwargs):
        """Test initialization with only required fields."""
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.distribution == "ubuntu"
        assert config.vm_name == "test-vm"
        assert config.hostname == "test-hostname"
        assert config.username == "testuser"
        assert config.password_hash == "$6$rounds=4096$somesalt$somehash"
        assert config.server_url == "https://sysmanage.example.com"

    def test_init_default_values(self, sample_vm_config):
        """Test default values are set correctly."""
        assert sample_vm_config.memory == "2G"
        assert sample_vm_config.disk_size == "20G"
        assert sample_vm_config.cpus == 2
        assert sample_vm_config.server_port == 8443
        assert sample_vm_config.use_https is True
        assert sample_vm_config.cloud_image_url == ""
        assert sample_vm_config.iso_url == ""
        assert sample_vm_config.use_cloud_init is True
        assert sample_vm_config.network == "default"
        assert sample_vm_config.disk_format == "qcow2"
        assert sample_vm_config.auto_approve_token is None
        assert sample_vm_config.child_host_id is None

    def test_init_computed_paths_empty(self, sample_vm_config):
        """Test computed paths are initialized to empty strings."""
        assert sample_vm_config.disk_path == ""
        assert sample_vm_config.cloud_init_iso_path == ""
        assert sample_vm_config.cloud_image_path == ""

    def test_init_with_custom_memory(self, valid_config_kwargs):
        """Test initialization with custom memory."""
        valid_config_kwargs["memory"] = "4G"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.memory == "4G"

    def test_init_with_custom_disk_size(self, valid_config_kwargs):
        """Test initialization with custom disk size."""
        valid_config_kwargs["disk_size"] = "100G"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.disk_size == "100G"

    def test_init_with_custom_cpus(self, valid_config_kwargs):
        """Test initialization with custom CPU count."""
        valid_config_kwargs["cpus"] = 8
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.cpus == 8

    def test_init_with_custom_network(self, valid_config_kwargs):
        """Test initialization with custom network."""
        valid_config_kwargs["network"] = "br0"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.network == "br0"

    def test_init_with_custom_disk_format(self, valid_config_kwargs):
        """Test initialization with custom disk format."""
        valid_config_kwargs["disk_format"] = "raw"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.disk_format == "raw"

    def test_init_with_auto_approve_token(self, valid_config_kwargs):
        """Test initialization with auto-approve token."""
        valid_config_kwargs["auto_approve_token"] = "tok-abc"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.auto_approve_token == "tok-abc"

    def test_init_with_child_host_id(self, valid_config_kwargs):
        """Test initialization with child host id."""
        valid_config_kwargs["child_host_id"] = "host-123"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.child_host_id == "host-123"


class TestKvmVmConfigRequiredFieldValidation:
    """Tests for required field validation."""

    def test_missing_vm_name_raises(self, valid_config_kwargs):
        """Test that missing VM name raises ValueError."""
        valid_config_kwargs["vm_name"] = ""
        with pytest.raises(ValueError, match="VM name is required"):
            KvmVmConfig(**valid_config_kwargs)

    def test_missing_hostname_raises(self, valid_config_kwargs):
        """Test that missing hostname raises ValueError."""
        valid_config_kwargs["hostname"] = ""
        with pytest.raises(ValueError, match="Hostname is required"):
            KvmVmConfig(**valid_config_kwargs)

    def test_missing_username_raises(self, valid_config_kwargs):
        """Test that missing username raises ValueError."""
        valid_config_kwargs["username"] = ""
        with pytest.raises(ValueError, match="Username is required"):
            KvmVmConfig(**valid_config_kwargs)

    def test_missing_password_hash_raises(self, valid_config_kwargs):
        """Test that missing password hash raises ValueError."""
        valid_config_kwargs["password_hash"] = ""
        with pytest.raises(ValueError, match="Password hash is required"):
            KvmVmConfig(**valid_config_kwargs)

    def test_missing_distribution_raises(self, valid_config_kwargs):
        """Test that missing distribution raises ValueError."""
        valid_config_kwargs["distribution"] = ""
        with pytest.raises(ValueError, match="Distribution is required"):
            KvmVmConfig(**valid_config_kwargs)


class TestKvmVmConfigMemoryValidation:
    """Tests for memory format validation."""

    def test_invalid_memory_format_raises(self, valid_config_kwargs):
        """Test that invalid memory format raises ValueError."""
        valid_config_kwargs["memory"] = "invalid"
        with pytest.raises(ValueError, match="Invalid memory format: invalid"):
            KvmVmConfig(**valid_config_kwargs)

    def test_empty_memory_raises(self, valid_config_kwargs):
        """Test that empty memory string raises ValueError."""
        valid_config_kwargs["memory"] = ""
        with pytest.raises(ValueError, match="Invalid memory format:"):
            KvmVmConfig(**valid_config_kwargs)

    def test_memory_with_letters_raises(self, valid_config_kwargs):
        """Test that memory with non-numeric prefix raises ValueError."""
        valid_config_kwargs["memory"] = "abcG"
        with pytest.raises(ValueError, match="Invalid memory format: abcG"):
            KvmVmConfig(**valid_config_kwargs)

    def test_memory_g_suffix_valid(self, valid_config_kwargs):
        """Test memory with G suffix is accepted."""
        valid_config_kwargs["memory"] = "4G"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("4G") == 4096

    def test_memory_m_suffix_valid(self, valid_config_kwargs):
        """Test memory with M suffix is accepted."""
        valid_config_kwargs["memory"] = "2048M"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("2048M") == 2048

    def test_memory_gb_suffix_valid(self, valid_config_kwargs):
        """Test memory with GB suffix is accepted."""
        valid_config_kwargs["memory"] = "2GB"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("2GB") == 2048

    def test_memory_mb_suffix_valid(self, valid_config_kwargs):
        """Test memory with MB suffix is accepted."""
        valid_config_kwargs["memory"] = "1024MB"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("1024MB") == 1024

    def test_memory_no_suffix_valid(self, valid_config_kwargs):
        """Test memory without suffix is treated as MB."""
        valid_config_kwargs["memory"] = "512"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("512") == 512

    def test_memory_lowercase_suffix(self, valid_config_kwargs):
        """Test memory with lowercase suffix is accepted (uppercased internally)."""
        valid_config_kwargs["memory"] = "4g"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("4g") == 4096

    def test_memory_with_spaces(self, valid_config_kwargs):
        """Test memory with surrounding whitespace is accepted."""
        valid_config_kwargs["memory"] = "  2G  "
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("  2G  ") == 2048

    def test_memory_fractional_g(self, valid_config_kwargs):
        """Test fractional memory in G is accepted."""
        valid_config_kwargs["memory"] = "0.5G"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_memory_mb("0.5G") == 512


class TestKvmVmConfigDiskValidation:
    """Tests for disk size format validation."""

    def test_invalid_disk_size_raises(self, valid_config_kwargs):
        """Test that invalid disk size format raises ValueError."""
        valid_config_kwargs["disk_size"] = "invalid"
        with pytest.raises(ValueError, match="Invalid disk size format: invalid"):
            KvmVmConfig(**valid_config_kwargs)

    def test_empty_disk_size_raises(self, valid_config_kwargs):
        """Test that empty disk size string raises ValueError."""
        valid_config_kwargs["disk_size"] = ""
        with pytest.raises(ValueError, match="Invalid disk size format:"):
            KvmVmConfig(**valid_config_kwargs)

    def test_disk_size_g_suffix(self, valid_config_kwargs):
        """Test disk size with G suffix."""
        valid_config_kwargs["disk_size"] = "50G"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_disk_gb("50G") == 50

    def test_disk_size_gb_suffix(self, valid_config_kwargs):
        """Test disk size with GB suffix."""
        valid_config_kwargs["disk_size"] = "100GB"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_disk_gb("100GB") == 100

    def test_disk_size_no_suffix(self, valid_config_kwargs):
        """Test disk size without suffix is treated as GB."""
        valid_config_kwargs["disk_size"] = "30"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_disk_gb("30") == 30

    def test_disk_size_lowercase(self, valid_config_kwargs):
        """Test disk size with lowercase suffix."""
        valid_config_kwargs["disk_size"] = "20g"
        config = KvmVmConfig(**valid_config_kwargs)
        assert config._parse_disk_gb("20g") == 20


class TestKvmVmConfigCpuValidation:
    """Tests for CPU count validation."""

    def test_cpus_zero_raises(self, valid_config_kwargs):
        """Test that zero CPUs raises ValueError."""
        valid_config_kwargs["cpus"] = 0
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            KvmVmConfig(**valid_config_kwargs)

    def test_cpus_negative_raises(self, valid_config_kwargs):
        """Test that negative CPUs raises ValueError."""
        valid_config_kwargs["cpus"] = -1
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            KvmVmConfig(**valid_config_kwargs)

    def test_cpus_over_limit_raises(self, valid_config_kwargs):
        """Test that over-limit CPUs raises ValueError."""
        valid_config_kwargs["cpus"] = 65
        with pytest.raises(ValueError, match="CPUs cannot exceed 64"):
            KvmVmConfig(**valid_config_kwargs)

    def test_cpus_at_minimum(self, valid_config_kwargs):
        """Test that 1 CPU is accepted."""
        valid_config_kwargs["cpus"] = 1
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.cpus == 1

    def test_cpus_at_maximum(self, valid_config_kwargs):
        """Test that 64 CPUs is accepted."""
        valid_config_kwargs["cpus"] = 64
        config = KvmVmConfig(**valid_config_kwargs)
        assert config.cpus == 64


class TestKvmVmConfigParseHelpers:
    """Tests for _parse_memory_mb and _parse_disk_gb edge cases."""

    def test_parse_memory_invalid_returns_zero(self, sample_vm_config):
        """Test that invalid memory returns 0 from helper."""
        assert sample_vm_config._parse_memory_mb("garbage") == 0
        assert sample_vm_config._parse_memory_mb("") == 0

    def test_parse_disk_invalid_returns_zero(self, sample_vm_config):
        """Test that invalid disk size returns 0 from helper."""
        assert sample_vm_config._parse_disk_gb("garbage") == 0
        assert sample_vm_config._parse_disk_gb("") == 0
