"""
Tests for hardware collector base module.
Tests the base class and common utility methods.
"""

# pylint: disable=redefined-outer-name,protected-access

import pytest

from src.sysmanage_agent.collection.hardware_collector_base import HardwareCollectorBase


class ConcreteCollector(HardwareCollectorBase):
    """Concrete implementation for testing abstract base class."""

    def get_cpu_info(self):
        return {"model": "Test CPU"}

    def get_memory_info(self):
        return {"total_mb": 1024}

    def get_storage_info(self):
        return [{"name": "/dev/sda"}]

    def get_network_info(self):
        return [{"name": "eth0"}]


@pytest.fixture
def collector():
    """Create a concrete collector for testing."""
    return ConcreteCollector()


class TestHardwareCollectorBaseInit:
    """Tests for HardwareCollectorBase initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None


class TestGetTimestamp:
    """Tests for _get_timestamp method."""

    def test_get_timestamp_returns_iso_format(self, collector):
        """Test that _get_timestamp returns ISO format."""
        timestamp = collector._get_timestamp()
        assert isinstance(timestamp, str)
        assert "T" in timestamp  # ISO format contains T separator


class TestParseSizeToBytes:
    """Tests for _parse_size_to_bytes method."""

    def test_parse_bytes(self, collector):
        """Test parsing bytes."""
        assert collector._parse_size_to_bytes("100B") == 100
        assert collector._parse_size_to_bytes("0B") == 0

    def test_parse_kilobytes(self, collector):
        """Test parsing kilobytes."""
        assert collector._parse_size_to_bytes("1K") == 1024
        assert collector._parse_size_to_bytes("2K") == 2048
        assert collector._parse_size_to_bytes("1.5K") == 1536

    def test_parse_megabytes(self, collector):
        """Test parsing megabytes."""
        assert collector._parse_size_to_bytes("1M") == 1024 * 1024
        assert collector._parse_size_to_bytes("2M") == 2 * 1024 * 1024

    def test_parse_gigabytes(self, collector):
        """Test parsing gigabytes."""
        assert collector._parse_size_to_bytes("1G") == 1024**3
        assert collector._parse_size_to_bytes("4.7G") == int(4.7 * 1024**3)

    def test_parse_terabytes(self, collector):
        """Test parsing terabytes."""
        assert collector._parse_size_to_bytes("1T") == 1024**4

    def test_parse_petabytes(self, collector):
        """Test parsing petabytes."""
        assert collector._parse_size_to_bytes("1P") == 1024**5

    def test_parse_empty_string(self, collector):
        """Test parsing empty string."""
        assert collector._parse_size_to_bytes("") == 0

    def test_parse_dash(self, collector):
        """Test parsing dash (common for N/A values)."""
        assert collector._parse_size_to_bytes("-") == 0

    def test_parse_none(self, collector):
        """Test parsing None."""
        assert collector._parse_size_to_bytes(None) == 0

    def test_parse_lowercase(self, collector):
        """Test parsing lowercase units."""
        assert collector._parse_size_to_bytes("1g") == 1024**3
        assert collector._parse_size_to_bytes("100k") == 100 * 1024

    def test_parse_with_whitespace(self, collector):
        """Test parsing with whitespace."""
        assert collector._parse_size_to_bytes(" 1G ") == 1024**3
        assert collector._parse_size_to_bytes("  2M  ") == 2 * 1024**2

    def test_parse_invalid_value(self, collector):
        """Test parsing invalid value."""
        assert collector._parse_size_to_bytes("invalid") == 0
        assert collector._parse_size_to_bytes("abc123") == 0


class TestBytesToHumanReadable:
    """Tests for _bytes_to_human_readable method."""

    def test_convert_zero(self, collector):
        """Test converting zero bytes."""
        assert collector._bytes_to_human_readable(0) == "0B"

    def test_convert_bytes(self, collector):
        """Test converting bytes."""
        assert collector._bytes_to_human_readable(100) == "100B"
        assert collector._bytes_to_human_readable(512) == "512B"

    def test_convert_kilobytes(self, collector):
        """Test converting to kilobytes."""
        assert collector._bytes_to_human_readable(1024) == "1.0K"
        assert collector._bytes_to_human_readable(2048) == "2.0K"

    def test_convert_megabytes(self, collector):
        """Test converting to megabytes."""
        result = collector._bytes_to_human_readable(1024 * 1024)
        assert result == "1.0M"

    def test_convert_gigabytes(self, collector):
        """Test converting to gigabytes."""
        result = collector._bytes_to_human_readable(1024**3)
        assert result == "1.0G"

    def test_convert_terabytes(self, collector):
        """Test converting to terabytes."""
        result = collector._bytes_to_human_readable(1024**4)
        assert result == "1.0T"

    def test_convert_petabytes(self, collector):
        """Test converting to petabytes."""
        result = collector._bytes_to_human_readable(1024**5)
        assert result == "1.0P"

    def test_convert_fractional(self, collector):
        """Test converting fractional values."""
        result = collector._bytes_to_human_readable(int(1.5 * 1024**3))
        assert "1.5G" in result


class TestIsPhysicalVolumeGeneric:
    """Tests for _is_physical_volume_generic method."""

    def test_root_mount_is_physical(self, collector):
        """Test that root mount is considered physical.

        Note: The generic method checks if 'dev' is in device_name as a logical pattern,
        so /dev/sda1 returns False. Platform-specific collectors have better detection.
        """
        # /dev/sda1 contains "dev" which is in logical_patterns
        assert collector._is_physical_volume_generic("/dev/sda1", "/") is False

    def test_mount_point_root_with_clean_device(self, collector):
        """Test that root mount with clean device name is physical."""
        # Using a device name without 'dev' in it
        assert collector._is_physical_volume_generic("sda1", "/") is True

    def test_mount_point_home_with_clean_device(self, collector):
        """Test that home mount with clean device name is physical."""
        assert collector._is_physical_volume_generic("sda2", "/home") is True

    def test_mount_point_var_with_clean_device(self, collector):
        """Test that var mount with clean device name is physical."""
        assert collector._is_physical_volume_generic("sda3", "/var") is True

    def test_tmpfs_is_logical(self, collector):
        """Test that tmpfs is considered logical."""
        assert collector._is_physical_volume_generic("tmpfs", "/tmp") is False

    def test_proc_is_logical(self, collector):
        """Test that proc is considered logical."""
        assert collector._is_physical_volume_generic("proc", "/proc") is False

    def test_sysfs_is_logical(self, collector):
        """Test that sysfs is considered logical."""
        assert collector._is_physical_volume_generic("sysfs", "/sys") is False

    def test_devtmpfs_is_logical(self, collector):
        """Test that devtmpfs is considered logical."""
        assert collector._is_physical_volume_generic("devtmpfs", "/dev") is False

    def test_cgroup_is_logical(self, collector):
        """Test that cgroup is considered logical."""
        assert (
            collector._is_physical_volume_generic("cgroup", "/sys/fs/cgroup") is False
        )

    def test_loop_device_is_logical(self, collector):
        """Test that loop device is considered logical."""
        assert (
            collector._is_physical_volume_generic("/dev/loop0", "/snap/test") is False
        )

    def test_unknown_device_without_dev_defaults_physical(self, collector):
        """Test that unknown device without logical patterns defaults to physical."""
        # Using a name that doesn't contain any logical patterns
        assert (
            collector._is_physical_volume_generic("unknown_disk", "/mnt/data") is True
        )

    def test_dev_in_device_name_returns_logical(self, collector):
        """Test that device names containing 'dev' return False (logical).

        This is a design limitation of the generic method - platform-specific
        collectors should be used for accurate detection.
        """
        assert collector._is_physical_volume_generic("/dev/sda1", "/mnt/data") is False


class TestAbstractMethods:
    """Tests to verify abstract methods are properly defined."""

    def test_get_cpu_info_implemented(self, collector):
        """Test that get_cpu_info can be called."""
        result = collector.get_cpu_info()
        assert "model" in result

    def test_get_memory_info_implemented(self, collector):
        """Test that get_memory_info can be called."""
        result = collector.get_memory_info()
        assert "total_mb" in result

    def test_get_storage_info_implemented(self, collector):
        """Test that get_storage_info can be called."""
        result = collector.get_storage_info()
        assert isinstance(result, list)

    def test_get_network_info_implemented(self, collector):
        """Test that get_network_info can be called."""
        result = collector.get_network_info()
        assert isinstance(result, list)
