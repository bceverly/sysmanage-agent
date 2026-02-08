"""
Tests for macOS hardware collector module.
Tests CPU, memory, storage, and network information gathering on macOS systems.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.hardware_collector_macos import (
    HardwareCollectorMacOS,
)


@pytest.fixture
def collector():
    """Create a macOS hardware collector for testing."""
    return HardwareCollectorMacOS()


class TestHardwareCollectorMacOSInit:
    """Tests for HardwareCollectorMacOS initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None


class TestGetCpuInfo:
    """Tests for get_cpu_info method."""

    def test_get_cpu_info_intel_success(self, collector):
        """Test successful Intel CPU info retrieval."""
        # For Intel CPUs, the model comes from chip_type if present, otherwise cpu_type
        # When chip_type is empty, the model defaults to chip_type (empty string)
        # unless chip_type contains something meaningful
        hardware_data = {
            "SPHardwareDataType": [
                {
                    "cpu_type": "Intel Core i7",
                    "chip_type": "Intel Core i7",  # chip_type is used for model
                    "number_processors": 8,
                    "current_processor_speed": "2.6 GHz",
                }
            ]
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(hardware_data)

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "Intel"
        assert cpu_info["model"] == "Intel Core i7"
        assert cpu_info["cores"] == 8
        assert cpu_info["threads"] == 8
        assert cpu_info["frequency_mhz"] == 2600

    def test_get_cpu_info_apple_silicon_success(self, collector):
        """Test successful Apple Silicon CPU info retrieval."""
        hardware_data = {
            "SPHardwareDataType": [
                {
                    "chip_type": "Apple M1 Pro",
                    "number_processors": "proc 10:8:2",
                    "current_processor_speed": "",
                }
            ]
        }

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(hardware_data)
            elif "hw.cpufrequency" in cmd:
                result.returncode = 0
                result.stdout = "3200000000"  # 3.2 GHz in Hz
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "Apple"
        assert cpu_info["model"] == "Apple M1 Pro"
        assert cpu_info["cores"] == 10
        assert cpu_info["frequency_mhz"] == 3200

    def test_get_cpu_info_apple_silicon_tbfrequency_fallback(self, collector):
        """Test Apple Silicon CPU frequency fallback to tbfrequency."""
        hardware_data = {
            "SPHardwareDataType": [
                {
                    "chip_type": "Apple M2",
                    "number_processors": 8,
                    "current_processor_speed": "",
                }
            ]
        }

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(hardware_data)
            elif "hw.cpufrequency" in cmd or "hw.cpufrequency_max" in cmd:
                result.returncode = 1
                result.stdout = ""
            elif "hw.tbfrequency" in cmd:
                result.returncode = 0
                result.stdout = "24000000"  # tbfrequency value
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        # tbfrequency fallback sets 3200 MHz for Apple Silicon
        assert cpu_info["frequency_mhz"] == 3200

    def test_get_cpu_info_mhz_speed(self, collector):
        """Test CPU info with MHz speed format."""
        hardware_data = {
            "SPHardwareDataType": [
                {
                    "cpu_type": "Intel Core 2 Duo",
                    "chip_type": "",
                    "number_processors": 2,
                    "current_processor_speed": "2400 MHz",
                }
            ]
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(hardware_data)

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 2400

    def test_get_cpu_info_command_failure(self, collector):
        """Test CPU info when system_profiler fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info == {}

    def test_get_cpu_info_exception(self, collector):
        """Test CPU info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            cpu_info = collector.get_cpu_info()

        assert "error" in cpu_info

    def test_get_cpu_info_number_processors_string_format(self, collector):
        """Test CPU info with complex number_processors string format."""
        hardware_data = {
            "SPHardwareDataType": [
                {
                    "cpu_type": "Intel Xeon",
                    "chip_type": "",
                    "number_processors": "proc 12:8:4",
                    "current_processor_speed": "3.0 GHz",
                }
            ]
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(hardware_data)

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["cores"] == 12
        assert cpu_info["threads"] == 12


class TestGetMemoryInfo:
    """Tests for get_memory_info method."""

    def test_get_memory_info_gb_success(self, collector):
        """Test successful memory info retrieval in GB."""
        hardware_data = {"SPHardwareDataType": [{"physical_memory": "16 GB"}]}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(hardware_data)

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 16384  # 16 GB in MB

    def test_get_memory_info_mb_format(self, collector):
        """Test memory info with MB format."""
        hardware_data = {"SPHardwareDataType": [{"physical_memory": "8192 MB"}]}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(hardware_data)

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 8192

    def test_get_memory_info_command_failure(self, collector):
        """Test memory info when system_profiler fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert "total_mb" not in mem_info

    def test_get_memory_info_exception(self, collector):
        """Test memory info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            mem_info = collector.get_memory_info()

        assert "error" in mem_info


class TestGetStorageInfo:
    """Tests for get_storage_info method."""

    def test_get_storage_info_success(self, collector):
        """Test successful storage info retrieval."""
        storage_data = {
            "SPStorageDataType": [
                {
                    "_name": "Macintosh HD",
                    "bsd_name": "disk3s1",
                    "mount_point": "/",
                    "file_system": "APFS",
                    "physical_drive": {"device_name": "APPLE SSD AP0512Q"},
                },
                {
                    "_name": "Data",
                    "bsd_name": "disk3s5",
                    "mount_point": "/System/Volumes/Data",
                    "file_system": "APFS",
                    "physical_drive": {"device_name": "APPLE SSD AP0512Q"},
                },
            ]
        }

        df_output = """Filesystem   1024-blocks    Used Available Capacity  Mounted on
/dev/disk3s1   500000000 250000000 250000000    50%   /
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd and "SPStorageDataType" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(storage_data)
            elif "df" in cmd:
                result.returncode = 0
                result.stdout = df_output
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            storage_info = collector.get_storage_info()

        # Should have at least root mount, /System/Volumes/Data should be excluded
        assert len(storage_info) >= 1
        root = next((d for d in storage_info if d.get("mount_point") == "/"), None)
        assert root is not None
        assert root["name"] == "Macintosh HD"
        assert root["file_system"] == "APFS"
        assert root["is_physical"] is True

    def test_get_storage_info_skips_system_volumes(self, collector):
        """Test that system volumes are excluded."""
        storage_data = {
            "SPStorageDataType": [
                {
                    "_name": "Macintosh HD",
                    "bsd_name": "disk3s1",
                    "mount_point": "/",
                    "file_system": "APFS",
                    "physical_drive": {},
                },
                {
                    "_name": "Preboot",
                    "bsd_name": "disk3s2",
                    "mount_point": "/System/Volumes/Preboot",
                    "file_system": "APFS",
                    "physical_drive": {},
                },
                {
                    "_name": "VM",
                    "bsd_name": "disk3s4",
                    "mount_point": "/System/Volumes/VM",
                    "file_system": "APFS",
                    "physical_drive": {},
                },
            ]
        }

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(storage_data)
            elif "df" in cmd:
                result.returncode = 0
                result.stdout = (
                    "Filesystem 1024-blocks Used Available Capacity Mounted\n"
                )
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            storage_info = collector.get_storage_info()

        # Should only include root, not Preboot or VM
        assert all(
            "/System/Volumes/Preboot" not in d.get("mount_point", "")
            for d in storage_info
        )
        assert all(
            "/System/Volumes/VM" not in d.get("mount_point", "") for d in storage_info
        )

    def test_get_storage_info_skips_snapshots(self, collector):
        """Test that snapshot volumes are excluded."""
        storage_data = {
            "SPStorageDataType": [
                {
                    "_name": "com.apple.os.update-snapshot",
                    "bsd_name": "disk3s1s1",
                    "mount_point": "/",
                    "file_system": "APFS",
                    "physical_drive": {},
                },
                {
                    "_name": "Macintosh HD - Data",
                    "bsd_name": "disk3s5",
                    "mount_point": "/System/Volumes/Data",
                    "file_system": "APFS",
                    "physical_drive": {},
                },
            ]
        }

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(storage_data)
            elif "df" in cmd:
                result.returncode = 0
                result.stdout = ""
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            storage_info = collector.get_storage_info()

        # Should not include snapshot
        assert not any("snapshot" in d.get("name", "").lower() for d in storage_info)

    def test_get_storage_info_exception(self, collector):
        """Test storage info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            storage_info = collector.get_storage_info()

        assert len(storage_info) > 0
        assert "error" in storage_info[0]


class TestIsPhysicalVolumeMacos:
    """Tests for _is_physical_volume_macos method."""

    def test_apple_ssd_is_physical(self, collector):
        """Test that Apple SSD is considered physical."""
        device = {"device_type": "APPLE SSD AP0512Q"}
        assert collector._is_physical_volume_macos(device) is True

    def test_disk_image_is_logical(self, collector):
        """Test that disk image is considered logical."""
        device = {"device_type": "Disk Image"}
        assert collector._is_physical_volume_macos(device) is False

    def test_empty_device_type_is_physical(self, collector):
        """Test that empty device type is considered physical."""
        device = {"device_type": ""}
        assert collector._is_physical_volume_macos(device) is True


class TestGetNetworkInfo:
    """Tests for get_network_info method."""

    def test_get_network_info_success(self, collector):
        """Test successful network info retrieval."""
        network_data = {
            "SPNetworkDataType": [
                {
                    "_name": "Ethernet",
                    "interface": "en0",
                    "type": "Ethernet",
                    "hardware": "Ethernet",
                    "has_ip_assigned": True,
                },
                {
                    "_name": "Wi-Fi",
                    "interface": "en1",
                    "type": "AirPort",
                    "hardware": "AirPort",
                    "has_ip_assigned": True,
                },
            ]
        }

        ifconfig_output = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:11:22:33:44:55
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 2001:db8::1 prefixlen 64
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 66:77:88:99:aa:bb
	inet 192.168.1.101 netmask 0xffffff00 broadcast 192.168.1.255
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(network_data)
            elif "ifconfig" in cmd:
                result.returncode = 0
                result.stdout = ifconfig_output
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            net_info = collector.get_network_info()

        assert len(net_info) == 2
        eth = next((i for i in net_info if i.get("name") == "Ethernet"), None)
        assert eth is not None
        assert eth["mac_address"] == "00:11:22:33:44:55"
        assert eth["ipv4_address"] == "192.168.1.100"
        assert eth["subnet_mask"] == "255.255.255.0"

    def test_get_network_info_ifconfig_failure(self, collector):
        """Test network info when ifconfig fails."""
        network_data = {
            "SPNetworkDataType": [
                {
                    "_name": "Ethernet",
                    "interface": "en0",
                    "type": "Ethernet",
                    "hardware": "Ethernet",
                    "has_ip_assigned": True,
                }
            ]
        }

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "system_profiler" in cmd:
                result.returncode = 0
                result.stdout = json.dumps(network_data)
            elif "ifconfig" in cmd:
                result.returncode = 1
                result.stdout = ""
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            net_info = collector.get_network_info()

        # Should still return interface from system_profiler
        assert len(net_info) == 1
        assert net_info[0]["name"] == "Ethernet"

    def test_get_network_info_exception(self, collector):
        """Test network info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            net_info = collector.get_network_info()

        assert len(net_info) > 0
        assert "error" in net_info[0]


class TestParseDfMountUsage:
    """Tests for _parse_df_mount_usage method."""

    def test_parse_df_mount_usage_success(self, collector):
        """Test successful df output parsing."""
        df_output = """Filesystem   1024-blocks     Used Available Capacity  Mounted on
/dev/disk3s1   500000000 250000000 250000000    50%    /
/dev/disk4s1  1000000000 500000000 500000000    50%    /Volumes/External
"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = df_output

        with patch("subprocess.run", return_value=mock_result):
            mount_usage = collector._parse_df_mount_usage()

        assert "/" in mount_usage
        assert mount_usage["/"]["capacity_bytes"] == 500000000 * 1024
        assert mount_usage["/"]["used_bytes"] == 250000000 * 1024

    def test_parse_df_mount_usage_failure(self, collector):
        """Test df parsing when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            mount_usage = collector._parse_df_mount_usage()

        assert mount_usage == {}


class TestParseIfconfigInterfaceDetails:
    """Tests for _parse_ifconfig_interface_details method."""

    def test_parse_ethernet_interface(self, collector):
        """Test parsing Ethernet interface details."""
        ifconfig_output = """en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
	ether 00:11:22:33:44:55
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 2001:db8::1 prefixlen 64
"""
        details = collector._parse_ifconfig_interface_details(ifconfig_output)

        assert "en0" in details
        assert details["en0"]["mac_address"] == "00:11:22:33:44:55"
        assert details["en0"]["ipv4_address"] == "192.168.1.100"
        assert details["en0"]["subnet_mask"] == "255.255.255.0"
        assert details["en0"]["ipv6_address"] == "2001:db8::1"
        assert details["en0"]["is_active"] is True

    def test_parse_interface_not_running(self, collector):
        """Test parsing interface that is not running."""
        ifconfig_output = """en0: flags=8822<BROADCAST> mtu 1500
	ether 00:11:22:33:44:55
"""
        details = collector._parse_ifconfig_interface_details(ifconfig_output)

        assert "en0" in details
        assert details["en0"]["is_active"] is False

    def test_parse_skips_link_local_ipv6(self, collector):
        """Test that link-local IPv6 is not captured as primary IPv6."""
        ifconfig_output = """en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
	inet6 fe80::1 prefixlen 64 scopeid 0x4
	inet6 2001:db8::1 prefixlen 64
"""
        details = collector._parse_ifconfig_interface_details(ifconfig_output)

        assert "en0" in details
        assert details["en0"]["ipv6_address"] == "2001:db8::1"


class TestConvertSizeToBytes:
    """Tests for _convert_size_to_bytes method."""

    def test_convert_gb(self, collector):
        """Test converting GB to bytes."""
        result = collector._convert_size_to_bytes(1.0, "GB")
        assert result == 1024**3

    def test_convert_tb(self, collector):
        """Test converting TB to bytes."""
        result = collector._convert_size_to_bytes(1.0, "TB")
        assert result == 1024**4

    def test_convert_mb(self, collector):
        """Test converting MB to bytes."""
        result = collector._convert_size_to_bytes(100.0, "MB")
        assert result == 100 * 1024**2

    def test_convert_unknown_unit(self, collector):
        """Test converting unknown unit returns None."""
        result = collector._convert_size_to_bytes(1.0, "KB")
        assert result is None


class TestGetMacosCpuInfoBackwardCompatibility:
    """Tests for backward compatibility method."""

    def test_get_macos_cpu_info_delegates(self, collector):
        """Test that _get_macos_cpu_info delegates to get_cpu_info."""
        with patch.object(collector, "get_cpu_info", return_value={"vendor": "Apple"}):
            result = collector._get_macos_cpu_info()
        assert result == {"vendor": "Apple"}


class TestApfsCorrectedUsage:
    """Tests for APFS usage correction."""

    def test_non_apfs_not_corrected(self, collector):
        """Test that non-APFS volumes are not corrected."""
        device = {"file_system": "HFS+"}
        usage_info = {"capacity_bytes": 500 * 1024**3, "used_bytes": 10 * 1024**3}

        result = collector._collect_apfs_corrected_usage(device, usage_info, "/", {})

        assert result == usage_info

    def test_apfs_small_volume_not_corrected(self, collector):
        """Test that small APFS volumes are not corrected."""
        device = {"file_system": "APFS"}
        usage_info = {"capacity_bytes": 50 * 1024**3, "used_bytes": 25 * 1024**3}

        result = collector._collect_apfs_corrected_usage(device, usage_info, "/", {})

        assert result == usage_info

    def test_apfs_normal_usage_not_corrected(self, collector):
        """Test that APFS volumes with normal usage are not corrected."""
        device = {"file_system": "APFS"}
        usage_info = {"capacity_bytes": 500 * 1024**3, "used_bytes": 50 * 1024**3}

        result = collector._collect_apfs_corrected_usage(device, usage_info, "/", {})

        assert result == usage_info


class TestParseDiskutilOutput:
    """Tests for _parse_diskutil_output method."""

    def test_parse_apfs_container(self, collector):
        """Test parsing APFS container from diskutil output."""
        diskutil_output = """/dev/disk0 (internal):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *500.1 GB   disk0

/dev/disk1 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      APFS Container Scheme -                      +500.0 GB   disk1
           Physical Store disk0s2
   1:                APFS Volume Macintosh HD            15.0 GB    disk1s1
"""

        result = collector._parse_diskutil_output(diskutil_output)

        assert len(result) >= 1
        # Should have APFS container
        container = next(
            (c for c in result if "APFS Container" in c.get("name", "")), None
        )
        assert container is not None
        assert container["is_physical"] is True

    def test_parse_disk_image(self, collector):
        """Test parsing disk image from diskutil output."""
        diskutil_output = """/dev/disk2 (disk image):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      GUID_partition_scheme                        *10.0 GB    disk2

/dev/disk3 (synthesized):
   #:                       TYPE NAME                    SIZE       IDENTIFIER
   0:      APFS Container Scheme -                      +10.0 GB    disk3
           Physical Store disk2s1
"""

        result = collector._parse_diskutil_output(diskutil_output)

        # Disk image containers should not be marked physical
        container = next(
            (c for c in result if "APFS Container" in c.get("name", "")), None
        )
        if container:
            assert container["is_physical"] is False
