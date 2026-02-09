"""
Tests for Windows hardware collector module.
Tests CPU, memory, storage, and network information gathering on Windows systems.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.hardware_collector_windows import (
    HardwareCollectorWindows,
)


@pytest.fixture
def collector():
    """Create a Windows hardware collector for testing."""
    return HardwareCollectorWindows()


class TestHardwareCollectorWindowsInit:
    """Tests for HardwareCollectorWindows initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None


class TestGetCpuInfo:
    """Tests for get_cpu_info method."""

    def test_get_cpu_info_success(self, collector):
        """Test successful CPU info retrieval."""
        wmic_output = """Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors
DESKTOP-ABC,GenuineIntel,3600,Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz,8,16
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "GenuineIntel"
        assert cpu_info["model"] == "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz"
        assert cpu_info["cores"] == 8
        assert cpu_info["threads"] == 16
        assert cpu_info["frequency_mhz"] == 3600

    def test_get_cpu_info_amd(self, collector):
        """Test CPU info for AMD processor."""
        wmic_output = """Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors
DESKTOP-XYZ,AuthenticAMD,4500,AMD Ryzen 9 5900X 12-Core Processor,12,24
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "AuthenticAMD"
        assert cpu_info["cores"] == 12
        assert cpu_info["threads"] == 24
        assert cpu_info["frequency_mhz"] == 4500

    def test_get_cpu_info_command_failure(self, collector):
        """Test CPU info when wmic command fails."""
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

    def test_get_cpu_info_empty_values(self, collector):
        """Test CPU info with empty values."""
        wmic_output = """Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors
DESKTOP-ABC,,,,,
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 0
        assert cpu_info["cores"] == 0
        assert cpu_info["threads"] == 0

    def test_get_cpu_info_insufficient_fields(self, collector):
        """Test CPU info with insufficient CSV fields."""
        wmic_output = """Node,Manufacturer,MaxClockSpeed
DESKTOP-ABC,GenuineIntel,3600
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        # Should return empty dict when not enough fields
        assert cpu_info == {}


class TestGetMemoryInfo:
    """Tests for get_memory_info method."""

    def test_get_memory_info_success(self, collector):
        """Test successful memory info retrieval."""
        wmic_output = """Node,TotalPhysicalMemory
DESKTOP-ABC,17179869184
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 16384  # 16 GB in MB

    def test_get_memory_info_large_ram(self, collector):
        """Test memory info with large RAM (128 GB)."""
        wmic_output = """Node,TotalPhysicalMemory
SERVER-01,137438953472
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 131072  # 128 GB in MB

    def test_get_memory_info_command_failure(self, collector):
        """Test memory info when wmic command fails."""
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

    def test_get_memory_info_empty_value(self, collector):
        """Test memory info with empty TotalPhysicalMemory."""
        wmic_output = """Node,TotalPhysicalMemory
DESKTOP-ABC,
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = wmic_output

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert "total_mb" not in mem_info


class TestGetStorageInfo:
    """Tests for get_storage_info method."""

    def test_get_storage_info_success(self, collector):
        """Test successful storage info retrieval."""
        diskdrive_output = """Node,DeviceID,InterfaceType,Model,Size
DESKTOP-ABC,\\\\.\\PHYSICALDRIVE0,SCSI,Samsung SSD 860,500107862016
"""
        logicaldisk_output = """Node,DeviceID,FileSystem,FreeSpace,Size,VolumeName
DESKTOP-ABC,C:,NTFS,250000000000,500000000000,Windows
DESKTOP-ABC,D:,NTFS,400000000000,1000000000000,Data
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "diskdrive" in cmd:
                result.stdout = diskdrive_output
            elif "logicaldisk" in cmd:
                result.stdout = logicaldisk_output
            else:
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            storage_info = collector.get_storage_info()

        assert len(storage_info) >= 3  # 1 physical + 2 logical

        # Check physical drive
        physical = next((d for d in storage_info if d.get("is_physical") is True), None)
        assert physical is not None
        assert "Samsung" in physical.get("model", "")

        # Check logical drives
        c_drive = next((d for d in storage_info if d.get("name") == "C:"), None)
        assert c_drive is not None
        assert c_drive["file_system"] == "NTFS"
        assert c_drive["is_physical"] is False

    def test_get_storage_info_physical_failure(self, collector):
        """Test storage info when physical disk collection fails."""
        logicaldisk_output = """Node,DeviceID,FileSystem,FreeSpace,Size,VolumeName
DESKTOP-ABC,C:,NTFS,250000000000,500000000000,Windows
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "diskdrive" in cmd:
                raise RuntimeError("Physical disk error")
            if "logicaldisk" in cmd:
                result.returncode = 0
                result.stdout = logicaldisk_output
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            storage_info = collector.get_storage_info()

        # Should still have logical drives
        assert len(storage_info) >= 1
        assert any(d.get("name") == "C:" for d in storage_info)

    def test_get_storage_info_logical_failure(self, collector):
        """Test storage info when logical disk collection fails."""
        diskdrive_output = """Node,DeviceID,InterfaceType,Model,Size
DESKTOP-ABC,\\\\.\\PHYSICALDRIVE0,SCSI,Samsung SSD 860,500107862016
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "diskdrive" in cmd:
                result.stdout = diskdrive_output
            elif "logicaldisk" in cmd:
                raise RuntimeError("Logical disk error")
            else:
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            storage_info = collector.get_storage_info()

        # Should have error entry
        assert any("error" in d for d in storage_info)


class TestIsPhysicalVolumeWindows:
    """Tests for _is_physical_volume_windows method."""

    def test_c_drive_is_physical(self, collector):
        """Test that C: drive is considered physical."""
        assert collector._is_physical_volume_windows("C:") is True

    def test_d_drive_is_physical(self, collector):
        """Test that D: drive is considered physical."""
        assert collector._is_physical_volume_windows("D:") is True

    def test_floppy_drive_is_logical(self, collector):
        """Test that floppy drives are considered logical."""
        assert collector._is_physical_volume_windows("A:") is False
        assert collector._is_physical_volume_windows("B:") is False

    def test_network_common_drives_are_logical(self, collector):
        """Test that common network drive letters are considered logical."""
        assert collector._is_physical_volume_windows("X:") is False
        assert collector._is_physical_volume_windows("Y:") is False
        assert collector._is_physical_volume_windows("Z:") is False

    def test_unc_path_is_logical(self, collector):
        """Test that UNC paths are considered logical."""
        assert collector._is_physical_volume_windows("\\\\server\\share") is False

    def test_drive_letter_normalization(self, collector):
        """Test that drive letters are normalized."""
        assert collector._is_physical_volume_windows("c:") is True
        assert collector._is_physical_volume_windows("C") is True


class TestGetNetworkInfo:
    """Tests for get_network_info method."""

    def test_get_network_info_success(self, collector):
        """Test successful network info retrieval."""
        ipconfig_output = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-ABC
   Primary Dns Suffix  . . . . . . . :

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : local
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 8.8.8.8

Wireless LAN adapter Wi-Fi:

   Media State . . . . . . . . . . . : Media disconnected
   Description . . . . . . . . . . . : Intel(R) Wireless-AC 9560
   Physical Address. . . . . . . . . : 66-77-88-99-AA-BB
"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ipconfig_output

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        assert len(net_info) >= 2

        eth = next((i for i in net_info if "Ethernet" in i.get("name", "")), None)
        assert eth is not None
        assert eth["mac_address"] == "00-11-22-33-44-55"
        assert eth["dhcp_enabled"] is True
        assert "192.168.1.100" in eth["ip_addresses"]
        assert eth["is_active"] is True
        assert eth["type"] == "Ethernet"

        wifi = next((i for i in net_info if "Wi-Fi" in i.get("name", "")), None)
        assert wifi is not None
        assert wifi["is_active"] is False
        assert wifi["type"] == "Wireless"

    def test_get_network_info_bluetooth(self, collector):
        """Test Bluetooth adapter detection."""
        ipconfig_output = """
Ethernet adapter Bluetooth Network Connection:

   Description . . . . . . . . . . . : Bluetooth Device
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ipconfig_output

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        assert len(net_info) == 1
        assert net_info[0]["type"] == "Bluetooth"

    def test_get_network_info_tunnel(self, collector):
        """Test tunnel adapter detection."""
        ipconfig_output = """
Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ipconfig_output

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        if net_info:
            assert net_info[0]["type"] == "Tunnel"

    def test_get_network_info_command_failure(self, collector):
        """Test network info when ipconfig fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        assert net_info == []

    def test_get_network_info_exception(self, collector):
        """Test network info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            net_info = collector.get_network_info()

        assert len(net_info) > 0
        assert "error" in net_info[0]

    def test_get_network_info_ipv6_address(self, collector):
        """Test IPv6 address parsing."""
        ipconfig_output = """
Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   IPv6 Address. . . . . . . . . . . : 2001:db8::1(Preferred)
   Link-local IPv6 Address . . . . . : fe80::1%4
   IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)
"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ipconfig_output

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        assert len(net_info) == 1
        # Should have both IPv4 and IPv6
        assert "192.168.1.100" in net_info[0]["ip_addresses"]
        assert "2001:db8::1" in net_info[0]["ip_addresses"]


class TestParseWmicCsvLines:
    """Tests for _parse_wmic_csv_lines method."""

    def test_parse_normal_output(self, collector):
        """Test parsing normal WMIC output."""
        stdout = """Header1,Header2
Value1,Value2
"""
        result = collector._parse_wmic_csv_lines(stdout)
        assert len(result) == 2
        assert result[0] == "Header1,Header2"
        assert result[1] == "Value1,Value2"

    def test_parse_empty_lines(self, collector):
        """Test parsing output with empty lines."""
        stdout = """Header1,Header2

Value1,Value2

"""
        result = collector._parse_wmic_csv_lines(stdout)
        assert len(result) == 2

    def test_parse_empty_output(self, collector):
        """Test parsing empty output."""
        result = collector._parse_wmic_csv_lines("")
        assert result == []


class TestParseCpuWmicData:
    """Tests for _parse_cpu_wmic_data method."""

    def test_parse_complete_data(self, collector):
        """Test parsing complete CPU data."""
        data = ["Node", "GenuineIntel", "3600", "Intel Core i7", "8", "16"]
        result = collector._parse_cpu_wmic_data(data)

        assert result["vendor"] == "GenuineIntel"
        assert result["frequency_mhz"] == 3600
        assert result["model"] == "Intel Core i7"
        assert result["cores"] == 8
        assert result["threads"] == 16

    def test_parse_incomplete_data(self, collector):
        """Test parsing incomplete CPU data."""
        data = ["Node", "GenuineIntel"]
        result = collector._parse_cpu_wmic_data(data)

        assert result == {}


class TestParsePhysicalDiskLine:
    """Tests for _parse_physical_disk_line method."""

    def test_parse_valid_line(self, collector):
        """Test parsing valid physical disk line."""
        _header = "Node,DeviceID,InterfaceType,Model,Size"
        # This would be the data line, not header
        data_line = "DESKTOP-ABC,\\\\.\\PHYSICALDRIVE0,SCSI,Samsung SSD,500107862016"
        result = collector._parse_physical_disk_line(data_line)

        assert result is not None
        assert result["name"] == "\\\\.\\PHYSICALDRIVE0"
        assert result["interface_type"] == "SCSI"
        assert result["is_physical"] is True

    def test_parse_empty_device(self, collector):
        """Test parsing line with empty device."""
        line = "DESKTOP-ABC,,SCSI,Samsung SSD,500107862016"
        result = collector._parse_physical_disk_line(line)

        assert result is None


class TestParseLogicalDiskLine:
    """Tests for _parse_logical_disk_line method."""

    def test_parse_valid_line(self, collector):
        """Test parsing valid logical disk line."""
        line = "DESKTOP-ABC,C:,NTFS,250000000000,500000000000,Windows"
        result = collector._parse_logical_disk_line(line)

        assert result is not None
        assert result["name"] == "C:"
        assert result["file_system"] == "NTFS"
        assert result["is_physical"] is False
        assert result["volume_name"] == "Windows"

    def test_parse_empty_device(self, collector):
        """Test parsing line with empty device."""
        line = "DESKTOP-ABC,,NTFS,250000000000,500000000000,Windows"
        result = collector._parse_logical_disk_line(line)

        assert result is None


class TestHandleMediaState:
    """Tests for _handle_media_state method."""

    def test_connected_state(self, collector):
        """Test handling connected media state."""
        adapter = {"is_active": False, "connection_status": "Unknown"}
        collector._handle_media_state(adapter, "Connected")

        assert adapter["is_active"] is True
        assert adapter["connection_status"] == "Connected"

    def test_disconnected_state(self, collector):
        """Test handling disconnected media state."""
        adapter = {"is_active": True, "connection_status": "Unknown"}
        collector._handle_media_state(adapter, "Media disconnected")

        assert adapter["is_active"] is False
        assert adapter["connection_status"] == "Disconnected"


class TestHandleDescription:
    """Tests for _handle_description method."""

    def test_wifi_adapter(self, collector):
        """Test detecting Wi-Fi adapter."""
        adapter = {"name": "Wi-Fi", "type": "Unknown"}
        collector._handle_description(adapter, "Intel Wireless-AC 9560")

        assert adapter["type"] == "Wireless"

    def test_ethernet_adapter(self, collector):
        """Test detecting Ethernet adapter."""
        adapter = {"name": "Ethernet", "type": "Unknown"}
        collector._handle_description(adapter, "Intel Gigabit Network Connection")

        assert adapter["type"] == "Ethernet"

    def test_bluetooth_adapter(self, collector):
        """Test detecting Bluetooth adapter."""
        adapter = {"name": "Bluetooth Network", "type": "Unknown"}
        collector._handle_description(adapter, "Bluetooth Device")

        assert adapter["type"] == "Bluetooth"

    def test_loopback_adapter(self, collector):
        """Test detecting loopback adapter."""
        adapter = {"name": "Loopback", "type": "Unknown"}
        collector._handle_description(adapter, "Microsoft Loopback Adapter")

        assert adapter["type"] == "Loopback"

    def test_vpn_adapter(self, collector):
        """Test detecting VPN adapter."""
        adapter = {"name": "VPN Connection", "type": "Unknown"}
        collector._handle_description(adapter, "TAP-Windows Adapter V9")

        # VPN uses "tunnel" prefix, so should default to Tunnel or Unknown
        # Based on implementation, VPN keyword triggers Tunnel
        assert adapter["type"] in ["Tunnel", "Unknown"]


class TestHandleIpAddress:
    """Tests for _handle_ip_address method."""

    def test_ipv4_address(self, collector):
        """Test handling IPv4 address."""
        adapter = {
            "ip_addresses": [],
            "is_active": False,
            "connection_status": "Unknown",
        }
        collector._handle_ip_address(adapter, "192.168.1.100(Preferred)")

        assert "192.168.1.100" in adapter["ip_addresses"]
        assert adapter["is_active"] is True

    def test_ipv6_address_with_zone_id(self, collector):
        """Test handling IPv6 address with zone ID."""
        adapter = {
            "ip_addresses": [],
            "is_active": False,
            "connection_status": "Unknown",
        }
        collector._handle_ip_address(adapter, "fe80::1%4")

        assert "fe80::1" in adapter["ip_addresses"]

    def test_none_value_skipped(self, collector):
        """Test that (none) value is skipped."""
        adapter = {
            "ip_addresses": [],
            "is_active": False,
            "connection_status": "Unknown",
        }
        collector._handle_ip_address(adapter, "(none)")

        assert len(adapter["ip_addresses"]) == 0


class TestGetWindowsCpuInfoBackwardCompatibility:
    """Tests for backward compatibility method."""

    def test_get_windows_cpu_info_delegates(self, collector):
        """Test that _get_windows_cpu_info delegates to get_cpu_info."""
        with patch.object(collector, "get_cpu_info", return_value={"vendor": "Intel"}):
            result = collector._get_windows_cpu_info()
        assert result == {"vendor": "Intel"}
