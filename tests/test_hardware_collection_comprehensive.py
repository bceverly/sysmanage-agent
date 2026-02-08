"""
Comprehensive tests for the hardware collection module.
Tests the main HardwareCollector class and cross-platform functionality.
"""

# pylint: disable=protected-access,redefined-outer-name

import json
from unittest.mock import Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.collection.hardware_collection import HardwareCollector
from src.sysmanage_agent.collection.hardware_collector_linux import (
    HardwareCollectorLinux,
)
from src.sysmanage_agent.collection.hardware_collector_macos import (
    HardwareCollectorMacOS,
)
from src.sysmanage_agent.collection.hardware_collector_windows import (
    HardwareCollectorWindows,
)
from src.sysmanage_agent.collection.hardware_collector_bsd import HardwareCollectorBSD


class TestHardwareCollectorPlatformSelection:
    """Tests for platform-specific collector selection."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_linux_platform_uses_linux_collector(self, mock_system):
        """Test that Linux platform uses Linux collector."""
        mock_system.return_value = "Linux"
        collector = HardwareCollector()

        assert isinstance(collector.collector, HardwareCollectorLinux)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_darwin_platform_uses_macos_collector(self, mock_system):
        """Test that Darwin platform uses macOS collector."""
        mock_system.return_value = "Darwin"
        collector = HardwareCollector()

        assert isinstance(collector.collector, HardwareCollectorMacOS)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_windows_platform_uses_windows_collector(self, mock_system):
        """Test that Windows platform uses Windows collector."""
        mock_system.return_value = "Windows"
        collector = HardwareCollector()

        assert isinstance(collector.collector, HardwareCollectorWindows)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_openbsd_platform_uses_bsd_collector(self, mock_system):
        """Test that OpenBSD platform uses BSD collector."""
        mock_system.return_value = "OpenBSD"
        collector = HardwareCollector()

        assert isinstance(collector.collector, HardwareCollectorBSD)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_freebsd_platform_uses_bsd_collector(self, mock_system):
        """Test that FreeBSD platform uses BSD collector."""
        mock_system.return_value = "FreeBSD"
        collector = HardwareCollector()

        assert isinstance(collector.collector, HardwareCollectorBSD)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_netbsd_platform_uses_bsd_collector(self, mock_system):
        """Test that NetBSD platform uses BSD collector."""
        mock_system.return_value = "NetBSD"
        collector = HardwareCollector()

        assert isinstance(collector.collector, HardwareCollectorBSD)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_unsupported_platform_has_no_collector(self, mock_system):
        """Test that unsupported platform has no collector."""
        mock_system.return_value = "UnknownOS"
        collector = HardwareCollector()

        assert collector.collector is None


class TestHardwareCollectorGetAttr:
    """Tests for __getattr__ delegation."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_getattr_delegates_to_collector(self, mock_system):
        """Test that attribute access is delegated to collector."""
        mock_system.return_value = "Linux"
        collector = HardwareCollector()

        # Access a method that exists on the collector
        assert hasattr(collector, "get_cpu_info")
        assert callable(collector.get_cpu_info)

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_getattr_raises_for_missing_attribute(self, mock_system):
        """Test that missing attribute raises AttributeError."""
        mock_system.return_value = "UnknownOS"
        collector = HardwareCollector()

        with pytest.raises(AttributeError):
            _ = collector.nonexistent_method

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_getattr_with_unsupported_platform_raises(self, mock_system):
        """Test that attribute access on unsupported platform raises."""
        mock_system.return_value = "UnknownOS"
        collector = HardwareCollector()

        with pytest.raises(AttributeError) as exc_info:
            _ = collector.get_cpu_info

        assert "HardwareCollector" in str(exc_info.value)


class TestHardwareCollectorGetHardwareInfo:
    """Tests for get_hardware_info method."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_get_hardware_info_unsupported_platform(self, mock_system):
        """Test hardware info for unsupported platform."""
        mock_system.return_value = "UnknownOS"
        collector = HardwareCollector()

        result = collector.get_hardware_info()

        assert "hardware_details" in result
        assert "storage_details" in result
        assert "network_details" in result
        assert result["storage_devices"] == []
        assert result["network_interfaces"] == []

        # Verify error message in hardware_details
        hw_details = json.loads(result["hardware_details"])
        assert "error" in hw_details
        assert "Unsupported platform" in hw_details["error"]

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_get_hardware_info_linux_success(self, mock_system):
        """Test successful hardware info on Linux."""
        mock_system.return_value = "Linux"

        cpu_info = {
            "vendor": "GenuineIntel",
            "model": "Intel Core i7",
            "cores": 8,
            "threads": 16,
            "frequency_mhz": 3600,
        }
        memory_info = {"total_mb": 16384, "available_mb": 8192}
        storage_info = [
            {"name": "sda", "size": "500G", "mount_point": "/", "is_physical": True}
        ]
        network_info = [{"name": "eth0", "mac_address": "00:11:22:33:44:55"}]

        with patch.object(
            HardwareCollectorLinux, "get_cpu_info", return_value=cpu_info
        ):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value=memory_info
            ):
                with patch.object(
                    HardwareCollectorLinux,
                    "get_storage_info",
                    return_value=storage_info,
                ):
                    with patch.object(
                        HardwareCollectorLinux,
                        "get_network_info",
                        return_value=network_info,
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        assert result["cpu_vendor"] == "GenuineIntel"
        assert result["cpu_model"] == "Intel Core i7"
        assert result["cpu_cores"] == 8
        assert result["cpu_threads"] == 16
        assert result["cpu_frequency_mhz"] == 3600
        assert result["memory_total_mb"] == 16384
        assert result["memory_available_mb"] == 8192
        assert result["storage_devices"] == storage_info
        assert result["network_interfaces"] == network_info

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_get_hardware_info_handles_none_values(self, mock_system):
        """Test hardware info handles None values correctly."""
        mock_system.return_value = "Linux"

        cpu_info = {
            "vendor": "Intel",
            "model": "Unknown",
            "cores": None,  # Can be None
            "threads": None,
            "frequency_mhz": None,
        }
        memory_info = {}  # Empty dict
        storage_info = []
        network_info = []

        with patch.object(
            HardwareCollectorLinux, "get_cpu_info", return_value=cpu_info
        ):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value=memory_info
            ):
                with patch.object(
                    HardwareCollectorLinux,
                    "get_storage_info",
                    return_value=storage_info,
                ):
                    with patch.object(
                        HardwareCollectorLinux,
                        "get_network_info",
                        return_value=network_info,
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        assert result["cpu_vendor"] == "Intel"
        assert result["cpu_cores"] is None
        assert result["cpu_threads"] is None
        assert result["cpu_frequency_mhz"] is None

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_get_hardware_info_exception_handling(self, mock_system):
        """Test hardware info handles exceptions gracefully."""
        mock_system.return_value = "Linux"

        with patch.object(
            HardwareCollectorLinux, "get_cpu_info", side_effect=Exception("CPU error")
        ):
            collector = HardwareCollector()
            result = collector.get_hardware_info()

        assert "hardware_details" in result
        hw_details = json.loads(result["hardware_details"])
        assert "error" in hw_details

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_get_hardware_info_json_serialization(self, mock_system):
        """Test that hardware info is JSON serializable."""
        mock_system.return_value = "Linux"

        cpu_info = {"vendor": "Intel", "model": "Core i7", "cores": 8}
        memory_info = {"total_mb": 16384}
        storage_info = [{"name": "sda", "size": "500G"}]
        network_info = [{"name": "eth0", "mac_address": "00:11:22:33:44:55"}]

        with patch.object(
            HardwareCollectorLinux, "get_cpu_info", return_value=cpu_info
        ):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value=memory_info
            ):
                with patch.object(
                    HardwareCollectorLinux,
                    "get_storage_info",
                    return_value=storage_info,
                ):
                    with patch.object(
                        HardwareCollectorLinux,
                        "get_network_info",
                        return_value=network_info,
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        # Should be able to parse hardware_details JSON
        hw_details = json.loads(result["hardware_details"])
        assert "cpu" in hw_details
        assert "memory" in hw_details

        # Should be able to parse storage_details JSON
        storage_details = json.loads(result["storage_details"])
        assert isinstance(storage_details, list)

        # Should be able to parse network_details JSON
        network_details = json.loads(result["network_details"])
        assert isinstance(network_details, list)


class TestHardwareCollectorIntegration:
    """Integration tests for hardware collection."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_darwin_full_integration(self, mock_system):
        """Test full integration on macOS."""
        mock_system.return_value = "Darwin"

        hardware_data = {
            "SPHardwareDataType": [
                {
                    "chip_type": "Apple M1",
                    "number_processors": 8,
                    "physical_memory": "16 GB",
                    "current_processor_speed": "",
                }
            ]
        }

        storage_data = {
            "SPStorageDataType": [
                {
                    "_name": "Macintosh HD",
                    "bsd_name": "disk1s1",
                    "mount_point": "/",
                    "file_system": "APFS",
                    "physical_drive": {"device_name": "APPLE SSD"},
                }
            ]
        }

        network_data = {
            "SPNetworkDataType": [
                {
                    "_name": "Ethernet",
                    "interface": "en0",
                    "type": "Ethernet",
                    "hardware": "Ethernet",
                }
            ]
        }

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "SPHardwareDataType" in cmd:
                result.stdout = json.dumps(hardware_data)
            elif "SPStorageDataType" in cmd:
                result.stdout = json.dumps(storage_data)
            elif "SPNetworkDataType" in cmd:
                result.stdout = json.dumps(network_data)
            elif "sysctl" in cmd:
                result.stdout = "3200000000"
            elif "ifconfig" in cmd:
                result.stdout = (
                    "en0: flags=8863<UP,BROADCAST,RUNNING>\n\tether 00:11:22:33:44:55\n"
                )
            elif "df" in cmd:
                result.stdout = ""
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            collector = HardwareCollector()
            result = collector.get_hardware_info()

        assert result["cpu_vendor"] == "Apple"
        assert result["cpu_cores"] == 8
        assert result["memory_total_mb"] == 16384

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_windows_full_integration(self, mock_system):
        """Test full integration on Windows."""
        mock_system.return_value = "Windows"

        cpu_output = """Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors
PC,GenuineIntel,3600,Intel Core i7,8,16
"""
        memory_output = """Node,TotalPhysicalMemory
PC,17179869184
"""
        diskdrive_output = """Node,DeviceID,InterfaceType,Model,Size
PC,\\\\.\\PHYSICALDRIVE0,SCSI,Samsung SSD,500107862016
"""
        logicaldisk_output = """Node,DeviceID,FileSystem,FreeSpace,Size,VolumeName
PC,C:,NTFS,250000000000,500000000000,Windows
"""
        ipconfig_output = """
Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Intel(R) Ethernet
   Physical Address. . . . . . . . . : 00-11-22-33-44-55
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "cpu" in cmd:
                result.stdout = cpu_output
            elif "computersystem" in cmd:
                result.stdout = memory_output
            elif "diskdrive" in cmd:
                result.stdout = diskdrive_output
            elif "logicaldisk" in cmd:
                result.stdout = logicaldisk_output
            elif "ipconfig" in cmd:
                result.stdout = ipconfig_output
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            collector = HardwareCollector()
            result = collector.get_hardware_info()

        assert result["cpu_vendor"] == "GenuineIntel"
        assert result["cpu_cores"] == 8
        assert result["cpu_threads"] == 16
        assert result["memory_total_mb"] == 16384


class TestHardwareCollectorStorageHandling:
    """Tests for storage information handling."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_storage_info_as_dict_is_converted_to_empty_list(self, mock_system):
        """Test that dict storage info results in empty storage_devices list."""
        mock_system.return_value = "Linux"

        # If storage_info is somehow a dict instead of list
        storage_info = {"error": "some error"}

        with patch.object(HardwareCollectorLinux, "get_cpu_info", return_value={}):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value={}
            ):
                with patch.object(
                    HardwareCollectorLinux,
                    "get_storage_info",
                    return_value=storage_info,
                ):
                    with patch.object(
                        HardwareCollectorLinux, "get_network_info", return_value=[]
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        # storage_devices should be empty list when storage_info is not a list
        assert result["storage_devices"] == []


class TestHardwareCollectorNetworkHandling:
    """Tests for network information handling."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_network_info_as_dict_is_converted_to_empty_list(self, mock_system):
        """Test that dict network info results in empty network_interfaces list."""
        mock_system.return_value = "Linux"

        # If network_info is somehow a dict instead of list
        network_info = {"error": "some error"}

        with patch.object(HardwareCollectorLinux, "get_cpu_info", return_value={}):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value={}
            ):
                with patch.object(
                    HardwareCollectorLinux, "get_storage_info", return_value=[]
                ):
                    with patch.object(
                        HardwareCollectorLinux,
                        "get_network_info",
                        return_value=network_info,
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        # network_interfaces should be empty list when network_info is not a list
        assert result["network_interfaces"] == []


class TestHardwareCollectorCpuFieldExtraction:
    """Tests for CPU field extraction."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_cpu_fields_extracted_correctly(self, mock_system):
        """Test that CPU fields are correctly extracted."""
        mock_system.return_value = "Linux"

        cpu_info = {
            "vendor": "AuthenticAMD",
            "model": "AMD Ryzen 9 5900X",
            "cores": 12,
            "threads": 24,
            "frequency_mhz": 4800,
        }

        with patch.object(
            HardwareCollectorLinux, "get_cpu_info", return_value=cpu_info
        ):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value={}
            ):
                with patch.object(
                    HardwareCollectorLinux, "get_storage_info", return_value=[]
                ):
                    with patch.object(
                        HardwareCollectorLinux, "get_network_info", return_value=[]
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        assert result["cpu_vendor"] == "AuthenticAMD"
        assert result["cpu_model"] == "AMD Ryzen 9 5900X"
        assert result["cpu_cores"] == 12
        assert result["cpu_threads"] == 24
        assert result["cpu_frequency_mhz"] == 4800

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_missing_cpu_fields_default_to_empty_or_none(self, mock_system):
        """Test that missing CPU fields default appropriately."""
        mock_system.return_value = "Linux"

        cpu_info = {}  # Empty CPU info

        with patch.object(
            HardwareCollectorLinux, "get_cpu_info", return_value=cpu_info
        ):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value={}
            ):
                with patch.object(
                    HardwareCollectorLinux, "get_storage_info", return_value=[]
                ):
                    with patch.object(
                        HardwareCollectorLinux, "get_network_info", return_value=[]
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        assert result["cpu_vendor"] == ""
        assert result["cpu_model"] == ""
        assert result["cpu_cores"] is None
        assert result["cpu_threads"] is None
        assert result["cpu_frequency_mhz"] is None


class TestHardwareCollectorMemoryFieldExtraction:
    """Tests for memory field extraction."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_memory_fields_extracted_correctly(self, mock_system):
        """Test that memory fields are correctly extracted."""
        mock_system.return_value = "Linux"

        memory_info = {"total_mb": 32768, "available_mb": 16384}

        with patch.object(HardwareCollectorLinux, "get_cpu_info", return_value={}):
            with patch.object(
                HardwareCollectorLinux, "get_memory_info", return_value=memory_info
            ):
                with patch.object(
                    HardwareCollectorLinux, "get_storage_info", return_value=[]
                ):
                    with patch.object(
                        HardwareCollectorLinux, "get_network_info", return_value=[]
                    ):
                        collector = HardwareCollector()
                        result = collector.get_hardware_info()

        assert result["memory_total_mb"] == 32768
        assert result["memory_available_mb"] == 16384


class TestHardwareCollectorLogger:
    """Tests for logger initialization."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_logger_is_created(self, mock_system):
        """Test that logger is created on initialization."""
        mock_system.return_value = "Linux"
        collector = HardwareCollector()

        assert hasattr(collector, "logger")
        assert collector.logger is not None


class TestHardwareCollectorSystemAttribute:
    """Tests for system attribute."""

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_system_attribute_is_set(self, mock_system):
        """Test that system attribute is set on initialization."""
        mock_system.return_value = "Linux"
        collector = HardwareCollector()

        assert collector.system == "Linux"

    @patch("src.sysmanage_agent.collection.hardware_collection.platform.system")
    def test_system_attribute_darwin(self, mock_system):
        """Test system attribute for Darwin."""
        mock_system.return_value = "Darwin"
        collector = HardwareCollector()

        assert collector.system == "Darwin"
