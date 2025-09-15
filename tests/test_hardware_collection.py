"""
Tests for the hardware collection module.
"""

# pylint: disable=protected-access

import json
from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.collection.hardware_collection import HardwareCollector


class TestHardwareCollector:
    """Test hardware information collection functionality."""

    @pytest.fixture
    def hardware_collector(self):
        """Create a hardware collector instance for testing."""
        return HardwareCollector()

    def test_hardware_collector_initialization(self, hardware_collector):
        """Test that HardwareCollector initializes correctly."""
        assert hardware_collector is not None
        assert hasattr(hardware_collector, "logger")

    @patch("platform.system")
    def test_get_hardware_info_unsupported_platform(
        self, mock_system, hardware_collector
    ):
        """Test hardware collection for unsupported platform."""
        mock_system.return_value = "UnsupportedOS"

        result = hardware_collector.get_hardware_info()

        assert "hardware_details" in result
        assert "storage_details" in result
        assert "network_details" in result

        # Check that error is properly handled
        hardware_details = json.loads(result["hardware_details"])
        assert "error" in hardware_details
        assert "UnsupportedOS" in hardware_details["error"]

    @patch("platform.system")
    @patch("subprocess.run")
    def test_get_macos_cpu_info_success(
        self, mock_run, mock_system, hardware_collector
    ):
        """Test macOS CPU information collection."""
        mock_system.return_value = "Darwin"

        # Mock system_profiler output
        mock_cpu_output = {
            "SPHardwareDataType": [
                {
                    "chip_type": "Apple M3 Max",
                    "cpu_type": "Apple M3 Max",
                    "number_processors": "proc 14:10:4",
                    "current_processor_speed": "4.05 GHz",
                }
            ]
        }

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(mock_cpu_output)

        cpu_info = hardware_collector._get_macos_cpu_info()

        assert cpu_info["vendor"] == "Apple"
        assert cpu_info["model"] == "Apple M3 Max"
        assert cpu_info["cores"] == 14
        assert cpu_info["frequency_mhz"] == 4050

    @patch("platform.system")
    @patch("subprocess.run")
    def test_get_macos_memory_info_success(
        self, mock_run, mock_system, hardware_collector
    ):
        """Test macOS memory information collection."""
        mock_system.return_value = "Darwin"

        # Mock system_profiler output
        mock_memory_output = {"SPHardwareDataType": [{"physical_memory": "32 GB"}]}

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps(mock_memory_output)

        memory_info = hardware_collector._get_macos_memory_info()

        assert memory_info["total_mb"] == 32768  # 32 GB = 32768 MB

    @patch("platform.system")
    @patch("subprocess.run")
    def test_get_macos_storage_info_with_capacity(
        self, mock_run, mock_system, hardware_collector
    ):
        """Test macOS storage information collection with capacity data."""
        mock_system.return_value = "Darwin"

        # Mock system_profiler output
        mock_storage_output = {
            "SPStorageDataType": [
                {
                    "_name": "Macintosh HD",
                    "bsd_name": "disk3s1s1",
                    "mount_point": "/",
                    "file_system": "APFS",
                    "physical_drive": {"device_name": "APPLE SSD AP1024Z"},
                }
            ]
        }

        # Mock df output
        mock_df_output = "Filesystem     1K-blocks      Used Available Capacity iused ifree %iused  Mounted on\n/dev/disk3s1s1 971350016 465678384 502983888    49% 2935063 2514919440    0%   /"

        # Set up multiple calls to subprocess.run
        def side_effect(*args, **kwargs):
            mock_result = Mock()
            mock_result.returncode = 0
            if "system_profiler" in args[0]:
                mock_result.stdout = json.dumps(mock_storage_output)
            elif "df" in args[0]:
                mock_result.stdout = mock_df_output
            return mock_result

        mock_run.side_effect = side_effect

        storage_info = hardware_collector._get_macos_storage_info()

        assert len(storage_info) > 0
        device = storage_info[0]
        assert device["name"] == "Macintosh HD"
        assert device["mount_point"] == "/"
        assert device["file_system"] == "APFS"
        assert device["capacity_bytes"] == 994662416384  # 971350016 * 1024
        assert device["used_bytes"] == 476854665216  # 465678384 * 1024
        assert device["available_bytes"] == 515055501312  # 502983888 * 1024

    @patch("platform.system")
    def test_get_linux_cpu_info_with_lscpu(self, mock_system, hardware_collector):
        """Test Linux CPU information collection using lscpu."""
        mock_system.return_value = "Linux"

        # Mock lscpu output
        lscpu_output = """Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              8
Thread(s) per core:  2
Core(s) per socket:  4
Socket(s):           1
Vendor ID:           GenuineIntel
CPU family:          6
Model:               142
Model name:          Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
CPU MHz:             1800.000
"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = lscpu_output

            cpu_info = hardware_collector._get_linux_cpu_info()

            assert cpu_info["vendor"] == "GenuineIntel"
            assert cpu_info["model"] == "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
            assert cpu_info["threads"] == 8
            assert cpu_info["cores"] == 4
            assert cpu_info["frequency_mhz"] == 1800

    @patch("platform.system")
    def test_get_linux_memory_info(self, mock_system, hardware_collector):
        """Test Linux memory information collection."""
        mock_system.return_value = "Linux"

        meminfo_content = """MemTotal:       16777216 kB
MemFree:         8388608 kB
MemAvailable:   12582912 kB
"""

        with patch("builtins.open", mock_open(read_data=meminfo_content)):
            memory_info = hardware_collector._get_linux_memory_info()

            assert memory_info["total_mb"] == 16384  # 16777216 kB / 1024

    @patch("platform.system")
    @patch("subprocess.run")
    def test_get_windows_cpu_info_success(
        self, mock_run, mock_system, hardware_collector
    ):
        """Test Windows CPU information collection."""
        mock_system.return_value = "Windows"

        # Mock wmic output - order matches actual wmic csv output
        wmic_output = "Node,Manufacturer,MaxClockSpeed,Name,NumberOfCores,NumberOfLogicalProcessors\nDESKTOP-TEST,Intel,3200,Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz,8,8"

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = wmic_output

        cpu_info = hardware_collector._get_windows_cpu_info()

        assert cpu_info["frequency_mhz"] == 3200
        assert cpu_info["vendor"] == "Intel"
        assert cpu_info["model"] == "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"
        assert cpu_info["cores"] == 8
        assert cpu_info["threads"] == 8

    @patch("platform.system")
    def test_get_bsd_cpu_info_success(self, mock_system, hardware_collector):
        """Test BSD CPU information collection."""
        mock_system.return_value = "FreeBSD"

        with patch("subprocess.run") as mock_run:
            # Mock multiple sysctl calls
            def side_effect(*args, **kwargs):
                mock_result = Mock()
                mock_result.returncode = 0
                if "hw.model" in args[0]:
                    mock_result.stdout = "Intel(R) Xeon(R) CPU E5-2680 v3 @ 2.50GHz"
                elif "hw.ncpu" in args[0]:
                    mock_result.stdout = "24"
                elif "hw.ncpuonline" in args[0]:
                    mock_result.stdout = "24"
                elif "hw.cpuspeed" in args[0]:
                    mock_result.stdout = "2500"
                return mock_result

            mock_run.side_effect = side_effect

            cpu_info = hardware_collector._get_bsd_cpu_info()

            assert "Intel" in cpu_info["model"]
            assert cpu_info["vendor"] == "Intel"
            assert cpu_info["threads"] == 24
            assert cpu_info["cores"] == 24
            assert cpu_info["frequency_mhz"] == 2500

    @patch("platform.system")
    def test_hardware_info_integration(self, mock_system, hardware_collector):
        """Test complete hardware information collection integration."""
        mock_system.return_value = "Darwin"

        # Mock all the macOS methods
        with patch.object(
            hardware_collector, "_get_macos_cpu_info"
        ) as mock_cpu, patch.object(
            hardware_collector, "_get_macos_memory_info"
        ) as mock_memory, patch.object(
            hardware_collector, "_get_macos_storage_info"
        ) as mock_storage, patch.object(
            hardware_collector, "_get_macos_network_info"
        ) as mock_network:

            # Set up mock returns
            mock_cpu.return_value = {"vendor": "Apple", "model": "M3 Max", "cores": 14}
            mock_memory.return_value = {"total_mb": 32768}
            mock_storage.return_value = [{"name": "SSD", "capacity_bytes": 1000000000}]
            mock_network.return_value = [
                {"name": "en0", "mac_address": "aa:bb:cc:dd:ee:ff"}
            ]

            result = hardware_collector.get_hardware_info()

            # Check that all data is present
            assert result["cpu_vendor"] == "Apple"
            assert result["cpu_model"] == "M3 Max"
            assert result["cpu_cores"] == 14
            assert result["memory_total_mb"] == 32768

            # Check storage and network arrays
            assert len(result["storage_devices"]) == 1
            assert len(result["network_interfaces"]) == 1

            # Check JSON fields for backward compatibility
            assert "storage_details" in result
            assert "network_details" in result
            assert "hardware_details" in result

            # Verify JSON fields can be parsed
            storage_details = json.loads(result["storage_details"])
            assert len(storage_details) == 1
            assert storage_details[0]["name"] == "SSD"

    def test_timestamp_generation(self, hardware_collector):
        """Test timestamp generation format."""
        timestamp = hardware_collector._get_timestamp()

        # Should be ISO format with timezone
        assert isinstance(timestamp, str)
        assert "T" in timestamp
        assert timestamp.endswith("+00:00") or timestamp.endswith("Z")
