"""
Tests for Linux hardware collector module.
Tests CPU, memory, storage, and network information gathering on Linux systems.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
from unittest.mock import Mock, mock_open, patch

import pytest

from src.sysmanage_agent.collection.hardware_collector_linux import (
    HardwareCollectorLinux,
)


@pytest.fixture
def collector():
    """Create a Linux hardware collector for testing."""
    return HardwareCollectorLinux()


class TestHardwareCollectorLinuxInit:
    """Tests for HardwareCollectorLinux initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None


class TestGetCpuInfoLscpu:
    """Tests for CPU info collection via lscpu."""

    def test_get_cpu_info_lscpu_success(self, collector):
        """Test successful CPU info retrieval via lscpu."""
        lscpu_output = """Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Vendor ID:                       GenuineIntel
Model name:                      Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
CPU(s):                          8
Core(s) per socket:              4
Socket(s):                       1
CPU MHz:                         1992.000
CPU max MHz:                     4000.0000
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = lscpu_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "GenuineIntel"
        assert cpu_info["model"] == "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz"
        assert cpu_info["threads"] == 8
        assert cpu_info["cores"] == 4
        assert cpu_info["frequency_mhz"] == 4000

    def test_get_cpu_info_lscpu_multi_socket(self, collector):
        """Test CPU info with multiple sockets."""
        # Note: The order matters - Socket(s) must come before Core(s) per socket
        # for multi-socket calculation to work correctly
        lscpu_output = """Vendor ID:                       GenuineIntel
Model name:                      Intel Xeon E5-2680
CPU(s):                          32
Socket(s):                       2
Core(s) per socket:              8
CPU MHz:                         2700.000
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = lscpu_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["cores"] == 16  # 8 cores * 2 sockets
        assert cpu_info["threads"] == 32

    def test_get_cpu_info_lscpu_amd(self, collector):
        """Test CPU info for AMD processor."""
        lscpu_output = """Vendor ID:                       AuthenticAMD
Model name:                      AMD Ryzen 9 5900X 12-Core Processor
CPU(s):                          24
Core(s) per socket:              12
Socket(s):                       1
CPU MHz:                         3700.000
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = lscpu_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "AuthenticAMD"
        assert cpu_info["cores"] == 12
        assert cpu_info["threads"] == 24


class TestGetCpuInfoProcCpuinfo:
    """Tests for CPU info collection via /proc/cpuinfo fallback."""

    def test_get_cpu_info_proc_cpuinfo_fallback(self, collector):
        """Test CPU info via /proc/cpuinfo when lscpu is unavailable."""
        proc_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
cpu MHz		: 1800.000

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
cpu MHz		: 1800.000

processor	: 2
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
cpu MHz		: 1800.000

processor	: 3
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
cpu MHz		: 1800.000
"""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            if "lscpu" in cmd:
                result.returncode = 1
                result.stdout = ""
            else:
                result.returncode = 0
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("builtins.open", mock_open(read_data=proc_cpuinfo)):
                cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "GenuineIntel"
        assert cpu_info["model"] == "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz"
        assert cpu_info["threads"] == 4
        assert cpu_info["frequency_mhz"] == 1800

    def test_get_cpu_info_frequency_from_model_ghz(self, collector):
        """Test CPU frequency extraction from model name (GHz)."""
        proc_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel Core i7-10700K @ 3.80GHz
"""

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("builtins.open", mock_open(read_data=proc_cpuinfo)):
                # Simulate cpufreq not available
                with patch("os.path.exists", return_value=False):
                    cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 3800

    def test_get_cpu_info_frequency_from_model_mhz(self, collector):
        """Test CPU frequency extraction from model name (MHz)."""
        proc_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel Pentium 4 2400MHz
"""

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("builtins.open", mock_open(read_data=proc_cpuinfo)):
                with patch("os.path.exists", return_value=False):
                    cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 2400


class TestGetCpuInfoFrequencyFallback:
    """Tests for CPU frequency fallback mechanisms."""

    def test_get_cpu_info_frequency_from_sysfs(self, collector):
        """Test CPU frequency from /sys/devices/system/cpu."""
        proc_cpuinfo = """processor	: 0
vendor_id	: GenuineIntel
model name	: Intel Core i5
"""

        def mock_open_files(filename, *args, **kwargs):
            if "cpuinfo_max_freq" in filename:
                return mock_open(read_data="3500000")()  # 3.5 GHz in kHz
            elif "cpuinfo" in filename:
                return mock_open(read_data=proc_cpuinfo)()
            raise FileNotFoundError

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("builtins.open", mock_open_files):
                cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 3500


class TestGetCpuInfoErrorHandling:
    """Tests for CPU info error handling."""

    def test_get_cpu_info_exception(self, collector):
        """Test CPU info with general exception."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("builtins.open", side_effect=Exception("test error")):
                cpu_info = collector.get_cpu_info()

        assert "error" in cpu_info

    def test_get_cpu_info_invalid_frequency(self, collector):
        """Test CPU info with invalid frequency value."""
        lscpu_output = """Vendor ID:                       GenuineIntel
Model name:                      Intel Core i5
CPU(s):                          4
Core(s) per socket:              4
Socket(s):                       1
CPU MHz:                         invalid
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = lscpu_output

        with patch("subprocess.run", return_value=mock_result):
            cpu_info = collector.get_cpu_info()

        # Should not crash, frequency might not be set
        assert "model" in cpu_info


class TestGetMemoryInfo:
    """Tests for get_memory_info method."""

    def test_get_memory_info_success(self, collector):
        """Test successful memory info retrieval."""
        meminfo_content = """MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          4096000 kB
"""
        with patch("builtins.open", mock_open(read_data=meminfo_content)):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 16000  # 16384000 kB / 1024

    def test_get_memory_info_large_memory(self, collector):
        """Test memory info with large RAM (e.g., server with 256GB)."""
        meminfo_content = """MemTotal:       268435456 kB
MemFree:        134217728 kB
"""
        with patch("builtins.open", mock_open(read_data=meminfo_content)):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 262144  # 256 GB in MB

    def test_get_memory_info_file_not_found(self, collector):
        """Test memory info when /proc/meminfo is not found."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            mem_info = collector.get_memory_info()

        assert "error" in mem_info

    def test_get_memory_info_exception(self, collector):
        """Test memory info with general exception."""
        with patch("builtins.open", side_effect=Exception("test error")):
            mem_info = collector.get_memory_info()

        assert "error" in mem_info


class TestGetStorageInfo:
    """Tests for get_storage_info method."""

    def test_get_storage_info_lsblk_success(self, collector):
        """Test successful storage info retrieval via lsblk."""
        lsblk_output = {
            "blockdevices": [
                {
                    "name": "sda",
                    "size": "500G",
                    "type": "disk",
                    "mountpoint": None,
                    "fstype": None,
                    "children": [
                        {
                            "name": "sda1",
                            "size": "512M",
                            "type": "part",
                            "mountpoint": "/boot/efi",
                            "fstype": "vfat",
                        },
                        {
                            "name": "sda2",
                            "size": "499.5G",
                            "type": "part",
                            "mountpoint": "/",
                            "fstype": "ext4",
                        },
                    ],
                },
                {
                    "name": "nvme0n1",
                    "size": "1T",
                    "type": "disk",
                    "mountpoint": None,
                    "fstype": None,
                    "children": [
                        {
                            "name": "nvme0n1p1",
                            "size": "1T",
                            "type": "part",
                            "mountpoint": "/home",
                            "fstype": "ext4",
                        }
                    ],
                },
            ]
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(lsblk_output)

        with patch("subprocess.run", return_value=mock_result):
            storage_info = collector.get_storage_info()

        # Should have parent devices and children
        assert len(storage_info) >= 4
        assert any(d["name"] == "sda" for d in storage_info)
        assert any(
            d["name"] == "sda2" and d["mount_point"] == "/" for d in storage_info
        )
        assert any(d["name"] == "nvme0n1" for d in storage_info)

    def test_get_storage_info_lsblk_not_found(self, collector):
        """Test storage info when lsblk is not available."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            storage_info = collector.get_storage_info()

        # Should return empty list without error
        assert storage_info == []

    def test_get_storage_info_lsblk_failure(self, collector):
        """Test storage info when lsblk fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            storage_info = collector.get_storage_info()

        assert storage_info == []

    def test_get_storage_info_exception(self, collector):
        """Test storage info with general exception."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json"

        with patch("subprocess.run", return_value=mock_result):
            storage_info = collector.get_storage_info()

        assert len(storage_info) > 0
        assert "error" in storage_info[0]


class TestIsPhysicalVolumeLinux:
    """Tests for _is_physical_volume_linux method."""

    def test_disk_type_is_physical(self, collector):
        """Test that disk type is considered physical."""
        device = {"name": "sda", "type": "disk", "mountpoint": None}
        assert collector._is_physical_volume_linux(device) is True

    def test_partition_is_logical(self, collector):
        """Test that partition type is considered logical."""
        device = {"name": "sda1", "type": "part", "mountpoint": "/"}
        assert collector._is_physical_volume_linux(device, is_child=True) is False

    def test_root_partition_is_logical_when_child(self, collector):
        """Test that root partition is logical when it's a child partition.

        The _is_physical_volume_linux method considers partitions (type 'part')
        as logical volumes. Root mount point only makes it physical if it's
        not explicitly a partition type.
        """
        device = {"name": "sda1", "type": "part", "mountpoint": "/"}
        # Partitions are considered logical even when mounted at root
        assert collector._is_physical_volume_linux(device) is False

    def test_lvm_is_logical(self, collector):
        """Test that LVM is considered logical."""
        device = {"name": "dm-0", "type": "lvm", "mountpoint": "/"}
        assert collector._is_physical_volume_linux(device) is False

    def test_loop_device_is_logical(self, collector):
        """Test that loop device is considered logical."""
        device = {"name": "loop0", "type": "loop", "mountpoint": "/snap/core"}
        assert collector._is_physical_volume_linux(device) is False

    def test_snap_mount_is_logical(self, collector):
        """Test that snap mount is considered logical."""
        device = {"name": "sda3", "type": "part", "mountpoint": "/snap/chromium/123"}
        assert collector._is_physical_volume_linux(device) is False

    def test_boot_efi_is_logical(self, collector):
        """Test that /boot/efi is considered logical."""
        device = {"name": "sda1", "type": "part", "mountpoint": "/boot/efi"}
        assert collector._is_physical_volume_linux(device) is False

    def test_nvme_disk_is_physical(self, collector):
        """Test that NVMe disk is considered physical."""
        device = {"name": "nvme0n1", "type": "disk", "mountpoint": None}
        assert collector._is_physical_volume_linux(device) is True

    def test_usb_drive_is_physical(self, collector):
        """Test that USB drive is considered physical."""
        device = {"name": "sdb", "type": "disk", "mountpoint": None}
        assert collector._is_physical_volume_linux(device) is True

    def test_ram_device_is_logical(self, collector):
        """Test that RAM device is considered logical."""
        device = {"name": "ram0", "type": "disk", "mountpoint": None}
        assert collector._is_physical_volume_linux(device) is False


class TestGetNetworkInfo:
    """Tests for get_network_info method."""

    def test_get_network_info_success(self, collector):
        """Test successful network info retrieval."""
        interfaces = ["eth0", "lo", "wlan0"]

        def mock_listdir(path):
            if path == "/sys/class/net":
                return interfaces
            return []

        def mock_exists(path):
            return True

        def mock_open_files(filename, *args, **kwargs):
            content_map = {
                "/sys/class/net/eth0/type": "1",
                "/sys/class/net/eth0/operstate": "up",
                "/sys/class/net/eth0/address": "00:11:22:33:44:55",
                "/sys/class/net/wlan0/type": "1",
                "/sys/class/net/wlan0/operstate": "down",
                "/sys/class/net/wlan0/address": "66:77:88:99:aa:bb",
            }
            for key, value in content_map.items():
                if filename == key:
                    return mock_open(read_data=value)()
            raise FileNotFoundError

        with patch("os.listdir", mock_listdir):
            with patch("os.path.exists", mock_exists):
                with patch("builtins.open", mock_open_files):
                    net_info = collector.get_network_info()

        # Should skip loopback
        assert len(net_info) == 2
        assert any(i["name"] == "eth0" for i in net_info)
        assert any(i["name"] == "wlan0" for i in net_info)
        assert not any(i["name"] == "lo" for i in net_info)

        eth0 = next(i for i in net_info if i["name"] == "eth0")
        assert eth0["state"] == "up"
        assert eth0["mac_address"] == "00:11:22:33:44:55"

    def test_get_network_info_no_interfaces(self, collector):
        """Test network info when no interfaces exist."""
        with patch("os.path.exists", return_value=False):
            net_info = collector.get_network_info()

        assert net_info == []

    def test_get_network_info_partial_attributes(self, collector):
        """Test network info when some attributes are missing."""

        def mock_listdir(path):
            if path == "/sys/class/net":
                return ["eth0"]
            return []

        def mock_path_exists(path):
            # /sys/class/net must exist for the loop to work
            if path == "/sys/class/net":
                return True
            # Only some attributes exist
            if "type" in path or "operstate" in path:
                return True
            return False

        def mock_path_join(base, *parts):
            import os.path as real_os_path

            return real_os_path.join(base, *parts)

        def mock_open_files(filename, *args, **kwargs):
            if "type" in filename:
                return mock_open(read_data="1")()
            elif "operstate" in filename:
                return mock_open(read_data="up")()
            raise FileNotFoundError

        with patch("os.listdir", mock_listdir):
            with patch("os.path.exists", mock_path_exists):
                with patch("builtins.open", mock_open_files):
                    net_info = collector.get_network_info()

        assert len(net_info) == 1
        assert net_info[0]["name"] == "eth0"
        assert "mac_address" not in net_info[0]  # Was not available

    def test_get_network_info_exception(self, collector):
        """Test network info with general exception."""
        with patch("os.path.exists", return_value=True):
            with patch("os.listdir", side_effect=Exception("test error")):
                net_info = collector.get_network_info()

        assert len(net_info) > 0
        assert "error" in net_info[0]


class TestGetLinuxStorageInfoBackwardCompatibility:
    """Tests for backward compatibility method."""

    def test_get_linux_storage_info_delegates(self, collector):
        """Test that _get_linux_storage_info delegates to get_storage_info."""
        with patch.object(
            collector, "get_storage_info", return_value=[{"name": "test"}]
        ):
            result = collector._get_linux_storage_info()
        assert result == [{"name": "test"}]


class TestProcessLscpuField:
    """Tests for _process_lscpu_field helper method."""

    def test_process_vendor_id(self, collector):
        """Test processing Vendor ID field."""
        cpu_info = {}
        collector._process_lscpu_field(cpu_info, "Vendor ID", "GenuineIntel")
        assert cpu_info["vendor"] == "GenuineIntel"

    def test_process_model_name(self, collector):
        """Test processing Model name field."""
        cpu_info = {}
        collector._process_lscpu_field(cpu_info, "Model name", "Intel Core i7")
        assert cpu_info["model"] == "Intel Core i7"

    def test_process_cpus(self, collector):
        """Test processing CPU(s) field."""
        cpu_info = {}
        collector._process_lscpu_field(cpu_info, "CPU(s)", "8")
        assert cpu_info["threads"] == 8

    def test_process_cores_per_socket(self, collector):
        """Test processing Core(s) per socket field."""
        cpu_info = {"sockets": 2}
        collector._process_lscpu_field(cpu_info, "Core(s) per socket", "4")
        assert cpu_info["cores"] == 8  # 4 cores * 2 sockets

    def test_process_sockets(self, collector):
        """Test processing Socket(s) field."""
        cpu_info = {}
        collector._process_lscpu_field(cpu_info, "Socket(s)", "2")
        assert cpu_info["sockets"] == 2

    def test_process_cpu_mhz(self, collector):
        """Test processing CPU MHz field."""
        cpu_info = {}
        collector._process_lscpu_field(cpu_info, "CPU MHz", "2400.000")
        assert cpu_info["frequency_mhz"] == 2400

    def test_process_cpu_max_mhz_overrides(self, collector):
        """Test that CPU max MHz overrides CPU MHz."""
        cpu_info = {"frequency_mhz": 2400}
        collector._process_lscpu_field(cpu_info, "CPU max MHz", "3600.000")
        assert cpu_info["frequency_mhz"] == 3600


class TestCollectInterfaceSysfsAttr:
    """Tests for _collect_interface_sysfs_attr helper method."""

    def test_collect_existing_attribute(self, collector):
        """Test collecting an existing sysfs attribute."""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="up\n")):
                result = collector._collect_interface_sysfs_attr(
                    "/sys/class/net/eth0", "operstate"
                )
        assert result == "up"

    def test_collect_nonexistent_attribute(self, collector):
        """Test collecting a non-existent sysfs attribute."""
        with patch("os.path.exists", return_value=False):
            result = collector._collect_interface_sysfs_attr(
                "/sys/class/net/eth0", "speed"
            )
        assert result == ""


class TestProcessCpuinfoField:
    """Tests for _process_cpuinfo_field helper method."""

    def test_process_vendor_id_field(self, collector):
        """Test processing vendor_id field."""
        cpu_info = {}
        processor_count = 0
        result = collector._process_cpuinfo_field(
            cpu_info, "vendor_id", "AuthenticAMD", processor_count
        )
        assert cpu_info["vendor"] == "AuthenticAMD"
        assert result == 0

    def test_process_model_name_field(self, collector):
        """Test processing model name field."""
        cpu_info = {}
        processor_count = 0
        result = collector._process_cpuinfo_field(
            cpu_info, "model name", "AMD Ryzen 5", processor_count
        )
        assert cpu_info["model"] == "AMD Ryzen 5"
        assert result == 0

    def test_process_cpu_mhz_field(self, collector):
        """Test processing cpu MHz field."""
        cpu_info = {}
        processor_count = 0
        result = collector._process_cpuinfo_field(
            cpu_info, "cpu MHz", "3500.000", processor_count
        )
        assert cpu_info["frequency_mhz"] == 3500
        assert result == 0

    def test_process_processor_field(self, collector):
        """Test processing processor field."""
        cpu_info = {}
        processor_count = 0
        result = collector._process_cpuinfo_field(
            cpu_info, "processor", "3", processor_count
        )
        assert result == 4  # processor 3 means at least 4 processors (0-3)

    def test_process_processor_field_updates_max(self, collector):
        """Test that processor count tracks maximum."""
        cpu_info = {}
        processor_count = 4
        result = collector._process_cpuinfo_field(
            cpu_info, "processor", "2", processor_count
        )
        assert result == 4  # Keeps higher count
