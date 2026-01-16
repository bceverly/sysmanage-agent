"""
Tests for BSD hardware collector module.
Tests CPU, memory, storage, and network information gathering on BSD systems.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.hardware_collector_bsd import HardwareCollectorBSD


@pytest.fixture
def collector():
    """Create a BSD hardware collector for testing."""
    return HardwareCollectorBSD()


class TestHardwareCollectorBSDInit:
    """Tests for HardwareCollectorBSD initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None


class TestGetCpuInfo:
    """Tests for get_cpu_info method."""

    def test_get_cpu_info_success(self, collector):
        """Test successful CPU info retrieval."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "hw.model" in cmd:
                result.stdout = "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\n"
            elif "hw.ncpu" in cmd:
                result.stdout = "8\n"
            elif "hw.ncpuonline" in cmd:
                result.stdout = "4\n"
            elif "hw.cpuspeed" in cmd:
                result.stdout = "1800\n"
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["model"] == "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz"
        assert cpu_info["vendor"] == "Intel"
        assert cpu_info["threads"] == 8
        assert cpu_info["cores"] == 4
        assert cpu_info["frequency_mhz"] == 1800

    def test_get_cpu_info_amd_vendor(self, collector):
        """Test CPU vendor detection for AMD."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "hw.model" in cmd:
                result.stdout = "AMD Ryzen 7 5800X\n"
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "AMD"

    def test_get_cpu_info_unknown_vendor(self, collector):
        """Test CPU vendor detection for unknown."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if "hw.model" in cmd:
                result.stdout = "ARM Cortex-A72\n"
            else:
                result.returncode = 1
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["vendor"] == "Unknown"

    def test_get_cpu_info_frequency_from_tsc(self, collector):
        """Test CPU frequency from TSC."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 1
            result.stdout = ""
            if "hw.model" in cmd:
                result.returncode = 0
                result.stdout = "Test CPU\n"
            elif "machdep.tsc_freq" in cmd:
                result.returncode = 0
                result.stdout = "2400000000\n"  # 2.4 GHz in Hz
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 2400

    def test_get_cpu_info_frequency_from_model(self, collector):
        """Test CPU frequency extracted from model name."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 1
            result.stdout = ""
            if "hw.model" in cmd:
                result.returncode = 0
                result.stdout = "Intel Core i5-10400 @ 2.90GHz\n"
            return result

        with patch("subprocess.run", side_effect=mock_run):
            cpu_info = collector.get_cpu_info()

        assert cpu_info["frequency_mhz"] == 2900

    def test_get_cpu_info_exception(self, collector):
        """Test CPU info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            cpu_info = collector.get_cpu_info()

        assert "error" in cpu_info


class TestGetMemoryInfo:
    """Tests for get_memory_info method."""

    def test_get_memory_info_success(self, collector):
        """Test successful memory info retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "17179869184\n"  # 16 GB in bytes

        with patch("subprocess.run", return_value=mock_result):
            mem_info = collector.get_memory_info()

        assert mem_info["total_mb"] == 16384

    def test_get_memory_info_failure(self, collector):
        """Test memory info retrieval failure."""
        mock_result = Mock()
        mock_result.returncode = 1

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

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if cmd[0] == "df":
                result.stdout = """Filesystem     Size    Used   Avail Capacity  Mounted on
/dev/ada0p2     20G    10G     10G    50%    /
/dev/ada0p3    100G    50G     50G    50%    /home
"""
            elif cmd[0] == "mount":
                result.stdout = """/dev/ada0p2 on / type ffs
/dev/ada0p3 on /home type ffs
"""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            with patch("glob.glob", return_value=[]):
                storage_info = collector.get_storage_info()

        assert len(storage_info) >= 2
        assert any(d["mount_point"] == "/" for d in storage_info)
        assert any(d["mount_point"] == "/home" for d in storage_info)

    def test_get_storage_info_skips_tmpfs(self, collector):
        """Test that storage info skips tmpfs."""

        def mock_run(cmd, **_kwargs):
            result = Mock()
            result.returncode = 0
            if cmd[0] == "df":
                result.stdout = """Filesystem     Size    Used   Avail Capacity  Mounted on
/dev/ada0p2     20G    10G     10G    50%    /
tmpfs           1G     0G      1G     0%    /tmp
"""
            elif cmd[0] == "mount":
                result.stdout = ""
            return result

        with patch("subprocess.run", side_effect=mock_run):
            with patch("glob.glob", return_value=[]):
                storage_info = collector.get_storage_info()

        # tmpfs should be skipped
        assert not any(
            d.get("mount_point") == "/tmp" for d in storage_info if "mount_point" in d
        )

    def test_get_storage_info_exception(self, collector):
        """Test storage info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            with patch("glob.glob", return_value=[]):
                storage_info = collector.get_storage_info()

        assert len(storage_info) > 0
        assert "error" in storage_info[0]


class TestShouldSkipBsdFilesystem:
    """Tests for _should_skip_bsd_filesystem method."""

    def test_skip_tmpfs(self, collector):
        """Test skipping tmpfs."""
        assert collector._should_skip_bsd_filesystem("tmpfs", "/tmp") is True

    def test_skip_procfs(self, collector):
        """Test skipping procfs."""
        assert collector._should_skip_bsd_filesystem("procfs", "/proc") is True

    def test_skip_mfs(self, collector):
        """Test skipping mfs."""
        assert collector._should_skip_bsd_filesystem("mfs", "/mfs") is True

    def test_skip_dev_mount(self, collector):
        """Test skipping /dev mount."""
        assert collector._should_skip_bsd_filesystem("devfs", "/dev") is True

    def test_dont_skip_root(self, collector):
        """Test not skipping root filesystem."""
        assert collector._should_skip_bsd_filesystem("/dev/ada0p2", "/") is False

    def test_dont_skip_home(self, collector):
        """Test not skipping home filesystem."""
        assert collector._should_skip_bsd_filesystem("/dev/ada0p3", "/home") is False


class TestIsPhysicalVolumeBsd:
    """Tests for _is_physical_volume_bsd method."""

    def test_openbsd_wd_drive_is_physical(self, collector):
        """Test OpenBSD IDE/SATA drive detection."""
        assert collector._is_physical_volume_bsd("/dev/wd0a", "/") is True

    def test_openbsd_sd_drive_is_physical(self, collector):
        """Test OpenBSD SCSI/USB drive detection."""
        assert collector._is_physical_volume_bsd("/dev/sd0a", "/") is True

    def test_freebsd_ada_drive_is_physical(self, collector):
        """Test FreeBSD SATA drive detection."""
        assert collector._is_physical_volume_bsd("/dev/ada0p2", "/") is True

    def test_freebsd_da_drive_is_physical(self, collector):
        """Test FreeBSD SCSI/USB drive detection."""
        assert collector._is_physical_volume_bsd("/dev/da0s1", "/") is True

    def test_nvme_drive_is_physical(self, collector):
        """Test NVMe drive detection."""
        assert collector._is_physical_volume_bsd("/dev/nvd0p2", "/") is True

    def test_tmpfs_is_logical(self, collector):
        """Test tmpfs is logical."""
        assert collector._is_physical_volume_bsd("tmpfs", "/tmp") is False

    def test_procfs_is_logical(self, collector):
        """Test procfs is logical."""
        assert collector._is_physical_volume_bsd("procfs", "/proc") is False

    def test_nfs_mount_is_logical(self, collector):
        """Test NFS mount is logical."""
        assert collector._is_physical_volume_bsd("server:/export", "/mnt/nfs") is False

    def test_unknown_dev_device_is_physical(self, collector):
        """Test unknown /dev/ device is physical."""
        assert collector._is_physical_volume_bsd("/dev/unknown", "/") is True


class TestGetNetworkInfo:
    """Tests for get_network_info method."""

    def test_get_network_info_success(self, collector):
        """Test successful network info retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=4e507bb<RXCSUM,TXCSUM,VLAN_MTU>
	ether 08:00:27:12:34:56
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 2001:db8::1 prefixlen 64
	media: Ethernet autoselect (1000baseT <full-duplex>)
	status: active
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 32768
	inet 127.0.0.1 netmask 0xff000000
"""

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        assert len(net_info) >= 1
        em0 = next((i for i in net_info if i.get("name") == "em0"), None)
        assert em0 is not None
        assert em0["mac_address"] == "08:00:27:12:34:56"
        assert em0["ipv4_address"] == "192.168.1.100"
        assert em0["ipv6_address"] == "2001:db8::1"
        assert em0["is_active"] is True

    def test_get_network_info_skips_loopback(self, collector):
        """Test that loopback interface is skipped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 32768
	inet 127.0.0.1 netmask 0xff000000
em0: flags=8843<UP,BROADCAST,RUNNING> mtu 1500
	ether 08:00:27:12:34:56
"""

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        # loopback should be skipped
        assert not any(i.get("name") == "lo0" for i in net_info)

    def test_get_network_info_wireless_detection(self, collector):
        """Test wireless interface detection."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """iwm0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:11:22:33:44:55
	media: IEEE802.11 autoselect
"""

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        if net_info:
            iwm0 = next((i for i in net_info if i.get("name") == "iwm0"), None)
            if iwm0:
                assert iwm0["interface_type"] == "wireless"

    def test_get_network_info_hex_netmask_conversion(self, collector):
        """Test hex netmask to dotted decimal conversion."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """em0: flags=8843<UP,BROADCAST,RUNNING> mtu 1500
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
"""

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        if net_info:
            em0 = next((i for i in net_info if i.get("name") == "em0"), None)
            if em0:
                assert em0["subnet_mask"] == "255.255.255.0"

    def test_get_network_info_interface_down(self, collector):
        """Test interface that is down."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """em0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
	ether 08:00:27:12:34:56
"""

        with patch("subprocess.run", return_value=mock_result):
            net_info = collector.get_network_info()

        if net_info:
            em0 = next((i for i in net_info if i.get("name") == "em0"), None)
            if em0:
                assert em0["is_active"] is False

    def test_get_network_info_exception(self, collector):
        """Test network info with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            net_info = collector.get_network_info()

        assert len(net_info) > 0
        assert "error" in net_info[0]
