"""
Comprehensive unit tests for diagnostics collection functionality.

Tests cover:
- CPU usage/load collection
- Memory usage collection
- Disk usage collection
- Process listing
- Service status collection
- System health indicators
- Multi-platform support (Linux, Windows, macOS)
- Error handling and edge cases
"""

# pylint: disable=protected-access,too-many-lines,unused-argument,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.diagnostics.diagnostic_collector import DiagnosticCollector

# Constants for patching
_PLATFORM_SYSTEM = (
    "src.sysmanage_agent.diagnostics.diagnostic_collector.platform.system"
)
_DIAG_AIOFILES_OPEN = (
    "src.sysmanage_agent.diagnostics.diagnostic_collector.aiofiles.open"
)
_DIAG_DATETIME = "src.sysmanage_agent.diagnostics.diagnostic_collector.datetime"


def _mock_aiofiles_open(read_data=""):
    """Create a mock for aiofiles.open that supports async context manager."""
    mock_file = AsyncMock()
    mock_file.read = AsyncMock(return_value=read_data)
    lines = [line + "\n" for line in read_data.split("\n")] if read_data else []
    mock_file.readlines = AsyncMock(return_value=lines)
    mock_file.write = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_file)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


def _mock_aiofiles_open_error(error=None):
    """Create a mock for aiofiles.open that raises on enter."""
    if error is None:
        error = IOError("File not found")
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(side_effect=error)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


class TestDiagnosticCollectorSetup:
    """Base setup for all diagnostic collector tests."""

    @pytest.fixture
    def mock_agent(self):
        """Create a comprehensive mock agent instance."""
        mock_agent = Mock()
        mock_agent.logger = Mock()
        mock_agent.system_ops = Mock()
        mock_agent.registration = Mock()
        mock_agent.running = True
        mock_agent.connected = True
        mock_agent.reconnect_attempts = 0
        mock_agent.last_ping = "2024-01-01T00:00:00Z"

        # Setup registration mock
        mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host",
            "platform": "Linux",
            "fqdn": "test-host.example.com",
            "ipv4": "192.168.1.100",
        }

        # Setup create_message and send_message
        mock_agent.create_message = Mock(
            return_value={"message_id": "msg-123", "message_type": "test"}
        )
        mock_agent.send_message = AsyncMock()

        return mock_agent

    @pytest.fixture
    def collector(self, mock_agent):
        """Create a DiagnosticCollector instance."""
        return DiagnosticCollector(mock_agent)


class TestCPUUsageLoadCollection(TestDiagnosticCollectorSetup):
    """Tests for CPU usage and load collection."""

    @pytest.mark.asyncio
    async def test_collect_process_info_cpu_data_linux(self, collector):
        """Test collecting CPU usage data on Linux."""
        cpu_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168340 11920 ?        Ss   Jan01   0:10 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]
www-data 12345 25.5  2.0 500000 160000 ?       S    10:00   5:30 /usr/sbin/apache2"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {
                    "success": True,
                    "result": {"stdout": cpu_output},
                },  # ps aux --sort=-%cpu
                {"success": True, "result": {"stdout": ""}},  # ps aux --sort=-%mem
                {
                    "success": True,
                    "result": {
                        "stdout": "10:00:00 up 5 days, 3:00,  1 user,  load average: 0.15, 0.10, 0.05"
                    },
                },  # uptime
                {
                    "success": True,
                    "result": {
                        "stdout": "              total        used        free\nMem:          16384        8192        8192"
                    },
                },  # free -h
            ]
        )

        result = await collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert "25.5" in result["top_processes_cpu"]
        assert "apache2" in result["top_processes_cpu"]

    @pytest.mark.asyncio
    async def test_collect_system_load_average(self, collector):
        """Test collecting system load average from uptime command."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": ""}},  # ps aux --sort=-%cpu
                {"success": True, "result": {"stdout": ""}},  # ps aux --sort=-%mem
                {
                    "success": True,
                    "result": {
                        "stdout": " 14:30:00 up 10 days,  2:30,  3 users,  load average: 1.50, 1.25, 0.95"
                    },
                },
                {"success": True, "result": {"stdout": ""}},  # free -h
            ]
        )

        result = await collector._collect_process_info()

        assert "system_load" in result
        assert "load average: 1.50, 1.25, 0.95" in result["system_load"]

    @pytest.mark.asyncio
    async def test_collect_cpu_high_load(self, collector):
        """Test collecting data when system has high CPU load."""
        high_cpu_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root     99999 99.9  5.0 1000000 500000 ?      R    10:00   60:00 /runaway/process
root     99998 95.0  4.0 800000 400000 ?       R    10:00   55:00 /another/heavy
root     99997 90.0  3.0 600000 300000 ?       R    10:00   50:00 /yet/another"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": high_cpu_output}},
                {"success": True, "result": {"stdout": ""}},
                {
                    "success": True,
                    "result": {
                        "stdout": " 14:30:00 up 1 day,  load average: 15.00, 12.50, 10.00"
                    },
                },
                {"success": True, "result": {"stdout": ""}},
            ]
        )

        result = await collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert "99.9" in result["top_processes_cpu"]
        assert "load average: 15.00" in result["system_load"]


class TestMemoryUsageCollection(TestDiagnosticCollectorSetup):
    """Tests for memory usage collection."""

    @pytest.mark.asyncio
    async def test_collect_memory_info_linux(self, collector):
        """Test collecting memory info on Linux using free command."""
        memory_output = """              total        used        free      shared  buff/cache   available
Mem:            15Gi       8.5Gi       2.0Gi       500Mi       5.0Gi       6.5Gi
Swap:           8.0Gi       1.0Gi       7.0Gi"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": ""}},  # ps aux --sort=-%cpu
                {"success": True, "result": {"stdout": ""}},  # ps aux --sort=-%mem
                {"success": True, "result": {"stdout": ""}},  # uptime
                {"success": True, "result": {"stdout": memory_output}},  # free -h
            ]
        )

        result = await collector._collect_process_info()

        assert "memory_info" in result
        assert "15Gi" in result["memory_info"]
        assert "8.5Gi" in result["memory_info"]
        assert "Swap" in result["memory_info"]

    @pytest.mark.asyncio
    async def test_collect_memory_processes(self, collector):
        """Test collecting memory-sorted process list."""
        memory_process_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
mysql    12345  5.0 45.0 4000000 7372800 ?     Sl   Jan01  10:00 /usr/sbin/mysqld
java     12346  2.0 30.0 3000000 4915200 ?     Sl   Jan01  20:00 /usr/bin/java -jar app.jar
nginx    12347  0.5 10.0 500000 1638400 ?      S    Jan01   2:00 nginx: worker process"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": ""}},  # ps aux --sort=-%cpu
                {
                    "success": True,
                    "result": {"stdout": memory_process_output},
                },  # ps aux --sort=-%mem
                {"success": True, "result": {"stdout": ""}},  # uptime
                {"success": True, "result": {"stdout": ""}},  # free -h
            ]
        )

        result = await collector._collect_process_info()

        assert "top_processes_memory" in result
        assert "mysqld" in result["top_processes_memory"]
        assert "45.0" in result["top_processes_memory"]

    @pytest.mark.asyncio
    async def test_collect_memory_low_available(self, collector):
        """Test collecting memory when available memory is critically low."""
        low_memory_output = """              total        used        free      shared  buff/cache   available
Mem:            15Gi       14.5Gi      100Mi       500Mi       400Mi       200Mi
Swap:           8.0Gi       7.5Gi       500Mi"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": low_memory_output}},
            ]
        )

        result = await collector._collect_process_info()

        assert "memory_info" in result
        assert "14.5Gi" in result["memory_info"]


class TestDiskUsageCollection(TestDiagnosticCollectorSetup):
    """Tests for disk usage collection."""

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_disk_usage_linux(self, mock_platform, collector):
        """Test collecting disk usage on Linux."""
        df_output = """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   60G   40G  60% /
/dev/sda2       500G  400G  100G  80% /home
tmpfs            16G  1.0G   15G   6% /tmp"""

        iostat_output = """Linux 5.15.0 (hostname) 	01/01/24 	_x86_64_	(8 CPU)

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           5.00    0.00    2.00    1.00    0.00   92.00

Device             tps    kB_read/s    kB_wrtn/s    kB_read    kB_wrtn
sda              50.00       500.00       300.00    1000000     600000"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": df_output}},
                {"success": True, "result": {"stdout": iostat_output}},
                {
                    "success": True,
                    "result": {"stdout": "50G\t/home/user\n30G\t/var/log"},
                },
            ]
        )

        result = await collector._collect_disk_usage()

        assert "filesystem_usage" in result
        assert "60%" in result["filesystem_usage"]
        assert "80%" in result["filesystem_usage"]
        assert "io_stats" in result
        assert "largest_directories" in result

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Windows")
    async def test_collect_disk_usage_windows(self, mock_platform, collector):
        """Test collecting disk usage on Windows."""
        windows_disk_output = """[
    {"DeviceID": "C:", "Size": 500000000000, "FreeSpace": 200000000000, "UsedSpace": 300000000000},
    {"DeviceID": "D:", "Size": 1000000000000, "FreeSpace": 700000000000, "UsedSpace": 300000000000}
]"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": windows_disk_output}},
                {"success": True, "result": {"stdout": "{}"}},
                {"success": True, "result": {"stdout": "[]"}},
            ]
        )

        result = await collector._collect_disk_usage()

        assert "filesystem_usage" in result
        assert "C:" in result["filesystem_usage"]

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_disk_usage_iostat_not_available(
        self, mock_platform, collector
    ):
        """Test disk usage when iostat is not installed."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {
                    "success": True,
                    "result": {"stdout": "Filesystem Size Used\n/dev/sda1 100G 50G"},
                },
                {"success": True, "result": {"stdout": "iostat not available"}},
                {"success": True, "result": {"stdout": "10G\t/var"}},
            ]
        )

        result = await collector._collect_disk_usage()

        assert "filesystem_usage" in result
        assert "io_stats" in result
        assert "iostat not available" in result["io_stats"]

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_disk_usage_critical_space(self, mock_platform, collector):
        """Test disk usage collection when disk is critically full."""
        critical_disk_output = """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   99G    1G  99% /
/dev/sda2       500G  498G    2G  99% /var"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": critical_disk_output}},
                {"success": True, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": ""}},
            ]
        )

        result = await collector._collect_disk_usage()

        assert "filesystem_usage" in result
        assert "99%" in result["filesystem_usage"]


class TestProcessListing(TestDiagnosticCollectorSetup):
    """Tests for process listing functionality."""

    @pytest.mark.asyncio
    async def test_collect_process_list_success(self, collector):
        """Test successful process list collection."""
        process_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168340 11920 ?        Ss   Jan01   0:10 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   Jan01   0:00 [rcu_gp]
www-data  1234  1.5  1.0 200000 80000 ?        S    10:00   1:00 apache2
mysql     2345  2.0  5.0 400000 400000 ?       Sl   Jan01  10:00 mysqld"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": process_output}},
                {"success": True, "result": {"stdout": process_output}},
                {"success": True, "result": {"stdout": "10:00:00 up 5 days"}},
                {"success": True, "result": {"stdout": "total 16G"}},
            ]
        )

        result = await collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert "apache2" in result["top_processes_cpu"]
        assert "mysqld" in result["top_processes_cpu"]

    @pytest.mark.asyncio
    async def test_collect_process_list_empty(self, collector):
        """Test process collection when commands return empty results."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": ""}}
        )

        result = await collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert result["top_processes_cpu"] == ""

    @pytest.mark.asyncio
    async def test_collect_process_zombie_processes(self, collector):
        """Test collecting data with zombie processes."""
        zombie_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root     12345  0.0  0.0      0     0 ?        Z    Jan01   0:00 [defunct]
root     12346  0.0  0.0      0     0 ?        Z    Jan01   0:00 [zombie_proc] <defunct>"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": zombie_output}},
                {"success": True, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": ""}},
            ]
        )

        result = await collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert "defunct" in result["top_processes_cpu"]


class TestServiceStatusCollection(TestDiagnosticCollectorSetup):
    """Tests for service status collection via configuration files."""

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Windows")
    async def test_collect_windows_services(self, mock_platform, collector):
        """Test collecting Windows service status."""
        services_output = """[
    {"Name": "wuauserv", "Status": "Running", "StartType": "Automatic"},
    {"Name": "BITS", "Status": "Running", "StartType": "DelayedAutoStart"},
    {"Name": "Spooler", "Status": "Stopped", "StartType": "Manual"}
]"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "network config"}},
                {"success": True, "result": {"stdout": services_output}},
                {"success": True, "result": {"stdout": "firewall config"}},
            ]
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("agent config")
        ):
            result = await collector._collect_configuration_files()

        assert "services_config" in result
        assert "wuauserv" in result["services_config"]
        assert "Running" in result["services_config"]

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_linux_ssh_config(self, mock_platform, collector):
        """Test collecting Linux SSH configuration as a service indicator."""
        ssh_config = """# SSH Server Configuration
Port 22
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {
                    "success": True,
                    "result": {"stdout": "auto eth0\niface eth0 inet dhcp"},
                },
                {"success": True, "result": {"stdout": ssh_config}},
            ]
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("agent config")
        ):
            result = await collector._collect_configuration_files()

        assert "ssh_config" in result
        assert "PermitRootLogin" in result["ssh_config"]


class TestSystemHealthIndicators(TestDiagnosticCollectorSetup):
    """Tests for system health indicators collection."""

    @pytest.mark.asyncio
    async def test_collect_agent_status_healthy(self, collector, mock_agent):
        """Test collecting agent status when system is healthy."""
        mock_agent.running = True
        mock_agent.connected = True
        mock_agent.reconnect_attempts = 0

        with patch(
            _DIAG_AIOFILES_OPEN,
            return_value=_mock_aiofiles_open(
                "INFO: Agent started\nINFO: Connected to server"
            ),
        ):
            result = await collector._collect_agent_logs()

        assert result["agent_status"]["running"] is True
        assert result["agent_status"]["connected"] is True
        assert result["agent_status"]["reconnect_attempts"] == 0

    @pytest.mark.asyncio
    async def test_collect_agent_status_unhealthy(self, collector, mock_agent):
        """Test collecting agent status when there are issues."""
        mock_agent.running = True
        mock_agent.connected = False
        mock_agent.reconnect_attempts = 5

        with patch(
            _DIAG_AIOFILES_OPEN,
            return_value=_mock_aiofiles_open(
                "ERROR: Connection lost\nERROR: Reconnecting..."
            ),
        ):
            result = await collector._collect_agent_logs()

        assert result["agent_status"]["running"] is True
        assert result["agent_status"]["connected"] is False
        assert result["agent_status"]["reconnect_attempts"] == 5

    @pytest.mark.asyncio
    async def test_collect_error_logs_system_errors(self, collector):
        """Test collecting system error logs as health indicators."""
        journalctl_output = """Jan 01 10:00:00 hostname kernel: EXT4-fs error (device sda1): __ext4_check_dir_entry
Jan 01 10:01:00 hostname systemd[1]: Failed to start Apache HTTP Server.
Jan 01 10:02:00 hostname kernel: Out of memory: Kill process 1234 (java) score 999"""

        dmesg_output = """[12345.678] ata1: error: hard reset failed
[12346.789] usb 1-1: device not accepting address 2, error -62"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": journalctl_output}},
                {"success": True, "result": {"stdout": dmesg_output}},
            ]
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("ERROR: Test error")
        ):
            result = await collector._collect_error_logs()

        assert "system_errors" in result
        assert "kernel_errors" in result
        assert "Out of memory" in result["system_errors"]


class TestMultiPlatformSupport(TestDiagnosticCollectorSetup):
    """Tests for multi-platform support."""

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_system_logs_linux(self, mock_platform, collector):
        """Test system log collection on Linux."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "journalctl output here"}},
                {"success": True, "result": {"stdout": "dmesg output here"}},
                {"success": True, "result": {"stdout": "auth.log content"}},
            ]
        )

        result = await collector._collect_system_logs()

        assert "journalctl_recent" in result
        assert "dmesg_recent" in result
        assert "auth_log" in result

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Windows")
    async def test_collect_system_logs_windows(self, mock_platform, collector):
        """Test system log collection on Windows."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": True,
                "result": {
                    "stdout": '[{"TimeCreated":"2024-01-01","Message":"Test event"}]'
                },
            }
        )

        result = await collector._collect_system_logs()

        assert "windows_system_log" in result
        assert "windows_application_log" in result
        assert "windows_security_log" in result

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Darwin")
    async def test_collect_system_logs_macos(self, mock_platform, collector):
        """Test system log collection on macOS (falls through to Unix path)."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "journalctl output"}},
                {"success": True, "result": {"stdout": "dmesg output"}},
                {"success": True, "result": {"stdout": "auth log"}},
            ]
        )

        result = await collector._collect_system_logs()

        # macOS uses the Unix path (non-Windows)
        assert "journalctl_recent" in result or "dmesg_recent" in result

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_network_info_linux(self, mock_platform, collector):
        """Test network info collection on Linux."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {
                    "success": True,
                    "result": {
                        "stdout": "1: lo: <LOOPBACK> mtu 65536\n2: eth0: <BROADCAST>"
                    },
                },
                {
                    "success": True,
                    "result": {"stdout": "default via 192.168.1.1 dev eth0"},
                },
                {"success": True, "result": {"stdout": "LISTEN  0  128  *:22  *:*"}},
                {"success": True, "result": {"stdout": "nameserver 8.8.8.8"}},
            ]
        )

        result = await collector._collect_network_info()

        assert "interfaces" in result
        assert "routes" in result
        assert "connections" in result
        assert "dns_config" in result

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Windows")
    async def test_collect_network_info_windows(self, mock_platform, collector):
        """Test network info collection on Windows."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "Windows network data"}}
        )

        result = await collector._collect_network_info()

        assert "interfaces" in result
        assert "routes" in result
        assert "connections" in result
        assert "dns_config" in result

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_environment_variables_linux(self, mock_platform, collector):
        """Test environment variable collection on Linux."""
        env_output = """PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
HOME=/root
USER=root
SHELL=/bin/bash
LANG=en_US.UTF-8"""

        python_path_output = """/usr/lib/python3.10
/usr/lib/python3.10/lib-dynload
/usr/local/lib/python3.10/dist-packages"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": env_output}},
                {"success": True, "result": {"stdout": python_path_output}},
            ]
        )

        result = await collector._collect_environment_variables()

        assert "safe_env_vars" in result
        assert "python_path" in result
        assert "PATH=" in result["safe_env_vars"]

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Windows")
    async def test_collect_environment_variables_windows(
        self, mock_platform, collector
    ):
        """Test environment variable collection on Windows."""
        env_output = """[
    {"Name": "PATH", "Value": "C:\\Windows\\System32"},
    {"Name": "COMPUTERNAME", "Value": "TESTPC"},
    {"Name": "USERNAME", "Value": "Administrator"}
]"""

        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": env_output}},
                {"success": True, "result": {"stdout": "C:\\Python310\\lib"}},
            ]
        )

        result = await collector._collect_environment_variables()

        assert "safe_env_vars" in result
        assert "python_path" in result


class TestErrorHandling(TestDiagnosticCollectorSetup):
    """Tests for error handling scenarios."""

    @pytest.mark.asyncio
    async def test_collect_diagnostics_exception_handling(self, collector, mock_agent):
        """Test that exceptions during collection are handled gracefully."""
        parameters = {
            "collection_id": "test-error",
            "collection_types": ["system_logs"],
        }

        # Mock get_system_info to throw an exception early in the collection process
        mock_agent.registration.get_system_info.side_effect = Exception(
            "System info retrieval failed"
        )

        with patch.object(
            collector, "_send_diagnostic_error", new_callable=AsyncMock
        ) as mock_send_error:
            result = await collector.collect_diagnostics(parameters)

        # Should return failure and try to send error
        assert result["success"] is False
        assert "error" in result
        mock_send_error.assert_called_once()

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_disk_usage_command_failure(self, mock_platform, collector):
        """Test disk usage collection when all commands fail."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": False,
                "result": {"stdout": "", "stderr": "Command not found"},
            }
        )

        result = await collector._collect_disk_usage()

        # Should return empty dict rather than crash
        assert isinstance(result, dict)
        assert "filesystem_usage" not in result

    @pytest.mark.asyncio
    async def test_collect_process_info_command_timeout(self, collector):
        """Test process info collection when commands time out."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=asyncio.TimeoutError("Command timed out")
        )

        result = await collector._collect_process_info()

        assert "error" in result

    @pytest.mark.asyncio
    async def test_send_diagnostic_error_handles_send_failure(
        self, collector, mock_agent
    ):
        """Test that send failures during error reporting are handled."""
        mock_agent.send_message = AsyncMock(side_effect=Exception("Network error"))

        # Should not raise exception
        await collector._send_diagnostic_error("test-123", Exception("Original error"))

        collector.logger.error.assert_called()

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_configuration_files_partial_failure(
        self, mock_platform, collector
    ):
        """Test configuration collection with partial command failures."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "network config"}},
                {
                    "success": False,
                    "result": {"stdout": "", "stderr": "Permission denied"},
                },
            ]
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("agent config")
        ):
            result = await collector._collect_configuration_files()

        assert "network_config" in result
        # ssh_config should not be present due to failure
        assert "agent_config" in result

    @pytest.mark.asyncio
    async def test_collect_agent_logs_missing_agent_attributes(
        self, collector, mock_agent
    ):
        """Test agent log collection when optional attributes are missing."""
        del mock_agent.reconnect_attempts
        del mock_agent.last_ping

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("Log line")):
            result = await collector._collect_agent_logs()

        assert result["agent_status"]["reconnect_attempts"] == 0
        assert result["agent_status"]["last_ping"] is None

    @pytest.mark.asyncio
    async def test_collect_error_logs_file_permission_denied(self, collector):
        """Test error log collection when file access is denied."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "system errors"}}
        )

        with patch(
            _DIAG_AIOFILES_OPEN,
            return_value=_mock_aiofiles_open_error(PermissionError("Access denied")),
        ):
            result = await collector._collect_error_logs()

        assert "agent_errors" in result
        assert "not accessible" in result["agent_errors"]


class TestWindowsEventLogCollection(TestDiagnosticCollectorSetup):
    """Tests for Windows Event Log collection."""

    @pytest.mark.asyncio
    async def test_collect_windows_event_log_success(self, collector):
        """Test successful Windows event log collection."""
        event_log_output = """[
    {"TimeCreated": "2024-01-01T10:00:00", "LevelDisplayName": "Information", "Id": 1000, "Message": "Service started"},
    {"TimeCreated": "2024-01-01T11:00:00", "LevelDisplayName": "Error", "Id": 1001, "Message": "Service failed"}
]"""

        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": event_log_output}}
        )

        result = await collector._collect_windows_event_log(
            "System", 100, "windows_system_log"
        )

        assert "windows_system_log" in result
        assert "Service started" in result["windows_system_log"]

    @pytest.mark.asyncio
    async def test_collect_windows_event_log_failure(self, collector):
        """Test Windows event log collection when command fails."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": False,
                "result": {"stdout": "", "stderr": "Access denied"},
            }
        )

        result = await collector._collect_windows_event_log(
            "Security", 50, "windows_security_log"
        )

        assert "windows_security_log" not in result

    @pytest.mark.asyncio
    async def test_collect_windows_security_log_requires_admin(self, collector):
        """Test Windows security log collection which requires admin privileges."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": True,
                "result": {
                    "stdout": "Security logs not accessible - admin privileges required"
                },
            }
        )

        result = await collector._collect_windows_event_log(
            "Security", 50, "windows_security_log"
        )

        assert "windows_security_log" in result
        assert "admin privileges required" in result["windows_security_log"]


class TestWindowsNetworkCommands(TestDiagnosticCollectorSetup):
    """Tests for Windows network command collection."""

    @pytest.mark.asyncio
    async def test_collect_windows_network_command_success(self, collector):
        """Test successful Windows network command collection."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "ipconfig output"}}
        )

        result = await collector._collect_windows_network_command(
            "ipconfig /all", "interfaces", "network interfaces"
        )

        assert "interfaces" in result
        assert result["interfaces"] == "ipconfig output"

    @pytest.mark.asyncio
    async def test_collect_windows_network_command_failure(self, collector):
        """Test Windows network command collection when command fails."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": False, "result": {"stdout": ""}}
        )

        result = await collector._collect_windows_network_command(
            "netstat -an", "connections", "network connections"
        )

        assert "connections" not in result

    @pytest.mark.asyncio
    async def test_collect_windows_dns_config_with_fallback(self, collector):
        """Test Windows DNS config collection with fallback mechanism."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {
                    "success": False,
                    "result": {"stdout": ""},
                },  # ipconfig /displaydns fails
                {
                    "success": True,
                    "result": {"stdout": '[{"ServerAddresses": ["8.8.8.8"]}]'},
                },  # Get-DnsClientServerAddress succeeds
            ]
        )

        result = await collector._collect_windows_dns_config()

        assert "dns_config" in result
        assert "8.8.8.8" in result["dns_config"]

    @pytest.mark.asyncio
    async def test_collect_windows_dns_config_both_methods_fail(self, collector):
        """Test Windows DNS config when both methods fail."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": False, "result": {"stdout": ""}}
        )

        result = await collector._collect_windows_dns_config()

        assert "dns_config" in result
        assert "not available" in result["dns_config"]


class TestStatisticsCalculation(TestDiagnosticCollectorSetup):
    """Tests for collection statistics calculation."""

    def test_calculate_statistics_with_nested_files(self, collector):
        """Test statistics calculation with nested file structures."""
        diagnostic_data = {
            "collection_id": "test-123",
            "config_files": {
                "files": ["file1.conf", "file2.conf"],
                "other_key": "value",
            },
            "logs": {"files": ["log1.log", "log2.log", "log3.log"]},
        }

        size, files = collector._calculate_collection_statistics(diagnostic_data)

        assert size > 0
        assert files == 5  # 2 + 3 files

    def test_calculate_statistics_with_mixed_types(self, collector):
        """Test statistics calculation with various data types."""
        diagnostic_data = {
            "collection_id": "test-123",
            "string_value": "ignored",
            "number_value": 42,
            "boolean_value": True,
            "none_value": None,
            "list_data": ["item1", "item2", "item3"],
            "dict_data": {"nested": "value"},
        }

        _size, files = collector._calculate_collection_statistics(diagnostic_data)

        # Only list and dict should contribute
        assert files == 3  # 3 items in list

    def test_calculate_statistics_empty_collections(self, collector):
        """Test statistics with empty collections."""
        diagnostic_data = {
            "collection_id": "test-123",
            "empty_list": [],
            "empty_dict": {},
            "empty_files": {"files": []},
        }

        _size, files = collector._calculate_collection_statistics(diagnostic_data)

        assert files == 0


class TestDiagnosticWorkflow(TestDiagnosticCollectorSetup):
    """Tests for complete diagnostic collection workflow."""

    @pytest.mark.asyncio
    async def test_full_workflow_success(self, collector, mock_agent):
        """Test complete diagnostic workflow from request to result."""
        parameters = {
            "collection_id": "workflow-test-123",
            "collection_types": ["process_info", "disk_usage"],
        }

        # Mock all the collection methods
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "test data"}}
        )

        result = await collector.collect_diagnostics(parameters)

        assert result["success"] is True
        assert result["collection_id"] == "workflow-test-123"
        mock_agent.create_message.assert_called()
        mock_agent.send_message.assert_called()

    @pytest.mark.asyncio
    async def test_workflow_with_unknown_collection_type(self, collector, mock_agent):
        """Test workflow handles unknown collection types gracefully."""
        parameters = {
            "collection_id": "unknown-type-test",
            "collection_types": ["unknown_type", "process_info"],
        }

        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "data"}}
        )

        result = await collector.collect_diagnostics(parameters)

        assert result["success"] is True
        # Should log warning for unknown type
        collector.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_workflow_continues_after_collection_failure(
        self, collector, mock_agent
    ):
        """Test that workflow continues even if one collection type fails."""
        parameters = {
            "collection_id": "partial-failure-test",
            "collection_types": ["system_logs", "network_info", "process_info"],
        }

        call_count = 0

        async def mock_execute(params):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # First collection type (system_logs uses 3 commands)
                raise RuntimeError("Collection failed")
            return {"success": True, "result": {"stdout": "data"}}

        collector.system_ops.execute_shell_command = AsyncMock(side_effect=mock_execute)

        with patch(_PLATFORM_SYSTEM, return_value="Linux"):
            result = await collector.collect_diagnostics(parameters)

        # Should still succeed overall
        assert result["success"] is True


class TestTimingAndPerformance(TestDiagnosticCollectorSetup):
    """Tests related to timing and performance logging."""

    @pytest.mark.asyncio
    async def test_collection_timing_logged(self, collector):
        """Test that collection timing is properly logged."""
        parameters = {
            "collection_id": "timing-test",
            "collection_types": ["process_info"],
        }

        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "data"}}
        )

        await collector.collect_diagnostics(parameters)

        # Check that timing-related log calls were made
        info_calls = [str(call) for call in collector.logger.info.call_args_list]
        assert any(
            "seconds" in str(call).lower() or "completed" in str(call).lower()
            for call in info_calls
        )

    @pytest.mark.asyncio
    async def test_send_timing_logged(self, collector, mock_agent):
        """Test that send timing is logged."""
        diagnostic_data = {
            "collection_id": "send-timing-test",
            "success": True,
            "data": "test",
        }

        await collector._send_diagnostic_result(diagnostic_data)

        info_calls = [str(call) for call in collector.logger.info.call_args_list]
        assert any(
            "sent" in str(call).lower() or "seconds" in str(call).lower()
            for call in info_calls
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
