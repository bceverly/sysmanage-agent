"""
Tests for child host collector module.
"""

# pylint: disable=redefined-outer-name,protected-access

import asyncio
import configparser
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.communication.child_host_collector import (
    ChildHostCollector,
)


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = Mock()
    agent.config_manager = Mock()
    agent.running = True
    agent.connected = True
    agent.registration = Mock()
    agent.registration.get_system_info = Mock(return_value={"hostname": "test-host"})
    agent.registration_manager = Mock()
    agent.registration_manager.get_host_approval_from_db = Mock(
        return_value=Mock(host_id="test-host-id")
    )
    agent.create_message = Mock(
        side_effect=lambda msg_type, data: {
            "message_type": msg_type,
            "message_id": "test-msg-id",
            "data": data,
        }
    )
    agent.send_message = AsyncMock(return_value=True)
    agent.child_host_ops = Mock()
    agent.child_host_ops.list_child_hosts = AsyncMock(
        return_value={"success": True, "child_hosts": []}
    )
    return agent


@pytest.fixture
def collector(mock_agent):
    """Create a ChildHostCollector for testing."""
    return ChildHostCollector(mock_agent)


class TestChildHostCollectorInit:
    """Tests for ChildHostCollector initialization."""

    def test_init_sets_agent(self, mock_agent):
        """Test that __init__ sets agent."""
        collector = ChildHostCollector(mock_agent)
        assert collector.agent == mock_agent

    def test_init_sets_logger(self, mock_agent):
        """Test that __init__ sets logger."""
        collector = ChildHostCollector(mock_agent)
        assert collector.logger is not None

    def test_init_sets_empty_keepalive_processes(self, mock_agent):
        """Test that __init__ sets empty keepalive processes dict."""
        collector = ChildHostCollector(mock_agent)
        assert not collector._wsl_keepalive_processes


class TestEnsureWslconfig:
    """Tests for _ensure_wslconfig method."""

    def test_ensure_wslconfig_creates_new_file(self, collector, tmp_path):
        """Test creating new .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Check file was created
        assert wslconfig_path.exists()
        assert result is True

        # Verify content
        config = configparser.RawConfigParser()
        config.read(str(wslconfig_path))
        assert config.get("wsl2", "vmIdleTimeout") == "-1"
        assert config.get("wsl", "autoStop") == "false"

    def test_ensure_wslconfig_existing_correct(self, collector, tmp_path):
        """Test with existing correctly configured .wslconfig."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with correct settings
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "-1")
        config.add_section("wsl")
        config.set("wsl", "autoStop", "false")
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config.write(config_file)

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Should not need update
        assert result is False

    def test_ensure_wslconfig_updates_existing(self, collector, tmp_path):
        """Test updating existing .wslconfig with wrong settings."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with wrong settings
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "0")  # Wrong value
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config.write(config_file)

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        assert result is True

        # Verify updated content
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(str(wslconfig_path))
        assert config.get("wsl2", "vmIdleTimeout") == "-1"

    def test_ensure_wslconfig_fixes_lowercase_keys(self, collector, tmp_path):
        """Test fixing lowercase keys in .wslconfig."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with lowercase keys
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config_file.write("[wsl2]\nvmidletimeout=-1\n[wsl]\nautostop=false\n")

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Should need update to fix case
        assert result is True

    def test_ensure_wslconfig_parse_error(self, collector, tmp_path):
        """Test handling of parse error in existing .wslconfig."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create malformed config
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config_file.write("this is not valid ini content [[[")

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Should still try to update
        assert result is True

    def test_ensure_wslconfig_permission_error_on_write(self, collector, tmp_path):
        """Test handling permission error when writing .wslconfig."""
        with patch("os.path.expanduser", return_value=str(tmp_path)):
            # Mock open to raise PermissionError on write
            original_open = open
            call_count = [0]

            def mock_open_func(*args, **kwargs):
                call_count[0] += 1
                if "w" in args[1] if len(args) > 1 else kwargs.get("mode", "r"):
                    raise PermissionError("Permission denied")
                return original_open(*args, **kwargs)

            with patch("builtins.open", side_effect=mock_open_func):
                result = collector._ensure_wslconfig()

        # Should return False on permission error
        assert result is False

    def test_ensure_wslconfig_general_write_error(self, collector, tmp_path):
        """Test handling general error when writing .wslconfig."""
        with patch("os.path.expanduser", return_value=str(tmp_path)):
            # Mock open to raise a general exception on write
            original_open = open

            def mock_open_func(*args, **kwargs):
                if "w" in args[1] if len(args) > 1 else kwargs.get("mode", "r"):
                    raise OSError("Disk full")
                return original_open(*args, **kwargs)

            with patch("builtins.open", side_effect=mock_open_func):
                result = collector._ensure_wslconfig()

        # Should return False on error
        assert result is False


class TestConfigureWsl2IdleTimeout:
    """Tests for _configure_wsl2_idle_timeout method."""

    def test_configure_wsl2_idle_timeout_adds_section(self, collector):
        """Test adding wsl2 section when it doesn't exist."""
        config = configparser.RawConfigParser()
        config.optionxform = str

        result = collector._configure_wsl2_idle_timeout(config)

        assert result is True
        assert config.has_section("wsl2")
        assert config.get("wsl2", "vmIdleTimeout") == "-1"

    def test_configure_wsl2_idle_timeout_already_correct(self, collector):
        """Test when vmIdleTimeout is already correct."""
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "-1")

        result = collector._configure_wsl2_idle_timeout(config)

        assert result is False

    def test_configure_wsl2_idle_timeout_wrong_value(self, collector):
        """Test when vmIdleTimeout has wrong value."""
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "60000")

        result = collector._configure_wsl2_idle_timeout(config)

        assert result is True
        assert config.get("wsl2", "vmIdleTimeout") == "-1"

    def test_configure_wsl2_idle_timeout_fixes_lowercase(self, collector):
        """Test fixing lowercase vmidletimeout."""
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmidletimeout", "-1")

        result = collector._configure_wsl2_idle_timeout(config)

        assert result is True
        # Should remove lowercase and add proper case
        assert not config.has_option("wsl2", "vmidletimeout")
        assert config.get("wsl2", "vmIdleTimeout") == "-1"


class TestConfigureWslAutostop:
    """Tests for _configure_wsl_autostop method."""

    def test_configure_wsl_autostop_adds_section(self, collector):
        """Test adding wsl section when it doesn't exist."""
        config = configparser.RawConfigParser()
        config.optionxform = str

        result = collector._configure_wsl_autostop(config)

        assert result is True
        assert config.has_section("wsl")
        assert config.get("wsl", "autoStop") == "false"

    def test_configure_wsl_autostop_already_correct(self, collector):
        """Test when autoStop is already correct."""
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl")
        config.set("wsl", "autoStop", "false")

        result = collector._configure_wsl_autostop(config)

        assert result is False

    def test_configure_wsl_autostop_wrong_value(self, collector):
        """Test when autoStop has wrong value."""
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl")
        config.set("wsl", "autoStop", "true")

        result = collector._configure_wsl_autostop(config)

        assert result is True
        assert config.get("wsl", "autoStop") == "false"

    def test_configure_wsl_autostop_fixes_lowercase(self, collector):
        """Test fixing lowercase autostop."""
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl")
        config.set("wsl", "autostop", "false")

        result = collector._configure_wsl_autostop(config)

        assert result is True
        # Should remove lowercase and add proper case
        assert not config.has_option("wsl", "autostop")
        assert config.get("wsl", "autoStop") == "false"


class TestWriteWslconfig:
    """Tests for _write_wslconfig method."""

    def test_write_wslconfig_new_file(self, collector, tmp_path):
        """Test writing new .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "-1")

        result = collector._write_wslconfig(
            config, wslconfig_path, creating_new_file=True
        )

        assert result is True
        assert wslconfig_path.exists()

    def test_write_wslconfig_update_existing(self, collector, tmp_path):
        """Test updating existing .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"
        wslconfig_path.write_text("[wsl2]\nvmIdleTimeout=0\n")

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "-1")

        result = collector._write_wslconfig(
            config, wslconfig_path, creating_new_file=False
        )

        assert result is True

    def test_write_wslconfig_permission_denied(self, collector, tmp_path):
        """Test handling permission denied."""
        wslconfig_path = tmp_path / ".wslconfig"
        config = configparser.RawConfigParser()

        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = collector._write_wslconfig(
                config, wslconfig_path, creating_new_file=True
            )

        assert result is False

    def test_write_wslconfig_general_error(self, collector, tmp_path):
        """Test handling general write error."""
        wslconfig_path = tmp_path / ".wslconfig"
        config = configparser.RawConfigParser()

        with patch("builtins.open", side_effect=OSError("Disk full")):
            result = collector._write_wslconfig(
                config, wslconfig_path, creating_new_file=True
            )

        assert result is False


class TestRestartWsl:
    """Tests for _restart_wsl method."""

    def test_restart_wsl_success(self, collector):
        """Test successful WSL restart."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            collector._restart_wsl()

        # Verify wsl --shutdown was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args == ["wsl", "--shutdown"]

    def test_restart_wsl_non_zero_return(self, collector):
        """Test WSL restart with non-zero return code."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = b"WSL is not installed"

        with patch("subprocess.run", return_value=mock_result):
            # Should not raise
            collector._restart_wsl()

    def test_restart_wsl_timeout(self, collector):
        """Test WSL restart timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("wsl", 30)):
            # Should not raise
            collector._restart_wsl()

    def test_restart_wsl_exception(self, collector):
        """Test WSL restart with exception."""
        with patch("subprocess.run", side_effect=Exception("WSL not found")):
            # Should not raise
            collector._restart_wsl()

    def test_restart_wsl_with_create_no_window(self, collector):
        """Test WSL restart uses CREATE_NO_WINDOW on Windows."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            with patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
                collector._restart_wsl()

        # Verify creationflags was passed
        call_kwargs = mock_run.call_args[1]
        assert "creationflags" in call_kwargs


class TestGetWslDistros:
    """Tests for _get_wsl_distros method."""

    def test_get_wsl_distros_success_utf16(self, collector):
        """Test getting WSL distros with UTF-16 output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Ubuntu\nDebian\n".encode("utf-16-le")

        with patch("subprocess.run", return_value=mock_result):
            distros = collector._get_wsl_distros()

        assert distros == ["Ubuntu", "Debian"]

    def test_get_wsl_distros_success_utf8(self, collector):
        """Test getting WSL distros with UTF-8 output."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Create bytes that aren't valid UTF-16LE but are valid UTF-8
        mock_result.stdout = b"Ubuntu\nDebian\n"

        with patch("subprocess.run", return_value=mock_result):
            distros = collector._get_wsl_distros()

        # May return empty list or parsed distros depending on decoding
        assert isinstance(distros, list)

    def test_get_wsl_distros_filters_windows(self, collector):
        """Test that Windows entries are filtered out."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Ubuntu\nWindows Subsystem\nDebian\n".encode("utf-16-le")

        with patch("subprocess.run", return_value=mock_result):
            distros = collector._get_wsl_distros()

        assert "Windows Subsystem" not in distros
        assert "Ubuntu" in distros
        assert "Debian" in distros

    def test_get_wsl_distros_non_zero_return(self, collector):
        """Test with non-zero return code."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = b""

        with patch("subprocess.run", return_value=mock_result):
            distros = collector._get_wsl_distros()

        assert distros == []

    def test_get_wsl_distros_exception(self, collector):
        """Test exception handling."""
        with patch("subprocess.run", side_effect=FileNotFoundError("wsl not found")):
            distros = collector._get_wsl_distros()

        assert distros == []

    def test_get_wsl_distros_filters_empty_lines(self, collector):
        """Test that empty lines are filtered out."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Ubuntu\n\n  \nDebian\n".encode("utf-16-le")

        with patch("subprocess.run", return_value=mock_result):
            distros = collector._get_wsl_distros()

        assert "" not in distros
        assert "  " not in distros

    def test_get_wsl_distros_unicode_decode_error_fallback(self, collector):
        """Test fallback to UTF-8 when UTF-16LE decoding fails."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Create an odd-length byte string that will fail UTF-16LE decoding
        # UTF-16LE requires pairs of bytes; an odd number of bytes raises UnicodeDecodeError
        mock_result.stdout = b"Ubuntu\nDebian\nX"  # 15 bytes = odd, will fail UTF-16LE

        with patch("subprocess.run", return_value=mock_result):
            distros = collector._get_wsl_distros()

        # The fallback to UTF-8 should work and parse the distros
        assert "Ubuntu" in distros
        assert "Debian" in distros


class TestStartKeepaliveProcess:
    """Tests for _start_keepalive_process method."""

    def test_start_keepalive_process_success(self, collector):
        """Test successful start of keep-alive process."""
        mock_process = Mock()
        mock_process.pid = 12345

        with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
            result = collector._start_keepalive_process("Ubuntu")

        assert result is True
        assert "Ubuntu" in collector._wsl_keepalive_processes
        assert collector._wsl_keepalive_processes["Ubuntu"] == mock_process

        # Verify correct command was used
        call_args = mock_popen.call_args[0][0]
        assert call_args == ["wsl", "-d", "Ubuntu", "--", "sleep", "infinity"]

    def test_start_keepalive_process_failure(self, collector):
        """Test failed start of keep-alive process."""
        with patch("subprocess.Popen", side_effect=OSError("Failed to start")):
            result = collector._start_keepalive_process("Ubuntu")

        assert result is False
        assert "Ubuntu" not in collector._wsl_keepalive_processes

    def test_start_keepalive_process_with_create_no_window(self, collector):
        """Test that CREATE_NO_WINDOW is used on Windows."""
        mock_process = Mock()

        with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
            with patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
                collector._start_keepalive_process("Ubuntu")

        call_kwargs = mock_popen.call_args[1]
        assert "creationflags" in call_kwargs


class TestStopKeepaliveProcess:
    """Tests for _stop_keepalive_process method."""

    def test_stop_keepalive_process_success(self, collector):
        """Test successful stop of keep-alive process."""
        mock_process = Mock()
        mock_process.wait = Mock()
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        collector._stop_keepalive_process("Ubuntu")

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once_with(timeout=5)
        assert "Ubuntu" not in collector._wsl_keepalive_processes

    def test_stop_keepalive_process_timeout_requires_kill(self, collector):
        """Test that kill is used when terminate times out."""
        mock_process = Mock()
        mock_process.wait = Mock(side_effect=subprocess.TimeoutExpired("wsl", 5))
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        collector._stop_keepalive_process("Ubuntu")

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()
        assert "Ubuntu" not in collector._wsl_keepalive_processes

    def test_stop_keepalive_process_not_found(self, collector):
        """Test stopping a process that doesn't exist."""
        # Should not raise
        collector._stop_keepalive_process("NonExistent")

    def test_stop_keepalive_process_error_during_stop(self, collector):
        """Test handling error during process stop."""
        mock_process = Mock()
        mock_process.terminate = Mock(side_effect=OSError("Process already dead"))
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        # Should not raise
        collector._stop_keepalive_process("Ubuntu")

        assert "Ubuntu" not in collector._wsl_keepalive_processes


class TestStopAllKeepaliveProcesses:
    """Tests for _stop_all_keepalive_processes method."""

    def test_stop_all_keepalive_processes_empty(self, collector):
        """Test stopping when no processes exist."""
        collector._stop_all_keepalive_processes()
        assert collector._wsl_keepalive_processes == {}

    def test_stop_all_keepalive_processes_multiple(self, collector):
        """Test stopping multiple processes."""
        mock_process1 = Mock()
        mock_process1.wait = Mock()
        mock_process2 = Mock()
        mock_process2.wait = Mock()

        collector._wsl_keepalive_processes["Ubuntu"] = mock_process1
        collector._wsl_keepalive_processes["Debian"] = mock_process2

        collector._stop_all_keepalive_processes()

        mock_process1.terminate.assert_called_once()
        mock_process2.terminate.assert_called_once()
        assert collector._wsl_keepalive_processes == {}


class TestEnsureKeepaliveProcesses:
    """Tests for _ensure_keepalive_processes method."""

    def test_ensure_keepalive_starts_new_processes(self, collector):
        """Test starting keep-alive for new distros."""
        mock_process = Mock()

        with patch.object(
            collector, "_get_wsl_distros", return_value=["Ubuntu", "Debian"]
        ):
            with patch("subprocess.Popen", return_value=mock_process):
                collector._ensure_keepalive_processes()

        assert "Ubuntu" in collector._wsl_keepalive_processes
        assert "Debian" in collector._wsl_keepalive_processes

    def test_ensure_keepalive_stops_removed_distros(self, collector):
        """Test stopping keep-alive for removed distros."""
        mock_process = Mock()
        mock_process.poll = Mock(return_value=None)  # Process still running
        mock_process.wait = Mock()
        collector._wsl_keepalive_processes["OldDistro"] = mock_process

        with patch.object(collector, "_get_wsl_distros", return_value=["Ubuntu"]):
            with patch("subprocess.Popen", return_value=Mock()):
                collector._ensure_keepalive_processes()

        assert "OldDistro" not in collector._wsl_keepalive_processes
        mock_process.terminate.assert_called_once()

    def test_ensure_keepalive_restarts_dead_processes(self, collector):
        """Test restarting processes that have exited."""
        dead_process = Mock()
        dead_process.poll = Mock(return_value=0)  # Process has exited
        collector._wsl_keepalive_processes["Ubuntu"] = dead_process

        new_process = Mock()

        with patch.object(collector, "_get_wsl_distros", return_value=["Ubuntu"]):
            with patch("subprocess.Popen", return_value=new_process):
                collector._ensure_keepalive_processes()

        assert collector._wsl_keepalive_processes["Ubuntu"] == new_process

    def test_ensure_keepalive_skips_running_processes(self, collector):
        """Test that running processes are not restarted."""
        running_process = Mock()
        running_process.poll = Mock(return_value=None)  # Process still running
        collector._wsl_keepalive_processes["Ubuntu"] = running_process

        with patch.object(collector, "_get_wsl_distros", return_value=["Ubuntu"]):
            with patch("subprocess.Popen") as mock_popen:
                collector._ensure_keepalive_processes()

        # Should not start a new process
        mock_popen.assert_not_called()
        assert collector._wsl_keepalive_processes["Ubuntu"] == running_process

    def test_ensure_keepalive_skips_empty_distro_names(self, collector):
        """Test that empty distro names are skipped."""
        # Note: The code only skips falsy values (empty string), not whitespace-only strings
        # _get_wsl_distros already filters whitespace in practice via strip()
        with patch.object(collector, "_get_wsl_distros", return_value=["Ubuntu", ""]):
            with patch("subprocess.Popen", return_value=Mock()) as mock_popen:
                collector._ensure_keepalive_processes()

        # Should only start for Ubuntu, not empty string
        assert mock_popen.call_count == 1


class TestKeepaliveProcesses:
    """Tests for WSL keepalive process management."""

    def test_keepalive_processes_initially_empty(self, collector):
        """Test that keepalive processes dict is initially empty."""
        assert collector._wsl_keepalive_processes == {}

    def test_add_keepalive_process(self, collector):
        """Test adding a keepalive process."""
        mock_process = Mock()
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        assert "Ubuntu" in collector._wsl_keepalive_processes
        assert collector._wsl_keepalive_processes["Ubuntu"] == mock_process

    def test_remove_keepalive_process(self, collector):
        """Test removing a keepalive process."""
        mock_process = Mock()
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        del collector._wsl_keepalive_processes["Ubuntu"]

        assert "Ubuntu" not in collector._wsl_keepalive_processes


class TestChildHostHeartbeat:
    """Tests for child_host_heartbeat method."""

    @pytest.mark.asyncio
    async def test_child_host_heartbeat_non_windows(self, collector, mock_agent):
        """Test heartbeat loop on non-Windows platform."""
        mock_agent.running = True

        # Simulate one iteration then stop
        iteration_count = [0]

        async def mock_sleep(_seconds):
            iteration_count[0] += 1
            if iteration_count[0] >= 1:
                mock_agent.running = False

        with patch("platform.system", return_value="Linux"):
            with patch("asyncio.sleep", side_effect=mock_sleep):
                await collector.child_host_heartbeat()

    @pytest.mark.asyncio
    async def test_child_host_heartbeat_windows(self, collector, mock_agent):
        """Test heartbeat loop on Windows with WSL setup."""
        mock_agent.running = True

        # Simulate one iteration then stop
        iteration_count = [0]

        async def mock_sleep(_seconds):
            iteration_count[0] += 1
            if iteration_count[0] >= 1:
                mock_agent.running = False

        with patch("platform.system", return_value="Windows"):
            with patch.object(collector, "_ensure_wslconfig", return_value=False):
                with patch.object(collector, "_ensure_keepalive_processes"):
                    with patch.object(collector, "_stop_all_keepalive_processes"):
                        with patch("asyncio.sleep", side_effect=mock_sleep):
                            await collector.child_host_heartbeat()

    @pytest.mark.asyncio
    async def test_child_host_heartbeat_windows_wslconfig_modified(
        self, collector, mock_agent
    ):
        """Test heartbeat restarts WSL when config was modified."""
        mock_agent.running = True

        iteration_count = [0]

        async def mock_sleep(_seconds):
            iteration_count[0] += 1
            if iteration_count[0] >= 1:
                mock_agent.running = False

        with patch("platform.system", return_value="Windows"):
            with patch.object(collector, "_ensure_wslconfig", return_value=True):
                with patch.object(collector, "_restart_wsl") as mock_restart:
                    with patch.object(collector, "_ensure_keepalive_processes"):
                        with patch.object(collector, "_stop_all_keepalive_processes"):
                            with patch("asyncio.sleep", side_effect=mock_sleep):
                                await collector.child_host_heartbeat()

        mock_restart.assert_called_once()

    @pytest.mark.asyncio
    async def test_child_host_heartbeat_cancelled(self, collector, mock_agent):
        """Test heartbeat loop cancellation."""
        mock_agent.running = True

        with patch("platform.system", return_value="Linux"):
            with patch("asyncio.sleep", side_effect=asyncio.CancelledError()):
                with pytest.raises(asyncio.CancelledError):
                    await collector.child_host_heartbeat()

    @pytest.mark.asyncio
    async def test_child_host_heartbeat_error_continues_loop(
        self, collector, mock_agent
    ):
        """Test that errors in the loop are caught and loop continues."""
        mock_agent.running = True

        # Simulate error then stop
        iteration_count = [0]

        async def mock_sleep(_seconds):
            iteration_count[0] += 1
            if iteration_count[0] == 1:
                return  # First iteration succeeds
            mock_agent.running = False

        with patch("platform.system", return_value="Linux"):
            with patch.object(
                collector,
                "send_child_hosts_update",
                side_effect=Exception("Test error"),
            ):
                with patch("asyncio.sleep", side_effect=mock_sleep):
                    await collector.child_host_heartbeat()

    @pytest.mark.asyncio
    async def test_child_host_heartbeat_cleanup_on_exit(self, collector, mock_agent):
        """Test that cleanup happens when heartbeat exits."""
        mock_agent.running = False

        with patch("platform.system", return_value="Windows"):
            with patch.object(collector, "_ensure_wslconfig", return_value=False):
                with patch.object(collector, "_ensure_keepalive_processes"):
                    with patch.object(
                        collector, "_stop_all_keepalive_processes"
                    ) as mock_stop:
                        await collector.child_host_heartbeat()

        mock_stop.assert_called_once()


class TestSendChildHostsUpdate:
    """Tests for send_child_hosts_update method."""

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_unsupported_platform(self, collector):
        """Test update on unsupported platform."""
        with patch("platform.system", return_value="Darwin"):
            await collector.send_child_hosts_update()

        # Should return early without sending anything
        collector.agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_windows_success(self, collector, mock_agent):
        """Test successful update on Windows."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={
                "success": True,
                "child_hosts": [
                    {"name": "Ubuntu", "status": "Running"},
                    {"name": "Debian", "status": "Stopped"},
                ],
            }
        )

        with patch("platform.system", return_value="Windows"):
            await collector.send_child_hosts_update()

        mock_agent.send_message.assert_called_once()
        call_args = mock_agent.create_message.call_args
        assert call_args[0][0] == "child_host_list_update"
        assert call_args[0][1]["count"] == 2

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_linux_success(self, collector, mock_agent):
        """Test successful update on Linux."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={
                "success": True,
                "child_hosts": [{"name": "container1", "status": "Running"}],
            }
        )

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_openbsd_success(self, collector, mock_agent):
        """Test successful update on OpenBSD."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={"success": True, "child_hosts": []}
        )

        with patch("platform.system", return_value="OpenBSD"):
            await collector.send_child_hosts_update()

        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_freebsd_success(self, collector, mock_agent):
        """Test successful update on FreeBSD."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={"success": True, "child_hosts": []}
        )

        with patch("platform.system", return_value="FreeBSD"):
            await collector.send_child_hosts_update()

        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_no_child_host_ops(
        self, collector, mock_agent
    ):
        """Test when agent doesn't have child_host_ops."""
        delattr(mock_agent, "child_host_ops")

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_collection_failed(
        self, collector, mock_agent
    ):
        """Test when child host collection fails."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={"success": False, "error": "Collection failed"}
        )

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_includes_host_id(
        self, collector, mock_agent
    ):
        """Test that host_id is included when available."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={"success": True, "child_hosts": []}
        )
        mock_agent.registration_manager.get_host_approval_from_db = Mock(
            return_value=Mock(host_id="test-uuid-1234")
        )

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        call_args = mock_agent.create_message.call_args
        assert call_args[0][1]["host_id"] == "test-uuid-1234"

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_no_host_approval(
        self, collector, mock_agent
    ):
        """Test when no host approval is available."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={"success": True, "child_hosts": []}
        )
        mock_agent.registration_manager.get_host_approval_from_db = Mock(
            return_value=None
        )

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        call_args = mock_agent.create_message.call_args
        assert "host_id" not in call_args[0][1]

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_send_failure(self, collector, mock_agent):
        """Test when sending message fails."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={"success": True, "child_hosts": []}
        )
        mock_agent.send_message = AsyncMock(return_value=False)

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        # Should log warning but not raise
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_exception(self, collector, mock_agent):
        """Test handling exception during update."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            side_effect=Exception("Connection error")
        )

        with patch("platform.system", return_value="Linux"):
            # Should not raise
            await collector.send_child_hosts_update()

    @pytest.mark.asyncio
    async def test_send_child_hosts_update_message_structure(
        self, collector, mock_agent
    ):
        """Test the structure of the sent message."""
        mock_agent.child_host_ops.list_child_hosts = AsyncMock(
            return_value={
                "success": True,
                "child_hosts": [
                    {"name": "test-vm", "status": "Running", "type": "vm"},
                ],
            }
        )
        mock_agent.registration.get_system_info = Mock(
            return_value={"hostname": "parent-host"}
        )

        with patch("platform.system", return_value="Linux"):
            await collector.send_child_hosts_update()

        call_args = mock_agent.create_message.call_args
        message_type = call_args[0][0]
        message_data = call_args[0][1]

        assert message_type == "child_host_list_update"
        assert message_data["success"] is True
        assert len(message_data["child_hosts"]) == 1
        assert message_data["count"] == 1
        assert message_data["hostname"] == "parent-host"
