"""
Tests for system control operations module.
Tests shell execution, reboot, shutdown, and system update operations.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.system_control import SystemControl


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = Mock()
    agent.registration = Mock()
    agent.registration.get_system_info = Mock(
        return_value={
            "hostname": "test-host",
            "platform": "Linux",
        }
    )
    agent.config = Mock()
    agent.config.is_script_execution_enabled = Mock(return_value=True)
    agent.config.get_allowed_shells = Mock(return_value=["bash", "sh"])
    agent.create_message = Mock(return_value={"message_type": "test"})
    agent.send_message = AsyncMock()
    agent.update_os_version = AsyncMock()
    agent.update_hardware = AsyncMock()
    agent.data_collector = Mock()
    agent.data_collector._send_graylog_status_update = AsyncMock()
    return agent


@pytest.fixture
def system_control(mock_agent):
    """Create a SystemControl instance for testing."""
    return SystemControl(mock_agent)


class TestSystemControlInit:
    """Tests for SystemControl initialization."""

    def test_init_sets_agent_instance(self, mock_agent):
        """Test that __init__ sets agent_instance."""
        control = SystemControl(mock_agent)
        assert control.agent_instance == mock_agent

    def test_init_creates_logger(self, mock_agent):
        """Test that __init__ creates logger."""
        control = SystemControl(mock_agent)
        assert control.logger is not None


class TestExecuteShellCommand:
    """Tests for execute_shell_command method."""

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self, system_control):
        """Test successful shell command execution."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"hello\n", b""))

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            result = await system_control.execute_shell_command(
                {"command": "echo hello"}
            )

        assert result["success"] is True
        assert result["result"]["stdout"] == "hello\n"
        assert result["result"]["stderr"] == ""
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self, system_control):
        """Test failed shell command execution."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error\n"))

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            result = await system_control.execute_shell_command({"command": "false"})

        assert result["success"] is False
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_execute_shell_command_no_command(self, system_control):
        """Test shell command execution without command."""
        result = await system_control.execute_shell_command({})

        assert result["success"] is False
        assert "No command specified" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_shell_command_with_working_dir(self, system_control):
        """Test shell command execution with working directory."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output\n", b""))

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_subprocess:
            result = await system_control.execute_shell_command(
                {"command": "pwd", "working_directory": "/tmp"}
            )

        mock_subprocess.assert_called_once()
        call_kwargs = mock_subprocess.call_args[1]
        assert call_kwargs["cwd"] == "/tmp"
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_shell_command_exception(self, system_control):
        """Test shell command execution with exception."""
        with patch(
            "asyncio.create_subprocess_shell", side_effect=Exception("test error")
        ):
            result = await system_control.execute_shell_command(
                {"command": "echo hello"}
            )

        assert result["success"] is False
        assert "test error" in result["error"]


class TestGetDetailedSystemInfo:
    """Tests for get_detailed_system_info method."""

    @pytest.mark.asyncio
    async def test_get_detailed_system_info_success(self, system_control, mock_agent):
        """Test successful system info retrieval."""
        with patch.object(
            system_control, "_send_antivirus_status_update", new_callable=AsyncMock
        ):
            with patch.object(
                system_control,
                "_send_commercial_antivirus_status_update",
                new_callable=AsyncMock,
            ):
                with patch(
                    "src.sysmanage_agent.operations.system_control.AntivirusCollector"
                ) as mock_av:
                    mock_av_instance = Mock()
                    mock_av_instance.collect_antivirus_status = Mock(
                        return_value={
                            "software_name": "ClamAV",
                            "enabled": True,
                        }
                    )
                    mock_av.return_value = mock_av_instance

                    with patch(
                        "src.sysmanage_agent.operations.system_control.CommercialAntivirusCollector"
                    ) as mock_cav:
                        mock_cav_instance = Mock()
                        mock_cav_instance.collect_commercial_antivirus_status = Mock(
                            return_value=None
                        )
                        mock_cav.return_value = mock_cav_instance

                        result = await system_control.get_detailed_system_info()

        assert result["success"] is True
        mock_agent.update_os_version.assert_called_once()
        mock_agent.update_hardware.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_detailed_system_info_exception(self, system_control, mock_agent):
        """Test system info retrieval with exception."""
        mock_agent.update_os_version.side_effect = Exception("test error")

        result = await system_control.get_detailed_system_info()

        assert result["success"] is False
        assert "test error" in result["error"]


class TestUpdateSystem:
    """Tests for update_system method."""

    @pytest.mark.asyncio
    async def test_update_system_success(self, system_control):
        """Test successful system update."""
        with patch(
            "src.sysmanage_agent.operations.system_control.UpdateDetector"
        ) as mock_detector:
            mock_instance = Mock()
            mock_instance.update_system = Mock(return_value="Update successful")
            mock_detector.return_value = mock_instance

            result = await system_control.update_system()

        assert result["success"] is True
        assert result["result"] == "Update successful"

    @pytest.mark.asyncio
    async def test_update_system_failure(self, system_control):
        """Test failed system update."""
        with patch(
            "src.sysmanage_agent.operations.system_control.UpdateDetector"
        ) as mock_detector:
            mock_instance = Mock()
            mock_instance.update_system = Mock(side_effect=Exception("update failed"))
            mock_detector.return_value = mock_instance

            result = await system_control.update_system()

        assert result["success"] is False
        assert "update failed" in result["error"]


class TestRestartService:
    """Tests for restart_service method."""

    @pytest.mark.asyncio
    async def test_restart_service_success(self, system_control):
        """Test successful service restart."""
        with patch.object(
            system_control, "execute_shell_command", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = {"success": True, "result": "service restarted"}

            result = await system_control.restart_service({"service_name": "nginx"})

        assert result["success"] is True
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0][0]
        assert "systemctl restart nginx" in call_args["command"]

    @pytest.mark.asyncio
    async def test_restart_service_no_service_name(self, system_control):
        """Test service restart without service name."""
        result = await system_control.restart_service({})

        assert result["success"] is False
        assert "No service name specified" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_service_exception(self, system_control):
        """Test service restart with exception."""
        with patch.object(
            system_control, "execute_shell_command", side_effect=Exception("test error")
        ):
            result = await system_control.restart_service({"service_name": "nginx"})

        assert result["success"] is False
        assert "test error" in result["error"]


class TestRebootSystem:
    """Tests for reboot_system method."""

    @pytest.mark.asyncio
    async def test_reboot_system_linux_success(self, system_control):
        """Test successful Linux reboot."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                system_control, "execute_shell_command", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = {"success": True}

                result = await system_control.reboot_system()

        assert result["success"] is True
        assert "reboot scheduled" in result["result"].lower()
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0][0]
        assert "shutdown -r" in call_args["command"]

    @pytest.mark.asyncio
    async def test_reboot_system_windows_success(self, system_control):
        """Test successful Windows reboot."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(
                system_control, "execute_shell_command", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = {"success": True}

                result = await system_control.reboot_system()

        assert result["success"] is True
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0][0]
        assert "shutdown /r" in call_args["command"]

    @pytest.mark.asyncio
    async def test_reboot_system_failure(self, system_control):
        """Test failed reboot."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                system_control, "execute_shell_command", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = {
                    "success": False,
                    "error": "permission denied",
                }

                result = await system_control.reboot_system()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_reboot_system_exception(self, system_control):
        """Test reboot with exception."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                system_control,
                "execute_shell_command",
                side_effect=Exception("test error"),
            ):
                result = await system_control.reboot_system()

        assert result["success"] is False
        assert "test error" in result["error"]


class TestShutdownSystem:
    """Tests for shutdown_system method."""

    @pytest.mark.asyncio
    async def test_shutdown_system_linux_success(self, system_control):
        """Test successful Linux shutdown."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                system_control, "execute_shell_command", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = {"success": True}

                result = await system_control.shutdown_system()

        assert result["success"] is True
        assert "shutdown scheduled" in result["result"].lower()
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0][0]
        assert "shutdown -h" in call_args["command"]

    @pytest.mark.asyncio
    async def test_shutdown_system_windows_success(self, system_control):
        """Test successful Windows shutdown."""
        with patch("platform.system", return_value="Windows"):
            with patch.object(
                system_control, "execute_shell_command", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = {"success": True}

                result = await system_control.shutdown_system()

        assert result["success"] is True
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args[0][0]
        assert "shutdown /s" in call_args["command"]

    @pytest.mark.asyncio
    async def test_shutdown_system_failure(self, system_control):
        """Test failed shutdown."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                system_control, "execute_shell_command", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = {
                    "success": False,
                    "error": "permission denied",
                }

                result = await system_control.shutdown_system()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_shutdown_system_exception(self, system_control):
        """Test shutdown with exception."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                system_control,
                "execute_shell_command",
                side_effect=Exception("test error"),
            ):
                result = await system_control.shutdown_system()

        assert result["success"] is False
        assert "test error" in result["error"]


class TestSendAntivirusStatusUpdate:
    """Tests for _send_antivirus_status_update method."""

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_success(
        self, system_control, mock_agent
    ):
        """Test successful antivirus status update."""
        antivirus_status = {
            "software_name": "ClamAV",
            "install_path": "/usr/bin/clamscan",
            "version": "0.103.0",
            "enabled": True,
        }

        await system_control._send_antivirus_status_update(antivirus_status)

        mock_agent.create_message.assert_called_once()
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_exception(
        self, system_control, mock_agent
    ):
        """Test antivirus status update with exception."""
        mock_agent.send_message.side_effect = Exception("send failed")

        # Should not raise exception, just log error
        await system_control._send_antivirus_status_update(
            {
                "software_name": "ClamAV",
            }
        )


class TestSendCommercialAntivirusStatusUpdate:
    """Tests for _send_commercial_antivirus_status_update method."""

    @pytest.mark.asyncio
    async def test_send_commercial_antivirus_status_update_success(
        self, system_control, mock_agent
    ):
        """Test successful commercial antivirus status update."""
        commercial_status = {
            "product_name": "Windows Defender",
            "product_version": "4.18.0",
            "service_enabled": True,
            "antispyware_enabled": True,
            "antivirus_enabled": True,
            "realtime_protection_enabled": True,
            "full_scan_age": 7,
            "quick_scan_age": 1,
            "full_scan_end_time": "2024-01-15T10:00:00",
            "quick_scan_end_time": "2024-01-15T12:00:00",
            "signature_last_updated": "2024-01-15T08:00:00",
            "signature_version": "1.401.123.0",
            "tamper_protection_enabled": True,
        }

        await system_control._send_commercial_antivirus_status_update(commercial_status)

        mock_agent.create_message.assert_called_once()
        call_args = mock_agent.create_message.call_args
        assert call_args[0][0] == "commercial_antivirus_status_update"
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_commercial_antivirus_status_update_exception(
        self, system_control, mock_agent
    ):
        """Test commercial antivirus status update with exception."""
        mock_agent.send_message.side_effect = Exception("send failed")

        # Should not raise exception, just log error
        await system_control._send_commercial_antivirus_status_update(
            {
                "product_name": "Test AV",
            }
        )
