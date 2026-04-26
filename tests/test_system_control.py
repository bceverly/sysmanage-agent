"""
Tests for system control operations module.
Tests shell execution, reboot, shutdown, and system update operations.
"""

# pylint: disable=redefined-outer-name,protected-access
# pylint: disable=missing-class-docstring,missing-function-docstring,unused-argument

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


# ---------------------------------------------------------------------------
# Extended coverage: timeout path, update_agent dispatcher, distro detection
# ---------------------------------------------------------------------------


class TestExecuteShellCommandTimeout:
    @pytest.mark.asyncio
    async def test_timeout_kills_process_and_returns_error(self, system_control):
        """Process exceeds timeout → kill + structured timeout payload."""
        proc = Mock()
        proc.kill = Mock()
        proc.wait = AsyncMock()
        proc.communicate = AsyncMock(side_effect=__import__("asyncio").TimeoutError())

        with patch(
            "src.sysmanage_agent.operations.system_control.asyncio.create_subprocess_shell",
            return_value=proc,
        ), patch(
            "src.sysmanage_agent.operations.system_control.asyncio.wait_for",
            side_effect=__import__("asyncio").TimeoutError(),
        ):
            result = await system_control.execute_shell_command(
                {"command": "sleep 9999", "timeout": 1}
            )
        assert result["success"] is False
        assert "timed out" in result["error"].lower()
        proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeout_with_already_dead_process_swallows_lookup_error(
        self, system_control
    ):
        proc = Mock()
        proc.kill = Mock(side_effect=ProcessLookupError())
        proc.wait = AsyncMock()

        with patch(
            "src.sysmanage_agent.operations.system_control.asyncio.create_subprocess_shell",
            return_value=proc,
        ), patch(
            "src.sysmanage_agent.operations.system_control.asyncio.wait_for",
            side_effect=__import__("asyncio").TimeoutError(),
        ):
            result = await system_control.execute_shell_command(
                {"command": "sleep 9999", "timeout": 1}
            )
        # Even when kill() raised, the function should still return a structured timeout.
        assert result["exit_code"] == -1


class TestGetDetailedSystemInfoExceptionArms:
    @pytest.mark.asyncio
    async def test_antivirus_collection_failure_logged_not_raised(
        self, system_control, mock_agent
    ):
        with patch(
            "src.sysmanage_agent.operations.system_control.AntivirusCollector",
            side_effect=RuntimeError("av broken"),
        ), patch(
            "src.sysmanage_agent.operations.system_control.CommercialAntivirusCollector"
        ) as commercial:
            commercial.return_value.collect_commercial_antivirus_status.return_value = (
                None
            )
            result = await system_control.get_detailed_system_info()
        # The outer call should still report success.
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_commercial_antivirus_failure_logged_not_raised(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.AntivirusCollector"
        ) as av_cls, patch(
            "src.sysmanage_agent.operations.system_control.CommercialAntivirusCollector",
            side_effect=RuntimeError("commercial broken"),
        ):
            av_cls.return_value.collect_antivirus_status.return_value = {}
            result = await system_control.get_detailed_system_info()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_graylog_status_failure_logged_not_raised(
        self, system_control, mock_agent
    ):
        mock_agent.data_collector._send_graylog_status_update = AsyncMock(
            side_effect=RuntimeError("graylog down")
        )
        with patch(
            "src.sysmanage_agent.operations.system_control.AntivirusCollector"
        ) as av_cls, patch(
            "src.sysmanage_agent.operations.system_control.CommercialAntivirusCollector"
        ) as commercial:
            av_cls.return_value.collect_antivirus_status.return_value = {}
            commercial.return_value.collect_commercial_antivirus_status.return_value = (
                None
            )
            result = await system_control.get_detailed_system_info()
        assert result["success"] is True


class TestUpdateAgentDispatcher:
    @pytest.mark.asyncio
    async def test_linux_dispatches_to_linux_helper(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.system",
            return_value="Linux",
        ), patch.object(
            system_control,
            "_update_agent_linux",
            new=AsyncMock(return_value={"success": True, "result": "ok"}),
        ) as helper:
            result = await system_control.update_agent()
        assert result == {"success": True, "result": "ok"}
        helper.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_freebsd_dispatches_to_freebsd_helper(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.system",
            return_value="FreeBSD",
        ), patch.object(
            system_control,
            "_update_agent_freebsd",
            new=AsyncMock(return_value={"success": True, "result": "ok"}),
        ) as helper:
            result = await system_control.update_agent()
        assert result["success"] is True
        helper.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_windows_returns_unsupported(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.system",
            return_value="Windows",
        ):
            result = await system_control.update_agent()
        assert result["success"] is False
        assert "Windows" in result["error"]

    @pytest.mark.asyncio
    async def test_darwin_returns_unsupported(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.system",
            return_value="Darwin",
        ):
            result = await system_control.update_agent()
        assert result["success"] is False
        assert "macOS" in result["error"]

    @pytest.mark.asyncio
    async def test_unknown_platform_returns_unsupported(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.system",
            return_value="Plan9",
        ):
            result = await system_control.update_agent()
        assert result["success"] is False
        assert (
            "plan9" in result["error"].lower()
            or "unsupported" in result["error"].lower()
        )

    @pytest.mark.asyncio
    async def test_exception_during_dispatch_returns_failure(self, system_control):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.system",
            side_effect=RuntimeError("platform down"),
        ):
            result = await system_control.update_agent()
        assert result["success"] is False
        assert "platform down" in result["error"]


class TestDetectLinuxDistro:
    # `create=True` on the three patches below lets the tests run on
    # Python 3.9, where platform.freedesktop_os_release does not exist
    # in the stdlib.  The patch materializes the attribute so the
    # production code's `hasattr(platform, ...)` guard sees it and
    # exercises the freedesktop branch under test.
    def test_uses_freedesktop_when_available(self):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.freedesktop_os_release",
            return_value={"ID": "Ubuntu", "ID_LIKE": "Debian"},
            create=True,
        ):
            distro_id, distro_id_like = SystemControl._detect_linux_distro()
        assert distro_id == "ubuntu"
        assert distro_id_like == "debian"

    def test_falls_back_to_os_release_file(self):
        # freedesktop helper raises OSError → falls through to file parse.
        os_release_content = 'ID="rocky"\nID_LIKE="rhel fedora"\n'
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.freedesktop_os_release",
            side_effect=OSError("no module"),
            create=True,
        ), patch(
            "builtins.open",
            __import__("unittest").mock.mock_open(read_data=os_release_content),
        ):
            distro_id, distro_id_like = SystemControl._detect_linux_distro()
        assert distro_id == "rocky"
        assert distro_id_like == "rhel fedora"

    def test_returns_none_tuple_when_no_os_release_file(self):
        with patch(
            "src.sysmanage_agent.operations.system_control.platform.freedesktop_os_release",
            side_effect=OSError("no module"),
            create=True,
        ), patch("builtins.open", side_effect=FileNotFoundError):
            distro_id, distro_id_like = SystemControl._detect_linux_distro()
        assert distro_id is None
        assert distro_id_like is None


class TestUpdateAgentLinux:
    @pytest.mark.asyncio
    async def test_unknown_distro_returns_failure(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=(None, None)
        ):
            result = await system_control._update_agent_linux()
        assert result["success"] is False
        assert "Cannot detect" in result["error"]

    @pytest.mark.asyncio
    async def test_debian_path_uses_apt_get(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=("ubuntu", "debian")
        ), patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": True}),
        ) as exec_cmd:
            result = await system_control._update_agent_linux()
        assert result["success"] is True
        cmd = exec_cmd.call_args.args[0]["command"]
        assert "apt-get" in cmd
        assert "sysmanage-agent" in cmd

    @pytest.mark.asyncio
    async def test_fedora_path_uses_dnf(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=("fedora", "")
        ), patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": True}),
        ) as exec_cmd:
            result = await system_control._update_agent_linux()
        assert result["success"] is True
        assert "dnf" in exec_cmd.call_args.args[0]["command"]

    @pytest.mark.asyncio
    async def test_suse_path_uses_zypper(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=("opensuse", "suse")
        ), patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": True}),
        ) as exec_cmd:
            await system_control._update_agent_linux()
        assert "zypper" in exec_cmd.call_args.args[0]["command"]

    @pytest.mark.asyncio
    async def test_alpine_path_uses_apk(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=("alpine", "")
        ), patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": True}),
        ) as exec_cmd:
            await system_control._update_agent_linux()
        assert "apk" in exec_cmd.call_args.args[0]["command"]

    @pytest.mark.asyncio
    async def test_unsupported_distro_returns_failure(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=("plan9", "")
        ):
            result = await system_control._update_agent_linux()
        assert result["success"] is False
        assert "plan9" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_command_failure_propagates(self, system_control):
        with patch.object(
            SystemControl, "_detect_linux_distro", return_value=("ubuntu", "debian")
        ), patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": False, "error": "apt locked"}),
        ):
            result = await system_control._update_agent_linux()
        assert result["success"] is False
        assert result["error"] == "apt locked"


class TestUpdateAgentFreebsd:
    @pytest.mark.asyncio
    async def test_success_uses_pkg(self, system_control):
        with patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": True}),
        ) as exec_cmd:
            result = await system_control._update_agent_freebsd()
        assert result["success"] is True
        assert "pkg" in exec_cmd.call_args.args[0]["command"]

    @pytest.mark.asyncio
    async def test_failure_propagates(self, system_control):
        with patch.object(
            system_control,
            "execute_shell_command",
            new=AsyncMock(return_value={"success": False, "error": "pkg broken"}),
        ):
            result = await system_control._update_agent_freebsd()
        assert result["success"] is False
