"""
Unit tests for src.sysmanage_agent.operations.system_operations module.
Tests system-level operations and commands.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
from unittest.mock import Mock, patch, AsyncMock

import pytest

from src.sysmanage_agent.operations.system_operations import SystemOperations


class TestSystemOperations:  # pylint: disable=too-many-public-methods
    """Test cases for SystemOperations class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.hostname = "test-host"
        self.mock_agent.platform = "Linux"
        self.mock_agent.ipv4 = "192.168.1.100"
        self.mock_agent.ipv6 = "::1"
        self.system_ops = SystemOperations(self.mock_agent)

    def test_init(self):
        """Test SystemOperations initialization."""
        assert self.system_ops.agent == self.mock_agent
        assert self.system_ops.logger is not None

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self):
        """Test successful shell command execution."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output", b""))

        with patch(
            "asyncio.create_subprocess_shell", new_callable=AsyncMock
        ) as mock_subprocess:
            mock_subprocess.return_value = mock_process

            parameters = {"command": "echo hello"}
            result = await self.system_ops.execute_shell_command(parameters)

            assert result["success"] is True
            assert result["result"]["stdout"] == "output"
            assert result["result"]["stderr"] == ""
            assert result["result"]["exit_code"] == 0
            assert result["exit_code"] == 0

            mock_subprocess.assert_called_once_with(
                "echo hello",
                cwd=None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

    @pytest.mark.asyncio
    async def test_execute_shell_command_with_working_directory(self):
        """Test shell command execution with working directory."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "asyncio.create_subprocess_shell", new_callable=AsyncMock
        ) as mock_subprocess:
            mock_subprocess.return_value = mock_process

            parameters = {"command": "ls", "working_directory": "/tmp"}
            result = await self.system_ops.execute_shell_command(parameters)

            assert result["success"] is True
            mock_subprocess.assert_called_once_with(
                "ls",
                cwd="/tmp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self):
        """Test shell command execution with non-zero exit code."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch(
            "asyncio.create_subprocess_shell", new_callable=AsyncMock
        ) as mock_subprocess:
            mock_subprocess.return_value = mock_process

            parameters = {"command": "false"}
            result = await self.system_ops.execute_shell_command(parameters)

            assert result["success"] is False
            assert result["result"]["stderr"] == "error"
            assert result["result"]["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_execute_shell_command_no_command(self):
        """Test shell command execution without command parameter."""
        parameters = {}
        result = await self.system_ops.execute_shell_command(parameters)

        assert result["success"] is False
        assert "No command specified" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_shell_command_exception(self):
        """Test shell command execution with exception."""
        with patch(
            "asyncio.create_subprocess_shell", side_effect=Exception("Test error")
        ):
            parameters = {"command": "echo test"}
            result = await self.system_ops.execute_shell_command(parameters)

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_get_detailed_system_info_success(self):
        """Test successful system info collection."""
        with patch("platform.architecture", return_value=("64bit", "ELF")):
            with patch("platform.processor", return_value="x86_64"):
                with patch("platform.system", return_value="Linux"):
                    with patch("platform.release", return_value="5.4.0"):
                        with patch("platform.version", return_value="Ubuntu 20.04"):
                            result = await self.system_ops.get_detailed_system_info()

                            assert result["success"] is True
                            info = result["result"]
                            assert info["hostname"] == "test-host"
                            assert info["platform"] == "Linux"
                            assert info["ipv4"] == "192.168.1.100"
                            assert info["ipv6"] == "::1"
                            assert info["architecture"] == "64bit"
                            assert info["processor"] == "x86_64"
                            assert info["system"] == "Linux"
                            assert info["release"] == "5.4.0"
                            assert info["version"] == "Ubuntu 20.04"

    @pytest.mark.asyncio
    async def test_get_detailed_system_info_exception(self):
        """Test system info collection with exception."""
        with patch("platform.architecture", side_effect=Exception("Platform error")):
            result = await self.system_ops.get_detailed_system_info()

            assert result["success"] is False
            assert "Platform error" in result["error"]

    @pytest.mark.asyncio
    async def test_install_package_success(self):
        """Test successful package installation."""
        mock_update_detector = Mock()
        mock_update_detector.install_package.return_value = (
            "Package installed successfully"
        )

        with patch(
            "src.sysmanage_agent.operations.system_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector_class.return_value = mock_update_detector

            parameters = {"package_name": "vim", "package_manager": "apt"}
            result = await self.system_ops.install_package(parameters)

            assert result["success"] is True
            assert result["result"] == "Package installed successfully"
            mock_update_detector.install_package.assert_called_once_with("vim", "apt")

    @pytest.mark.asyncio
    async def test_install_package_no_name(self):
        """Test package installation without package name."""
        parameters = {}
        result = await self.system_ops.install_package(parameters)

        assert result["success"] is False
        assert "No package name specified" in result["error"]

    @pytest.mark.asyncio
    async def test_install_package_exception(self):
        """Test package installation with exception."""
        mock_update_detector = Mock()
        mock_update_detector.install_package.side_effect = Exception("Install failed")

        with patch(
            "src.sysmanage_agent.operations.system_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector_class.return_value = mock_update_detector

            parameters = {"package_name": "vim"}
            result = await self.system_ops.install_package(parameters)

            assert result["success"] is False
            assert "Install failed" in result["error"]

    @pytest.mark.asyncio
    async def test_update_system_success(self):
        """Test successful system update."""
        mock_update_detector = Mock()
        mock_update_detector.update_system.return_value = "System updated successfully"

        with patch(
            "src.sysmanage_agent.operations.system_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector_class.return_value = mock_update_detector

            result = await self.system_ops.update_system()

            assert result["success"] is True
            assert result["result"] == "System updated successfully"
            mock_update_detector.update_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_system_exception(self):
        """Test system update with exception."""
        mock_update_detector = Mock()
        mock_update_detector.update_system.side_effect = Exception("Update failed")

        with patch(
            "src.sysmanage_agent.operations.system_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector_class.return_value = mock_update_detector

            result = await self.system_ops.update_system()

            assert result["success"] is False
            assert "Update failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_service_success(self):
        """Test successful service restart."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {"success": True, "result": "Service restarted"}

            parameters = {"service_name": "nginx"}
            result = await self.system_ops.restart_service(parameters)

            assert result["success"] is True
            mock_execute.assert_called_once_with(
                {"command": "sudo systemctl restart nginx"}
            )

    @pytest.mark.asyncio
    async def test_restart_service_no_name(self):
        """Test service restart without service name."""
        parameters = {}
        result = await self.system_ops.restart_service(parameters)

        assert result["success"] is False
        assert "No service name specified" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_service_exception(self):
        """Test service restart with exception."""
        with patch.object(
            self.system_ops,
            "execute_shell_command",
            side_effect=Exception("Service error"),
        ):
            parameters = {"service_name": "nginx"}
            result = await self.system_ops.restart_service(parameters)

            assert result["success"] is False
            assert "Service error" in result["error"]

    @pytest.mark.asyncio
    async def test_reboot_system_success(self):
        """Test successful system reboot."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await self.system_ops.reboot_system()

            assert result["success"] is True
            assert "System reboot scheduled" in result["result"]
            mock_execute.assert_called_once_with({"command": "sudo shutdown -r +1"})

    @pytest.mark.asyncio
    async def test_reboot_system_command_failure(self):
        """Test system reboot with command failure."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {"success": False, "error": "Permission denied"}

            result = await self.system_ops.reboot_system()

            assert result["success"] is False
            assert result["error"] == "Permission denied"

    @pytest.mark.asyncio
    async def test_reboot_system_exception(self):
        """Test system reboot with exception."""
        with patch.object(
            self.system_ops,
            "execute_shell_command",
            side_effect=Exception("Reboot error"),
        ):
            result = await self.system_ops.reboot_system()

            assert result["success"] is False
            assert "Reboot error" in result["error"]

    @pytest.mark.asyncio
    async def test_shutdown_system_success(self):
        """Test successful system shutdown."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await self.system_ops.shutdown_system()

            assert result["success"] is True
            assert "System shutdown scheduled" in result["result"]
            mock_execute.assert_called_once_with({"command": "sudo shutdown -h +1"})

    @pytest.mark.asyncio
    async def test_shutdown_system_command_failure(self):
        """Test system shutdown with command failure."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {"success": False, "error": "Permission denied"}

            result = await self.system_ops.shutdown_system()

            assert result["success"] is False
            assert result["error"] == "Permission denied"

    @pytest.mark.asyncio
    async def test_shutdown_system_exception(self):
        """Test system shutdown with exception."""
        with patch.object(
            self.system_ops,
            "execute_shell_command",
            side_effect=Exception("Shutdown error"),
        ):
            result = await self.system_ops.shutdown_system()

            assert result["success"] is False
            assert "Shutdown error" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_success(self):
        """Test successful Ubuntu Pro attachment."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "result": {"stdout": "Attached successfully"},
            }

            parameters = {"token": "test-token-123"}
            result = await self.system_ops.ubuntu_pro_attach(parameters)

            assert result["success"] is True
            mock_execute.assert_called_once_with(
                {"command": "sudo pro attach test-token-123"}
            )

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_no_token(self):
        """Test Ubuntu Pro attachment without token."""
        parameters = {}
        result = await self.system_ops.ubuntu_pro_attach(parameters)

        assert result["success"] is False
        assert "Ubuntu Pro token is required" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_exception(self):
        """Test Ubuntu Pro attachment with exception."""
        with patch.object(
            self.system_ops, "execute_shell_command", side_effect=Exception("Pro error")
        ):
            parameters = {"token": "test-token-123"}
            result = await self.system_ops.ubuntu_pro_attach(parameters)

            assert result["success"] is False
            assert "Pro error" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_command_failure(self):
        """Test Ubuntu Pro attachment with command failure."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            with patch.object(
                self.system_ops,
                "_send_os_update_after_pro_change",
                new_callable=AsyncMock,
            ):
                mock_execute.return_value = {
                    "success": False,
                    "result": {"stderr": "Invalid token"},
                }

                parameters = {"token": "invalid-token"}
                result = await self.system_ops.ubuntu_pro_attach(parameters)

                assert result["success"] is False
                assert "Failed to attach Ubuntu Pro" in result["error"]
                assert result["output"] == "Invalid token"

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_success_with_update(self):
        """Test successful Ubuntu Pro attachment with OS update."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            with patch.object(
                self.system_ops,
                "_send_os_update_after_pro_change",
                new_callable=AsyncMock,
            ) as mock_update:
                mock_execute.return_value = {
                    "success": True,
                    "result": {"stdout": "Attached successfully"},
                }

                parameters = {"token": "valid-token"}
                result = await self.system_ops.ubuntu_pro_attach(parameters)

                assert result["success"] is True
                assert (
                    "Ubuntu Pro subscription attached successfully" in result["result"]
                )
                assert result["output"] == "Attached successfully"
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_ubuntu_pro_detach_success(self):
        """Test successful Ubuntu Pro detachment."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            with patch.object(
                self.system_ops,
                "_send_os_update_after_pro_change",
                new_callable=AsyncMock,
            ) as mock_update:
                mock_execute.return_value = {
                    "success": True,
                    "result": {"stdout": "Detached successfully"},
                }

                result = await self.system_ops.ubuntu_pro_detach({})

                assert result["success"] is True
                assert (
                    "Ubuntu Pro subscription detached successfully" in result["result"]
                )
                assert result["output"] == "Detached successfully"
                mock_execute.assert_called_once_with(
                    {"command": "sudo pro detach --assume-yes"}
                )
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_ubuntu_pro_detach_failure(self):
        """Test Ubuntu Pro detachment failure."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {
                "success": False,
                "result": {"stderr": "Not attached"},
            }

            result = await self.system_ops.ubuntu_pro_detach({})

            assert result["success"] is False
            assert "Failed to detach Ubuntu Pro" in result["error"]
            assert result["output"] == "Not attached"

    @pytest.mark.asyncio
    async def test_ubuntu_pro_detach_exception(self):
        """Test Ubuntu Pro detachment with exception."""
        with patch.object(
            self.system_ops,
            "execute_shell_command",
            side_effect=Exception("Detach error"),
        ):
            result = await self.system_ops.ubuntu_pro_detach({})

            assert result["success"] is False
            assert "Detach error" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service_success(self):
        """Test successful Ubuntu Pro service enable."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            with patch.object(
                self.system_ops,
                "_send_os_update_after_pro_change",
                new_callable=AsyncMock,
            ) as mock_update:
                mock_execute.return_value = {
                    "success": True,
                    "result": {"stdout": "Service enabled"},
                }

                parameters = {"service": "esm-infra"}
                result = await self.system_ops.ubuntu_pro_enable_service(parameters)

                assert result["success"] is True
                assert (
                    "Ubuntu Pro service esm-infra enabled successfully"
                    in result["result"]
                )
                mock_execute.assert_called_once_with(
                    {"command": "sudo pro enable esm-infra --assume-yes"}
                )
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service_no_name(self):
        """Test Ubuntu Pro service enable without service name."""
        parameters = {}
        result = await self.system_ops.ubuntu_pro_enable_service(parameters)

        assert result["success"] is False
        assert "Service name is required" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service_failure(self):
        """Test Ubuntu Pro service enable failure."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {
                "success": False,
                "result": {"stderr": "Service not available"},
            }

            parameters = {"service": "invalid-service"}
            result = await self.system_ops.ubuntu_pro_enable_service(parameters)

            assert result["success"] is False
            assert "Failed to enable Ubuntu Pro service" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service_exception(self):
        """Test Ubuntu Pro service enable with exception."""
        with patch.object(
            self.system_ops,
            "execute_shell_command",
            side_effect=Exception("Enable error"),
        ):
            parameters = {"service": "esm-infra"}
            result = await self.system_ops.ubuntu_pro_enable_service(parameters)

            assert result["success"] is False
            assert "Enable error" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service_success(self):
        """Test successful Ubuntu Pro service disable."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            with patch.object(
                self.system_ops,
                "_send_os_update_after_pro_change",
                new_callable=AsyncMock,
            ) as mock_update:
                mock_execute.return_value = {
                    "success": True,
                    "result": {"stdout": "Service disabled"},
                }

                parameters = {"service": "esm-infra"}
                result = await self.system_ops.ubuntu_pro_disable_service(parameters)

                assert result["success"] is True
                assert (
                    "Ubuntu Pro service esm-infra disabled successfully"
                    in result["result"]
                )
                mock_execute.assert_called_once_with(
                    {"command": "sudo pro disable esm-infra --assume-yes"}
                )
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service_no_name(self):
        """Test Ubuntu Pro service disable without service name."""
        parameters = {}
        result = await self.system_ops.ubuntu_pro_disable_service(parameters)

        assert result["success"] is False
        assert "Service name is required" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service_failure(self):
        """Test Ubuntu Pro service disable failure."""
        with patch.object(
            self.system_ops, "execute_shell_command", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.return_value = {
                "success": False,
                "result": {"stderr": "Service not found"},
            }

            parameters = {"service": "invalid-service"}
            result = await self.system_ops.ubuntu_pro_disable_service(parameters)

            assert result["success"] is False
            assert "Failed to disable Ubuntu Pro service" in result["error"]

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service_exception(self):
        """Test Ubuntu Pro service disable with exception."""
        with patch.object(
            self.system_ops,
            "execute_shell_command",
            side_effect=Exception("Disable error"),
        ):
            parameters = {"service": "esm-infra"}
            result = await self.system_ops.ubuntu_pro_disable_service(parameters)

            assert result["success"] is False
            assert "Disable error" in result["error"]

    @pytest.mark.asyncio
    async def test_send_os_update_after_pro_change(self):
        """Test _send_os_update_after_pro_change method."""
        with patch("asyncio.sleep", new_callable=AsyncMock):
            self.system_ops.agent.registration.get_os_version_info.return_value = {
                "os": "Ubuntu",
                "version": "20.04",
            }
            self.system_ops.agent.registration.get_system_info.return_value = {
                "hostname": "test-host"
            }
            self.system_ops.agent.create_message.return_value = {
                "type": "os_version_update",
                "data": {"os": "Ubuntu", "version": "20.04", "hostname": "test-host"},
            }
            self.system_ops.agent.send_message = AsyncMock()

            await self.system_ops._send_os_update_after_pro_change()

            self.system_ops.agent.registration.get_os_version_info.assert_called_once()
            self.system_ops.agent.registration.get_system_info.assert_called_once()
            self.system_ops.agent.create_message.assert_called_once_with(
                "os_version_update",
                {"os": "Ubuntu", "version": "20.04", "hostname": "test-host"},
            )
            self.system_ops.agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_os_update_after_pro_change_exception(self):
        """Test _send_os_update_after_pro_change with exception."""
        with patch("asyncio.sleep", new_callable=AsyncMock):
            self.system_ops.agent.registration.get_os_version_info.side_effect = (
                Exception("OS info error")
            )

            # Should not raise exception, just log it
            await self.system_ops._send_os_update_after_pro_change()
