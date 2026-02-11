"""
Unit tests for src.sysmanage_agent.operations.system_operations module.
Tests system-level operations and commands.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, Mock, patch

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

        # Mock the registration.get_system_info() method
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        # Mock registration.get_os_version_info() to return a dict
        self.mock_agent.registration.get_os_version_info.return_value = {
            "os": "Ubuntu",
            "version": "22.04",
        }

        self.system_ops = SystemOperations(self.mock_agent)
        # Link agent to system_ops for delegated operations
        self.mock_agent.system_ops = self.system_ops

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
        # Mock the async methods
        self.mock_agent.update_os_version = AsyncMock()
        self.mock_agent.update_hardware = AsyncMock()

        with patch(
            "src.sysmanage_agent.operations.system_control.AntivirusCollector"
        ) as mock_av_collector:
            mock_av_instance = Mock()
            mock_av_instance.collect_antivirus_status.return_value = {
                "software_name": "clamav",
                "enabled": True,
            }
            mock_av_collector.return_value = mock_av_instance

            self.system_ops._send_antivirus_status_update = AsyncMock()

            result = await self.system_ops.get_detailed_system_info()

            assert result["success"] is True
            assert result["result"] == "System info refresh initiated"
            self.mock_agent.update_os_version.assert_called_once()
            self.mock_agent.update_hardware.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_detailed_system_info_exception(self):
        """Test system info collection with exception."""
        # Mock the async methods with one raising an exception
        self.mock_agent.update_os_version = AsyncMock(
            side_effect=Exception("Platform error")
        )
        self.mock_agent.update_hardware = AsyncMock()

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
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
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
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
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
            "src.sysmanage_agent.operations.system_control.UpdateDetector"
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
            "src.sysmanage_agent.operations.system_control.UpdateDetector"
        ) as mock_detector_class:
            mock_detector_class.return_value = mock_update_detector

            result = await self.system_ops.update_system()

            assert result["success"] is False
            assert "Update failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_service_success(self):
        """Test successful service restart."""
        with patch.object(
            self.system_ops.system_control,
            "execute_shell_command",
            new_callable=AsyncMock,
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
            self.system_ops.system_control,
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
            self.system_ops.system_control,
            "execute_shell_command",
            new_callable=AsyncMock,
        ) as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await self.system_ops.reboot_system()

            assert result["success"] is True
            assert "System reboot scheduled" in result["result"]
            # Command varies by platform - just verify it was called
            mock_execute.assert_called_once()
            call_args = mock_execute.call_args[0][0]
            assert "command" in call_args

    @pytest.mark.asyncio
    async def test_reboot_system_command_failure(self):
        """Test system reboot with command failure."""
        with patch.object(
            self.system_ops.system_control,
            "execute_shell_command",
            new_callable=AsyncMock,
        ) as mock_execute:
            mock_execute.return_value = {"success": False, "error": "Permission denied"}

            result = await self.system_ops.reboot_system()

            assert result["success"] is False
            assert result["error"] == "Permission denied"

    @pytest.mark.asyncio
    async def test_reboot_system_exception(self):
        """Test system reboot with exception."""
        with patch.object(
            self.system_ops.system_control,
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
            self.system_ops.system_control,
            "execute_shell_command",
            new_callable=AsyncMock,
        ) as mock_execute:
            mock_execute.return_value = {"success": True}

            result = await self.system_ops.shutdown_system()

            assert result["success"] is True
            assert "System shutdown scheduled" in result["result"]
            # Command varies by platform - just verify it was called
            mock_execute.assert_called_once()
            call_args = mock_execute.call_args[0][0]
            assert "command" in call_args

    @pytest.mark.asyncio
    async def test_shutdown_system_command_failure(self):
        """Test system shutdown with command failure."""
        with patch.object(
            self.system_ops.system_control,
            "execute_shell_command",
            new_callable=AsyncMock,
        ) as mock_execute:
            mock_execute.return_value = {"success": False, "error": "Permission denied"}

            result = await self.system_ops.shutdown_system()

            assert result["success"] is False
            assert result["error"] == "Permission denied"

    @pytest.mark.asyncio
    async def test_shutdown_system_exception(self):
        """Test system shutdown with exception."""
        with patch.object(
            self.system_ops.system_control,
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
                self.system_ops.ubuntu_pro_ops,
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
                self.system_ops.ubuntu_pro_ops,
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
                self.system_ops.ubuntu_pro_ops,
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
                self.system_ops.ubuntu_pro_ops,
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
                self.system_ops.ubuntu_pro_ops,
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

    # ========== Package Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_install_packages_delegation(self):
        """Test install_packages delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops, "install_packages", new_callable=AsyncMock
        ) as mock_install:
            mock_install.return_value = {"success": True, "packages": ["vim", "curl"]}

            parameters = {
                "request_id": "test-123",
                "packages": [{"package_name": "vim"}, {"package_name": "curl"}],
            }
            result = await self.system_ops.install_packages(parameters)

            assert result["success"] is True
            mock_install.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_uninstall_packages_delegation(self):
        """Test uninstall_packages delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops, "uninstall_packages", new_callable=AsyncMock
        ) as mock_uninstall:
            mock_uninstall.return_value = {"success": True}

            parameters = {
                "request_id": "test-456",
                "packages": [{"package_name": "vim"}],
            }
            result = await self.system_ops.uninstall_packages(parameters)

            assert result["success"] is True
            mock_uninstall.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_install_packages_with_apt_delegation(self):
        """Test _install_packages_with_apt delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_install_packages_with_apt",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = {"success": True, "output": "Installed"}

            result = await self.system_ops._install_packages_with_apt(["vim", "curl"])

            assert result["success"] is True
            mock_apt.assert_called_once_with(["vim", "curl"])

    @pytest.mark.asyncio
    async def test_uninstall_packages_with_apt_delegation(self):
        """Test _uninstall_packages_with_apt delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_uninstall_packages_with_apt",
            new_callable=AsyncMock,
        ) as mock_apt:
            mock_apt.return_value = {"success": True, "output": "Removed"}

            result = await self.system_ops._uninstall_packages_with_apt(["vim"])

            assert result["success"] is True
            mock_apt.assert_called_once_with(["vim"])

    @pytest.mark.asyncio
    async def test_send_installation_completion_delegation(self):
        """Test _send_installation_completion delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_send_installation_completion",
            new_callable=AsyncMock,
        ) as mock_send:
            await self.system_ops._send_installation_completion(
                "req-123", True, "All installed"
            )

            mock_send.assert_called_once_with("req-123", True, "All installed")

    @pytest.mark.asyncio
    async def test_send_installation_status_update_delegation(self):
        """Test _send_installation_status_update delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_send_installation_status_update",
            new_callable=AsyncMock,
        ) as mock_send:
            await self.system_ops._send_installation_status_update(
                "install-123",
                "completed",
                "vim",
                "admin",
                error_message=None,
                installed_version="8.2",
                installation_log="Success",
            )

            mock_send.assert_called_once_with(
                "install-123",
                "completed",
                "vim",
                "admin",
                None,
                "8.2",
                "Success",
            )

    @pytest.mark.asyncio
    async def test_run_package_update_delegation(self):
        """Test _run_package_update delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_run_package_update",
            new_callable=AsyncMock,
        ) as mock_update:
            await self.system_ops._run_package_update()

            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_update_detection_delegation(self):
        """Test _trigger_update_detection delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_trigger_update_detection",
            new_callable=AsyncMock,
        ) as mock_trigger:
            await self.system_ops._trigger_update_detection()

            mock_trigger.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_package_versions_delegation(self):
        """Test _get_package_versions delegates to package_ops."""
        with patch.object(
            self.system_ops.package_ops,
            "_get_package_versions",
            new_callable=AsyncMock,
        ) as mock_versions:
            mock_versions.return_value = {"vim": "8.2", "curl": "7.68"}

            result = await self.system_ops._get_package_versions(["vim", "curl"])

            assert result == {"vim": "8.2", "curl": "7.68"}
            mock_versions.assert_called_once_with(["vim", "curl"])

    # ========== SSH Key Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_ssh_keys_delegation(self):
        """Test deploy_ssh_keys delegates to ssh_ops."""
        with patch.object(
            self.system_ops.ssh_ops, "deploy_ssh_keys", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.return_value = {"success": True, "result": "Keys deployed"}

            parameters = {
                "username": "testuser",
                "ssh_keys": ["ssh-rsa AAAA..."],
            }
            result = await self.system_ops.deploy_ssh_keys(parameters)

            assert result["success"] is True
            mock_deploy.assert_called_once_with(parameters)

    def test_validate_ssh_key_inputs_delegation(self):
        """Test _validate_ssh_key_inputs delegates to ssh_ops."""
        with patch.object(
            self.system_ops.ssh_ops, "_validate_ssh_key_inputs"
        ) as mock_validate:
            mock_validate.return_value = {"valid": True}

            result = self.system_ops._validate_ssh_key_inputs(
                "testuser", ["ssh-rsa AAAA..."]
            )

            assert result["valid"] is True
            mock_validate.assert_called_once_with("testuser", ["ssh-rsa AAAA..."])

    def test_setup_ssh_environment_delegation(self):
        """Test _setup_ssh_environment delegates to ssh_ops."""
        with patch.object(
            self.system_ops.ssh_ops, "_setup_ssh_environment"
        ) as mock_setup:
            mock_setup.return_value = {"success": True, "ssh_dir": "/home/user/.ssh"}

            result = self.system_ops._setup_ssh_environment("testuser")

            assert result["success"] is True
            mock_setup.assert_called_once_with("testuser")

    # ========== Certificate Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_certificates_delegation(self):
        """Test deploy_certificates delegates to certificate_ops."""
        with patch.object(
            self.system_ops.certificate_ops,
            "deploy_certificates",
            new_callable=AsyncMock,
        ) as mock_deploy:
            mock_deploy.return_value = {
                "success": True,
                "result": "Certificates deployed",
            }

            parameters = {
                "certificates": [{"name": "cert.pem", "content": "-----BEGIN..."}]
            }
            result = await self.system_ops.deploy_certificates(parameters)

            assert result["success"] is True
            mock_deploy.assert_called_once_with(parameters)

    # ========== OpenTelemetry Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_delegation(self):
        """Test deploy_opentelemetry delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops, "deploy_opentelemetry", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.return_value = {"success": True, "result": "OTel deployed"}

            parameters = {"config": "test-config"}
            result = await self.system_ops.deploy_opentelemetry(parameters)

            assert result["success"] is True
            mock_deploy.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_delegation(self):
        """Test remove_opentelemetry delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops, "remove_opentelemetry", new_callable=AsyncMock
        ) as mock_remove:
            mock_remove.return_value = {"success": True, "result": "OTel removed"}

            result = await self.system_ops.remove_opentelemetry({})

            assert result["success"] is True
            mock_remove.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_delegation(self):
        """Test start_opentelemetry_service delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops,
            "start_opentelemetry_service",
            new_callable=AsyncMock,
        ) as mock_start:
            mock_start.return_value = {"success": True, "result": "Service started"}

            result = await self.system_ops.start_opentelemetry_service({})

            assert result["success"] is True
            mock_start.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_stop_opentelemetry_service_delegation(self):
        """Test stop_opentelemetry_service delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops,
            "stop_opentelemetry_service",
            new_callable=AsyncMock,
        ) as mock_stop:
            mock_stop.return_value = {"success": True, "result": "Service stopped"}

            result = await self.system_ops.stop_opentelemetry_service({})

            assert result["success"] is True
            mock_stop.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_restart_opentelemetry_service_delegation(self):
        """Test restart_opentelemetry_service delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops,
            "restart_opentelemetry_service",
            new_callable=AsyncMock,
        ) as mock_restart:
            mock_restart.return_value = {"success": True, "result": "Service restarted"}

            result = await self.system_ops.restart_opentelemetry_service({})

            assert result["success"] is True
            mock_restart.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_connect_opentelemetry_grafana_delegation(self):
        """Test connect_opentelemetry_grafana delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops,
            "connect_opentelemetry_grafana",
            new_callable=AsyncMock,
        ) as mock_connect:
            mock_connect.return_value = {"success": True, "result": "Connected"}

            parameters = {"grafana_url": "http://grafana:3000"}
            result = await self.system_ops.connect_opentelemetry_grafana(parameters)

            assert result["success"] is True
            mock_connect.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_disconnect_opentelemetry_grafana_delegation(self):
        """Test disconnect_opentelemetry_grafana delegates to otel_ops."""
        with patch.object(
            self.system_ops.otel_ops,
            "disconnect_opentelemetry_grafana",
            new_callable=AsyncMock,
        ) as mock_disconnect:
            mock_disconnect.return_value = {"success": True, "result": "Disconnected"}

            result = await self.system_ops.disconnect_opentelemetry_grafana({})

            assert result["success"] is True
            mock_disconnect.assert_called_once_with({})

    # ========== Antivirus Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_antivirus_delegation(self):
        """Test deploy_antivirus delegates to antivirus_ops."""
        with patch.object(
            self.system_ops.antivirus_ops, "deploy_antivirus", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.return_value = {"success": True, "result": "AV deployed"}

            result = await self.system_ops.deploy_antivirus({})

            assert result["success"] is True
            mock_deploy.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_enable_antivirus_delegation(self):
        """Test enable_antivirus delegates to antivirus_ops."""
        with patch.object(
            self.system_ops.antivirus_ops, "enable_antivirus", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "result": "AV enabled"}

            result = await self.system_ops.enable_antivirus({})

            assert result["success"] is True
            mock_enable.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_disable_antivirus_delegation(self):
        """Test disable_antivirus delegates to antivirus_ops."""
        with patch.object(
            self.system_ops.antivirus_ops, "disable_antivirus", new_callable=AsyncMock
        ) as mock_disable:
            mock_disable.return_value = {"success": True, "result": "AV disabled"}

            result = await self.system_ops.disable_antivirus({})

            assert result["success"] is True
            mock_disable.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_remove_antivirus_delegation(self):
        """Test remove_antivirus delegates to antivirus_ops."""
        with patch.object(
            self.system_ops.antivirus_ops, "remove_antivirus", new_callable=AsyncMock
        ) as mock_remove:
            mock_remove.return_value = {"success": True, "result": "AV removed"}

            result = await self.system_ops.remove_antivirus({})

            assert result["success"] is True
            mock_remove.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_delegation(self):
        """Test _send_antivirus_status_update delegates to antivirus_ops."""
        with patch.object(
            self.system_ops.antivirus_ops,
            "_send_antivirus_status_update",
            new_callable=AsyncMock,
        ) as mock_send:
            antivirus_status = {"software_name": "clamav", "enabled": True}
            await self.system_ops._send_antivirus_status_update(antivirus_status)

            mock_send.assert_called_once_with(antivirus_status)

    # ========== Repository Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_list_third_party_repositories_delegation(self):
        """Test list_third_party_repositories delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops,
            "list_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_list:
            mock_list.return_value = {"success": True, "repositories": []}

            result = await self.system_ops.list_third_party_repositories({})

            assert result["success"] is True
            mock_list.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_add_third_party_repository_delegation(self):
        """Test add_third_party_repository delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops,
            "add_third_party_repository",
            new_callable=AsyncMock,
        ) as mock_add:
            mock_add.return_value = {"success": True, "result": "Repository added"}

            parameters = {"repository_url": "https://example.com/repo"}
            result = await self.system_ops.add_third_party_repository(parameters)

            assert result["success"] is True
            mock_add.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_delete_third_party_repositories_delegation(self):
        """Test delete_third_party_repositories delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops,
            "delete_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.return_value = {
                "success": True,
                "result": "Repositories deleted",
            }

            parameters = {"repository_ids": [1, 2, 3]}
            result = await self.system_ops.delete_third_party_repositories(parameters)

            assert result["success"] is True
            mock_delete.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_enable_third_party_repositories_delegation(self):
        """Test enable_third_party_repositories delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops,
            "enable_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_enable:
            mock_enable.return_value = {
                "success": True,
                "result": "Repositories enabled",
            }

            parameters = {"repository_ids": [1, 2]}
            result = await self.system_ops.enable_third_party_repositories(parameters)

            assert result["success"] is True
            mock_enable.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_disable_third_party_repositories_delegation(self):
        """Test disable_third_party_repositories delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops,
            "disable_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_disable:
            mock_disable.return_value = {
                "success": True,
                "result": "Repositories disabled",
            }

            parameters = {"repository_ids": [1, 2]}
            result = await self.system_ops.disable_third_party_repositories(parameters)

            assert result["success"] is True
            mock_disable.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_trigger_third_party_repository_rescan_delegation(self):
        """Test _trigger_third_party_repository_rescan delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops,
            "_trigger_third_party_repository_rescan",
            new_callable=AsyncMock,
        ) as mock_rescan:
            await self.system_ops._trigger_third_party_repository_rescan()

            mock_rescan.assert_called_once()

    def test_check_obs_url_delegation(self):
        """Test _check_obs_url delegates to repo_ops."""
        with patch.object(
            self.system_ops.repo_ops, "_check_obs_url", create=True
        ) as mock_check:
            mock_check.return_value = True

            result = self.system_ops._check_obs_url("https://download.opensuse.org/")

            assert result is True
            mock_check.assert_called_once_with("https://download.opensuse.org/")

    def test_check_obs_url_invalid(self):
        """Test _check_obs_url with invalid URL."""
        with patch.object(
            self.system_ops.repo_ops, "_check_obs_url", create=True
        ) as mock_check:
            mock_check.return_value = False

            result = self.system_ops._check_obs_url("https://random-site.com/")

            assert result is False
            mock_check.assert_called_once_with("https://random-site.com/")

    # ========== Firewall Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_firewall_delegation(self):
        """Test deploy_firewall delegates to firewall_ops."""
        with patch.object(
            self.system_ops.firewall_ops, "deploy_firewall", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.return_value = {"success": True, "result": "Firewall deployed"}

            result = await self.system_ops.deploy_firewall({})

            assert result["success"] is True
            mock_deploy.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_enable_firewall_delegation(self):
        """Test enable_firewall delegates to firewall_ops."""
        with patch.object(
            self.system_ops.firewall_ops, "enable_firewall", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "result": "Firewall enabled"}

            result = await self.system_ops.enable_firewall({})

            assert result["success"] is True
            mock_enable.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_disable_firewall_delegation(self):
        """Test disable_firewall delegates to firewall_ops."""
        with patch.object(
            self.system_ops.firewall_ops, "disable_firewall", new_callable=AsyncMock
        ) as mock_disable:
            mock_disable.return_value = {"success": True, "result": "Firewall disabled"}

            result = await self.system_ops.disable_firewall({})

            assert result["success"] is True
            mock_disable.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_restart_firewall_delegation(self):
        """Test restart_firewall delegates to firewall_ops."""
        with patch.object(
            self.system_ops.firewall_ops, "restart_firewall", new_callable=AsyncMock
        ) as mock_restart:
            mock_restart.return_value = {
                "success": True,
                "result": "Firewall restarted",
            }

            result = await self.system_ops.restart_firewall({})

            assert result["success"] is True
            mock_restart.assert_called_once_with({})

    # ========== User Account Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_create_host_user_delegation(self):
        """Test create_host_user delegates to user_account_ops."""
        with patch.object(
            self.system_ops.user_account_ops, "create_host_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {"success": True, "result": "User created"}

            parameters = {"username": "newuser", "groups": ["sudo"]}
            result = await self.system_ops.create_host_user(parameters)

            assert result["success"] is True
            mock_create.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_create_host_group_delegation(self):
        """Test create_host_group delegates to user_account_ops."""
        with patch.object(
            self.system_ops.user_account_ops,
            "create_host_group",
            new_callable=AsyncMock,
        ) as mock_create:
            mock_create.return_value = {"success": True, "result": "Group created"}

            parameters = {"group_name": "newgroup"}
            result = await self.system_ops.create_host_group(parameters)

            assert result["success"] is True
            mock_create.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_delete_host_user_delegation(self):
        """Test delete_host_user delegates to user_account_ops."""
        with patch.object(
            self.system_ops.user_account_ops, "delete_host_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "result": "User deleted"}

            parameters = {"username": "olduser"}
            result = await self.system_ops.delete_host_user(parameters)

            assert result["success"] is True
            mock_delete.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_delete_host_group_delegation(self):
        """Test delete_host_group delegates to user_account_ops."""
        with patch.object(
            self.system_ops.user_account_ops,
            "delete_host_group",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.return_value = {"success": True, "result": "Group deleted"}

            parameters = {"group_name": "oldgroup"}
            result = await self.system_ops.delete_host_group(parameters)

            assert result["success"] is True
            mock_delete.assert_called_once_with(parameters)

    # ========== Hostname Operations Delegation Tests ==========

    @pytest.mark.asyncio
    async def test_change_hostname_delegation(self):
        """Test change_hostname delegates to hostname_ops."""
        with patch.object(
            self.system_ops.hostname_ops, "change_hostname", new_callable=AsyncMock
        ) as mock_change:
            mock_change.return_value = {"success": True, "result": "Hostname changed"}

            parameters = {"hostname": "new-hostname"}
            result = await self.system_ops.change_hostname(parameters)

            assert result["success"] is True
            mock_change.assert_called_once_with(parameters)

    # ========== Initialization Tests ==========

    def test_init_all_operation_handlers(self):
        """Test that all operation handlers are initialized."""
        assert self.system_ops.certificate_ops is not None
        assert self.system_ops.system_control is not None
        assert self.system_ops.package_ops is not None
        assert self.system_ops.otel_ops is not None
        assert self.system_ops.antivirus_ops is not None
        assert self.system_ops.firewall_ops is not None
        assert self.system_ops.repo_ops is not None
        assert self.system_ops.ssh_ops is not None
        assert self.system_ops.ubuntu_pro_ops is not None
        assert self.system_ops.user_account_ops is not None
        assert self.system_ops.hostname_ops is not None

    def test_init_agent_reference(self):
        """Test that agent reference is properly set."""
        assert self.system_ops.agent == self.mock_agent

    def test_init_logger(self):
        """Test that logger is properly initialized."""
        assert self.system_ops.logger is not None
        assert (
            self.system_ops.logger.name
            == "src.sysmanage_agent.operations.system_operations"
        )

    # ========== Edge Case Tests ==========

    @pytest.mark.asyncio
    async def test_install_packages_with_empty_parameters(self):
        """Test install_packages with empty parameters."""
        with patch.object(
            self.system_ops.package_ops, "install_packages", new_callable=AsyncMock
        ) as mock_install:
            mock_install.return_value = {
                "success": False,
                "error": "No packages specified",
            }

            result = await self.system_ops.install_packages({})

            assert result["success"] is False
            mock_install.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_deploy_certificates_with_empty_list(self):
        """Test deploy_certificates with empty certificate list."""
        with patch.object(
            self.system_ops.certificate_ops,
            "deploy_certificates",
            new_callable=AsyncMock,
        ) as mock_deploy:
            mock_deploy.return_value = {
                "success": False,
                "error": "No certificates provided",
            }

            result = await self.system_ops.deploy_certificates({"certificates": []})

            assert result["success"] is False
            mock_deploy.assert_called_once_with({"certificates": []})

    @pytest.mark.asyncio
    async def test_deploy_ssh_keys_with_invalid_user(self):
        """Test deploy_ssh_keys with invalid username."""
        with patch.object(
            self.system_ops.ssh_ops, "deploy_ssh_keys", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.return_value = {
                "success": False,
                "error": "User does not exist",
            }

            parameters = {"username": "nonexistent", "ssh_keys": ["ssh-rsa AAAA..."]}
            result = await self.system_ops.deploy_ssh_keys(parameters)

            assert result["success"] is False
            mock_deploy.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_change_hostname_with_invalid_hostname(self):
        """Test change_hostname with invalid hostname."""
        with patch.object(
            self.system_ops.hostname_ops, "change_hostname", new_callable=AsyncMock
        ) as mock_change:
            mock_change.return_value = {
                "success": False,
                "error": "Invalid hostname format",
            }

            parameters = {"hostname": "invalid..hostname"}
            result = await self.system_ops.change_hostname(parameters)

            assert result["success"] is False
            mock_change.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_create_host_user_with_existing_user(self):
        """Test create_host_user when user already exists."""
        with patch.object(
            self.system_ops.user_account_ops, "create_host_user", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = {
                "success": False,
                "error": "User already exists",
            }

            parameters = {"username": "existinguser"}
            result = await self.system_ops.create_host_user(parameters)

            assert result["success"] is False
            mock_create.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_add_third_party_repository_with_invalid_url(self):
        """Test add_third_party_repository with invalid URL."""
        with patch.object(
            self.system_ops.repo_ops,
            "add_third_party_repository",
            new_callable=AsyncMock,
        ) as mock_add:
            mock_add.return_value = {
                "success": False,
                "error": "Invalid repository URL",
            }

            parameters = {"repository_url": "not-a-valid-url"}
            result = await self.system_ops.add_third_party_repository(parameters)

            assert result["success"] is False
            mock_add.assert_called_once_with(parameters)

    # ========== Exception Handling Tests ==========

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry_exception(self):
        """Test deploy_opentelemetry when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops, "deploy_opentelemetry", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.side_effect = Exception("Deployment failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.deploy_opentelemetry({})

            assert "Deployment failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_deploy_firewall_exception(self):
        """Test deploy_firewall when exception is raised."""
        with patch.object(
            self.system_ops.firewall_ops, "deploy_firewall", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.side_effect = Exception("Firewall installation failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.deploy_firewall({})

            assert "Firewall installation failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_deploy_antivirus_exception(self):
        """Test deploy_antivirus when exception is raised."""
        with patch.object(
            self.system_ops.antivirus_ops, "deploy_antivirus", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.side_effect = Exception("ClamAV installation failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.deploy_antivirus({})

            assert "ClamAV installation failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_host_group_exception(self):
        """Test create_host_group when exception is raised."""
        with patch.object(
            self.system_ops.user_account_ops,
            "create_host_group",
            new_callable=AsyncMock,
        ) as mock_create:
            mock_create.side_effect = Exception("Group creation failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.create_host_group({"group_name": "testgroup"})

            assert "Group creation failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_delete_host_user_exception(self):
        """Test delete_host_user when exception is raised."""
        with patch.object(
            self.system_ops.user_account_ops, "delete_host_user", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.side_effect = Exception("User deletion failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.delete_host_user({"username": "testuser"})

            assert "User deletion failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_delete_host_group_exception(self):
        """Test delete_host_group when exception is raised."""
        with patch.object(
            self.system_ops.user_account_ops,
            "delete_host_group",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.side_effect = Exception("Group deletion failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.delete_host_group({"group_name": "testgroup"})

            assert "Group deletion failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_change_hostname_exception(self):
        """Test change_hostname when exception is raised."""
        with patch.object(
            self.system_ops.hostname_ops, "change_hostname", new_callable=AsyncMock
        ) as mock_change:
            mock_change.side_effect = Exception("Hostname change failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.change_hostname({"hostname": "newhostname"})

            assert "Hostname change failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_list_third_party_repositories_exception(self):
        """Test list_third_party_repositories when exception is raised."""
        with patch.object(
            self.system_ops.repo_ops,
            "list_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_list:
            mock_list.side_effect = Exception("Repository listing failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.list_third_party_repositories({})

            assert "Repository listing failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_enable_third_party_repositories_exception(self):
        """Test enable_third_party_repositories when exception is raised."""
        with patch.object(
            self.system_ops.repo_ops,
            "enable_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_enable:
            mock_enable.side_effect = Exception("Repository enable failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.enable_third_party_repositories(
                    {"repository_ids": [1]}
                )

            assert "Repository enable failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_disable_third_party_repositories_exception(self):
        """Test disable_third_party_repositories when exception is raised."""
        with patch.object(
            self.system_ops.repo_ops,
            "disable_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_disable:
            mock_disable.side_effect = Exception("Repository disable failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.disable_third_party_repositories(
                    {"repository_ids": [1]}
                )

            assert "Repository disable failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_delete_third_party_repositories_exception(self):
        """Test delete_third_party_repositories when exception is raised."""
        with patch.object(
            self.system_ops.repo_ops,
            "delete_third_party_repositories",
            new_callable=AsyncMock,
        ) as mock_delete:
            mock_delete.side_effect = Exception("Repository deletion failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.delete_third_party_repositories(
                    {"repository_ids": [1]}
                )

            assert "Repository deletion failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_trigger_third_party_repository_rescan_exception(self):
        """Test _trigger_third_party_repository_rescan when exception is raised."""
        with patch.object(
            self.system_ops.repo_ops,
            "_trigger_third_party_repository_rescan",
            new_callable=AsyncMock,
        ) as mock_rescan:
            mock_rescan.side_effect = Exception("Rescan failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops._trigger_third_party_repository_rescan()

            assert "Rescan failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_enable_antivirus_exception(self):
        """Test enable_antivirus when exception is raised."""
        with patch.object(
            self.system_ops.antivirus_ops, "enable_antivirus", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.side_effect = Exception("Enable failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.enable_antivirus({})

            assert "Enable failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_disable_antivirus_exception(self):
        """Test disable_antivirus when exception is raised."""
        with patch.object(
            self.system_ops.antivirus_ops, "disable_antivirus", new_callable=AsyncMock
        ) as mock_disable:
            mock_disable.side_effect = Exception("Disable failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.disable_antivirus({})

            assert "Disable failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_remove_antivirus_exception(self):
        """Test remove_antivirus when exception is raised."""
        with patch.object(
            self.system_ops.antivirus_ops, "remove_antivirus", new_callable=AsyncMock
        ) as mock_remove:
            mock_remove.side_effect = Exception("Remove failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.remove_antivirus({})

            assert "Remove failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_remove_opentelemetry_exception(self):
        """Test remove_opentelemetry when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops, "remove_opentelemetry", new_callable=AsyncMock
        ) as mock_remove:
            mock_remove.side_effect = Exception("Remove failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.remove_opentelemetry({})

            assert "Remove failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_start_opentelemetry_service_exception(self):
        """Test start_opentelemetry_service when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops,
            "start_opentelemetry_service",
            new_callable=AsyncMock,
        ) as mock_start:
            mock_start.side_effect = Exception("Start failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.start_opentelemetry_service({})

            assert "Start failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_stop_opentelemetry_service_exception(self):
        """Test stop_opentelemetry_service when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops,
            "stop_opentelemetry_service",
            new_callable=AsyncMock,
        ) as mock_stop:
            mock_stop.side_effect = Exception("Stop failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.stop_opentelemetry_service({})

            assert "Stop failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_restart_opentelemetry_service_exception(self):
        """Test restart_opentelemetry_service when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops,
            "restart_opentelemetry_service",
            new_callable=AsyncMock,
        ) as mock_restart:
            mock_restart.side_effect = Exception("Restart failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.restart_opentelemetry_service({})

            assert "Restart failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_connect_opentelemetry_grafana_exception(self):
        """Test connect_opentelemetry_grafana when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops,
            "connect_opentelemetry_grafana",
            new_callable=AsyncMock,
        ) as mock_connect:
            mock_connect.side_effect = Exception("Connect failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.connect_opentelemetry_grafana({})

            assert "Connect failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_disconnect_opentelemetry_grafana_exception(self):
        """Test disconnect_opentelemetry_grafana when exception is raised."""
        with patch.object(
            self.system_ops.otel_ops,
            "disconnect_opentelemetry_grafana",
            new_callable=AsyncMock,
        ) as mock_disconnect:
            mock_disconnect.side_effect = Exception("Disconnect failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.disconnect_opentelemetry_grafana({})

            assert "Disconnect failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_enable_firewall_exception(self):
        """Test enable_firewall when exception is raised."""
        with patch.object(
            self.system_ops.firewall_ops, "enable_firewall", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.side_effect = Exception("Enable failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.enable_firewall({})

            assert "Enable failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_disable_firewall_exception(self):
        """Test disable_firewall when exception is raised."""
        with patch.object(
            self.system_ops.firewall_ops, "disable_firewall", new_callable=AsyncMock
        ) as mock_disable:
            mock_disable.side_effect = Exception("Disable failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.disable_firewall({})

            assert "Disable failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_restart_firewall_exception(self):
        """Test restart_firewall when exception is raised."""
        with patch.object(
            self.system_ops.firewall_ops, "restart_firewall", new_callable=AsyncMock
        ) as mock_restart:
            mock_restart.side_effect = Exception("Restart failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.restart_firewall({})

            assert "Restart failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_deploy_ssh_keys_exception(self):
        """Test deploy_ssh_keys when exception is raised."""
        with patch.object(
            self.system_ops.ssh_ops, "deploy_ssh_keys", new_callable=AsyncMock
        ) as mock_deploy:
            mock_deploy.side_effect = Exception("SSH key deployment failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.deploy_ssh_keys(
                    {"username": "user", "ssh_keys": []}
                )

            assert "SSH key deployment failed" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_deploy_certificates_exception(self):
        """Test deploy_certificates when exception is raised."""
        with patch.object(
            self.system_ops.certificate_ops,
            "deploy_certificates",
            new_callable=AsyncMock,
        ) as mock_deploy:
            mock_deploy.side_effect = Exception("Certificate deployment failed")

            with pytest.raises(Exception) as excinfo:
                await self.system_ops.deploy_certificates({"certificates": []})

            assert "Certificate deployment failed" in str(excinfo.value)

    # ========== Return Value Validation Tests ==========

    @pytest.mark.asyncio
    async def test_install_packages_return_structure(self):
        """Test install_packages returns expected structure."""
        with patch.object(
            self.system_ops.package_ops, "install_packages", new_callable=AsyncMock
        ) as mock_install:
            expected_return = {
                "success": True,
                "request_id": "test-123",
                "successful_packages": [{"package_name": "vim", "version": "8.2"}],
                "failed_packages": [],
                "installation_log": "All packages installed",
            }
            mock_install.return_value = expected_return

            result = await self.system_ops.install_packages(
                {"request_id": "test-123", "packages": [{"package_name": "vim"}]}
            )

            assert result == expected_return

    @pytest.mark.asyncio
    async def test_uninstall_packages_return_structure(self):
        """Test uninstall_packages returns expected structure."""
        with patch.object(
            self.system_ops.package_ops, "uninstall_packages", new_callable=AsyncMock
        ) as mock_uninstall:
            expected_return = {
                "success": True,
                "request_id": "test-456",
                "successful_packages": [{"package_name": "vim"}],
                "failed_packages": [],
                "uninstall_log": "All packages uninstalled",
            }
            mock_uninstall.return_value = expected_return

            result = await self.system_ops.uninstall_packages(
                {"request_id": "test-456", "packages": [{"package_name": "vim"}]}
            )

            assert result == expected_return

    @pytest.mark.asyncio
    async def test_get_package_versions_return_structure(self):
        """Test _get_package_versions returns expected structure."""
        with patch.object(
            self.system_ops.package_ops,
            "_get_package_versions",
            new_callable=AsyncMock,
        ) as mock_versions:
            expected_return = {"vim": "8.2.0", "curl": "7.68.0", "git": "2.34.0"}
            mock_versions.return_value = expected_return

            result = await self.system_ops._get_package_versions(["vim", "curl", "git"])

            assert result == expected_return
            assert len(result) == 3
