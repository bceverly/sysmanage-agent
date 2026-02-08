"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm_ssh module.
Tests VMM SSH operations for VM management.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_vmm_ssh import VmmSshOperations


class TestVmmSshOperationsInit:
    """Test cases for VmmSshOperations initialization."""

    def test_init_with_logger(self):
        """Test VmmSshOperations initialization with logger."""
        mock_logger = Mock()
        ssh_ops = VmmSshOperations(mock_logger)

        assert ssh_ops.logger == mock_logger


class TestWaitForSSH:
    """Test cases for waiting for SSH availability."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.asyncio.sleep")
    async def test_wait_for_ssh_immediate_success(
        self, mock_sleep, mock_time, mock_run_command
    ):
        """Test SSH becomes available immediately."""
        mock_time.return_value = 0
        mock_run_command.return_value = Mock(returncode=0)

        result = await self.ssh_ops.wait_for_ssh("192.168.1.100")

        assert result["success"] is True
        mock_run_command.assert_called_once()
        # Should have one sleep call after success (5 seconds for sshd init)
        mock_sleep.assert_called()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.asyncio.sleep")
    async def test_wait_for_ssh_success_after_retries(
        self, mock_sleep, mock_time, mock_run_command
    ):
        """Test SSH becomes available after a few retries."""
        # Start at time 0, then 5, 10, 15
        mock_time.side_effect = [0, 5, 10, 15]
        mock_run_command.side_effect = [
            Mock(returncode=1),  # First attempt fails
            Mock(returncode=1),  # Second attempt fails
            Mock(returncode=0),  # Third attempt succeeds
        ]

        result = await self.ssh_ops.wait_for_ssh("192.168.1.100", timeout=300)

        assert result["success"] is True
        assert mock_run_command.call_count == 3

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.asyncio.sleep")
    async def test_wait_for_ssh_timeout(self, mock_sleep, mock_time, mock_run_command):
        """Test SSH timeout when host never responds."""
        # Simulate time passing beyond timeout
        mock_time.side_effect = [0, 100, 200, 301]  # Last value exceeds 300 timeout
        mock_run_command.return_value = Mock(returncode=1)

        result = await self.ssh_ops.wait_for_ssh("192.168.1.100", timeout=300)

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.asyncio.sleep")
    async def test_wait_for_ssh_exception_during_check(
        self, mock_sleep, mock_time, mock_run_command
    ):
        """Test SSH check with exception (continues retrying)."""
        mock_time.side_effect = [0, 5, 10]
        mock_run_command.side_effect = [
            Exception("Connection refused"),
            Mock(returncode=0),
        ]

        result = await self.ssh_ops.wait_for_ssh("192.168.1.100", timeout=300)

        assert result["success"] is True
        # Should log debug message for exception
        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.asyncio.sleep")
    async def test_wait_for_ssh_nc_command_args(
        self, mock_sleep, mock_time, mock_run_command
    ):
        """Test that correct nc command is used."""
        mock_time.return_value = 0
        mock_run_command.return_value = Mock(returncode=0)

        await self.ssh_ops.wait_for_ssh("192.168.1.100")

        mock_run_command.assert_called_once_with(
            ["nc", "-z", "-w", "5", "192.168.1.100", "22"], timeout=10
        )


class TestRunSSHCommand:
    """Test cases for running SSH commands."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_run_ssh_command_success(self, mock_run_command):
        """Test successful SSH command execution."""
        mock_run_command.return_value = Mock(
            returncode=0, stdout="command output", stderr=""
        )

        result = await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "testuser", "password123", "echo hello"
        )

        assert result["success"] is True
        assert result["stdout"] == "command output"
        assert result["stderr"] == ""
        assert result["returncode"] == 0
        assert result["error"] is None

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_run_ssh_command_failure(self, mock_run_command):
        """Test failed SSH command execution."""
        mock_run_command.return_value = Mock(
            returncode=1, stdout="", stderr="command not found"
        )

        result = await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "testuser", "password123", "nonexistent_command"
        )

        assert result["success"] is False
        assert result["returncode"] == 1
        assert result["error"] == "command not found"

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_run_ssh_command_timeout(self, mock_run_command):
        """Test SSH command timeout."""
        mock_run_command.side_effect = asyncio.TimeoutError()

        result = await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "testuser", "password123", "long_running_command"
        )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_run_ssh_command_exception(self, mock_run_command):
        """Test SSH command with unexpected exception."""
        mock_run_command.side_effect = Exception("Connection failed")

        result = await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "testuser", "password123", "echo hello"
        )

        assert result["success"] is False
        assert "Connection failed" in result["error"]

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_run_ssh_command_args(self, mock_run_command):
        """Test that correct sshpass/ssh command is constructed."""
        mock_run_command.return_value = Mock(returncode=0, stdout="", stderr="")

        await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "testuser", "password123", "echo hello"
        )

        expected_args = [
            "sshpass",
            "-p",
            "password123",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=30",
            "testuser@192.168.1.100",
            "echo hello",
        ]
        mock_run_command.assert_called_once_with(expected_args, timeout=300)


class TestInstallAgentViaSSH:
    """Test cases for installing agent via SSH."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_install_agent_success(self, mock_run_ssh):
        """Test successful agent installation."""
        mock_run_ssh.return_value = {"success": True}

        commands = ["pkg_add sysmanage-agent", "rcctl enable sysmanage_agent"]

        result = await self.ssh_ops.install_agent_via_ssh(
            "192.168.1.100", "root", "password123", commands
        )

        assert result["success"] is True
        assert mock_run_ssh.call_count == 2

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_install_agent_continues_on_failure(self, mock_run_ssh):
        """Test that installation continues even if a command fails."""
        mock_run_ssh.side_effect = [
            {"success": False, "stderr": "Package not found", "error": "Error"},
            {"success": True},
        ]

        commands = ["pkg_add nonexistent", "pkg_add sysmanage-agent"]

        result = await self.ssh_ops.install_agent_via_ssh(
            "192.168.1.100", "root", "password123", commands
        )

        # Should still succeed overall (continues trying)
        assert result["success"] is True
        assert mock_run_ssh.call_count == 2
        self.mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_install_agent_adds_sudo_for_non_root(self, mock_run_ssh):
        """Test that sudo is added for non-root users."""
        mock_run_ssh.return_value = {"success": True}

        commands = ["pkg_add sysmanage-agent"]

        await self.ssh_ops.install_agent_via_ssh(
            "192.168.1.100", "testuser", "password123", commands  # Not root
        )

        # Should add sudo to command
        call_args = mock_run_ssh.call_args
        assert "sudo pkg_add sysmanage-agent" == call_args[0][3]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_install_agent_no_sudo_for_sudo_commands(self, mock_run_ssh):
        """Test that sudo is not duplicated."""
        mock_run_ssh.return_value = {"success": True}

        commands = ["sudo pkg_add sysmanage-agent"]  # Already has sudo

        await self.ssh_ops.install_agent_via_ssh(
            "192.168.1.100", "testuser", "password123", commands
        )

        # Should not add duplicate sudo
        call_args = mock_run_ssh.call_args
        assert call_args[0][3] == "sudo pkg_add sysmanage-agent"

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_install_agent_exception(self, mock_run_ssh):
        """Test agent installation with exception."""
        mock_run_ssh.side_effect = Exception("SSH connection lost")

        commands = ["pkg_add sysmanage-agent"]

        result = await self.ssh_ops.install_agent_via_ssh(
            "192.168.1.100", "root", "password123", commands
        )

        assert result["success"] is False
        assert "SSH connection lost" in result["error"]


class TestConfigureAgentViaSSH:
    """Test cases for configuring agent via SSH."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_configure_agent_success(self, mock_run_ssh):
        """Test successful agent configuration."""
        mock_run_ssh.return_value = {"success": True}

        result = await self.ssh_ops.configure_agent_via_ssh(
            "192.168.1.100",
            "root",
            "password123",
            "sysmanage.example.com",
            "vm01.example.com",
            8443,
            True,
        )

        assert result["success"] is True
        # Verify config was written
        call_args = mock_run_ssh.call_args
        config_cmd = call_args[0][3]
        assert "cat > /etc/sysmanage-agent.yaml" in config_cmd
        assert "sysmanage.example.com" in config_cmd
        assert "vm01.example.com" in config_cmd
        assert "8443" in config_cmd
        assert "use_https: true" in config_cmd

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_configure_agent_http(self, mock_run_ssh):
        """Test agent configuration with HTTP."""
        mock_run_ssh.return_value = {"success": True}

        await self.ssh_ops.configure_agent_via_ssh(
            "192.168.1.100",
            "root",
            "password123",
            "sysmanage.example.com",
            "vm01.example.com",
            8080,
            False,  # HTTP
        )

        call_args = mock_run_ssh.call_args
        config_cmd = call_args[0][3]
        assert "use_https: false" in config_cmd

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_configure_agent_non_root(self, mock_run_ssh):
        """Test agent configuration as non-root user."""
        mock_run_ssh.return_value = {"success": True}

        await self.ssh_ops.configure_agent_via_ssh(
            "192.168.1.100",
            "testuser",  # Non-root
            "password123",
            "sysmanage.example.com",
            "vm01.example.com",
            8443,
            True,
        )

        call_args = mock_run_ssh.call_args
        config_cmd = call_args[0][3]
        # Should wrap with sudo
        assert "sudo sh -c" in config_cmd

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_configure_agent_failure(self, mock_run_ssh):
        """Test agent configuration failure."""
        mock_run_ssh.return_value = {"success": False, "error": "Permission denied"}

        result = await self.ssh_ops.configure_agent_via_ssh(
            "192.168.1.100",
            "root",
            "password123",
            "sysmanage.example.com",
            "vm01.example.com",
            8443,
            True,
        )

        assert result["success"] is False
        assert "Failed to write agent config" in result["error"]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_configure_agent_exception(self, mock_run_ssh):
        """Test agent configuration with exception."""
        mock_run_ssh.side_effect = Exception("Connection lost")

        result = await self.ssh_ops.configure_agent_via_ssh(
            "192.168.1.100",
            "root",
            "password123",
            "sysmanage.example.com",
            "vm01.example.com",
            8443,
            True,
        )

        assert result["success"] is False
        assert "Connection lost" in result["error"]


class TestStartAgentServiceViaSSH:
    """Test cases for starting agent service via SSH."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_start_service_systemd(self, mock_run_ssh):
        """Test starting service on systemd system."""
        mock_run_ssh.side_effect = [
            {"success": True, "stdout": "/usr/bin/systemctl"},  # detect
            {"success": True},  # start
        ]

        result = await self.ssh_ops.start_agent_service_via_ssh(
            "192.168.1.100", "root", "password123"
        )

        assert result["success"] is True
        # Should use systemctl
        start_call = mock_run_ssh.call_args_list[1]
        assert "systemctl enable --now sysmanage-agent" in start_call[0][3]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_start_service_rcctl(self, mock_run_ssh):
        """Test starting service on OpenBSD with rcctl."""
        mock_run_ssh.side_effect = [
            {"success": True, "stdout": "/usr/sbin/rcctl"},  # detect
            {"success": True},  # start
        ]

        result = await self.ssh_ops.start_agent_service_via_ssh(
            "192.168.1.100", "root", "password123"
        )

        assert result["success"] is True
        # Should use rcctl
        start_call = mock_run_ssh.call_args_list[1]
        assert "rcctl enable sysmanage_agent" in start_call[0][3]
        assert "rcctl start sysmanage_agent" in start_call[0][3]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_start_service_fallback(self, mock_run_ssh):
        """Test starting service with fallback when detection fails."""
        mock_run_ssh.side_effect = [
            {"success": True, "stdout": ""},  # No init system detected
            {"success": True},  # start (fallback)
        ]

        result = await self.ssh_ops.start_agent_service_via_ssh(
            "192.168.1.100", "root", "password123"
        )

        assert result["success"] is True
        # Should use fallback command
        start_call = mock_run_ssh.call_args_list[1]
        cmd = start_call[0][3]
        assert "systemctl enable --now sysmanage-agent" in cmd
        assert "rcctl enable sysmanage_agent" in cmd

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_start_service_non_root(self, mock_run_ssh):
        """Test starting service as non-root user."""
        mock_run_ssh.side_effect = [
            {"success": True, "stdout": "/usr/bin/systemctl"},
            {"success": True},
        ]

        await self.ssh_ops.start_agent_service_via_ssh(
            "192.168.1.100", "testuser", "password123"  # Non-root
        )

        # Should wrap with sudo
        start_call = mock_run_ssh.call_args_list[1]
        assert "sudo sh -c" in start_call[0][3]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_start_service_failure(self, mock_run_ssh):
        """Test starting service failure."""
        mock_run_ssh.side_effect = [
            {"success": True, "stdout": "/usr/bin/systemctl"},
            {"success": False, "error": "Service not found"},
        ]

        result = await self.ssh_ops.start_agent_service_via_ssh(
            "192.168.1.100", "root", "password123"
        )

        assert result["success"] is False
        assert "Failed to start agent service" in result["error"]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_start_service_exception(self, mock_run_ssh):
        """Test starting service with exception."""
        mock_run_ssh.side_effect = Exception("Connection refused")

        result = await self.ssh_ops.start_agent_service_via_ssh(
            "192.168.1.100", "root", "password123"
        )

        assert result["success"] is False
        assert "Connection refused" in result["error"]


class TestVmmSshOperationsIntegration:
    """Integration-style tests for VMM SSH operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "wait_for_ssh")
    @patch.object(VmmSshOperations, "install_agent_via_ssh")
    @patch.object(VmmSshOperations, "configure_agent_via_ssh")
    @patch.object(VmmSshOperations, "start_agent_service_via_ssh")
    async def test_full_agent_deployment(
        self, mock_start, mock_configure, mock_install, mock_wait
    ):
        """Test full agent deployment workflow."""
        mock_wait.return_value = {"success": True}
        mock_install.return_value = {"success": True}
        mock_configure.return_value = {"success": True}
        mock_start.return_value = {"success": True}

        ip_address = "192.168.1.100"
        username = "root"
        password = "password123"

        # Wait for SSH
        wait_result = await self.ssh_ops.wait_for_ssh(ip_address)
        assert wait_result["success"] is True

        # Install agent
        install_result = await self.ssh_ops.install_agent_via_ssh(
            ip_address, username, password, ["pkg_add sysmanage-agent"]
        )
        assert install_result["success"] is True

        # Configure agent
        configure_result = await self.ssh_ops.configure_agent_via_ssh(
            ip_address,
            username,
            password,
            "sysmanage.example.com",
            "vm01.example.com",
            8443,
            True,
        )
        assert configure_result["success"] is True

        # Start service
        start_result = await self.ssh_ops.start_agent_service_via_ssh(
            ip_address, username, password
        )
        assert start_result["success"] is True

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_run_multiple_commands_sequentially(self, mock_run_command):
        """Test running multiple SSH commands sequentially."""
        mock_run_command.return_value = Mock(returncode=0, stdout="success", stderr="")

        commands = [
            "apt-get update",
            "apt-get install -y python3",
            "pip3 install sysmanage-agent",
        ]

        for cmd in commands:
            result = await self.ssh_ops.run_ssh_command(
                "192.168.1.100", "root", "password", cmd
            )
            assert result["success"] is True

        assert mock_run_command.call_count == 3


class TestVmmSshOperationsEdgeCases:
    """Edge case tests for VMM SSH operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.ssh_ops = VmmSshOperations(self.mock_logger)

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_empty_command_output(self, mock_run_command):
        """Test handling empty command output."""
        mock_run_command.return_value = Mock(returncode=0, stdout="", stderr="")

        result = await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "root", "password", "true"
        )

        assert result["success"] is True
        assert result["stdout"] == ""

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    async def test_command_with_special_characters(self, mock_run_command):
        """Test command with special characters."""
        mock_run_command.return_value = Mock(
            returncode=0, stdout="hello world", stderr=""
        )

        cmd = "echo 'hello world' && echo $PATH"
        result = await self.ssh_ops.run_ssh_command(
            "192.168.1.100", "root", "password", cmd
        )

        assert result["success"] is True
        # Verify command was passed correctly
        call_args = mock_run_command.call_args[0][0]
        assert call_args[-1] == cmd

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_install_with_empty_commands(self, mock_run_ssh):
        """Test installation with empty command list."""
        result = await self.ssh_ops.install_agent_via_ssh(
            "192.168.1.100", "root", "password123", []  # Empty commands
        )

        assert result["success"] is True
        mock_run_ssh.assert_not_called()

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.run_command_async")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_ssh.asyncio.sleep")
    async def test_wait_for_ssh_with_short_timeout(
        self, mock_sleep, mock_time, mock_run_command
    ):
        """Test SSH wait with very short timeout."""
        mock_time.side_effect = [0, 2]  # Exceeds timeout of 1
        mock_run_command.return_value = Mock(returncode=1)

        result = await self.ssh_ops.wait_for_ssh("192.168.1.100", timeout=1)

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    @patch.object(VmmSshOperations, "run_ssh_command")
    async def test_configure_agent_special_hostname(self, mock_run_ssh):
        """Test configuration with special characters in hostname."""
        mock_run_ssh.return_value = {"success": True}

        result = await self.ssh_ops.configure_agent_via_ssh(
            "192.168.1.100",
            "root",
            "password123",
            "sysmanage.example.com",
            "vm-test_01.subdomain.example.com",  # Complex hostname
            8443,
            True,
        )

        assert result["success"] is True
        call_args = mock_run_ssh.call_args
        config_cmd = call_args[0][3]
        assert "vm-test_01.subdomain.example.com" in config_cmd
