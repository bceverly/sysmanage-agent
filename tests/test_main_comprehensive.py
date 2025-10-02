"""
Comprehensive tests for main.py SysManageAgent class.
Focuses on improving coverage for async methods, message handlers,
system operations, and diagnostics collection.
"""

import os
import tempfile
import uuid
from unittest.mock import AsyncMock, Mock, patch

import pytest
import yaml

from main import SysManageAgent


class TestSysManageAgentAsyncMethods:
    """Test async methods in SysManageAgent class."""

    @pytest.fixture
    def agent_with_config(self):
        """Create agent with temporary config for testing."""
        # Create a temporary log file for this test
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as temp_log:
            temp_log_path = temp_log.name

        config_data = {
            "server": {"hostname": "test.com", "port": 8080},
            "agent": {"id": str(uuid.uuid4())},
            "logging": {"file": temp_log_path},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        with patch("main.initialize_database"), patch("main.get_database_manager"):
            agent = SysManageAgent(temp_config)

        yield agent

        if os.path.exists(temp_config):
            os.unlink(temp_config)
        if os.path.exists(temp_log_path):
            os.unlink(temp_log_path)

    def test_try_load_config_exists(self, agent_with_config):
        """Test try_load_config with existing file."""
        agent = agent_with_config

        with patch("os.path.exists", return_value=True):
            result = agent.try_load_config("test_config.yaml")
            assert result is True

    def test_try_load_config_missing(self, agent_with_config):
        """Test try_load_config with missing file."""
        agent = agent_with_config

        with patch("os.path.exists", return_value=False):
            result = agent.try_load_config("missing_config.yaml")
            assert result is False

    def test_create_message(self, agent_with_config):
        """Test create_message method."""
        agent = agent_with_config

        message_type = "test_message"
        data = {"key": "value"}

        result = agent.create_message(message_type, data)

        assert result["message_id"] is not None
        assert result["timestamp"] is not None
        assert result["message_type"] == message_type
        assert result["data"] == data

    def test_create_system_info_message(self, agent_with_config):
        """Test create_system_info_message method."""
        agent = agent_with_config

        mock_system_info = {
            "hostname": "test-host",
            "platform": "Linux",
            "platform_release": "5.4.0",
        }

        agent.registration.get_system_info = Mock(return_value=mock_system_info)

        result = agent.create_system_info_message()

        assert result["message_type"] == "system_info"
        assert result["data"] == mock_system_info
        agent.registration.get_system_info.assert_called_once()

    def test_create_heartbeat_message(self, agent_with_config):
        """Test create_heartbeat_message method."""
        agent = agent_with_config

        mock_system_info = {
            "hostname": "test-host",
            "ipv4": ["192.168.1.100"],
            "ipv6": ["::1"],
        }

        agent.registration.get_system_info = Mock(return_value=mock_system_info)
        agent.config.is_script_execution_enabled = Mock(return_value=True)
        agent.config.get_allowed_shells = Mock(return_value=["bash", "sh"])

        with patch("main.is_running_privileged", return_value=False):
            result = agent.create_heartbeat_message()

        assert result["message_type"] == "heartbeat"
        assert result["data"]["agent_status"] == "healthy"
        assert result["data"]["hostname"] == "test-host"
        assert result["data"]["ipv4"] == ["192.168.1.100"]
        assert result["data"]["ipv6"] == ["::1"]
        assert result["data"]["is_privileged"] is False
        assert result["data"]["script_execution_enabled"] is True
        assert result["data"]["enabled_shells"] == ["bash", "sh"]
        agent.registration.get_system_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_success(self, agent_with_config):
        """Test successful message sending."""
        agent = agent_with_config
        agent.message_handler.queue_outbound_message = AsyncMock(
            return_value="msg_id_123"
        )

        message = {"type": "test", "data": "test_data"}

        result = await agent.send_message(message)

        assert result is True
        agent.message_handler.queue_outbound_message.assert_called_once_with(message)

    @pytest.mark.asyncio
    async def test_send_message_failure(self, agent_with_config):
        """Test send_message failure handling."""
        agent = agent_with_config
        agent.message_handler.queue_outbound_message = AsyncMock(
            side_effect=Exception("Queue error")
        )

        message = {"type": "test", "data": "test_data"}

        result = await agent.send_message(message)

        assert result is False
        agent.message_handler.queue_outbound_message.assert_called_once_with(message)

    @pytest.mark.asyncio
    async def test_handle_command_unknown(self, agent_with_config):
        """Test handling unknown command."""
        agent = agent_with_config
        agent.message_processor.handle_command = AsyncMock()

        message = {
            "message_id": str(uuid.uuid4()),
            "command": "unknown_command",
            "parameters": {},
        }

        await agent.handle_command(message)
        agent.message_processor.handle_command.assert_called_once_with(message)

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self, agent_with_config):
        """Test successful shell command execution."""
        agent = agent_with_config

        parameters = {"command": "echo hello"}
        expected_result = {
            "success": True,
            "stdout": "hello\n",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.execute_shell_command = AsyncMock(return_value=expected_result)

        result = await agent.execute_shell_command(parameters)

        assert result == expected_result
        agent.system_ops.execute_shell_command.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self, agent_with_config):
        """Test failed shell command execution."""
        agent = agent_with_config

        parameters = {"command": "false"}  # Command that always fails
        expected_result = {
            "success": False,
            "stdout": "",
            "stderr": "Command failed",
            "exit_code": 1,
        }

        agent.system_ops.execute_shell_command = AsyncMock(return_value=expected_result)

        result = await agent.execute_shell_command(parameters)

        assert result == expected_result
        agent.system_ops.execute_shell_command.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_execute_shell_command_exception(self, agent_with_config):
        """Test shell command execution with exception."""
        agent = agent_with_config

        parameters = {"command": "echo test"}

        agent.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Execution error")
        )

        # The method should propagate the exception since it doesn't handle them
        with pytest.raises(Exception, match="Execution error"):
            await agent.execute_shell_command(parameters)

    @pytest.mark.asyncio
    async def test_get_detailed_system_info(self, agent_with_config):
        """Test detailed system info collection."""
        agent = agent_with_config

        mock_system_info = {
            "hostname": "test.example.com",
            "platform": "Linux",
            "platform_release": "5.4.0",
            "memory": {"total": 8000000000, "available": 4000000000},
        }

        agent.system_ops.get_detailed_system_info = AsyncMock(
            return_value=mock_system_info
        )

        result = await agent.get_detailed_system_info()

        assert result == mock_system_info
        agent.system_ops.get_detailed_system_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_install_package_success(self, agent_with_config):
        """Test successful package installation."""
        agent = agent_with_config

        parameters = {"package_name": "vim"}
        expected_result = {
            "success": True,
            "stdout": "Package installed successfully",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.install_package = AsyncMock(return_value=expected_result)

        result = await agent.install_package(parameters)

        assert result == expected_result
        agent.system_ops.install_package.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_install_package_missing_name(self, agent_with_config):
        """Test package installation with missing package name."""
        agent = agent_with_config

        parameters = {}
        expected_result = {"success": False, "error": "package_name is required"}

        agent.system_ops.install_package = AsyncMock(return_value=expected_result)

        result = await agent.install_package(parameters)

        assert result == expected_result
        agent.system_ops.install_package.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_update_system_success(self, agent_with_config):
        """Test successful system update."""
        agent = agent_with_config

        expected_result = {
            "success": True,
            "stdout": "System updated successfully",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.update_system = AsyncMock(return_value=expected_result)

        result = await agent.update_system()

        assert result == expected_result
        agent.system_ops.update_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_service_success(self, agent_with_config):
        """Test successful service restart."""
        agent = agent_with_config

        parameters = {"service_name": "nginx"}

        expected_result = {
            "success": True,
            "stdout": "Service restarted",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.restart_service = AsyncMock(return_value=expected_result)

        result = await agent.restart_service(parameters)

        assert result == expected_result
        agent.system_ops.restart_service.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_restart_service_missing_name(self, agent_with_config):
        """Test service restart with missing service name."""
        agent = agent_with_config

        parameters = {}
        expected_result = {"success": False, "error": "service_name is required"}

        agent.system_ops.restart_service = AsyncMock(return_value=expected_result)

        result = await agent.restart_service(parameters)

        assert result == expected_result
        agent.system_ops.restart_service.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_reboot_system(self, agent_with_config):
        """Test system reboot command."""
        agent = agent_with_config

        expected_result = {
            "success": True,
            "message": "Rebooting system",
            "stdout": "Rebooting system",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.reboot_system = AsyncMock(return_value=expected_result)

        result = await agent.reboot_system()

        assert result == expected_result
        agent.system_ops.reboot_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_system(self, agent_with_config):
        """Test system shutdown command."""
        agent = agent_with_config

        expected_result = {
            "success": True,
            "message": "Shutting down system",
            "stdout": "Shutting down system",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.shutdown_system = AsyncMock(return_value=expected_result)

        result = await agent.shutdown_system()

        assert result == expected_result
        agent.system_ops.shutdown_system.assert_called_once()


class TestUbuntuProOperations:
    """Test Ubuntu Pro related operations."""

    @pytest.fixture
    def agent_with_config(self):
        """Create agent with temporary config for testing."""
        # Create a temporary log file for this test
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as temp_log:
            temp_log_path = temp_log.name

        config_data = {
            "server": {"hostname": "test.com", "port": 8080},
            "agent": {"id": str(uuid.uuid4())},
            "logging": {"file": temp_log_path},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        with patch("main.initialize_database"), patch("main.get_database_manager"):
            agent = SysManageAgent(temp_config)

        yield agent

        if os.path.exists(temp_config):
            os.unlink(temp_config)
        if os.path.exists(temp_log_path):
            os.unlink(temp_log_path)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_success(self, agent_with_config):
        """Test successful Ubuntu Pro attach."""
        agent = agent_with_config

        parameters = {"token": "test_token"}
        expected_result = {
            "success": True,
            "stdout": "Ubuntu Pro attached successfully",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.ubuntu_pro_attach = AsyncMock(return_value=expected_result)

        result = await agent.ubuntu_pro_attach(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_attach.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach_missing_token(self, agent_with_config):
        """Test Ubuntu Pro attach with missing token."""
        agent = agent_with_config

        parameters = {}
        expected_result = {"success": False, "error": "token is required"}

        agent.system_ops.ubuntu_pro_attach = AsyncMock(return_value=expected_result)

        result = await agent.ubuntu_pro_attach(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_attach.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_detach_success(self, agent_with_config):
        """Test successful Ubuntu Pro detach."""
        agent = agent_with_config

        parameters = {}

        expected_result = {
            "success": True,
            "stdout": "Ubuntu Pro detached successfully",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.ubuntu_pro_detach = AsyncMock(return_value=expected_result)

        result = await agent.ubuntu_pro_detach(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_detach.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service_success(self, agent_with_config):
        """Test successful Ubuntu Pro service enable."""
        agent = agent_with_config

        parameters = {"service": "esm-infra"}

        expected_result = {
            "success": True,
            "stdout": "Service enabled",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.ubuntu_pro_enable_service = AsyncMock(
            return_value=expected_result
        )

        result = await agent.ubuntu_pro_enable_service(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_enable_service.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service_missing_service(self, agent_with_config):
        """Test Ubuntu Pro service enable with missing service name."""
        agent = agent_with_config

        parameters = {}
        expected_result = {"success": False, "error": "service is required"}

        agent.system_ops.ubuntu_pro_enable_service = AsyncMock(
            return_value=expected_result
        )

        result = await agent.ubuntu_pro_enable_service(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_enable_service.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service_success(self, agent_with_config):
        """Test successful Ubuntu Pro service disable."""
        agent = agent_with_config

        parameters = {"service": "esm-infra"}

        expected_result = {
            "success": True,
            "stdout": "Service disabled",
            "stderr": "",
            "exit_code": 0,
        }

        agent.system_ops.ubuntu_pro_disable_service = AsyncMock(
            return_value=expected_result
        )

        result = await agent.ubuntu_pro_disable_service(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_disable_service.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service_missing_service(self, agent_with_config):
        """Test Ubuntu Pro service disable with missing service name."""
        agent = agent_with_config

        parameters = {}
        expected_result = {"success": False, "error": "service is required"}

        agent.system_ops.ubuntu_pro_disable_service = AsyncMock(
            return_value=expected_result
        )

        result = await agent.ubuntu_pro_disable_service(parameters)

        assert result == expected_result
        agent.system_ops.ubuntu_pro_disable_service.assert_called_once_with(parameters)


class TestScriptExecution:
    """Test script execution functionality."""

    @pytest.fixture
    def agent_with_config(self):
        """Create agent with temporary config for testing."""
        # Create a temporary log file for this test
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as temp_log:
            temp_log_path = temp_log.name

        config_data = {
            "server": {"hostname": "test.com", "port": 8080},
            "agent": {"id": str(uuid.uuid4())},
            "logging": {"file": temp_log_path},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        with patch("main.initialize_database"), patch("main.get_database_manager"):
            agent = SysManageAgent(temp_config)

        yield agent

        if os.path.exists(temp_config):
            os.unlink(temp_config)
        if os.path.exists(temp_log_path):
            os.unlink(temp_log_path)

    @pytest.mark.asyncio
    async def test_execute_script_success(self, agent_with_config):
        """Test successful script execution."""
        agent = agent_with_config

        parameters = {
            "execution_uuid": str(uuid.uuid4()),
            "script_content": "echo 'hello world'",
            "shell_type": "bash",
        }

        expected_result = {
            "success": True,
            "exit_code": 0,
            "stdout": "hello world\n",
            "stderr": "",
        }

        agent.script_ops.execute_script = AsyncMock(return_value=expected_result)

        result = await agent.execute_script(parameters)

        assert result == expected_result
        agent.script_ops.execute_script.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_execute_script_missing_uuid(self, agent_with_config):
        """Test script execution with missing execution UUID."""
        agent = agent_with_config

        parameters = {"script_content": "echo 'test'", "shell_type": "bash"}
        expected_result = {"success": False, "error": "execution_uuid is required"}

        agent.script_ops.execute_script = AsyncMock(return_value=expected_result)

        result = await agent.execute_script(parameters)

        assert result == expected_result
        agent.script_ops.execute_script.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_execute_script_missing_content(self, agent_with_config):
        """Test script execution with missing script content."""
        agent = agent_with_config

        parameters = {"execution_uuid": str(uuid.uuid4()), "shell_type": "bash"}
        expected_result = {"success": False, "error": "script_content is required"}

        agent.script_ops.execute_script = AsyncMock(return_value=expected_result)

        result = await agent.execute_script(parameters)

        assert result == expected_result
        agent.script_ops.execute_script.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_execute_script_missing_shell_type(self, agent_with_config):
        """Test script execution with missing shell type."""
        agent = agent_with_config

        parameters = {
            "execution_uuid": str(uuid.uuid4()),
            "script_content": "echo 'test'",
        }
        expected_result = {"success": False, "error": "shell_type is required"}

        agent.script_ops.execute_script = AsyncMock(return_value=expected_result)

        result = await agent.execute_script(parameters)

        assert result == expected_result
        agent.script_ops.execute_script.assert_called_once_with(parameters)
