"""
Basic tests for SysManage agent functionality.
"""

import json
import platform
import socket
from unittest.mock import patch, Mock

import pytest

from main import SysManageAgent


class TestAgentInitialization:
    """Test agent initialization and basic properties."""

    def test_agent_creation(self):
        """Test creating an agent instance."""
        agent = SysManageAgent("wss://test.example.com/agent/connect")

        assert agent.server_url == "wss://test.example.com/agent/connect"
        assert agent.agent_id is not None
        assert len(agent.agent_id) > 0
        assert agent.websocket is None
        assert agent.running is False
        assert agent.hostname is not None
        assert agent.platform is not None

    def test_agent_default_url(self):
        """Test agent with default server URL."""
        agent = SysManageAgent()

        assert agent.server_url == "wss://api.sysmanage.org:6443/agent/connect"

    @patch("main.socket.getfqdn")
    def test_get_hostname(self, mock_getfqdn):
        """Test hostname detection."""
        mock_getfqdn.return_value = "test.example.com"

        agent = SysManageAgent()
        hostname = agent.get_hostname()

        assert hostname == "test.example.com"
        assert mock_getfqdn.call_count == 2  # Called once in __init__ and once in test

    @patch("main.socket.socket")
    def test_get_ip_addresses_success(self, mock_socket):
        """Test successful IP address detection."""
        # Mock IPv4 socket - need to support context manager
        mock_ipv4_socket = Mock()
        mock_ipv4_socket.getsockname.return_value = ("192.168.1.100", 12345)
        mock_ipv4_socket.__enter__ = Mock(return_value=mock_ipv4_socket)
        mock_ipv4_socket.__exit__ = Mock(return_value=None)

        # Mock IPv6 socket - need to support context manager
        mock_ipv6_socket = Mock()
        mock_ipv6_socket.getsockname.return_value = ("2001:db8::1", 12345, 0, 0)
        mock_ipv6_socket.__enter__ = Mock(return_value=mock_ipv6_socket)
        mock_ipv6_socket.__exit__ = Mock(return_value=None)

        def socket_side_effect(family, socket_type):
            if family == socket.AF_INET:
                return mock_ipv4_socket
            if family == socket.AF_INET6:
                return mock_ipv6_socket
            return Mock()

        mock_socket.side_effect = socket_side_effect

        agent = SysManageAgent()
        ipv4, ipv6 = agent.get_ip_addresses()

        assert ipv4 == "192.168.1.100"
        assert ipv6 == "2001:db8::1"

    @patch("main.socket.socket")
    def test_get_ip_addresses_failure(self, mock_socket):
        """Test IP address detection with connection failures."""
        mock_socket.side_effect = Exception("Network error")

        agent = SysManageAgent()
        ipv4, ipv6 = agent.get_ip_addresses()

        assert ipv4 is None
        assert ipv6 is None

    def test_platform_detection(self):
        """Test platform detection."""
        agent = SysManageAgent()

        assert agent.platform == platform.system()
        assert agent.platform in ["Linux", "Windows", "Darwin", "FreeBSD", "OpenBSD"]


class TestMessageCreation:
    """Test message creation functionality."""

    def test_create_message_basic(self, agent):
        """Test basic message creation."""
        msg = agent.create_message("test_type", {"key": "value"})

        assert msg["message_type"] == "test_type"
        assert msg["data"]["key"] == "value"
        assert "message_id" in msg
        assert "timestamp" in msg
        assert len(msg["message_id"]) > 0

    def test_create_message_no_data(self, agent):
        """Test message creation without data."""
        msg = agent.create_message("ping")

        assert msg["message_type"] == "ping"
        assert msg["data"] == {}
        assert "message_id" in msg
        assert "timestamp" in msg

    def test_create_system_info_message(self, agent):
        """Test system info message creation."""
        msg = agent.create_system_info_message()

        assert msg["message_type"] == "system_info"
        assert msg["data"]["hostname"] == agent.hostname
        assert msg["data"]["platform"] == agent.platform
        assert msg["data"]["ipv4"] == agent.ipv4
        assert msg["data"]["ipv6"] == agent.ipv6

    def test_create_heartbeat_message(self, agent):
        """Test heartbeat message creation."""
        msg = agent.create_heartbeat_message()

        assert msg["message_type"] == "heartbeat"
        assert msg["data"]["agent_status"] == "healthy"
        assert "timestamp" in msg["data"]


class TestMessageSending:
    """Test message sending functionality."""

    @pytest.mark.asyncio
    async def test_send_message_success(self, agent, mock_websocket):
        """Test successful message sending."""
        agent.websocket = mock_websocket
        message = {"test": "data"}

        await agent.send_message(message)

        mock_websocket.send.assert_called_once_with(json.dumps(message))

    @pytest.mark.asyncio
    async def test_send_message_no_websocket(self, agent):
        """Test message sending without websocket connection."""
        agent.websocket = None

        # Should not raise an exception
        await agent.send_message({"test": "data"})

    @pytest.mark.asyncio
    async def test_send_message_failure(self, agent, mock_websocket):
        """Test message sending failure."""
        agent.websocket = mock_websocket
        mock_websocket.send.side_effect = Exception("Connection error")

        # Should not raise an exception
        await agent.send_message({"test": "data"})


class TestCommandHandling:
    """Test command handling functionality."""

    @pytest.mark.asyncio
    async def test_handle_command_execute_shell(self, agent, mock_subprocess):
        """Test handling execute_shell command."""
        with patch("asyncio.create_subprocess_shell", return_value=mock_subprocess):
            command_msg = {
                "message_id": "cmd-123",
                "data": {
                    "command_type": "execute_shell",
                    "parameters": {"command": "echo hello"},
                },
            }

            # Mock send_message to capture the result
            sent_messages = []

            async def mock_send_message(msg):
                sent_messages.append(msg)

            agent.send_message = mock_send_message

            await agent.handle_command(command_msg)

            assert len(sent_messages) == 1
            result_msg = sent_messages[0]
            assert result_msg["message_type"] == "command_result"
            assert result_msg["data"]["command_id"] == "cmd-123"
            assert result_msg["data"]["success"] is True

    @pytest.mark.asyncio
    async def test_handle_command_get_system_info(self, agent):
        """Test handling get_system_info command."""
        command_msg = {
            "message_id": "cmd-456",
            "data": {"command_type": "get_system_info", "parameters": {}},
        }

        sent_messages = []

        async def mock_send_message(msg):
            sent_messages.append(msg)

        agent.send_message = mock_send_message

        await agent.handle_command(command_msg)

        assert len(sent_messages) == 1
        result_msg = sent_messages[0]
        assert result_msg["message_type"] == "command_result"
        assert result_msg["data"]["success"] is True
        assert "hostname" in result_msg["data"]["result"]

    @pytest.mark.asyncio
    async def test_handle_command_unknown_type(self, agent):
        """Test handling unknown command type."""
        command_msg = {
            "message_id": "cmd-999",
            "data": {"command_type": "unknown_command", "parameters": {}},
        }

        sent_messages = []

        async def mock_send_message(msg):
            sent_messages.append(msg)

        agent.send_message = mock_send_message

        await agent.handle_command(command_msg)

        assert len(sent_messages) == 1
        result_msg = sent_messages[0]
        assert result_msg["message_type"] == "command_result"
        assert result_msg["data"]["success"] is False
        assert "Unknown command type" in result_msg["data"]["error"]


class TestCommandExecution:
    """Test individual command execution methods."""

    @pytest.mark.asyncio
    async def test_execute_shell_command_success(self, agent, mock_subprocess):
        """Test successful shell command execution."""
        with patch("asyncio.create_subprocess_shell", return_value=mock_subprocess):
            result = await agent.execute_shell_command({"command": "echo hello"})

            assert result["success"] is True
            assert result["result"]["stdout"] == "Hello World\n"
            assert result["result"]["stderr"] == ""
            assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_execute_shell_command_failure(self, agent):
        """Test shell command execution failure."""
        mock_process = Mock()
        mock_process.communicate = Mock(side_effect=Exception("Process error"))

        with patch("asyncio.create_subprocess_shell", return_value=mock_process):
            result = await agent.execute_shell_command({"command": "invalid"})

            assert result["success"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_shell_command_no_command(self, agent):
        """Test shell command execution without command parameter."""
        result = await agent.execute_shell_command({})

        assert result["success"] is False
        assert "No command specified" in result["error"]

    @pytest.mark.asyncio
    async def test_get_detailed_system_info(self, agent):
        """Test getting detailed system information."""
        result = await agent.get_detailed_system_info()

        assert result["success"] is True
        info = result["result"]
        assert "hostname" in info
        assert "platform" in info
        assert "system" in info
        assert "architecture" in info

    @pytest.mark.asyncio
    async def test_install_package_not_implemented(self, agent):
        """Test package installation (not implemented)."""
        result = await agent.install_package({"package_name": "nginx"})

        assert result["success"] is False
        assert "not yet implemented" in result["error"]

    @pytest.mark.asyncio
    async def test_install_package_no_name(self, agent):
        """Test package installation without package name."""
        result = await agent.install_package({})

        assert result["success"] is False
        assert "No package name specified" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_service_not_implemented(self, agent):
        """Test service restart (not implemented)."""
        result = await agent.restart_service({"service_name": "nginx"})

        assert result["success"] is False
        assert "not yet implemented" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_service_no_name(self, agent):
        """Test service restart without service name."""
        result = await agent.restart_service({})

        assert result["success"] is False
        assert "No service name specified" in result["error"]
