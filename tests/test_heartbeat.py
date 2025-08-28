"""
Test heartbeat functionality on the agent side.
"""

import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

import pytest

from config import ConfigManager
from main import SysManageAgent


class TestAgentHeartbeat:
    """Test agent heartbeat functionality."""

    @pytest.fixture
    def agent_config(self, tmp_path):
        """Create a temporary config file for testing."""
        config_file = tmp_path / "test_client.yaml"
        config_content = """
server:
  hostname: "test-server.example.com"
  port: 8000
  use_https: false
  api_path: "/api"

client:
  hostname_override: null
  registration_retry_interval: 30
  max_registration_retries: 10

logging:
  level: "INFO"
  file: null
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

websocket:
  auto_reconnect: true
  reconnect_interval: 5
  ping_interval: 30

i18n:
  language: "en"
"""
        config_file.write_text(config_content)
        return str(config_file)

    @pytest.fixture
    def mock_agent(self, agent_config):
        """Create a mock SysManage agent."""
        with patch("main.ClientRegistration"), patch("main.set_language"):
            agent = SysManageAgent(agent_config)
            agent.websocket = AsyncMock()
            agent.logger = Mock()
            return agent

    def test_create_heartbeat_message(self, mock_agent):
        """Test heartbeat message creation."""
        message = mock_agent.create_heartbeat_message()

        assert message["message_type"] == "heartbeat"
        assert "message_id" in message
        assert "timestamp" in message
        assert message["data"]["agent_status"] == "healthy"
        assert isinstance(message["data"]["timestamp"], str)

    def test_create_message_structure(self, mock_agent):
        """Test general message creation structure."""
        test_data = {"test_key": "test_value"}
        message = mock_agent.create_message("test_type", test_data)

        assert message["message_type"] == "test_type"
        assert "message_id" in message
        assert "timestamp" in message
        assert message["data"] == test_data

    def test_create_message_with_empty_data(self, mock_agent):
        """Test message creation with empty data."""
        message = mock_agent.create_message("test_type")

        assert message["message_type"] == "test_type"
        assert message["data"] == {}

    @pytest.mark.asyncio
    async def test_send_message_success(self, mock_agent):
        """Test successful message sending."""
        test_message = {"message_type": "heartbeat", "data": {}}

        await mock_agent.send_message(test_message)

        mock_agent.websocket.send.assert_called_once()
        mock_agent.logger.debug.assert_called_with("Sent message: %s", "heartbeat")

    @pytest.mark.asyncio
    async def test_send_message_failure(self, mock_agent):
        """Test message sending failure."""
        mock_agent.websocket.send.side_effect = Exception("Connection error")
        test_message = {"message_type": "heartbeat", "data": {}}

        await mock_agent.send_message(test_message)

        mock_agent.logger.error.assert_called_with(
            "Failed to send message: %s", mock_agent.websocket.send.side_effect
        )

    @pytest.mark.asyncio
    async def test_send_message_no_websocket(self, mock_agent):
        """Test message sending when websocket is None."""
        mock_agent.websocket = None
        test_message = {"message_type": "heartbeat", "data": {}}

        await mock_agent.send_message(test_message)

        # Should not raise an exception, just do nothing
        mock_agent.logger.debug.assert_not_called()
        mock_agent.logger.error.assert_not_called()

    @pytest.mark.asyncio
    async def test_message_sender_heartbeat_loop(self, mock_agent):
        """Test the message sender heartbeat loop."""
        mock_agent.running = True
        mock_agent.config.get_ping_interval = Mock(
            return_value=0.1
        )  # Very short interval for testing

        # Mock asyncio.sleep to stop the loop after first iteration
        with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
            with pytest.raises(asyncio.CancelledError):
                await mock_agent.message_sender()

        # Verify initial system info was sent
        assert mock_agent.websocket.send.call_count >= 1

    @pytest.mark.asyncio
    async def test_message_sender_error_handling(self, mock_agent):
        """Test message sender error handling."""
        mock_agent.running = True
        mock_agent.websocket.send.side_effect = Exception("Send error")
        mock_agent.config.get_ping_interval = Mock(return_value=0.1)

        with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
            with pytest.raises(asyncio.CancelledError):
                await mock_agent.message_sender()

        # Verify error was logged
        mock_agent.logger.error.assert_called()


class TestAgentConfiguration:
    """Test agent configuration for heartbeat functionality."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create a config manager with test configuration."""

        config_file = tmp_path / "test_config.yaml"
        config_content = """
websocket:
  ping_interval: 60
  reconnect_interval: 10
  auto_reconnect: true
"""
        config_file.write_text(config_content)
        return ConfigManager(str(config_file))

    def test_get_ping_interval(self, config_manager):
        """Test getting ping interval from configuration."""
        interval = config_manager.get_ping_interval()
        assert interval == 60

    def test_get_ping_interval_default(self, tmp_path):
        """Test default ping interval when not configured."""

        config_file = tmp_path / "empty_config.yaml"
        config_file.write_text("{}")

        config_manager = ConfigManager(str(config_file))
        interval = config_manager.get_ping_interval()
        assert interval == 30  # Default value

    def test_get_reconnect_interval(self, config_manager):
        """Test getting reconnect interval from configuration."""
        interval = config_manager.get_reconnect_interval()
        assert interval == 10

    def test_should_auto_reconnect(self, config_manager):
        """Test auto reconnect configuration."""
        should_reconnect = config_manager.should_auto_reconnect()
        assert should_reconnect is True

    def test_should_auto_reconnect_default(self, tmp_path):
        """Test default auto reconnect behavior."""

        config_file = tmp_path / "empty_config.yaml"
        config_file.write_text("{}")

        config_manager = ConfigManager(str(config_file))
        should_reconnect = config_manager.should_auto_reconnect()
        assert should_reconnect is True  # Default value


class TestSystemInfoMessage:
    """Test system info message creation."""

    @pytest.fixture
    def mock_registration(self):
        """Create a mock registration handler."""
        registration = Mock()
        registration.get_system_info.return_value = {
            "hostname": "test-host.example.com",
            "platform": "Linux",
            "ipv4": "192.168.1.100",
            "ipv6": "2001:db8::1",
            "architecture": "x86_64",
            "processor": "Intel Core i7",
        }
        return registration

    @pytest.fixture
    def mock_agent_with_registration(self, tmp_path, mock_registration):
        """Create a mock agent with registration handler."""
        # Create a temporary config file
        config_file = tmp_path / "test_client.yaml"
        config_content = """
server:
  hostname: "test-server.example.com"
  port: 8000
  use_https: false
  api_path: "/api"

i18n:
  language: "en"
"""
        config_file.write_text(config_content)

        with patch("main.ClientRegistration", return_value=mock_registration), patch(
            "main.set_language"
        ):
            agent = SysManageAgent(str(config_file))
            return agent

    def test_create_system_info_message(self, mock_agent_with_registration):
        """Test system info message creation."""
        message = mock_agent_with_registration.create_system_info_message()

        assert message["message_type"] == "system_info"
        assert "message_id" in message
        assert "timestamp" in message

        data = message["data"]
        assert data["hostname"] == "test-host.example.com"
        assert data["platform"] == "Linux"
        assert data["ipv4"] == "192.168.1.100"
        assert data["ipv6"] == "2001:db8::1"


class TestMessageHandling:
    """Test agent message handling functionality."""

    def test_message_id_uniqueness(self):
        """Test that message IDs are unique."""

        with patch("main.ClientRegistration"), patch("main.set_language"):

            # Create messages and verify unique IDs
            messages = []
            for _ in range(10):
                msg = SysManageAgent.create_message(None, "test", {})
                messages.append(msg["message_id"])

            # All message IDs should be unique
            assert len(set(messages)) == len(messages)

    def test_message_timestamp_format(self):
        """Test that message timestamps are properly formatted."""

        with patch("main.ClientRegistration"), patch("main.set_language"):

            msg = SysManageAgent.create_message(None, "test", {})
            timestamp = msg["timestamp"]

            # Should be able to parse the timestamp
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            assert isinstance(parsed_time, datetime)
            assert parsed_time.tzinfo is not None
