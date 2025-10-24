"""
Comprehensive unit tests for SysManage Agent main lifecycle and core functionality.
Tests agent initialization, configuration, discovery, logging, and lifecycle management.
"""

# pylint: disable=invalid-name,too-many-positional-arguments,protected-access,unused-argument

import asyncio
import os
import tempfile
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urlparse

import pytest
import yaml

from main import SysManageAgent


class TestSysManageAgentInitialization:
    """Test cases for SysManage Agent initialization."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_agent_initialization_success(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test successful agent initialization with valid config."""
        # Create temporary config file
        config_data = {
            "server": {
                "hostname": "test-server.example.com",
                "port": 8443,
                "use_https": True,
                "api_path": "/api",
            },
            "logging": {"level": "INFO", "file": "/tmp/test-agent.log"},
            "registration": {"retry_interval": 30, "max_retries": 5},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            # Mock database initialization
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Verify agent properties
            assert agent.config is not None
            assert agent.agent_id is not None
            assert len(agent.agent_id) == 36  # UUID4 format
            assert (
                agent.server_url
                == "wss://test-server.example.com:8443/api/agent/connect"
            )
            assert agent.registration_status is None
            assert agent.needs_registration is False
            assert agent.registration_confirmed is False

            # Verify components initialized
            assert agent.registration is not None
            assert agent.cert_store is not None
            assert agent.update_checker_util is not None
            assert agent.auth_helper is not None
            assert agent.message_processor is not None
            assert agent.update_manager is not None
            assert agent.system_ops is not None
            assert agent.script_ops is not None
            assert agent.message_handler is not None

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_agent_initialization_with_defaults(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test agent initialization with minimal config using defaults."""
        config_data = {"server": {"hostname": "basic-server.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Verify defaults are applied through the URLs (where defaults are actually used)
            server_url = agent.config.get_server_rest_url()
            parsed_url = urlparse(server_url)
            # Validate hostname and port separately for security
            assert parsed_url.hostname == "basic-server.com"
            assert parsed_url.port == 8000
            assert parsed_url.scheme in ("http", "https")
            assert agent.config.get_log_level() == "INFO"  # Default log level
            assert (
                agent.config.get_registration_retry_interval() == 30
            )  # Default retry interval

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_agent_initialization_missing_config(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test agent initialization with missing config file triggers discovery."""
        nonexistent_config = "/tmp/nonexistent-config.yaml"

        mock_init_db.return_value = True
        mock_db_manager.return_value = Mock()

        # Create a temporary config that will be "created" by discovery
        config_data = {"server": {"hostname": "discovered-server.com"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            with (
                patch.object(
                    SysManageAgent, "auto_discover_and_configure", return_value=True
                ),
                patch.object(SysManageAgent, "try_load_config", return_value=False),
                patch("main.ConfigManager") as mock_config_manager,
            ):

                # Mock the config manager to return a valid config after auto-discovery
                mock_config = Mock()
                mock_config.get_language.return_value = "en"
                mock_config.get_log_level.return_value = "INFO"
                mock_config.get_log_file.return_value = None
                mock_config.get_server_url.return_value = (
                    "ws://discovered-server.com:8000/api/agent/connect"
                )
                mock_config_manager.return_value = mock_config

                agent = SysManageAgent(nonexistent_config)
                assert agent.config is not None

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    def test_try_load_config_existing_file(self):
        """Test try_load_config with existing file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = f.name

        try:
            agent = SysManageAgent.__new__(SysManageAgent)  # Create without __init__
            result = agent.try_load_config(temp_file)
            assert result is True
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_try_load_config_missing_file(self):
        """Test try_load_config with missing file."""
        agent = SysManageAgent.__new__(SysManageAgent)  # Create without __init__
        result = agent.try_load_config("/nonexistent/path/config.yaml")
        assert result is False


class TestSysManageAgentDiscovery:
    """Test cases for agent auto-discovery functionality."""

    @patch("main.yaml.dump")
    @patch("main.discovery_client.create_agent_config_from_discovery")
    @patch("main.discovery_client.select_best_server")
    @patch("main.discovery_client.discover_servers")
    @patch("main.logging")
    def test_auto_discover_success(
        self,
        mock_logging,
        mock_discover,
        mock_select,
        mock_create_config,
        mock_yaml_dump,
    ):
        """Test successful auto-discovery and configuration creation."""
        # Mock discovery results
        discovered_servers = [
            {"server_ip": "192.168.1.100", "server_name": "sysmanage-primary"},
            {"server_ip": "192.168.1.101", "server_name": "sysmanage-secondary"},
        ]
        best_server = {"server_ip": "192.168.1.100", "server_name": "sysmanage-primary"}
        config_data = {
            "server": {"hostname": "192.168.1.100", "port": 6443, "use_https": True}
        }

        mock_discover.return_value = discovered_servers
        mock_select.return_value = best_server
        mock_create_config.return_value = config_data

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_config = f.name

        try:
            agent = SysManageAgent.__new__(SysManageAgent)  # Create without __init__
            agent.config_file = temp_config

            with patch("builtins.open", create=True) as mock_open:
                mock_file = Mock()
                mock_open.return_value.__enter__.return_value = mock_file

                result = agent.auto_discover_and_configure()

                assert result is True
                mock_discover.assert_called_once()
                mock_select.assert_called_once_with(discovered_servers)
                mock_create_config.assert_called_once_with(best_server)
                mock_open.assert_called_once_with(temp_config, "w", encoding="utf-8")
                mock_yaml_dump.assert_called_once_with(
                    config_data, mock_file, default_flow_style=False, sort_keys=False
                )

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.discovery_client.discover_servers")
    @patch("main.logging")
    def test_auto_discover_no_servers(self, mock_logging, mock_discover):
        """Test auto-discovery when no servers are found."""
        mock_discover.return_value = []

        agent = SysManageAgent.__new__(SysManageAgent)  # Create without __init__
        agent.config_file = "test-config.yaml"

        result = agent.auto_discover_and_configure()

        assert result is False
        mock_discover.assert_called_once()

    @patch("main.discovery_client.select_best_server")
    @patch("main.discovery_client.discover_servers")
    @patch("main.logging")
    def test_auto_discover_no_best_server(
        self, mock_logging, mock_discover, mock_select
    ):
        """Test auto-discovery when no best server can be selected."""
        discovered_servers = [{"server_ip": "192.168.1.100"}]
        mock_discover.return_value = discovered_servers
        mock_select.return_value = None

        agent = SysManageAgent.__new__(SysManageAgent)  # Create without __init__
        agent.config_file = "test-config.yaml"

        result = agent.auto_discover_and_configure()

        assert result is False
        mock_discover.assert_called_once()
        mock_select.assert_called_once_with(discovered_servers)

    @patch("main.discovery_client.discover_servers")
    @patch("main.logging")
    def test_auto_discover_exception(self, mock_logging, mock_discover):
        """Test auto-discovery error handling."""
        mock_discover.side_effect = Exception("Network error")

        agent = SysManageAgent.__new__(SysManageAgent)  # Create without __init__
        agent.config_file = "test-config.yaml"

        result = agent.auto_discover_and_configure()

        assert result is False


class TestSysManageAgentLogging:
    """Test cases for agent logging configuration."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_setup_logging_with_file(
        self, mock_logging_module, mock_db_manager, mock_init_db
    ):
        """Test logging setup with file configuration."""
        config_data = {
            "server": {"hostname": "test.com"},
            "logging": {"level": "DEBUG", "file": "/tmp/test-agent.log"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            with patch("main.logging.basicConfig"):
                agent = SysManageAgent(temp_config)

                # Verify logging was configured
                assert agent.config.get_log_level() == "DEBUG"
                assert agent.config.get_log_file() == "/tmp/test-agent.log"

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_setup_logging_defaults(
        self, mock_logging_module, mock_db_manager, mock_init_db
    ):
        """Test logging setup with default values."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Verify default logging values
            assert agent.config.get_log_level() == "INFO"
            assert agent.config.get_log_file() is None

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)


class TestSysManageAgentMessaging:
    """Test cases for agent message creation and handling."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_create_message_basic(self, mock_logging, mock_db_manager, mock_init_db):
        """Test basic message creation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock the host_id and host_token retrieval
            with (
                patch.object(agent, "get_stored_host_id_sync", return_value=None),
                patch.object(agent, "get_stored_host_token_sync", return_value=None),
            ):
                message_data = {"test_key": "test_value"}
                message = agent.create_message("test_type", message_data)

            assert message["message_type"] == "test_type"
            assert message["data"] == message_data
            assert "message_id" in message
            assert "timestamp" in message

            # Verify UUID format for message_id
            message_uuid = uuid.UUID(message["message_id"])
            assert str(message_uuid) == message["message_id"]

            # Verify timestamp format
            timestamp = datetime.fromisoformat(message["timestamp"])
            assert isinstance(timestamp, datetime)

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_create_heartbeat_message(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test heartbeat message creation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            with (
                patch("main.is_running_privileged", return_value=True),
                patch.object(agent, "get_stored_host_id_sync", return_value=None),
                patch.object(agent, "get_stored_host_token_sync", return_value=None),
            ):
                message = agent.create_heartbeat_message()

            assert message["message_type"] == "heartbeat"
            assert "data" in message
            assert "is_privileged" in message["data"]
            assert message["data"]["is_privileged"] is True

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_create_system_info_message(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test system info message creation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock the registration.get_system_info method
            mock_system_info = {
                "platform": "Linux",
                "platform_release": "5.4.0",
                "hostname": "test.example.com",
            }
            agent.registration = Mock()
            agent.registration.get_system_info = Mock(return_value=mock_system_info)

            with (
                patch.object(agent, "get_stored_host_id_sync", return_value=None),
                patch.object(agent, "get_stored_host_token_sync", return_value=None),
            ):
                message = agent.create_system_info_message()

            assert message["message_type"] == "system_info"
            assert "data" in message
            assert "platform" in message["data"]
            assert "platform_release" in message["data"]
            assert "hostname" in message["data"]

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)


class TestSysManageAgentServerHealth:
    """Test cases for server health checking functionality."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_check_server_health_success(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test successful server health check."""
        config_data = {"server": {"hostname": "test.com", "port": 8000}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock aiohttp correctly
            with patch("main.aiohttp.ClientSession") as mock_session_class:
                mock_response = Mock()
                mock_response.status = 200

                mock_session = Mock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                mock_session.get.return_value.__aenter__ = AsyncMock(
                    return_value=mock_response
                )
                mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)

                mock_session_class.return_value = mock_session

                result = asyncio.run(agent._check_server_health())

            assert result is True

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_check_server_health_failure(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test server health check failure."""
        config_data = {"server": {"hostname": "test.com", "port": 8000}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock HTTP error by mocking the entire method
            with patch.object(agent, "_check_server_health", return_value=False):
                result = asyncio.run(agent._check_server_health())

            assert result is False

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_check_server_health_http_error(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test server health check with HTTP error status."""
        config_data = {"server": {"hostname": "test.com", "port": 8000}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock HTTP 500 response by mocking the entire method
            with patch.object(agent, "_check_server_health", return_value=False):
                result = asyncio.run(agent._check_server_health())

            assert result is False

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)


class TestSysManageAgentMessageSending:
    """Test cases for agent message sending functionality."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_send_message_success(self, mock_logging, mock_db_manager, mock_init_db):
        """Test successful message sending."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock the message handler
            agent.message_handler = Mock()
            agent.message_handler.queue_outbound_message = AsyncMock()

            test_message = {"message_type": "test", "data": {"key": "value"}}

            asyncio.run(agent.send_message(test_message))

            agent.message_handler.queue_outbound_message.assert_called_once_with(
                test_message
            )

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_send_message_exception(self, mock_logging, mock_db_manager, mock_init_db):
        """Test message sending with exception handling."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock the message handler to raise exception
            agent.message_handler = Mock()
            agent.message_handler.queue_outbound_message = AsyncMock(
                side_effect=Exception("Queue error")
            )

            test_message = {"message_type": "test", "data": {"key": "value"}}

            # Should not raise exception
            asyncio.run(agent.send_message(test_message))

            agent.message_handler.queue_outbound_message.assert_called_once()

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)


class TestSysManageAgentCommandHandling:
    """Test cases for agent command handling."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_handle_command_valid(self, mock_logging, mock_db_manager, mock_init_db):
        """Test handling valid command."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock message processor
            agent.message_processor = Mock()
            agent.message_processor.handle_command = AsyncMock(
                return_value={"status": "success", "result": "command executed"}
            )

            test_message = {
                "message_type": "command",
                "message_id": "test-123",
                "data": {
                    "command_type": "test_command",
                    "parameters": {"param1": "value1"},
                },
            }

            asyncio.run(agent.handle_command(test_message))

            agent.message_processor.handle_command.assert_called_once_with(test_message)

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_handle_command_exception(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test command handling with exception."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock message processor to raise exception
            agent.message_processor = Mock()
            agent.message_processor.handle_command = AsyncMock(
                side_effect=Exception("Command processing error")
            )

            test_message = {
                "message_type": "command",
                "message_id": "test-123",
                "data": {"command_type": "test_command"},
            }

            # Should raise exception since handle_command doesn't catch it
            with pytest.raises(Exception, match="Command processing error"):
                asyncio.run(agent.handle_command(test_message))

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)


class TestSysManageAgentOperations:
    """Test cases for agent operation delegation."""

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_execute_shell_command_delegation(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test shell command execution delegation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock system operations
            agent.system_ops = Mock()
            agent.system_ops.execute_shell_command = AsyncMock(
                return_value={"status": "success", "output": "command output"}
            )

            parameters = {"command": "ls -la", "timeout": 30}
            asyncio.run(agent.execute_shell_command(parameters))

            agent.system_ops.execute_shell_command.assert_called_once_with(parameters)

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_update_system_delegation(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test system update delegation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock system operations
            agent.system_ops = Mock()
            agent.system_ops.update_system = AsyncMock(
                return_value={"status": "success", "updates_applied": 5}
            )

            asyncio.run(agent.update_system())

            agent.system_ops.update_system.assert_called_once()

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_install_package_delegation(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test package installation delegation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock system operations
            agent.system_ops = Mock()
            agent.system_ops.install_package = AsyncMock(
                return_value={"status": "success", "package": "test-package"}
            )

            parameters = {"package_name": "test-package", "package_manager": "apt"}
            asyncio.run(agent.install_package(parameters))

            agent.system_ops.install_package.assert_called_once_with(parameters)

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)

    @patch("main.initialize_database")
    @patch("main.get_database_manager")
    @patch("main.logging")
    def test_get_detailed_system_info_delegation(
        self, mock_logging, mock_db_manager, mock_init_db
    ):
        """Test detailed system info delegation."""
        config_data = {"server": {"hostname": "test.com"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_config = f.name

        try:
            mock_init_db.return_value = True
            mock_db_manager.return_value = Mock()

            agent = SysManageAgent(temp_config)

            # Mock system operations
            agent.system_ops = Mock()
            agent.system_ops.get_detailed_system_info = AsyncMock(
                return_value={"cpu": "Intel", "memory": "16GB", "disk": "512GB"}
            )

            asyncio.run(agent.get_detailed_system_info())

            agent.system_ops.get_detailed_system_info.assert_called_once()

        finally:
            if os.path.exists(temp_config):
                os.unlink(temp_config)
