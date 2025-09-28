"""
Simple targeted tests for main.py to improve coverage by exercising specific uncovered lines.
Focus on simple methods that can be tested without complex mocking.
"""

# pylint: disable=import-outside-toplevel

import os
import tempfile
from unittest.mock import Mock, patch


class TestMainTargeted:
    """Simple targeted tests for main.py based on coverage analysis."""

    def test_try_load_config_exists(self):
        """Test try_load_config when config file exists."""
        # Create a temporary config file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as tmp:
            tmp.write(b"test: config")
            tmp_path = tmp.name

        try:
            from main import SysManageAgent

            agent = object.__new__(SysManageAgent)  # Create without calling __init__
            result = agent.try_load_config(tmp_path)
            assert result is True
        finally:
            os.unlink(tmp_path)

    def test_try_load_config_not_exists(self):
        """Test try_load_config when config file doesn't exist."""
        from main import SysManageAgent

        agent = object.__new__(SysManageAgent)  # Create without calling __init__
        result = agent.try_load_config("/nonexistent/file.yaml")
        assert result is False

    def test_create_message_basic(self):
        """Test create_message method with basic parameters."""
        from main import SysManageAgent

        # Create a mock agent with minimal setup
        agent = object.__new__(SysManageAgent)
        agent.logger = Mock()

        # Mock the sync methods that create_message calls
        agent.get_stored_host_id_sync = Mock(return_value=None)
        agent.get_stored_host_token_sync = Mock(return_value=None)

        # Test create_message method
        result = agent.create_message("test_type")

        # Verify message structure (using actual field names from the code)
        assert isinstance(result, dict)
        assert result["message_type"] == "test_type"
        assert "message_id" in result
        assert "timestamp" in result
        assert "data" in result

    def test_create_message_with_data(self):
        """Test create_message method with data parameter."""
        from main import SysManageAgent

        # Create a mock agent with minimal setup
        agent = object.__new__(SysManageAgent)
        agent.logger = Mock()

        # Mock the sync methods
        agent.get_stored_host_id_sync = Mock(return_value=None)
        agent.get_stored_host_token_sync = Mock(return_value=None)

        test_data = {"key": "value", "number": 42}
        result = agent.create_message("test_type", test_data)

        # Verify message structure includes data
        assert result["data"] == test_data

    def test_create_message_with_host_id(self):
        """Test create_message method when host_id is stored."""
        from main import SysManageAgent

        # Create a mock agent with minimal setup
        agent = object.__new__(SysManageAgent)
        agent.logger = Mock()

        # Mock the sync methods to return values
        agent.get_stored_host_id_sync = Mock(return_value="test-host-id")
        agent.get_stored_host_token_sync = Mock(return_value="test-token")

        result = agent.create_message("test_type")

        # Verify host_id and host_token are added to data
        assert result["data"]["host_id"] == "test-host-id"
        assert result["data"]["host_token"] == "test-token"

    def test_create_message_with_existing_host_id(self):
        """Test create_message method when host_id already in data."""
        from main import SysManageAgent

        # Create a mock agent with minimal setup
        agent = object.__new__(SysManageAgent)
        agent.logger = Mock()

        # Mock should not be called when host_id exists
        agent.get_stored_host_id_sync = Mock()
        agent.get_stored_host_token_sync = Mock()

        test_data = {"host_id": "existing-host-id"}
        result = agent.create_message("test_type", test_data)

        # Verify existing host_id is preserved and sync methods not called
        assert result["data"]["host_id"] == "existing-host-id"
        agent.get_stored_host_id_sync.assert_not_called()
        agent.get_stored_host_token_sync.assert_not_called()

    def test_create_system_info_message(self):
        """Test create_system_info_message method."""
        from main import SysManageAgent

        # Create a mock agent with minimal setup
        agent = object.__new__(SysManageAgent)
        agent.logger = Mock()

        # Mock registration to return system info
        agent.registration = Mock()
        agent.registration.get_system_info.return_value = {
            "os": "Linux",
            "arch": "x86_64",
        }

        # Mock the create_message method to avoid complexity
        agent.create_message = Mock(return_value={"message_type": "system_info"})

        agent.create_system_info_message()

        # Verify the method calls the right components
        agent.registration.get_system_info.assert_called_once()
        agent.create_message.assert_called_once_with(
            "system_info", {"os": "Linux", "arch": "x86_64"}
        )

    @patch("main.is_running_privileged")
    def test_create_heartbeat_message(self, mock_is_privileged):
        """Test create_heartbeat_message method."""
        from main import SysManageAgent

        # Create a mock agent with minimal setup
        agent = object.__new__(SysManageAgent)
        agent.logger = Mock()

        # Mock registration to return complete system info
        agent.registration = Mock()
        agent.registration.get_system_info.return_value = {
            "hostname": "test-host",
            "ipv4": "192.168.1.100",
            "ipv6": "::1",
        }

        # Mock config methods
        agent.config = Mock()
        agent.config.is_script_execution_enabled.return_value = True
        agent.config.get_allowed_shells.return_value = ["/bin/bash"]

        # Mock is_running_privileged function
        mock_is_privileged.return_value = False

        # Mock the create_message method to avoid complexity
        agent.create_message = Mock(return_value={"message_type": "heartbeat"})

        agent.create_heartbeat_message()

        # Verify the method calls the right components
        agent.registration.get_system_info.assert_called_once()
        # Check that create_message was called with heartbeat type and expected data structure
        call_args = agent.create_message.call_args
        assert call_args[0][0] == "heartbeat"  # First positional arg is message type
        heartbeat_data = call_args[0][1]  # Second positional arg is data
        assert "agent_status" in heartbeat_data
        assert "hostname" in heartbeat_data
        assert "ipv4" in heartbeat_data
