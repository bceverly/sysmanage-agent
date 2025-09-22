"""
Unit tests for agent-side package installation functionality
"""

import os
import sys
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch

import pytest

# Add the parent directory to sys.path to allow imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# pylint: disable=wrong-import-position,protected-access
from src.sysmanage_agent.operations.system_operations import SystemOperations
from src.sysmanage_agent.collection.update_detection import UpdateDetector


class TestPackageInstallation:
    """Test cases for package installation functionality"""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock agent instance"""
        agent = Mock()
        agent.hostname = "test-agent.example.com"
        agent.get_host_approval_from_db = Mock(return_value=Mock(host_id=1))
        agent.registration = Mock()
        agent.registration.get_system_info = Mock(
            return_value={
                "hostname": "test-agent.example.com",
                "fqdn": "test-agent.example.com",
            }
        )
        agent.send_message = AsyncMock()
        return agent

    @pytest.fixture
    def system_operations(self, mock_agent):
        """Create SystemOperations instance with mock agent"""
        return SystemOperations(mock_agent)

    @pytest.mark.asyncio
    async def test_install_package_success(self, system_operations, mock_agent):
        """Test successful package installation"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.return_value = {
                "success": True,
                "version": "1.0.0",
                "output": "Package installed successfully",
            }

            parameters = {
                "package_name": "vim",
                "package_manager": "apt",
                "installation_id": "test-uuid-123",
                "requested_by": "test-user",
            }

            result = await system_operations.install_package(parameters)

            # Verify successful result
            assert result["success"] is True
            assert result["package_name"] == "vim"
            assert result["installation_id"] == "test-uuid-123"
            assert result["installed_version"] == "1.0.0"

            # Verify status update messages were sent
            assert mock_agent.send_message.call_count == 2

            # Check "installing" status message
            installing_call = mock_agent.send_message.call_args_list[0][0][0]
            assert installing_call["message_type"] == "package_installation_status"
            assert installing_call["status"] == "installing"
            assert installing_call["installation_id"] == "test-uuid-123"
            assert installing_call["package_name"] == "vim"

            # Check "completed" status message
            completed_call = mock_agent.send_message.call_args_list[1][0][0]
            assert completed_call["message_type"] == "package_installation_status"
            assert completed_call["status"] == "completed"
            assert completed_call["installation_id"] == "test-uuid-123"
            assert completed_call["installed_version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_install_package_failure(self, system_operations, mock_agent):
        """Test failed package installation"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.side_effect = Exception("Package not found")

            parameters = {
                "package_name": "nonexistent-package",
                "package_manager": "apt",
                "installation_id": "test-uuid-456",
                "requested_by": "test-user",
            }

            result = await system_operations.install_package(parameters)

            # Verify failure result
            assert result["success"] is False
            assert result["package_name"] == "nonexistent-package"
            assert result["installation_id"] == "test-uuid-456"
            assert "Package not found" in result["error"]

            # Verify status update messages were sent
            assert mock_agent.send_message.call_count == 2

            # Check "installing" status message
            installing_call = mock_agent.send_message.call_args_list[0][0][0]
            assert installing_call["status"] == "installing"

            # Check "failed" status message
            failed_call = mock_agent.send_message.call_args_list[1][0][0]
            assert failed_call["status"] == "failed"
            assert "Package not found" in failed_call["error_message"]

    @pytest.mark.asyncio
    async def test_install_package_missing_name(self, system_operations):
        """Test package installation with missing package name"""
        parameters = {
            "package_manager": "apt",
            "installation_id": "test-uuid-789",
            "requested_by": "test-user",
        }

        result = await system_operations.install_package(parameters)

        # Verify error result
        assert result["success"] is False
        assert "No package name specified" in result["error"]

    @pytest.mark.asyncio
    async def test_install_package_string_result(self, system_operations, mock_agent):
        """Test package installation with string result from UpdateDetector"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.return_value = "Package vim installed successfully"

            parameters = {
                "package_name": "vim",
                "package_manager": "apt",
                "installation_id": "test-uuid-string",
                "requested_by": "test-user",
            }

            result = await system_operations.install_package(parameters)

            # Verify successful result with string output
            assert result["success"] is True
            assert result["package_name"] == "vim"
            assert result["installation_id"] == "test-uuid-string"

            # Check completed status message includes installation log
            completed_call = mock_agent.send_message.call_args_list[1][0][0]
            assert completed_call["status"] == "completed"
            assert (
                completed_call["installation_log"]
                == "Package vim installed successfully"
            )

    @pytest.mark.asyncio
    async def test_install_package_error_in_string_result(
        self, system_operations, mock_agent
    ):
        """Test package installation with error in string result"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.return_value = "Error: failed to install package vim"

            parameters = {
                "package_name": "vim",
                "package_manager": "apt",
                "installation_id": "test-uuid-error",
                "requested_by": "test-user",
            }

            result = await system_operations.install_package(parameters)

            # Verify failure detected from string content
            assert result["success"] is False
            assert "Error: failed to install package vim" in result["error"]

            # Check failed status message
            failed_call = mock_agent.send_message.call_args_list[1][0][0]
            assert failed_call["status"] == "failed"
            assert (
                "Error: failed to install package vim" in failed_call["error_message"]
            )

    @pytest.mark.asyncio
    async def test_install_package_without_installation_id(
        self, system_operations, mock_agent
    ):
        """Test package installation without installation_id (backward compatibility)"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.return_value = {"success": True, "version": "1.0.0"}

            parameters = {
                "package_name": "curl",
                "package_manager": "apt",
                "requested_by": "test-user",
                # No installation_id provided
            }

            result = await system_operations.install_package(parameters)

            # Verify successful result
            assert result["success"] is True
            assert result["package_name"] == "curl"
            assert result["installation_id"] is None

            # Verify no status update messages were sent (since no installation_id)
            assert mock_agent.send_message.call_count == 0

    @pytest.mark.asyncio
    async def test_send_installation_status_update(self, system_operations, mock_agent):
        """Test the _send_installation_status_update method directly"""
        await system_operations._send_installation_status_update(
            installation_id="test-status-update",
            status="installing",
            package_name="test-package",
            requested_by="test-user",
            error_message=None,
            installed_version=None,
            installation_log=None,
        )

        # Verify message was sent
        assert mock_agent.send_message.call_count == 1
        call_args = mock_agent.send_message.call_args[0][0]

        assert call_args["message_type"] == "package_installation_status"
        assert call_args["installation_id"] == "test-status-update"
        assert call_args["status"] == "installing"
        assert call_args["package_name"] == "test-package"
        assert call_args["requested_by"] == "test-user"
        assert call_args["host_id"] == "1"
        assert call_args["hostname"] == "test-agent.example.com"

    @pytest.mark.asyncio
    async def test_send_installation_status_update_with_optional_fields(
        self, system_operations, mock_agent
    ):
        """Test status update with all optional fields"""
        await system_operations._send_installation_status_update(
            installation_id="test-complete",
            status="completed",
            package_name="test-package",
            requested_by="test-user",
            error_message=None,
            installed_version="2.1.0",
            installation_log="Package installed successfully with dependencies",
        )

        call_args = mock_agent.send_message.call_args[0][0]

        assert call_args["status"] == "completed"
        assert call_args["installed_version"] == "2.1.0"
        assert (
            call_args["installation_log"]
            == "Package installed successfully with dependencies"
        )

    @pytest.mark.asyncio
    async def test_send_installation_status_update_with_error(
        self, system_operations, mock_agent
    ):
        """Test status update with error message"""
        await system_operations._send_installation_status_update(
            installation_id="test-error",
            status="failed",
            package_name="test-package",
            requested_by="test-user",
            error_message="Package repository not available",
            installed_version=None,
            installation_log=None,
        )

        call_args = mock_agent.send_message.call_args[0][0]

        assert call_args["status"] == "failed"
        assert call_args["error_message"] == "Package repository not available"
        assert "installed_version" not in call_args
        assert "installation_log" not in call_args

    @pytest.mark.asyncio
    async def test_send_installation_status_update_exception_handling(
        self, system_operations, mock_agent
    ):
        """Test that exceptions in status update don't crash the installation"""
        # Make send_message raise an exception
        mock_agent.send_message.side_effect = Exception("Network error")

        # This should not raise an exception
        await system_operations._send_installation_status_update(
            installation_id="test-exception",
            status="installing",
            package_name="test-package",
            requested_by="test-user",
        )

        # Verify the send_message was attempted
        assert mock_agent.send_message.call_count == 1

    def test_package_installation_logging(self, system_operations):
        """Test that package installation logs the correct information"""
        with patch(
            "src.sysmanage_agent.operations.system_operations.logging"
        ) as mock_logging:
            mock_logger = Mock()
            mock_logging.getLogger.return_value = mock_logger

            # Create new instance to get fresh logger
            SystemOperations(Mock())

            # Test that the logger is properly configured
            assert mock_logging.getLogger.called

    @pytest.mark.asyncio
    async def test_install_package_auto_package_manager(
        self, system_operations, mock_agent
    ):
        """Test package installation with auto package manager detection"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.return_value = {"success": True, "version": "1.0.0"}

            parameters = {
                "package_name": "git",
                "package_manager": "auto",  # Let agent choose the best manager
                "installation_id": "test-auto-pm",
                "requested_by": "test-user",
            }

            result = await system_operations.install_package(parameters)

            # Verify the call was made with auto package manager
            mock_install.assert_called_once_with("git", "auto")
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_install_package_integration_flow(
        self, system_operations, mock_agent
    ):
        """Test the complete package installation flow"""
        with patch.object(UpdateDetector, "install_package") as mock_install:
            mock_install.return_value = {
                "success": True,
                "version": "8.2.0",
                "output": "Successfully installed vim 8.2.0",
            }

            # Simulate a complete package installation request
            parameters = {
                "package_name": "vim",
                "package_manager": "apt",
                "installation_id": "integration-test-123",
                "requested_by": "admin",
                "requested_at": datetime.now(timezone.utc).isoformat(),
            }

            result = await system_operations.install_package(parameters)

            # Verify complete successful flow
            assert result["success"] is True
            assert result["package_name"] == "vim"
            assert result["installation_id"] == "integration-test-123"
            assert result["installed_version"] == "8.2.0"

            # Verify all status updates were sent
            assert mock_agent.send_message.call_count == 2

            # Verify the sequence of status updates
            status_calls = [
                call[0][0] for call in mock_agent.send_message.call_args_list
            ]
            assert status_calls[0]["status"] == "installing"
            assert status_calls[1]["status"] == "completed"
            assert status_calls[1]["installed_version"] == "8.2.0"
            assert status_calls[1]["installation_log"] == str(mock_install.return_value)
