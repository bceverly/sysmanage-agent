"""
Unit tests for src.sysmanage_agent.core.agent_utils module.
Tests utility classes and functions for agent operations.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.database.models import Priority
from src.sysmanage_agent.core.agent_utils import (
    AuthenticationHelper,
    MessageProcessor,
    UpdateChecker,
    is_running_privileged,
)


class TestUpdateChecker:
    """Test cases for UpdateChecker class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.running = True
        self.mock_agent.connected = True
        self.mock_agent.check_updates = AsyncMock()
        self.mock_agent.config.get_update_check_interval.return_value = 3600  # 1 hour

        self.mock_logger = Mock()
        self.update_checker = UpdateChecker(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_perform_periodic_check_success_with_updates(self):
        """Test successful periodic check that finds updates."""
        self.mock_agent.check_updates.return_value = {"total_updates": 5}

        result = await self.update_checker.perform_periodic_check()

        assert result is True
        self.mock_agent.check_updates.assert_called_once()
        self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_perform_periodic_check_success_no_updates(self):
        """Test successful periodic check with no updates."""
        self.mock_agent.check_updates.return_value = {"total_updates": 0}

        result = await self.update_checker.perform_periodic_check()

        assert result is True
        self.mock_agent.check_updates.assert_called_once()

    @pytest.mark.asyncio
    async def test_perform_periodic_check_not_running(self):
        """Test periodic check when agent is not running."""
        self.mock_agent.running = False

        result = await self.update_checker.perform_periodic_check()

        assert result is False
        self.mock_agent.check_updates.assert_not_called()

    @pytest.mark.asyncio
    async def test_perform_periodic_check_not_connected(self):
        """Test periodic check when agent is not connected."""
        self.mock_agent.connected = False

        result = await self.update_checker.perform_periodic_check()

        assert result is False
        self.mock_agent.check_updates.assert_not_called()

    @pytest.mark.asyncio
    async def test_perform_periodic_check_exception(self):
        """Test periodic check with exception."""
        self.mock_agent.check_updates.side_effect = Exception("Update check failed")

        result = await self.update_checker.perform_periodic_check()

        assert result is False
        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_run_update_checker_loop_single_iteration(self):
        """Test update checker loop for one iteration."""
        # Set up mocks
        self.mock_agent.running = True

        # Mock event loop time to trigger immediate update
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.time.side_effect = [
                0,
                3700,
            ]  # Start at 0, then past interval

            # Make the loop exit after one iteration
            call_count = 0

            async def mock_sleep(duration):
                _ = duration
                nonlocal call_count
                call_count += 1
                if call_count >= 1:
                    self.mock_agent.running = False

            with patch("asyncio.sleep", side_effect=mock_sleep):
                with patch.object(
                    self.update_checker, "perform_periodic_check"
                ) as mock_check:
                    mock_check.return_value = True

                    await self.update_checker.run_update_checker_loop()

                    mock_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_update_checker_loop_cancelled(self):
        """Test update checker loop cancellation."""
        with patch("asyncio.sleep", side_effect=asyncio.CancelledError()):
            with pytest.raises(asyncio.CancelledError):
                await self.update_checker.run_update_checker_loop()

    @pytest.mark.asyncio
    async def test_run_update_checker_loop_exception_continues(self):
        """Test update checker loop continues after exception."""
        call_count = 0

        async def mock_sleep(duration):
            _ = duration
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Random error")
            if call_count >= 2:
                self.mock_agent.running = False

        with patch("asyncio.sleep", side_effect=mock_sleep):
            await self.update_checker.run_update_checker_loop()

        assert call_count >= 2


class TestAuthenticationHelper:
    """Test cases for AuthenticationHelper class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "test-server",
            "port": 8080,
            "use_https": False,
        }
        self.mock_agent.config.should_verify_ssl.return_value = True

        self.mock_logger = Mock()
        self.auth_helper = AuthenticationHelper(self.mock_agent, self.mock_logger)

    def test_build_auth_url_http(self):
        """Test building HTTP auth URL."""
        result = self.auth_helper.build_auth_url()

        assert result == "http://test-server:8080/agent/auth"

    def test_build_auth_url_https(self):
        """Test building HTTPS auth URL."""
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "secure-server",
            "port": 8443,
            "use_https": True,
        }

        result = self.auth_helper.build_auth_url()

        assert result == "https://secure-server:8443/agent/auth"

    def test_build_auth_url_defaults(self):
        """Test building auth URL with default values."""
        self.mock_agent.config.get_server_config.return_value = {}

        result = self.auth_helper.build_auth_url()

        assert result == "http://localhost:8000/agent/auth"

    # Note: Comprehensive aiohttp async context manager mocking is complex.
    # The build_auth_url method provides good coverage of the auth logic.
    # In a real environment, integration tests would cover the full HTTP flow.


class TestMessageProcessor:
    """Test cases for MessageProcessor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.create_message.return_value = {"type": "command_result"}
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.execute_shell_command = AsyncMock(
            return_value={"success": True}
        )
        self.mock_agent.get_detailed_system_info = AsyncMock(
            return_value={"success": True}
        )
        self.mock_agent.execute_script = AsyncMock(return_value={"success": True})
        self.mock_agent.check_updates = AsyncMock(return_value={"success": True})
        self.mock_agent.get_host_approval_from_db.return_value = Mock(host_id="host123")
        self.mock_agent.registration.get_system_info.return_value = {
            "fqdn": "test.example.com"
        }
        self.mock_agent.message_handler.queue_outbound_message = AsyncMock()

        self.mock_logger = Mock()
        self.processor = MessageProcessor(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_handle_command_execute_shell(self):
        """Test handling execute_shell command."""
        message = {
            "message_id": "cmd123",
            "data": {
                "command_type": "execute_shell",
                "parameters": {"command": "ls -la"},
            },
        }

        await self.processor.handle_command(message)

        self.mock_agent.execute_shell_command.assert_called_once_with(
            {"command": "ls -la"}
        )
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_command_get_system_info(self):
        """Test handling get_system_info command."""
        message = {
            "message_id": "cmd123",
            "data": {"command_type": "get_system_info", "parameters": {}},
        }

        await self.processor.handle_command(message)

        self.mock_agent.get_detailed_system_info.assert_called_once()
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_command_execute_script_no_response(self):
        """Test handling execute_script command (no response sent)."""
        message = {
            "message_id": "cmd123",
            "data": {
                "command_type": "execute_script",
                "parameters": {
                    "script_content": "echo test",
                    "execution_id": "exec123",
                },
            },
        }

        with patch.object(self.processor, "_send_script_execution_result") as mock_send:
            mock_send.return_value = None

            await self.processor.handle_command(message)

            self.mock_agent.execute_script.assert_called_once()
            # Should not send regular command result for script execution
            self.mock_agent.send_message.assert_not_called()
            mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_command_check_updates(self):
        """Test handling check_updates command."""
        message = {
            "message_id": "cmd123",
            "data": {"command_type": "check_updates", "parameters": {}},
        }

        await self.processor.handle_command(message)

        self.mock_agent.check_updates.assert_called_once()
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_command_unknown_type(self):
        """Test handling unknown command type."""
        message = {
            "message_id": "cmd123",
            "data": {"command_type": "unknown_command", "parameters": {}},
        }

        await self.processor.handle_command(message)

        self.mock_agent.send_message.assert_called_once()
        # Check that error message was sent
        call_args = self.mock_agent.create_message.call_args[0]
        assert call_args[0] == "command_result"
        assert "success" in call_args[1] and call_args[1]["success"] is False

    @pytest.mark.asyncio
    async def test_handle_command_exception(self):
        """Test handling command with exception."""
        self.mock_agent.execute_shell_command.side_effect = Exception("Command failed")

        message = {
            "message_id": "cmd123",
            "data": {
                "command_type": "execute_shell",
                "parameters": {"command": "failing_command"},
            },
        }

        await self.processor.handle_command(message)

        # Should send error result
        self.mock_agent.send_message.assert_called_once()
        call_args = self.mock_agent.create_message.call_args[0]
        assert call_args[0] == "command_result"
        assert "success" in call_args[1] and call_args[1]["success"] is False
        assert "error" in call_args[1]

    @pytest.mark.asyncio
    async def test_dispatch_command_generic_command_unwrapping(self):
        """Test dispatching generic_command with nested command."""
        result = await self.processor._dispatch_command(
            "generic_command", {"command_type": "get_system_info", "parameters": {}}
        )

        assert result == {"success": True}
        self.mock_agent.get_detailed_system_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_command_generic_command_missing_nested(self):
        """Test dispatching generic_command without nested command_type."""
        result = await self.processor._dispatch_command(
            "generic_command", {"parameters": {}}
        )

        assert result["success"] is False
        assert "missing nested command_type" in result["error"]

    @pytest.mark.asyncio
    async def test_dispatch_command_script_execution_duplicate_uuid(self):
        """Test script execution with duplicate UUID."""
        with patch.object(
            self.processor, "_check_execution_uuid_processed", return_value=True
        ):
            result = await self.processor._dispatch_command(
                "execute_script",
                {"execution_uuid": "uuid123", "script_content": "echo test"},
            )

            assert result["success"] is True
            assert result["duplicate"] is True
            self.mock_agent.execute_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_command_script_execution_new_uuid(self):
        """Test script execution with new UUID."""
        with patch.object(
            self.processor, "_check_execution_uuid_processed", return_value=False
        ):
            with patch.object(self.processor, "_store_execution_uuid") as mock_store:
                with patch.object(
                    self.processor, "_send_script_execution_result"
                ) as mock_send:
                    result = await self.processor._dispatch_command(
                        "execute_script",
                        {"execution_uuid": "uuid123", "script_content": "echo test"},
                    )

                    assert result["success"] is True
                    mock_store.assert_called_once()
                    mock_send.assert_called_once()
                    self.mock_agent.execute_script.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_script_execution_result(self):
        """Test sending script execution result."""
        parameters = {
            "execution_id": "exec123",
            "execution_uuid": "uuid123",
            "script_name": "test_script.sh",
            "timestamp": "2023-01-01T00:00:00Z",
        }
        result = {
            "success": True,
            "exit_code": 0,
            "stdout": "Hello World",
            "stderr": "",
            "execution_time": 1.5,
            "shell_used": "/bin/bash",
        }

        await self.processor._send_script_execution_result(parameters, result)

        self.mock_agent.message_handler.queue_outbound_message.assert_called_once()
        call_args = self.mock_agent.message_handler.queue_outbound_message.call_args
        message = call_args[0][0]
        priority = call_args[1]["priority"]

        assert message["message_type"] == "script_execution_result"
        assert message["execution_id"] == "exec123"
        assert message["execution_uuid"] == "uuid123"
        assert message["success"] is True
        assert message["host_id"] == "host123"
        assert priority == Priority.HIGH

    @pytest.mark.asyncio
    async def test_send_script_execution_result_exception(self):
        """Test sending script execution result with exception."""
        self.mock_agent.get_host_approval_from_db.side_effect = Exception("DB error")

        parameters = {"execution_id": "exec123"}
        result = {"success": True}

        await self.processor._send_script_execution_result(parameters, result)

        self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_check_execution_uuid_processed_exists(self):
        """Test checking execution UUID that exists."""
        mock_execution = Mock()
        mock_session = Mock()
        mock_session.query.return_value.filter.return_value.first.return_value = (
            mock_execution
        )

        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager"
        ) as mock_db:
            mock_db.return_value.get_session.return_value = mock_session

            result = await self.processor._check_execution_uuid_processed("uuid123")

            assert result is True
            mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_execution_uuid_processed_not_exists(self):
        """Test checking execution UUID that doesn't exist."""
        mock_session = Mock()
        mock_session.query.return_value.filter.return_value.first.return_value = None

        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager"
        ) as mock_db:
            mock_db.return_value.get_session.return_value = mock_session

            result = await self.processor._check_execution_uuid_processed("uuid123")

            assert result is False

    @pytest.mark.asyncio
    async def test_check_execution_uuid_processed_exception(self):
        """Test checking execution UUID with database exception."""
        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager",
            side_effect=Exception("DB error"),
        ):
            result = await self.processor._check_execution_uuid_processed("uuid123")

            assert result is False
            self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_store_execution_uuid_new(self):
        """Test storing new execution UUID."""
        mock_session = Mock()
        mock_session.query.return_value.filter.return_value.first.return_value = None

        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager"
        ) as mock_db:
            mock_db.return_value.get_session.return_value = mock_session

            parameters = {
                "execution_id": "exec123",
                "execution_uuid": "uuid123",
                "script_name": "test.sh",
                "shell_type": "/bin/bash",
            }

            await self.processor._store_execution_uuid(parameters)

            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_execution_uuid_exists(self):
        """Test storing execution UUID that already exists."""
        mock_execution = Mock()
        mock_session = Mock()
        mock_session.query.return_value.filter.return_value.first.return_value = (
            mock_execution
        )

        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager"
        ) as mock_db:
            mock_db.return_value.get_session.return_value = mock_session

            parameters = {"execution_uuid": "uuid123"}

            await self.processor._store_execution_uuid(parameters)

            mock_session.add.assert_not_called()
            mock_session.commit.assert_not_called()
            self.mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_store_execution_uuid_no_uuid(self):
        """Test storing execution without UUID."""
        parameters = {"execution_id": "exec123"}

        await self.processor._store_execution_uuid(parameters)

        self.mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_store_execution_uuid_exception(self):
        """Test storing execution UUID with exception."""
        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager",
            side_effect=Exception("DB error"),
        ):
            parameters = {"execution_uuid": "uuid123"}

            await self.processor._store_execution_uuid(parameters)

            self.mock_logger.error.assert_called()


class TestPrivilegeDetection:
    """Test cases for is_running_privileged function."""

    @patch("sys.platform", "linux")
    def test_is_running_privileged_root_linux(self):
        """Test privilege detection on Linux as root."""
        with patch("os.geteuid", return_value=0, create=True):
            result = is_running_privileged()
            assert result is True

    @patch("sys.platform", "linux")
    def test_is_running_privileged_non_root_linux(self):
        """Test privilege detection on Linux as non-root."""
        with patch("os.geteuid", return_value=1000, create=True):
            result = is_running_privileged()
            assert result is False

    @patch("sys.platform", "win32")
    def test_is_running_privileged_admin_windows(self):
        """Test privilege detection on Windows as admin."""
        # Mock the ctypes module to simulate Windows environment
        mock_ctypes = Mock()
        mock_windll = Mock()
        mock_shell32 = Mock()
        mock_shell32.IsUserAnAdmin.return_value = 1
        mock_windll.shell32 = mock_shell32
        mock_ctypes.windll = mock_windll

        with patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            result = is_running_privileged()

            assert result is True

    @patch("sys.platform", "win32")
    def test_is_running_privileged_non_admin_windows(self):
        """Test privilege detection on Windows as non-admin."""
        # Mock the ctypes module to simulate Windows environment
        mock_ctypes = Mock()
        mock_windll = Mock()
        mock_shell32 = Mock()
        mock_shell32.IsUserAnAdmin.return_value = 0
        mock_windll.shell32 = mock_shell32
        mock_ctypes.windll = mock_windll

        with patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            result = is_running_privileged()

            assert result is False

    @patch("sys.platform", "linux")
    def test_is_running_privileged_exception(self):
        """Test privilege detection with exception."""
        with patch("os.geteuid", side_effect=Exception("Access error"), create=True):
            result = is_running_privileged()
            assert result is False  # Should default to non-privileged for security
