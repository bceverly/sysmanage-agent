"""
Test edge cases and error handling for agent_utils.py.
Focused on improving test coverage by targeting uncovered paths.
"""

import asyncio
from unittest.mock import Mock, patch, AsyncMock

import pytest

from src.sysmanage_agent.core.agent_utils import (
    UpdateChecker,
    AuthenticationHelper,
    MessageProcessor,
    is_running_privileged,
)


class TestUpdateCheckerEdgeCases:
    """Test edge cases for UpdateChecker class."""

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.update_checker = UpdateChecker(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_perform_periodic_check_not_running(self):
        """Test periodic check when agent is not running."""
        self.mock_agent.running = False
        self.mock_agent.connected = True

        result = await self.update_checker.perform_periodic_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_perform_periodic_check_not_connected(self):
        """Test periodic check when agent is not connected."""
        self.mock_agent.running = True
        self.mock_agent.connected = False

        result = await self.update_checker.perform_periodic_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_perform_periodic_check_exception(self):
        """Test periodic check with exception in check_updates."""
        self.mock_agent.running = True
        self.mock_agent.connected = True
        self.mock_agent.check_updates = AsyncMock(side_effect=Exception("Update error"))

        result = await self.update_checker.perform_periodic_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_run_update_checker_loop_cancelled(self):
        """Test update checker loop cancellation."""
        self.mock_agent.running = True
        self.mock_agent.config.get_update_check_interval.return_value = 3600

        with patch("asyncio.sleep", side_effect=asyncio.CancelledError):
            with pytest.raises(asyncio.CancelledError):
                await self.update_checker.run_update_checker_loop()

    @pytest.mark.asyncio
    async def test_run_update_checker_loop_exception_recovery(self):
        """Test update checker loop handles exceptions and continues."""
        self.mock_agent.running = True
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("First error")
            # Stop the loop after recovery
            self.mock_agent.running = False

        self.mock_agent.config.get_update_check_interval.return_value = 3600

        with patch("asyncio.sleep", side_effect=side_effect):
            with patch("asyncio.get_event_loop") as mock_loop:
                mock_loop.return_value.time.return_value = 1000

                # Should not raise exception, should handle and continue
                await self.update_checker.run_update_checker_loop()

        assert call_count[0] >= 2  # Should have retried after exception


class TestAuthenticationHelperEdgeCases:
    """Test edge cases for AuthenticationHelper class."""

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.auth_helper = AuthenticationHelper(self.mock_agent, self.mock_logger)

    def test_build_auth_url_default_values(self):
        """Test build_auth_url with default config values."""
        self.mock_agent.config.get_server_config.return_value = {}

        url = self.auth_helper.build_auth_url()
        assert url == "http://localhost:8000/agent/auth"

    def test_build_auth_url_https(self):
        """Test build_auth_url with HTTPS enabled."""
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "server.example.com",
            "port": 443,
            "use_https": True,
        }

        url = self.auth_helper.build_auth_url()
        assert url == "https://server.example.com:443/agent/auth"


class TestMessageProcessorEdgeCases:
    """Test edge cases for MessageProcessor class."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.message_processor = MessageProcessor(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_dispatch_command_generic_command_missing_nested_type(self):
        """Test generic_command dispatch without nested command_type."""
        result = await self.message_processor._dispatch_command(
            "generic_command", {"parameters": {}}
        )

        assert not result["success"]
        assert "missing nested command_type" in result["error"]

    @pytest.mark.asyncio
    async def test_dispatch_command_unknown_command_type(self):
        """Test dispatch with unknown command type."""
        result = await self.message_processor._dispatch_command("unknown_command", {})

        assert not result["success"]
        assert "Unknown command type" in result["error"]

    @pytest.mark.asyncio
    async def test_send_script_execution_result_missing_host_approval(self):
        """Test script execution result sending without host approval."""
        parameters = {
            "execution_id": "test_exec",
            "execution_uuid": "test_uuid",
            "script_name": "test_script",
        }
        result = {"success": True, "exit_code": 0}

        self.mock_agent.get_host_approval_from_db.return_value = None
        self.mock_agent.registration.get_system_info.return_value = {
            "fqdn": "test.local"
        }
        self.mock_agent.message_handler.queue_outbound_message = AsyncMock()

        await self.message_processor._send_script_execution_result(parameters, result)

        # Should still queue message without host_id
        self.mock_agent.message_handler.queue_outbound_message.assert_called_once()
        queued_message = (
            self.mock_agent.message_handler.queue_outbound_message.call_args[0][0]
        )
        assert "host_id" not in queued_message

    @pytest.mark.asyncio
    async def test_send_script_execution_result_exception(self):
        """Test script execution result sending with exception."""
        parameters = {"execution_id": "test_exec"}
        result = {"success": True}

        self.mock_agent.get_host_approval_from_db.side_effect = Exception("DB error")

        # Should not raise exception
        await self.message_processor._send_script_execution_result(parameters, result)

    @pytest.mark.asyncio
    async def test_check_execution_uuid_processed_exception(self):
        """Test execution UUID checking with database exception."""
        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager"
        ) as mock_db:
            mock_db.side_effect = Exception("DB connection error")

            result = await self.message_processor._check_execution_uuid_processed(
                "test_uuid"
            )
            # Should return False to allow processing if check fails
            assert result is False

    @pytest.mark.asyncio
    async def test_store_execution_uuid_no_uuid(self):
        """Test storing execution UUID when none provided."""
        parameters = {"execution_id": "test_exec"}

        # Should log warning and return early
        await self.message_processor._store_execution_uuid(parameters)

    @pytest.mark.asyncio
    async def test_store_execution_uuid_already_exists(self):
        """Test storing execution UUID when it already exists."""
        parameters = {"execution_id": "test_exec", "execution_uuid": "existing_uuid"}

        mock_session = Mock()
        mock_existing = Mock()
        mock_session.query.return_value.filter.return_value.first.return_value = (
            mock_existing
        )

        mock_db_manager = Mock()
        mock_db_manager.get_session.return_value = mock_session

        with patch(
            "src.sysmanage_agent.core.agent_utils.get_database_manager",
            return_value=mock_db_manager,
        ):
            await self.message_processor._store_execution_uuid(parameters)

            # Should not add new record
            mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_script_duplicate_uuid(self):
        """Test execute_script with duplicate UUID."""
        parameters = {"execution_uuid": "duplicate_uuid"}

        with patch.object(
            self.message_processor, "_check_execution_uuid_processed", return_value=True
        ):
            result = await self.message_processor._dispatch_command(
                "execute_script", parameters
            )

            assert result["success"]
            assert result["duplicate"]


class TestIsRunningPrivilegedEdgeCases:
    """Test edge cases for is_running_privileged function."""

    def test_is_running_privileged_unix_root(self):
        """Test privilege detection on Unix as root."""
        with patch("sys.platform", "linux"):
            with patch("os.geteuid", return_value=0, create=True):
                assert is_running_privileged() is True

    def test_is_running_privileged_unix_user(self):
        """Test privilege detection on Unix as regular user."""
        with patch("sys.platform", "linux"):
            with patch("os.geteuid", return_value=1000, create=True):
                assert is_running_privileged() is False

    def test_is_running_privileged_exception_handling(self):
        """Test privilege detection with exception."""
        with patch("sys.platform", "linux"):
            with patch(
                "os.geteuid", side_effect=AttributeError("No geteuid"), create=True
            ):
                # Should default to False for security
                assert is_running_privileged() is False
