"""
Enhanced comprehensive pytest tests for message_handler.py.
Focuses on uncovered methods and code paths to increase coverage from 42% to 70%+.
"""

# pylint: disable=protected-access,unused-argument,broad-exception-raised,try-except-raise

import asyncio
import json
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
import websockets

from src.sysmanage_agent.communication.message_handler import MessageHandler


class TestMessageHandlerEnhanced:  # pylint: disable=too-many-public-methods
    """Enhanced test cases focusing on uncovered code paths."""

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.mock_agent = Mock()
        self.mock_agent.connected = True
        self.mock_agent.running = True
        self.mock_agent.websocket = AsyncMock()
        self.mock_agent.needs_registration = False
        self.mock_agent.last_registration_time = None

        # Setup registration manager
        self.mock_agent.registration_manager = Mock()
        self.mock_agent.registration_manager.get_stored_host_id_sync = Mock(
            return_value="test-host-id"
        )
        self.mock_agent.registration_manager.get_stored_host_token_sync = Mock(
            return_value="test-host-token"
        )

        # Setup registration
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info = Mock(
            return_value={
                "hostname": "test-host",
                "ipv4": "192.168.1.100",
                "ipv6": "::1",
                "os": "Linux",
            }
        )

        # Setup config
        self.mock_agent.config = Mock()
        self.mock_agent.config.is_script_execution_enabled = Mock(return_value=True)
        self.mock_agent.config.get_allowed_shells = Mock(return_value=["bash", "sh"])
        self.mock_agent.config.get_ping_interval = Mock(return_value=30)
        self.mock_agent.config.get_server_config = Mock(
            return_value={
                "hostname": "localhost",
                "port": 8000,
                "use_https": False,
            }
        )
        self.mock_agent.config.should_verify_ssl = Mock(return_value=True)

        # Setup message processor
        self.mock_agent.message_processor = AsyncMock()
        self.mock_agent.message_processor.handle_command = AsyncMock()

        # Setup clear_stored_host_id
        self.mock_agent.clear_stored_host_id = AsyncMock()
        self.mock_agent.registration_status = "registered"
        self.mock_agent.registration_confirmed = True

        with patch(
            "src.sysmanage_agent.communication.message_handler.MessageQueueManager"
        ):
            self.handler = MessageHandler(self.mock_agent)
        self.handler.queue_manager = Mock()

    # Tests for create_message method (lines 52-116)

    def test_create_message_with_data(self):
        """Test create_message with custom data."""
        message = self.handler.create_message("test_type", {"key": "value"})

        assert message["message_type"] == "test_type"
        assert "message_id" in message
        assert "timestamp" in message
        assert message["data"]["key"] == "value"
        assert message["data"]["host_id"] == "test-host-id"
        assert message["data"]["host_token"] == "test-host-token"

    def test_create_message_without_data(self):
        """Test create_message without data parameter."""
        message = self.handler.create_message("test_type")

        assert message["message_type"] == "test_type"
        assert "message_id" in message
        assert "timestamp" in message
        assert message["data"]["host_id"] == "test-host-id"
        assert message["data"]["host_token"] == "test-host-token"

    def test_create_message_with_existing_host_id(self):
        """Test create_message when host_id already in data."""
        message = self.handler.create_message(
            "test_type", {"host_id": "existing-host-id", "other": "data"}
        )

        assert message["data"]["host_id"] == "existing-host-id"
        assert message["data"]["other"] == "data"

    def test_create_message_no_stored_host_id(self):
        """Test create_message when no stored host_id available."""
        self.mock_agent.registration_manager.get_stored_host_id_sync.return_value = None
        self.mock_agent.registration_manager.get_stored_host_token_sync.return_value = (
            None
        )

        message = self.handler.create_message("test_type", {"key": "value"})

        assert message["message_type"] == "test_type"
        assert message["data"]["key"] == "value"
        assert "host_id" not in message["data"]
        assert "host_token" not in message["data"]

    def test_create_message_large_data(self):
        """Test create_message with large data (>1000 bytes)."""
        large_data = {"large_key": "x" * 2000}
        message = self.handler.create_message("test_type", large_data)

        assert message["message_type"] == "test_type"
        assert "message_id" in message
        assert message["data"]["large_key"] == "x" * 2000

    def test_create_message_small_data(self):
        """Test create_message with small data (<1000 bytes)."""
        small_data = {"small_key": "value"}
        message = self.handler.create_message("test_type", small_data)

        assert message["message_type"] == "test_type"
        assert message["data"]["small_key"] == "value"

    # Tests for create_system_info_message (lines 118-121)

    def test_create_system_info_message(self):
        """Test create_system_info_message."""
        message = self.handler.create_system_info_message()

        assert message["message_type"] == "system_info"
        assert message["data"]["hostname"] == "test-host"
        assert message["data"]["ipv4"] == "192.168.1.100"
        assert message["data"]["ipv6"] == "::1"
        assert message["data"]["os"] == "Linux"

    # Tests for create_heartbeat_message (lines 123-139)

    def test_create_heartbeat_message(self):
        """Test create_heartbeat_message."""
        with patch(
            "src.sysmanage_agent.communication.message_handler.is_running_privileged"
        ) as mock_is_privileged:
            mock_is_privileged.return_value = True

            message = self.handler.create_heartbeat_message()

            assert message["message_type"] == "heartbeat"
            assert message["data"]["agent_status"] == "healthy"
            assert message["data"]["hostname"] == "test-host"
            assert message["data"]["ipv4"] == "192.168.1.100"
            assert message["data"]["ipv6"] == "::1"
            assert message["data"]["is_privileged"] is True
            assert message["data"]["script_execution_enabled"] is True
            assert message["data"]["enabled_shells"] == ["bash", "sh"]
            assert "timestamp" in message["data"]

    def test_create_heartbeat_message_not_privileged(self):
        """Test create_heartbeat_message when not running privileged."""
        with patch(
            "src.sysmanage_agent.communication.message_handler.is_running_privileged"
        ) as mock_is_privileged:
            mock_is_privileged.return_value = False
            self.mock_agent.config.is_script_execution_enabled.return_value = False

            message = self.handler.create_heartbeat_message()

            assert message["data"]["is_privileged"] is False
            assert message["data"]["script_execution_enabled"] is False

    # Tests for send_message (lines 141-152)

    @pytest.mark.asyncio
    async def test_send_message_success(self):
        """Test send_message successful queuing."""
        message = {"message_type": "test", "data": "value"}
        self.handler.queue_outbound_message = AsyncMock(return_value="msg-123")

        result = await self.handler.send_message(message)

        assert result is True
        self.handler.queue_outbound_message.assert_called_once_with(message)

    @pytest.mark.asyncio
    async def test_send_message_failure(self):
        """Test send_message when queuing fails."""
        message = {"message_type": "test", "data": "value"}
        self.handler.queue_outbound_message = AsyncMock(
            side_effect=Exception("Queue error")
        )

        result = await self.handler.send_message(message)

        assert result is False

    # Tests for handle_command (line 156)

    @pytest.mark.asyncio
    async def test_handle_command(self):
        """Test handle_command delegates to message_processor."""
        message = {"message_type": "command", "command": "test"}

        await self.handler.handle_command(message)

        self.mock_agent.message_processor.handle_command.assert_called_once_with(
            message
        )

    # Tests for _check_server_health (lines 158-188)

    @pytest.mark.asyncio
    async def test_check_server_health_success_http(self):
        """Test _check_server_health with successful HTTP connection."""
        mock_response = Mock()
        mock_response.status = 200

        mock_get_cm = AsyncMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = AsyncMock()

        mock_session = Mock()
        mock_session.get.return_value = mock_get_cm

        mock_session_cm = AsyncMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = AsyncMock()

        with patch("aiohttp.ClientSession", return_value=mock_session_cm):
            with patch("aiohttp.TCPConnector"):
                result = await self.handler._check_server_health()

        assert result is True

    @pytest.mark.asyncio
    async def test_check_server_health_success_https(self):
        """Test _check_server_health with HTTPS connection."""
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "secure.example.com",
            "port": 443,
            "use_https": True,
        }

        mock_response = Mock()
        mock_response.status = 200

        mock_get_cm = AsyncMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = AsyncMock()

        mock_session = Mock()
        mock_session.get.return_value = mock_get_cm

        mock_session_cm = AsyncMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = AsyncMock()

        with patch("aiohttp.ClientSession", return_value=mock_session_cm):
            with patch("aiohttp.TCPConnector"):
                with patch("ssl.create_default_context") as mock_ssl:
                    mock_ssl_context = Mock()
                    mock_ssl.return_value = mock_ssl_context

                    result = await self.handler._check_server_health()

        assert result is True

    @pytest.mark.asyncio
    async def test_check_server_health_no_ssl_verify(self):
        """Test _check_server_health with SSL verification disabled."""
        self.mock_agent.config.get_server_config.return_value = {
            "hostname": "secure.example.com",
            "port": 443,
            "use_https": True,
        }
        self.mock_agent.config.should_verify_ssl.return_value = False

        mock_response = Mock()
        mock_response.status = 200

        mock_get_cm = AsyncMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = AsyncMock()

        mock_session = Mock()
        mock_session.get.return_value = mock_get_cm

        mock_session_cm = AsyncMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = AsyncMock()

        with patch("aiohttp.ClientSession", return_value=mock_session_cm):
            with patch("aiohttp.TCPConnector"):
                with patch("ssl.create_default_context") as mock_ssl:
                    mock_ssl_context = Mock()
                    mock_ssl_context.check_hostname = True
                    mock_ssl_context.verify_mode = ssl.CERT_REQUIRED
                    mock_ssl.return_value = mock_ssl_context

                    result = await self.handler._check_server_health()

                    # Verify SSL was disabled
                    assert mock_ssl_context.check_hostname is False
                    assert mock_ssl_context.verify_mode == ssl.CERT_NONE

        assert result is True

    @pytest.mark.asyncio
    async def test_check_server_health_failure(self):
        """Test _check_server_health with connection failure."""
        mock_response = Mock()
        mock_response.status = 500

        mock_get_cm = AsyncMock()
        mock_get_cm.__aenter__.return_value = mock_response
        mock_get_cm.__aexit__.return_value = AsyncMock()

        mock_session = Mock()
        mock_session.get.return_value = mock_get_cm

        mock_session_cm = AsyncMock()
        mock_session_cm.__aenter__.return_value = mock_session
        mock_session_cm.__aexit__.return_value = AsyncMock()

        with patch("aiohttp.ClientSession", return_value=mock_session_cm):
            with patch("aiohttp.TCPConnector"):
                result = await self.handler._check_server_health()

        assert result is False

    @pytest.mark.asyncio
    async def test_check_server_health_exception(self):
        """Test _check_server_health with exception."""
        with patch("aiohttp.ClientSession", side_effect=Exception("Connection error")):
            result = await self.handler._check_server_health()

        assert result is False

    # Tests for _handle_server_error (lines 190-272)

    @pytest.mark.asyncio
    async def test_handle_server_error_host_not_registered(self):
        """Test _handle_server_error with host_not_registered error."""
        data = {
            "error_type": "host_not_registered",
            "message": "Host not found",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with patch.object(
            self.handler, "_handle_host_not_registered", new_callable=AsyncMock
        ) as mock_handle:
            await self.handler._handle_server_error(data)

        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_server_error_host_not_approved(self):
        """Test _handle_server_error with host_not_approved error."""
        data = {
            "error_type": "host_not_approved",
            "message": "Host pending approval",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        await self.handler._handle_server_error(data)
        # Should log warning but not raise exception

    @pytest.mark.asyncio
    async def test_handle_server_error_missing_hostname(self):
        """Test _handle_server_error with missing_hostname error."""
        data = {
            "error_type": "missing_hostname",
            "message": "Hostname required",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        await self.handler._handle_server_error(data)
        # Should log error but not raise exception

    @pytest.mark.asyncio
    async def test_handle_server_error_queue_error(self):
        """Test _handle_server_error with queue_error."""
        data = {
            "error_type": "queue_error",
            "message": "Failed to queue message",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        await self.handler._handle_server_error(data)
        # Should log error but not raise exception

    @pytest.mark.asyncio
    async def test_handle_server_error_stale_error(self):
        """Test _handle_server_error ignoring stale error messages."""
        # Set last registration time to now
        self.mock_agent.last_registration_time = datetime.now(timezone.utc)

        # Create error message from 1 hour ago using timedelta
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)
        data = {
            "error_type": "host_not_registered",
            "message": "Host not found",
            "timestamp": old_time.isoformat(),
        }

        with patch.object(
            self.handler, "_handle_host_not_registered", new_callable=AsyncMock
        ) as mock_handle:
            await self.handler._handle_server_error(data)

        # Should not call handler for stale error
        mock_handle.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_server_error_fresh_error(self):
        """Test _handle_server_error processing fresh error messages."""
        # Set last registration time to 1 hour ago using timedelta
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)
        self.mock_agent.last_registration_time = old_time

        # Create error message from now
        data = {
            "error_type": "host_not_registered",
            "message": "Host not found",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with patch.object(
            self.handler, "_handle_host_not_registered", new_callable=AsyncMock
        ) as mock_handle:
            await self.handler._handle_server_error(data)

        # Should call handler for fresh error
        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_server_error_no_timestamp(self):
        """Test _handle_server_error without timestamp."""
        data = {
            "error_type": "host_not_registered",
            "message": "Host not found",
        }

        with patch.object(
            self.handler, "_handle_host_not_registered", new_callable=AsyncMock
        ) as mock_handle:
            await self.handler._handle_server_error(data)

        # Should process normally without timestamp
        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_server_error_no_last_registration_time(self):
        """Test _handle_server_error without last_registration_time."""
        self.mock_agent.last_registration_time = None
        data = {
            "error_type": "host_not_registered",
            "message": "Host not found",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with patch.object(
            self.handler, "_handle_host_not_registered", new_callable=AsyncMock
        ) as mock_handle:
            await self.handler._handle_server_error(data)

        # Should process normally
        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_server_error_invalid_timestamp(self):
        """Test _handle_server_error with invalid timestamp format."""
        self.mock_agent.last_registration_time = datetime.now(timezone.utc)
        data = {
            "error_type": "host_not_registered",
            "message": "Host not found",
            "timestamp": "invalid-timestamp",
        }

        with patch.object(
            self.handler, "_handle_host_not_registered", new_callable=AsyncMock
        ) as mock_handle:
            await self.handler._handle_server_error(data)

        # Should process normally despite invalid timestamp
        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_server_error_unknown_error_type(self):
        """Test _handle_server_error with unknown error type."""
        data = {
            "error_type": "unknown_error",
            "message": "Unknown error occurred",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        await self.handler._handle_server_error(data)
        # Should log but not raise exception

    # Tests for _handle_host_not_registered (lines 274-295)

    @pytest.mark.asyncio
    async def test_handle_host_not_registered(self):
        """Test _handle_host_not_registered clears state and triggers re-registration."""
        await self.handler._handle_host_not_registered()

        # Verify state was cleared
        self.mock_agent.clear_stored_host_id.assert_called_once()
        assert self.mock_agent.registration_status is None
        assert self.mock_agent.registration_confirmed is False
        assert self.mock_agent.needs_registration is True
        assert self.mock_agent.running is False

    @pytest.mark.asyncio
    async def test_handle_host_not_registered_clear_error(self):
        """Test _handle_host_not_registered when clearing host_id fails."""
        self.mock_agent.clear_stored_host_id.side_effect = Exception("Database error")

        await self.handler._handle_host_not_registered()

        # Should continue despite error
        assert self.mock_agent.needs_registration is True
        assert self.mock_agent.running is False

    # Tests for message_receiver (lines 297-387)

    @pytest.mark.asyncio
    async def test_message_receiver_command(self):
        """Test message_receiver queuing command message for processing."""
        command_message = json.dumps(
            {"message_type": "command", "command": "test_command"}
        )
        self.mock_agent.websocket.recv = AsyncMock(side_effect=[command_message])

        # Mock queue_inbound_message to stop after queueing
        async def queue_and_stop(*args):
            self.mock_agent.running = False
            return "test-queue-id"

        self.handler.queue_inbound_message = AsyncMock(side_effect=queue_and_stop)
        self.handler.inbound_queue_processor_running = True  # Prevent task creation

        await self.handler.message_receiver()

        # Commands should be queued, not processed directly
        self.handler.queue_inbound_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_message_receiver_ping(self):
        """Test message_receiver responding to ping message."""
        ping_message = json.dumps({"message_type": "ping", "message_id": "ping-123"})
        self.mock_agent.websocket.recv = AsyncMock(side_effect=[ping_message])

        # Stop after one message
        def stop_running(*args):
            self.mock_agent.running = False
            return True

        self.handler.send_message = AsyncMock(side_effect=stop_running)

        await self.handler.message_receiver()

        self.handler.send_message.assert_called_once()
        call_args = self.handler.send_message.call_args[0][0]
        assert call_args["message_type"] == "pong"
        assert call_args["data"]["ping_id"] == "ping-123"

    @pytest.mark.asyncio
    async def test_message_receiver_ack_with_queue_id(self):
        """Test message_receiver processing ack with queue_id."""
        ack_message = json.dumps(
            {
                "message_type": "ack",
                "queue_id": "queue-123",
                "status": "success",
                "data": {},
            }
        )
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[ack_message, asyncio.CancelledError()]
        )

        # Stop after one message
        self.mock_agent.running = True

        async def stop_after_one(*args):
            await asyncio.sleep(0.01)
            self.mock_agent.running = False

        asyncio.create_task(stop_after_one(None))

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_ack_without_queue_id(self):
        """Test message_receiver processing ack without queue_id."""
        ack_message = json.dumps(
            {
                "message_type": "ack",
                "status": "processed",
                "data": {"acked_message_id": "msg-456"},
            }
        )
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[ack_message, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_error(self):
        """Test message_receiver processing error message."""
        error_message = json.dumps(
            {
                "message_type": "error",
                "error_type": "test_error",
                "message": "Test error message",
            }
        )
        self.mock_agent.websocket.recv = AsyncMock(side_effect=[error_message])

        def stop_running(*args):
            self.mock_agent.running = False

        with patch.object(
            self.handler, "_handle_server_error", new_callable=AsyncMock
        ) as mock_handle:
            mock_handle.side_effect = stop_running

            await self.handler.message_receiver()

        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_message_receiver_error_needs_registration(self):
        """Test message_receiver returning when needs_registration is set."""
        error_message = json.dumps(
            {
                "message_type": "error",
                "error_type": "host_not_registered",
                "message": "Host not registered",
            }
        )
        self.mock_agent.websocket.recv = AsyncMock(side_effect=[error_message])

        async def set_needs_registration(*args):
            self.mock_agent.needs_registration = True

        with patch.object(
            self.handler, "_handle_server_error", new_callable=AsyncMock
        ) as mock_handle:
            mock_handle.side_effect = set_needs_registration

            await self.handler.message_receiver()

        mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_message_receiver_host_approved(self):
        """Test message_receiver processing host_approved message."""
        approval_message = json.dumps(
            {"message_type": "host_approved", "host_id": "host-123"}
        )
        self.mock_agent.websocket.recv = AsyncMock(side_effect=[approval_message])
        self.mock_agent.handle_host_approval = AsyncMock()

        def stop_running(*args):
            self.mock_agent.running = False

        self.mock_agent.handle_host_approval.side_effect = stop_running

        await self.handler.message_receiver()

        self.mock_agent.handle_host_approval.assert_called_once()

    @pytest.mark.asyncio
    async def test_message_receiver_registration_success(self):
        """Test message_receiver processing registration_success message."""
        reg_message = json.dumps(
            {"message_type": "registration_success", "host_id": "host-456"}
        )
        self.mock_agent.websocket.recv = AsyncMock(side_effect=[reg_message])
        self.mock_agent.handle_registration_success = AsyncMock()

        def stop_running(*args):
            self.mock_agent.running = False

        self.mock_agent.handle_registration_success.side_effect = stop_running

        await self.handler.message_receiver()

        self.mock_agent.handle_registration_success.assert_called_once()

    @pytest.mark.asyncio
    async def test_message_receiver_diagnostic_result_ack(self):
        """Test message_receiver processing diagnostic_result_ack message."""
        diag_ack = json.dumps(
            {"message_type": "diagnostic_result_ack", "status": "processed"}
        )
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[diag_ack, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_available_packages_batch_queued(self):
        """Test message_receiver processing available_packages_batch_queued."""
        pkg_message = json.dumps(
            {"message_type": "available_packages_batch_queued", "status": "queued"}
        )
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[pkg_message, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_available_packages_batch_start_queued(self):
        """Test message_receiver processing batch_start_queued."""
        start_message = json.dumps(
            {
                "message_type": "available_packages_batch_start_queued",
                "status": "queued",
            }
        )
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[start_message, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_available_packages_batch_end_queued(self):
        """Test message_receiver processing batch_end_queued."""
        end_message = json.dumps(
            {
                "message_type": "available_packages_batch_end_queued",
                "status": "completed",
            }
        )
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[end_message, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()

    @pytest.mark.asyncio
    async def test_message_receiver_unknown_message_type(self):
        """Test message_receiver handling unknown message type."""
        unknown_message = json.dumps({"message_type": "unknown_type", "data": "test"})
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[unknown_message, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()
        # Should log warning but continue

    @pytest.mark.asyncio
    async def test_message_receiver_invalid_json(self):
        """Test message_receiver handling invalid JSON."""
        invalid_json = "{ invalid json }"
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[invalid_json, asyncio.CancelledError()]
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()
        # Should log error but continue

    @pytest.mark.asyncio
    async def test_message_receiver_processing_exception(self):
        """Test message_receiver handling exception during message processing."""
        message = json.dumps({"message_type": "command", "command": "test"})
        self.mock_agent.websocket.recv = AsyncMock(
            side_effect=[message, asyncio.CancelledError()]
        )
        self.mock_agent.message_processor.handle_command.side_effect = Exception(
            "Processing error"
        )

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_receiver()
        # Should log error but continue

    @pytest.mark.asyncio
    async def test_message_receiver_connection_closed(self):
        """Test message_receiver handling connection closed."""
        self.mock_agent.websocket.recv.side_effect = websockets.ConnectionClosed(
            None, None
        )

        await self.handler.message_receiver()

        assert self.mock_agent.connected is False
        assert self.mock_agent.websocket is None

    @pytest.mark.asyncio
    async def test_message_receiver_general_exception(self):
        """Test message_receiver handling general exception."""
        self.mock_agent.websocket.recv.side_effect = Exception("Unexpected error")

        await self.handler.message_receiver()

        assert self.mock_agent.connected is False
        assert self.mock_agent.websocket is None

    # Tests for message_sender (lines 389-416)

    @pytest.mark.asyncio
    async def test_message_sender_sends_initial_system_info(self):
        """Test message_sender sends initial system info."""
        self.handler.send_message = AsyncMock()
        self.mock_agent.config.get_ping_interval.return_value = 0.1

        # Stop after initial message
        async def stop_after_send(*args):
            self.mock_agent.running = False
            return True

        self.handler.send_message.side_effect = stop_after_send

        await self.handler.message_sender()

        # Should have sent system info
        assert self.handler.send_message.call_count >= 1
        first_call = self.handler.send_message.call_args_list[0][0][0]
        assert first_call["message_type"] == "system_info"

    @pytest.mark.asyncio
    async def test_message_sender_sends_periodic_heartbeats(self):
        """Test message_sender sends periodic heartbeats."""
        self.handler.send_message = AsyncMock(return_value=True)
        self.mock_agent.config.get_ping_interval.return_value = 0.1

        # Stop after a few iterations
        call_count = [0]

        async def count_and_stop(*args):
            call_count[0] += 1
            if call_count[0] >= 3:
                self.mock_agent.running = False
            return True

        self.handler.send_message.side_effect = count_and_stop

        await self.handler.message_sender()

        # Should have sent system info + heartbeats
        assert self.handler.send_message.call_count >= 2

    @pytest.mark.asyncio
    async def test_message_sender_heartbeat_failure(self):
        """Test message_sender handling heartbeat send failure."""
        call_count = [0]

        async def fail_on_heartbeat(message):
            call_count[0] += 1
            if message["message_type"] == "heartbeat":
                return False  # Heartbeat fails
            return True  # System info succeeds

        self.handler.send_message = AsyncMock(side_effect=fail_on_heartbeat)
        self.mock_agent.config.get_ping_interval.return_value = 0.1

        await self.handler.message_sender()

        # Should return after heartbeat failure
        assert call_count[0] >= 1

    @pytest.mark.asyncio
    async def test_message_sender_cancelled_error(self):
        """Test message_sender handling CancelledError."""
        self.handler.send_message = AsyncMock(return_value=True)
        self.mock_agent.config.get_ping_interval.return_value = 0.1

        call_count = [0]

        async def raise_cancelled(*args):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise asyncio.CancelledError()
            return True

        self.handler.send_message.side_effect = raise_cancelled

        with pytest.raises(asyncio.CancelledError):
            await self.handler.message_sender()

    @pytest.mark.asyncio
    async def test_message_sender_general_exception(self):
        """Test message_sender handling general exception."""
        call_count = [0]

        async def raise_exception(*args):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise Exception("Send error")
            return True

        self.handler.send_message = AsyncMock(side_effect=raise_exception)
        self.mock_agent.config.get_ping_interval.return_value = 0.1

        await self.handler.message_sender()

        # Should return after exception
        assert call_count[0] >= 2

    @pytest.mark.asyncio
    async def test_message_sender_disconnected_during_sleep(self):
        """Test message_sender when agent disconnects during sleep."""
        self.handler.send_message = AsyncMock(return_value=True)
        self.mock_agent.config.get_ping_interval.return_value = 0.01

        call_count = [0]

        async def disconnect_after_first(*args):
            call_count[0] += 1
            if call_count[0] >= 2:
                self.mock_agent.connected = False
                self.mock_agent.running = False
            return True

        self.handler.send_message.side_effect = disconnect_after_first

        await self.handler.message_sender()

        # Should check connected status before sending
        assert call_count[0] >= 1

    # Tests for on_connection_lost with cancellation (lines 649-653)

    @pytest.mark.asyncio
    async def test_on_connection_lost_with_running_task(self):
        """Test on_connection_lost with actually running task."""

        # Create a real task that will be cancelled
        async def long_running_task():
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                raise

        task = asyncio.create_task(long_running_task())
        self.handler.processing_task = task
        self.handler.queue_processor_running = True

        await self.handler.on_connection_lost()

        assert self.handler.queue_processor_running is False
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_on_connection_lost_with_completed_task(self):
        """Test on_connection_lost with already completed task."""

        # Create a task that completes immediately
        async def completed_task():
            return "done"

        task = asyncio.create_task(completed_task())
        await asyncio.sleep(0.01)  # Let it complete
        self.handler.processing_task = task
        self.handler.queue_processor_running = True

        await self.handler.on_connection_lost()

        assert self.handler.queue_processor_running is False
        assert task.done()
