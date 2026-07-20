# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Enhanced comprehensive pytest tests for message_handler.py (receiver/sender paths).

Split from test_message_handler_enhanced.py to keep each file under the 1000-line limit.
"""

# pylint: disable=protected-access,unused-argument,broad-exception-raised,try-except-raise

import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch

import pytest
import websockets

from src.sysmanage_agent.communication.message_handler import MessageHandler


class TestMessageHandlerReceiver:  # pylint: disable=too-many-public-methods
    """Enhanced test cases for message receiver/sender code paths."""

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
    async def test_dispatch_logging_config_update_extracts_nested_payload(self):
        """logging_config_update payload is nested under the envelope's "data".

        Regression: the dispatcher must read ``data["data"]["logging"]``, not a
        top-level ``data["logging"]`` (which is always absent → an empty config
        that silently no-ops the server-pushed logging settings).
        """
        self.mock_agent.apply_logging_config = Mock()
        payload = {
            "native_enabled": True,
            "native_target": "auto",
            "native_identifier": "sysmanage-agent",
            "log_level": "WARNING",
            "verbosity": "medium",
        }
        envelope = {
            "message_type": "logging_config_update",
            "message_id": "msg-1",
            "data": {"logging": payload},
            "queue_message_id": "q-1",
        }

        # Returns False (keep the receiver loop running) and forwards the
        # correctly-unwrapped payload to the agent.
        should_exit = await self.handler._dispatch_received_message(envelope)

        assert should_exit is False
        self.mock_agent.apply_logging_config.assert_called_once_with(payload)

    @pytest.mark.asyncio
    async def test_dispatch_logging_config_update_missing_payload(self):
        """A logging_config_update with no nested payload applies an empty dict."""
        self.mock_agent.apply_logging_config = Mock()
        envelope = {"message_type": "logging_config_update", "data": {}}

        await self.handler._dispatch_received_message(envelope)

        self.mock_agent.apply_logging_config.assert_called_once_with({})

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
        """Test message_receiver handling general exception.

        Unexpected exceptions are re-raised so the outer connection
        lifecycle reconnects (rather than the receiver task quietly
        dying while the sender keeps the WS pumping outbound traffic
        — which leaves inbound commands silently disappearing).  See
        the matching docstring in ``MessageHandler.message_receiver``.
        """
        self.mock_agent.websocket.recv.side_effect = Exception("Unexpected error")

        with pytest.raises(Exception, match="Unexpected error"):
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
