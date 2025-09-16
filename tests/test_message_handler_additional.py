"""
Additional comprehensive tests for message_handler module.
Tests missing coverage areas to improve overall coverage.
"""

import json
from unittest.mock import Mock, AsyncMock, patch
import pytest

from src.database.models import QueueDirection, Priority
from tests.message_handler_test_base import MessageHandlerTestBase


class TestQueuedMessageHandlerAdditional(
    MessageHandlerTestBase
):  # pylint: disable=too-many-public-methods
    """Additional test cases for QueuedMessageHandler class coverage."""

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_queue_outbound_message_task_creation_exception(
        self, mock_create_task
    ):
        """Test queue_outbound_message when task creation fails (lines 92-93)."""
        message = {"message_type": "test", "data": "value"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-123"
        self.mock_agent.connected = True
        self.handler.queue_processor_running = False

        # Make create_task raise an exception
        mock_create_task.side_effect = Exception("Task creation failed")

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-123"
        mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_queue_inbound_message_basic(self):
        """Test queue_inbound_message method (lines 109-123)."""
        message = {
            "message_type": "command",
            "data": "test_command",
            "correlation_id": "corr-456",
            "reply_to": "reply-789",
        }
        self.handler.queue_manager.enqueue_message.return_value = "inbound-msg-123"

        result = await self.handler.queue_inbound_message(message)

        assert result == "inbound-msg-123"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="command",
            message_data=message,
            direction=QueueDirection.INBOUND,
            priority=Priority.NORMAL,
            correlation_id="corr-456",
            reply_to="reply-789",
        )

    @pytest.mark.asyncio
    async def test_queue_inbound_message_no_message_type(self):
        """Test queue_inbound_message without message_type."""
        message = {"data": "test_data"}
        self.handler.queue_manager.enqueue_message.return_value = "inbound-unknown"

        result = await self.handler.queue_inbound_message(message)

        assert result == "inbound-unknown"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="unknown",
            message_data=message,
            direction=QueueDirection.INBOUND,
            priority=Priority.NORMAL,
            correlation_id=None,
            reply_to=None,
        )

    @pytest.mark.asyncio
    async def test_send_message_direct_not_connected(self):
        """Test send_message_direct when not connected (lines 135-137)."""
        message = {"message_type": "test", "data": "value"}
        self.mock_agent.connected = False
        self.mock_agent.websocket = None

        result = await self.handler.send_message_direct(message)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_message_direct_no_websocket(self):
        """Test send_message_direct when websocket is None."""
        message = {"message_type": "test", "data": "value"}
        self.mock_agent.connected = True
        self.mock_agent.websocket = None

        result = await self.handler.send_message_direct(message)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_message_direct_success(self):
        """Test send_message_direct successful send (lines 139-142)."""
        message = {"message_type": "test", "data": "value"}
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()

        result = await self.handler.send_message_direct(message)

        assert result is True
        self.mock_agent.websocket.send.assert_called_once_with(json.dumps(message))

    @pytest.mark.asyncio
    async def test_send_message_direct_exception(self):
        """Test send_message_direct when websocket.send raises exception (lines 143-148)."""
        message = {"message_type": "test", "data": "value"}
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()
        self.mock_agent.websocket.send.side_effect = Exception("Send failed")

        result = await self.handler.send_message_direct(message)

        assert result is False
        # Connection should be marked as broken
        assert self.mock_agent.connected is False
        assert self.mock_agent.websocket is None

    @pytest.mark.asyncio
    async def test_process_outbound_queue_already_running(self):
        """Test process_outbound_queue when already running (lines 159-161)."""
        self.handler.queue_processor_running = True

        await self.handler.process_outbound_queue()

        # Should exit early without processing
        self.handler.queue_manager.dequeue_messages.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_outbound_queue_no_messages(self):
        """Test process_outbound_queue with no messages (lines 174-177)."""
        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.return_value = []

        with patch("asyncio.sleep") as mock_sleep:
            # Set up to exit after first iteration
            mock_sleep.side_effect = [
                None,
                lambda: setattr(self.mock_agent, "connected", False),
            ]

            await self.handler.process_outbound_queue()

            mock_sleep.assert_called_with(1)

    @pytest.mark.asyncio
    async def test_process_outbound_queue_message_processing_success(self):
        """Test process_outbound_queue successful message processing (lines 180-226)."""
        # Create mock message
        mock_message = Mock()
        mock_message.message_id = "test-msg-123"

        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.side_effect = [
            [mock_message],  # First call returns message
            [],  # Second call returns empty to exit loop
        ]
        self.handler.queue_manager.mark_processing.return_value = True
        self.handler.queue_manager.deserialize_message_data.return_value = {
            "test": "data"
        }

        with patch.object(
            self.handler, "send_message_direct", return_value=True
        ) as mock_send:
            with patch("asyncio.sleep") as mock_sleep:
                # First sleep is after message processing, second will exit loop
                mock_sleep.side_effect = [
                    None,
                    lambda: setattr(self.mock_agent, "connected", False),
                ]

                await self.handler.process_outbound_queue()

                # Verify message was processed
                self.handler.queue_manager.mark_processing.assert_called_with(
                    "test-msg-123"
                )
                mock_send.assert_called_once()
                self.handler.queue_manager.mark_completed.assert_called_with(
                    "test-msg-123"
                )

    @pytest.mark.asyncio
    async def test_process_outbound_queue_message_processing_failed(self):
        """Test process_outbound_queue failed message processing."""
        mock_message = Mock()
        mock_message.message_id = "test-msg-456"

        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.side_effect = [
            [mock_message],  # First call returns message
            [],  # Won't be reached due to connection break
        ]
        self.handler.queue_manager.mark_processing.return_value = True
        self.handler.queue_manager.deserialize_message_data.return_value = {
            "test": "data"
        }

        with patch.object(self.handler, "send_message_direct", return_value=False):
            await self.handler.process_outbound_queue()

            # Verify message was marked as failed
            self.handler.queue_manager.mark_failed.assert_called_with(
                "test-msg-456", "Failed to send over WebSocket", retry=True
            )

    @pytest.mark.asyncio
    async def test_process_outbound_queue_connection_lost_during_processing(self):
        """Test process_outbound_queue when connection is lost during processing."""
        mock_message = Mock()
        mock_message.message_id = "test-msg-789"

        # Start connected, then lose connection after dequeue
        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.return_value = [mock_message]

        def lose_connection_after_mark(*args):
            self.mock_agent.connected = False
            return True

        self.handler.queue_manager.mark_processing.side_effect = (
            lose_connection_after_mark
        )

        await self.handler.process_outbound_queue()

        # Should break out of loop after losing connection
        self.handler.queue_manager.mark_processing.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_outbound_queue_mark_processing_fails(self):
        """Test process_outbound_queue when mark_processing fails."""
        mock_message = Mock()
        mock_message.message_id = "test-msg-fail"

        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.side_effect = [
            [mock_message],
            [],  # Second call returns empty
        ]
        self.handler.queue_manager.mark_processing.return_value = False  # Fails to mark

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.side_effect = [
                None,
                lambda: setattr(self.mock_agent, "connected", False),
            ]

            await self.handler.process_outbound_queue()

            # Should skip message processing
            self.handler.queue_manager.deserialize_message_data.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_outbound_queue_deserialization_exception(self):
        """Test process_outbound_queue when deserialization raises exception (lines 213-224)."""
        mock_message = Mock()
        mock_message.message_id = "test-msg-exception"

        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.side_effect = [[mock_message], []]
        self.handler.queue_manager.mark_processing.return_value = True
        self.handler.queue_manager.deserialize_message_data.side_effect = Exception(
            "Deserialization failed"
        )

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.side_effect = [
                None,
                lambda: setattr(self.mock_agent, "connected", False),
            ]

            await self.handler.process_outbound_queue()

            # Should mark message as failed
            self.handler.queue_manager.mark_failed.assert_called_with(
                "test-msg-exception",
                "Exception processing message: Deserialization failed",
                retry=True,
            )

    @pytest.mark.asyncio
    async def test_process_outbound_queue_general_exception(self):
        """Test process_outbound_queue with general exception (lines 228-229)."""
        self.mock_agent.connected = True
        self.handler.queue_manager.dequeue_messages.side_effect = Exception(
            "General queue error"
        )

        await self.handler.process_outbound_queue()

        # Should handle exception gracefully and set running flag to False
        assert self.handler.queue_processor_running is False

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_on_connection_established_success(self, mock_create_task):
        """Test on_connection_established successful task creation (lines 239-259)."""
        self.handler.queue_processor_running = False
        mock_task = Mock()
        mock_create_task.return_value = mock_task

        await self.handler.on_connection_established()

        mock_create_task.assert_called_once()
        assert self.handler.processing_task == mock_task

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_on_connection_established_already_running(self, mock_create_task):
        """Test on_connection_established when processor already running."""
        self.handler.queue_processor_running = True

        await self.handler.on_connection_established()

        mock_create_task.assert_not_called()

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_on_connection_established_task_creation_fails(
        self, mock_create_task
    ):
        """Test on_connection_established when task creation fails (lines 254-257)."""
        self.handler.queue_processor_running = False
        mock_create_task.side_effect = Exception("Task creation failed")

        await self.handler.on_connection_established()

        mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_on_connection_lost_with_completed_task(self):
        """Test on_connection_lost with completed processing task."""
        mock_task = Mock()
        mock_task.done.return_value = True
        self.handler.processing_task = mock_task

        await self.handler.on_connection_lost()

        mock_task.cancel.assert_not_called()
        assert self.handler.queue_processor_running is False

    @pytest.mark.asyncio
    async def test_on_connection_lost_no_task(self):
        """Test on_connection_lost with no processing task."""
        self.handler.processing_task = None

        await self.handler.on_connection_lost()

        assert self.handler.queue_processor_running is False

    @pytest.mark.asyncio
    async def test_cleanup_old_messages(self):
        """Test cleanup_old_messages method (line 311)."""
        self.handler.queue_manager.cleanup_old_messages.return_value = 42

        result = await self.handler.cleanup_old_messages(14)

        assert result == 42
        self.handler.queue_manager.cleanup_old_messages.assert_called_once_with(14)

    @pytest.mark.asyncio
    async def test_cleanup_old_messages_default_days(self):
        """Test cleanup_old_messages with default parameter."""
        self.handler.queue_manager.cleanup_old_messages.return_value = 10

        result = await self.handler.cleanup_old_messages()

        assert result == 10
        self.handler.queue_manager.cleanup_old_messages.assert_called_once_with(7)

    def test_close_with_running_task(self):
        """Test close method with running processing task (lines 315-321)."""
        mock_task = Mock()
        mock_task.done.return_value = False
        self.handler.processing_task = mock_task

        mock_db_manager = Mock()
        self.handler.queue_manager.db_manager = mock_db_manager

        self.handler.close()

        mock_task.cancel.assert_called_once()
        mock_db_manager.close.assert_called_once()

    def test_close_with_completed_task(self):
        """Test close method with completed processing task."""
        mock_task = Mock()
        mock_task.done.return_value = True
        self.handler.processing_task = mock_task

        mock_db_manager = Mock()
        self.handler.queue_manager.db_manager = mock_db_manager

        self.handler.close()

        mock_task.cancel.assert_not_called()
        mock_db_manager.close.assert_called_once()

    def test_close_no_task(self):
        """Test close method with no processing task."""
        self.handler.processing_task = None

        mock_db_manager = Mock()
        self.handler.queue_manager.db_manager = mock_db_manager

        self.handler.close()

        mock_db_manager.close.assert_called_once()

    def test_close_no_db_manager(self):
        """Test close method when queue_manager has no db_manager attribute."""
        mock_task = Mock()
        mock_task.done.return_value = False
        self.handler.processing_task = mock_task

        # Don't set db_manager attribute

        self.handler.close()

        mock_task.cancel.assert_called_once()

    def test_close_with_exception(self):
        """Test close method when an exception occurs."""
        mock_task = Mock()
        mock_task.done.return_value = False
        mock_task.cancel.side_effect = Exception("Cancel failed")
        self.handler.processing_task = mock_task

        # Should not raise exception
        self.handler.close()
