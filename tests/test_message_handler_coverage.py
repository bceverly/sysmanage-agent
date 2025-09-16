"""
Comprehensive unit tests for src.sysmanage_agent.communication.message_handler module.
Tests the QueuedMessageHandler class for message queuing and processing.
"""

from unittest.mock import patch
import pytest
from src.sysmanage_agent.communication.message_handler import QueuedMessageHandler
from src.database.models import QueueDirection, Priority
from tests.message_handler_test_base import MessageHandlerTestBase


class TestQueuedMessageHandler(
    MessageHandlerTestBase
):  # pylint: disable=too-many-public-methods
    """Test cases for QueuedMessageHandler class."""

    def test_init_with_database_path(self):
        """Test QueuedMessageHandler initialization with database path."""
        with patch(
            "src.sysmanage_agent.communication.message_handler.MessageQueueManager"
        ) as mock_qm:
            handler = QueuedMessageHandler(self.mock_agent, "/custom/path.db")
            mock_qm.assert_called_once_with("/custom/path.db")
            assert handler.agent == self.mock_agent

    def test_init_without_database_path(self):
        """Test QueuedMessageHandler initialization without database path."""
        with patch(
            "src.sysmanage_agent.communication.message_handler.MessageQueueManager"
        ) as mock_qm:
            handler = QueuedMessageHandler(self.mock_agent)
            mock_qm.assert_called_once_with(None)
            assert handler.agent == self.mock_agent

    @pytest.mark.asyncio
    async def test_queue_outbound_message_heartbeat(self):
        """Test queuing outbound heartbeat message."""
        message = {"message_type": "heartbeat", "data": "test"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-123"

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-123"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="heartbeat",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.HIGH,
            correlation_id=None,
        )

    @pytest.mark.asyncio
    async def test_queue_outbound_message_command_result(self):
        """Test queuing outbound command result message."""
        message = {"message_type": "command_result", "result": "success"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-456"

        result = await self.handler.queue_outbound_message(
            message, correlation_id="corr-123"
        )

        assert result == "msg-456"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="command_result",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.HIGH,
            correlation_id="corr-123",
        )

    @pytest.mark.asyncio
    async def test_queue_outbound_message_script_execution_result(self):
        """Test queuing outbound script execution result message."""
        message = {"message_type": "script_execution_result", "output": "done"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-789"

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-789"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="script_execution_result",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.HIGH,
            correlation_id=None,
        )

    @pytest.mark.asyncio
    async def test_queue_outbound_message_system_info(self):
        """Test queuing outbound system info message."""
        message = {"message_type": "system_info", "cpu": 50}
        self.handler.queue_manager.enqueue_message.return_value = "msg-101"

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-101"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="system_info",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.NORMAL,
            correlation_id=None,
        )

    @pytest.mark.asyncio
    async def test_queue_outbound_message_error(self):
        """Test queuing outbound error message."""
        message = {"message_type": "error", "error": "connection failed"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-urgent"

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-urgent"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="error",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.URGENT,
            correlation_id=None,
        )

    @pytest.mark.asyncio
    async def test_queue_outbound_message_unknown_type(self):
        """Test queuing outbound message with unknown type."""
        message = {"message_type": "custom_type", "data": "test"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-unknown"

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-unknown"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="custom_type",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.NORMAL,  # Default priority
            correlation_id=None,
        )

    @pytest.mark.asyncio
    async def test_queue_outbound_message_no_message_type(self):
        """Test queuing outbound message without message_type."""
        message = {"data": "test"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-no-type"

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-no-type"
        self.handler.queue_manager.enqueue_message.assert_called_once_with(
            message_type="unknown",
            message_data=message,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.NORMAL,
            correlation_id=None,
        )

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_queue_outbound_message_no_trigger_when_disconnected(
        self, mock_create_task
    ):
        """Test that queuing message doesn't trigger processing when agent is disconnected."""
        message = {"message_type": "test", "data": "value"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-no-trigger"
        self.mock_agent.connected = False

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-no-trigger"
        mock_create_task.assert_not_called()

    @patch("asyncio.create_task")
    @pytest.mark.asyncio
    async def test_queue_outbound_message_no_trigger_when_processor_running(
        self, mock_create_task
    ):
        """Test that queuing message doesn't trigger processing when processor is already running."""
        message = {"message_type": "test", "data": "value"}
        self.handler.queue_manager.enqueue_message.return_value = "msg-running"
        self.mock_agent.connected = True
        self.handler.queue_processor_running = True

        result = await self.handler.queue_outbound_message(message)

        assert result == "msg-running"
        mock_create_task.assert_not_called()

    def test_get_queue_statistics(self):
        """Test getting queue statistics."""
        mock_stats = {"pending": 5, "in_progress": 2, "completed": 100, "failed": 3}
        # Mock the get_queue_stats method to return appropriate stats for each direction
        self.handler.queue_manager.get_queue_stats.side_effect = [
            mock_stats,  # For OUTBOUND
            mock_stats,  # For INBOUND
        ]

        result = self.handler.get_queue_statistics()

        expected = {
            "outbound": mock_stats,
            "inbound": mock_stats,
            "total": {
                "pending": 10,  # 5 + 5
                "in_progress": 4,  # 2 + 2
                "completed": 200,  # 100 + 100
                "failed": 6,  # 3 + 3
            },
        }
        assert result == expected
        assert self.handler.queue_manager.get_queue_stats.call_count == 2
