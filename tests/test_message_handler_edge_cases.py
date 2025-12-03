"""
Test edge cases and error handling for message_handler.py.
Focused on improving test coverage by targeting uncovered paths.
"""

import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.database.models import Priority, QueueDirection
from src.sysmanage_agent.communication.message_handler import MessageHandler


class TestMessageHandlerEdgeCases:  # pylint: disable=too-many-public-methods
    """Test edge cases for MessageHandler class."""

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.mock_agent = Mock()
        self.mock_agent.connected = False
        self.mock_agent.registration_manager = Mock()
        self.mock_agent.registration_manager.get_stored_host_id_sync = Mock(
            return_value="test-host-id"
        )
        self.mock_agent.registration_manager.get_stored_host_token_sync = Mock(
            return_value="test-host-token"
        )
        self.handler = MessageHandler(self.mock_agent)

    def test_init_with_agent_instance(self):
        """Test initialization with agent instance."""
        handler = MessageHandler(self.mock_agent)
        assert handler is not None
        assert handler.agent == self.mock_agent

    @pytest.mark.asyncio
    async def test_queue_outbound_message_priority_mapping(self):
        """Test automatic priority mapping based on message type."""
        test_cases = [
            ("heartbeat", Priority.HIGH),
            ("command_result", Priority.HIGH),
            ("script_execution_result", Priority.HIGH),
            ("system_info", Priority.NORMAL),
            ("error", Priority.URGENT),
            ("unknown_type", Priority.NORMAL),  # Default case
        ]

        for message_type, expected_priority in test_cases:
            message = {"message_type": message_type}

            with patch.object(
                self.handler.queue_manager, "enqueue_message", return_value="msg_id"
            ) as mock_enqueue:
                await self.handler.queue_outbound_message(message)

                mock_enqueue.assert_called_once()
                call_args = mock_enqueue.call_args[1]
                assert call_args["priority"] == expected_priority

    @pytest.mark.asyncio
    async def test_queue_outbound_message_with_explicit_priority(self):
        """Test queueing message with explicitly set priority."""
        message = {"message_type": "test"}

        with patch.object(
            self.handler.queue_manager, "enqueue_message", return_value="msg_id"
        ) as mock_enqueue:
            await self.handler.queue_outbound_message(message, priority=Priority.URGENT)

            call_args = mock_enqueue.call_args[1]
            assert call_args["priority"] == Priority.URGENT

    @pytest.mark.asyncio
    async def test_queue_outbound_message_triggers_processing_when_connected(self):
        """Test that queueing triggers processing when agent is connected."""
        self.mock_agent.connected = True
        self.handler.queue_processor_running = False

        message = {"message_type": "test"}

        with patch.object(
            self.handler.queue_manager, "enqueue_message", return_value="msg_id"
        ):
            with patch("asyncio.create_task") as mock_create_task:
                await self.handler.queue_outbound_message(message)

                mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_queue_outbound_message_task_creation_exception(self):
        """Test exception handling during task creation."""
        self.mock_agent.connected = True
        self.handler.queue_processor_running = False

        message = {"message_type": "test"}

        with patch.object(
            self.handler.queue_manager, "enqueue_message", return_value="msg_id"
        ):
            with patch(
                "asyncio.create_task", side_effect=Exception("Task creation failed")
            ):
                # Should not raise exception
                await self.handler.queue_outbound_message(message)

    @pytest.mark.asyncio
    async def test_queue_inbound_message(self):
        """Test inbound message queueing."""
        message = {
            "message_type": "command",
            "correlation_id": "corr_123",
            "reply_to": "reply_456",
        }

        with patch.object(
            self.handler.queue_manager, "enqueue_message", return_value="msg_id"
        ) as mock_enqueue:
            result = await self.handler.queue_inbound_message(message)

            assert result == "msg_id"
            mock_enqueue.assert_called_once_with(
                message_type="command",
                message_data=message,
                direction=QueueDirection.INBOUND,
                priority=Priority.NORMAL,
                correlation_id="corr_123",
                reply_to="reply_456",
            )

    @pytest.mark.asyncio
    async def test_send_message_direct_not_connected(self):
        """Test direct message sending when not connected."""
        self.mock_agent.connected = False
        self.mock_agent.websocket = None

        message = {"message_type": "test"}
        result = await self.handler.send_message_direct(message)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_message_direct_websocket_exception(self):
        """Test direct message sending with WebSocket exception."""
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()
        self.mock_agent.websocket.send.side_effect = Exception("WebSocket error")

        message = {"message_type": "test"}
        result = await self.handler.send_message_direct(message)

        assert result is False
        assert self.mock_agent.connected is False
        assert self.mock_agent.websocket is None

    @pytest.mark.asyncio
    async def test_process_outbound_queue_already_running(self):
        """Test process outbound queue when already running."""
        self.handler.queue_processor_running = True

        # Should return early without processing
        await self.handler.process_outbound_queue()

    @pytest.mark.asyncio
    async def test_process_outbound_queue_mark_processing_fails(self):
        """Test process outbound queue when mark_processing fails."""
        self.mock_agent.connected = True

        mock_messages = [Mock(message_id="msg_1")]

        with patch.object(
            self.handler.queue_manager, "dequeue_messages", return_value=mock_messages
        ):
            with patch.object(
                self.handler.queue_manager, "mark_processing", return_value=False
            ):  # Fails to mark
                with patch("asyncio.sleep") as mock_sleep:
                    # Stop after first iteration
                    def side_effect(delay):
                        _ = delay
                        self.mock_agent.connected = False

                    mock_sleep.side_effect = side_effect

                    await self.handler.process_outbound_queue()

                    # Should continue to next message

    @pytest.mark.asyncio
    async def test_process_outbound_queue_send_failure(self):
        """Test process outbound queue when message send fails."""
        self.mock_agent.connected = True

        mock_message = Mock(message_id="msg_1")
        mock_messages = [mock_message]

        with patch.object(
            self.handler.queue_manager, "dequeue_messages", return_value=mock_messages
        ):
            with patch.object(
                self.handler.queue_manager, "mark_processing", return_value=True
            ):
                with patch.object(
                    self.handler.queue_manager,
                    "deserialize_message_data",
                    return_value={"test": "data"},
                ):
                    with patch.object(
                        self.handler, "send_message_direct", return_value=False
                    ):
                        with patch.object(
                            self.handler.queue_manager, "mark_failed"
                        ) as mock_failed:
                            # Stop after first iteration
                            def side_effect(*args, **kwargs):
                                _ = args
                                _ = kwargs
                                self.mock_agent.connected = False

                            mock_failed.side_effect = side_effect

                            await self.handler.process_outbound_queue()

                            mock_failed.assert_called_once_with(
                                "msg_1", "Failed to send over WebSocket", retry=True
                            )

    @pytest.mark.asyncio
    async def test_process_outbound_queue_message_processing_exception(self):
        """Test process outbound queue with exception during message processing."""
        self.mock_agent.connected = True

        mock_message = Mock(message_id="msg_1")
        mock_messages = [mock_message]

        with patch.object(
            self.handler.queue_manager, "dequeue_messages", return_value=mock_messages
        ):
            with patch.object(
                self.handler.queue_manager, "mark_processing", return_value=True
            ):
                with patch.object(
                    self.handler.queue_manager,
                    "deserialize_message_data",
                    side_effect=Exception("Deserialization error"),
                ):
                    with patch.object(
                        self.handler.queue_manager, "mark_failed"
                    ) as mock_failed:
                        with patch("asyncio.sleep") as mock_sleep:
                            # Stop after first iteration
                            def side_effect(delay):
                                _ = delay
                                self.mock_agent.connected = False

                            mock_sleep.side_effect = side_effect

                            await self.handler.process_outbound_queue()

                            mock_failed.assert_called_once()
                            call_args = mock_failed.call_args[0]
                            assert "Deserialization error" in call_args[1]

    @pytest.mark.asyncio
    async def test_process_outbound_queue_general_exception(self):
        """Test process outbound queue with general exception."""
        self.mock_agent.connected = True

        with patch.object(
            self.handler.queue_manager,
            "dequeue_messages",
            side_effect=Exception("Queue error"),
        ):
            # Should handle exception and exit gracefully
            await self.handler.process_outbound_queue()

            assert not self.handler.queue_processor_running

    @pytest.mark.asyncio
    async def test_on_connection_established_already_running(self):
        """Test connection established when both queue processors already running."""
        self.handler.queue_processor_running = True
        self.handler.inbound_queue_processor_running = True

        with patch("asyncio.create_task") as mock_create_task:
            await self.handler.on_connection_established()

            mock_create_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_connection_established_task_creation_exception(self):
        """Test connection established with task creation exception."""
        self.handler.queue_processor_running = False

        with patch(
            "asyncio.create_task", side_effect=Exception("Task creation failed")
        ):
            # Should handle exception gracefully
            await self.handler.on_connection_established()

    @pytest.mark.asyncio
    async def test_on_connection_lost_task_already_done(self):
        """Test connection lost when processing task is already done."""
        # Fix: Use Mock instead of AsyncMock for task object
        self.handler.processing_task = Mock()
        self.handler.processing_task.done.return_value = True

        await self.handler.on_connection_lost()

        self.handler.processing_task.cancel.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_connection_lost_no_task(self):
        """Test connection lost when no processing task exists."""
        self.handler.processing_task = None

        # Should not raise exception
        await self.handler.on_connection_lost()

        assert not self.handler.queue_processor_running

    def test_get_queue_statistics(self):
        """Test queue statistics retrieval."""
        outbound_stats = {"pending": 5, "in_progress": 2, "completed": 10, "failed": 1}
        inbound_stats = {"pending": 3, "in_progress": 1, "completed": 8, "failed": 0}

        with patch.object(self.handler.queue_manager, "get_queue_stats") as mock_stats:
            mock_stats.side_effect = [outbound_stats, inbound_stats]

            result = self.handler.get_queue_statistics()

            assert result["outbound"] == outbound_stats
            assert result["inbound"] == inbound_stats
            assert result["total"]["pending"] == 8
            assert result["total"]["in_progress"] == 3
            assert result["total"]["completed"] == 18
            assert result["total"]["failed"] == 1

    @pytest.mark.asyncio
    async def test_cleanup_old_messages(self):
        """Test cleanup of old messages."""
        with patch.object(
            self.handler.queue_manager, "cleanup_old_messages", return_value=15
        ) as mock_cleanup:
            result = await self.handler.cleanup_old_messages(7)

            assert result == 15
            mock_cleanup.assert_called_once_with(7)

    def test_close_with_running_task(self):
        """Test close method with running task."""
        self.handler.processing_task = Mock()
        self.handler.processing_task.done.return_value = False
        self.handler.queue_manager.db_manager = Mock()

        self.handler.close()

        self.handler.processing_task.cancel.assert_called_once()
        self.handler.queue_manager.db_manager.close.assert_called_once()

    def test_close_with_exception(self):
        """Test close method with exception."""
        self.handler.processing_task = Mock()
        self.handler.processing_task.cancel.side_effect = Exception("Cancel failed")

        # Should not raise exception
        self.handler.close()

    def test_close_no_db_manager(self):
        """Test close method when db_manager doesn't exist."""
        self.handler.processing_task = None

        # Should not raise exception
        self.handler.close()

    @pytest.mark.asyncio
    async def test_send_message_direct_success(self):
        """Test successful direct message sending."""
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()

        message = {"message_type": "test", "data": "test_data"}
        result = await self.handler.send_message_direct(message)

        assert result is True
        self.mock_agent.websocket.send.assert_called_once_with(json.dumps(message))
