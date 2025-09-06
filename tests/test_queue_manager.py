"""
Unit tests for the Message Queue Manager.
Tests message queuing, dequeuing, retry logic, and state management.
"""

import os
import tempfile
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from database.models import MessageQueue, QueueStatus, QueueDirection, Priority
from database.queue_manager import MessageQueueManager


class TestMessageQueueManager:
    """Test suite for MessageQueueManager functionality."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file for testing."""
        temp_fd, temp_path = tempfile.mkstemp(suffix=".db")
        os.close(temp_fd)  # Close file descriptor, we just need the path
        yield temp_path
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def queue_manager(self, temp_db_path):
        """Create a MessageQueueManager with a temporary database."""
        manager = MessageQueueManager(temp_db_path)

        # Create tables in the temporary database
        manager.db_manager.create_tables()

        yield manager

        # Cleanup - clear all data for test isolation
        with manager.get_session() as session:
            session.query(MessageQueue).delete()
            session.commit()
        manager.db_manager.close()

    def test_enqueue_message(self, queue_manager):
        """Test basic message enqueuing."""
        message_data = {"test": "data", "timestamp": "2024-01-01T12:00:00Z"}

        message_id = queue_manager.enqueue_message(
            message_type="test_message",
            message_data=message_data,
            direction=QueueDirection.OUTBOUND,
            priority=Priority.NORMAL,
        )

        # Verify message was created
        assert message_id is not None
        assert isinstance(message_id, str)

        # Verify message is in database
        message = queue_manager.get_message(message_id)
        assert message is not None
        assert message.message_type == "test_message"
        assert message.direction == QueueDirection.OUTBOUND.value
        assert message.priority == Priority.NORMAL.value
        assert message.status == QueueStatus.PENDING.value
        assert message.retry_count == 0

        # Verify message data serialization
        deserialized_data = queue_manager.deserialize_message_data(message)
        assert deserialized_data == message_data

    def test_dequeue_messages(self, queue_manager):
        """Test message dequeuing with priority ordering."""
        # Create messages with different priorities
        low_msg_id = queue_manager.enqueue_message(
            "low_priority", {"data": "low"}, QueueDirection.OUTBOUND, Priority.LOW
        )
        urgent_msg_id = queue_manager.enqueue_message(
            "urgent_priority",
            {"data": "urgent"},
            QueueDirection.OUTBOUND,
            Priority.URGENT,
        )
        normal_msg_id = queue_manager.enqueue_message(
            "normal_priority",
            {"data": "normal"},
            QueueDirection.OUTBOUND,
            Priority.NORMAL,
        )

        # Dequeue messages - should be ordered by priority
        messages = queue_manager.dequeue_messages(
            QueueDirection.OUTBOUND, limit=10, priority_order=True
        )

        assert len(messages) == 3

        # Messages should be ordered: urgent, normal, low
        assert messages[0].message_id == urgent_msg_id
        assert messages[0].priority == Priority.URGENT.value
        assert messages[1].message_id == normal_msg_id
        assert messages[1].priority == Priority.NORMAL.value
        assert messages[2].message_id == low_msg_id
        assert messages[2].priority == Priority.LOW.value

    def test_message_processing_lifecycle(self, queue_manager):
        """Test complete message processing lifecycle."""
        message_id = queue_manager.enqueue_message(
            "lifecycle_test", {"data": "test"}, QueueDirection.OUTBOUND
        )

        # Initially pending
        message = queue_manager.get_message(message_id)
        assert message.is_pending
        assert not message.is_in_progress
        assert not message.is_completed

        # Mark as processing
        success = queue_manager.mark_processing(message_id)
        assert success

        message = queue_manager.get_message(message_id)
        assert not message.is_pending
        assert message.is_in_progress
        assert not message.is_completed
        assert message.started_at is not None

        # Mark as completed
        success = queue_manager.mark_completed(message_id)
        assert success

        message = queue_manager.get_message(message_id)
        assert not message.is_pending
        assert not message.is_in_progress
        assert message.is_completed
        assert message.completed_at is not None

    def test_message_retry_logic(self, queue_manager):
        """Test message retry logic with exponential backoff."""
        message_id = queue_manager.enqueue_message(
            "retry_test", {"data": "test"}, QueueDirection.OUTBOUND, max_retries=3
        )

        # Mark as processing, then fail
        queue_manager.mark_processing(message_id)
        success = queue_manager.mark_failed(message_id, "Test error", retry=True)
        assert success

        message = queue_manager.get_message(message_id)
        assert message.is_pending  # Should be back to pending for retry
        assert message.retry_count == 1
        assert message.error_message == "Test error"
        assert message.scheduled_at is not None  # Should be scheduled for retry
        assert message.started_at is None  # Should be reset

        # Fail again until max retries reached
        queue_manager.mark_processing(message_id)
        queue_manager.mark_failed(message_id, "Test error 2", retry=True)
        queue_manager.mark_processing(message_id)
        queue_manager.mark_failed(message_id, "Test error 3", retry=True)

        # Fourth failure should mark as permanently failed
        queue_manager.mark_processing(message_id)
        queue_manager.mark_failed(message_id, "Final error", retry=True)

        message = queue_manager.get_message(message_id)
        assert message.is_failed
        assert message.retry_count == 4  # All retries exhausted
        assert message.completed_at is not None

    def test_scheduled_messages(self, queue_manager):
        """Test scheduled message processing."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)

        message_id = queue_manager.enqueue_message(
            "scheduled_test",
            {"data": "scheduled"},
            QueueDirection.OUTBOUND,
            scheduled_at=future_time,
        )

        # Should not be returned when dequeuing (not ready yet)
        messages = queue_manager.dequeue_messages(QueueDirection.OUTBOUND)
        assert len(messages) == 0

        message = queue_manager.get_message(message_id)
        assert not message.is_ready_for_processing

        # Test with past scheduled time
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        past_msg_id = queue_manager.enqueue_message(
            "past_scheduled",
            {"data": "ready"},
            QueueDirection.OUTBOUND,
            scheduled_at=past_time,
        )

        messages = queue_manager.dequeue_messages(QueueDirection.OUTBOUND)
        assert len(messages) == 1
        assert messages[0].message_id == past_msg_id

    def test_queue_statistics(self, queue_manager):
        """Test queue statistics functionality."""
        # Create messages with different states
        queue_manager.enqueue_message("pending1", {}, QueueDirection.OUTBOUND)
        queue_manager.enqueue_message("pending2", {}, QueueDirection.OUTBOUND)
        queue_manager.enqueue_message("pending3", {}, QueueDirection.INBOUND)

        processing_id = queue_manager.enqueue_message(
            "processing", {}, QueueDirection.OUTBOUND
        )
        queue_manager.mark_processing(processing_id)

        completed_id = queue_manager.enqueue_message(
            "completed", {}, QueueDirection.OUTBOUND
        )
        queue_manager.mark_processing(completed_id)
        queue_manager.mark_completed(completed_id)

        failed_id = queue_manager.enqueue_message(
            "failed", {}, QueueDirection.OUTBOUND, max_retries=0
        )
        queue_manager.mark_processing(failed_id)
        queue_manager.mark_failed(failed_id, "Test failure", retry=False)

        # Test overall stats
        stats = queue_manager.get_queue_stats()
        assert stats["total"] == 6
        assert stats["pending"] == 3  # 2 outbound + 1 inbound
        assert stats["in_progress"] == 1
        assert stats["completed"] == 1
        assert stats["failed"] == 1

        # Test direction-specific stats
        outbound_stats = queue_manager.get_queue_stats(QueueDirection.OUTBOUND)
        assert outbound_stats["total"] == 5
        assert outbound_stats["pending"] == 2

        inbound_stats = queue_manager.get_queue_stats(QueueDirection.INBOUND)
        assert inbound_stats["total"] == 1
        assert inbound_stats["pending"] == 1

    def test_message_cleanup(self, queue_manager):
        """Test old message cleanup functionality."""
        # Create old completed message
        old_msg_id = queue_manager.enqueue_message(
            "old_message", {}, QueueDirection.OUTBOUND
        )
        queue_manager.mark_processing(old_msg_id)
        queue_manager.mark_completed(old_msg_id)

        # Manually set completion date to be old
        with queue_manager.get_session() as session:
            message = (
                session.query(MessageQueue).filter_by(message_id=old_msg_id).first()
            )
            message.completed_at = datetime.now(timezone.utc) - timedelta(days=10)
            session.commit()

        # Create recent message
        recent_msg_id = queue_manager.enqueue_message(
            "recent_message", {}, QueueDirection.OUTBOUND
        )
        queue_manager.mark_processing(recent_msg_id)
        queue_manager.mark_completed(recent_msg_id)

        # Clean up messages older than 7 days
        deleted_count = queue_manager.cleanup_old_messages(older_than_days=7)
        assert deleted_count == 1

        # Verify old message is gone, recent remains
        assert queue_manager.get_message(old_msg_id) is None
        assert queue_manager.get_message(recent_msg_id) is not None

    def test_correlation_and_reply_to(self, queue_manager):
        """Test message correlation and reply-to functionality."""
        correlation_id = str(uuid.uuid4())

        # Create original message
        original_id = queue_manager.enqueue_message(
            "command",
            {"action": "get_info"},
            QueueDirection.OUTBOUND,
            correlation_id=correlation_id,
        )

        # Create reply message
        reply_id = queue_manager.enqueue_message(
            "command_result",
            {"result": "success"},
            QueueDirection.INBOUND,
            correlation_id=correlation_id,
            reply_to=original_id,
        )

        original = queue_manager.get_message(original_id)
        reply = queue_manager.get_message(reply_id)

        assert original.correlation_id == correlation_id
        assert reply.correlation_id == correlation_id
        assert reply.reply_to == original_id

    def test_invalid_operations(self, queue_manager):
        """Test invalid operations and error handling."""
        # Test marking non-existent message as processing
        success = queue_manager.mark_processing("non-existent-id")
        assert not success

        # Test marking non-existent message as completed
        success = queue_manager.mark_completed("non-existent-id")
        assert not success

        # Test marking non-existent message as failed
        success = queue_manager.mark_failed("non-existent-id")
        assert not success

        # Test getting non-existent message
        message = queue_manager.get_message("non-existent-id")
        assert message is None

    def test_json_serialization_edge_cases(self, queue_manager):
        """Test JSON serialization with edge cases."""
        # Test with complex data structure
        complex_data = {
            "nested": {"key": "value"},
            "array": [1, 2, 3],
            "datetime": datetime.now(timezone.utc).isoformat(),
            "null_value": None,
            "boolean": True,
        }

        message_id = queue_manager.enqueue_message(
            "complex_data", complex_data, QueueDirection.OUTBOUND
        )

        message = queue_manager.get_message(message_id)
        deserialized = queue_manager.deserialize_message_data(message)

        assert deserialized == complex_data

        # Test with invalid JSON data (simulate corruption)
        with queue_manager.get_session() as session:
            message = (
                session.query(MessageQueue).filter_by(message_id=message_id).first()
            )
            message.message_data = "invalid json {"
            session.commit()

        # Should return empty dict for invalid JSON
        corrupted_message = queue_manager.get_message(message_id)
        deserialized = queue_manager.deserialize_message_data(corrupted_message)
        assert deserialized == {}


if __name__ == "__main__":
    pytest.main([__file__])
