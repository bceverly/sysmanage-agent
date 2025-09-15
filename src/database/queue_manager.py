"""
Message Queue Manager for SysManage Agent.
Provides persistent message queuing with retry logic and priority handling.
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Union
from contextlib import contextmanager

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc

from .base import get_database_manager
from .models import MessageQueue, QueueMetrics, QueueStatus, QueueDirection, Priority
from src.i18n import _
from src.sysmanage_agent.utils.verbosity_logger import get_logger

logger = get_logger(__name__)


class MessageQueueManager:
    """
    Manages persistent message queues for agent communication.

    Handles both inbound (received from server) and outbound (to send to server)
    message queues with retry logic, priority handling, and metrics collection.
    """

    def __init__(self, database_path: str = None):
        """
        Initialize the queue manager.

        Args:
            database_path: Optional path to database file
        """
        self.db_manager = get_database_manager(database_path)
        logger.info(_("Message queue manager initialized"))

    @contextmanager
    def get_session(self):
        """Get a database session with automatic cleanup."""
        session = self.db_manager.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def enqueue_message(
        self,
        message_type: str,
        message_data: Dict[str, Any],
        direction: Union[str, QueueDirection],
        priority: Union[str, Priority] = Priority.NORMAL,
        message_id: str = None,
        scheduled_at: datetime = None,
        max_retries: int = 3,
        correlation_id: str = None,
        reply_to: str = None,
    ) -> str:
        """
        Add a message to the queue.

        Args:
            message_type: Type of message (e.g., 'heartbeat', 'command_result')
            message_data: Message payload as dictionary
            direction: Message direction (inbound/outbound)
            priority: Message priority (low/normal/high/urgent)
            message_id: Optional custom message ID (UUID will be generated if not provided)
            scheduled_at: Optional time to process message (for delays)
            max_retries: Maximum retry attempts
            correlation_id: Optional correlation ID for request/response tracking
            reply_to: Optional message ID this is replying to

        Returns:
            str: Message ID of queued message
        """
        if message_id is None:
            message_id = str(uuid.uuid4())

        # Ensure direction and priority are strings
        if isinstance(direction, QueueDirection):
            direction = direction.value
        if isinstance(priority, Priority):
            priority = priority.value

        # Serialize message data
        serialized_data = json.dumps(message_data, default=str)

        with self.get_session() as session:
            queue_item = MessageQueue(
                message_id=message_id,
                direction=direction,
                message_type=message_type,
                message_data=serialized_data,
                status=QueueStatus.PENDING.value,
                priority=priority,
                max_retries=max_retries,
                scheduled_at=scheduled_at,
                correlation_id=correlation_id,
                reply_to=reply_to,
                created_at=datetime.now(timezone.utc),
            )

            session.add(queue_item)
            session.flush()  # Get the ID

            logger.debug(
                _("Enqueued message: id=%s, type=%s, direction=%s, priority=%s"),
                message_id,
                message_type,
                direction,
                priority,
            )

        return message_id

    def dequeue_messages(
        self,
        direction: Union[str, QueueDirection],
        limit: int = 10,
        priority_order: bool = True,
    ) -> List[MessageQueue]:
        """
        Get pending messages ready for processing.

        Args:
            direction: Message direction to dequeue
            limit: Maximum number of messages to return
            priority_order: Whether to order by priority (urgent first)

        Returns:
            List[MessageQueue]: Ready messages ordered by priority/creation time
        """
        if isinstance(direction, QueueDirection):
            direction = direction.value

        now = datetime.now(timezone.utc)

        with self.get_session() as session:
            query = session.query(MessageQueue).filter(
                and_(
                    MessageQueue.direction == direction,
                    MessageQueue.status == QueueStatus.PENDING.value,
                    or_(
                        MessageQueue.scheduled_at.is_(None),
                        MessageQueue.scheduled_at <= now,
                    ),
                )
            )

            if priority_order:
                # Order by priority (urgent=4, high=3, normal=2, low=1), then by creation time
                priority_map = {
                    Priority.URGENT.value: 4,
                    Priority.HIGH.value: 3,
                    Priority.NORMAL.value: 2,
                    Priority.LOW.value: 1,
                }

                # SQLAlchemy doesn't have a direct way to order by custom priority,
                # so we'll order by creation time and handle priority in Python
                # In a production system, you might want to add a numeric priority column
                query = query.order_by(asc(MessageQueue.created_at))
            else:
                query = query.order_by(asc(MessageQueue.created_at))

            messages = query.limit(limit).all()

            # Sort by priority if requested (since SQLite doesn't support CASE WHEN in ORDER BY easily)
            if priority_order and messages:
                priority_map = {
                    Priority.URGENT.value: 4,
                    Priority.HIGH.value: 3,
                    Priority.NORMAL.value: 2,
                    Priority.LOW.value: 1,
                }
                messages.sort(
                    key=lambda m: (
                        priority_map.get(m.priority, 0),  # Priority first
                        m.created_at,  # Then creation time
                    ),
                    reverse=True,  # Higher priority first, older messages first
                )

            # Eagerly load all attributes to avoid DetachedInstanceError
            for message in messages:
                session.refresh(message)
                session.expunge(message)

            return messages

    def mark_processing(self, message_id: str) -> bool:
        """
        Mark a message as currently being processed.

        Args:
            message_id: ID of message to mark as in progress

        Returns:
            bool: True if successfully marked, False if message not found or already processed
        """
        with self.get_session() as session:
            message = (
                session.query(MessageQueue).filter_by(message_id=message_id).first()
            )

            if not message or not message.is_pending:
                return False

            message.status = QueueStatus.IN_PROGRESS.value
            message.started_at = datetime.now(timezone.utc)

            logger.debug(_("Marked message as processing: %s"), message_id)
            return True

    def mark_completed(self, message_id: str) -> bool:
        """
        Mark a message as successfully processed.

        Args:
            message_id: ID of message to mark as completed

        Returns:
            bool: True if successfully marked, False if message not found
        """
        with self.get_session() as session:
            message = (
                session.query(MessageQueue).filter_by(message_id=message_id).first()
            )

            if not message:
                return False

            message.status = QueueStatus.COMPLETED.value
            message.completed_at = datetime.now(timezone.utc)

            logger.debug(_("Marked message as completed: %s"), message_id)
            return True

    def mark_failed(
        self, message_id: str, error_message: str = None, retry: bool = True
    ) -> bool:
        """
        Mark a message as failed and optionally retry.

        Args:
            message_id: ID of message to mark as failed
            error_message: Optional error description
            retry: Whether to retry the message if retries are available

        Returns:
            bool: True if successfully marked, False if message not found
        """
        with self.get_session() as session:
            message = (
                session.query(MessageQueue).filter_by(message_id=message_id).first()
            )

            if not message:
                return False

            message.retry_count += 1
            message.last_error_at = datetime.now(timezone.utc)

            if error_message:
                message.error_message = error_message

            # Check if we should retry or mark as permanently failed
            if retry and message.retry_count < message.max_retries:
                # Reset to pending for retry with exponential backoff
                message.status = QueueStatus.PENDING.value
                # Schedule retry with exponential backoff
                backoff_seconds = min(
                    60 * (2 ** (message.retry_count - 1)), 3600
                )  # Max 1 hour
                message.scheduled_at = datetime.now(timezone.utc) + timedelta(
                    seconds=backoff_seconds
                )
                message.started_at = None  # Reset processing timestamp

                logger.info(
                    _(
                        "Message %s failed (attempt %d/%d), scheduled for retry in %d seconds"
                    ),
                    message_id,
                    message.retry_count,
                    message.max_retries,
                    backoff_seconds,
                )
            else:
                # Max retries reached or retry disabled
                message.status = QueueStatus.FAILED.value
                message.completed_at = datetime.now(timezone.utc)

                logger.warning(
                    _("Message %s permanently failed after %d attempts: %s"),
                    message_id,
                    message.retry_count,
                    error_message,
                )

            return True

    def get_message(self, message_id: str) -> Optional[MessageQueue]:
        """
        Get a specific message by ID.

        Args:
            message_id: Message ID to retrieve

        Returns:
            Optional[MessageQueue]: Message if found, None otherwise
        """
        with self.get_session() as session:
            message = (
                session.query(MessageQueue).filter_by(message_id=message_id).first()
            )
            if message:
                # Eagerly load all attributes to avoid DetachedInstanceError
                session.refresh(message)
                session.expunge(message)
            return message

    def get_queue_stats(
        self, direction: Union[str, QueueDirection] = None
    ) -> Dict[str, int]:
        """
        Get queue statistics.

        Args:
            direction: Optional direction to filter by

        Returns:
            Dict[str, int]: Statistics including pending, processing, completed, failed counts
        """
        if isinstance(direction, QueueDirection):
            direction = direction.value

        with self.get_session() as session:
            query = session.query(MessageQueue)

            if direction:
                query = query.filter(MessageQueue.direction == direction)

            all_messages = query.all()

            stats = {
                "total": len(all_messages),
                "pending": sum(1 for m in all_messages if m.is_pending),
                "in_progress": sum(1 for m in all_messages if m.is_in_progress),
                "completed": sum(1 for m in all_messages if m.is_completed),
                "failed": sum(1 for m in all_messages if m.is_failed),
            }

            if direction:
                stats["direction"] = direction

            return stats

    def cleanup_old_messages(
        self, older_than_days: int = 7, keep_failed: bool = True
    ) -> int:
        """
        Clean up old completed messages to prevent database growth.

        Args:
            older_than_days: Remove messages older than this many days
            keep_failed: Whether to keep failed messages for debugging

        Returns:
            int: Number of messages deleted
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=older_than_days)

        with self.get_session() as session:
            query = session.query(MessageQueue).filter(
                and_(
                    MessageQueue.completed_at < cutoff_date,
                    MessageQueue.status == QueueStatus.COMPLETED.value,
                )
            )

            if not keep_failed:
                # Also clean up old failed messages
                query = query.union(
                    session.query(MessageQueue).filter(
                        and_(
                            MessageQueue.completed_at < cutoff_date,
                            MessageQueue.status == QueueStatus.FAILED.value,
                        )
                    )
                )

            deleted_count = query.count()
            query.delete(synchronize_session=False)

            logger.info(_("Cleaned up %d old messages"), deleted_count)
            return deleted_count

    def deserialize_message_data(self, message: MessageQueue) -> Dict[str, Any]:
        """
        Deserialize message data from JSON.

        Args:
            message: MessageQueue instance

        Returns:
            Dict[str, Any]: Deserialized message data
        """
        try:
            return json.loads(message.message_data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(
                _("Failed to deserialize message %s: %s"), message.message_id, e
            )
            return {}
