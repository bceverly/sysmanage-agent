# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Message Queue Manager for SysManage Agent.
Provides persistent message queuing with retry logic and priority handling.
"""

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import and_, asc, func, or_, text

from src.i18n import _
from src.sysmanage_agent.utils.verbosity_logger import get_logger

from .base import get_database_manager
from .models import (
    InstallationRequestTracking,
    MessageQueue,
    Priority,
    QueueDirection,
    QueueStatus,
    ScriptExecution,
)

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
        logger.info("Message queue manager initialized")

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

    def enqueue_message(  # pylint: disable=too-many-arguments
        self,
        message_type: str,
        message_data: Dict[str, Any],
        direction: Union[str, QueueDirection],
        *,
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
                "Enqueued message: id=%s, type=%s, direction=%s, priority=%s",
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

            logger.debug("Marked message as processing: %s", message_id)
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

            # DELETE, don't mark.  A delivered message has no reader: the only
            # references to QueueStatus.COMPLETED anywhere in the agent were
            # this write, the retention delete, and an is_completed property —
            # nothing ever loaded one back.  Retaining them cost 10.75 GB in
            # eight days on a dev host while the entire rest of the database was
            # under 10 MB, and the queue's whole purpose is to survive a
            # disconnect, not to be a history of everything ever sent.
            #
            # Failures are different and are kept (see mark_failed): those are
            # the rows with diagnostic value.
            session.delete(message)

            logger.debug("Delivered and removed message from queue: %s", message_id)
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
                    "Message %s failed (attempt %d/%d), scheduled for retry in %d seconds",
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

            # COUNT in SQL.  This used to be ``query.all()`` followed by four
            # Python passes, which materialises every row INCLUDING its
            # message_data blob just to produce four integers — ~11 GB of RAM
            # against the database that prompted this audit.  It survived only
            # because nothing in the agent currently calls it.
            by_status = dict(
                query.with_entities(
                    MessageQueue.status, func.count(MessageQueue.message_id)
                ).group_by(MessageQueue.status)
            )
            stats = {
                "total": sum(by_status.values()),
                "pending": by_status.get(QueueStatus.PENDING.value, 0),
                "in_progress": by_status.get(QueueStatus.IN_PROGRESS.value, 0),
                "completed": by_status.get(QueueStatus.COMPLETED.value, 0),
                "failed": by_status.get(QueueStatus.FAILED.value, 0),
            }

            if direction:
                stats["direction"] = direction

            return stats

    def cleanup_old_messages(
        self, older_than_days: int = 7, keep_failed: bool = False
    ) -> int:
        """
        Remove queue rows that are no longer useful, and reclaim the space.

        Delivered messages are deleted the moment the server acknowledges them
        (see ``mark_completed``), so in normal operation there is nothing here
        to collect.  This is the backstop for two cases:

          * rows left ``completed`` by an agent that predates that change, and
          * FAILED rows, which are retained for diagnosis but must not
            accumulate forever.

        Args:
            older_than_days: Age threshold, measured from ``completed_at``.
            keep_failed: Retain failed rows regardless of age.  Defaults to
                False now: failures are worth keeping for a while, not for
                ever, and "for ever" is what the old default meant given
                nothing ever called this.

        Returns:
            int: Number of rows deleted.
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        collectable = [QueueStatus.COMPLETED.value]
        if not keep_failed:
            collectable.append(QueueStatus.FAILED.value)

        with self.get_session() as session:
            # A single DELETE with an IN clause.  The previous implementation
            # built a UNION of two queries and called .delete() on it, which
            # SQLAlchemy cannot translate into a bulk DELETE.
            deleted_count = (
                session.query(MessageQueue)
                .filter(
                    and_(
                        MessageQueue.completed_at < cutoff_date,
                        MessageQueue.status.in_(collectable),
                    )
                )
                .delete(synchronize_session=False)
            )

        if deleted_count:
            logger.info("Cleaned up %d old queue message(s)", deleted_count)
            # SQLite never returns freed pages to the filesystem on its own, so
            # a large delete leaves the file exactly as big as it was.  Without
            # this the disk pressure that motivated the delete does not go away.
            self.vacuum()
        return deleted_count

    def cleanup_old_tracking_records(self, older_than_days: int = 7) -> int:
        """Collect finished script-execution and install-tracking rows.

        Both tables are ledgers with no reader once the work is finished:

          * ``script_executions`` exists to reject a duplicate result for an
            execution the agent has already reported.  The server will not
            re-send a months-old execution, so the ledger only has to cover a
            recent window — but nothing ever deleted from it, so it grew by one
            row per script run for the life of the agent.
          * ``installation_request_tracking`` correlates an install request with
            its outcome.  Rows are marked completed/failed and keep the full
            ``result_log``, and were likewise never deleted.

        Both were empty on the host that prompted this audit, which is why they
        had not caused trouble yet; the queue simply filled the disk first.

        Returns:
            int: Number of rows deleted across both tables.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        deleted = 0
        with self.get_session() as session:
            deleted += (
                session.query(ScriptExecution)
                .filter(
                    ScriptExecution.completed_at.isnot(None),
                    ScriptExecution.completed_at < cutoff,
                )
                .delete(synchronize_session=False)
            )
            deleted += (
                session.query(InstallationRequestTracking)
                .filter(
                    InstallationRequestTracking.completed_at.isnot(None),
                    InstallationRequestTracking.completed_at < cutoff,
                )
                .delete(synchronize_session=False)
            )
        if deleted:
            logger.info("Cleaned up %d finished tracking record(s)", deleted)
        return deleted

    def vacuum(self) -> None:
        """Return free pages to the filesystem.

        Best-effort: VACUUM needs a write lock and rewrites the whole file, so
        it can fail on a busy database.  That is not worth failing a
        maintenance pass over — the next prune will try again.
        """
        try:
            with self.get_session() as session:
                session.execute(text("VACUUM"))
            logger.info("Reclaimed free space from the agent database")
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.warning("VACUUM skipped (database busy?): %s", error)

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
        except (json.JSONDecodeError, TypeError) as error:
            logger.exception(
                _("Failed to deserialize message %s: %s"), message.message_id, error
            )
            return {}

    def recover_stuck_messages(self, stale_minutes: int = 10) -> int:
        """
        Recover messages stuck in 'in_progress' status.

        If a message has been in_progress for longer than stale_minutes,
        it's likely due to a crash or error during processing. This method
        resets such messages to 'pending' for retry, or marks them as 'failed'
        if they've exceeded max_retries.

        This should be called on agent startup and periodically during operation
        to prevent messages from being permanently stuck.

        Args:
            stale_minutes: Consider messages stale after this many minutes

        Returns:
            int: Number of messages recovered/cleaned up
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=stale_minutes)
        recovered_count = 0

        with self.get_session() as session:
            # Find stuck in_progress messages
            stuck_messages = (
                session.query(MessageQueue)
                .filter(
                    and_(
                        MessageQueue.status == QueueStatus.IN_PROGRESS.value,
                        or_(
                            MessageQueue.started_at.is_(None),
                            MessageQueue.started_at < cutoff_time,
                        ),
                    )
                )
                .all()
            )

            for message in stuck_messages:
                message.retry_count += 1

                if message.retry_count < message.max_retries:
                    # Reset to pending for retry
                    message.status = QueueStatus.PENDING.value
                    message.started_at = None
                    message.error_message = (
                        f"Recovered from stuck in_progress state "
                        f"(attempt {message.retry_count}/{message.max_retries})"
                    )
                    logger.info(
                        "Recovered stuck message %s (type: %s), will retry",
                        message.message_id,
                        message.message_type,
                    )
                else:
                    # Max retries exceeded, mark as failed
                    message.status = QueueStatus.FAILED.value
                    message.completed_at = datetime.now(timezone.utc)
                    message.error_message = (
                        f"Failed after {message.retry_count} attempts "
                        "(stuck in in_progress state)"
                    )
                    logger.warning(
                        _(
                            "Message %s (type: %s) exceeded max retries, marked as failed"
                        ),
                        message.message_id,
                        message.message_type,
                    )

                recovered_count += 1

            if recovered_count > 0:
                logger.info("Recovered %d stuck messages", recovered_count)

        return recovered_count

    def is_duplicate_message(self, message_id: str) -> bool:
        """
        Check if a message with this ID has already been received/processed.

        This is used for deduplication when the server retries sending a command
        that the agent already received. This prevents the same command from
        being executed multiple times.

        Args:
            message_id: The message ID to check (this is the server's message ID,
                       not the local queue message ID)

        Returns:
            bool: True if this message has already been processed, False otherwise
        """
        with self.get_session() as session:
            # Look for any message with this message_id in the message data
            # We need to search the JSON message_data field for the message_id
            messages = (
                session.query(MessageQueue)
                .filter(MessageQueue.direction == QueueDirection.INBOUND.value)
                .all()
            )

            for message in messages:
                try:
                    data = json.loads(message.message_data)
                    # Check both the top-level message_id and nested data.message_id
                    stored_msg_id = data.get("message_id") or data.get("data", {}).get(
                        "message_id"
                    )
                    if stored_msg_id == message_id:
                        logger.info(
                            "Duplicate message detected: %s (status: %s)",
                            message_id,
                            message.status,
                        )
                        return True
                except (json.JSONDecodeError, TypeError):
                    continue

            return False
