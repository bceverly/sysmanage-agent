"""
Database models for SysManage Agent message queues.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Index
from sqlalchemy.types import TypeDecorator, String as SQLString

from .base import Base


class QueueStatus(str, Enum):
    """Message queue status enumeration."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class QueueDirection(str, Enum):
    """Message queue direction enumeration."""

    OUTBOUND = "outbound"  # Messages to send to server
    INBOUND = "inbound"  # Messages received from server


class Priority(str, Enum):
    """Message priority enumeration."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class UTCDateTime(TypeDecorator):
    """SQLAlchemy type to ensure datetime is stored as UTC."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert datetime to UTC before storing."""
        if value is not None:
            if value.tzinfo is None:
                # Assume naive datetime is UTC
                value = value.replace(tzinfo=timezone.utc)
            else:
                # Convert to UTC
                value = value.astimezone(timezone.utc)
            # Store as naive UTC datetime
            return value.replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        """Convert stored datetime back to UTC timezone-aware."""
        if value is not None:
            return value.replace(tzinfo=timezone.utc)
        return value


class MessageQueue(Base):
    """
    Message queue table for persistent message storage.

    This table stores both inbound and outbound messages with their
    processing status, priority, and timestamps.
    """

    __tablename__ = "message_queue"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Message identification
    message_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID
    direction = Column(String(10), nullable=False, index=True)  # inbound/outbound

    # Message content
    message_type = Column(String(50), nullable=False, index=True)
    message_data = Column(Text, nullable=False)  # JSON serialized message

    # Queue management
    status = Column(String(15), nullable=False, default="pending", index=True)
    priority = Column(String(10), nullable=False, default="normal", index=True)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)

    # Timestamps (all stored as UTC)
    created_at = Column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    scheduled_at = Column(UTCDateTime, nullable=True)  # When to process (for delays)
    started_at = Column(UTCDateTime, nullable=True)  # When processing started
    completed_at = Column(UTCDateTime, nullable=True)  # When processing finished

    # Error handling
    error_message = Column(Text, nullable=True)
    last_error_at = Column(UTCDateTime, nullable=True)

    # Metadata
    correlation_id = Column(
        String(36), nullable=True, index=True
    )  # For message correlation
    reply_to = Column(String(36), nullable=True, index=True)  # For message replies

    # Create composite indexes for common queries
    __table_args__ = (
        Index(
            "idx_queue_processing", "direction", "status", "priority", "scheduled_at"
        ),
        Index("idx_queue_cleanup", "status", "completed_at"),
        Index("idx_queue_retry", "status", "retry_count", "max_retries"),
    )

    def __repr__(self):
        return (
            f"<MessageQueue(id={self.id}, message_id='{self.message_id}', "
            f"type='{self.message_type}', direction='{self.direction}', "
            f"status='{self.status}')>"
        )

    @property
    def is_pending(self) -> bool:
        """Check if message is pending processing."""
        return self.status == QueueStatus.PENDING.value

    @property
    def is_in_progress(self) -> bool:
        """Check if message is currently being processed."""
        return self.status == QueueStatus.IN_PROGRESS.value

    @property
    def is_completed(self) -> bool:
        """Check if message processing is completed."""
        return self.status == QueueStatus.COMPLETED.value

    @property
    def is_failed(self) -> bool:
        """Check if message processing failed."""
        return self.status == QueueStatus.FAILED.value

    @property
    def can_retry(self) -> bool:
        """Check if message can be retried."""
        return self.retry_count < self.max_retries and self.is_failed

    @property
    def is_ready_for_processing(self) -> bool:
        """Check if message is ready for processing."""
        if not self.is_pending:
            return False

        # Check if scheduled time has passed
        if self.scheduled_at is not None:
            now = datetime.now(timezone.utc)
            return self.scheduled_at <= now

        return True


class QueueMetrics(Base):
    """
    Table for storing queue performance metrics and statistics.
    """

    __tablename__ = "queue_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Metric identification
    metric_name = Column(String(50), nullable=False, index=True)
    direction = Column(String(10), nullable=False, index=True)  # inbound/outbound

    # Metric values
    count = Column(Integer, nullable=False, default=0)
    total_time_ms = Column(Integer, nullable=False, default=0)
    avg_time_ms = Column(Integer, nullable=False, default=0)
    min_time_ms = Column(Integer, nullable=True)
    max_time_ms = Column(Integer, nullable=True)

    # Error tracking
    error_count = Column(Integer, nullable=False, default=0)

    # Timestamps
    period_start = Column(UTCDateTime, nullable=False)
    period_end = Column(UTCDateTime, nullable=False)
    updated_at = Column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    # Indexes for efficient querying
    __table_args__ = (
        Index(
            "idx_metrics_period",
            "metric_name",
            "direction",
            "period_start",
            "period_end",
        ),
        Index("idx_metrics_latest", "metric_name", "direction", "updated_at"),
    )

    def __repr__(self):
        return (
            f"<QueueMetrics(id={self.id}, metric='{self.metric_name}', "
            f"direction='{self.direction}', count={self.count})>"
        )


class HostApproval(Base):
    """
    Table for storing host approval status and assigned host_id from server.

    This table maintains the approval state and host_id assigned by the server
    when the agent's host registration is approved.
    """

    __tablename__ = "host_approval"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Host identification from server
    host_id = Column(Integer, nullable=True, index=True)  # Server-assigned host ID

    # Approval information
    approval_status = Column(String(20), nullable=False, default="pending", index=True)
    certificate = Column(Text, nullable=True)  # Client certificate from server

    # Timestamps
    approved_at = Column(UTCDateTime, nullable=True)  # When approval was received
    created_at = Column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self):
        return (
            f"<HostApproval(id={self.id}, host_id={self.host_id}, "
            f"status='{self.approval_status}')>"
        )

    @property
    def is_approved(self) -> bool:
        """Check if host is approved."""
        return self.approval_status == "approved"

    @property
    def has_host_id(self) -> bool:
        """Check if host has been assigned a server host_id."""
        return self.host_id is not None
