"""
Tests for database models module.
Tests GUID and UTCDateTime type decorators and model properties.
"""

# pylint: disable=redefined-outer-name,protected-access

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.base import Base
from src.database.models import (
    GUID,
    UTCDateTime,
    QueueStatus,
    QueueDirection,
    Priority,
    MessageQueue,
    QueueMetrics,
    HostApproval,
    ScriptExecution,
    AvailablePackage,
    InstallationRequestTracking,
    VmmBuildCache,
)


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite engine for testing."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(in_memory_engine):
    """Create a database session for testing."""
    session_factory = sessionmaker(bind=in_memory_engine)
    session = session_factory()
    yield session
    session.close()


class TestGUIDTypeDecorator:
    """Tests for GUID type decorator."""

    def test_guid_process_bind_param_with_uuid(self):
        """Test GUID binding with uuid.UUID instance."""
        guid = GUID()
        test_uuid = uuid.uuid4()
        mock_dialect = Mock()
        mock_dialect.name = "sqlite"

        result = guid.process_bind_param(test_uuid, mock_dialect)
        assert result == str(test_uuid)

    def test_guid_process_bind_param_with_string(self):
        """Test GUID binding with string UUID."""
        guid = GUID()
        test_uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        mock_dialect = Mock()
        mock_dialect.name = "sqlite"

        result = guid.process_bind_param(test_uuid_str, mock_dialect)
        assert result == test_uuid_str

    def test_guid_process_bind_param_with_none(self):
        """Test GUID binding with None."""
        guid = GUID()
        mock_dialect = Mock()
        mock_dialect.name = "sqlite"

        result = guid.process_bind_param(None, mock_dialect)
        assert result is None

    def test_guid_process_bind_param_with_invalid_uuid(self):
        """Test GUID binding with invalid UUID raises error."""
        guid = GUID()
        mock_dialect = Mock()
        mock_dialect.name = "sqlite"

        with pytest.raises(ValueError, match="Invalid UUID value"):
            guid.process_bind_param("not-a-uuid", mock_dialect)

    def test_guid_process_result_value_with_string(self):
        """Test GUID result processing with string UUID."""
        guid = GUID()
        test_uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        mock_dialect = Mock()

        result = guid.process_result_value(test_uuid_str, mock_dialect)
        assert isinstance(result, uuid.UUID)
        assert str(result) == test_uuid_str

    def test_guid_process_result_value_with_uuid(self):
        """Test GUID result processing with uuid.UUID."""
        guid = GUID()
        test_uuid = uuid.uuid4()
        mock_dialect = Mock()

        result = guid.process_result_value(test_uuid, mock_dialect)
        assert result == test_uuid

    def test_guid_process_result_value_with_none(self):
        """Test GUID result processing with None."""
        guid = GUID()
        mock_dialect = Mock()

        result = guid.process_result_value(None, mock_dialect)
        assert result is None

    def test_guid_process_result_value_with_corrupt_data(self):
        """Test GUID result processing with corrupt data returns None."""
        guid = GUID()
        mock_dialect = Mock()

        with patch("src.database.models.logging.getLogger") as mock_logger:
            mock_log_instance = Mock()
            mock_logger.return_value = mock_log_instance
            result = guid.process_result_value("corrupt-data", mock_dialect)
            assert result is None

    def test_guid_process_literal_param(self):
        """Test GUID literal parameter processing."""
        guid = GUID()
        test_uuid = uuid.uuid4()
        mock_dialect = Mock()

        result = guid.process_literal_param(test_uuid, mock_dialect)
        assert result == str(test_uuid)

    def test_guid_process_literal_param_with_none(self):
        """Test GUID literal parameter processing with None."""
        guid = GUID()
        mock_dialect = Mock()

        result = guid.process_literal_param(None, mock_dialect)
        assert result is None

    def test_guid_python_type(self):
        """Test GUID python_type property."""
        guid = GUID()
        assert guid.python_type == uuid.UUID

    def test_guid_cache_ok(self):
        """Test that GUID has cache_ok set."""
        guid = GUID()
        assert guid.cache_ok is True


class TestUTCDateTimeTypeDecorator:
    """Tests for UTCDateTime type decorator."""

    def test_utc_datetime_process_bind_param_with_naive(self):
        """Test UTCDateTime binding with naive datetime."""
        utc_dt = UTCDateTime()
        naive_dt = datetime(2024, 1, 15, 12, 0, 0)
        mock_dialect = Mock()

        result = utc_dt.process_bind_param(naive_dt, mock_dialect)
        # Should be stored as naive datetime (tzinfo removed)
        assert result.tzinfo is None
        assert result == datetime(2024, 1, 15, 12, 0, 0)

    def test_utc_datetime_process_bind_param_with_utc(self):
        """Test UTCDateTime binding with UTC datetime."""
        utc_dt = UTCDateTime()
        aware_dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_dialect = Mock()

        result = utc_dt.process_bind_param(aware_dt, mock_dialect)
        assert result.tzinfo is None
        assert result == datetime(2024, 1, 15, 12, 0, 0)

    def test_utc_datetime_process_bind_param_with_offset(self):
        """Test UTCDateTime binding with offset timezone converts to UTC."""
        utc_dt = UTCDateTime()
        # Create a datetime at noon in UTC+5
        offset_tz = timezone(timedelta(hours=5))
        aware_dt = datetime(
            2024, 1, 15, 17, 0, 0, tzinfo=offset_tz
        )  # 17:00 UTC+5 = 12:00 UTC
        mock_dialect = Mock()

        result = utc_dt.process_bind_param(aware_dt, mock_dialect)
        assert result.tzinfo is None
        # Should be converted to UTC (17:00 - 5:00 = 12:00)
        assert result == datetime(2024, 1, 15, 12, 0, 0)

    def test_utc_datetime_process_bind_param_with_none(self):
        """Test UTCDateTime binding with None."""
        utc_dt = UTCDateTime()
        mock_dialect = Mock()

        result = utc_dt.process_bind_param(None, mock_dialect)
        assert result is None

    def test_utc_datetime_process_result_value(self):
        """Test UTCDateTime result processing adds UTC timezone."""
        utc_dt = UTCDateTime()
        stored_dt = datetime(2024, 1, 15, 12, 0, 0)
        mock_dialect = Mock()

        result = utc_dt.process_result_value(stored_dt, mock_dialect)
        assert result.tzinfo == timezone.utc
        assert result == datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_utc_datetime_process_result_value_with_none(self):
        """Test UTCDateTime result processing with None."""
        utc_dt = UTCDateTime()
        mock_dialect = Mock()

        result = utc_dt.process_result_value(None, mock_dialect)
        assert result is None

    def test_utc_datetime_process_literal_param(self):
        """Test UTCDateTime literal parameter processing."""
        utc_dt = UTCDateTime()
        test_dt = datetime(2024, 1, 15, 12, 0, 0)
        mock_dialect = Mock()

        result = utc_dt.process_literal_param(test_dt, mock_dialect)
        assert result == str(test_dt)

    def test_utc_datetime_process_literal_param_with_none(self):
        """Test UTCDateTime literal parameter processing with None."""
        utc_dt = UTCDateTime()
        mock_dialect = Mock()

        result = utc_dt.process_literal_param(None, mock_dialect)
        assert result is None

    def test_utc_datetime_python_type(self):
        """Test UTCDateTime python_type property."""
        utc_dt = UTCDateTime()
        assert utc_dt.python_type == datetime

    def test_utc_datetime_cache_ok(self):
        """Test that UTCDateTime has cache_ok set."""
        utc_dt = UTCDateTime()
        assert utc_dt.cache_ok is True


class TestEnumerations:
    """Tests for model enumerations."""

    def test_queue_status_values(self):
        """Test QueueStatus enumeration values."""
        assert QueueStatus.PENDING.value == "pending"
        assert QueueStatus.IN_PROGRESS.value == "in_progress"
        assert QueueStatus.COMPLETED.value == "completed"
        assert QueueStatus.FAILED.value == "failed"

    def test_queue_direction_values(self):
        """Test QueueDirection enumeration values."""
        assert QueueDirection.OUTBOUND.value == "outbound"
        assert QueueDirection.INBOUND.value == "inbound"

    def test_priority_values(self):
        """Test Priority enumeration values."""
        assert Priority.LOW.value == "low"
        assert Priority.NORMAL.value == "normal"
        assert Priority.HIGH.value == "high"
        assert Priority.URGENT.value == "urgent"


class TestMessageQueueModel:
    """Tests for MessageQueue model."""

    def test_message_queue_creation(self, db_session):
        """Test creating a MessageQueue instance."""
        msg = MessageQueue(
            message_id="test-msg-123",
            direction="outbound",
            message_type="heartbeat",
            message_data='{"test": "data"}',
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.id is not None
        assert msg.message_id == "test-msg-123"
        assert msg.direction == "outbound"
        assert msg.status == "pending"
        assert msg.priority == "normal"
        assert msg.retry_count == 0
        assert msg.max_retries == 3

    def test_message_queue_is_pending(self, db_session):
        """Test is_pending property."""
        msg = MessageQueue(
            message_id="test-1",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="pending",
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_pending is True
        assert msg.is_in_progress is False
        assert msg.is_completed is False
        assert msg.is_failed is False

    def test_message_queue_is_in_progress(self, db_session):
        """Test is_in_progress property."""
        msg = MessageQueue(
            message_id="test-2",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="in_progress",
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_pending is False
        assert msg.is_in_progress is True

    def test_message_queue_is_completed(self, db_session):
        """Test is_completed property."""
        msg = MessageQueue(
            message_id="test-3",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="completed",
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_completed is True

    def test_message_queue_is_failed(self, db_session):
        """Test is_failed property."""
        msg = MessageQueue(
            message_id="test-4",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="failed",
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_failed is True

    def test_message_queue_can_retry(self, db_session):
        """Test can_retry property."""
        msg = MessageQueue(
            message_id="test-5",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="failed",
            retry_count=1,
            max_retries=3,
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.can_retry is True

    def test_message_queue_cannot_retry_max_reached(self, db_session):
        """Test can_retry property when max retries reached."""
        msg = MessageQueue(
            message_id="test-6",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="failed",
            retry_count=3,
            max_retries=3,
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.can_retry is False

    def test_message_queue_is_ready_for_processing(self, db_session):
        """Test is_ready_for_processing property."""
        msg = MessageQueue(
            message_id="test-7",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="pending",
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_ready_for_processing is True

    def test_message_queue_not_ready_when_scheduled_future(self, db_session):
        """Test is_ready_for_processing is False when scheduled in future."""
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        msg = MessageQueue(
            message_id="test-8",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="pending",
            scheduled_at=future_time,
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_ready_for_processing is False

    def test_message_queue_ready_when_scheduled_past(self, db_session):
        """Test is_ready_for_processing is True when scheduled time passed."""
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        msg = MessageQueue(
            message_id="test-9",
            direction="outbound",
            message_type="test",
            message_data="{}",
            status="pending",
            scheduled_at=past_time,
        )
        db_session.add(msg)
        db_session.commit()

        assert msg.is_ready_for_processing is True

    def test_message_queue_repr(self, db_session):
        """Test MessageQueue __repr__."""
        msg = MessageQueue(
            message_id="test-repr",
            direction="outbound",
            message_type="heartbeat",
            message_data="{}",
        )
        db_session.add(msg)
        db_session.commit()

        repr_str = repr(msg)
        assert "MessageQueue" in repr_str
        assert "test-repr" in repr_str
        assert "heartbeat" in repr_str


class TestHostApprovalModel:
    """Tests for HostApproval model."""

    def test_host_approval_creation(self, db_session):
        """Test creating a HostApproval instance."""
        approval = HostApproval(
            approval_status="pending",
        )
        db_session.add(approval)
        db_session.commit()

        assert approval.id is not None
        assert approval.approval_status == "pending"
        assert approval.host_id is None

    def test_host_approval_is_approved(self, db_session):
        """Test is_approved property."""
        approval = HostApproval(
            approval_status="approved",
            host_id=uuid.uuid4(),
        )
        db_session.add(approval)
        db_session.commit()

        assert approval.is_approved is True

    def test_host_approval_not_approved(self, db_session):
        """Test is_approved property when not approved."""
        approval = HostApproval(approval_status="pending")
        db_session.add(approval)
        db_session.commit()

        assert approval.is_approved is False

    def test_host_approval_has_host_id(self, db_session):
        """Test has_host_id property."""
        test_host_id = uuid.uuid4()
        approval = HostApproval(
            approval_status="approved",
            host_id=test_host_id,
        )
        db_session.add(approval)
        db_session.commit()

        assert approval.has_host_id is True

    def test_host_approval_no_host_id(self, db_session):
        """Test has_host_id property when no host_id."""
        approval = HostApproval(approval_status="pending")
        db_session.add(approval)
        db_session.commit()

        assert approval.has_host_id is False

    def test_host_approval_repr(self, db_session):
        """Test HostApproval __repr__."""
        approval = HostApproval(approval_status="pending")
        db_session.add(approval)
        db_session.commit()

        repr_str = repr(approval)
        assert "HostApproval" in repr_str
        assert "pending" in repr_str


class TestScriptExecutionModel:
    """Tests for ScriptExecution model."""

    def test_script_execution_creation(self, db_session):
        """Test creating a ScriptExecution instance."""
        script = ScriptExecution(
            execution_id="exec-123",
            execution_uuid="uuid-456",
        )
        db_session.add(script)
        db_session.commit()

        assert script.id is not None
        assert script.execution_id == "exec-123"
        assert script.execution_uuid == "uuid-456"
        assert script.status == "pending"

    def test_script_execution_is_completed(self, db_session):
        """Test is_completed property."""
        script = ScriptExecution(
            execution_id="exec-1",
            execution_uuid="uuid-1",
            status="completed",
        )
        db_session.add(script)
        db_session.commit()

        assert script.is_completed is True

    def test_script_execution_is_completed_failed(self, db_session):
        """Test is_completed property when failed."""
        script = ScriptExecution(
            execution_id="exec-2",
            execution_uuid="uuid-2",
            status="failed",
        )
        db_session.add(script)
        db_session.commit()

        assert script.is_completed is True

    def test_script_execution_result_already_sent(self, db_session):
        """Test result_already_sent property."""
        script = ScriptExecution(
            execution_id="exec-3",
            execution_uuid="uuid-3",
            result_sent_at=datetime.now(timezone.utc),
        )
        db_session.add(script)
        db_session.commit()

        assert script.result_already_sent is True

    def test_script_execution_result_not_sent(self, db_session):
        """Test result_already_sent property when not sent."""
        script = ScriptExecution(
            execution_id="exec-4",
            execution_uuid="uuid-4",
        )
        db_session.add(script)
        db_session.commit()

        assert script.result_already_sent is False

    def test_script_execution_repr(self, db_session):
        """Test ScriptExecution __repr__."""
        script = ScriptExecution(
            execution_id="exec-repr",
            execution_uuid="uuid-repr",
        )
        db_session.add(script)
        db_session.commit()

        repr_str = repr(script)
        assert "ScriptExecution" in repr_str
        assert "uuid-repr" in repr_str


class TestAvailablePackageModel:
    """Tests for AvailablePackage model."""

    def test_available_package_creation(self, db_session):
        """Test creating an AvailablePackage instance."""
        package = AvailablePackage(
            package_manager="apt",
            package_name="test-package",
            package_version="1.0.0",
            package_description="A test package",
            collection_date=datetime.now(timezone.utc),
        )
        db_session.add(package)
        db_session.commit()

        assert package.id is not None
        assert package.package_manager == "apt"
        assert package.package_name == "test-package"

    def test_available_package_repr(self, db_session):
        """Test AvailablePackage __repr__."""
        package = AvailablePackage(
            package_manager="yum",
            package_name="vim",
            package_version="8.0",
            collection_date=datetime.now(timezone.utc),
        )
        db_session.add(package)
        db_session.commit()

        repr_str = repr(package)
        assert "AvailablePackage" in repr_str
        assert "yum" in repr_str
        assert "vim" in repr_str


class TestInstallationRequestTrackingModel:
    """Tests for InstallationRequestTracking model."""

    def test_installation_request_creation(self, db_session):
        """Test creating an InstallationRequestTracking instance."""
        request = InstallationRequestTracking(
            request_id="req-123",
            requested_by="admin",
            packages_json='["pkg1", "pkg2"]',
        )
        db_session.add(request)
        db_session.commit()

        assert request.id is not None
        assert request.request_id == "req-123"
        assert request.status == "pending"

    def test_installation_request_repr(self, db_session):
        """Test InstallationRequestTracking __repr__."""
        request = InstallationRequestTracking(
            request_id="req-repr",
            requested_by="test",
            packages_json="[]",
        )
        db_session.add(request)
        db_session.commit()

        repr_str = repr(request)
        assert "InstallationRequestTracking" in repr_str
        assert "req-repr" in repr_str


class TestVmmBuildCacheModel:
    """Tests for VmmBuildCache model."""

    def test_vmm_build_cache_creation(self, db_session):
        """Test creating a VmmBuildCache instance."""
        cache = VmmBuildCache(
            openbsd_version="7.7",
            agent_version="0.9.9.8",
            site_tgz_path="/var/cache/vmm/site77.tgz",
        )
        db_session.add(cache)
        db_session.commit()

        assert cache.id is not None
        assert cache.openbsd_version == "7.7"
        assert cache.agent_version == "0.9.9.8"
        assert cache.build_status == "success"

    def test_vmm_build_cache_repr(self, db_session):
        """Test VmmBuildCache __repr__."""
        cache = VmmBuildCache(
            openbsd_version="7.6",
            agent_version="0.9.9.7",
            site_tgz_path="/var/cache/vmm/site76.tgz",
        )
        db_session.add(cache)
        db_session.commit()

        repr_str = repr(cache)
        assert "VmmBuildCache" in repr_str
        assert "7.6" in repr_str
        assert "0.9.9.7" in repr_str


class TestQueueMetricsModel:
    """Tests for QueueMetrics model."""

    def test_queue_metrics_creation(self, db_session):
        """Test creating a QueueMetrics instance."""
        now = datetime.now(timezone.utc)
        metrics = QueueMetrics(
            metric_name="message_processing",
            direction="outbound",
            count=100,
            total_time_ms=5000,
            avg_time_ms=50,
            period_start=now - timedelta(hours=1),
            period_end=now,
        )
        db_session.add(metrics)
        db_session.commit()

        assert metrics.id is not None
        assert metrics.metric_name == "message_processing"
        assert metrics.count == 100

    def test_queue_metrics_repr(self, db_session):
        """Test QueueMetrics __repr__."""
        now = datetime.now(timezone.utc)
        metrics = QueueMetrics(
            metric_name="test_metric",
            direction="inbound",
            count=50,
            total_time_ms=1000,
            avg_time_ms=20,
            period_start=now - timedelta(hours=1),
            period_end=now,
        )
        db_session.add(metrics)
        db_session.commit()

        repr_str = repr(metrics)
        assert "QueueMetrics" in repr_str
        assert "test_metric" in repr_str
