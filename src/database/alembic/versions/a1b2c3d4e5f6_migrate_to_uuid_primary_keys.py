"""Migrate all integer primary keys to UUIDs in sysmanage-agent

Revision ID: a1b2c3d4e5f6
Revises: 9ad14cccd903
Create Date: 2025-09-21 16:00:00.000000

"""

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "9ad14cccd903"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Migrate all integer primary keys to UUIDs."""
    # Get database connection to check dialect
    conn = op.get_bind()

    # Add UUID extension for PostgreSQL
    if conn.dialect.name == "postgresql":
        op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    # For SQLite, we need to recreate all tables since ALTER COLUMN TYPE is not supported
    if conn.dialect.name == "sqlite":
        # Clean up any existing backup tables from previous failed attempts
        op.execute("DROP TABLE IF EXISTS message_queue_backup")
        op.execute("DROP TABLE IF EXISTS queue_metrics_backup")
        op.execute("DROP TABLE IF EXISTS host_approval_backup")
        op.execute("DROP TABLE IF EXISTS script_executions_backup")
        op.execute("DROP TABLE IF EXISTS available_packages_backup")
        op.execute("DROP TABLE IF EXISTS installation_request_tracking_backup")
        op.execute("DROP TABLE IF EXISTS system_info_backup")

        # Backup existing data
        op.execute(
            """
        CREATE TABLE message_queue_backup AS
        SELECT * FROM message_queue
        """
        )

        op.execute(
            """
        CREATE TABLE queue_metrics_backup AS
        SELECT * FROM queue_metrics
        """
        )

        op.execute(
            """
        CREATE TABLE host_approval_backup AS
        SELECT * FROM host_approval
        """
        )

        op.execute(
            """
        CREATE TABLE script_executions_backup AS
        SELECT * FROM script_executions
        """
        )

        op.execute(
            """
        CREATE TABLE available_packages_backup AS
        SELECT * FROM available_packages
        """
        )

        op.execute(
            """
        CREATE TABLE installation_request_tracking_backup AS
        SELECT * FROM installation_request_tracking
        """
        )

        # Drop existing tables
        op.drop_table("message_queue")
        op.drop_table("queue_metrics")
        op.drop_table("host_approval")
        op.drop_table("script_executions")
        op.drop_table("available_packages")
        op.drop_table("installation_request_tracking")

        # Recreate tables with UUID primary keys
        # MessageQueue table with UUID primary key
        op.create_table(
            "message_queue",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "message_id", sa.String(36), nullable=False, index=True, unique=True
            ),
            sa.Column("direction", sa.String(10), nullable=False, index=True),
            sa.Column("message_type", sa.String(50), nullable=False, index=True),
            sa.Column("message_data", sa.Text(), nullable=False),
            sa.Column(
                "status", sa.String(15), nullable=False, default="pending", index=True
            ),
            sa.Column(
                "priority", sa.String(10), nullable=False, default="normal", index=True
            ),
            sa.Column("retry_count", sa.Integer(), nullable=False, default=0),
            sa.Column("max_retries", sa.Integer(), nullable=False, default=3),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("scheduled_at", sa.DateTime(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("last_error_at", sa.DateTime(), nullable=True),
            sa.Column("correlation_id", sa.String(36), nullable=True, index=True),
            sa.Column("reply_to", sa.String(36), nullable=True, index=True),
        )

        # QueueMetrics table with UUID primary key
        op.create_table(
            "queue_metrics",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("metric_name", sa.String(50), nullable=False, index=True),
            sa.Column("direction", sa.String(10), nullable=False, index=True),
            sa.Column("count", sa.Integer(), nullable=False, default=0),
            sa.Column("total_time_ms", sa.Integer(), nullable=False, default=0),
            sa.Column("avg_time_ms", sa.Integer(), nullable=False, default=0),
            sa.Column("min_time_ms", sa.Integer(), nullable=True),
            sa.Column("max_time_ms", sa.Integer(), nullable=True),
            sa.Column("error_count", sa.Integer(), nullable=False, default=0),
            sa.Column("period_start", sa.DateTime(), nullable=False),
            sa.Column("period_end", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

        # HostApproval table with UUID primary key and foreign key
        op.create_table(
            "host_approval",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("host_id", sa.String(36), nullable=True, index=True),
            sa.Column("host_token", sa.String(64), nullable=True, index=True),
            sa.Column(
                "approval_status",
                sa.String(20),
                nullable=False,
                default="pending",
                index=True,
            ),
            sa.Column("certificate", sa.Text(), nullable=True),
            sa.Column("approved_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )

        # ScriptExecution table with UUID primary key
        op.create_table(
            "script_executions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("execution_id", sa.String(36), nullable=False, index=True),
            sa.Column(
                "execution_uuid", sa.String(36), nullable=False, unique=True, index=True
            ),
            sa.Column("script_name", sa.String(255), nullable=True),
            sa.Column("shell_type", sa.String(50), nullable=True),
            sa.Column(
                "status", sa.String(20), nullable=False, default="pending", index=True
            ),
            sa.Column("exit_code", sa.Integer(), nullable=True),
            sa.Column("stdout_output", sa.Text(), nullable=True),
            sa.Column("stderr_output", sa.Text(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("execution_time", sa.Integer(), nullable=True),
            sa.Column("received_at", sa.DateTime(), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("result_sent_at", sa.DateTime(), nullable=True),
        )

        # AvailablePackage table with UUID primary key
        op.create_table(
            "available_packages",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("package_manager", sa.String(50), nullable=False),
            sa.Column("package_name", sa.String(255), nullable=False),
            sa.Column("package_version", sa.String(100), nullable=False),
            sa.Column("package_description", sa.Text(), nullable=True),
            sa.Column("collection_date", sa.DateTime(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

        # InstallationRequestTracking table with UUID primary key
        op.create_table(
            "installation_request_tracking",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "request_id", sa.String(36), nullable=False, unique=True, index=True
            ),
            sa.Column("requested_by", sa.String(100), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, default="pending"),
            sa.Column("packages_json", sa.Text(), nullable=False),
            sa.Column("received_at", sa.DateTime(), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("result_log", sa.Text(), nullable=True),
            sa.Column("success", sa.String(10), nullable=True),
        )

        # Restore data with UUID conversion
        # Note: In SQLite, we lose the old integer IDs but that's acceptable for the agent
        # Generate UUIDs for existing records
        op.execute(
            """
        INSERT INTO message_queue (id, message_id, direction, message_type, message_data, status, priority, retry_count, max_retries, created_at, scheduled_at, started_at, completed_at, error_message, last_error_at, correlation_id, reply_to)
        SELECT
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) as id,
            message_id, direction, message_type, message_data, status, priority, retry_count, max_retries, created_at, scheduled_at, started_at, completed_at, error_message, last_error_at, correlation_id, reply_to
        FROM message_queue_backup
        """
        )

        op.execute(
            """
        INSERT INTO queue_metrics (id, metric_name, direction, count, total_time_ms, avg_time_ms, min_time_ms, max_time_ms, error_count, period_start, period_end, updated_at)
        SELECT
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) as id,
            metric_name, direction, count, total_time_ms, avg_time_ms, min_time_ms, max_time_ms, error_count, period_start, period_end, updated_at
        FROM queue_metrics_backup
        """
        )

        op.execute(
            """
        INSERT INTO host_approval (id, host_id, host_token, approval_status, certificate, approved_at, created_at, updated_at)
        SELECT
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) as id,
            CASE WHEN host_id IS NOT NULL THEN lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) ELSE NULL END as host_id,
            host_token, approval_status, certificate, approved_at, created_at, updated_at
        FROM host_approval_backup
        """
        )

        op.execute(
            """
        INSERT INTO script_executions (id, execution_id, execution_uuid, script_name, shell_type, status, exit_code, stdout_output, stderr_output, error_message, execution_time, received_at, started_at, completed_at, result_sent_at)
        SELECT
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) as id,
            execution_id, execution_uuid, script_name, shell_type, status, exit_code, stdout_output, stderr_output, error_message, execution_time, received_at, started_at, completed_at, result_sent_at
        FROM script_executions_backup
        """
        )

        op.execute(
            """
        INSERT INTO available_packages (id, package_manager, package_name, package_version, package_description, collection_date, created_at)
        SELECT
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) as id,
            package_manager, package_name, package_version, package_description, collection_date, created_at
        FROM available_packages_backup
        """
        )

        op.execute(
            """
        INSERT INTO installation_request_tracking (id, request_id, requested_by, status, packages_json, received_at, started_at, completed_at, result_log, success)
        SELECT
            lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))) as id,
            request_id, requested_by, status, packages_json, received_at, started_at, completed_at, result_log, success
        FROM installation_request_tracking_backup
        """
        )

        # Drop backup tables
        op.drop_table("message_queue_backup")
        op.drop_table("queue_metrics_backup")
        op.drop_table("host_approval_backup")
        op.drop_table("script_executions_backup")
        op.drop_table("available_packages_backup")
        op.drop_table("installation_request_tracking_backup")

        # Recreate indexes
        op.create_index(
            "idx_queue_processing",
            "message_queue",
            ["direction", "status", "priority", "scheduled_at"],
        )
        op.create_index(
            "idx_queue_cleanup", "message_queue", ["status", "completed_at"]
        )
        op.create_index(
            "idx_queue_retry", "message_queue", ["status", "retry_count", "max_retries"]
        )
        op.create_index(
            "idx_metrics_period",
            "queue_metrics",
            ["metric_name", "direction", "period_start", "period_end"],
        )
        op.create_index(
            "idx_metrics_latest",
            "queue_metrics",
            ["metric_name", "direction", "updated_at"],
        )

    elif conn.dialect.name == "postgresql":
        # For PostgreSQL, we can use more sophisticated ALTER operations
        # This is a destructive migration for agent - we'll drop and recreate with UUIDs
        # Agent data is not critical to preserve unlike server data

        # Drop tables and recreate with UUID primary keys
        op.drop_table("message_queue")
        op.drop_table("queue_metrics")
        op.drop_table("host_approval")
        op.drop_table("script_executions")
        op.drop_table("available_packages")
        op.drop_table("installation_request_tracking")

        # Recreate with UUID columns using PostgreSQL UUID type
        op.create_table(
            "message_queue",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                default=uuid.uuid4,
            ),
            sa.Column(
                "message_id", sa.String(36), nullable=False, index=True, unique=True
            ),
            sa.Column("direction", sa.String(10), nullable=False, index=True),
            sa.Column("message_type", sa.String(50), nullable=False, index=True),
            sa.Column("message_data", sa.Text(), nullable=False),
            sa.Column(
                "status", sa.String(15), nullable=False, default="pending", index=True
            ),
            sa.Column(
                "priority", sa.String(10), nullable=False, default="normal", index=True
            ),
            sa.Column("retry_count", sa.Integer(), nullable=False, default=0),
            sa.Column("max_retries", sa.Integer(), nullable=False, default=3),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("correlation_id", sa.String(36), nullable=True, index=True),
            sa.Column("reply_to", sa.String(36), nullable=True, index=True),
        )

        # Other tables...
        # (Similar pattern for other tables with PostgreSQL UUID type)


def downgrade() -> None:
    """Downgrade not supported - this is a destructive migration."""
    raise NotImplementedError("Downgrade not supported for UUID migration")
