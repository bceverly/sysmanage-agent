"""add_script_executions_table

Revision ID: 36b13f6f9d87
Revises: 5fb27492bb5b
Create Date: 2025-09-12 17:01:00.569064

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "36b13f6f9d87"
down_revision: Union[str, Sequence[str], None] = "5fb27492bb5b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create script_executions table
    op.create_table(
        "script_executions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
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


def downgrade() -> None:
    """Downgrade schema."""
    # Drop script_executions table
    op.drop_table("script_executions")
