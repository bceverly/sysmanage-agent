"""Add host_approval table for storing server-assigned host_id

Revision ID: 5fb27492bb5b
Revises: e5365e178a37
Create Date: 2025-09-06 06:23:20.135531

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5fb27492bb5b"
down_revision: Union[str, Sequence[str], None] = "e5365e178a37"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create host_approval table
    op.create_table(
        "host_approval",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("approval_status", sa.String(length=20), nullable=False),
        sa.Column("certificate", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes
    op.create_index(
        op.f("ix_host_approval_host_id"), "host_approval", ["host_id"], unique=False
    )
    op.create_index(
        op.f("ix_host_approval_approval_status"),
        "host_approval",
        ["approval_status"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index(op.f("ix_host_approval_approval_status"), table_name="host_approval")
    op.drop_index(op.f("ix_host_approval_host_id"), table_name="host_approval")

    # Drop table
    op.drop_table("host_approval")
