"""Add VMM build cache table

Revision ID: b2c3d4e5f6g7
Revises: a149f26a0a57
Create Date: 2025-12-10 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6g7"
down_revision: Union[str, Sequence[str], None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema - add vmm_build_cache table.

    This migration is idempotent - it checks if the table exists before creating it.
    """
    # Get database connection
    bind = op.get_bind()
    inspector = inspect(bind)

    # Check if table already exists
    if "vmm_build_cache" not in inspector.get_table_names():
        # Create vmm_build_cache table
        op.create_table(
            "vmm_build_cache",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("openbsd_version", sa.String(length=10), nullable=False),
            sa.Column("agent_version", sa.String(length=20), nullable=False),
            sa.Column("site_tgz_path", sa.String(length=512), nullable=False),
            sa.Column("agent_package_path", sa.String(length=512), nullable=True),
            sa.Column("site_tgz_checksum", sa.String(length=64), nullable=True),
            sa.Column("built_at", sa.DateTime(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(), nullable=False),
            sa.Column("build_status", sa.String(length=20), nullable=False),
            sa.Column("build_log", sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )

        # Create indexes (only if they don't exist)
        op.create_index(
            op.f("ix_vmm_build_cache_openbsd_version"),
            "vmm_build_cache",
            ["openbsd_version"],
            unique=False,
        )
        op.create_index(
            op.f("ix_vmm_build_cache_agent_version"),
            "vmm_build_cache",
            ["agent_version"],
            unique=False,
        )
        op.create_index(
            "idx_vmm_cache_version",
            "vmm_build_cache",
            ["openbsd_version", "agent_version"],
            unique=True,
        )


def downgrade() -> None:
    """
    Downgrade schema - remove vmm_build_cache table.

    This migration is idempotent - it checks if the table exists before dropping it.
    """
    # Get database connection
    bind = op.get_bind()
    inspector = inspect(bind)

    # Check if table exists before trying to drop it
    if "vmm_build_cache" in inspector.get_table_names():
        # Drop indexes first
        try:
            op.drop_index("idx_vmm_cache_version", table_name="vmm_build_cache")
        except Exception:  # nosec B110 # pylint: disable=broad-except
            pass  # Index might not exist

        try:
            op.drop_index(
                op.f("ix_vmm_build_cache_agent_version"),
                table_name="vmm_build_cache",
            )
        except Exception:  # nosec B110 # pylint: disable=broad-except
            pass  # Index might not exist

        try:
            op.drop_index(
                op.f("ix_vmm_build_cache_openbsd_version"),
                table_name="vmm_build_cache",
            )
        except Exception:  # nosec B110 # pylint: disable=broad-except
            pass  # Index might not exist

        # Drop table
        op.drop_table("vmm_build_cache")
