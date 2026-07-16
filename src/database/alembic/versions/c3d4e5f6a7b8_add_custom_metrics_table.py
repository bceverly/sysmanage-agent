# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Add custom_metrics table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6g7
Create Date: 2026-07-09 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6g7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema - add custom_metrics table.

    This migration is idempotent - it checks if the table exists before
    creating it.
    """
    bind = op.get_bind()
    inspector = inspect(bind)

    if "custom_metrics" not in inspector.get_table_names():
        op.create_table(
            "custom_metrics",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("metric_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("script", sa.Text(), nullable=False),
            sa.Column("interpreter", sa.String(length=20), nullable=False),
            sa.Column("cadence_seconds", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

        op.create_index(
            op.f("ix_custom_metrics_metric_id"),
            "custom_metrics",
            ["metric_id"],
            unique=True,
        )


def downgrade() -> None:
    """
    Downgrade schema - remove custom_metrics table.

    This migration is idempotent - it checks if the table exists before
    dropping it.
    """
    bind = op.get_bind()
    inspector = inspect(bind)

    if "custom_metrics" in inspector.get_table_names():
        try:
            op.drop_index(
                op.f("ix_custom_metrics_metric_id"),
                table_name="custom_metrics",
            )
        except Exception:  # nosec B110 # pylint: disable=broad-except
            pass  # Index might not exist

        op.drop_table("custom_metrics")
