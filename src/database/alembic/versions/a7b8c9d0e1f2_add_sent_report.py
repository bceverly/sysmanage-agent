# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Add sent_report table (server Phase 22.2: persisted send-on-change)

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-10-02 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, Sequence[str], None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add sent_report.  Idempotent: skips a table that already exists."""
    if "sent_report" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "sent_report",
            sa.Column("message_type", sa.String(length=64), nullable=False),
            sa.Column("digest", sa.String(length=64), nullable=True),
            sa.Column("sent_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("message_type"),
        )


def downgrade() -> None:
    """Remove sent_report (idempotent)."""
    if "sent_report" in inspect(op.get_bind()).get_table_names():
        op.drop_table("sent_report")
