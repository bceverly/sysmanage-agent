# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Add collection_run table (server Phase 22.1: persisted last-run)

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-02 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, Sequence[str], None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add collection_run.  Idempotent: skips a table that already exists."""
    if "collection_run" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "collection_run",
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("last_run_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("name"),
        )


def downgrade() -> None:
    """Remove collection_run (idempotent)."""
    if "collection_run" in inspect(op.get_bind()).get_table_names():
        op.drop_table("collection_run")
