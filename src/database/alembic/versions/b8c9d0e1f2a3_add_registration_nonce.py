# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Add registration_nonce table (server Phase 22: idempotent registration)

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-10-05 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, Sequence[str], None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add registration_nonce.  Idempotent: skips a table that already exists."""
    if "registration_nonce" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "registration_nonce",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("nonce", sa.String(length=128), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade() -> None:
    """Remove registration_nonce (idempotent)."""
    if "registration_nonce" in inspect(op.get_bind()).get_table_names():
        op.drop_table("registration_nonce")
