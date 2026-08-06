# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""drop unused agent tables (queue_metrics, vmm_build_cache)

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-08-06 00:00:00.000000

Both tables were declared and migrated but never used:

  * ``queue_metrics`` — intended for queue performance statistics.  Nothing in
    the agent ever wrote a row; the only references outside the model were a
    comment in an old migration and a ``__repr__`` unit test.
  * ``vmm_build_cache`` — intended to cache VMM build artifacts so they were not
    rebuilt.  Zero references anywhere outside the model definition.

Found by a 2026-08-06 audit of what the agent database actually holds.  Both
were empty on the audited host, and being empty they cost nothing at runtime —
but they are schema surface that has to be migrated, reasoned about and kept
consistent for something no code path touches.

Recreating either is a new migration away if the feature is picked up.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("queue_metrics", "vmm_build_cache")


def upgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table in _TABLES:
        # Idempotent: an agent that never ran the migration which created these
        # (or a fresh install off a newer baseline) simply has nothing to drop.
        if table in existing:
            op.drop_table(table)


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())

    if "queue_metrics" not in existing:
        op.create_table(
            "queue_metrics",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("metric_name", sa.String(100), nullable=False),
            sa.Column("metric_value", sa.Float, nullable=False),
            sa.Column("recorded_at", sa.DateTime, nullable=False),
        )
    if "vmm_build_cache" not in existing:
        op.create_table(
            "vmm_build_cache",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("version", sa.String(50), nullable=False),
            sa.Column("file_path", sa.String(500), nullable=False),
            sa.Column("created_at", sa.DateTime, nullable=False),
        )
