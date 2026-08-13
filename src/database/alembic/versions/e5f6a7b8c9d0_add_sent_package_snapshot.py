# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""add sent_package_snapshot — what the server already has, so we can send deltas

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-08-12 22:30:00.000000

The agent re-transmitted its entire ~89k-package catalog every collection cycle
because it had no record of what the server already held.  ``available_packages``
cannot serve that purpose: it is replaced wholesale by each scan, so it only
ever describes "now", never "what was delivered".

This table is the delivered snapshot.  The difference between the current scan
and this is exactly the set of puts and takes to transmit.

Two properties make it safe to diff against:

  * it is written ONLY after a transmission the server accepted, so a failed
    send leaves it describing what the server genuinely holds rather than what
    we hoped it received; and
  * it carries the fingerprint of the snapshot, which must match the
    fingerprint the SERVER reports holding before a delta is sent.  When they
    disagree the agent sends a full catalog rather than guessing.

Idempotent: safe to run against a database that already has the table.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "sent_package_snapshot"


def upgrade() -> None:
    if inspect(op.get_bind()).has_table(_TABLE):
        return
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("package_manager", sa.String(length=50), nullable=False),
        sa.Column("package_name", sa.String(length=255), nullable=False),
        sa.Column("package_version", sa.String(length=100), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=False),
    )
    # The diff reads the whole snapshot by manager; the fingerprint index
    # supports the "is this still the base the server holds?" check.
    op.create_index(f"ix_{_TABLE}_manager", _TABLE, ["package_manager"])
    op.create_index(f"ix_{_TABLE}_fingerprint", _TABLE, ["fingerprint"])


def downgrade() -> None:
    if not inspect(op.get_bind()).has_table(_TABLE):
        return
    op.drop_index(f"ix_{_TABLE}_fingerprint", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_manager", table_name=_TABLE)
    op.drop_table(_TABLE)
