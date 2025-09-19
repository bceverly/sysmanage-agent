"""Add available_packages table for package management

Revision ID: 580e06d90203
Revises: 299a813b94db
Create Date: 2025-09-18 16:04:11.504327

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "580e06d90203"
down_revision: Union[str, Sequence[str], None] = "299a813b94db"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create available_packages table
    op.create_table(
        "available_packages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("package_manager", sa.String(50), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("package_version", sa.String(100), nullable=False),
        sa.Column("package_description", sa.Text(), nullable=True),
        sa.Column("collection_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Create indexes for performance
    op.create_index(
        "ix_available_packages_manager", "available_packages", ["package_manager"]
    )
    op.create_index(
        "ix_available_packages_name", "available_packages", ["package_name"]
    )
    op.create_index(
        "ix_available_packages_collection_date",
        "available_packages",
        ["collection_date"],
    )

    # Create unique constraint to prevent duplicates
    op.create_index(
        "ix_available_packages_unique",
        "available_packages",
        ["package_manager", "package_name"],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index("ix_available_packages_unique", table_name="available_packages")
    op.drop_index(
        "ix_available_packages_collection_date", table_name="available_packages"
    )
    op.drop_index("ix_available_packages_name", table_name="available_packages")
    op.drop_index("ix_available_packages_manager", table_name="available_packages")

    # Drop table
    op.drop_table("available_packages")
