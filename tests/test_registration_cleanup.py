# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Clearing stale host identity on re-registration.

This cleanup has failed silently twice, in two different ways, and both times
the agent LOGGED a cleanup it had not performed:

1. The statements were bare strings, which SQLAlchemy 2.x refuses -- fixed by
   wrapping them in ``text()``.
2. Once they actually executed, one named a table that does not exist
   (``script_execution`` for ``script_executions``). SQLite aborts the whole
   transaction on error, so the ``host_approval`` delete on the line ABOVE was
   rolled back with it. The agent then carried its previous host_id across
   every restart while the server had issued a different one.

So these tests run the statements against a REAL SQLite database built from
the agent's own models. A mocked session would have accepted either bug.
"""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from src.database.models import Base

# The statements executed by RegistrationManager.clear_host_approval_and_data.
CLEANUP_SQL = [
    "DELETE FROM host_approval",
    "DELETE FROM script_executions",
    "DELETE FROM message_queue WHERE message_data LIKE '%host_id%'",
]


def _insert_stale_approval(session):
    """A leftover approval row, as a re-registering agent would find."""
    session.execute(
        text(
            "INSERT INTO host_approval "
            "(id, host_id, approval_status, created_at, updated_at) "
            "VALUES (1, 'stale-id', 'approved', "
            "'2026-08-28 00:00:00', '2026-08-28 00:00:00')"
        )
    )
    session.commit()


@pytest.fixture(name="session")
def _session():
    # Dispose the engine explicitly: an in-memory SQLite connection finalised
    # by the garbage collector raises during interpreter teardown, which
    # pytest surfaces as an unraisable-exception error on unrelated tests.
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    try:
        yield s
    finally:
        s.close()
        engine.dispose()


def test_every_cleanup_statement_names_a_real_table(session):
    # The regression guard: a wrong table name raises here rather than in
    # production, where the caller swallows it and logs success.
    for sql in CLEANUP_SQL:
        session.execute(text(sql))
    session.commit()


def test_the_tables_the_cleanup_targets_exist_in_the_schema(session):
    names = set(Base.metadata.tables)
    assert "host_approval" in names
    assert "script_executions" in names
    assert "message_queue" in names
    # The name that caused the outage is NOT a table.
    assert "script_execution" not in names


def test_a_bad_table_name_would_roll_back_the_whole_cleanup(session):
    """Why one wrong name broke everything, pinned as behaviour.

    The deletes share a transaction. If a later statement raises, the earlier
    ones are undone -- which is exactly how a stale host_approval row survived
    a cleanup that reported success.
    """
    _insert_stale_approval(session)

    with pytest.raises(Exception):
        session.execute(text("DELETE FROM host_approval"))
        session.execute(text("DELETE FROM script_execution"))  # the old bug
        session.commit()
    session.rollback()

    remaining = session.execute(text("SELECT COUNT(*) FROM host_approval")).scalar()
    assert remaining == 1, "the stale row survives — this is the production bug"


def test_the_corrected_sequence_actually_clears_the_stale_row(session):
    _insert_stale_approval(session)

    for sql in CLEANUP_SQL:
        session.execute(text(sql))
    session.commit()

    remaining = session.execute(text("SELECT COUNT(*) FROM host_approval")).scalar()
    assert remaining == 0
