# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.core.fact_store`` -- Phase 21.1 S2.

Two properties carry this module.  The first is that a column no provider
fills reads as NULL, because that is what lets a PUBLISHED osquery pack run
here unmodified.  The second is that tenant-authored pack SQL cannot write:
by S4 that statement has crossed the network from a user, and "the store is
in-memory anyway" is not a reason to let it try.
"""

import sqlite3
from keyword import iskeyword

import pytest

from src.sysmanage_agent.core.fact_schema import FACT_COLUMNS, FACT_TABLES
from src.sysmanage_agent.core.fact_store import FactStore


@pytest.fixture(name="store")
def _store():
    with FactStore() as store:
        yield store


def test_unfilled_contract_columns_read_as_null(store):
    store.materialize("users", [{"uid": 0, "username": "root"}])
    row = store.query("SELECT username, shell, is_hidden FROM users")[0]
    assert row["username"] == "root"
    assert row["shell"] is None and row["is_hidden"] is None


def test_keys_outside_the_contract_are_ignored_not_fatal(store):
    # A collector growing a field must not break every pack on the host.
    store.materialize("users", [{"username": "root", "favourite_colour": "blue"}])
    assert store.query("SELECT username FROM users") == [{"username": "root"}]


def test_a_table_outside_the_contract_is_refused(store):
    with pytest.raises(KeyError):
        store.materialize("not_a_table", [])


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO users (uid) VALUES (1)",
        "UPDATE users SET username = 'x'",
        "DELETE FROM users",
        "DROP TABLE users",
        "CREATE TABLE evil (x)",
        "ATTACH DATABASE '/tmp/x.db' AS x",
    ],
)
def test_pack_sql_cannot_write(store, sql):
    store.materialize("users", [{"uid": 0, "username": "root"}])
    with pytest.raises(sqlite3.DatabaseError):
        store.query(sql)
    # and the data is untouched
    assert store.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 1


def test_a_second_statement_is_refused(store):
    store.materialize("users", [{"uid": 0, "username": "root"}])
    with pytest.raises(sqlite3.DatabaseError):
        store.query("SELECT 1; DROP TABLE users")


def test_reads_still_work_after_a_refusal(store):
    """The authorizer must be lifted again, or one bad pack would brick the
    store for every pack after it in the same pass."""
    store.materialize("users", [{"uid": 0, "username": "root"}])
    with pytest.raises(sqlite3.DatabaseError):
        store.query("DELETE FROM users")
    store.materialize("groups", [{"gid": 0, "groupname": "root"}])
    assert store.query("SELECT groupname FROM groups") == [{"groupname": "root"}]


def test_the_store_survives_many_refusals(store):
    """Guards a defect that only existed on CPython 3.9 and 3.10.

    ``set_authorizer(None)`` does not reset before 3.11: the read-only
    authorizer stayed installed, so the FIRST query permanently denied every
    later materialize() and the store could never be rebuilt. One refused pack
    would have taken the whole collection pass down with it on those
    interpreters, for the rest of the process's life.

    Looping rather than asserting once: the bug was cumulative state, and a
    single round trip is exactly what the original test did and missed.
    """
    for i in range(3):
        store.materialize("users", [{"uid": i, "username": f"u{i}"}])
        with pytest.raises(sqlite3.DatabaseError):
            store.query("DELETE FROM users")
        assert store.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 1
        store.query("SELECT 1 AS ok")
        store._conn.execute("DROP TABLE users")  # pylint: disable=protected-access


def test_multi_statement_refusal_is_a_database_error(store):
    """The documented contract, on every supported interpreter.

    3.9 and 3.10 raise ``sqlite3.Warning`` for a multi-statement execute and
    3.11+ raise ``ProgrammingError``. Warning does NOT inherit DatabaseError,
    so a caller following this method's docstring would have caught nothing on
    the older ones -- "SELECT 1; DROP TABLE users" refused, then the refusal
    itself missed.
    """
    store.materialize("users", [{"uid": 0, "username": "root"}])
    with pytest.raises(sqlite3.DatabaseError):
        store.query("SELECT 1; DROP TABLE users")


def test_parameters_are_bound_not_interpolated(store):
    store.materialize("users", [{"uid": 0, "username": "root"}])
    assert store.query("SELECT uid FROM users WHERE username = ?", ["root"]) == [
        {"uid": 0}
    ]


def test_contract_identifiers_are_bare():
    """Keeps the ``# nosemgrep`` on the CREATE TABLE in materialize() honest.

    SQLite cannot parameterize an identifier, so that DDL interpolates the
    table and column names directly. What makes that safe is not the quoting
    -- it is that both come from the contract. Nothing stops a later edit from
    adding a name with a quote, a space or a semicolon in it, and at that point
    the suppression would be covering a real injection rather than a false
    positive. Assert the premise rather than trust a future reader to re-derive
    it from two files away.
    """
    names = set(FACT_TABLES) | {c for cols in FACT_COLUMNS.values() for c in cols}
    assert names
    for name in sorted(names):
        assert name.isidentifier(), name
        assert not iskeyword(name), name


def test_every_contract_table_materializes(store):
    """The identifier check above is only worth something if these names are
    the ones actually fed to CREATE TABLE."""
    for table in FACT_TABLES:
        store.materialize(table, [])
    assert set(store.tables) == set(FACT_TABLES)
