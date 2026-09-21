# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.core.fact_store`` — Phase 21.1 S2.

Two properties carry this module.  The first is that a column no provider
fills reads as NULL, because that is what lets a PUBLISHED osquery pack run
here unmodified.  The second is that tenant-authored pack SQL cannot write:
by S4 that statement has crossed the network from a user, and "the store is
in-memory anyway" is not a reason to let it try.
"""

import sqlite3

import pytest

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


def test_parameters_are_bound_not_interpolated(store):
    store.materialize("users", [{"uid": 0, "username": "root"}])
    assert store.query("SELECT uid FROM users WHERE username = ?", ["root"]) == [
        {"uid": 0}
    ]
