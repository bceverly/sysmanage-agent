# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
In-memory fact store — ROADMAP Phase 21.1, slice S2.

WHY THIS EXISTS
---------------
A query pack is SQL.  On a host running ``osqueryd`` the daemon executes it;
on a host without one — every BSD, because osquery has no port there at all —
something else has to, or those platforms get no facts and the advisor goes
silent on them.

That something is ``sqlite3``, which is in the Python standard library and
which this agent already runs on (``agent.db``).  The native provider
materialises the contracted tables into an in-memory database and the SAME
pack SQL executes against it.  So a pack is written once, against osquery's
schema, and runs unmodified on OpenBSD and NetBSD — no second dialect, and no
new dependency on any platform.

UNTRUSTED SQL
-------------
Pack SQL is not ours.  Phase 21.1 S4 lets a TENANT author packs, so by the
time this runs the statement has crossed the network and come from a user.
Two guards, because one is not enough:

* a SQLite AUTHORIZER that permits only read operations, so a statement
  cannot INSERT, UPDATE, DELETE, ATTACH another database, or reach a
  filesystem-backed table even if it gets past the first check; and
* single-statement execution, so ``SELECT 1; DROP TABLE users`` is rejected by
  the driver rather than run as two statements.

The store is in-memory and rebuilt per collection, so there is nothing
persistent to corrupt — but "the blast radius is small" is not a reason to let
a tenant's SQL write anything at all.
"""

import sqlite3
from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.sysmanage_agent.core.fact_schema import FACT_TABLES, columns

# sqlite3 authorizer actions that a read-only query legitimately needs.
_READ_ONLY_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
)


class FactStore:
    """Contract tables materialised into SQLite, queryable with pack SQL."""

    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._materialised: List[str] = []

    # -- building ---------------------------------------------------------

    def materialize(self, table: str, rows: Sequence[Mapping[str, Any]]) -> None:
        """Create ``table`` with its CONTRACT columns and insert ``rows``.

        Columns come from the contract, not from the rows, so a column no
        provider fills reads as NULL rather than failing the query — which is
        what lets a published pack select a column we do not populate and
        still run.  Keys in a row that are not contract columns are ignored:
        a collector growing a new field must not break every pack on the host.
        """
        if table not in FACT_TABLES:
            raise KeyError(f"{table!r} is not in the fact contract")
        cols = columns(table)
        # Identifiers are contract constants, never user input -- the
        # authorizer below is what defends the QUERY side.
        col_sql = ", ".join(f'"{c}"' for c in cols)
        self._conn.execute(f'CREATE TABLE "{table}" ({col_sql})')  # nosec B608
        placeholders = ", ".join("?" for _ in cols)
        self._conn.executemany(
            f'INSERT INTO "{table}" ({col_sql}) VALUES ({placeholders})',  # nosec B608
            [tuple(row.get(c) for c in cols) for row in rows],
        )
        self._conn.commit()
        self._materialised.append(table)

    @property
    def tables(self) -> List[str]:
        """Tables present in this store, in materialisation order."""
        return list(self._materialised)

    # -- querying ---------------------------------------------------------

    def query(
        self, sql: str, params: Optional[Sequence[Any]] = None
    ) -> List[Dict[str, Any]]:
        """Run ONE read-only statement and return rows as dicts.

        Raises ``sqlite3.DatabaseError`` if the statement tries to write, or if
        more than one statement is supplied.  Both are refusals, not
        best-effort: a pack that wants to write is not a pack we ran wrong, it
        is a pack we must not run.
        """
        self._conn.set_authorizer(_authorizer)
        try:
            cursor = self._conn.execute(sql, tuple(params or ()))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            # Lifted immediately: materialize() legitimately writes, and a
            # store left authorised read-only could not be rebuilt.
            self._conn.set_authorizer(None)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "FactStore":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


def _authorizer(action: int, *_args: Any) -> int:
    """Permit reads, refuse everything else."""
    return sqlite3.SQLITE_OK if action in _READ_ONLY_ACTIONS else sqlite3.SQLITE_DENY
