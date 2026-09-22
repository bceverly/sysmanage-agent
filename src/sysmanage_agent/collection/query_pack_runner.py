# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Run a query pack against this host's facts — ROADMAP Phase 21.1, slice S4.

S1-S3 built the substrate: a contract of osquery-schema tables, a native
provider that fills them everywhere, an osquery provider that fills them
faster where it exists, and a SQLite store the pack SQL runs against.  This is
what finally executes a pack.

WHAT ARRIVES HERE IS UNTRUSTED
------------------------------
From S4 a pack can be tenant-authored, so the SQL has crossed the network and
come from a user.  Three independent guards, because any one of them could be
bypassed by a change nobody connected to this file:

1. the SERVER's licensed engine refuses a statement that is not a single
   read before it is ever dispatched;
2. ``FactStore.query`` runs it under a sqlite3 authorizer permitting only
   SELECT/READ, and rejects multiple statements; and
3. the store is in-memory and rebuilt per run, so there is nothing persistent
   to reach even if the first two were defeated.

An agent too old to have (2) is exactly why (1) exists, and a server that
never got the engine is exactly why (2) does.

ONLY THE DECLARED TABLES ARE MATERIALISED
-----------------------------------------
A query declares the tables it reads (``required_tables``), and only those are
built.  Collecting all sixteen for a pack that reads one would make a
one-table query cost as much as a full inventory sweep, on every host, every
interval.  The cost of the declaration being wrong is a clean "no such table"
error on that query alone -- not a wrong answer, which is the trade we want.

NOT MEASURED IS NOT EMPTY
-------------------------
A query whose tables this host does not serve comes back ``not_covered`` with
the agent's own reason code, never as zero rows.  The server grades such a run
``partial`` rather than ``success``, so a host that could not answer never
reads as a host that answered "nothing".
"""

import logging
import sqlite3
from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.sysmanage_agent.collection import fact_native, fact_osquery
from src.sysmanage_agent.collection.fact_providers import bootstrap_fact_providers
from src.sysmanage_agent.core.fact_schema import (
    FACT_CONTRACT_VERSION,
    FACT_TABLES,
    PROVIDER_OSQUERY,
    build_fact_coverage,
)
from src.sysmanage_agent.core.fact_store import FactStore

logger = logging.getLogger(__name__)

QUERY_STATUS_OK = "ok"
QUERY_STATUS_NOT_COVERED = "not_covered"
QUERY_STATUS_ERROR = "error"

REASON_NOT_IN_CONTRACT = "not_in_contract"
REASON_NOT_COVERED = "not_covered"

# A pack that returns a million rows would be a denial of service against the
# store-and-forward queue rather than a useful measurement, so each query is
# capped and the result says so. Truncating LOUDLY is the point: a silently
# clipped result set is a wrong answer.
MAX_ROWS_PER_QUERY = 10000


def _materialize(
    store: FactStore,
    tables: Sequence[str],
    coverage,
    table_params=None,
) -> Dict[str, str]:
    """Build the requested tables. Returns {table: reason} for those we cannot.

    The provider is chosen per table by the coverage advertisement, so this
    honours exactly the same decision the server was told about -- a host that
    advertised ``users: osquery`` reads users through osquery here.
    """
    served = (coverage or {}).get("served") or {}
    unsupported = (coverage or {}).get("unsupported") or {}
    not_applicable = (coverage or {}).get("not_applicable") or {}

    wanted: List[str] = []
    refused: Dict[str, str] = {}
    for table in tables:
        if table not in FACT_TABLES:
            refused[table] = REASON_NOT_IN_CONTRACT
        elif table in served:
            wanted.append(table)
        else:
            refused[table] = (
                unsupported.get(table)
                or not_applicable.get(table)
                or REASON_NOT_COVERED
            )

    by_provider: Dict[str, List[str]] = {}
    for table in wanted:
        by_provider.setdefault(served[table], []).append(table)

    collected: Dict[str, List[Dict[str, Any]]] = {}
    for provider, provider_tables in by_provider.items():
        if provider == PROVIDER_OSQUERY:
            collected.update(fact_osquery.collect(provider_tables))
        else:
            collected.update(fact_native.collect(provider_tables, table_params))

    for table in wanted:
        rows = collected.get(table)
        if rows is None:
            # The provider advertised the table and then could not read it.
            # That is a provider failure, not an empty table, and it must not
            # become one -- so the query that needs it is not-covered rather
            # than answered against a table that was never built.
            refused[table] = "provider_failed"
            continue
        if table not in store.tables:
            store.materialize(table, rows)
    return refused


def _run_one(store: FactStore, query: Mapping[str, Any], refused: Mapping[str, str]):
    """Execute one query. Never raises — a bad query fails only itself."""
    name = str(query.get("name") or "")
    required = list(query.get("required_tables") or [])

    missing = [t for t in required if t in refused]
    if missing:
        return {
            "name": name,
            "status": QUERY_STATUS_NOT_COVERED,
            "reason": refused[missing[0]],
            "rows": [],
        }

    sql = query.get("sql") or ""
    try:
        rows = store.query(sql)
    except sqlite3.DatabaseError as exc:
        # Includes the authorizer's refusal of a write, and the driver's
        # refusal of a second statement. Both are the guard working.
        logger.warning("query pack query %s refused or failed: %s", name, exc)
        return {
            "name": name,
            "status": QUERY_STATUS_ERROR,
            "error": str(exc),
            "rows": [],
        }
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("query pack query %s raised", name)
        return {
            "name": name,
            "status": QUERY_STATUS_ERROR,
            "error": str(exc),
            "rows": [],
        }

    truncated = len(rows) > MAX_ROWS_PER_QUERY
    return {
        "name": name,
        "status": QUERY_STATUS_OK,
        "rows": rows[:MAX_ROWS_PER_QUERY],
        "row_count": len(rows),
        "truncated": truncated,
    }


def run_pack(pack: Mapping[str, Any], config: Optional[Any] = None) -> Dict[str, Any]:
    """Run every query in ``pack`` and return the per-query outcomes.

    ``pack`` is what the server's engine built: ``{"pack_name", "pack_id",
    "shared_pack_id", "version", "queries": [{"name","sql","required_tables"}]}``.

    Always returns a result. A pack that could not run at all still reports
    the contract version and an empty result list, because "the agent said
    nothing" and "the agent said it could measure nothing" are different
    facts and the server grades them differently.
    """
    bootstrap_fact_providers(config)
    coverage = build_fact_coverage(fact_native.platform_name())

    queries = list(pack.get("queries") or [])
    needed: List[str] = []
    for query in queries:
        for table in query.get("required_tables") or []:
            if table not in needed:
                needed.append(table)

    results: List[Dict[str, Any]] = []
    store = FactStore()
    try:
        # Parameters the SERVER holds as policy and the host cannot know --
        # currently the file watch list. Absent for every pack that does not
        # use a parameterized table, which is all of them before S7.
        refused = _materialize(store, needed, coverage, pack.get("table_params") or {})
        for query in queries:
            results.append(_run_one(store, query, refused))
    finally:
        store.close()

    # Queries the SERVER already knew this host could not answer travel in the
    # dispatch so they are recorded here rather than silently absent -- the
    # run then accounts for every query in the pack, not just the ones that
    # were attempted.
    for skipped in pack.get("not_covered") or []:
        results.append(
            {
                "name": skipped.get("name"),
                "status": QUERY_STATUS_NOT_COVERED,
                "reason": skipped.get("reason") or REASON_NOT_COVERED,
                "rows": [],
            }
        )

    return {
        # ECHOED, not generated: the server opened a run row before queuing
        # this command and correlates the results by that id. Leaving it out
        # is not a partial failure -- the measurements come back, the server
        # cannot tell which run they belong to, and it discards all of them.
        # That is exactly what happened on the first live round trip
        # (2026-09-21): both hosts ran all three queries and the server logged
        # "results arrived for run None ... 3 result(s) discarded".
        "run_id": pack.get("run_id"),
        "pack_name": pack.get("pack_name"),
        "pack_id": pack.get("pack_id"),
        "shared_pack_id": pack.get("shared_pack_id"),
        "version": pack.get("version"),
        "contract_version": FACT_CONTRACT_VERSION,
        "results": results,
    }
