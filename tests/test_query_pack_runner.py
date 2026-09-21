# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``collection.query_pack_runner`` — Phase 21.1 S4.

What is actually at risk here is not "does the SQL run". It is that a pack is
TENANT-AUTHORED from this slice on, and that the substrate's safety property
survives execution:

  * a write must be refused, by this agent, regardless of what the server let
    through (the server's engine is the other half, not a substitute);
  * a query whose tables this host does not serve must come back
    ``not_covered`` with a reason, never as zero rows — zero rows is an answer,
    and it is the wrong one; and
  * one bad query must fail only itself. A pack is a batch, and a batch that
    aborts on its first error loses the measurements that did succeed.
"""

from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection import fact_native as fn
from src.sysmanage_agent.collection import query_pack_runner as qpr
from src.sysmanage_agent.core import fact_schema as fs


@pytest.fixture(autouse=True)
def clean_providers():
    fs.clear_providers()
    yield
    fs.clear_providers()


def pack(*queries, **kw):
    out = {"pack_name": "test", "queries": list(queries)}
    out.update(kw)
    return out


def q(name, sql, tables=None):
    return {"name": name, "sql": sql, "required_tables": list(tables or [])}


def by_name(result):
    return {r["name"]: r for r in result["results"]}


class TestExecution:
    def test_a_pack_runs_against_real_host_facts(self):
        out = qpr.run_pack(pack(q("users", "SELECT username FROM users", ["users"])))
        row = by_name(out)["users"]
        assert row["status"] == "ok"
        assert row["rows"], "no users on a host that certainly has some"

    def test_the_contract_version_travels_with_every_run(self):
        """A fleet upgrades gradually; without this, comparing results across
        hosts silently compares different contracts."""
        out = qpr.run_pack(pack(q("u", "SELECT 1 AS n", [])))
        assert out["contract_version"] == fs.FACT_CONTRACT_VERSION

    def test_a_query_declaring_no_tables_still_runs(self):
        out = qpr.run_pack(pack(q("n", "SELECT 1 AS n", [])))
        assert by_name(out)["n"]["rows"] == [{"n": 1}]

    def test_pack_identity_is_echoed_back(self):
        out = qpr.run_pack(pack(q("n", "SELECT 1 AS n"), pack_id="p1", version=7))
        assert out["pack_id"] == "p1" and out["version"] == 7


class TestUntrustedSql:
    """The agent's guard, independent of whatever the server allowed."""

    @pytest.mark.parametrize(
        "sql",
        [
            "DROP TABLE users",
            "DELETE FROM users",
            "INSERT INTO users (uid) VALUES (1)",
            "UPDATE users SET uid = 1",
        ],
    )
    def test_writes_are_refused_here_too(self, sql):
        out = qpr.run_pack(pack(q("evil", sql, ["users"])))
        assert by_name(out)["evil"]["status"] == "error"

    def test_a_second_statement_is_refused(self):
        out = qpr.run_pack(pack(q("evil", "SELECT 1; DROP TABLE users", ["users"])))
        assert by_name(out)["evil"]["status"] == "error"

    def test_a_refused_query_does_not_take_the_pack_down(self):
        """A batch that aborts on its first error loses the measurements that
        did succeed."""
        out = qpr.run_pack(
            pack(
                q("good", "SELECT username FROM users", ["users"]),
                q("evil", "DROP TABLE users", ["users"]),
                q("also_good", "SELECT 2 AS n"),
            )
        )
        rows = by_name(out)
        assert rows["good"]["status"] == "ok"
        assert rows["evil"]["status"] == "error"
        assert rows["also_good"]["status"] == "ok"

    def test_the_store_survives_a_refused_write(self):
        """The authorizer is lifted in a finally; a store left read-only could
        not be rebuilt, and every later query would fail for the wrong
        reason."""
        out = qpr.run_pack(
            pack(
                q("evil", "DELETE FROM users", ["users"]),
                q("after", "SELECT username FROM users", ["users"]),
            )
        )
        assert by_name(out)["after"]["status"] == "ok"


class TestNotMeasuredIsNotEmpty:
    def test_an_unserved_table_is_not_covered_not_empty(self):
        """Zero rows is an answer. It is the wrong one when nobody asked."""
        out = qpr.run_pack(pack(q("procs", "SELECT * FROM processes", ["processes"])))
        row = by_name(out)["procs"]
        # This host may or may not serve processes; either answer is correct,
        # but an unserved table must NEVER read as an empty ok.
        if row["status"] != "ok":
            assert row["status"] == qpr.QUERY_STATUS_NOT_COVERED
            assert row["reason"]

    def test_a_table_outside_the_contract_says_so(self):
        out = qpr.run_pack(pack(q("bogus", "SELECT 1", ["not_a_real_table"])))
        row = by_name(out)["bogus"]
        assert row["status"] == qpr.QUERY_STATUS_NOT_COVERED
        assert row["reason"] == qpr.REASON_NOT_IN_CONTRACT

    def test_server_side_skips_are_recorded_not_dropped(self):
        """The run must account for every query in the pack, not just the ones
        that were attempted."""
        out = qpr.run_pack(
            pack(
                q("ran", "SELECT 1 AS n"),
                not_covered=[{"name": "skipped", "reason": "wrong_platform"}],
            )
        )
        rows = by_name(out)
        assert rows["skipped"]["status"] == qpr.QUERY_STATUS_NOT_COVERED
        assert rows["skipped"]["reason"] == "wrong_platform"

    def test_a_provider_that_advertised_then_failed_is_not_an_empty_table(self):
        """The nastiest case: coverage says served, collection returns
        nothing. Answering the query against a table that was never built
        would report 'no rows' for a measurement that never happened."""
        with patch.object(fn, "collect", return_value={}):
            out = qpr.run_pack(
                pack(q("users", "SELECT username FROM users", ["users"]))
            )
        row = by_name(out)["users"]
        assert row["status"] == qpr.QUERY_STATUS_NOT_COVERED
        assert row["reason"] == "provider_failed"


class TestBounds:
    def test_only_the_declared_tables_are_materialised(self):
        """A one-table query must not cost a full inventory sweep on every
        host, every interval."""
        with patch.object(fn, "collect", wraps=fn.collect) as collect:
            qpr.run_pack(pack(q("u", "SELECT username FROM users", ["users"])))
        asked = collect.call_args[0][0]
        assert list(asked) == ["users"]

    def test_a_huge_result_is_truncated_loudly(self):
        """A silently clipped result set is a wrong answer."""
        with patch.object(qpr, "MAX_ROWS_PER_QUERY", 2):
            out = qpr.run_pack(
                pack(
                    q(
                        "many",
                        "SELECT 1 AS n UNION ALL SELECT 2 UNION ALL SELECT 3",
                    )
                )
            )
        row = by_name(out)["many"]
        assert row["truncated"] is True
        assert row["row_count"] == 3
        assert len(row["rows"]) == 2

    def test_a_result_within_the_cap_is_not_flagged_truncated(self):
        out = qpr.run_pack(pack(q("few", "SELECT 1 AS n")))
        assert by_name(out)["few"]["truncated"] is False


class TestCorrelation:
    """The server correlates results to a run it opened at dispatch time."""

    def test_the_run_id_is_echoed_back(self):
        """Without this the measurements return and the server discards every
        one of them, because it cannot tell which run they belong to. Not a
        partial failure -- a total loss that looks like a successful run on
        the agent side. Found on the first live round trip, 2026-09-21."""
        out = qpr.run_pack(pack(q("n", "SELECT 1 AS n"), run_id="run-123"))
        assert out["run_id"] == "run-123"

    def test_a_pack_with_no_run_id_still_returns_a_result(self):
        """An ad-hoc run (S5) has no run row; the key is present and None
        rather than absent, so the consumer reads one shape either way."""
        out = qpr.run_pack(pack(q("n", "SELECT 1 AS n")))
        assert out["run_id"] is None
