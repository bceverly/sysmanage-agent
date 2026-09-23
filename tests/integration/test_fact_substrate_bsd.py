# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Fact substrate on the BSDs — ROADMAP Phase 21.1, exit-gate evidence.

These run inside the QEMU VMs spun up by .github/workflows/bsd-tests.yml,
which is the ONLY place the phase's central claim can be tested: *the
substrate works where osquery does not*. osquery has no port for OpenBSD or
NetBSD at all, and no package table on any BSD, so push-green CI on Linux
proves nothing about it. Everything here is skipped off-BSD so the same
pytest invocation still works in the cross-platform matrix.

WHY THESE EXIST AS A SEPARATE FILE
----------------------------------
The existing BSD integration tests check uname, package managers, rc.d and
pty — generic platform sanity from earlier phases. Nothing touched the fact
substrate, so dispatching bsd-tests.yml would have run 24 tests that say
nothing about 21.1 and reported success.

EVERY TEST IS MARKED ``integration``
------------------------------------
The workflow selects on ``-m integration`` and prints "No agent tests tagged
@pytest.mark.integration — exiting clean" when nothing matches, then PASSES.
An unmarked test here would not run and the job would stay green — the same
empty-green failure as the screenshot tier bug. The marker is load-bearing,
not decoration; ``test_this_module_is_marked_for_the_bsd_workflow`` asserts it
of every test in the file rather than trusting review to catch a missing one.
"""

# pylint: disable=missing-function-docstring,invalid-name

import importlib
import inspect
import json
import platform
import socket
import sys

import pytest

from src.sysmanage_agent.collection import fact_native, fact_osquery
from src.sysmanage_agent.collection.fact_providers import bootstrap_fact_providers
from src.sysmanage_agent.core import fact_schema
from src.sysmanage_agent.core.fact_store import FactStore

BSD_NAMES = {"FreeBSD", "OpenBSD", "NetBSD"}
NO_OSQUERY_BSDS = {"OpenBSD", "NetBSD"}

bsd_only = pytest.mark.skipif(
    platform.system() not in BSD_NAMES,
    reason="BSD-specific; requires platform.system() in {FreeBSD, OpenBSD, NetBSD}.",
)

# Tables the native provider must serve on ANY platform, because they come
# from the standard library or from inventory the agent already collects.
# Deliberately excludes psutil-backed tables: the BSD jobs install psutil
# best-effort (``|| true``), so demanding it would make a missing package look
# like a substrate failure.
STDLIB_BACKED = ("os_version", "system_info", "users", "groups", "mounts")


@pytest.fixture(name="substrate", scope="module")
def _substrate():
    """Providers registered exactly as the agent registers them."""
    bootstrap_fact_providers(None, force=True)
    return fact_schema.build_fact_coverage(fact_native.platform_name())


# -- the premise -------------------------------------------------------


@pytest.mark.integration
@bsd_only
def test_this_module_is_marked_for_the_bsd_workflow():
    """A test here that forgets ``@pytest.mark.integration`` never runs, and
    the workflow reports success anyway. Assert the marker instead."""
    module = sys.modules[__name__]
    tests = [
        (name, obj)
        for name, obj in vars(module).items()
        if name.startswith("test_") and inspect.isfunction(obj)
    ]
    assert tests, "no tests found — this assertion would pass vacuously"
    for name, func in tests:
        marks = {m.name for m in getattr(func, "pytestmark", [])}
        assert "integration" in marks, f"{name} is not marked integration"


@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() not in NO_OSQUERY_BSDS,
    reason="The no-osquery premise only applies to OpenBSD and NetBSD.",
)
def test_osquery_really_is_absent_here():
    """The premise the whole phase rests on.

    If osquery ever ships for OpenBSD or NetBSD this fails, and that is the
    point: the justification for building a native provider would have
    changed and we should find out from a test rather than from a rewrite.
    """
    assert fact_osquery.osquery_path() is None


@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() != "FreeBSD", reason="FreeBSD is the only BSD with a port."
)
def test_freebsd_osquery_table_inventory_is_recorded(tmp_path):
    """ROADMAP: 'WHICH cross-platform tables the FreeBSD port actually builds.
    specs/ membership is not proof the FreeBSD binary ships them.'

    Only answerable on real FreeBSD, so capture it as an artifact rather than
    hardcoding an expectation that would rot with the port.
    """
    if fact_osquery.osquery_path() is None:
        pytest.skip("osquery not installed in this FreeBSD image")
    available = sorted(fact_osquery.available_tables(refresh=True))
    contract = set(fact_schema.FACT_TABLES)
    report = {
        "platform": platform.platform(),
        "osquery_tables_total": len(available),
        "contract_tables_served_by_osquery": sorted(contract & set(available)),
        "contract_tables_missing_from_port": sorted(contract - set(available)),
    }
    out = tmp_path / "freebsd-osquery-tables.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nFreeBSD osquery inventory:\n" + json.dumps(report, indent=2))

    # The invariant 21.1 is built on: no package table on any BSD, which is
    # exactly why sysmanage_packages exists.
    for pkg_table in ("deb_packages", "rpm_packages", "homebrew_packages"):
        assert pkg_table not in available, (
            f"{pkg_table} appeared in the FreeBSD port — the premise for "
            "sysmanage_packages has changed; re-read ROADMAP 21.1 S2."
        )


# -- the substrate itself ----------------------------------------------


@pytest.mark.integration
@bsd_only
def test_substrate_imports_without_third_party_packages():
    """The design claim that makes the BSDs affordable: stdlib only.

    The OpenBSD job installs no sqlalchemy and psutil only best-effort. A
    substrate module that grew a third-party import would fail to load there
    -- on the platform the substrate exists for.
    """
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    assert stdlib, "need stdlib_module_names (py3.10+) to make this meaningful"
    allowed = stdlib | {"src"}
    for name in (
        "src.sysmanage_agent.core.fact_schema",
        "src.sysmanage_agent.core.fact_store",
        "src.sysmanage_agent.collection.fact_providers",
        "src.sysmanage_agent.collection.fact_file_state",
    ):
        module = importlib.import_module(name)
        source = inspect.getsource(module)
        for line in source.splitlines():
            line = line.strip()
            if line.startswith("import ") and " " in line:
                root = line.split()[1].split(".")[0].split(",")[0]
                assert root in allowed, f"{name} imports non-stdlib {root!r}"


@pytest.mark.integration
@bsd_only
def test_every_contract_table_lands_in_exactly_one_bucket(substrate):
    """The safety property: no table may be silently absent from the
    advertisement, because a consumer reads absence as 'nothing to report'."""
    buckets = ("served", "unsupported", "not_applicable")
    seen = {}
    for bucket in buckets:
        for table in substrate[bucket]:
            assert table not in seen, f"{table} in both {seen[table]} and {bucket}"
            seen[table] = bucket
    assert set(seen) == set(fact_schema.FACT_TABLES)
    assert substrate["contract_version"] == fact_schema.FACT_CONTRACT_VERSION


@pytest.mark.integration
@bsd_only
def test_the_stdlib_backed_tables_are_served_here(substrate):
    for table in STDLIB_BACKED:
        assert table in substrate["served"], (
            f"{table} is not served on {platform.system()}; "
            f"unsupported says {substrate['unsupported'].get(table)!r}"
        )


@pytest.mark.integration
@bsd_only
def test_served_tables_actually_collect(substrate):
    """Advertising a table and then failing to build it is worse than not
    advertising it: the consumer trusts the advertisement."""
    for table in STDLIB_BACKED:
        if table not in substrate["served"]:
            continue
        rows = fact_native.collect([table]).get(table)
        assert rows is not None, f"{table} advertised served but collected None"
        declared = set(fact_schema.columns(table))
        for row in rows[:20]:
            assert set(row) <= declared, f"{table} row has off-contract keys"


@pytest.mark.integration
@bsd_only
def test_users_and_os_version_are_not_empty():
    """Every BSD has root and a version. Zero rows here would mean the native
    provider is reporting 'measured, found nothing' about a populated host --
    the exact confusion this phase exists to remove."""
    collected = fact_native.collect(["users", "os_version"])
    assert collected["users"], "no users on a BSD — root must exist"
    assert any(r.get("username") == "root" for r in collected["users"])
    assert collected["os_version"], "os_version is empty"
    assert collected["os_version"][0].get("name")


@pytest.mark.integration
@bsd_only
def test_sysmanage_packages_serves_where_osquery_has_no_package_table(substrate):
    """THE reason the portable table exists. osquery has no package table on
    ANY BSD, so without this vulnerability matching simply would not happen
    on FreeBSD, OpenBSD or NetBSD."""
    assert "sysmanage_packages" in substrate["served"]
    rows = fact_native.collect(["sysmanage_packages"])["sysmanage_packages"]
    assert rows, "no packages found on a BSD — the package collector is silent"
    assert any(r.get("name") for r in rows)


@pytest.mark.integration
@bsd_only
def test_a_pack_written_against_osquery_runs_here():
    """End to end, and the whole portability claim in one test: contract rows
    materialised into SQLite and queried with osquery-dialect SQL, on a
    platform osquery cannot run on."""
    collected = fact_native.collect(["users", "os_version"])
    with FactStore() as store:
        for table, rows in collected.items():
            store.materialize(table, rows)
        found = store.query(
            "SELECT username, uid FROM users WHERE username = ? LIMIT 1", ["root"]
        )
        assert found and found[0]["username"] == "root"
        joined = store.query("SELECT COUNT(*) AS n FROM users")
        assert joined[0]["n"] == len(collected["users"])


@pytest.mark.integration
@bsd_only
def test_unmeasured_is_distinguishable_from_measured_empty(substrate):
    """The property the entire phase is built around, asserted on a real BSD.

    A table we do not serve must be absent from ``served`` WITH a reason --
    never served-and-empty, which a consumer cannot tell from 'measured, found
    nothing'.
    """
    unserved = set(substrate["unsupported"]) | set(substrate["not_applicable"])
    assert unserved, "expected at least one unserved table on a BSD"
    for table in unserved:
        reason = substrate["unsupported"].get(table) or substrate["not_applicable"].get(
            table
        )
        assert reason, f"{table} is unserved with no reason given"
        assert table not in substrate["served"]


@pytest.mark.integration
@bsd_only
def test_file_state_reports_absent_rather_than_nothing(tmp_path):
    """Phase 21.1 S7 on a BSD. A watched path that does not exist must come
    back as a ROW saying absent -- a missing row is indistinguishable from a
    path nobody watched."""
    present = tmp_path / "present.conf"
    present.write_text("ListenAddress 0.0.0.0\n", encoding="utf-8")
    missing = tmp_path / "definitely-not-here.conf"
    collected = fact_native.collect(
        ["sysmanage_file_state"],
        {"sysmanage_file_state": {"paths": [str(present), str(missing)]}},
    )
    rows = {r["path"]: r for r in collected["sysmanage_file_state"]}
    assert str(present) in rows and str(missing) in rows
    assert rows[str(present)]["state"] == "present"
    assert rows[str(present)]["sha256"]
    assert rows[str(missing)]["state"] == "absent"
    assert rows[str(missing)]["sha256"] is None


@pytest.mark.integration
@bsd_only
def test_listening_ports_does_not_claim_unix_sockets_it_never_looked_at(substrate):
    """Regression for the defect the S3 conformance run surfaced on
    2026-09-23: the table advertised itself SERVED while psutil's
    ``kind="inet"`` pass could not see AF_UNIX at all, so a query about unix
    sockets answered 'no rows' on a host running 1,538 of them.

    Only meaningful where the table is served (it is gated on being able to
    see EVERY socket, i.e. root), so skip rather than assert a half-truth.
    """
    if "listening_ports" not in substrate["served"]:
        pytest.skip("listening_ports is not served here (needs root); nothing to check")
    rows = fact_native.collect(["listening_ports"])["listening_ports"]
    unix = [r for r in rows if r.get("family") == int(socket.AF_UNIX)]
    for row in unix:
        assert row.get(
            "path"
        ), "an AF_UNIX row must carry its path — that is its identity"
        assert row.get("port") == 0
