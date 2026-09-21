# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
osquery fact provider — ROADMAP Phase 21.1, slice S3.

WHAT THIS IS
------------
The same contract tables, served by ``osqueryi`` where it exists: Linux,
macOS, Windows and FreeBSD.  It is an ACCELERATOR, not the floor -- the native
provider (S2) is the floor, and it is what OpenBSD and NetBSD use, because
osquery has no port there at all.

WHICH TABLES, AND WHY WE ASK OSQUERY RATHER THAN ASSUME
-------------------------------------------------------
The served set is DERIVED by asking the binary what it has
(``osquery_registry``), never hand-listed.  The same rule ``capabilities.py``
states at length applies here for a sharper reason than usual: osquery's table
set genuinely differs per platform and per build.  The FreeBSD port has no
package tables at all, and a hand-maintained list would claim tables that
return "no such table" at query time -- which a pack reads as an error, or
worse, as zero rows.

DEGRADING RATHER THAN DISAPPEARING
----------------------------------
FreeBSD's port carries seven downstream patches from a maintainer's personal
fork.  When it breaks, the right answer is the NATIVE provider, not "no
facts".  That is why the probe here is allowed to fail: ``_choose_provider``
walks past an unhealthy provider to the next one, so a broken osqueryd costs
fidelity, never coverage.

TYPES
-----
``osqueryi --json`` returns EVERY column as a string -- ``"0"``, not ``0``.
The native provider returns real ints.  That is not a bug on either side, but
it means the two cannot be compared directly, which is what
``conformance_diff`` exists to handle.
"""

import json
import logging
import platform
import shutil
import subprocess  # nosec B404 - fixed argv, no shell; see _run
from typing import Any, Dict, List, Optional, Sequence, Set

from src.sysmanage_agent.core.fact_schema import (
    FACT_TABLES,
    PROVIDER_OSQUERY,
    REASON_MISSING_TOOL,
    register_provider,
)

logger = logging.getLogger(__name__)

# Where the binary usually lives when it is not on PATH -- a service account's
# PATH is frequently not an operator's.
_CANDIDATE_PATHS = (
    "/usr/bin/osqueryi",
    "/usr/local/bin/osqueryi",
    "/opt/osquery/bin/osqueryi",
    "/usr/local/osquery/bin/osqueryi",
    r"C:\Program Files\osquery\osqueryi.exe",
)

_QUERY_TIMEOUT_SECONDS = 60

# Flags for every invocation.
#
# ``--disable_extensions``: we query only CORE osquery tables -- all fourteen
# of the osquery-origin contract tables are built in -- so loading a site's
# extensions buys nothing and adds code to our process's blast radius.  It
# also keeps discovery honest: ``osquery_registry`` is read under the SAME
# flags, so a table we cannot load is a table we never claim.
#
# NOT passed: ``--database_path``.  osqueryi defaults to an ephemeral database
# of its own, which is precisely what lets it run alongside an osqueryd that
# holds the RocksDB lock.  Pointing the two at one path is how you get "IO
# error: lock hold by current process" on a host where both are wanted.
_FLAGS = ("--json", "--disable_extensions")

# Tables this platform's osquery build HAS but must not be used for, keyed by
# ``platform.system().lower()``.
#
# This is not defensiveness in the abstract. Measured on FreeBSD
# 14.4-RELEASE-p8 with the 5.23.0 port on 2026-09-21: ``listening_ports``
# returned 459 rows of which 425 had ``port = 0``, while emitting
# ``kinfo_getfile(): No such process`` to stderr. The real listeners on that
# host were 22, 123, 443, 514, 3000 and 43045, which the NATIVE provider
# reported correctly.
#
# The table is present and the probe says healthy, so nothing in the ordinary
# path would decline it -- and because osquery is preferred when healthy,
# enabling it on FreeBSD would REPLACE correct native data with garbage. That
# is the "fragile leg" the phase plan predicted, arriving exactly where it was
# predicted: a port carrying seven downstream patches from a personal fork.
#
# Named, not detected. A data-quality heuristic would be guessing at what
# garbage looks like; a named table with a measured reason is auditable, and
# it is removed the day the port is fixed.
_DENYLIST: Dict[str, Dict[str, str]] = {
    "freebsd": {
        # Measured 2026-09-21: 0 rows on a host whose CA bundle holds 118
        # certificates, which the native provider reads. An empty answer from
        # a table that HAS the data available is the worst kind -- it is
        # indistinguishable from "this host has no certificates".
        "certificates": (
            "the FreeBSD osquery port returns 0 certificates on a host with a "
            "118-certificate CA bundle; the native provider reads them"
        ),
        "listening_ports": (
            "the FreeBSD osquery port returns mostly port=0 rows "
            "(measured 425 of 459 on 5.23.0); the native provider is correct"
        ),
    },
}


def denied_tables(platform_name: Optional[str] = None) -> Dict[str, str]:
    """{table: reason} this platform must not read through osquery."""
    name = (platform_name or platform.system()).lower()
    return dict(_DENYLIST.get(name, {}))


# Memoised: build_fact_coverage() probes every table, and shelling out per
# table would mean sixteen subprocess launches per report.
_available_tables: Optional[Set[str]] = None


def osquery_path() -> Optional[str]:
    """The osqueryi binary, or None when this host has none."""
    found = shutil.which("osqueryi")
    if found:
        return found
    for candidate in _CANDIDATE_PATHS:
        if shutil.which(candidate):
            return candidate
    return None


def _run(sql: str, binary: Optional[str] = None) -> List[Dict[str, Any]]:
    """Execute one statement through ``osqueryi --json``.

    No shell: argv is a fixed list, so the SQL is one argument and cannot be
    re-parsed by a shell however it is written.  osquery itself is read-only
    with respect to the host, which matters from S4 onward when the statement
    is tenant-authored.
    """
    path = binary or osquery_path()
    if not path:
        raise FileNotFoundError("osqueryi not found")
    result = subprocess.run(  # nosec B603 - fixed argv, no shell
        [path, *_FLAGS, sql],
        capture_output=True,
        text=True,
        timeout=_QUERY_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"osqueryi exited {result.returncode}: {result.stderr.strip()[:200]}"
        )
    payload = json.loads(result.stdout or "[]")
    return payload if isinstance(payload, list) else []


def available_tables(refresh: bool = False) -> Set[str]:
    """Contract tables this osquery build actually has.

    Asked of the binary, then intersected with the contract.  An empty set is
    the honest answer when osquery is absent or unhealthy, and the caller
    reports the table unsupported rather than serving a query that would fail.
    """
    global _available_tables  # pylint: disable=global-statement
    if _available_tables is not None and not refresh:
        return _available_tables
    try:
        rows = _run(
            "SELECT name FROM osquery_registry "
            "WHERE registry = 'table' AND active = 1"
        )
        names = {str(row.get("name")) for row in rows}
    except Exception as exc:  # pylint: disable=broad-except
        logger.info("osquery unavailable for fact collection: %s", exc)
        names = set()
    # sysmanage_* tables are ours by definition; osquery never serves them.
    # Denylisted tables are dropped HERE rather than at query time, so they
    # never enter the served set and coverage reports them against the native
    # provider -- the host keeps the table, and keeps a correct answer.
    denied = denied_tables()
    for table, reason in denied.items():
        if table in names:
            logger.info(
                "osquery has %s on this platform but it is denylisted: %s",
                table,
                reason,
            )
    _available_tables = {
        name
        for name in names
        if name in FACT_TABLES
        and not name.startswith("sysmanage_")
        and name not in denied
    }
    return _available_tables


def reset_cache() -> None:
    """Forget the probed table set — for tests and for agent restart paths."""
    global _available_tables  # pylint: disable=global-statement
    _available_tables = None


def register_osquery_provider(enabled: bool = True) -> None:
    """Register osquery for every contract table this build actually has.

    ``enabled`` is the operator's opt-in.  When it is off nothing is
    registered, so coverage reports the native provider and says so -- the
    host is not silently using osquery because it happened to be installed.
    """
    if not enabled:
        return
    for table in sorted(available_tables()):
        register_provider(
            table,
            PROVIDER_OSQUERY,
            lambda t=table: t in available_tables(),
            REASON_MISSING_TOOL,
        )


def collect(tables: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Read each table through osquery. A table that fails is OMITTED.

    Omitted, not empty: an empty list here would be indistinguishable from
    "measured, found none", and the caller decides what to do about a table it
    asked for and did not get.
    """
    collected: Dict[str, List[Dict[str, Any]]] = {}
    for table in tables:
        try:
            collected[table] = _run(f"SELECT * FROM {table}")  # nosec B608
        except Exception:  # pylint: disable=broad-except
            logger.exception("osquery could not read %s", table)
    return collected


def _comparable(rows: Sequence[Dict[str, Any]], columns: Sequence[str]):
    """Rows reduced to comparable form: chosen columns, values as strings.

    osqueryi returns every value as a string and the native provider returns
    real types, so a raw diff would report every row as different and tell us
    nothing.  Normalising both sides is what makes the comparison about the
    FACTS rather than about JSON typing.
    """
    out = []
    for row in rows:
        out.append(
            tuple("" if row.get(col) is None else str(row.get(col)) for col in columns)
        )
    return sorted(out)


def conformance_diff(
    columns: Sequence[str],
    native_rows: Sequence[Dict[str, Any]],
    osquery_rows: Sequence[Dict[str, Any]],
) -> Dict[str, List[Any]]:
    """Rows the two providers disagree on, over ``columns``.

    Compared on a chosen column subset because the providers legitimately fill
    different amounts of a table: native leaves ``users.gid`` NULL on purpose,
    and demanding equality there would flag every row while saying nothing
    about whether the two agree on who the users ARE.
    """
    native = _comparable(native_rows, columns)
    osquery = _comparable(osquery_rows, columns)
    native_only = [row for row in native if row not in osquery]
    osquery_only = [row for row in osquery if row not in native]
    return {"native_only": native_only, "osquery_only": osquery_only}
