#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""
Fact provider conformance harness -- ROADMAP Phase 21.1, slice S3.

WHAT IT ANSWERS
---------------
"Does a pack written against osquery get the same answer from our native
provider?"  That question cannot be settled by unit tests: they assert that
the collector fills ``directory`` rather than ``home_directory``, which is a
statement about our code.  Whether the RESULTING ROWS match what osquery
reports on the same live host is a statement about the world, and only a
real host with both providers can make it.

Run it on a host that has osquery -- a Linux, macOS or FreeBSD box:

    python3 scripts/fact_conformance.py                 # every shared table
    python3 scripts/fact_conformance.py users groups    # only these
    python3 scripts/fact_conformance.py --json          # machine-readable

WHY IT IS COVERAGE-AWARE RATHER THAN A BLIND DIFF
-------------------------------------------------
Two differences are EXPECTED and reporting them as failures would bury the
real ones:

  * A table only one provider serves is not a disagreement.  FreeBSD's
    osquery port has no package tables at all; skipping is the correct
    finding, and the harness says so rather than counting zero rows as a
    mismatch.
  * Privilege.  ``listening_ports`` from an unprivileged process sees only
    that process's own sockets, so a root osqueryd and a non-root agent
    legitimately disagree -- about privilege, not about facts.  Those tables
    are flagged, and comparing them means running this as root on both sides.

Comparison is on the IDENTIFYING columns below rather than on whole rows.
The native provider leaves some contract columns NULL on purpose (it does not
invent a ``uid_signed``), and demanding equality there would flag every row
while saying nothing about whether the two agree on who the users ARE.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# pylint: disable=wrong-import-position
from src.sysmanage_agent.collection import fact_native, fact_osquery  # noqa: E402
from src.sysmanage_agent.collection.fact_providers import (  # noqa: E402
    bootstrap_fact_providers,
)
from src.sysmanage_agent.core import fact_schema  # noqa: E402

# What makes a row THE SAME ROW.  Chosen to be what a pack would join or group
# on, not what is merely present.
IDENTIFYING = {
    "os_version": ("name", "version", "platform"),
    "system_info": ("hostname",),
    "users": ("username", "uid", "directory", "shell"),
    "groups": ("groupname", "gid"),
    "user_groups": ("uid", "gid"),
    "interface_addresses": ("interface", "address"),
    # ``path`` is load-bearing, not decoration: an AF_UNIX row carries its
    # identity THERE and reports port 0, protocol 0 and an empty address. With
    # only the first three columns every unix socket on the host collapses to
    # the same ('0', '0', '') tuple, so the 2026-09-23 run printed 920
    # indistinguishable rows and said nothing about which sockets differed.
    "listening_ports": ("port", "protocol", "address", "path"),
    "processes": ("pid", "name"),
    # NOT ``path``: the two providers answer "where did I read this" with
    # different conventions -- native names the individual .pem it parsed,
    # osquery names the ca-certificates.crt bundle it read every cert out of
    # (122 distinct native paths against 1 for osquery). Including it made
    # every single row differ and hid whether they agree on which
    # CERTIFICATES exist, which is the question. common_name + serial is a
    # real identity both providers populate: 122/121 disagreements became 7/6.
    "certificates": ("common_name", "serial"),
    "mounts": ("device", "path", "type"),
    "deb_packages": ("name", "version", "arch"),
    "rpm_packages": ("name", "version", "release"),
    "homebrew_packages": ("name", "version"),
    "programs": ("name", "version"),
}

# Tables whose content depends on the privilege of the reader, not on the
# provider.  A difference here is a finding about how the harness was run.
PRIVILEGE_SENSITIVE = ("listening_ports", "processes")

# Differences that are neither provider's fault and will never go away, keyed
# by (platform, table).  Reported WITH the explanation rather than suppressed:
# a pack author needs to know the two providers answer differently here, and
# hiding it would make the report look cleaner than the world is.
KNOWN_PLATFORM_DIFFERENCES = {
    ("linux", "processes"): (
        "Linux keeps only TASK_COMM_LEN-1 (15) characters of a process name "
        "in comm, which is what osquery reports; psutil reads the full name "
        "from the arguments -- 'gnome-terminal-server' vs 'gnome-terminal-'. "
        "Same trap as FreeBSD, different width. A pack matching "
        "processes.name exactly WILL differ by provider; prefer LIKE, or "
        "match on path."
    ),
    ("linux", "certificates"): (
        "PATH CONVENTION, not missing data. The native provider walks "
        "/etc/ssl/certs and reports the individual .pem it parsed; osquery "
        "reads the ca-certificates.crt bundle and reports THAT path for every "
        "certificate inside it. Both are truthful answers to 'where did I "
        "read this' and neither is convertible into the other, so the "
        "comparison identifies on common_name + serial instead. "
        "One real difference survives and native is the more complete side: "
        "it reports CN=ubuntu from /etc/ssl/certs/ssl-cert-snakeoil.pem, a "
        "host certificate that is NOT in the CA bundle and which osquery "
        "therefore never sees. For certificate-expiry monitoring that is the "
        "host's own TLS identity -- exactly the cert you want tracked."
    ),
    ("linux", "listening_ports"): (
        "Two structural differences remain, both from HOW each provider "
        "enumerates rather than from what is true. (1) AF_PACKET sockets "
        "(family 17, protocol carrying an ethertype such as 2054=ARP or "
        "34958=EAPOL): visible to osquery, and psutil offers no way to "
        "enumerate them on any platform. (2) NAMESPACES: osquery derives this "
        "table from process_open_sockets, which walks /proc/<pid>/fd across "
        "every process, so as root it crosses into containers and reports "
        "their in-container paths (/etc/pacman.d/gnupg/S.dirmngr from an Arch "
        "container on a host with no pacman). psutil reads the HOST's socket "
        "table, so it reports host-namespace sockets only. On a container "
        "host osquery will therefore report strictly more AF_UNIX rows -- "
        "7,758 process_open_sockets entries against 200 in /proc/net/unix on "
        "the 2026-09-23 box. Matching it would mean reimplementing the "
        "/proc/<pid>/fd walk: root-only, Linux-only, and squarely against the "
        "portability this provider exists for. "
        "Native reports zero rows osquery does not have, on either count. "
        "A pack COUNTING rows in listening_ports will differ by provider on "
        "Linux; filter on family, or on port/path, rather than counting."
    ),
    ("freebsd", "processes"): (
        "FreeBSD's kernel keeps only MAXCOMLEN (19) characters of a process "
        "name, which is what osquery reports; psutil reads the full name from "
        "the arguments -- 'gnome-session-binary' vs 'gnome-session-binar'. A "
        "pack matching processes.name exactly WILL differ by provider here; "
        "prefer LIKE, or match on path."
    ),
}


def shared_tables(requested):
    """Tables both providers serve here, plus why each of the rest is out."""
    platform_name = fact_native.platform_name()
    osquery_has = fact_osquery.available_tables()
    denied = fact_osquery.denied_tables(platform_name)
    both, skipped = [], {}
    for table in requested:
        if table not in fact_schema.FACT_TABLES:
            skipped[table] = "not in the contract"
        elif not fact_schema.applicable(table, platform_name):
            skipped[table] = f"not applicable on {platform_name}"
        elif table not in IDENTIFYING:
            skipped[table] = "sysmanage extension: no osquery counterpart"
        elif table in denied:
            # Distinct from "the build does not have it": the table IS there
            # and we refuse to read it. Saying the wrong one would send an
            # operator looking for a missing feature instead of at a
            # deliberate, measured decision.
            skipped[table] = f"denylisted on this platform -- {denied[table]}"
        elif table not in osquery_has:
            skipped[table] = "this osquery build does not have it"
        else:
            both.append(table)
    return both, skipped


def compare(tables):
    """Run both providers over ``tables`` and diff the identifying columns."""
    native_rows = fact_native.collect(tables)
    osquery_rows = fact_osquery.collect(tables)
    results = {}
    for table in tables:
        if table not in osquery_rows:
            # Omitted, not empty -- collect() distinguishes the two precisely
            # so this case cannot masquerade as "osquery found nothing".
            results[table] = {"error": "osquery could not read it"}
            continue
        diff = fact_osquery.conformance_diff(
            IDENTIFYING[table], native_rows.get(table, []), osquery_rows[table]
        )
        results[table] = {
            "native_rows": len(native_rows.get(table, [])),
            "osquery_rows": len(osquery_rows[table]),
            "native_only": diff["native_only"],
            "osquery_only": diff["osquery_only"],
            "agree": not diff["native_only"] and not diff["osquery_only"],
            "privilege_sensitive": table in PRIVILEGE_SENSITIVE,
        }
    return results


def report(results, skipped, limit):
    """Human-readable summary. Returns the process exit code."""
    disagreed = 0
    for table, row in sorted(results.items()):
        if "error" in row:
            print(f"  ERROR    {table}: {row['error']}")
            disagreed += 1
            continue
        if row["agree"]:
            print(
                f"  agree    {table}: {row['native_rows']} native / "
                f"{row['osquery_rows']} osquery rows"
            )
            continue
        disagreed += 1
        known = KNOWN_PLATFORM_DIFFERENCES.get((fact_native.platform_name(), table))
        if known:
            note = " (known platform difference)"
        elif row["privilege_sensitive"]:
            note = " (privilege-sensitive: run both as root)"
        else:
            note = ""
        print(
            f"  DIFFER   {table}: {len(row['native_only'])} native-only, "
            f"{len(row['osquery_only'])} osquery-only{note}"
        )
        if known:
            print(f"             note: {known}")
        for label in ("native_only", "osquery_only"):
            for value in row[label][:limit]:
                print(f"             {label[:-5]:8} {value}")
            if len(row[label]) > limit:
                print(f"             ... {len(row[label]) - limit} more")

    for table, why in sorted(skipped.items()):
        print(f"  skipped  {table}: {why}")

    print(
        f"\n{len(results) - disagreed}/{len(results)} compared tables agree; "
        f"{len(skipped)} skipped."
    )
    return 1 if disagreed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tables", nargs="*", help="tables to compare (default: all)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--limit", type=int, default=5, help="differing rows to print per side"
    )
    args = parser.parse_args()

    if not fact_osquery.osquery_path():
        print(
            "osqueryi not found -- this harness compares a live osquery against "
            "the native provider, so there is nothing to compare here.\n"
            "Run it on a host with osquery installed (Linux, macOS, FreeBSD).",
            file=sys.stderr,
        )
        return 2

    # Register the providers before collecting anything. Without this the
    # native side answers with an empty registry and the whole report reads
    # "native has nothing, osquery has everything" -- a confident, entirely
    # wrong conclusion about a provider that works.
    bootstrap_fact_providers(None)

    requested = args.tables or sorted(fact_schema.FACT_TABLES)
    tables, skipped = shared_tables(requested)
    results = compare(tables)

    if args.json:
        print(json.dumps({"compared": results, "skipped": skipped}, indent=2))
        return 1 if any(not r.get("agree") for r in results.values()) else 0
    return report(results, skipped, args.limit)


if __name__ == "__main__":
    sys.exit(main())
