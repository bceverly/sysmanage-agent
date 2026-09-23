# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Endpoint fact schema contract -- ROADMAP Phase 21.1, slice S1.

WHAT THIS IS
------------
The list of fact TABLES this agent may serve, and the machinery that reports
which of them it actually serves on THIS host, and by which provider.  It is
the contract every later slice binds to: the native provider (S2), the osquery
provider (S3), the query packs (S4) and the engines that consume the facts
(S6) all speak in these table names.

WHY THE NAMES ARE OSQUERY'S
---------------------------
Where osquery has a table, the contract IS osquery's table and column names --
verified against ``osquery/osquery/specs`` on 2026-09-21, not recalled.  The
value being bought in this phase is the QUERY ECOSYSTEM (published packs, CIS
content, the rules Phase 21.2 will carry); a schema of our own invention would
discard exactly that and leave every query hand-ported.  A pack written once
therefore runs on every platform that serves the tables it reads.

WHY SOME NAMES ARE OURS
-----------------------
osquery has NO spec directory for any BSD (the set is darwin, linux, linwin,
macwin, posix, sleuthkit, utility, windows) and there is no ``pkg_packages``.
So even on FreeBSD, where the port exists, osquery offers no package
inventory -- and installed packages are exactly what ``vuln_engine`` matches
CVEs against.  Facts osquery does not model get a ``sysmanage_`` prefix.  That
prefix is a promise: we never squat on an osquery name with different
semantics, because a pack that reads ``deb_packages`` must get deb packages or
nothing, never "something like it".

THE SAFETY PROPERTY
-------------------
Every contract table appears in EXACTLY ONE of ``served`` or ``unsupported``
in the report.  Nothing is inferred from absence.  This is the whole point of
the slice: a table that was never measured, reported as an empty result,
becomes "no findings", which an operator reads as "compliant".  Unmeasured and
measured-empty must never be the same value anywhere above this line.

WHERE THE TRUTH COMES FROM
--------------------------
Coverage is DERIVED from the provider registry -- the same registry the
collectors register into -- never hand-maintained, for the reason
``capabilities.py`` gives at length: a capability list that lies is worse than
none.  At S1 the registry is empty by design, so a host honestly reports that
it serves no tables yet; S2 and S3 fill it in.
"""

from typing import Callable, Dict, List, Optional, Tuple

# Bump when the TABLE SET or a table's columns change in a way a consumer must
# know about.  Independent of CAPABILITY_SCHEMA_VERSION on purpose: the fact
# contract will move at a different pace from the command taxonomy, and tying
# them would force a bump of one for a change in the other.
# v2 (21.1 S7) added ``sysmanage_file_state``.  Nothing GATES on this number --
# it is recorded on runs and findings so a mixed-version fleet is legible --
# but a consumer of a table added after v1 must require a POSITIVE
# advertisement for it rather than assuming an older agent simply had nothing
# to report.  See host_facts.serves() on the server.
FACT_CONTRACT_VERSION = 2

# Providers.  A table is served by exactly one on a given host.
PROVIDER_OSQUERY = "osquery"
PROVIDER_NATIVE = "native"

# Why a contract table is not served here.  CODES, never prose: the server owns
# translation, exactly as it does for capability reasons.
REASON_NO_PROVIDER = "no_provider"  # nothing has registered for it yet
REASON_WRONG_PLATFORM = "wrong_platform"  # not part of the taxonomy on this OS
REASON_MISSING_TOOL = "missing_tool"  # provider present, prerequisite absent
REASON_PROVIDER_FAILED = "provider_failed"  # registered, but unhealthy here
# The agent can see only PART of the answer -- an unprivileged process
# enumerating sockets, say.  Reported unsupported rather than served, because a
# partial security fact is worse than a missing one: "nothing is listening on
# 22" reads as safe, and a pack cannot tell a true negative from a blind spot.
REASON_INSUFFICIENT_PRIVILEGE = "insufficient_privilege"

# Reasons that mean "this is not a gap in the agent" -- the table does not exist
# on this operating system at all.  Mirrors capability_probes.INAPPLICABLE_
# REASONS so the two taxonomies read the same way.
INAPPLICABLE_FACT_REASONS = frozenset({REASON_WRONG_PLATFORM})

# ---------------------------------------------------------------------------
# The v1 contract.
#
# table -> (origin, platforms)
#   origin     "osquery" when the name and columns are osquery's, "sysmanage"
#              when we define it because osquery does not model the fact.
#   platforms  the OSes where the table is MEANINGFUL, as returned by
#              platform.system().lower().  Empty tuple = every platform.
#              This is applicability, NOT availability: a table meaningful
#              here but unserved is a gap; one not meaningful here is not.
#
# Deliberately small.  osquery ships 200+ tables; v1 covers what this agent
# already collects, so S2 is a re-shaping of existing collectors rather than
# new collection.  Growing the contract is a data edit plus a version bump.
# ---------------------------------------------------------------------------
ANY_PLATFORM: Tuple[str, ...] = ()

FACT_TABLES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # Cross-platform in osquery (specs/).
    "os_version": ("osquery", ANY_PLATFORM),
    "system_info": ("osquery", ANY_PLATFORM),
    "users": ("osquery", ANY_PLATFORM),
    "groups": ("osquery", ANY_PLATFORM),
    "user_groups": ("osquery", ANY_PLATFORM),
    "interface_addresses": ("osquery", ANY_PLATFORM),
    "listening_ports": ("osquery", ANY_PLATFORM),
    "processes": ("osquery", ANY_PLATFORM),
    "certificates": ("osquery", ANY_PLATFORM),
    # specs/posix/ -- no Windows equivalent under this name.
    "mounts": ("osquery", ("linux", "darwin", "freebsd", "openbsd", "netbsd")),
    # Per-platform package tables, kept at their osquery names so published
    # packs keep working where osquery runs.
    "deb_packages": ("osquery", ("linux",)),
    "rpm_packages": ("osquery", ("linux",)),
    "homebrew_packages": ("osquery", ("darwin",)),
    "programs": ("osquery", ("windows",)),
    # Ours, and the reason the BSDs are not second-class: ONE installed-package
    # table every platform populates.  Our packs and vuln_engine read this, so
    # package facts are portable even where osquery has no package table at
    # all -- which is every BSD, port or no port.
    "sysmanage_packages": ("sysmanage", ANY_PLATFORM),
    # osquery models installed software, not PENDING updates, and update
    # detection is a large part of this agent.
    "sysmanage_available_updates": ("sysmanage", ANY_PLATFORM),
    # Ours, and NOT osquery's `file`/`hash` pair, for one decisive reason:
    # osquery's `file` returns NO ROW for a path that does not exist, and no
    # row for one it could not read either.  Absent, unreadable and
    # never-asked-for are then the same observation -- which is precisely the
    # ambiguity this phase exists to remove, in the feature whose whole job is
    # reporting real differences.  Our table carries an explicit `state` per
    # WATCHED path instead, so "the file is gone" and "we were not allowed to
    # look" stay distinguishable from each other and from "we never watched
    # it".  Content is never collected -- see FACT_COLUMNS below.
    "sysmanage_file_state": ("sysmanage", ANY_PLATFORM),
}


# ---------------------------------------------------------------------------
# Columns.  For an osquery-named table these are OSQUERY'S OWN columns, taken
# from `osquery/osquery/specs` on 2026-09-21 -- a pack that selects a column we
# do not fill must get NULL, never an error, so the full column list is
# declared even where no provider populates all of it.  Getting a name wrong
# here is worse than omitting the table: the query succeeds and returns the
# wrong thing.  Two that catch people out -- osquery says `directory`, not
# `home_directory`, and `groupname`, not `group_name`.
# ---------------------------------------------------------------------------
FACT_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "os_version": (
        "name",
        "version",
        "major",
        "minor",
        "patch",
        "build",
        "platform",
        "platform_like",
        "codename",
        "arch",
        "extra",
        "install_date",
        "revision",
        "pid_with_namespace",
        "mount_namespace_id",
    ),
    "system_info": (
        "hostname",
        "uuid",
        "cpu_type",
        "cpu_subtype",
        "cpu_brand",
        "cpu_physical_cores",
        "cpu_logical_cores",
        "cpu_sockets",
        "cpu_microcode",
        "physical_memory",
        "hardware_vendor",
        "hardware_model",
        "hardware_version",
        "hardware_serial",
        "board_vendor",
        "board_model",
        "board_version",
        "board_serial",
        "computer_name",
        "local_hostname",
        "emulated_cpu_type",
    ),
    "users": (
        "uid",
        "gid",
        "uid_signed",
        "gid_signed",
        "username",
        "description",
        "directory",
        "shell",
        "uuid",
        "type",
        "is_hidden",
        "pid_with_namespace",
        "include_remote",
    ),
    "groups": (
        "gid",
        "gid_signed",
        "groupname",
        "group_sid",
        "comment",
        "is_hidden",
        "pid_with_namespace",
    ),
    "user_groups": ("uid", "gid"),
    "interface_addresses": (
        "interface",
        "address",
        "mask",
        "broadcast",
        "point_to_point",
        "type",
        "friendly_name",
    ),
    "listening_ports": (
        "pid",
        "port",
        "protocol",
        "family",
        "address",
        "fd",
        "socket",
        "path",
        "net_namespace",
    ),
    "processes": (
        "pid",
        "name",
        "path",
        "cmdline",
        "state",
        "cwd",
        "root",
        "uid",
        "gid",
        "euid",
        "egid",
        "suid",
        "sgid",
        "on_disk",
        "wired_size",
        "resident_size",
        "total_size",
        "user_time",
        "system_time",
        "disk_bytes_read",
        "disk_bytes_written",
        "start_time",
        "parent",
        "pgroup",
        "threads",
        "nice",
        "elevated_token",
        "secure_process",
        "protection_type",
        "virtual_process",
        "elapsed_time",
        "handle_count",
        "percent_processor_time",
        "upid",
        "uppid",
        "cpu_type",
        "cpu_subtype",
        "translated",
        "cgroup_path",
    ),
    "certificates": (
        "common_name",
        "subject",
        "issuer",
        "ca",
        "self_signed",
        "not_valid_before",
        "not_valid_after",
        "signing_algorithm",
        "key_algorithm",
        "key_strength",
        "key_usage",
        "subject_key_id",
        "authority_key_id",
        "path",
        "serial",
        "sid",
        "store_location",
        "store",
        "username",
        "store_id",
    ),
    "mounts": (
        "device",
        "device_alias",
        "path",
        "type",
        "blocks_size",
        "blocks",
        "blocks_free",
        "blocks_available",
        "inodes",
        "inodes_free",
        "flags",
    ),
    "deb_packages": (
        "name",
        "version",
        "source",
        "size",
        "arch",
        "revision",
        "status",
        "maintainer",
        "section",
        "priority",
        "admindir",
        "pid_with_namespace",
        "mount_namespace_id",
    ),
    "rpm_packages": (
        "name",
        "version",
        "release",
        "source",
        "size",
        "arch",
        "epoch",
        "install_time",
        "vendor",
        "package_group",
        "pid_with_namespace",
        "mount_namespace_id",
    ),
    "homebrew_packages": (
        "name",
        "path",
        "version",
        "type",
        "auto_updates",
        "app_name",
        "prefix",
    ),
    "programs": (
        "name",
        "version",
        "install_location",
        "install_source",
        "language",
        "publisher",
        "uninstall_string",
        "install_date",
        "identifying_number",
        "package_family_name",
        "upgrade_code",
    ),
    # Ours.  Kept deliberately narrow -- every platform must be able to fill
    # every column, or the table stops being the portable one.
    "sysmanage_packages": (
        "name",
        "version",
        "package_manager",
        "architecture",
        "description",
        "source",
    ),
    "sysmanage_available_updates": (
        "name",
        "current_version",
        "available_version",
        "package_manager",
        "is_security",
        "source",
    ),
    # One row per WATCHED path, always -- including paths that are absent or
    # unreadable, which is the entire point of the table.
    #
    # THERE IS NO CONTENT COLUMN, BY DESIGN.  A hash answers "did this change"
    # without ever moving the file off the host, so watching /etc/shadow or a
    # private key cannot leak it into the server database, its API responses,
    # its backups or its logs.  The cost is that drift says THAT a file
    # changed, not WHAT changed in it; that trade was made deliberately.
    "sysmanage_file_state": (
        "path",  # as DECLARED in the watch list, not as resolved
        "state",  # present | absent | unreadable | not_a_file
        "sha256",  # NULL unless state == present and type == regular
        "size",
        "mode",  # octal string, e.g. "0644"
        "uid",
        "gid",
        "owner",  # resolved name where the platform can; NULL otherwise
        "group_name",  # osquery says groupname; ours is explicit
        "mtime",  # epoch seconds
        "type",  # regular | directory | symlink | other
        "target",  # symlink target, NULL otherwise
    ),
}


def columns(table: str) -> Tuple[str, ...]:
    """The declared columns of a contract table."""
    return FACT_COLUMNS[table]


# provider registry: table -> (provider name, predicate answering "can this
# host serve it right now?").  S2/S3 register into this; empty at S1.
# table -> provider -> (probe, reason-when-unavailable).  A table may have
# MORE THAN ONE provider; PROVIDER_ORDER decides which is used.
_PROVIDERS: Dict[str, Dict[str, Tuple[Callable[[], bool], str]]] = {}

# Preference, highest first.  osquery wins where it is healthy because it is
# the wider and better-tested implementation; native is the floor that makes
# every platform work.  The ORDER is the whole mechanism behind "FreeBSD
# degrades to native rather than to nothing" -- see build_fact_coverage.
PROVIDER_ORDER: Tuple[str, ...] = (PROVIDER_OSQUERY, PROVIDER_NATIVE)


def register_provider(
    table: str,
    provider: str,
    available: Callable[[], bool],
    unavailable_reason: str = REASON_MISSING_TOOL,
) -> None:
    """Declare that ``provider`` can serve ``table`` when ``available()``.

    ``unavailable_reason`` is what the report says when the probe answers no.
    A parameter rather than a constant because the honest answer differs: a
    missing binary is ``missing_tool``, but an unprivileged process that can
    see only its own sockets is ``insufficient_privilege`` -- and telling an
    operator "tool missing" when the tool is fine and the agent simply is not
    root sends them somewhere useless.

    Refuses a table outside the contract.  An unknown table would be collected
    and then silently ignored by every consumer, which is a harder bug to see
    than a loud registration error.
    """
    if table not in FACT_TABLES:
        raise KeyError(f"{table!r} is not in the v{FACT_CONTRACT_VERSION} contract")
    if provider not in (PROVIDER_OSQUERY, PROVIDER_NATIVE):
        raise ValueError(f"unknown provider {provider!r}")
    _PROVIDERS.setdefault(table, {})[provider] = (
        available,
        unavailable_reason,
    )


def registered_providers(table: str) -> Tuple[str, ...]:
    """Providers declared for ``table``, in preference order.

    Declared, NOT healthy: this answers "who could serve this?", which is a
    different question from "who does serve it?" and is the one a diagnostic
    needs when a table is unsupported on a host where the binary is installed.
    ``build_fact_coverage`` answers the other one.
    """
    registered = _PROVIDERS.get(table, {})
    return tuple(p for p in PROVIDER_ORDER if p in registered)


def has_providers() -> bool:
    """Is anything registered at all?

    Exists because a boolean "we bootstrapped" flag kept elsewhere can go
    stale the moment someone calls ``clear_providers`` -- and a stale flag
    means the bootstrap declines to re-register, leaving a host that serves
    nothing while every collector on it works. Asking the registry cannot go
    stale, so the bootstrap asks.
    """
    return bool(_PROVIDERS)


def clear_providers() -> None:
    """Drop every registration -- for tests, and for agent restart paths."""
    _PROVIDERS.clear()


def applicable(table: str, platform_name: str) -> bool:
    """Is ``table`` part of the taxonomy on this OS at all?"""
    platforms = FACT_TABLES[table][1]
    return not platforms or platform_name in platforms


def _choose_provider(registered):
    """(provider, None) for the best healthy provider, else (None, reason).

    Walks PROVIDER_ORDER and takes the first provider whose probe says yes, so
    a table both providers can serve is served by osquery while remaining
    servable natively.

    A probe that RAISES does not stop the walk.  That is the FreeBSD case made
    concrete: its osquery port carries seven downstream patches, and when one
    of them breaks, the right answer is the native provider -- not "no facts".
    A provider that cannot answer for itself is unhealthy, never served, but
    it must not take the table down with it.
    """
    first_reason = None
    for provider in PROVIDER_ORDER:
        entry = registered.get(provider)
        if entry is None:
            continue
        available, reason = entry
        try:
            usable = bool(available())
        except Exception:  # pylint: disable=broad-except
            usable = False
            reason = REASON_PROVIDER_FAILED
        if usable:
            return provider, None
        if first_reason is None:
            first_reason = reason
    return None, first_reason or REASON_NO_PROVIDER


def build_fact_coverage(platform_name: str) -> Dict[str, object]:
    """What this host serves, and why it does not serve the rest.

    Every contract table lands in exactly one bucket -- see THE SAFETY PROPERTY
    in the module docstring.  ``not_applicable`` is kept out of
    ``unsupported`` so a Windows host does not read as having a gap for
    ``mounts``, which is not a table it could ever serve.
    """
    served: Dict[str, str] = {}
    unsupported: Dict[str, str] = {}
    not_applicable: Dict[str, str] = {}

    for table in sorted(FACT_TABLES):
        if not applicable(table, platform_name):
            not_applicable[table] = REASON_WRONG_PLATFORM
            continue
        registered = _PROVIDERS.get(table)
        if not registered:
            unsupported[table] = REASON_NO_PROVIDER
            continue
        chosen, reason = _choose_provider(registered)
        if chosen is not None:
            served[table] = chosen
        else:
            unsupported[table] = reason

    return {
        "contract_version": FACT_CONTRACT_VERSION,
        "served": served,
        "unsupported": unsupported,
        "not_applicable": not_applicable,
    }


def contract_tables(origin: Optional[str] = None) -> List[str]:
    """Contract table names, optionally filtered to one origin."""
    return sorted(
        name
        for name, (table_origin, _) in FACT_TABLES.items()
        if origin is None or table_origin == origin
    )
