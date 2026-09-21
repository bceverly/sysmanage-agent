# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Native fact provider — ROADMAP Phase 21.1, slice S2.

WHAT THIS IS
------------
The contract tables, filled from the collectors this agent ALREADY has.  It is
a re-shaping of existing collection, not new collection: the same data that
goes up as inventory today, expressed in the fact schema so a query pack can
read it.

WHY IT SHIPS BEFORE THE OSQUERY PROVIDER
----------------------------------------
osquery has no port on OpenBSD or NetBSD and no package table on any BSD, so
if the osquery provider landed first those hosts would go from "collected
natively today" to "no facts at all" — and nothing would notice until an
advisor rule returned nothing for them, which reads as compliant.  This
provider is therefore the floor everywhere, and osquery is an accelerator on
the platforms that have it.

FIDELITY RULES, AND WHY THEY MATTER MORE THAN COVERAGE
------------------------------------------------------
A pack written against osquery must get osquery's meaning or NOTHING.  So:

* A column we cannot fill honestly is left NULL.  ``users.gid`` is the
  example: our collector reports a user's group NAMES, not a primary gid, and
  a plausible-looking guess is worse than a null because a pack filtering on
  it would silently select the wrong hosts.
* ``is_system_user`` is NOT mapped onto ``users.is_hidden``.  They sound
  similar and are not: osquery's ``is_hidden`` is about whether an account is
  hidden from the login UI, which is not what "system account" means.  Same
  name-shaped trap as ``directory`` vs ``home_directory``.
* Unresolvable rows are dropped rather than invented.  ``user_groups`` needs
  a (uid, gid) pair; a group name we cannot resolve to a gid produces no row.
"""

import logging
import os
import platform
import socket
from typing import Any, Callable, Dict, List, Mapping, Sequence

from src.sysmanage_agent.core.fact_schema import (
    PROVIDER_NATIVE,
    REASON_INSUFFICIENT_PRIVILEGE,
    REASON_MISSING_TOOL,
    register_provider,
)

logger = logging.getLogger(__name__)


def _rows(builder: Callable[[], Sequence[Mapping[str, Any]]]) -> List[Dict[str, Any]]:
    """Run a builder, turning a collector failure into an empty table.

    Callers must NOT read this as "measured, found none" — the coverage report
    is what says whether a table is served at all, and a provider that throws
    is reported unsupported there.  This only keeps one broken collector from
    taking down the whole collection pass.
    """
    try:
        return [dict(row) for row in builder()]
    except Exception:  # pylint: disable=broad-except
        logger.exception("native fact builder failed")
        return []


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------


def build_users(collector) -> List[Dict[str, Any]]:
    """osquery ``users`` from UserAccessCollector.get_user_accounts()."""
    out = []
    for acct in collector.get_user_accounts() or []:
        out.append(
            {
                "uid": acct.get("uid"),
                "username": acct.get("username"),
                # osquery calls it `directory`; ours is `home_directory`.
                "directory": acct.get("home_directory"),
                "shell": acct.get("shell"),
                # gid / is_hidden deliberately absent -- see FIDELITY RULES.
            }
        )
    return out


def build_groups(collector) -> List[Dict[str, Any]]:
    """osquery ``groups`` — note `groupname`, not `group_name`."""
    return [
        {"gid": grp.get("gid"), "groupname": grp.get("group_name")}
        for grp in (collector.get_user_groups() or [])
    ]


def build_user_groups(collector) -> List[Dict[str, Any]]:
    """osquery ``user_groups`` — (uid, gid) membership pairs.

    Our collector gives group NAMES per user, so the names are resolved
    through the group table.  A name that does not resolve yields no row: a
    membership with an invented gid would be a false positive in exactly the
    queries this table exists to answer.
    """
    by_name = {
        grp.get("group_name"): grp.get("gid")
        for grp in (collector.get_user_groups() or [])
        if grp.get("group_name") is not None
    }
    out = []
    for acct in collector.get_user_accounts() or []:
        uid = acct.get("uid")
        for name in acct.get("groups") or []:
            gid = by_name.get(name)
            if uid is not None and gid is not None:
                out.append({"uid": uid, "gid": gid})
    return out


def build_os_version(collector) -> List[Dict[str, Any]]:
    """osquery ``os_version`` — exactly one row."""
    info = collector.get_os_version_info() or {}
    os_info = info.get("os_info") or {}
    return [
        {
            "name": os_info.get("distribution") or info.get("platform"),
            "version": os_info.get("distribution_version")
            or info.get("platform_release"),
            "codename": os_info.get("distribution_codename"),
            "platform": (info.get("platform") or "").lower() or None,
            "arch": info.get("machine_architecture"),
            "build": info.get("platform_version"),
        }
    ]


def build_sysmanage_packages(collector) -> List[Dict[str, Any]]:
    """The portable installed-package table.

    This is the one that makes the BSDs first-class: osquery has no package
    table on ANY BSD, so without this, vulnerability matching would simply not
    happen on FreeBSD, OpenBSD or NetBSD.
    """
    inventory = collector.get_software_inventory() or {}
    return [
        {
            "name": pkg.get("package_name"),
            "version": pkg.get("version"),
            "package_manager": pkg.get("package_manager"),
            "architecture": pkg.get("architecture"),
            "description": pkg.get("description"),
            "source": pkg.get("source"),
        }
        for pkg in (inventory.get("software_packages") or [])
    ]


# osquery reports Linux process state as the single letter from /proc stat;
# psutil reports a word.  The mapping is exact, so translating is FAITHFUL --
# and it matters, because a published pack filters on `state = 'R'` and would
# match nothing against "running".
_PROCESS_STATE = {
    "running": "R",
    "sleeping": "S",
    "disk-sleep": "D",
    "stopped": "T",
    "tracing-stop": "t",
    "zombie": "Z",
    "dead": "X",
    "wake-kill": "K",
    "waking": "W",
    "idle": "I",
    "parked": "P",
}


def build_processes(collector) -> List[Dict[str, Any]]:
    """osquery ``processes`` from ProcessCollector.collect_processes().

    ``uid``/``gid`` stay NULL: the collector reports a username, and resolving
    it to a uid here would be a guess on any host with a directory service.
    """
    processes, _truncated = collector.collect_processes()
    out = []
    for proc in processes or []:
        out.append(
            {
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "cmdline": proc.get("command_line"),
                "state": _PROCESS_STATE.get(proc.get("status")),
                "resident_size": proc.get("memory_rss_bytes"),
                "parent": proc.get("parent_pid"),
            }
        )
    return out


def build_certificates(collector) -> List[Dict[str, Any]]:
    """osquery ``certificates``.

    ``self_signed`` is DERIVED as subject == issuer, which is osquery's own
    definition rather than an invention, so the column carries its real
    meaning instead of a null.
    """
    out = []
    for cert in collector.collect_certificates() or []:
        subject = cert.get("subject")
        issuer = cert.get("issuer")
        out.append(
            {
                "common_name": cert.get("certificate_name"),
                "subject": subject,
                "issuer": issuer,
                "ca": int(bool(cert.get("is_ca"))),
                "self_signed": (int(subject == issuer) if subject and issuer else None),
                "not_valid_before": cert.get("not_before"),
                "not_valid_after": cert.get("not_after"),
                "key_usage": cert.get("key_usage"),
                "path": cert.get("file_path"),
                "serial": cert.get("serial_number"),
            }
        )
    return out


def build_interface_addresses(collector) -> List[Dict[str, Any]]:
    """osquery ``interface_addresses`` — ONE ROW PER ADDRESS.

    Our collector carries v4 and v6 on the same interface record; osquery's
    shape is one row each, and a pack counting addresses would be wrong if we
    collapsed them.
    """
    out = []
    for iface in (collector.get_hardware_info() or {}).get("network_interfaces") or []:
        name = iface.get("name")
        if iface.get("ipv4_address"):
            out.append(
                {
                    "interface": name,
                    "address": iface.get("ipv4_address"),
                    "mask": iface.get("subnet_mask"),
                }
            )
        if iface.get("ipv6_address"):
            # No mask: the collector's subnet_mask is the v4 one, and reusing
            # it here would state something false about the v6 address.
            out.append({"interface": name, "address": iface.get("ipv6_address")})
    return out


def build_mounts(collector) -> List[Dict[str, Any]]:
    """osquery ``mounts``.

    The block/inode columns stay NULL: the collector reports a byte size, not
    a block count, and dividing by an assumed block size would put a specific
    wrong number where a pack expects a real one.
    """
    return [
        {
            "device": dev.get("name"),
            "path": dev.get("mount_point"),
            "type": dev.get("file_system"),
        }
        for dev in (collector.get_hardware_info() or {}).get("storage_devices") or []
    ]


def build_system_info(collector) -> List[Dict[str, Any]]:
    """osquery ``system_info`` — exactly one row.

    ``physical_memory`` is BYTES in osquery and megabytes in our collector, so
    it is converted rather than copied.  ``cpu_type`` is the machine
    architecture (osquery's meaning), NOT the vendor string -- those are
    different facts that both look like "the CPU".
    """
    info = collector.get_hardware_info() or {}
    memory_mb = info.get("memory_total_mb")
    return [
        {
            "hostname": platform.node() or None,
            "cpu_type": platform.machine() or None,
            "cpu_brand": info.get("cpu_model"),
            "cpu_physical_cores": info.get("cpu_cores"),
            "cpu_logical_cores": info.get("cpu_threads"),
            "physical_memory": (
                int(memory_mb) * 1024 * 1024 if memory_mb is not None else None
            ),
        }
    ]


def build_available_updates(collector) -> List[Dict[str, Any]]:
    """``sysmanage_available_updates`` — osquery models installed software,
    not pending updates, so this table is ours."""
    payload = collector.get_available_updates() or {}
    return [
        {
            "name": upd.get("package_name"),
            "current_version": upd.get("current_version"),
            "available_version": upd.get("available_version"),
            "package_manager": upd.get("package_manager"),
            "is_security": int(bool(upd.get("is_security_update"))),
        }
        for upd in (payload.get("available_updates") or [])
    ]


# Which package managers feed each osquery-named package table.  Filling these
# lets a PUBLISHED pack that reads `deb_packages` work on a host with no
# osqueryd -- the rows are genuine dpkg data, so the table keeps its meaning.
_PACKAGE_TABLE_MANAGERS = {
    "deb_packages": {"apt", "dpkg"},
    "rpm_packages": {"dnf", "yum", "rpm", "zypper"},
    "homebrew_packages": {"brew", "homebrew"},
    "programs": {"winget", "chocolatey", "msi", "windows"},
}


def _packages_for(collector, table: str) -> List[Dict[str, Any]]:
    managers = _PACKAGE_TABLE_MANAGERS[table]
    inventory = collector.get_software_inventory() or {}
    rows = []
    for pkg in inventory.get("software_packages") or []:
        if (pkg.get("package_manager") or "").lower() not in managers:
            continue
        row = {"name": pkg.get("package_name"), "version": pkg.get("version")}
        if table in ("deb_packages", "rpm_packages"):
            row["arch"] = pkg.get("architecture")
        if table == "programs":
            row["publisher"] = pkg.get("source")
        rows.append(row)
    return rows


# osquery's ``listening_ports.protocol`` is the IANA IP PROTOCOL NUMBER --
# 6 for TCP, 17 for UDP -- while psutil reports the SOCKET TYPE
# (SOCK_STREAM = 1, SOCK_DGRAM = 2). Emitting the socket type is a silent
# wrong answer of the worst kind: ``WHERE protocol = 6``, which is what a
# published osquery pack writes for TCP, matches NOTHING, and ``protocol = 1``
# (ICMP, in IANA terms) matches every TCP socket. The query succeeds either
# way. Found on the first live round trip, 2026-09-21, when a FreeBSD host
# reported sshd on port 22 with protocol 1.
#
# ``family`` needs no such map: psutil's AddressFamily values ARE the OS
# AF_* constants, which is exactly what osquery reports.
_IP_PROTOCOL = {
    int(socket.SOCK_STREAM): int(socket.IPPROTO_TCP),
    int(socket.SOCK_DGRAM): int(socket.IPPROTO_UDP),
}


def can_enumerate_sockets() -> bool:
    """Can this process see EVERY listening socket, not just its own?

    Unprivileged psutil returns the caller's sockets and silently omits the
    rest, which would make ``listening_ports`` answer "nothing is listening on
    22" when sshd is running -- a false negative in exactly the security
    queries the table exists for.  So the table is served only when the answer
    can be complete.
    """
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        return geteuid() == 0
    try:  # Windows
        import ctypes  # noqa: PLC0415

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pylint: disable=broad-except
        return False


def build_listening_ports(_collector=None) -> List[Dict[str, Any]]:
    """osquery ``listening_ports`` via psutil, which the agent already uses."""
    import psutil  # noqa: PLC0415

    out = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN or conn.laddr is None:
            continue
        out.append(
            {
                "pid": conn.pid,
                "port": conn.laddr.port,
                "address": conn.laddr.ip,
                "protocol": _IP_PROTOCOL.get(conn.type),
                "family": conn.family,
                "fd": getattr(conn, "fd", None),
            }
        )
    return out


def build_deb_packages(collector) -> List[Dict[str, Any]]:
    return _packages_for(collector, "deb_packages")


def build_rpm_packages(collector) -> List[Dict[str, Any]]:
    return _packages_for(collector, "rpm_packages")


def build_homebrew_packages(collector) -> List[Dict[str, Any]]:
    return _packages_for(collector, "homebrew_packages")


def build_programs(collector) -> List[Dict[str, Any]]:
    return _packages_for(collector, "programs")


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

# table -> (collector factory, builder).  Adding a table is one entry here
# plus a builder; the coverage report follows automatically, which is what
# keeps "advertised" and "actually served" the same set.
NATIVE_TABLES: Dict[str, Any] = {}


def _register_table(
    table: str, collector_factory, builder, probe=None, reason=None
) -> None:
    NATIVE_TABLES[table] = (collector_factory, builder)
    register_provider(
        table,
        PROVIDER_NATIVE,
        probe or (lambda: True),
        reason or REASON_MISSING_TOOL,
    )


def register_native_provider() -> None:
    """Register every table this provider can serve on this host.

    Imports are local so a platform whose collector cannot even be imported
    reports that table unsupported instead of taking down the agent.
    """
    from src.sysmanage_agent.collection.os_info_collection import (  # noqa: PLC0415
        OSInfoCollector,
    )
    from src.sysmanage_agent.collection.software_inventory_collection import (  # noqa: PLC0415
        SoftwareInventoryCollector,
    )
    from src.sysmanage_agent.collection.user_access_collection import (  # noqa: PLC0415
        UserAccessCollector,
    )

    from src.sysmanage_agent.collection.certificate_collection import (  # noqa: PLC0415
        CertificateCollector,
    )
    from src.sysmanage_agent.collection.hardware_collection import (  # noqa: PLC0415
        HardwareCollector,
    )
    from src.sysmanage_agent.collection.process_collection import (  # noqa: PLC0415
        ProcessCollector,
    )
    from src.sysmanage_agent.collection.update_detection import (  # noqa: PLC0415
        UpdateDetector,
    )

    _register_table("users", UserAccessCollector, build_users)
    _register_table("groups", UserAccessCollector, build_groups)
    _register_table("user_groups", UserAccessCollector, build_user_groups)
    _register_table("os_version", OSInfoCollector, build_os_version)
    _register_table("system_info", HardwareCollector, build_system_info)
    _register_table("interface_addresses", HardwareCollector, build_interface_addresses)
    _register_table("mounts", HardwareCollector, build_mounts)
    _register_table("processes", ProcessCollector, build_processes)
    _register_table("certificates", CertificateCollector, build_certificates)
    _register_table(
        "sysmanage_packages", SoftwareInventoryCollector, build_sysmanage_packages
    )
    _register_table(
        "sysmanage_available_updates", UpdateDetector, build_available_updates
    )
    # Registered on every platform: build_fact_coverage() checks applicability
    # FIRST, so a table this OS cannot have is reported not_applicable rather
    # than served.  A host that CAN have them but has none -- deb_packages on
    # a Fedora box -- correctly reports served with zero rows, which is
    # "measured, found none" and is the truth.
    _register_table("deb_packages", SoftwareInventoryCollector, build_deb_packages)
    _register_table("rpm_packages", SoftwareInventoryCollector, build_rpm_packages)
    _register_table(
        "homebrew_packages", SoftwareInventoryCollector, build_homebrew_packages
    )
    _register_table("programs", SoftwareInventoryCollector, build_programs)
    # No collector object: psutil is read directly.  Gated on privilege -- see
    # can_enumerate_sockets().
    _register_table(
        "listening_ports",
        lambda: None,
        lambda _c: build_listening_ports(),
        can_enumerate_sockets,
        REASON_INSUFFICIENT_PRIVILEGE,
    )


def collect(tables: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Build the requested tables. Unknown/unregistered tables are skipped."""
    collected: Dict[str, List[Dict[str, Any]]] = {}
    cache: Dict[Any, Any] = {}
    for table in tables:
        registration = NATIVE_TABLES.get(table)
        if registration is None:
            continue
        factory, builder = registration
        # One collector instance per class per pass: three of the five tables
        # come from UserAccessCollector, and re-reading the account database
        # per table would triple the cost for identical data.
        collector = cache.setdefault(factory, factory())
        collected[table] = _rows(lambda c=collector, b=builder: b(c))
    return collected


def platform_name() -> str:
    """This host's platform, as the contract spells it."""
    return platform.system().lower()
