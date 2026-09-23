# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Native fact provider -- ROADMAP Phase 21.1, slice S2.

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
natively today" to "no facts at all" -- and nothing would notice until an
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
from datetime import datetime, timezone
import platform
import re
import subprocess
import socket
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from src.sysmanage_agent.core.fact_schema import (
    PROVIDER_NATIVE,
    REASON_INSUFFICIENT_PRIVILEGE,
    REASON_MISSING_TOOL,
    register_provider,
)

logger = logging.getLogger(__name__)


def _rows(builder: Callable[[], Sequence[Mapping[str, Any]]]) -> List[Dict[str, Any]]:
    """Run a builder, turning a collector failure into an empty table.

    Callers must NOT read this as "measured, found none" -- the coverage report
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
    """osquery ``groups`` -- note `groupname`, not `group_name`."""
    return [
        {"gid": grp.get("gid"), "groupname": grp.get("group_name")}
        for grp in (collector.get_user_groups() or [])
    ]


def build_user_groups(collector) -> List[Dict[str, Any]]:
    """osquery ``user_groups`` -- (uid, gid) membership pairs.

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


def _os_release() -> Dict[str, str]:
    """``/etc/os-release`` as a dict, empty where there is none."""
    out: Dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    key, _, value = line.partition("=")
                    if value:
                        out[key.strip()] = value.strip().strip('"').strip("'")
            break
        except OSError:
            continue
    return out


def build_os_version(collector) -> List[Dict[str, Any]]:
    """osquery ``os_version`` -- exactly one row.

    ``platform`` is the DISTRIBUTION, not the kernel. osquery reports
    ``ubuntu``/``debian``/``rhel`` on Linux, taken from os-release ``ID``; we
    reported ``linux``, so the documented osquery idiom
    ``WHERE platform = 'ubuntu'`` matched nothing here while the query
    succeeded. Measured against osquery 5.20.0 on Ubuntu 26.04, 2026-09-21.

    On the BSDs, macOS and Windows the two already agree -- osquery's platform
    there IS ``freebsd``/``darwin``/``windows`` -- which is why only the Linux
    leg needed this and why the FreeBSD comparison showed ``os_version``
    agreeing all along.

    ``version`` follows the same rule: osquery reports os-release ``VERSION``
    ("26.04.1 LTS (Resolute Raccoon)"), not ``VERSION_ID`` ("26.04").
    ``platform_like`` comes from ``ID_LIKE`` and was previously always NULL.
    """
    info = collector.get_os_version_info() or {}
    os_info = info.get("os_info") or {}
    release = _os_release()

    # macOS: osquery reports platform ``darwin`` and the plain release number.
    # Our collector reports ``macos`` and a marketing-prefixed string
    # ("Sequoia 15.6"), so a pack written the osquery way -- ``WHERE platform
    # = 'darwin'`` -- matched nothing, and the version was both prefixed and
    # a patch level behind (15.6 where the host was on 15.6.1). Measured on
    # macOS 15.6.1, 2026-09-21.
    mac_platform = None
    mac_version = None
    if platform.system() == "Darwin":
        mac_platform = "darwin"
        mac_version = platform.mac_ver()[0] or None

    return [
        {
            "name": os_info.get("distribution") or info.get("platform"),
            "version": mac_version
            or release.get("VERSION")
            or os_info.get("distribution_version")
            or info.get("platform_release"),
            "codename": os_info.get("distribution_codename")
            or release.get("VERSION_CODENAME"),
            "platform": mac_platform
            or release.get("ID")
            or (info.get("platform") or "").lower()
            or None,
            "platform_like": release.get("ID_LIKE") or mac_platform or None,
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
    # limit=None: the operator snapshot is capped at 1,000 by resource use so
    # a busy host does not flood the server. Inherited here that cap made the
    # fact table LIE -- 1,000 rows presented as the whole truth, with the
    # low-CPU daemons dropped first, which are exactly the ones a security
    # pack asks about. A pack running "WHERE name = 'sshd'" got a confident
    # "not running". The conformance run on 2026-09-23 showed it as an exact
    # 1,000 against osquery's 1,048, every native pid a subset of osquery's.
    processes, _truncated = collector.collect_processes(limit=None)
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


# ``CN = value`` inside an X.509 distinguished name, in either of the two
# spacings OpenSSL emits ("CN = x" and "CN=x").
_CN_IN_DN = re.compile(r"(?:^|,)\s*CN\s*=\s*([^,]+)")


def common_name_of(subject: Optional[str]) -> Optional[str]:
    """The CN component of a distinguished name.

    osquery's ``certificates.common_name`` is the subject's CN, not the whole
    DN. Our collector leaves ``certificate_name`` unset for certificates read
    out of a bundle -- measured on FreeBSD 14.4, every certificate in
    ``/usr/local/share/certs/ca-root-nss.crt`` came back with a full subject
    and a NULL name -- so the column shipped empty and a pack matching on
    ``common_name`` matched nothing.

    Derived, not invented: the CN really is in the subject we already hold.
    """
    if not subject:
        return None
    found = _CN_IN_DN.search(subject)
    return found.group(1).strip() if found else None


def _osquery_serial(serial: Optional[str]) -> Optional[str]:
    """The serial as osquery renders it.

    osquery formats the serial with OpenSSL's ``BN_bn2hex``, which returns a
    bare ``"0"`` for a zero serial. The native side reads ``openssl x509
    -serial``, whose command-line output pads to whole bytes and prints
    ``00``. Same certificate, two spellings, and a pack filtering
    ``serial = '0'`` matches one provider and not the other.

    Leading zeros are otherwise PRESERVED by both -- "02" for Buypass Class 2
    Root CA, "0DD3E3BC6CF96BB1" for ANF Secure Server Root CA -- so this
    normalizes the all-zero case ONLY. A general lstrip("0") would rewrite
    those two into values neither provider reports, turning 122 agreeing rows
    into 122 disagreeing ones. Found by the S3 conformance run, 2026-09-23.
    """
    if serial is None:
        return None
    text = str(serial).strip()
    if text and set(text) == {"0"}:
        return "0"
    return text


def _osquery_epoch(value) -> Optional[str]:
    """A certificate date as osquery reports it: epoch seconds, as text.

    The collector hands over ISO-8601. Passing that through broke every pack
    written the osquery way -- ``CAST(not_valid_after AS INTEGER)`` turns
    "2030-12-31T09:37:37+00:00" into 2030, so every certificate read as long
    expired (found by the 21.2 S0 spike, 2026-09-23). Unparseable input is
    NULL, not a guess.
    """
    if value is None:
        return None
    text = str(value).strip()
    if text.isdigit():
        return text
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return str(int(parsed.timestamp()))


def build_certificates(collector) -> List[Dict[str, Any]]:
    """osquery ``certificates``.

    ``self_signed`` is DERIVED as subject == issuer, which is osquery's own
    definition rather than an invention, so the column carries its real
    meaning instead of a null.  ``common_name`` is derived the same way -- see
    ``common_name_of``.

    ``ca`` is X509_check_ca, as osquery's is: ``basic_constraints_ca`` from
    the collector, not its path/subject heuristic ``is_ca`` (which called
    ACCVRAIZ1, a root CA, "not a CA"). Windows records carry no
    ``basic_constraints_ca``; there the store-based ``is_ca`` stands.
    """
    out = []
    for cert in collector.collect_certificates() or []:
        subject = cert.get("subject")
        issuer = cert.get("issuer")
        out.append(
            {
                "common_name": cert.get("certificate_name") or common_name_of(subject),
                "subject": subject,
                "issuer": issuer,
                "ca": int(
                    bool(
                        cert["basic_constraints_ca"]
                        if "basic_constraints_ca" in cert
                        else cert.get("is_ca")
                    )
                ),
                "self_signed": (int(subject == issuer) if subject and issuer else None),
                "not_valid_before": _osquery_epoch(cert.get("not_before")),
                "not_valid_after": _osquery_epoch(cert.get("not_after")),
                "key_usage": cert.get("key_usage"),
                "path": cert.get("file_path"),
                "serial": _osquery_serial(cert.get("serial_number")),
            }
        )
    return out


# ``inet <addr> netmask 0x<hex>`` as BSD ifconfig prints it.
_IFCONFIG_INET = re.compile(
    r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]{8})", re.M
)


def _ipv4_masks_from_ifconfig() -> Dict[str, str]:
    """{address: dotted-quad mask} for IPv4, read from ``ifconfig``.

    OpenBSD only. Measured on OpenBSD 7.9 on 2026-09-21: psutil returns
    ``netmask=None`` for EVERY IPv4 address there while filling IPv6 masks
    correctly -- a gap in its BSD implementation, not in the OS, which prints
    the mask perfectly well. NetBSD 10.1 and Linux both populate it, so this
    fallback is needed on exactly one platform.

    Without it, ``interface_addresses.mask`` is silently NULL for every v4
    address on a first-class platform, and a pack asking which addresses sit
    on a given subnet cannot answer there.
    """
    try:
        result = subprocess.run(  # nosec B603, B607
            ["ifconfig", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0:
        return {}

    masks = {}
    for address, hex_mask in _IFCONFIG_INET.findall(result.stdout):
        value = int(hex_mask, 16)
        masks[address] = ".".join(
            str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0)
        )
    return masks


def build_interface_addresses(_collector=None) -> List[Dict[str, Any]]:
    """osquery ``interface_addresses`` -- ONE ROW PER ADDRESS, from the OS.

    Read from ``psutil.net_if_addrs`` rather than the hardware inventory,
    which is shaped for a different question and lost rows osquery has. Two
    ways, both measured on FreeBSD 14.4 on 2026-09-21:

    * LOOPBACK was absent. osquery reported ``lo0`` with 127.0.0.1, ::1 and
      fe80::1%lo0; we reported none of them. A pack checking whether a service
      is bound to loopback -- a normal security question -- got a confidently
      empty answer.
    * The inventory holds ONE v4 and ONE v6 per interface, so a second address
      on the same interface simply vanished. osquery emits every address.

    Each address carries its OWN mask. The previous code reused the v4 subnet
    mask for the v4 row and left v6 masked NULL, which was right to refuse --
    but the real fix is reading the mask that belongs to each address.
    """
    import socket as _socket  # noqa: PLC0415

    import psutil  # noqa: PLC0415

    families = {_socket.AF_INET, _socket.AF_INET6}
    interfaces = psutil.net_if_addrs() or {}

    # Only shell out when psutil actually left a v4 mask empty, so Linux,
    # NetBSD, macOS and Windows never pay for a subprocess they do not need.
    fallback: Dict[str, str] = {}
    if any(
        addr.family == _socket.AF_INET and not getattr(addr, "netmask", None)
        for addrs in interfaces.values()
        for addr in addrs
    ):
        fallback = _ipv4_masks_from_ifconfig()

    out = []
    for name, addrs in interfaces.items():
        for addr in addrs:
            if addr.family not in families:
                continue
            mask = getattr(addr, "netmask", None)
            if mask is None and addr.family == _socket.AF_INET:
                mask = fallback.get(addr.address)
            out.append(
                {
                    "interface": name,
                    "address": addr.address or None,
                    "mask": mask,
                    "broadcast": getattr(addr, "broadcast", None),
                    "point_to_point": getattr(addr, "ptp", None),
                }
            )
    return out


def build_mounts(_collector=None) -> List[Dict[str, Any]]:
    """osquery ``mounts`` -- the MOUNT TABLE, read from the OS.

    Not the storage-device inventory, which is what this used to read. The two
    look interchangeable and are not: a disk is not a mount. Measured on
    FreeBSD 14.4 on 2026-09-21, the device list produced raw devices with no
    mount point (``/dev/da0``, type ``raw``) and reported ``type`` as
    ``unknown`` for every real filesystem, because a ZFS dataset has no
    "file system" field in a disk inventory. A pack asking the natural
    question -- ``WHERE type = 'zfs'`` -- matched NOTHING, and the query
    succeeded. osquery reported all 27 mounts with their true types.

    ``psutil.disk_partitions`` is getmntinfo(2) on the BSDs, /proc/mounts on
    Linux and GetLogicalDriveStrings on Windows, which is the same source
    osquery reads.

    ``all=True`` on purpose: osquery's ``mounts`` includes devfs, procfs and
    fdescfs, and filtering to "real" disks would silently drop rows osquery
    has.

    The block/inode columns come from ``statvfs`` -- but ONLY for the local
    filesystem types in ``_STATVFS_SAFE_TYPES``. A ``statvfs`` on an
    unreachable network mount blocks, turning one unavailable NFS server into
    a hung fact collection on every interval, so network, FUSE and unknown
    types keep NULL: "not measured for this mount", never a guess. Until
    2026-09-23 every mount stayed NULL, and the 21.2 S0 spike showed what that
    cost: "filesystem more than 90% full" evaluated to "does not fire" on a
    real host whose capacity had simply never been read.
    """
    import psutil  # noqa: PLC0415

    # psutil's LINUX backend contains, verbatim, ``if device == 'none':
    # device = ''`` (psutil._pslinux.disk_partitions). The kernel spells it
    # ``none`` in both /proc/mounts and /proc/self/mountinfo -- for
    # /sys/fs/pstore and the systemd credential tmpfs mounts -- and that is
    # what osquery reports. The blank is psutil's normalization, not a fact
    # about the host, so putting it back is exact rather than a guess.
    #
    # LINUX ONLY, deliberately. That substitution lives in psutil's Linux
    # backend; on a platform where the same behavior is not verified, an
    # empty device could mean something else entirely, and emitting "none"
    # there would INVENT a fact -- the failure this phase exists to prevent.
    # Found by the S3 conformance run, 2026-09-23 (4 mounts, device only).
    restore_none = platform.system() == "Linux"

    out = []
    for part in psutil.disk_partitions(all=True):
        device = part.device or None
        if device is None and restore_none:
            device = "none"
        out.append(
            {
                "device": device,
                "path": part.mountpoint or None,
                "type": part.fstype or None,
                # osquery's ``flags`` is the mount option string.
                "flags": getattr(part, "opts", None) or None,
                **_mount_capacity(part.mountpoint, part.fstype),
            }
        )
    return out


# Filesystems whose ``statvfs`` answers from local state and cannot block on
# a network peer. Anything else -- nfs, cifs/smbfs, 9p, fuse.* (sshfs, rclone,
# gvfs), afs, ceph -- is left unmeasured on purpose; see build_mounts.
_STATVFS_SAFE_TYPES = frozenset(
    (
        # Local disk and memory filesystems.
        "ext2 ext3 ext4 xfs btrfs zfs f2fs jfs reiserfs vfat msdos msdosfs exfat"
        " ntfs ntfs3 tmpfs devtmpfs ramfs ufs ffs hammer hammer2 apfs hfs lfs mfs"
        " cd9660 iso9660 squashfs overlay"
        # Kernel pseudo-filesystems, answered by the kernel itself. osquery
        # reports them (as zeros); measuring them keeps the two providers
        # comparable instead of NULL-vs-0 on every such row.
        " proc sysfs devpts cgroup cgroup2 securityfs debugfs tracefs configfs"
        " pstore bpf mqueue hugetlbfs efivarfs fusectl binfmt_misc nsfs devfs"
        " fdescfs procfs linprocfs linsysfs kernfs ptyfs"
    ).split()
)


def _mount_capacity(path: Optional[str], fstype: Optional[str]) -> Dict[str, Any]:
    """osquery's block/inode columns for one mount, or {} when not measured.

    ``blocks_size`` is ``f_frsize`` -- POSIX counts ``f_blocks`` in those
    units, so ``blocks * blocks_size`` is bytes on every platform. (Linux
    osquery reports ``f_bsize``; the two are equal there, verified against
    osqueryi on 2026-09-23 for /, /boot, /tmp and /run.)
    """
    if not path or (fstype or "").lower() not in _STATVFS_SAFE_TYPES:
        return {}
    try:
        st = os.statvfs(path)
    except OSError:
        return {}
    return {
        "blocks_size": st.f_frsize,
        "blocks": st.f_blocks,
        "blocks_free": st.f_bfree,
        "blocks_available": st.f_bavail,
        "inodes": st.f_files,
        "inodes_free": st.f_ffree,
    }


def build_system_info(collector) -> List[Dict[str, Any]]:
    """osquery ``system_info`` -- exactly one row.

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
    """``sysmanage_available_updates`` -- osquery models installed software,
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
    # osquery's ``programs`` IS the Windows registry uninstall list -- the
    # Add/Remove Programs view. It is not the winget catalog.
    #
    # This set used to be {"winget", "chocolatey", "msi", "windows"} and the
    # real manager value is ``windows_registry``, which matched NONE of them,
    # so the table reported winget's 204 packages while excluding all 195
    # registry-installed programs. Measured on Windows 11 (26220) on
    # 2026-09-21. Chocolatey and MSI installs register in the uninstall keys
    # too, so reading the registry covers them rather than needing their own
    # entries.
    #
    # winget and microsoft_store packages are not lost: they are carried by
    # ``sysmanage_packages``, the portable table, which is exactly what it is
    # for.
    "programs": {"windows_registry"},
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
            # The PUBLISHER, not the source. This read ``source`` and so
            # reported "winget_repository" -- a package origin -- in a column
            # osquery fills with the software vendor ("Igor Pavlov",
            # "Microsoft Corporation"). The inventory carries the real value;
            # it simply was not being read.
            row["publisher"] = pkg.get("publisher")
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


# ``socket.AF_UNIX`` does not exist on Windows, and referencing it there is an
# AttributeError rather than a graceful absence. The value is 1 on every POSIX
# platform and osquery reports family "1" for a unix socket everywhere, so the
# fallback is the contract's own answer rather than a guess. Production never
# reached the attribute on Windows (psutil rejects kind="unix" there and the
# caller returns early), but a mocked test did -- and a constant that only
# resolves on some platforms is a trap regardless of who trips it first.
_AF_UNIX = int(getattr(socket, "AF_UNIX", 1))


def _unix_listeners() -> List[Dict[str, Any]]:
    """AF_UNIX listening sockets, shaped exactly as osquery reports them.

    WHY THIS EXISTS (found by the S3 conformance run, 2026-09-23). The inet
    pass below cannot produce these for two independent reasons: psutil's
    ``kind="inet"`` excludes AF_UNIX outright, and psutil reports every unix
    socket with ``status == CONN_NONE``, so the ``CONN_LISTEN`` filter would
    drop all of them even if the kind were widened.

    The result was the phase's OWN central failure, inside the substrate: the
    table advertised itself SERVED while never looking at unix sockets at all,
    so ``SELECT path FROM listening_ports WHERE family = 1`` answered "no rows"
    -- indistinguishable from "measured, and there are none" -- on a host
    running 1,538 of them. A pack asking which daemon owns a socket got a
    confident, wrong, empty answer.

    A unix socket with a bound path IS the listener; an empty ``laddr`` is a
    connected or anonymous socket and osquery does not list those either.
    """
    import psutil  # noqa: PLC0415

    out: List[Dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind="unix")
    except (psutil.Error, OSError, NotImplementedError, ValueError):
        # A platform whose psutil cannot enumerate unix sockets must not cost
        # us the inet rows as well; the caller still gets a real answer for
        # the families we can see.
        logger.debug("psutil cannot enumerate unix sockets on this platform")
        return out
    for conn in conns:
        path = conn.laddr if isinstance(conn.laddr, str) else ""
        if not path:
            continue
        out.append(
            {
                "pid": conn.pid,
                # osquery reports 0/0/"" for these three on AF_UNIX; the path
                # carries the identity. Matching it exactly is what lets one
                # pack run against either provider.
                "port": 0,
                "address": "",
                "protocol": 0,
                "family": _AF_UNIX,
                "path": path,
                "fd": getattr(conn, "fd", None),
            }
        )
    return out


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
    out.extend(_unix_listeners())
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
    # No collector: addresses come from the OS, not the hardware inventory.
    _register_table(
        "interface_addresses", lambda: None, lambda _c: build_interface_addresses()
    )
    # No collector: the mount table comes from the OS, not from the hardware
    # inventory -- see build_mounts.
    _register_table("mounts", lambda: None, lambda _c: build_mounts())
    _register_table("processes", ProcessCollector, build_processes)
    _register_table("certificates", CertificateCollector, build_certificates)
    _register_table(
        "sysmanage_packages", SoftwareInventoryCollector, build_sysmanage_packages
    )
    _register_table(
        "sysmanage_available_updates", UpdateDetector, build_available_updates
    )
    _register_table(
        "sysmanage_process_packages",
        lambda: None,
        lambda _c: _process_packages(),
    )
    # Parameterized -- see PARAMETERIZED_TABLES. Registered here so the
    # coverage advertisement reports it like any other table (this agent CAN
    # serve it on every platform); the factory/builder pair is never called,
    # because ``collect`` intercepts the table before the NATIVE_TABLES lookup.
    _register_table(
        "sysmanage_file_state", lambda: None, lambda _c: _PARAMETERIZED_BUILDER
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


def _process_packages() -> List[Dict[str, Any]]:
    """Kept in its own module: fact_native is near the 1,000-line limit."""
    from src.sysmanage_agent.collection.fact_process_packages import (  # noqa: PLC0415
        build_process_packages,
    )

    return build_process_packages()


# Tables whose CONTENT depends on something that travels with the dispatch
# rather than on the host alone. Every other contract table answers "what is
# true here"; a watch list answers "what is true about THESE paths", and the
# paths are policy the server holds. Kept as an explicit set rather than a
# signature probe so the special case is greppable.
PARAMETERIZED_TABLES = frozenset({"sysmanage_file_state"})

# Sentinel returned by the registered builder for a parameterized table, so a
# future caller that reaches it through NATIVE_TABLES instead of ``collect``
# fails loudly here rather than silently reporting an empty table.
_PARAMETERIZED_BUILDER = None


def _build_parameterized(table: str, params: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Build one parameterized table from the dispatch's own parameters.

    An absent or empty parameter is NOT an error: it means the server assigned
    no watch list to this host, and the honest answer is zero rows. The
    consumer is what must distinguish "nothing watched" from "everything
    watched matched" -- see the differ, which refuses to call two empty watch
    lists identical.
    """
    if table == "sysmanage_file_state":
        from src.sysmanage_agent.collection.fact_file_state import (  # noqa: PLC0415
            build_file_state,
        )

        return build_file_state(params.get("paths") or [])
    logger.warning("no builder for parameterized table %s", table)
    return []


def collect(
    tables: Sequence[str],
    table_params: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Build the requested tables. Unknown/unregistered tables are skipped.

    Registers first if nothing has. ``NATIVE_TABLES`` is filled by
    ``register_native_provider()``, so a caller that collects without
    bootstrapping used to get ``{}`` for every table -- not an error, just
    silence, which reads as "this host has no facts" and is wrong in the
    direction that looks like data. The conformance harness did exactly that
    on 2026-09-21 and reported the native provider as empty on a FreeBSD box
    that serves 1,116 packages.
    """
    if not NATIVE_TABLES:
        register_native_provider()
    collected: Dict[str, List[Dict[str, Any]]] = {}
    cache: Dict[Any, Any] = {}
    for table in tables:
        if table in PARAMETERIZED_TABLES:
            params = (table_params or {}).get(table) or {}
            collected[table] = _rows(
                lambda tb=table, pr=params: _build_parameterized(tb, pr)
            )
            continue
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
