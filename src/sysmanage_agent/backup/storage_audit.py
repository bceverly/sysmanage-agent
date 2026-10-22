# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Is this storage host set up so a backed-up host can only append? (24.1/24.5)

The documented storage layout, checked rather than assumed.  Read-only: it
reads configuration files, ``sysctl`` / ``sysrc`` values, the active export
list, ``zfs get`` and ``stat`` -- it changes nothing.  Each finding is
``{"code", "level", "params"}``; ``level`` is ``error`` (backups are not
protected or will not work), ``warning`` (they work, with a weakness) or
``ok``.  The server turns the codes into messages with the fix.

Baseline (once per storage host): the NFS server runs, serves NFSv4, and
(FreeBSD) shows NFS clients' locks to local programs; the backup service
account exists.  Per repository: it is its own filesystem and its own
export, restricted to the backed-up host's address and mapped to the
service account, and its directories enforce append-only (finished packs
and snapshots owned by root, the directories sticky and group-writable).
"""

import grp
import os
import platform
import posixpath
import pwd
import stat
import subprocess  # nosec B404 -- fixed argv, no shell
from typing import Any, Callable, Dict, List, Optional

from src.sysmanage_agent.backup import storage_fs

ERROR, WARNING, OK = "error", "warning", "ok"
PROTECTED_DIR_MODE = 0o1770
FINISHED_SUFFIXES = (".tar.gz", ".idx", ".sum", ".seek")
TIMEOUT = 10


def _finding(code: str, level: str, **params) -> Dict[str, Any]:
    return {"code": code, "level": level, "params": params}


def _run(argv: List[str]) -> Optional[str]:
    try:
        done = subprocess.run(  # nosec B603 -- fixed argv
            argv, capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------


def _freebsd_baseline(run: Callable, read: Callable) -> List[Dict[str, Any]]:
    found = []
    enabled = (run(["sysrc", "-n", "nfs_server_enable"]) or "").upper() == "YES"
    running = run(["pgrep", "-x", "nfsd"]) is not None
    found.append(_finding("nfs_server", OK if enabled and running else ERROR,
                          enabled=enabled, running=running))  # fmt: skip
    v4 = (run(["sysrc", "-n", "nfsv4_server_enable"]) or "").upper() == "YES"
    found.append(_finding("nfs_v4", OK if v4 else ERROR))
    minimum = run(["sysctl", "-n", "vfs.nfsd.server_min_nfsvers"])
    found.append(_finding("nfs_v4_only", OK if minimum == "4" else WARNING,
                          min_version=minimum))  # fmt: skip
    locks = run(["sysctl", "-n", "vfs.nfsd.enable_locallocks"])
    found.append(_finding("nfs_local_locks", OK if locks == "1" else ERROR))
    root = any(
        line.strip().startswith("V4:") for line in read("/etc/exports").splitlines()
    )
    found.append(_finding("nfs_v4_root", OK if root else ERROR))
    return found


def _linux_baseline(run: Callable, read: Callable) -> List[Dict[str, Any]]:
    running = any(
        run(["systemctl", "is-active", unit]) == "active"
        for unit in ("nfs-server", "nfs-kernel-server")
    )
    found = [_finding("nfs_server", OK if running else ERROR, running=running)]
    versions = read("/proc/fs/nfsd/versions").split()
    v4 = any(v.startswith("+4") for v in versions)
    found.append(_finding("nfs_v4", OK if v4 else ERROR))
    v3 = "+3" in versions
    found.append(_finding("nfs_v4_only", WARNING if v3 else OK))
    return found


def baseline(system: str, account: str, run=_run, read=_read) -> List[Dict[str, Any]]:
    """The storage host's own NFS and account set-up."""
    found = _freebsd_baseline(run, read) if system == "FreeBSD" else []
    if system == "Linux":
        found = _linux_baseline(run, read)
    try:
        pwd.getpwnam(account)
        grp.getgrnam(account)
        found.append(_finding("service_account", OK, account=account))
    except KeyError:
        found.append(_finding("service_account", ERROR, account=account))
    return found


# ---------------------------------------------------------------------------
# exports
# ---------------------------------------------------------------------------


def _export_lines(system: str, read: Callable) -> List[str]:
    """Every export line in effect (FreeBSD: exports + ZFS sharenfs file;
    Linux: the kernel's active table, else the configured files)."""
    if system == "FreeBSD":
        text = read("/etc/exports") + "\n" + read("/etc/zfs/exports")
    else:
        text = read("/var/lib/nfs/etab") or read("/etc/exports")
        exports_d = "/etc/exports.d"
        if os.path.isdir(exports_d):
            for name in sorted(os.listdir(exports_d)):
                if name.endswith(".exports"):
                    text += "\n" + read(posixpath.join(exports_d, name))
    lines = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line and not line.startswith("V4:"):
            lines.append(line)
    return lines


def _covers(export: Dict[str, Any], path: str, own_fs: bool) -> bool:
    """Does ``export`` reach ``path``?  An export never crosses into another
    filesystem -- unless (Linux) it says ``crossmnt`` or ``nohide`` -- so a
    repository on its own dataset / subvolume is out of a parent's reach."""
    if path == export["path"]:
        return True
    if not (export["alldirs"] and path.startswith(export["path"].rstrip("/") + "/")):
        return False
    crosses = {"crossmnt", "nohide"} & set(export["options"])
    return not own_fs or bool(crosses)


def _parse_export(system: str, line: str) -> Dict[str, Any]:
    """``{"path", "options", "clients"}`` for one export line."""
    fields = line.split()
    path = fields[0]
    if system == "FreeBSD":
        options = [f for f in fields[1:] if f.startswith("-")]
        clients = [f for f in fields[1:] if not f.startswith("-")]
        return {"path": path, "options": options, "clients": clients,
                "alldirs": "-alldirs" in options}  # fmt: skip
    clients, options = [], []
    for spec in fields[1:]:
        host, _, opts = spec.partition("(")
        clients.append(host)
        options += opts.rstrip(")").split(",") if opts else []
    # Linux exports a whole filesystem tree below the path by default.
    return {"path": path, "options": options, "clients": clients, "alldirs": True}


def _mapping(system: str, options: List[str], uid: int, gid: int) -> str:
    """``ok`` | ``implicit_group`` | ``missing``: are all clients mapped to
    the service account?"""
    if system == "FreeBSD":
        mapall = next((o for o in options if o.startswith("-mapall=")), None)
        if mapall is None:
            return "missing"
        return "ok" if ":" in mapall else "implicit_group"
    squash = "all_squash" in options
    anonuid = f"anonuid={uid}" in options
    anongid = f"anongid={gid}" in options
    return "ok" if squash and anonuid and anongid else "missing"


def export_findings(
    system: str,
    repository: str,
    client: Optional[str],
    account: str,
    read=_read,
    own_fs: bool = False,
) -> List[Dict[str, Any]]:
    """How the repository is exported, and to whom."""
    exports = [_parse_export(system, line) for line in _export_lines(system, read)]
    own = [e for e in exports if e["path"] == repository]
    wider = [
        e["path"] for e in exports
        if e["path"] != repository and _covers(e, repository, own_fs)
    ]  # fmt: skip
    found = []
    if wider:
        found.append(_finding("export_shared", ERROR, exports=sorted(set(wider))))
    if not own:
        found.append(_finding("export_own", ERROR if not wider else WARNING))
        return found
    found.append(_finding("export_own", OK))
    clients = sorted({c for e in own for c in e["clients"]})
    open_to = [c for c in clients if c != client and c not in (f"{client}/32",)]
    if not clients or "*" in clients or open_to:
        found.append(_finding("export_restricted", WARNING, clients=clients,
                              expected=client))  # fmt: skip
    else:
        found.append(_finding("export_restricted", OK, clients=clients))
    try:
        uid, gid = pwd.getpwnam(account).pw_uid, grp.getgrnam(account).gr_gid
    except KeyError:
        uid = gid = -1
    mapping = {_mapping(system, e["options"], uid, gid) for e in own}
    level = OK if mapping == {"ok"} else ERROR if "missing" in mapping else WARNING
    found.append(_finding("export_mapping", level, mapping=sorted(mapping)))
    return found


def client_path(system: str, repository: str, read=_read) -> Optional[str]:
    """The path a host mounts over NFSv4 to reach ``repository``, or None
    when this server's set-up does not export it under NFSv4 at all.

    FreeBSD: relative to the ``V4:`` root in /etc/exports.  Linux: relative
    to an ``fsid=0`` / ``fsid=root`` export if there is one, else the path
    itself (Linux's pseudo-root mirrors the real tree)."""
    root = None
    if system == "FreeBSD":
        for line in read("/etc/exports").splitlines():
            fields = line.split("#", 1)[0].split()
            if fields[:1] == ["V4:"] and len(fields) > 1:
                root = fields[1]
        if root is None:
            return None
    else:
        for line in _export_lines(system, read):
            export = _parse_export(system, line)
            if {"fsid=0", "fsid=root"} & set(export["options"]):
                root = export["path"]
        if root is None:
            return repository
    root = posixpath.normpath(root)
    if repository == root:
        return "/"
    if not repository.startswith(root.rstrip("/") + "/"):
        return None
    return "/" + posixpath.relpath(repository, root)


# ---------------------------------------------------------------------------
# the repository itself
# ---------------------------------------------------------------------------


def _protected_dir(st: os.stat_result, gid: int) -> bool:
    return (
        st.st_uid == 0
        and st.st_gid == gid
        and stat.S_IMODE(st.st_mode) == PROTECTED_DIR_MODE
    )


def layout_findings(
    repository: str, account: str, lstat=os.lstat
) -> List[Dict[str, Any]]:
    """Directories sticky + group-writable and root-owned; finished packs
    and snapshots root-owned and read-only."""
    try:
        gid = grp.getgrnam(account).gr_gid
    except KeyError:
        return [_finding("append_only_layout", ERROR, reason="no_account")]
    loose = []
    for sub in ("", "packs", "snapshots"):
        try:
            if not _protected_dir(lstat(posixpath.join(repository, sub)), gid):
                loose.append(sub or ".")
        except OSError:
            continue  # not created yet (no capture so far)
    unprotected = 0
    packs = posixpath.join(repository, "packs")
    try:
        names = os.listdir(packs)
    except OSError:
        names = []
    for name in names:
        if name.endswith(FINISHED_SUFFIXES) and not name.startswith("."):
            try:
                st = lstat(posixpath.join(packs, name))
            except OSError:
                continue
            if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o222:
                unprotected += 1
    if loose or unprotected:
        return [_finding("append_only_layout", WARNING, directories=loose,
                         unprotected_files=unprotected)]  # fmt: skip
    return [_finding("append_only_layout", OK)]


def filesystem_findings(repository: str, read_text: Callable) -> List[Dict[str, Any]]:
    """Its own filesystem (dataset / subvolume / mount)?"""
    described = storage_fs.describe(repository, read_text=read_text)
    own = described["mount_point"] == posixpath.normpath(repository)
    if described["type"] == "btrfs" and described["btrfs_subvolume"]:
        own = True
    return [_finding("own_filesystem", OK if own else WARNING,
                     type=described["type"], mount_point=described["mount_point"])]  # fmt: skip


def audit(
    repository: str,
    *,
    client: Optional[str],
    account: str,
    read_text: Callable,
    system: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Every finding for one repository on this storage host."""
    system = system or platform.system()
    filesystem = filesystem_findings(repository, read_text)
    own_fs = filesystem[0]["level"] == OK
    return (
        baseline(system, account)
        + filesystem
        + export_findings(system, repository, client, account, own_fs=own_fs)
        + layout_findings(repository, account)
    )
