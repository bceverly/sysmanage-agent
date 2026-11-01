# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Keep a host's backup on the host: leave out its network mounts.

restate's capture goes into any directory it meets, and a network share
mounted on the host (NFS, SMB, sshfs...) is just a directory to it, so the
host's backup would carry another server's data.  Worse, merely opening a
systemd automount point (``x-systemd.automount``, an autofs trigger) mounts
the share.  Found on beast (2026-11-01): an NFS share from the NAS, an SMB
share over Tailscale, and an automounted NFS share.

So, until restate leaves network filesystems out by itself (it will say so
with ``"skips_network_mounts": true`` in ``restate features``), the agent
writes every network and autofs mount point of the HOST's mount table into
a rules file of its own as ``ephemeral``.  restate checks a path against its
rules after an ``fstatat`` that does not follow and before it opens it, so a
left-out automount is never triggered.

An operator who wants a share in this host's backup anyway says so by
putting a path inside it in "Also back up" (``keep_paths``): that mount is
then not left out, and the reply says which.
"""

import posixpath
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup.job_validation import mount_types

# Filesystems whose data lives on another machine (or is fetched on use).
NETWORK_TYPES = frozenset(
    {
        "nfs", "nfs4", "cifs", "smb3", "smbfs", "smb2", "afs", "ncpfs",
        "9p", "ceph", "glusterfs", "lustre", "davfs", "gfs2", "ocfs2",
        "fuse.sshfs", "fuse.rclone", "fuse.s3fs", "fuse.gcsfuse",
        "fuse.glusterfs", "fuse.ceph", "fuse.davfs2", "fuse.goofys",
        "fuse.cephfs", "fuse.juicefs", "fuse.lizardfs", "fuse.moosefs",
    }
)  # fmt: skip
# An automount trigger: opening it mounts whatever is behind it.
AUTOFS = "autofs"
# Already left out by restate's own rules (and never anyone's data).
_SYSTEM_TREES = ("/proc", "/sys", "/dev", "/run")
# Characters restate's glob gives a meaning, and "#" (after whitespace it
# would start a comment): a literal path escapes each with a backslash.
_GLOB_SPECIAL = "\\*?[#"


@dataclass
class Found:
    """What this host's mount table holds that is not this host's."""

    excluded: List[str] = field(default_factory=list)
    kept: List[str] = field(default_factory=list)  # opted in by keep_paths
    native: bool = False  # restate leaves them out itself

    def report(self) -> Dict[str, Any]:
        return {"excluded": self.excluded, "kept": self.kept, "native": self.native}


def skips_network_mounts(features: Optional[Dict[str, Any]]) -> bool:
    """restate leaves network filesystems out by itself (announced in
    ``restate features``; then the agent's rules file is not needed)."""
    return bool((features or {}).get("skips_network_mounts"))


def read_host_mountinfo() -> str:
    """The HOST's mount table (PID 1's): the agent's own namespace is
    private (PrivateTmp/ProtectHome) and may not show what restate sees."""
    for path in (host_mount.HOST_MOUNTINFO, host_mount.SELF_MOUNTINFO):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            continue
    return ""


def _under(path: str, root: str) -> bool:
    root = posixpath.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _literal_prefix(pattern: str) -> Optional[str]:
    """The fixed leading part of an absolute keep pattern, or None for one
    that matches at any depth (no leading ``/``)."""
    if not pattern.startswith("/"):
        return None
    parts = []
    for part in pattern.split("/")[1:]:
        if any(ch in part for ch in "*?[\\"):
            break
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _opted_in(point: str, keep_paths: Iterable[str]) -> bool:
    """A keep path lies inside this mount (or leads into it)."""
    for pattern in keep_paths:
        prefix = _literal_prefix(pattern)
        if prefix is not None and prefix != "/" and _under(prefix, point):
            return True
    return False


def scan(
    mountinfo: str,
    *,
    repository_mount: Optional[str] = None,
    keep_paths: Iterable[str] = (),
) -> Found:
    """The host's network and automount points to leave out, sorted.

    Never the backup repository's own mount (``repository_mount``, the
    target's mount point the agent mounts the storage under), nothing under
    the kernel's virtual trees, and nothing an operator opted into.
    """
    keep = list(keep_paths)
    found = Found()
    for point, fstype in sorted(mount_types(mountinfo or "").items()):
        if fstype not in NETWORK_TYPES and fstype != AUTOFS:
            continue
        point = posixpath.normpath(point)
        if any(_under(point, tree) for tree in _SYSTEM_TREES):
            continue
        if repository_mount and _under(point, repository_mount):
            continue
        if _opted_in(point, keep):
            found.kept.append(point)
        else:
            found.excluded.append(point)
    return found


def _escaped(path: str) -> Optional[str]:
    """``path`` as a literal restate pattern, or None when no rules line can
    hold it (a line break, or whitespace at either end, which the rules
    reader trims)."""
    if "\n" in path or "\r" in path or path != path.strip():
        return None
    return "".join("\\" + ch if ch in _GLOB_SPECIAL else ch for ch in path)


def rules_text(points: Iterable[str]) -> Tuple[str, List[str]]:
    """``(rules file, points it could not express)``."""
    lines = [
        "# Written by sysmanage-agent: this host's network and automount",
        "# points, left out of its backup (another server's data).  Replaced",
        "# before every capture.  To keep one, add a path inside it to the",
        '# policy\'s "Also back up".',
    ]
    skipped = []
    for point in points:
        pattern = _escaped(point)
        if pattern is None:
            skipped.append(point)
            continue
        lines.append(f"ephemeral {pattern}")
    return "\n".join(lines) + "\n", skipped
