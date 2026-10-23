# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The backed-up host's own export, mounted only while a job runs (24.1).

Nobody edits /etc/fstab on a backed-up host: the server sends where the
host's repository is exported (the storage host's address and the NFSv4
path, which the storage host's agent worked out), and the agent mounts it
at ``<mount point>/<repo dir>`` when a capture, estimate, listing or restore
starts, and unmounts it when the last one ends.  A mount the operator made
(fstab, autofs) is used as it is and never unmounted.

Between jobs nothing is mounted, so ransomware on the host finds no
repository to reach at all; while one is, the export itself is append-only.
"""

import os
import posixpath
from typing import Dict, List, Optional

from src.i18n import _

from src.sysmanage_agent.backup.job_validation import NFS_TYPES

# Hard (never silently lose a write), TCP, NFSv4 only; no setuid or device
# files from the storage host.
MOUNT_OPTIONS = "vers=4,proto=tcp,hard,nosuid,nodev"


def device(source: Dict[str, str]) -> str:
    """``server:/path`` (an IPv6 server in brackets)."""
    server = source["server"]
    if ":" in server:
        server = f"[{server}]"
    return f"{server}:{source['path']}"


def mount_argv(source: Dict[str, str], where: str) -> List[str]:
    """The exact mount command (run with sudo)."""
    return ["mount", "-t", "nfs4", "-o", MOUNT_OPTIONS, device(source), where]


def mounted_nfs(where: str, mounts: Dict[str, str]) -> bool:
    """Is ``where`` itself an NFS mount right now?"""
    return mounts.get(posixpath.normpath(where)) in NFS_TYPES


# Pre-flight before a capture writes anything (24.1): the repository's mount
# must take a new file, lock it -- NFS locking is what keeps a capture and a
# storage-side prune apart -- and have room.  Read-only jobs skip it.
MIN_FREE_BYTES = 1 << 30
MIN_FREE_FRACTION = 0.01
PREFLIGHT_SECONDS = 30
PROBE = ".sysmanage-preflight-"


def preflight(where: str, run_id: str) -> Optional[str]:
    """None when the repository can take a capture, else why not.  Blocking
    file I/O on an NFS mount: call it off the event loop, with a timeout."""
    import fcntl  # pylint: disable=import-outside-toplevel  # Unix only

    probe = posixpath.join(where, PROBE + run_id)
    try:
        handle = os.open(probe, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        return _("The backup storage at %(where)s cannot take new files: %(error)s") % {
            "where": where, "error": error.strerror}  # fmt: skip
    try:
        fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(handle, fcntl.LOCK_UN)
    except OSError as error:
        return _("Locking does not work on the backup storage at %(where)s: %(error)s") % {
            "where": where, "error": error.strerror}  # fmt: skip
    finally:
        os.close(handle)
        try:
            os.unlink(probe)
        except OSError:
            pass
    stats = os.statvfs(where)
    free, total = stats.f_bavail * stats.f_frsize, stats.f_blocks * stats.f_frsize
    if free < MIN_FREE_BYTES or (total and free < total * MIN_FREE_FRACTION):
        return _("The backup storage at %(where)s is nearly full (%(free)d MB free).") % {
            "where": where, "free": free // (1 << 20)}  # fmt: skip
    return None
