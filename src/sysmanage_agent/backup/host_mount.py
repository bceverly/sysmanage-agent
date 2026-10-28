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

Where systemd runs, the mount is made by systemd (``systemd-mount``) and
every check reads the HOST's mount table (``/proc/1/mountinfo``), never the
agent's own: the agent's unit has PrivateTmp/ProtectHome, which give it a
private mount namespace, so a plain ``mount`` from the agent was visible to
the agent alone.  Its checks passed, restate's own unit (``restate-job@``,
in the host's namespace) saw no mount, and the capture wrote the repository
to the host's local disk -- reported as a good backup (production, ubiquiti,
2026-10-27).
"""

import errno
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


# The host's mount table: what restate's unit sees.  PID 1's, readable
# without privileges; the agent's own (/proc/self) is only the fallback when
# it is not (a container or a hardened /proc).
HOST_MOUNTINFO = "/proc/1/mountinfo"
SELF_MOUNTINFO = "/proc/self/mountinfo"


def systemd_running(isdir=os.path.isdir) -> bool:
    """systemd is PID 1 (sd_booted's test)."""
    return isdir("/run/systemd/system")


def mount_argv(source: Dict[str, str], where: str, systemd: bool = False) -> List[str]:
    """The exact mount command (run with sudo).  With systemd, systemd mounts
    it (a transient mount unit), so it exists in the host's namespace -- not
    in the agent's private one -- and the command waits until it is mounted."""
    if systemd:
        return ["systemd-mount", "--no-ask-password", "--collect", "--type=nfs4",
                f"--options={MOUNT_OPTIONS}", device(source), where]  # fmt: skip
    return ["mount", "-t", "nfs4", "-o", MOUNT_OPTIONS, device(source), where]


def umount_argv(where: str, systemd: bool = False) -> List[str]:
    return ["systemd-umount", where] if systemd else ["umount", where]


def mounted_nfs(where: str, mounts: Dict[str, str]) -> bool:
    """Is ``where`` itself an NFS mount right now?"""
    return mounts.get(posixpath.normpath(where)) in NFS_TYPES


# Pre-flight before a capture writes anything (24.1): the repository must
# take new files, its lock must work -- NFS locking is what keeps a capture
# and a storage-side prune apart -- and it must have room.  Read-only jobs
# skip it.  It makes no file: the repository's top is append-only on the
# storage host (chattr +a), so anything made there could never be removed,
# and ``capture --create`` refuses a directory with anything in it.
MIN_FREE_BYTES = 1 << 30
MIN_FREE_FRACTION = 0.01
PREFLIGHT_SECONDS = 30
LOCK_FILE = "lock"
# lockf answers these while someone else holds the lock (a Linux client is
# told of a lock held on a FreeBSD server as EIO): locking works, and restate
# itself waits or reports busy.
HELD_ELSEWHERE = (errno.EAGAIN, errno.EACCES, errno.EIO)


def preflight(where: str) -> Optional[str]:
    """None when the repository can take a capture, else why not.  Blocking
    file I/O on an NFS mount: call it off the event loop, with a timeout."""
    # Over NFS, access(2) asks the server, so it answers for the export's
    # squashed account, not for this host's user.
    if not os.access(where, os.W_OK | os.X_OK):
        return _cannot_write(where, os.strerror(errno.EACCES))
    reason = _lock_works(posixpath.join(where, LOCK_FILE), where)
    if reason:
        return reason
    stats = os.statvfs(where)
    free, total = stats.f_bavail * stats.f_frsize, stats.f_blocks * stats.f_frsize
    if free < MIN_FREE_BYTES or (total and free < total * MIN_FREE_FRACTION):
        return _("The backup storage at %(where)s is nearly full (%(free)d MB free).") % {
            "where": where, "free": free // (1 << 20)}  # fmt: skip
    return None


def _cannot_write(where: str, error: str) -> str:
    return _("The backup storage at %(where)s cannot take new files: %(error)s") % {
        "where": where, "error": error}  # fmt: skip


def _lock_works(lock: str, where: str) -> Optional[str]:
    """Lock restate's own lock file and let it go; a repository without one
    yet (before its first capture) has nothing to lock."""
    import fcntl  # pylint: disable=import-outside-toplevel  # Unix only

    try:
        handle = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        return _cannot_write(where, error.strerror)
    try:
        fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(handle, fcntl.LOCK_UN)
    except OSError as error:
        if error.errno not in HELD_ELSEWHERE:
            return _("Locking does not work on the backup storage at %(where)s: %(error)s") % {
                "where": where, "error": error.strerror}  # fmt: skip
    finally:
        os.close(handle)
    return None
