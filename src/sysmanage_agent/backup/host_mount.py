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

import posixpath
from typing import Dict, List

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
