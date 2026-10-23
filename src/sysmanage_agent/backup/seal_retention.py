# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Which seal snapshots are past the target's retention (24.5).

Every good backup is sealed with a ZFS or read-only btrfs snapshot
(``sysmanage-<run id>``).  Without retention they pile up for ever, and an
administrator would have to clear them by hand.  After each seal the storage
host removes ITS OWN seals older than the target's ``keep_days`` -- always
keeping the newest -- and nothing else:

* ZFS: ``<dataset>@sysmanage-<uuid>`` snapshots of the sealed dataset, aged by
  ZFS's own ``creation`` property.
* btrfs: snapshots this agent made, recorded with their time in a ledger in
  its state directory; one it has no record of is never removed.
"""

import posixpath
import re
from typing import Dict, Iterable, List, Tuple

SEAL_PREFIX = "sysmanage-"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_SEAL_NAME = re.compile(rf"^{SEAL_PREFIX}{_UUID}$")
DAY = 86400


def is_seal(name: str) -> bool:
    """A snapshot name this agent makes (``sysmanage-<run id>``)."""
    return bool(_SEAL_NAME.match(name))


def expired(
    created: Iterable[Tuple[str, float]], keep_days: int, now: float
) -> List[str]:
    """Names older than ``keep_days``, oldest first -- never the newest one,
    so a target always keeps at least one immutable copy."""
    seals = sorted(created, key=lambda item: item[1])
    if len(seals) <= 1:
        return []
    cutoff = now - keep_days * DAY
    return [name for name, at in seals[:-1] if at < cutoff]


def zfs_seals(listing: str, dataset: str) -> List[Tuple[str, float]]:
    """``[(dataset@sysmanage-<uuid>, creation)]`` from
    ``zfs list -Hp -t snapshot -o name,creation -d 1 <dataset>``."""
    found = []
    for line in listing.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or "@" not in fields[0]:
            continue
        owner, _, snap = fields[0].partition("@")
        if owner != dataset or not is_seal(snap):
            continue
        try:
            found.append((fields[0], float(fields[1])))
        except ValueError:
            continue
    return found


def zfs_list_argv(zfs: str, dataset: str) -> List[str]:
    return [
        zfs,
        "list",
        "-Hp",
        "-t",
        "snapshot",
        "-o",
        "name,creation",
        "-d",
        "1",
        dataset,
    ]


def zfs_destroy_argv(zfs: str, snapshot: str) -> List[str]:
    """Recursive: the seal snapshotted every host's child dataset too."""
    return [zfs, "destroy", "-r", snapshot]


def btrfs_seals(ledger: Dict[str, float], snapshot_dir: str) -> List[Tuple[str, float]]:
    """The ledger's seals that live in ``snapshot_dir``."""
    return [
        (path, at)
        for path, at in ledger.items()
        if posixpath.dirname(path) == snapshot_dir and is_seal(posixpath.basename(path))
    ]


def btrfs_delete_argv(btrfs: str, path: str) -> List[str]:
    return [btrfs, "subvolume", "delete", path]


def delete_argv(mode: str, tool: str, name: str) -> List[str]:
    """The command that removes one seal for this seal mode."""
    if mode == "zfs_snapshot":
        return zfs_destroy_argv(tool, name)
    return btrfs_delete_argv(tool, name)
