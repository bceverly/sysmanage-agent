# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Which ZFS datasets the off-site copy sends, and the commands for them.

* Every dataset at and under the storage path's own dataset -- each host's
  repository, the storage host's own (24.13), cloud photos -- is sent ON ITS
  OWN (``zfs send``, never ``-R``): restate's datasets appear as hosts are
  added, and a new one starts with a full instead of breaking a recursive
  incremental.  The operator may leave datasets out, and add others the
  storage host keeps (``include``).
* The copy keeps its own snapshots, ``<dataset>@sysmanage-offsite-<UTC
  time>``, as incremental bases -- never sanoid's or the seal's, which are
  pruned on their own schedules and would break the chain.  After a good
  upload only the new snapshot and its base are kept.
"""

import datetime
import re
from typing import Dict, Iterable, List, Optional, Set

SNAP_PREFIX = "sysmanage-offsite-"
_DATASET = re.compile(r"[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*")
_SNAP = re.compile(re.escape(SNAP_PREFIX) + r"\d{8}T\d{6}Z")


class DatasetError(ValueError):
    """A dataset or snapshot name the copy will not use."""


def valid_dataset(name: str) -> str:
    if not isinstance(name, str) or len(name) > 255 or not _DATASET.fullmatch(name):
        raise DatasetError(f"not a ZFS dataset name: {name!r}")
    return name


def valid_snapshot(name: str) -> str:
    if not isinstance(name, str) or not _SNAP.fullmatch(name):
        raise DatasetError(f"not an off-site copy snapshot: {name!r}")
    return name


def snapshot_name(moment: Optional[datetime.datetime] = None) -> str:
    moment = moment or datetime.datetime.now(datetime.timezone.utc)
    return SNAP_PREFIX + moment.astimezone(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )


def filesystems(listing: str) -> Dict[str, str]:
    """``zfs list -H -t filesystem -o name,mountpoint`` -> {name: mountpoint}."""
    found: Dict[str, str] = {}
    for line in listing.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and _DATASET.fullmatch(parts[0]):
            found[parts[0]] = parts[1]
    return found


def storage_dataset(found: Dict[str, str], storage_path: str) -> Optional[str]:
    """The dataset mounted exactly at the storage path."""
    wanted = storage_path.rstrip("/") or "/"
    return next(
        (name for name, point in found.items() if point.rstrip("/") == wanted), None
    )


def chosen(
    found: Dict[str, str], root: Optional[str], exclude: Iterable[str],
    include: Iterable[str],
) -> List[str]:  # fmt: skip
    """The datasets to send, in a stable order: ``root`` and everything under
    it, minus ``exclude`` (and whatever is under an excluded one), plus
    ``include`` -- only datasets that exist."""
    left_out = {valid_dataset(d) for d in exclude}

    def excluded(name: str) -> bool:
        return any(name == d or name.startswith(d + "/") for d in left_out)

    picked: Set[str] = set()
    if root:
        picked = {n for n in found if n == root or n.startswith(root + "/")}
    picked |= {valid_dataset(d) for d in include if d in found}
    return sorted(n for n in picked if not excluded(n))


def offsite_snapshots(listing: str, dataset: str) -> List[str]:
    """Our snapshot names of ``dataset`` from ``zfs list -H -t snapshot -o
    name -d 1 <dataset>``, oldest first."""
    names = []
    for line in listing.splitlines():
        full = line.strip()
        if full.startswith(dataset + "@"):
            snap = full[len(dataset) + 1 :]
            if _SNAP.fullmatch(snap):
                names.append(snap)
    return sorted(names)


def to_remove(have: Iterable[str], keep: Iterable[Optional[str]]) -> List[str]:
    kept = {k for k in keep if k}
    return [s for s in have if s not in kept]


# --- argv (the caller adds sudo and the zfs path) ---------------------------------


def list_filesystems() -> List[str]:
    return ["zfs", "list", "-H", "-t", "filesystem", "-o", "name,mountpoint"]


def list_snapshots(dataset: str) -> List[str]:
    return ["zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-d", "1",
            valid_dataset(dataset)]  # fmt: skip


def take_snapshots(datasets: Iterable[str], snapshot: str) -> List[str]:
    """One ``zfs snapshot`` for all of them: atomic, a consistent moment."""
    valid_snapshot(snapshot)
    return ["zfs", "snapshot"] + [f"{valid_dataset(d)}@{snapshot}" for d in datasets]


def send(dataset: str, snapshot: str, base: Optional[str] = None) -> List[str]:
    target = f"{valid_dataset(dataset)}@{valid_snapshot(snapshot)}"
    if base:
        return ["zfs", "send", "-i", f"{dataset}@{valid_snapshot(base)}", target]
    return ["zfs", "send", target]


def destroy(dataset: str, snapshot: str) -> List[str]:
    return ["zfs", "destroy", f"{valid_dataset(dataset)}@{valid_snapshot(snapshot)}"]


def receive(dataset: str) -> List[str]:
    return ["zfs", "receive", "-u", valid_dataset(dataset)]
