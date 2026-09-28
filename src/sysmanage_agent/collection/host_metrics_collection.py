# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Host-level resource metrics for the built-in metric graphs (Phase 21.5).

Five numbers per periodic run -- CPU %, memory used %, swap used %, the
1-minute load average, and the used % of the fullest local disk -- so the
server can keep a history of them.  Everything else the agent reports about
resources is a point-in-time snapshot the server replaces each time.

Two rules shape it:

* **A number we could not read is left out, never sent as 0.**  "No swap
  configured" and "swap unreadable" are not "0% swap used", and a chart would
  draw them as if they were.  The server stores only the series present.
* **CPU is the average over the interval, not an instant.**  psutil's
  ``cpu_percent(interval=None)`` answers "since the previous call", so the
  collector primes it once at construction; every later read is the mean over
  the ~5 minutes since the last periodic run -- the number a chart of the
  period should show -- and never blocks.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psutil

# Keys are the server's built-in metric keys; keep them in step with
# ``backend/services/host_metrics.py`` in the server.
CPU_PERCENT = "host.cpu_percent"
MEMORY_USED_PERCENT = "host.memory_used_percent"
SWAP_USED_PERCENT = "host.swap_used_percent"
LOAD_1M = "host.load_1m"
DISK_USED_PERCENT_MAX = "host.disk_used_percent_max"

# Persistent local filesystems -- the ones "is a disk filling up?" is about.
# Memory-backed (tmpfs), image (squashfs, iso9660) and kernel pseudo
# filesystems are excluded: they are full by design or not disks at all, and
# network filesystems are excluded because statvfs on them can block on a peer.
_DISK_TYPES = frozenset(
    (
        "ext2 ext3 ext4 xfs btrfs zfs f2fs jfs reiserfs vfat msdos msdosfs exfat"
        " ntfs ntfs3 refs ufs ffs hammer hammer2 apfs hfs lfs"
    ).split()
)


def _round(value: float) -> float:
    return round(float(value), 2)


class HostMetricsCollector:
    """Reads the five host metrics; one instance lives for the agent's life."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        # Prime both interval-based readers so the first real read is a mean
        # over a real interval rather than psutil's meaningless first 0.0.
        self._try(lambda: psutil.cpu_percent(interval=None), "cpu (prime)")
        self._try(psutil.getloadavg, "load average (prime)")

    def _try(self, read, what: str) -> Any:
        try:
            return read()
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.debug("host metrics: %s unavailable: %s", what, error)
            return None

    def _swap_percent(self) -> Optional[float]:
        swap = self._try(psutil.swap_memory, "swap")
        # No swap configured is absent, not "0% used".
        if swap is None or not getattr(swap, "total", 0):
            return None
        return swap.percent

    def _load_1m(self) -> Optional[float]:
        load = self._try(psutil.getloadavg, "load average")
        return load[0] if load else None

    def _disk_used_percent_max(self) -> Optional[float]:
        partitions = self._try(lambda: psutil.disk_partitions(all=False), "disks")
        fullest = None
        for part in partitions or []:
            if (part.fstype or "").lower() not in _DISK_TYPES:
                continue
            # A read-only mount (macOS's sealed system volume, a mounted
            # recovery image) cannot fill up in a way anyone can act on.
            if "ro" in (part.opts or "").split(","):
                continue
            usage = self._try(
                lambda p=part.mountpoint: psutil.disk_usage(p),
                f"disk usage of {part.mountpoint}",
            )
            if usage is not None and (fullest is None or usage.percent > fullest):
                fullest = usage.percent
        return fullest

    def collect(self) -> Dict[str, Any]:
        """``{"collected_at": iso, "metrics": {key: value}}`` -- only the
        metrics that could be read."""
        memory = self._try(psutil.virtual_memory, "memory")
        readings = {
            CPU_PERCENT: self._try(lambda: psutil.cpu_percent(interval=None), "cpu"),
            MEMORY_USED_PERCENT: memory.percent if memory is not None else None,
            SWAP_USED_PERCENT: self._swap_percent(),
            LOAD_1M: self._load_1m(),
            DISK_USED_PERCENT_MAX: self._disk_used_percent_max(),
        }
        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {k: _round(v) for k, v in readings.items() if v is not None},
        }
