# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Send-on-change for snapshot reports (server Phase 22.1).

WHY
---
Every five minutes the agent sent its whole software inventory, users,
hardware, certificates, roles, firewall, antivirus... -- ~288 full inventories
a day per host, almost all identical to the last.  The server's scale harness
showed what that costs: at 1,000 agents ~90 messages a second arrive, most of
them repeats, and a single server process keeps up with about a third of that.

THE RULE
--------
A snapshot report is sent only when its content differs from the last one
this agent queued, or when that last one is older than ``RESEND_AFTER`` (24 h
-- well inside the server's freshest posture window, two days).  "Content"
ignores fields that change on every collection without carrying information
(timestamps, ids).  Two report types follow their own cadence:

  * process lists change on every collection (CPU percentages), so they are
    sent when the SET of processes changes, else at most every 15 minutes;
  * host metrics are samples, sent every 15 minutes -- the server keeps one
    sample per 15 minutes anyway.

Always sent: anything the server ASKED for (a command or a refresh broadcast
runs inside ``forced()``) and everything after the agent's identity changes
(``reset()``).

The memory survives an agent RESTART (server Phase 22.2): it is kept in the
agent's database (``src/database/sent_reports.py``).  It used to be in-process
on purpose -- a fresh process told the server everything once -- but at fleet
scale that is every agent's full inventory at once whenever the fleet is
upgraded or rebooted, the burst the 10,000-agent storm could not drain.  The
24-hour resend still bounds how stale the server can get, and timestamps are
wall-clock now, so they mean something after a restart (a clock that went
backwards makes a report due, never overdue-forever).

A report is remembered only after it was queued (``record``), so a failed
queue never suppresses the next attempt; the queue itself is in the agent's
database too, so a queued report survives a restart and is delivered.
"""

import contextlib
import contextvars
import hashlib
import json
import threading
import time
from typing import Any, Dict, Optional, Tuple

RESEND_AFTER = 24 * 3600
SAMPLE_INTERVAL = 15 * 60

SNAPSHOT_TYPES = frozenset({
    "software_inventory_update", "user_access_update", "hardware_update",
    "host_certificates_update", "role_data", "os_version_update",
    "reboot_status_update", "third_party_repository_update",
    "antivirus_status_update", "firewall_status_update", "graylog_status_update",
    "child_host_list_update", "fips_compliance_update", "package_updates_update",
    "process_status_update", "host_metrics",
})  # fmt: skip

# A newer report of these types replaces a still-queued older one (22.1):
# each is the whole current state, so after an outage only the newest is
# worth sending.  Not host_metrics -- every sample is a point on a chart --
# and never a paginated type (a batch is many messages of one type).
SUPERSEDING_TYPES = (SNAPSHOT_TYPES - {"host_metrics"}) | {"heartbeat"}


def supersedes(message_type: str) -> bool:
    """Does a new ``message_type`` message replace a pending older one?"""
    return message_type in SUPERSEDING_TYPES


# Fields that change on every collection without carrying information.
VOLATILE = frozenset({
    "timestamp", "collection_timestamp", "collected_at", "detection_timestamp",
    "message_id", "host_token",
})  # fmt: skip

# Per process: what identifies it (its CPU and memory figures do not).
_PROCESS_IDENTITY = ("pid", "name", "user", "username", "command", "cmdline", "exe")

_forced = contextvars.ContextVar("send_forced", default=False)


@contextlib.contextmanager
def forced():
    """Everything sent inside this block goes out, changed or not -- the
    server asked for it."""
    token = _forced.set(True)
    try:
        yield
    finally:
        _forced.reset(token)


def is_forced() -> bool:
    """True inside ``forced()``: the server asked for this."""
    return _forced.get()


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def _process_identity(data: Dict[str, Any]) -> Any:
    processes = data.get("processes")
    if not isinstance(processes, list):
        return _canonical(data)
    return sorted(
        json.dumps(
            {k: p.get(k) for k in _PROCESS_IDENTITY}, sort_keys=True, default=str
        )
        for p in processes
        if isinstance(p, dict)
    )


def digest(message: Dict[str, Any]) -> str:
    """The content fingerprint of a report (volatile fields excluded)."""
    data = message.get("data", message)
    if message.get("message_type") == "process_status_update":
        basis = _process_identity(data)
    elif message.get("message_type") == "host_metrics":
        basis = None  # samples: time-based only
    else:
        basis = _canonical(data)
    encoded = json.dumps(basis, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class SnapshotGate:
    """Remembers, per report type, what was last queued and when."""

    def __init__(self, clock=time.time, store=None):
        self._clock = clock
        self._store = store  # sent_reports (persisted), or None (memory only)
        self._last: Dict[str, Tuple[str, float]] = {}
        self._loaded = store is None
        self._lock = threading.Lock()

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        persisted = self._store.load()
        with self._lock:
            if not self._loaded:
                for message_type, value in persisted.items():
                    self._last.setdefault(message_type, value)
                self._loaded = True

    def decide(self, message: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """``(send, digest)`` for this report; ``digest`` is what to
        ``record`` once it is queued (None for reports this gate ignores)."""
        message_type = message.get("message_type")
        if message_type not in SNAPSHOT_TYPES:
            return True, None
        fingerprint = digest(message)
        if _forced.get():
            return True, fingerprint
        self._ensure_loaded()
        with self._lock:
            previous = self._last.get(message_type)
        if previous is None:
            return True, fingerprint
        last_digest, last_at = previous
        age = self._clock() - last_at
        if age < 0:
            return True, fingerprint  # the clock went backwards: resend
        if message_type == "host_metrics":
            return age >= SAMPLE_INTERVAL, fingerprint
        resend_after = (
            SAMPLE_INTERVAL if message_type == "process_status_update" else RESEND_AFTER
        )
        return fingerprint != last_digest or age >= resend_after, fingerprint

    def record(self, message_type: str, fingerprint: Optional[str]) -> None:
        if fingerprint is None:
            return
        now = self._clock()
        with self._lock:
            self._last[message_type] = (fingerprint, now)
        if self._store is not None:
            self._store.save(message_type, fingerprint, now)

    def reset(self) -> None:
        """Forget everything: the next collection sends every report."""
        with self._lock:
            self._last.clear()
            self._loaded = True  # nothing to load: the memory was just wiped
        if self._store is not None:
            self._store.clear()


def _persisted_store():
    from src.database import sent_reports  # pylint: disable=import-outside-toplevel

    return sent_reports


gate = SnapshotGate(store=_persisted_store())
