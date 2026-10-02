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
runs inside ``forced()``), everything after the agent's identity changes
(``reset()``), and everything after an agent restart (the memory is in-process
on purpose: a fresh process tells the server everything once).

A report is remembered only after it was queued (``record``), so a failed
queue never suppresses the next attempt.
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

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._last: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def decide(self, message: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """``(send, digest)`` for this report; ``digest`` is what to
        ``record`` once it is queued (None for reports this gate ignores)."""
        message_type = message.get("message_type")
        if message_type not in SNAPSHOT_TYPES:
            return True, None
        fingerprint = digest(message)
        if _forced.get():
            return True, fingerprint
        with self._lock:
            previous = self._last.get(message_type)
        if previous is None:
            return True, fingerprint
        last_digest, last_at = previous
        age = self._clock() - last_at
        if message_type == "host_metrics":
            return age >= SAMPLE_INTERVAL, fingerprint
        resend_after = (
            SAMPLE_INTERVAL if message_type == "process_status_update" else RESEND_AFTER
        )
        return fingerprint != last_digest or age >= resend_after, fingerprint

    def record(self, message_type: str, fingerprint: Optional[str]) -> None:
        if fingerprint is None:
            return
        with self._lock:
            self._last[message_type] = (fingerprint, self._clock())

    def reset(self) -> None:
        """Forget everything: the next collection sends every report."""
        with self._lock:
            self._last.clear()


gate = SnapshotGate()
