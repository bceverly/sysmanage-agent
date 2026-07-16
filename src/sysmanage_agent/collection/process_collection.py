# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Running-process collection and termination for the SysManage agent.

Uses ``psutil`` (already an agent dependency) so the same code path works on
Linux, macOS, the BSDs, and Windows.  Collection takes a two-pass CPU sample
so ``cpu_percent`` is meaningful rather than the 0.0 that a single call
returns, then sorts by resource usage and caps the result so a busy host
doesn't ship tens of thousands of rows every interval.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

from src.i18n import _

# Cap the snapshot so a host with thousands of processes doesn't flood the
# server.  We keep the most resource-hungry ones (the ones an operator would
# want to see/kill); truncation is logged, never silent.
MAX_PROCESSES = 1000

# Seconds between the priming pass and the measured pass for CPU sampling.
_CPU_SAMPLE_INTERVAL = 0.5

# Fields pulled in a single ``oneshot()`` to minimise per-process syscalls.
_PROC_ATTRS = [
    "pid",
    "ppid",
    "name",
    "username",
    "status",
    "memory_percent",
    "memory_info",
    "cmdline",
    "create_time",
]


class ProcessCollector:
    """Collects running processes and terminates them on request."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)

    def collect_processes(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Return ``(processes, truncated)`` for the current host.

        ``processes`` is sorted by CPU% then memory% (descending) and capped at
        ``MAX_PROCESSES``; ``truncated`` is True when the cap dropped rows.
        Blocking (it sleeps for a CPU sample) — call via a thread executor.
        """
        # Pass 1: prime cpu_percent() so the second read reflects real usage.
        primed = []
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(None)
                primed.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(_CPU_SAMPLE_INTERVAL)

        cpu_count = psutil.cpu_count() or 1
        processes: List[Dict[str, Any]] = []
        for proc in primed:
            try:
                with proc.oneshot():
                    # Normalise to whole-machine percent (psutil reports a
                    # single busy core as ~100% * Ncores otherwise).
                    cpu_percent = proc.cpu_percent(None) / cpu_count
                    info = proc.as_dict(attrs=_PROC_ATTRS)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            processes.append(self._normalise(info, cpu_percent))

        processes.sort(
            key=lambda p: (p["cpu_percent"] or 0.0, p["memory_percent"] or 0.0),
            reverse=True,
        )

        truncated = len(processes) > MAX_PROCESSES
        if truncated:
            self.logger.info(
                _("Process snapshot truncated from %d to %d (cap)"),
                len(processes),
                MAX_PROCESSES,
            )
            processes = processes[:MAX_PROCESSES]

        return processes, truncated

    @staticmethod
    def _normalise(info: Dict[str, Any], cpu_percent: float) -> Dict[str, Any]:
        """Turn a psutil as_dict() blob into the server's wire format."""
        cmdline = info.get("cmdline") or []
        command_line = " ".join(cmdline) if cmdline else (info.get("name") or "")

        mem_info = info.get("memory_info")
        memory_rss_bytes = getattr(mem_info, "rss", None) if mem_info else None

        create_time = info.get("create_time")
        started_at = None
        if create_time:
            started_at = datetime.fromtimestamp(
                create_time, tz=timezone.utc
            ).isoformat()

        mem_percent = info.get("memory_percent")
        return {
            "pid": info.get("pid"),
            "parent_pid": info.get("ppid"),
            "name": info.get("name") or "",
            "username": info.get("username"),
            "status": info.get("status"),
            "cpu_percent": round(cpu_percent, 2),
            "memory_percent": (
                round(mem_percent, 2) if mem_percent is not None else None
            ),
            "memory_rss_bytes": memory_rss_bytes,
            "command_line": command_line[:4096],  # guard pathological cmdlines
            "started_at": started_at,
        }

    def kill_process(
        self,
        pid: int,
        *,
        force: bool = False,
        expected_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Terminate ``pid``.

        ``force`` sends SIGKILL instead of SIGTERM.  ``expected_name`` is an
        optional safety check — if given and the live process name doesn't
        match, the kill is refused (guards against PID reuse between the
        snapshot the operator saw and now).
        """
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return {"success": False, "error": _("No process with PID %d") % pid}

        try:
            actual_name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            actual_name = None

        if expected_name and actual_name and actual_name != expected_name:
            return {
                "success": False,
                "error": _(
                    "PID %(pid)d is now '%(actual)s', not '%(expected)s' "
                    "(process may have been recycled); kill refused"
                )
                % {"pid": pid, "actual": actual_name, "expected": expected_name},
            }

        try:
            if force:
                proc.kill()
            else:
                proc.terminate()
            # Best-effort reap so the caller learns if it actually exited.
            try:
                proc.wait(timeout=5)
                exited = True
            except psutil.TimeoutExpired:
                exited = False
        except psutil.AccessDenied:
            return {
                "success": False,
                "error": _("Access denied terminating PID %d") % pid,
            }
        except psutil.NoSuchProcess:
            # Already gone between lookup and signal — treat as success.
            exited = True

        self.logger.info(
            _("Sent %(sig)s to PID %(pid)d ('%(name)s')"),
            {"sig": "SIGKILL" if force else "SIGTERM", "pid": pid, "name": actual_name},
        )
        return {
            "success": True,
            "pid": pid,
            "name": actual_name,
            "signal": "SIGKILL" if force else "SIGTERM",
            "exited": exited,
        }
