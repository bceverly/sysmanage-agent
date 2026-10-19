# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Machine checks (Phase 23.1): the hardware errors the CPU itself reports --
memory, cache, bus, interconnect -- counted over the last 24 hours.

* Linux ..... rasdaemon's own database, through ``ras-mc-ctl --errors``
              (only where rasdaemon is installed: without it the kernel log
              is the only record, and EDAC already counts memory errors, so
              an absent rasdaemon adds no source line -- no noise)
* Windows ... WHEA-Logger events in the System log (the PowerShell script in
              ``hardware_health_windows``), judged here the same way

One component, kind ``memory``: corrected errors only -> WARNING with
``machine_checks`` {count}; any uncorrected / fatal one -> FAILED with
``machine_checks_fatal`` {count}.

``ras-mc-ctl --errors`` prints one line per MCE record under ``MCE
events:`` (or ``No MCE errors.``), each ``<id> <YYYY-MM-DD HH:MM:SS +zzzz>
error: <message>, ..., mci <MCi_STATUS decoded>, ...`` -- the format read
from ras-mc-ctl 0.8.4 itself.  Its ``--since`` takes a date only, so the
agent asks from yesterday's date and keeps the last 24 hours itself.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from src.sysmanage_agent.collection.hardware_health import (
    FAILED,
    MEMORY,
    OK,
    RAN,
    SOURCE_FAILED,
    WARNING,
    Report,
    Runner,
    reason,
)

WINDOW_HOURS = 24
RASDAEMON = "rasdaemon"

# The record's prefix; the error text is the rest of the line without its
# leading spaces.  The old ``error:\s*(.*)$`` tail overlapped and backtracked
# (Sonar S5852).
_MCE_RECORD = re.compile(
    r"\s*\d+\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: [+-]\d{4})?)\s+error:"
)
# Uncorrected in any of rasdaemon's spellings (Intel "Uncorrected_error",
# AMD "Uncorrected (Fatal)" / "Uncorrected (Non-Fatal)"), or a corrupt
# processor context: never "Corrected_error".
_FATAL = re.compile(r"\bUncorrected|Processor_context_corrupt")


def machine_check_state(corrected: int, fatal: int) -> Tuple[str, List[Dict]]:
    """Uncorrected errors fail; corrected ones warn; none is ok."""
    if fatal:
        return FAILED, [reason("machine_checks_fatal", count=fatal)]
    if corrected:
        return WARNING, [reason("machine_checks", count=corrected)]
    return OK, []


def add_machine_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    report: Report, ident: str, name: str, corrected: int, fatal: int, source: str
) -> None:
    state, reasons = machine_check_state(corrected, fatal)
    metrics = {
        "corrected_errors": corrected,
        "uncorrected_errors": fatal,
        "window_hours": WINDOW_HOURS,
    }
    report.add(MEMORY, ident, name, state, reasons, metrics, source)


def _timestamp(text: str) -> Optional[datetime]:
    """rasdaemon's ``%Y-%m-%d %H:%M:%S %z`` (local time without a zone)."""
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            stamp = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return stamp if stamp.tzinfo else stamp.astimezone()
    return None


def parse_ras_errors(text: str, now: datetime) -> Optional[Tuple[int, int]]:
    """``ras-mc-ctl --errors`` -> (corrected, fatal) machine checks since
    ``now`` - 24 h, or None when the output has no MCE section at all (a
    rasdaemon built without MCE support, as on ARM)."""
    since = now - timedelta(hours=WINDOW_HOURS)
    corrected = fatal = 0
    found = in_mce = False
    for line in text.splitlines():
        if line.startswith("No MCE errors"):
            found = True
        elif line.startswith("MCE events:"):
            found = in_mce = True
        elif in_mce and not line.strip():
            in_mce = False
        elif in_mce:
            judged = _judge_record(line, since)
            corrected += judged == "corrected"
            fatal += judged == "fatal"
    return (corrected, fatal) if found else None


def _judge_record(line: str, since: datetime) -> Optional[str]:
    """One MCE record: "fatal", "corrected", or None (older / unreadable)."""
    match = _MCE_RECORD.match(line)
    stamp = _timestamp(match.group(1)) if match else None
    if stamp is None or stamp < since:
        return None
    return "fatal" if _FATAL.search(line[match.end() :].lstrip()) else "corrected"


def collect_rasdaemon(
    report: Report, run: Runner, now: Optional[Callable[[], datetime]] = None
) -> None:
    """Machine checks from rasdaemon; nothing at all when it is absent."""
    current = (now or (lambda: datetime.now(timezone.utc)))()
    since = (current - timedelta(hours=WINDOW_HOURS)).astimezone().date()
    rc, out = run(["ras-mc-ctl", "--errors", f"--since={since.isoformat()}"])
    if rc not in (0, -1):
        # a rasdaemon older than --since: the window is applied here anyway
        rc, out = run(["ras-mc-ctl", "--errors"])
    if rc == -1:
        return  # no rasdaemon: EDAC already covers memory
    if rc != 0:
        report.source(RASDAEMON, SOURCE_FAILED, out)
        return
    counts = parse_ras_errors(out, current)
    report.source(RASDAEMON, RAN)
    if counts is not None:
        add_machine_checks(report, "mce", "Machine checks", *counts, RASDAEMON)
