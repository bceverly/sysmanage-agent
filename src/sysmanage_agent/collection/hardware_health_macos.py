# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
macOS hardware health (Phase 23.1 S1), from the base system:

* drives ..... ``diskutil info -plist`` for each physical whole disk: the
               SMART verdict macOS itself keeps ("Verified" / "Failing";
               "Not Supported" on many external enclosures -- unknown, not
               healthy)
* thermals ... ``pmset -g therm``: a recorded thermal warning level, or the
               CPU held below full speed
"""

from __future__ import annotations

import plistlib
import re
from typing import Dict, List, Optional

from src.sysmanage_agent.collection.hardware_health import (
    ABSENT,
    DRIVE,
    FAILED,
    OK,
    RAN,
    SENSOR,
    SOURCE_FAILED,
    UNKNOWN,
    WARNING,
    Report,
    reason,
)

_SMART = {"Verified": OK, "Failing": FAILED}


def _plist(text: str) -> Optional[Dict]:
    try:
        data = plistlib.loads(text.encode())
    except (ValueError, TypeError):  # InvalidFileException is a ValueError
        return None
    return data if isinstance(data, dict) else None


def parse_whole_disks(text: str) -> List[str]:
    """``diskutil list -plist physical`` -> the whole disks."""
    data = _plist(text) or {}
    return [str(d) for d in data.get("WholeDisks") or []]


def disk_component(info: Dict) -> Dict[str, object]:
    smart = str(info.get("SMARTStatus") or "")
    state = _SMART.get(smart, UNKNOWN)
    reasons = [] if state == OK else [reason("smart_status", status=smart or None)]
    return {
        "id": str(info.get("DeviceIdentifier") or ""),
        "name": info.get("MediaName") or info.get("IORegistryEntryName"),
        "state": state,
        "reasons": reasons,
        "metrics": {
            "smart_status": smart or None,
            "solid_state": info.get("SolidState"),
            "internal": info.get("Internal"),
        },
    }


def parse_pmset_therm(text: str):
    """State and reasons from ``pmset -g therm``."""
    reasons = []
    level = re.search(r"thermal warning level\s*(?:set to|=|:)\s*(\d+)", text, re.I)
    if level and int(level.group(1)) > 0:
        reasons.append(reason("thermal_warning", level=int(level.group(1))))
    limit = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", text)
    if limit and int(limit.group(1)) < 100:
        reasons.append(reason("cpu_speed_limited", percent=int(limit.group(1))))
    if reasons:
        return WARNING, reasons
    if "No thermal warning level has been recorded" in text or limit:
        return OK, []
    return UNKNOWN, [reason("thermal_unreported")]


def collect(report: Report, _system, run, _read=None) -> None:
    rc, out = run(["diskutil", "list", "-plist", "physical"])
    if rc == -1:
        report.source("diskutil", ABSENT)
    elif rc != 0:
        report.source("diskutil", SOURCE_FAILED, out)
    else:
        report.source("diskutil", RAN)
        for disk in parse_whole_disks(out):
            rc, info_text = run(["diskutil", "info", "-plist", disk])
            info = _plist(info_text) if rc == 0 else None
            if info is None:
                report.add(
                    DRIVE,
                    disk,
                    disk,
                    UNKNOWN,
                    [reason("diskutil_failed")],
                    {},
                    "diskutil",
                )
                continue
            comp = disk_component(info)
            report.add(
                DRIVE, comp["id"] or disk, comp["name"], comp["state"],
                comp["reasons"], comp["metrics"], "diskutil",
            )  # fmt: skip
    rc, out = run(["pmset", "-g", "therm"])
    if rc != 0:
        report.source("pmset", ABSENT if rc == -1 else SOURCE_FAILED, out)
        return
    report.source("pmset", RAN)
    state, reasons = parse_pmset_therm(out)
    report.add(SENSOR, "thermal", "Thermal state", state, reasons, {}, "pmset")
