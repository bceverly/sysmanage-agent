# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Vendor hardware RAID and BMC health (Phase 23.1), where the tools exist:

* Broadcom / LSI MegaRAID ... ``storcli64 /call show all J`` (and Dell's
                              ``perccli``, the same JSON): virtual drives,
                              physical drives, controller, BBU / CacheVault
* HPE Smart Array ........... ``ssacli ctrl all show config detail``
* Microchip / Adaptec ....... ``arcconf getconfig N al``
* the BMC ................... ``ipmitool sdr elist`` (sensors the BMC itself
                              judges) and ``ipmitool sel elist`` (hardware
                              events of the last 24 hours)

Most hosts have none of these, so a vendor tool that is not installed is
NOT a source at all -- five "absent" lines on every laptop would be noise.
A tool that is there but fails is a failed source, with its output.
``ipmitool`` runs only where a BMC device node exists (or, on Windows, where
the tool itself is installed), and needs root.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from src.sysmanage_agent.collection.hardware_health import (
    ARRAY,
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
    worst,
)

logger = logging.getLogger(__name__)

Runner = Callable[[list], Tuple[int, str]]

# tool locations: PATH first, then where the vendors' packages put them
STORCLI = (
    "storcli64",
    "storcli",
    "/opt/MegaRAID/storcli/storcli64",
    "/opt/MegaRAID/storcli/storcli",
)
PERCCLI = (
    "perccli64",
    "perccli",
    "/opt/MegaRAID/perccli/perccli64",
    "/opt/MegaRAID/perccli/perccli",
)
SSACLI = ("ssacli", "/opt/smartstorageadmin/ssacli/bin/ssacli")
ARCCONF = ("arcconf", "/usr/Arcconf/arcconf")
IPMI_DEVICES = {
    "Linux": ("/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"),
    "FreeBSD": ("/dev/ipmi0", "/dev/ipmi"),
}
MAX_ARCCONF_CONTROLLERS = 8
MAX_BMC_SENSORS = 60
SEL_WINDOW = timedelta(hours=24)


_RESPONSE_DATA = "Response Data"
_CONTROLLER_STATUS = "Controller Status"
_NO_CONTROLLER = "no controller"


def _root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _first_present(run: Runner, candidates: Iterable[str], args: List[str]):
    """``(tool, rc, out)`` of the first candidate that is installed, else
    None -- a missing vendor tool is not reported at all."""
    for tool in candidates:
        rc, out = run([tool, *args])
        if rc != -1:
            return tool, rc, out
    return None


def _judge(value: Optional[str], table: Dict[str, str], default: str) -> str:
    return table.get(str(value or "").strip().lower(), default)


def _percent(text: str) -> Optional[float]:
    match = re.search(r"(\d+(?:\.\d+)?)\s*%", text or "")
    return float(match.group(1)) if match else None


# --- Broadcom / LSI MegaRAID (storcli, perccli) -------------------------------

_VD_STATES = {"optl": OK, "dgrd": WARNING, "pdgd": WARNING, "rec": WARNING}
_VD_STATES["ofln"] = FAILED
_PD_STATES = {
    "onln": OK,
    "ugood": OK,
    "ghs": OK,
    "dhs": OK,
    "jbod": OK,
    "rbld": WARNING,
    "offln": WARNING,
    "cpybck": WARNING,
    "ugunsp": WARNING,
    "ubunsp": WARNING,
    "failed": FAILED,
    "ubad": FAILED,
    "msng": FAILED,
}
_BATTERY_STATES = {"optimal": OK, "learning": OK, "charging": WARNING}
_BATTERY_STATES.update(failed=FAILED, missing=FAILED)
_CONTROLLER_STATES = {"optimal": OK, "ok": OK, "failed": FAILED}


def _megaraid_drive_id(ctrl: int, eid_slot: str) -> str:
    """``252:0`` -> ``c0/e252/s0``; a direct-attached ``:0`` -> ``c0/s0``."""
    eid, _sep, slot = str(eid_slot).partition(":")
    eid = eid.strip()
    if eid and eid != "-":
        return f"c{ctrl}/e{eid}/s{slot.strip()}"
    return f"c{ctrl}/s{slot.strip()}"


def parse_storcli_details(data: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    """``/call/eall/sall show all J`` -> {drive id: error counters}."""
    details: Dict[str, Dict[str, object]] = {}
    for ctrl in data.get("Controllers") or []:
        for key, value in ((ctrl or {}).get(_RESPONSE_DATA) or {}).items():
            match = re.fullmatch(r"Drive /(\S+) - Detailed Information", key)
            if not match or not isinstance(value, dict):
                continue
            state = value.get(f"Drive /{match.group(1)} State") or {}
            details[match.group(1)] = {
                "media_errors": state.get("Media Error Count"),
                "other_errors": state.get("Other Error Count"),
                "predictive_failures": state.get("Predictive Failure Count"),
                "smart_alert": state.get("S.M.A.R.T alert flagged by drive"),
            }
    return details


def parse_storcli_rebuild(data: Dict[str, object]) -> Dict[str, float]:
    """``/call/eall/sall show rebuild J`` -> {drive id: percent}."""
    progress: Dict[str, float] = {}
    for ctrl in data.get("Controllers") or []:
        rows = (ctrl or {}).get(_RESPONSE_DATA)
        for row in rows if isinstance(rows, list) else []:
            percent = row.get("Progress%")
            if isinstance(percent, (int, float)):
                progress[str(row.get("Drive-ID", "")).lstrip("/")] = float(percent)
    return progress


def _storcli_pd(ctrl: int, row: Dict, details: Dict, rebuild: Dict) -> Dict:
    ident = _megaraid_drive_id(ctrl, row.get("EID:Slt", ""))
    status = str(row.get("State") or "").strip()
    state = _judge(status, _PD_STATES, WARNING)
    reasons = [] if state == OK else [reason("health_status", status=status)]
    extra = details.get(ident) or {}
    media = extra.get("media_errors")
    if isinstance(media, int) and media > 0:
        state = worst([state, WARNING])
        reasons.append(reason("media_errors", count=media))
    predictive = extra.get("predictive_failures")
    if (isinstance(predictive, int) and predictive > 0) or str(
        extra.get("smart_alert") or ""
    ).lower() == "yes":
        state = worst([state, WARNING])
        reasons.append(reason("smart_failed"))
    if status.lower() == "rbld" and ident in rebuild:
        reasons.append(reason("rebuilding", percent=rebuild[ident]))
    metrics = {"state": status, "group": row.get("DG"), **extra}
    metrics["model"] = str(row.get("Model") or "").strip() or None
    return {"id": ident, "state": state, "reasons": reasons, "metrics": metrics}


def _storcli_vd(ctrl: int, row: Dict, drives: List[Dict]) -> Dict:
    group, _sep, number = str(row.get("DG/VD", "")).partition("/")
    status = str(row.get("State") or "").strip()
    state = _judge(status, _VD_STATES, UNKNOWN)
    reasons = [] if state == OK else [reason("array_state", state=status)]
    members = [d for d in drives if str(d["metrics"].get("group")) == group]
    bad = [
        d["id"]
        for d in members
        if _judge(d["metrics"]["state"], _PD_STATES, WARNING) != OK
    ]
    if bad:
        reasons.append(reason("failed_members", members=bad))
    for member in members:
        reasons += [r for r in member["reasons"] if r["code"] == "rebuilding"]
    metrics = {"state": status, "level": row.get("TYPE"), "members": len(members)}
    name = str(row.get("Name") or "").strip() or f"c{ctrl}/v{number}"
    return {"id": f"c{ctrl}/v{number}", "name": name, "state": state,
            "reasons": reasons, "metrics": metrics}  # fmt: skip


def _storcli_controller(data: Dict) -> Tuple[str, List, Dict]:
    status = str((data.get("Status") or {}).get(_CONTROLLER_STATUS) or "").strip()
    states = [_judge(status, _CONTROLLER_STATES, WARNING) if status else UNKNOWN]
    reasons = [] if states[0] == OK else [reason("controller_status", status=status)]
    metrics: Dict[str, object] = {"controller_status": status or None}
    for key in ("BBU_Info", "Cachevault_Info"):
        for unit in data.get(key) or []:
            battery = str(unit.get("State") or "").strip()
            judged = _judge(battery, _BATTERY_STATES, WARNING)
            states.append(judged)
            metrics["cache_battery"] = battery
            if judged != OK:
                reasons.append(reason("cache_battery", status=battery))
    return worst(states), reasons, metrics


def parse_storcli(
    data: Dict[str, object],
    details: Optional[Dict] = None,
    rebuild: Optional[Dict] = None,
) -> Tuple[List[Dict[str, object]], List[str]]:
    """``/call show all J`` -> (components, controller errors)."""
    components: List[Dict[str, object]] = []
    errors: List[str] = []
    for ctrl in data.get("Controllers") or []:
        status = (ctrl or {}).get("Command Status") or {}
        if str(status.get("Status", "")).lower() != "success":
            errors.append(str(status.get("Description") or status))
            continue
        number = status.get("Controller", len(components))
        body = ctrl.get(_RESPONSE_DATA) or {}
        components += _storcli_controller_components(number, body, details, rebuild)
    return components, errors


def _storcli_controller_components(number, body, details, rebuild) -> List[Dict]:
    drives = [
        _storcli_pd(number, row, details or {}, rebuild or {})
        for row in body.get("PD LIST") or []
    ]
    arrays = [_storcli_vd(number, row, drives) for row in body.get("VD LIST") or []]
    state, reasons, metrics = _storcli_controller(body)
    model = str((body.get("Basics") or {}).get("Model") or "").strip()
    controller = {"id": f"c{number}", "name": model or f"controller {number}",
                  "state": state, "reasons": reasons, "metrics": metrics,
                  "kind": SENSOR}  # fmt: skip
    for drive in drives:
        drive["kind"] = DRIVE
    for array in arrays:
        array["kind"] = ARRAY
    return [controller, *arrays, *drives]


def _json(text: str) -> Optional[Dict[str, object]]:
    try:
        data = json.loads(text[text.index("{") :])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _no_controller(errors: List[str]) -> bool:
    return bool(errors) and all(_NO_CONTROLLER in e.lower() for e in errors)


def _storcli_extras(run: Runner, tool: str, components: List[Dict]):
    """Per-drive error counters, and rebuild progress when a drive rebuilds."""
    _rc, out = run([tool, "/call/eall/sall", "show", "all", "J"])
    details = parse_storcli_details(_json(out) or {})
    rebuild: Dict[str, float] = {}
    if any(c["metrics"].get("state") == "Rbld" for c in components):
        _rc, out = run([tool, "/call/eall/sall", "show", "rebuild", "J"])
        rebuild = parse_storcli_rebuild(_json(out) or {})
    return details, rebuild


def collect_megaraid(report: Report, run: Runner) -> None:
    for family, candidates in (("storcli", STORCLI), ("perccli", PERCCLI)):
        found = _first_present(run, candidates, ["/call", "show", "all", "J"])
        if found:
            _megaraid(report, run, family, *found)
            return  # both families see the same controllers


def _megaraid(report: Report, run: Runner, family: str, tool, rc, out) -> None:
    data = _json(out)
    if data is None:
        report.source(family, SOURCE_FAILED, f"rc={rc}: {out}")
        return
    components, errors = parse_storcli(data)
    if _no_controller(errors):
        report.source(family, RAN, _NO_CONTROLLER)
        return
    if errors:
        report.source(family, SOURCE_FAILED, "; ".join(errors))
    if not components:
        return
    details, rebuild = _storcli_extras(run, tool, components)
    components, _errors = parse_storcli(data, details, rebuild)
    if not errors:
        report.source(family, RAN)
    _add_all(report, components, family)


def _add_all(report: Report, components: List[Dict], source: str) -> None:
    for comp in components:
        report.add(
            comp["kind"], comp["id"], comp.get("name"), comp["state"],
            comp["reasons"], comp["metrics"], source,
        )  # fmt: skip


# --- HPE Smart Array (ssacli) -------------------------------------------------

_SSA_PD_STATES = {"ok": OK, "predictive failure": WARNING, "failed": FAILED}
_SSA_PD_STATES["rebuilding"] = WARNING


def _ssa_new(state: Dict, kind: str, ident: str, name: str) -> Dict[str, object]:
    group = state.get("array")
    return {"kind": kind, "id": ident, "name": name, "fields": {}, "group": group}


def _ssa_line(state: Dict, line: str) -> None:
    """One line of ``ssacli ... show config detail`` into the parse state."""
    stripped = line.strip()
    controller = re.match(r"^\S.* in Slot (\S+)", line)
    if controller:
        state["array"] = None
        current = _ssa_new(state, SENSOR, f"slot{controller.group(1)}", stripped)
        state["controller"] = current
        state["items"].append(current)
        state["current"] = current
        return
    slot = (state.get("controller") or {}).get("id", "slot?")
    logical = re.match(r"Logical Drive: (\S+)", stripped)
    physical = re.fullmatch(r"physicaldrive (\S+)", stripped)  # not summaries
    if logical:
        state["current"] = _ssa_new(state, ARRAY, f"{slot}/ld{logical.group(1)}", "")
        state["current"]["name"] = f"Logical Drive {logical.group(1)}"
    elif physical:
        state["current"] = _ssa_new(state, DRIVE, f"{slot}/{physical.group(1)}", "")
    elif ":" not in stripped or stripped.startswith("Array:"):
        # Array / Unassigned / SEP / Expander headers end the item before them
        state["current"] = None
        array = stripped.startswith("Array:")
        state["array"] = f"{slot}/{stripped[6:].strip()}" if array else None
        return
    else:
        key, _sep, value = stripped.partition(":")
        if state["current"] is not None:
            state["current"]["fields"].setdefault(key.strip(), value.strip())
        return
    state["items"].append(state["current"])


def parse_ssacli(text: str) -> List[Dict[str, object]]:
    """Controllers, logical drives and physical drives with their fields."""
    state: Dict[str, object] = {"items": [], "current": None, "controller": None}
    for line in text.splitlines():
        if line.strip():
            _ssa_line(state, line)
    return state["items"]


def _ssa_controller(fields: Dict[str, str]) -> Tuple[str, List, Dict]:
    status = fields.get(_CONTROLLER_STATUS)
    battery = fields.get("Battery/Capacitor Status")
    states, reasons = [OK], []
    if status and status.upper() != "OK":
        states.append(FAILED if status.lower().startswith("failed") else WARNING)
        reasons.append(reason("controller_status", status=status))
    if battery and battery.upper() != "OK":
        states.append(FAILED if battery.lower().startswith("failed") else WARNING)
        reasons.append(reason("cache_battery", status=battery))
    metrics = {"controller_status": status, "cache_battery": battery}
    metrics["cache_status"] = fields.get("Cache Status")
    return (worst(states) if status else UNKNOWN), reasons, metrics


def _ssa_logical(fields: Dict[str, str]) -> Tuple[str, List, Dict]:
    status = fields.get("Status", "")
    lowered = status.lower()
    if lowered == "ok":
        state, reasons = OK, []
    elif lowered == "failed":
        state, reasons = FAILED, [reason("array_state", state=status)]
    else:  # Interim Recovery Mode, Ready for Rebuild, Recovering, ...
        state, reasons = WARNING, [reason("array_state", state=status)]
    if lowered.startswith("recovering"):
        reasons.append(reason("rebuilding", percent=_percent(status)))
    metrics = {"state": status or None, "level": fields.get("Fault Tolerance")}
    metrics["disk"] = fields.get("Disk Name")
    return (state if status else UNKNOWN), reasons, metrics


def _ssa_physical(fields: Dict[str, str]) -> Tuple[str, List, Dict]:
    status = fields.get("Status", "")
    state = _judge(status, _SSA_PD_STATES, WARNING) if status else UNKNOWN
    reasons = [] if state in (OK, UNKNOWN) else [reason("health_status", status=status)]
    temperature = fields.get("Current Temperature (C)", "")
    metrics = {
        "state": status or None,
        "model": " ".join(fields.get("Model", "").split()) or None,
        "temperature_c": int(temperature) if temperature.isdigit() else None,
        "drive_type": fields.get("Drive Type"),
    }
    return state, reasons, metrics


_SSA_JUDGES = {SENSOR: _ssa_controller, ARRAY: _ssa_logical, DRIVE: _ssa_physical}


def ssacli_components(text: str) -> List[Dict[str, object]]:
    components = []
    for item in parse_ssacli(text):
        state, reasons, metrics = _SSA_JUDGES[item["kind"]](item["fields"])
        components.append({**item, "state": state, "reasons": reasons,
                           "metrics": metrics})  # fmt: skip
    _ssa_link_members(components)
    return components


def _ssa_link_members(components: List[Dict]) -> None:
    """A logical drive not ok names the physical drives not ok in its Array
    (ssacli lists both under the same ``Array:`` header)."""
    for array in (c for c in components if c["kind"] == ARRAY and c["state"] != OK):
        bad = [
            c["id"]
            for c in components
            if c["kind"] == DRIVE
            and c["group"] is not None
            and c["group"] == array["group"]
            and c["state"] != OK
        ]
        if bad:
            array["reasons"].append(reason("failed_members", members=bad))


def collect_ssacli(report: Report, run: Runner) -> None:
    found = _first_present(run, SSACLI, ["ctrl", "all", "show", "config", "detail"])
    if not found:
        return
    _tool, rc, out = found
    if rc != 0:
        report.source("ssacli", SOURCE_FAILED, f"rc={rc}: {out}")
        return
    report.source("ssacli", RAN)
    _add_all(report, ssacli_components(out), "ssacli")


# --- Microchip / Adaptec (arcconf) --------------------------------------------

_ARC_LD_STATES = {"optimal": OK, "degraded": WARNING, "failed": FAILED}
_ARC_LD_STATES.update(rebuilding=WARNING, offline=FAILED)
_ARC_PD_STATES = {
    "online": OK,
    "ready": OK,
    "hot spare": OK,
    "global hot-spare": OK,
    "dedicated hot-spare": OK,
    "raw (pass through)": OK,
    "optimal": OK,
    "rebuilding": WARNING,
    "failed": FAILED,
}
_ARC_KEY = re.compile(r"^\s*(.+?)\s+:\s?(.*)$")


def _arc_section(state: Dict, stripped: str) -> bool:
    """Section headers of ``getconfig al``; True when the line was one."""
    lowered = stripped.lower()
    ctrl = state["ctrl"]
    if lowered == "controller information":
        state["current"] = state["controller"]
    elif lowered.startswith("controller") and re.search(
        r"battery|zmm|flash backup|backup unit", lowered
    ):
        state["current"] = state["battery"]
    elif re.fullmatch(r"logical device number (\d+)", lowered):
        number = lowered.split()[-1]
        state["current"] = {"kind": ARRAY, "id": f"c{ctrl}/ld{number}", "fields": {}}
        state["items"].append(state["current"])
    elif re.fullmatch(r"channel #(\d+):", lowered):
        state["channel"] = re.findall(r"\d+", lowered)[0]
    elif re.fullmatch(r"device #(\d+)", lowered):
        ident = f"c{ctrl}/ch{state['channel']}/d{lowered.split('#')[1]}"
        state["current"] = {"kind": DRIVE, "id": ident, "fields": {}}
        state["items"].append(state["current"])
    elif lowered.endswith("information"):
        # a logical device's segments are its own; other headers end a block
        state["current"] = state["current"] if "segment" in lowered else None
    else:
        return False
    return True


def parse_arcconf(text: str, ctrl: int = 1) -> Dict[str, object]:
    """``arcconf getconfig N al`` -> controller fields, battery fields, and
    logical / physical devices with their fields."""
    state: Dict[str, object] = {
        "ctrl": ctrl,
        "controller": {},
        "battery": {},
        "items": [],
        "current": None,
        "channel": "0",
    }
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) == {"-"} or _arc_section(state, stripped):
            continue
        match = _ARC_KEY.match(line)
        current = state["current"]
        if current is None:
            continue
        fields = current["fields"] if "fields" in current else current
        if match:
            fields.setdefault(match.group(1).strip(), match.group(2).strip())
        elif stripped.startswith("Device is "):
            fields["Device is"] = stripped[len("Device is ") :]
    found = re.search(r"Controllers found:\s*(\d+)", text)
    state["found"] = int(found.group(1)) if found else None
    return state


def _arc_logical(item: Dict, ctrl: int) -> Dict:
    fields = item["fields"]
    status = fields.get("Status of Logical Device", "")
    head = re.split(r"[,(]", status)[0].strip()
    state = _judge(head, _ARC_LD_STATES, WARNING) if status else UNKNOWN
    reasons = [] if state in (OK, UNKNOWN) else [reason("array_state", state=status)]
    if "rebuild" in status.lower():
        reasons.append(reason("rebuilding", percent=_percent(status)))
    missing = [
        k
        for k, v in fields.items()
        if re.match(r"(Group \d+, )?Segment \d+$", k) and "missing" in v.lower()
    ]
    if missing:
        reasons.append(reason("failed_members", members=missing))
    name = fields.get("Logical Device name") or item["id"]
    metrics = {"state": status or None, "level": fields.get("RAID level")}
    return {**item, "name": f"{name} (controller {ctrl})", "state": state,
            "reasons": reasons, "metrics": metrics}  # fmt: skip


def _arc_physical(item: Dict, ctrl: int) -> Optional[Dict]:
    fields = item["fields"]
    status = fields.get("State")
    if not status or "enclosure" in fields.get("Device is", "").lower():
        return None  # enclosure services devices carry no drive state
    location = re.search(
        r"Enclosure (\d+), Slot (\d+)", fields.get("Reported Location", "")
    )
    if location:
        item = {**item, "id": f"c{ctrl}/e{location.group(1)}/s{location.group(2)}"}
    state = _judge(status, _ARC_PD_STATES, WARNING)
    reasons = [] if state == OK else [reason("health_status", status=status)]
    smart = fields.get("S.M.A.R.T.", "").lower()
    warnings = fields.get("S.M.A.R.T. warnings", "")
    if smart == "yes" or (warnings.isdigit() and int(warnings) > 0):
        state = worst([state, WARNING])
        reasons.append(reason("smart_failed"))
    name = " ".join(f"{fields.get('Vendor', '')} {fields.get('Model', '')}".split())
    metrics = {"state": status, "model": name or None}
    metrics["smart_warnings"] = int(warnings) if warnings.isdigit() else None
    return {**item, "name": name or item["id"], "state": state, "reasons": reasons,
            "metrics": metrics}  # fmt: skip


def _arc_controller(parsed: Dict, ctrl: int) -> Dict:
    fields, battery = parsed["controller"], parsed["battery"].get("Status")
    status = fields.get(_CONTROLLER_STATUS)
    state = _judge(status, {"optimal": OK, "failed": FAILED}, WARNING)
    reasons = [] if state == OK else [reason("controller_status", status=status)]
    if battery:
        judged = _judge(
            re.sub(r"^zmm\s+", "", battery.lower()), _BATTERY_STATES, WARNING
        )
        if judged != OK:
            reasons.append(reason("cache_battery", status=battery))
        state = worst([state, judged])
    metrics = {"controller_status": status, "cache_battery": battery}
    name = fields.get("Controller Model") or f"controller {ctrl}"
    return {"kind": SENSOR, "id": f"c{ctrl}", "name": name,
            "state": state if status else UNKNOWN, "reasons": reasons,
            "metrics": metrics}  # fmt: skip


def arcconf_components(parsed: Dict[str, object], ctrl: int) -> List[Dict[str, object]]:
    components = [_arc_controller(parsed, ctrl)]
    for item in parsed["items"]:
        if item["kind"] == ARRAY:
            components.append(_arc_logical(item, ctrl))
        else:
            physical = _arc_physical(item, ctrl)
            if physical:
                components.append(physical)
    return components


def collect_arcconf(report: Report, run: Runner) -> None:
    found = _first_present(run, ARCCONF, ["getconfig", "1", "al"])
    if not found:
        return
    tool, rc, out = found
    parsed = parse_arcconf(out, 1)
    if parsed["found"] == 0:
        report.source("arcconf", RAN, _NO_CONTROLLER)
        return
    if rc != 0:
        report.source("arcconf", SOURCE_FAILED, f"rc={rc}: {out}")
        return
    components = arcconf_components(parsed, 1)
    for ctrl in range(2, min(parsed["found"] or 1, MAX_ARCCONF_CONTROLLERS) + 1):
        rc, out = run([tool, "getconfig", str(ctrl), "al"])
        if rc == 0:
            components += arcconf_components(parse_arcconf(out, ctrl), ctrl)
    report.source("arcconf", RAN)
    _add_all(report, components, "arcconf")


# --- the BMC (ipmitool) -------------------------------------------------------

# Event / discrete-state text that means trouble; anything else (presence,
# power on, log cleared, OEM records) is informational.
_EVENT_FAILED = re.compile(
    r"uncorrectable|failure detected|drive fault|non-recoverable|"
    r"(?:lower|upper) critical going|\bierr\b|thermal trip|in failed array|"
    r"machine check",
    re.IGNORECASE,
)
_EVENT_WARNING = re.compile(
    r"correctable ecc|predictive failure|non-critical going|ac lost|"
    r"input lost|in critical array|rebuild|configuration error|"
    r"limit reached|fault",
    re.IGNORECASE,
)
_SDR_STATUS = {"ok": OK, "nc": WARNING, "lnc": WARNING, "unc": WARNING}
_SDR_STATUS.update(dict.fromkeys(("cr", "lcr", "ucr", "nr", "lnr", "unr"), FAILED))
_SDR_UNITS = (
    ("degrees c", "temperature_c"),
    ("rpm", "rpm"),
    ("volts", "volts"),
    ("watts", "watts"),
    ("amps", "amps"),
)
_POWER_SUPPLY = re.compile(r"\bps\s?\d|\bpsu|power supply|pwr ?supply", re.IGNORECASE)


def event_severity(text: str) -> str:
    """OK (informational), WARNING or FAILED for a SEL / discrete text."""
    if _EVENT_FAILED.search(text or ""):
        return FAILED
    if _EVENT_WARNING.search(text or ""):
        return WARNING
    return OK


def parse_sdr_elist(text: str) -> List[Dict[str, object]]:
    """``ipmitool sdr elist``: name | id | status | entity | reading."""
    sensors = []
    for line in text.splitlines():
        fields = [f.strip() for f in line.split("|")]
        if len(fields) < 5 or not fields[0]:
            continue
        name, sid, status, entity, reading = fields[:5]
        metric, value = None, None
        number = re.match(r"^(-?\d+(?:\.\d+)?)\s+(.+)$", reading)
        if number:
            unit = number.group(2).strip().lower()
            metric = next((m for u, m in _SDR_UNITS if unit == u), None)
            value = float(number.group(1))
        sensors.append({"name": name, "id": sid, "status": status.lower(),
                        "entity": entity, "reading": reading,
                        "metric": metric, "value": value})  # fmt: skip
    return sensors


def _watched(sensor: Dict) -> bool:
    """An ok sensor is worth reporting: temperature, fan, voltage, power."""
    if sensor["metric"] in ("temperature_c", "rpm", "volts"):
        return True
    return sensor["entity"].startswith("10.") or bool(
        _POWER_SUPPLY.search(sensor["name"])
    )


def _sdr_component(sensor: Dict) -> Optional[Dict[str, object]]:
    status = sensor["status"]
    if status == "ns" or status not in _SDR_STATUS:
        return None  # no reading: not measured, not reported
    state = _SDR_STATUS[status]
    if state == OK and sensor["metric"] is None:
        state = event_severity(sensor["reading"])  # discrete: "Failure detected"
    if state == OK and not _watched(sensor):
        return None
    reasons = []
    if state != OK:
        reasons.append(reason("sensor_status", sensor=sensor["name"],
                              value=sensor["reading"], status=status))  # fmt: skip
    metrics = {"status": status, "reading": sensor["reading"] or None}
    if sensor["metric"]:
        metrics[sensor["metric"]] = sensor["value"]
    return {"kind": SENSOR, "id": f"bmc/{sensor['name']}", "name": sensor["name"],
            "state": state, "reasons": reasons, "metrics": metrics}  # fmt: skip


def sdr_components(text: str) -> List[Dict[str, object]]:
    """Sensors not ok first, then the watched ok ones, at most 60; a name the
    BMC repeats gets its sensor id appended."""
    components, seen = [], set()
    for sensor in parse_sdr_elist(text):
        comp = _sdr_component(sensor)
        if comp is None:
            continue
        if comp["id"] in seen:
            comp["id"] = f"{comp['id']}/{sensor['id']}"
        seen.add(comp["id"])
        components.append(comp)
    components.sort(key=lambda c: c["state"] == OK)
    return components[:MAX_BMC_SENSORS]


def _sel_time(date: str, clock: str) -> Optional[datetime]:
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M:%S"):
        try:
            return datetime.strptime(f"{date} {clock}", fmt)
        except ValueError:
            continue
    return None  # "Pre-Init" and other untimed entries


def parse_sel_elist(text: str) -> List[Dict[str, object]]:
    """``ipmitool sel elist``: id | date | time | sensor | event | direction."""
    events = []
    for line in text.splitlines():
        fields = [f.strip() for f in line.split("|")]
        if len(fields) < 5:
            continue
        direction = fields[5] if len(fields) > 5 else ""
        events.append({"when": _sel_time(fields[1], fields[2]), "sensor": fields[3],
                       "event": fields[4], "direction": direction})  # fmt: skip
    return events


def parse_sel_time(text: str) -> Optional[datetime]:
    """``ipmitool sel time get`` -> the BMC's own clock."""
    match = re.search(r"(\d+/\d+/\d+)\s+(\d+:\d+:\d+)", text or "")
    return _sel_time(match.group(1), match.group(2)) if match else None


def sel_component(text: str, now: datetime) -> Dict[str, object]:
    """One component for the event log: the problem events (asserted, not
    informational) of the 24 hours before ``now`` on the BMC's clock."""
    events = parse_sel_elist(text)
    problems = []
    for event in events:
        when = event["when"]
        if when is None or not now - SEL_WINDOW <= when <= now + timedelta(hours=1):
            continue
        if event["direction"].lower() == "deasserted":
            continue
        severity = event_severity(event["event"])
        if severity != OK:
            problems.append((when, severity, event))
    state, reasons = OK, []
    if problems:
        newest = max(problems, key=lambda p: p[0])[2]
        state = worst(p[1] for p in problems)
        last = f"{newest['event']} ({newest['sensor']})"
        reasons.append(reason("sel_events", count=len(problems), last=last))
    metrics = {"sel_entries": len(events), "problem_events_24h": len(problems)}
    return {"kind": SENSOR, "id": "bmc/sel", "name": "BMC event log", "state": state,
            "reasons": reasons, "metrics": metrics}  # fmt: skip


def _has_bmc(system: str, run: Runner, exists) -> bool:
    """A BMC device node (Linux / FreeBSD) or, on Windows, the tool."""
    if system == "Windows":
        return run(["ipmitool", "-V"])[0] != -1
    return any(exists(path) for path in IPMI_DEVICES.get(system, ()))


def collect_ipmi(
    report: Report, system: str, run: Runner, exists, is_root, now=None
) -> None:
    if not _has_bmc(system, run, exists):
        return
    privileged = system == "Windows" or is_root()  # Windows: the driver decides
    rc, out = run(["ipmitool", "sdr", "elist"]) if privileged else (None, "")
    if rc is None:
        if run(["ipmitool", "-V"])[0] != -1:
            report.source("ipmitool", SOURCE_FAILED, "not_privileged")
        return
    if rc == -1:
        return
    if rc != 0:
        report.source("ipmitool", SOURCE_FAILED, f"rc={rc}: {out}")
        return
    components = sdr_components(out)
    rc, sel = run(["ipmitool", "sel", "elist"])
    if rc == 0:
        bmc_now = parse_sel_time(run(["ipmitool", "sel", "time", "get"])[1])
        components.append(sel_component(sel, bmc_now or now or datetime.now()))
        report.source("ipmitool", RAN)
    else:
        report.source("ipmitool", SOURCE_FAILED, f"sel rc={rc}: {sel}")
    _add_all(report, components, "ipmitool")


# --- the entry point ------------------------------------------------------------


def collect(
    report: Report, system: str, run: Runner, exists=None, is_root=None, now=None
) -> None:
    """Every vendor tool that is installed; one failing never stops the rest."""
    exists = exists or os.path.exists
    is_root = is_root or _root
    collectors = (
        ("storcli", lambda: collect_megaraid(report, run)),
        ("ssacli", lambda: collect_ssacli(report, run)),
        ("arcconf", lambda: collect_arcconf(report, run)),
        ("ipmitool", lambda: collect_ipmi(report, system, run, exists, is_root, now)),
    )
    for name, collector in collectors:
        try:
            collector()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("vendor hardware health: %s failed: %s", name, exc)
            report.source(name, SOURCE_FAILED, str(exc))
