# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Hardware health (Phase 23.1 S1): drives, arrays, pools, sensors and memory,
from the operating system's own sources first.

The S0 spike found smartmontools installed on NONE of seven lab machines, so
the native sources ARE the product and ``smartctl`` is only an extra where it
exists: the NVMe SMART log through the kernel (Linux ioctl, FreeBSD
``nvmecontrol``), ``/proc/mdstat``, ``zpool``, hwmon and EDAC sysfs, OpenBSD
``hw.sensors``, ``diskutil`` and the Windows storage cmdlets.

The report is our own schema, the same on every OS::

    {"schema_version": 1,
     "components": [{"kind": "drive" | "array" | "pool" | "sensor" | "memory",
                     "id": ..., "name": ..., "state": "ok" | "warning" |
                     "failed" | "unknown", "reasons": [{"code": ..., params}],
                     "metrics": {...}, "source": ...}],
     "sources": [{"name": ..., "status": "ran" | "absent" | "failed",
                  "detail": ...}]}

A reason is a CODE and its parameters (``{"code": "media_errors", "count":
19}``), never an English sentence: the server's UI words it in the reader's
language.

"Not measured" is never "healthy": a value the host could not read is
absent from ``metrics`` (never 0), a component nothing could judge is
``unknown``, and every source says whether it ran, is not there, or failed --
so an empty report from a host with no sources reads as "not measured", not
as "nothing wrong".  Parsers are pure functions of the tool's output, tested
against real recordings in ``tests/fixtures/hardware_health/`` (the failures
in them were constructed on lab machines: a file-backed ZFS mirror, an md
RAID1 on loop devices).
"""

from __future__ import annotations

import json
import logging
import platform
import re
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.collection.time_service import _run

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# component kinds
DRIVE = "drive"
ARRAY = "array"
POOL = "pool"
SENSOR = "sensor"
MEMORY = "memory"

# component states, worst last
OK = "ok"
UNKNOWN = "unknown"
WARNING = "warning"
FAILED = "failed"
_RANK = {OK: 0, UNKNOWN: 1, WARNING: 2, FAILED: 3}

# source statuses
RAN = "ran"
ABSENT = "absent"
SOURCE_FAILED = "failed"

# A drive at or past this share of its rated endurance is flagged.
WEAR_WARNING_PERCENT = 90

Runner = Callable[[list], Tuple[int, str]]
Reader = Callable[[str], Optional[str]]


def reason(code: str, **params) -> Dict[str, object]:
    """Why a component is not ok: a code the UI translates, and its values."""
    return {"code": code, **params}


def worst(states: Iterable[str]) -> str:
    """The worst of ``states`` (OK for none)."""
    return max(states, key=lambda s: _RANK.get(s, 0), default=OK)


class Report:
    """Components and the sources that produced them."""

    def __init__(self):
        self.components: List[Dict[str, object]] = []
        self.sources: List[Dict[str, object]] = []

    def source(self, name: str, status: str, detail: Optional[str] = None) -> None:
        entry: Dict[str, object] = {"name": name, "status": status}
        if detail:
            entry["detail"] = detail[:300]
        self.sources.append(entry)

    def add(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        kind: str,
        ident: str,
        name: Optional[str],
        state: str,
        reasons: Optional[List[str]] = None,
        metrics: Optional[Dict[str, object]] = None,
        source: Optional[str] = None,
    ) -> None:
        self.components.append(
            {
                "kind": kind,
                "id": ident,
                "name": name or ident,
                "state": state,
                "reasons": reasons or [],
                # never a None in metrics: absent means not measured
                "metrics": {k: v for k, v in (metrics or {}).items() if v is not None},
                "source": source,
            }
        )

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "state": (
                worst(c["state"] for c in self.components)
                if self.components
                else UNKNOWN
            ),
            "components": self.components,
            "sources": self.sources,
        }


# --- NVMe SMART / health log (log page 0x02), any OS -------------------------

# Critical Warning bits (NVMe base spec, SMART / Health log byte 0).
_NVME_CRITICAL = (
    (0x01, FAILED, "spare_below_threshold"),
    (0x02, WARNING, "temperature_threshold"),
    (0x04, FAILED, "reliability_degraded"),
    (0x08, FAILED, "read_only"),
    (0x10, WARNING, "volatile_backup_failed"),
    (0x20, FAILED, "pmr_read_only"),
)


def nvme_state(metrics: Dict[str, object]) -> Tuple[str, List[str]]:
    """Judge an NVMe drive from its SMART / health log metrics."""
    states, reasons = [OK], []
    critical = metrics.get("critical_warning")
    if isinstance(critical, int):
        for bit, state, code in _NVME_CRITICAL:
            if critical & bit:
                states.append(state)
                reasons.append(reason(code))
    used = metrics.get("percent_used")
    if isinstance(used, int) and used >= WEAR_WARNING_PERCENT:
        states.append(WARNING)
        reasons.append(reason("endurance_used", percent=used))
    media = metrics.get("media_errors")
    if isinstance(media, int) and media > 0:
        states.append(WARNING)
        reasons.append(reason("media_errors", count=media))
    if critical is None:
        return UNKNOWN, [reason("smart_not_read")]
    return worst(states), reasons


def parse_nvme_log_page(raw: bytes) -> Dict[str, object]:
    """The 512-byte SMART / health log (Linux reads it through the ioctl)."""
    if len(raw) < 192:
        return {}

    def u128(offset):
        return int.from_bytes(raw[offset : offset + 16], "little")

    kelvin = int.from_bytes(raw[1:3], "little")
    return {
        "critical_warning": raw[0],
        "temperature_c": round(kelvin - 273.15, 1) if kelvin else None,
        "available_spare": raw[3],
        "available_spare_threshold": raw[4],
        "percent_used": raw[5],
        "power_on_hours": u128(128),
        "unsafe_shutdowns": u128(144),
        "media_errors": u128(160),
        "error_log_entries": u128(176),
    }


_NVMECONTROL_FIELDS = {
    "Critical Warning State": ("critical_warning", 16),
    "Available spare": ("available_spare", 10),
    "Available spare threshold": ("available_spare_threshold", 10),
    "Percentage used": ("percent_used", 10),
    "Power on hours": ("power_on_hours", 10),
    "Unsafe shutdowns": ("unsafe_shutdowns", 10),
    "Media errors": ("media_errors", 10),
    "No. error info log entries": ("error_log_entries", 10),
}


def parse_nvmecontrol_logpage(text: str) -> Dict[str, object]:
    """FreeBSD ``nvmecontrol logpage -p 2 nvmeN``."""
    metrics: Dict[str, object] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith(" "):
            continue  # the indented lines break Critical Warning into bits
        key, _sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key in _NVMECONTROL_FIELDS:
            field, base = _NVMECONTROL_FIELDS[key]
            try:
                metrics[field] = int(value.split()[0], base)
            except (ValueError, IndexError):
                continue
        elif key == "Temperature" and "C" in value:
            match = re.search(r"(-?[\d.]+) C", value)
            if match:
                metrics["temperature_c"] = float(match.group(1))
    return metrics


# --- ZFS, Linux and the BSDs -------------------------------------------------

_POOL_STATES = {
    "ONLINE": OK,
    "DEGRADED": WARNING,
    "OFFLINE": WARNING,
    "FAULTED": FAILED,
    "UNAVAIL": FAILED,
    "REMOVED": FAILED,
    "SUSPENDED": FAILED,
}
_ZPOOL_DEVICE = re.compile(
    r"^\s+(\S+)\s+(ONLINE|DEGRADED|OFFLINE|FAULTED|UNAVAIL|REMOVED|AVAIL|INUSE)"
    r"(?:\s+(\d+\S*)\s+(\d+\S*)\s+(\d+\S*))?"
)


def parse_zpool_list(text: str) -> Dict[str, str]:
    """``zpool list -H -o name,health`` -> {pool: health}."""
    pools = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0].strip():
            pools[fields[0].strip()] = fields[1].strip()
    return pools


def _count(value: Optional[str]) -> int:
    """zpool error counts: ``0``, ``211``, or abbreviated (``1.2K``)."""
    if not value:
        return 0
    match = re.match(r"([\d.]+)([KMGT]?)", value)
    if not match:
        return 0
    scale = {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[match.group(2)]
    return int(float(match.group(1)) * scale)


def parse_zpool_status(text: str) -> Dict[str, object]:
    """One pool's ``zpool status``: its state, the devices not ONLINE, error
    counts summed over its devices, the scan line and the errors line."""
    result: Dict[str, object] = {"devices_not_online": [], "read": 0, "write": 0}
    result["cksum"] = 0
    in_config = False
    for line in text.splitlines():
        stripped = line.strip()
        key = stripped.split(":", 1)[0]
        if key in ("state", "scan", "errors") and ":" in stripped:
            result[key] = stripped.split(":", 1)[1].strip()
            in_config = in_config and key != "errors"
        elif stripped.startswith("NAME") and "STATE" in stripped:
            in_config = True
        elif in_config:
            _zpool_device(line, result)
    return result


def _zpool_device(line: str, result: Dict[str, object]) -> None:
    """One row of the config table: a device not ONLINE, and its errors."""
    match = _ZPOOL_DEVICE.match(line)
    if not match:
        return
    name, state = match.group(1), match.group(2)
    if state not in ("ONLINE", "AVAIL", "INUSE"):
        result["devices_not_online"].append(
            reason("device_not_online", device=name, state=state)
        )
    for key, value in zip(("read", "write", "cksum"), match.groups()[2:]):
        result[key] += _count(value)


def zpool_state(health: str, status: Dict[str, object]) -> Tuple[str, List[str]]:
    """A pool's state: its health, AND its error counts -- a mirror that
    repaired 211 checksum errors in a scrub still says ONLINE (recorded)."""
    state = _POOL_STATES.get(health, UNKNOWN)
    reasons = [reason("pool_health", health=health)] if state != OK else []
    reasons += list(status.get("devices_not_online") or [])
    errors = {k: status.get(k, 0) for k in ("read", "write", "cksum")}
    if any(errors.values()):
        state = worst([state, WARNING])
        reasons.append(reason("device_errors", **errors))
    data = str(status.get("errors") or "")
    if data and not data.startswith("No known data errors"):
        state = worst([state, FAILED])
        reasons.append(reason("data_errors", detail=data))
    return state, reasons


def collect_zfs(report: Report, run: Runner) -> None:
    rc, out = run(["zpool", "list", "-H", "-o", "name,health"])
    if rc == -1:
        report.source("zpool", ABSENT)
        return
    if rc != 0:
        report.source("zpool", SOURCE_FAILED, out)
        return
    report.source("zpool", RAN)
    for pool, health in parse_zpool_list(out).items():
        _rc, status_text = run(["zpool", "status", pool])
        status = parse_zpool_status(status_text)
        state, reasons = zpool_state(health, status)
        metrics = {k: status.get(k) for k in ("read", "write", "cksum", "scan")}
        metrics["health"] = health
        report.add(POOL, pool, pool, state, reasons, metrics, "zpool")


# --- smartctl, where it happens to be installed ------------------------------

_SMART_ATTRIBUTES = {
    5: "reallocated_sectors",
    187: "reported_uncorrectable",
    197: "pending_sectors",
    198: "offline_uncorrectable",
}


def _smart_metrics(data: Dict[str, object]) -> Dict[str, object]:
    """The values worth keeping from ``smartctl -j``: temperature, the ATA
    attributes we judge on, and the NVMe health log."""
    metrics: Dict[str, object] = {}
    temperature = (data.get("temperature") or {}).get("current")
    if temperature is not None:
        metrics["temperature_c"] = temperature
    for attr in (data.get("ata_smart_attributes") or {}).get("table") or []:
        field = _SMART_ATTRIBUTES.get(attr.get("id"))
        if field:
            metrics[field] = (attr.get("raw") or {}).get("value")
    nvme = data.get("nvme_smart_health_information_log")
    if isinstance(nvme, dict):
        metrics.update(
            critical_warning=nvme.get("critical_warning"),
            percent_used=nvme.get("percentage_used"),
            media_errors=nvme.get("media_errors"),
            power_on_hours=nvme.get("power_on_hours"),
        )
    return metrics


_SECTOR_FIELDS = ("reallocated_sectors", "pending_sectors", "offline_uncorrectable")


def parse_smartctl_json(data: Dict[str, object]) -> Tuple[str, List[str], Dict]:
    """``smartctl -j -H -A`` (SATA / SAS / NVMe) -> state, reasons, metrics."""
    metrics = _smart_metrics(data)
    passed = (data.get("smart_status") or {}).get("passed")
    nvme = data.get("nvme_smart_health_information_log")
    state, reasons = nvme_state(metrics) if isinstance(nvme, dict) else (OK, [])
    if passed is False:
        state = FAILED
        reasons.insert(0, reason("smart_failed"))
    elif passed is None and not nvme:
        state = UNKNOWN
    for field in _SECTOR_FIELDS:
        value = metrics.get(field)
        if isinstance(value, int) and value > 0:
            state = worst([state, WARNING])
            reasons.append(reason(field, count=value))
    return state, reasons, metrics


def smartctl_drive(report: "Report", run, device: str, ident: str, model) -> None:
    """One drive through ``smartctl -j -H -A``; without smartctl, the drive
    is UNKNOWN with the reason (and S6 recommends installing smartmontools)."""
    rc, out = run(["smartctl", "-j", "-H", "-A", device])
    if rc == -1:
        report.add(DRIVE, ident, model, UNKNOWN, [reason("smartctl_absent")], {}, None)
        return
    try:
        state, reasons, metrics = parse_smartctl_json(json.loads(out))
    except (ValueError, TypeError):
        state, reasons, metrics = UNKNOWN, [reason("smartctl_failed", rc=rc)], {}
    report.add(DRIVE, ident, model, state, reasons, metrics, "smartctl")


def smartctl_source(report: "Report", run) -> None:
    rc, _out = run(["smartctl", "--version"])
    report.source("smartctl", ABSENT if rc == -1 else RAN)


# --- temperature sensors with the OS's own thresholds ------------------------

# Below or above these, a temperature reading is a sentinel, not a reading
# (x13s ACPI zones report 0 K and exactly 0 C for absent sensors).
PLAUSIBLE_C = (1.0, 150.0)


def plausible(celsius: Optional[float]) -> bool:
    return celsius is not None and PLAUSIBLE_C[0] <= celsius <= PLAUSIBLE_C[1]


def temperature_state(
    celsius: float, high: Optional[float], critical: Optional[float]
) -> Tuple[str, List[str]]:
    """Judged ONLY against the thresholds the hardware itself declares; a
    sensor without any is reported, never guessed at."""
    if plausible(critical) and celsius >= critical:
        return FAILED, [reason("temperature_critical", value=celsius, limit=critical)]
    if plausible(high) and celsius >= high:
        return WARNING, [reason("temperature_high", value=celsius, limit=high)]
    return OK, []


# --- the entry point ---------------------------------------------------------


def collect_hardware_health(
    system: Optional[str] = None,
    run: Optional[Runner] = None,
    read: Optional[Reader] = None,
) -> Dict[str, object]:
    """This host's hardware health report.  Never raises."""
    # pylint: disable=import-outside-toplevel  # each OS's module, on its OS
    system = system or platform.system()
    if run is None:
        run = _run
        if system == "Linux":  # an unprivileged agent reads through sudo -n
            from src.sysmanage_agent.collection.hardware_health_privilege import (
                privileged_runner,
            )

            run = privileged_runner(_run)
    report = Report()
    try:
        if system == "Linux":
            from src.sysmanage_agent.collection import hardware_health_linux as osmod
        elif system in ("FreeBSD", "OpenBSD", "NetBSD"):
            from src.sysmanage_agent.collection import hardware_health_bsd as osmod
        elif system == "Windows":
            from src.sysmanage_agent.collection import hardware_health_windows as osmod
        elif system == "Darwin":
            from src.sysmanage_agent.collection import hardware_health_macos as osmod
        else:
            report.source("platform", ABSENT, f"no collectors for {system}")
            return report.as_dict()
        osmod.collect(report, system, run, read)
        if system in ("Linux", "FreeBSD", "Windows"):  # vendor RAID CLIs, the BMC
            from src.sysmanage_agent.collection import hardware_health_vendor

            hardware_health_vendor.collect(report, system, run)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning(_("Hardware health collection failed: %s"), exc)
        report.source("collector", SOURCE_FAILED, str(exc))
    return report.as_dict()
