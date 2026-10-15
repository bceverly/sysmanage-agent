# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
BSD RAID volumes and NetBSD sensors (Phase 23.1), from the base system:

OpenBSD and NetBSD
  * ``bioctl`` ...... softraid and hardware RAID volumes (mfi, mfii, ami,
                      arc/arcmsr, ciss, mpii): each volume's status, its
                      rebuild progress, and every member chunk / disk.
                      Needs root (``/dev/bio``); unprivileged it fails and
                      the hw.sensors / envstat verdict stays.  The
                      controllers come from the kernel sensors: a bio driver
                      registers one drive sensor per volume, so a host with
                      no volume has no controller to ask.

NetBSD
  * ``envstat -x`` .. every sysmon_envsys sensor as a proplib XML plist.
                      Temperatures are judged ONLY against the limits the
                      sensor declares (``warning-max`` / ``critical-max``);
                      when it declares none, the kernel's own state
                      (``warning-over`` ...) is kept.  Drives keep their
                      ``drive-state``; any other sensor (fan, voltage,
                      battery) is a component only when the kernel flags it.
  * ``raidctl -s`` .. each RAIDframe set listed in ``hw.disknames``.

Deduplication: on both systems the kernel sensor for a RAID controller
(OpenBSD ``hw.sensors.softraid0.drive0``, NetBSD ``mfi0`` drive sensors) is a
one-word summary of the same volumes ``bioctl`` details.  When ``bioctl``
reported at least one volume on a controller, the bioctl components
(``<controller>/<volume>``) REPLACE the sensor component; when bioctl is not
there, not permitted, or found nothing, the sensor component stays.

The tools live in /sbin and /usr/sbin, which a non-root NetBSD PATH omits:
the default runner resolves them by absolute path (``hardware_identity
._tool``), so the argv here names the tool only.
"""

from __future__ import annotations

import plistlib
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from src.sysmanage_agent.collection.hardware_health import (
    ABSENT,
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
    plausible,
    reason,
    temperature_state,
    worst,
)

# --- bioctl (OpenBSD and NetBSD) ----------------------------------------------

# Volume statuses (sys/dev/biovar.h, BIOC_SV*_S on both systems).  A scrub
# or a parity check of a healthy volume is routine; a volume still being
# built or migrated is not redundant yet.
_BIO_VOLUME_STATES = {
    "Online": OK,
    "Scrubbing": OK,
    "Checking": OK,
    "Degraded": WARNING,
    "Rebuild": WARNING,
    "Building": WARNING,
    "Migrating": WARNING,
    "Offline": FAILED,
    "Failed": FAILED,
    "Invalid": UNKNOWN,
}
_VOL_STATUS = "|".join(_BIO_VOLUME_STATES)
_DISK_STATUS = (
    "Online|Offline|Failed|Rebuild|Hot spare|Unused|Scrubbing|Pass through|Invalid"
)
# member disks that carry the volume's data and are healthy
_MEMBER_ACTIVE = ("Online", "Scrubbing", "Pass through")
# not members of the volume's redundancy at all
_MEMBER_SPARE = ("Hot spare", "Unused")
_MEMBER_FAILED = ("Failed", "Offline")

# OpenBSD ``bioctl <controller>``:
#   "softraid0 0 Rebuild      500105249280 sd4     RAID1 42% done "
#   "          1 Rebuild      500105249280 0:1.0   noencl <sd2a>"
_OPENBSD_VOLUME = re.compile(
    rf"^\s*([a-z]+\d+)\s+(\d+)\s+({_VOL_STATUS})\s+\d+\s+(\S+)\s+"
    r"(RAID\w+|CRYPTO|CONCAT)(?:\s+(\d+)% done)?"
)
_OPENBSD_DISK = re.compile(
    rf"^\s*(\d+)\s+({_DISK_STATUS})\s+.+?\s+(\d+:\d+\.\d+)\s+\S+\s+<(.*)>\s*$"
)
# NetBSD ``bioctl <controller> show``:
#   "     0 Rebuild      136G                  ld0   RAID 1    N/A  37.50% done"
#   "   0:1 Rebuild      136G         0:1.0 noencl <SEAGATE ST3146356SS>"
_NETBSD_VOLUME = re.compile(
    rf"^\s*(\d+)\s+({_VOL_STATUS})\s+\S+\s+(.+?)\s+"
    r"(RAID \S+|Hot spare|Pass through)\s+\S+(?:\s+([\d.]+)% done)?"
)
_NETBSD_DISK = re.compile(
    rf"^\s*(\d+):(\d+)\s+({_DISK_STATUS})\s+\S+\s+(\d+:\d+\.\d+)\s+\S+\s+<(.*)>\s*$"
)

# bio(4) drivers whose kernel sensors describe RAID volumes
OPENBSD_BIO_DRIVERS = ("softraid", "mfi", "mfii", "ami", "arc", "ciss", "mpii")
NETBSD_BIO_DRIVERS = ("mfi", "mfii", "arcmsr", "ciss", "mpii", "cac")


def _member_name(vendor: str, location: str) -> str:
    """A softraid chunk names its partition (``sd0a``); a hardware RAID disk
    names its model, which is not a name -- use its channel:target.lun."""
    vendor = vendor.strip()
    return vendor if re.fullmatch(r"[a-z]+\d+[a-p]?", vendor) else location


def _percent(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    number = float(value)
    return int(number) if number.is_integer() else number


def parse_openbsd_bioctl(text: str) -> List[Dict[str, object]]:
    """OpenBSD ``bioctl <controller>`` -> one entry per volume.  A hot spare
    row ("softraid0 1 Hot spare ...") is not a volume and is skipped."""
    volumes: List[Dict[str, object]] = []
    for line in text.splitlines():
        match = _OPENBSD_VOLUME.match(line)
        if match:
            ctrl, volid, status, device, level, percent = match.groups()
            volumes.append(
                {"controller": ctrl, "volume": int(volid), "status": status,
                 "device": device, "level": level, "percent": _percent(percent),
                 "members": []}
            )  # fmt: skip
            continue
        disk = _OPENBSD_DISK.match(line)
        if disk and volumes:
            volumes[-1]["members"].append(
                {"status": disk.group(2),
                 "name": _member_name(disk.group(4), disk.group(3))}
            )  # fmt: skip
    return volumes


def parse_netbsd_bioctl(text: str, controller: str) -> List[Dict[str, object]]:
    """NetBSD ``bioctl <controller> show`` -> one entry per volume.  Hot
    spare and pass-through "volumes" are single disks, not arrays."""
    volumes: List[Dict[str, object]] = []
    current: Optional[Dict[str, object]] = None
    for line in text.splitlines():
        match = _NETBSD_VOLUME.match(line)
        if match:
            volid, status, label, level, percent = match.groups()
            current = None
            if level.startswith("RAID"):
                current = {
                    "controller": controller, "volume": int(volid),
                    "status": status, "device": label.split()[0], "level": level,
                    "percent": _percent(percent), "members": [],
                }  # fmt: skip
                volumes.append(current)
            continue
        disk = _NETBSD_DISK.match(line)
        if disk and current is not None:
            current["members"].append(
                {"status": disk.group(3),
                 "name": _member_name(disk.group(5), disk.group(4))}
            )  # fmt: skip
    return volumes


def bio_volume_state(volume: Dict[str, object]) -> Tuple[str, List[Dict]]:
    """A volume's state: its own status, and every member not healthy."""
    status = str(volume["status"])
    state = _BIO_VOLUME_STATES.get(status, UNKNOWN)
    reasons = [] if state == OK else [reason("array_state", state=status)]
    if status == "Rebuild" and volume.get("percent") is not None:
        reasons.append(reason("rebuilding", percent=volume["percent"]))
    members = [m for m in volume["members"] if m["status"] not in _MEMBER_SPARE]
    active = sum(1 for m in members if m["status"] in _MEMBER_ACTIVE)
    if active < len(members):
        state = worst([state, WARNING])
        reasons.append(reason("array_degraded", active=active, total=len(members)))
    failed = [m["name"] for m in members if m["status"] in _MEMBER_FAILED]
    if failed:
        reasons.append(reason("failed_members", members=failed))
    for member in members:
        if member["status"] not in _MEMBER_ACTIVE + _MEMBER_FAILED:
            label = f"{member['name']} ({member['status']})"
            reasons.append(reason("member_state", member=label))
    return state, reasons


def _add_bio_volume(report: Report, volume: Dict[str, object]) -> None:
    state, reasons = bio_volume_state(volume)
    members = volume["members"]
    metrics = {
        "status": volume["status"],
        "level": volume["level"],
        "members": len([m for m in members if m["status"] not in _MEMBER_SPARE]),
        "progress_percent": volume.get("percent"),
    }
    report.add(
        ARRAY, f"{volume['controller']}/{volume['volume']}",
        f"{volume['device']} {volume['level']}", state, reasons, metrics, "bioctl",
    )  # fmt: skip


def _bioctl(run, system: str, controller: str):
    if system == "NetBSD":
        rc, out = run(["bioctl", controller, "show"])
        return rc, out, parse_netbsd_bioctl(out, controller)
    rc, out = run(["bioctl", controller])
    return rc, out, parse_openbsd_bioctl(out)


def collect_bioctl(
    report: Report, run, controllers: Iterable[str], system: str
) -> Set[str]:
    """Every volume on ``controllers``; returns the controllers bioctl
    detailed, whose kernel sensor summary the caller then leaves out."""
    controllers = sorted(set(controllers))
    if not controllers:
        report.source("bioctl", ABSENT, "no RAID volumes")
        return set()
    covered: Set[str] = set()
    failures = []
    for controller in controllers:
        rc, out, volumes = _bioctl(run, system, controller)
        if rc == -1:
            report.source("bioctl", ABSENT)
            return covered
        if rc != 0 and not volumes:
            # "Can't open /dev/bio: Permission denied" without root
            failures.append(f"{controller}: {out.strip()[:120]}")
            continue
        for volume in volumes:
            _add_bio_volume(report, volume)
        if volumes:
            covered.add(controller)
    if failures:
        report.source("bioctl", SOURCE_FAILED, "; ".join(failures))
    else:
        report.source("bioctl", RAN)
    return covered


def _base(device: str) -> str:
    return device.rstrip("0123456789")


# --- NetBSD envstat -------------------------------------------------------------

# sysmon_envsys sensor states (sys/dev/sysmon/sysmon_envsys_tables.c)
_ENVSYS_STATES = {
    "valid": OK,
    "invalid": UNKNOWN,
    "unknown": UNKNOWN,
    "critical": FAILED,
    "critical-under": FAILED,
    "critical-over": FAILED,
    "warning-under": WARNING,
    "warning-over": WARNING,
}
_DRIVE_STATES = {
    "online": OK,
    "ready": OK,
    "idle": OK,
    "active": OK,
    "checking": OK,
    "powering up": OK,
    "powering down": OK,
    "building": WARNING,
    "rebuilding": WARNING,
    "degraded": WARNING,
    "migrating": WARNING,
    "failed": FAILED,
    "offline": FAILED,
    "unknown": UNKNOWN,
}
# cur-value units: micro-volts, micro-watts ... ; fans in RPM
_ENVSYS_UNITS = {
    "Fan": (1, "RPM"),
    "Voltage DC": (1e6, "V"),
    "Voltage AC": (1e6, "V"),
    "Ohms": (1e6, "Ohm"),
    "Watts": (1e6, "W"),
    "Ampere": (1e6, "A"),
    "Watt hour": (1e6, "Wh"),
    "Ampere hour": (1e6, "Ah"),
}
_MICROKELVIN_ZERO_C = 273150000


def _celsius(microkelvin) -> Optional[float]:
    """Temperatures and their limits are micro-kelvin."""
    if not isinstance(microkelvin, int):
        return None
    return round((microkelvin - _MICROKELVIN_ZERO_C) / 1e6, 2)


def parse_envstat_xml(text: str) -> Dict[str, List[Dict[str, object]]]:
    """``envstat -x`` -> {device: [sensor dicts]}; raises ValueError when the
    output is not a plist.  Each device's array ends with a
    ``device-properties`` dict, which is not a sensor."""
    start, end = text.find("<?xml"), text.rfind("</plist>")
    if start < 0 or end < 0:
        raise ValueError("no plist in envstat -x output")
    try:
        data = plistlib.loads(text[start : end + len("</plist>")].encode())
    except Exception as exc:  # pylint: disable=broad-exception-caught
        raise ValueError(f"envstat -x: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("envstat -x: not a dictionary")
    return {
        device: [s for s in sensors if isinstance(s, dict) and "type" in s]
        for device, sensors in data.items()
        if isinstance(sensors, list)
    }


def _envstat_value(sensor: Dict[str, object]) -> str:
    """The reading in the sensor's own units, for the sensor_status reason."""
    if sensor.get("battery-capacity"):
        return str(sensor["battery-capacity"])
    if sensor.get("drive-state"):
        return str(sensor["drive-state"])
    value = sensor.get("cur-value")
    if not isinstance(value, int):
        return str(sensor.get("state") or "")
    scale, unit = _ENVSYS_UNITS.get(str(sensor.get("type")), (1, ""))
    return f"{value / scale:g} {unit}".strip()


def _envstat_reason(sensor: Dict[str, object]) -> Dict[str, object]:
    return reason(
        "sensor_status", sensor=str(sensor.get("description") or ""),
        value=_envstat_value(sensor), status=str(sensor.get("state") or ""),
    )  # fmt: skip


def _envstat_temperature(report: Report, device: str, sensor) -> None:
    celsius = _celsius(sensor.get("cur-value"))
    if not plausible(celsius):
        return  # invalid: no cur-value at all, or a sentinel
    high = _celsius(sensor.get("warning-max"))
    critical = _celsius(sensor.get("critical-max"))
    state, reasons = temperature_state(celsius, high, critical)
    kernel = _ENVSYS_STATES.get(str(sensor.get("state")), OK)
    if not reasons and kernel in (WARNING, FAILED):
        # flagged against a limit the sensor did not expose to userland
        state, reasons = kernel, [_envstat_reason(sensor)]
    desc = str(sensor.get("description") or "temperature")
    metrics = {"temperature_c": celsius, "high_c": high, "critical_c": critical}
    report.add(SENSOR, f"{device}/{desc}", f"{device} {desc}", state, reasons,
               {k: v for k, v in metrics.items() if plausible(v)}, "envstat")  # fmt: skip


def _envstat_drive(report: Report, device: str, sensor) -> None:
    drive_state = str(sensor.get("drive-state") or "unknown")
    state = worst(
        [_DRIVE_STATES.get(drive_state, UNKNOWN),
         _ENVSYS_STATES.get(str(sensor.get("state")), UNKNOWN)]
    )  # fmt: skip
    kind = ARRAY if _base(device) in NETBSD_BIO_DRIVERS else DRIVE
    desc = str(sensor.get("description") or "drive")
    reasons = [] if state == OK else [_envstat_reason(sensor)]
    report.add(kind, f"{device}/{desc}", f"{device} {desc}", state, reasons,
               {"drive_state": drive_state}, "envstat")  # fmt: skip


def _envstat_other(report: Report, device: str, sensor) -> None:
    """A fan, voltage or battery is a component only when the kernel flags
    it; an ``invalid`` one (an unused voltage input) is not measured."""
    state = _ENVSYS_STATES.get(str(sensor.get("state")))
    if state not in (WARNING, FAILED):
        return
    desc = str(sensor.get("description") or sensor.get("type"))
    report.add(SENSOR, f"{device}/{desc}", f"{device} {desc}", state,
               [_envstat_reason(sensor)], {}, "envstat")  # fmt: skip


def read_envstat(report: Report, run) -> Dict[str, List[Dict[str, object]]]:
    rc, out = run(["envstat", "-x"])
    if rc == -1:
        report.source("envstat", ABSENT)
        return {}
    if rc != 0:
        report.source("envstat", SOURCE_FAILED, out)
        return {}
    try:
        devices = parse_envstat_xml(out)
    except ValueError as exc:
        report.source("envstat", SOURCE_FAILED, str(exc))
        return {}
    report.source("envstat", RAN)
    return devices


def add_envstat(
    report: Report, devices: Dict[str, List[Dict]], skip: Iterable[str] = ()
) -> None:
    """Components from the sensors; drive sensors of a controller in
    ``skip`` are left out (bioctl detailed its volumes)."""
    skip = set(skip)
    for device, sensors in devices.items():
        for sensor in sensors:
            kind = sensor.get("type")
            if kind == "Temperature":
                _envstat_temperature(report, device, sensor)
            elif kind == "Drive" and device not in skip:
                _envstat_drive(report, device, sensor)
            elif kind != "Drive":
                _envstat_other(report, device, sensor)


# --- NetBSD RAIDframe -----------------------------------------------------------

_RAID_COMPONENT = re.compile(r"^\s+(\S+):\s+(\w+)\s*$")
# rf_ds_* (sbin/raidctl/raidctl.c device_status)
_COMPONENT_LOST = ("failed", "reconstructing")
_COMPONENT_OK = ("optimal",)
_SPARE_OK = ("spare", "used_spare")


def _raidctl_header(line: str, result: Dict[str, object]) -> Optional[str]:
    """The section a header line opens, or None when it is not a header."""
    if line.startswith("Components:"):
        return "components"
    if line.startswith("Spares:"):
        return "spares"
    level = re.match(r"^\s*RAID Level:\s*(\S+)", line)
    if level:
        result.setdefault("level", level.group(1))
    for pattern, key in (
        (r"^Parity status:\s*(\S+)", "parity"),
        (r"^Reconstruction is (\d+)% complete", "recon_percent"),
        (r"^Parity Re-write is (\d+)% complete", "rewrite_percent"),
    ):
        match = re.match(pattern, line)
        if match:
            value = match.group(1)
            result[key] = int(value) if value.isdigit() else value
    return None


def parse_raidctl_status(text: str) -> Dict[str, object]:
    """``raidctl -s raidN`` -> components and spares (name, status), the
    RAID level from the first component label, parity and progress."""
    result: Dict[str, object] = {"components": [], "spares": []}
    section: Optional[str] = None
    for line in text.splitlines():
        header = _raidctl_header(line, result)
        if header:
            section = header
            continue
        match = _RAID_COMPONENT.match(line) if section else None
        if match:
            result[section].append((match.group(1), match.group(2)))
        else:
            section = None  # the lists end where the labels begin
    return result


def _raid_lost(level: Optional[str], statuses: List[str]) -> bool:
    """Beyond what the level tolerates: any member of a RAID 0, a whole
    mirrored pair of a RAID 1 (columns 0/1, 2/3 ...), two of a RAID 4/5."""
    lost = [s in _COMPONENT_LOST for s in statuses]
    if not any(lost):
        return False
    if level == "1":
        return any(all(lost[i : i + 2]) for i in range(0, len(lost), 2))
    if level in ("4", "5"):
        return sum(lost) > 1
    return True


def raidctl_state(status: Dict[str, object]) -> Tuple[str, List[Dict]]:
    components = list(status.get("components") or [])
    if not components:
        return UNKNOWN, []
    statuses = [s for _name, s in components]
    active = sum(1 for s in statuses if s in _COMPONENT_OK)
    states, reasons = [OK], []
    if active < len(components):
        states.append(FAILED if _raid_lost(status.get("level"), statuses) else WARNING)
        reasons.append(reason("array_degraded", active=active, total=len(components)))
    failed = [name for name, s in components if s == "failed"]
    if failed:
        reasons.append(reason("failed_members", members=failed))
    odd = [(n, s) for n, s in components if s not in _COMPONENT_OK + ("failed",)]
    odd += [(n, s) for n, s in status.get("spares") or [] if s not in _SPARE_OK]
    for name, member_status in odd:
        states.append(WARNING)
        reasons.append(reason("member_state", member=f"{name} ({member_status})"))
    if "reconstructing" in statuses and status.get("recon_percent") is not None:
        reasons.append(reason("rebuilding", percent=status["recon_percent"]))
    if status.get("parity") == "DIRTY":
        states.append(WARNING)
        reasons.append(reason("array_state", state="parity DIRTY"))
    return worst(states), reasons


def collect_raidctl(report: Report, run) -> None:
    """Each RAIDframe set the kernel lists in ``hw.disknames``."""
    rc, out = run(["sysctl", "-n", "hw.disknames"])
    sets = sorted(set(re.findall(r"\braid\d+\b", out))) if rc == 0 else []
    if not sets:
        report.source("raidctl", ABSENT, "no RAIDframe sets")
        return
    failures = []
    for name in sets:
        rc, text = run(["raidctl", "-s", name])
        if rc == -1:
            report.source("raidctl", ABSENT)
            return
        status = parse_raidctl_status(text)
        if rc != 0 and not status["components"]:
            failures.append(f"{name}: {text.strip()[:120]}")
            continue
        state, reasons = raidctl_state(status)
        level = status.get("level")
        rebuilding = any(s == "reconstructing" for _n, s in status["components"])
        metrics = {
            "level": level,
            "members": len(status["components"]),
            "parity": status.get("parity"),
            "rebuild_percent": status.get("recon_percent") if rebuilding else None,
        }
        label = f"{name} RAID{level}" if level else name
        report.add(ARRAY, name, label, state, reasons, metrics, "raidctl")
    if failures:
        report.source("raidctl", SOURCE_FAILED, "; ".join(failures))
    else:
        report.source("raidctl", RAN)


# --- NetBSD entry point ---------------------------------------------------------


def collect_netbsd(report: Report, run) -> None:
    """envstat sensors, bioctl volumes on the controllers envstat lists,
    and RAIDframe sets."""
    devices = read_envstat(report, run)
    controllers = [d for d in devices if _base(d) in NETBSD_BIO_DRIVERS]
    covered = collect_bioctl(report, run, controllers, "NetBSD")
    add_envstat(report, devices, skip=covered)
    collect_raidctl(report, run)
