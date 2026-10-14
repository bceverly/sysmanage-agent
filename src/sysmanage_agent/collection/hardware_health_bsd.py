# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
BSD hardware health (Phase 23.1 S1), from the base system:

FreeBSD
  * NVMe drives ..... ``nvmecontrol logpage -p 2`` (base system; root)
  * other drives .... ``smartctl -j`` where installed, else ``unknown``
  * ZFS pools ....... ``zpool``
  * GEOM mirrors .... ``gmirror status -s`` / ``graid status -s`` when the
                      class is loaded (the lab box has neither loaded)
  * temperatures .... ``hw.acpi.thermal.tzN`` against the zone's own
                      ``_CRT`` / ``_PSV``, and ``dev.cpu.N.temperature``
                      where coretemp / amdtemp is loaded

OpenBSD (and NetBSD's ``envstat`` once a NetBSD host is in the lab again)
  * ``sysctl hw.sensors`` -- the kernel already judges each sensor (OK /
    WARNING / CRITICAL): NVMe endurance and spare, softraid volumes and
    drives, temperatures.  We keep its verdict rather than second-guess it.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

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
    collect_zfs,
    nvme_state,
    parse_nvmecontrol_logpage,
    plausible,
    reason,
    smartctl_drive,
    smartctl_source,
    temperature_state,
    worst,
)

# --- FreeBSD -------------------------------------------------------------------


def parse_nvmecontrol_devlist(text: str) -> Dict[str, str]:
    """``nvmecontrol devlist`` -> {controller: model}."""
    controllers = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(nvme\d+):\s*(.*)$", line)
        if match:
            controllers[match.group(1)] = match.group(2).strip()
    return controllers


def collect_freebsd_nvme(report: Report, run) -> None:
    rc, out = run(["nvmecontrol", "devlist"])
    if rc == -1:
        report.source("nvmecontrol", ABSENT)
        return
    controllers = parse_nvmecontrol_devlist(out)
    if rc != 0 and not controllers:
        # "No NVMe controllers found" exits non-zero
        report.source("nvmecontrol", RAN if "No NVMe" in out else SOURCE_FAILED, out)
        return
    failures = []
    for ctrl, model in controllers.items():
        rc, page = run(["nvmecontrol", "logpage", "-p", "2", ctrl])
        metrics = parse_nvmecontrol_logpage(page) if rc == 0 else {}
        if rc != 0:
            failures.append(f"{ctrl}: {page.strip()[:120]}")
        state, reasons = nvme_state(metrics)
        report.add(DRIVE, ctrl, model, state, reasons, metrics, "nvmecontrol")
    if failures:
        report.source("nvmecontrol", SOURCE_FAILED, "; ".join(failures))
    else:
        report.source("nvmecontrol", RAN)


# NVMe (read natively) and paravirtual disks (no SMART at all).
_NOT_SMART = ("nda", "nvd", "nvme", "vtbd", "xbd")


def parse_geom_disks(text: str) -> List[Dict[str, object]]:
    """``geom disk list`` -> [{name, mediasize, descr}]."""
    disks: List[Dict[str, object]] = []
    for line in text.splitlines():
        key, _sep, value = line.strip().partition(": ")
        if key == "Geom name":
            disks.append({"name": value.strip(), "mediasize": None, "descr": None})
        elif disks and key == "Mediasize":
            size = value.split()[0] if value.split() else ""
            disks[-1]["mediasize"] = int(size) if size.isdigit() else None
        elif disks and key == "descr":
            disks[-1]["descr"] = value.strip() or None
    return disks


def collect_freebsd_disks(report: Report, run) -> None:
    """SATA / SAS / USB disks through smartctl.  NVMe is read natively
    (nvmecontrol); an empty card reader (Mediasize 0 -- the lab box has one)
    is not a drive; paravirtual disks (virtio ``vtbd``, Xen ``xbd``) have no
    SMART."""
    rc, out = run(["geom", "disk", "list"])
    if rc != 0:
        return
    disks = [
        d
        for d in parse_geom_disks(out)
        if not str(d["name"]).startswith(_NOT_SMART) and d["mediasize"]
    ]
    for disk in disks:
        smartctl_drive(
            report, run, f"/dev/{disk['name']}", str(disk["name"]), disk["descr"]
        )
    if disks:
        smartctl_source(report, run)


_GEOM_STATES = {"COMPLETE": OK, "OPTIMAL": OK, "DEGRADED": WARNING}


def parse_geom_status(text: str) -> List[Dict[str, object]]:
    """``gmirror status -s`` / ``graid status -s``: name, state, members."""
    volumes: Dict[str, Dict[str, object]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        name, state, member = fields[0], fields[1], " ".join(fields[2:])
        volume = volumes.setdefault(name, {"name": name, "state": state, "members": []})
        volume["members"].append(member)
    return list(volumes.values())


def collect_geom(report: Report, run, geom: str) -> None:
    rc, out = run([geom, "status", "-s"])
    if rc == -1:
        report.source(geom, ABSENT)
        return
    if rc != 0:
        # "Command 'status' not available" = the class is not loaded: nothing
        # is mirrored that way on this host.
        detail = "class not loaded" if "not available" in out else out
        report.source(geom, ABSENT if "not available" in out else SOURCE_FAILED, detail)
        return
    report.source(geom, RAN)
    for volume in parse_geom_status(out):
        state = _GEOM_STATES.get(str(volume["state"]).upper(), FAILED)
        reasons = [] if state == OK else [reason("array_state", state=volume["state"])]
        bad = [m for m in volume["members"] if "ACTIVE" not in m and "ONLINE" not in m]
        reasons += [reason("member_state", member=m) for m in bad]
        report.add(
            ARRAY, str(volume["name"]), str(volume["name"]), state, reasons,
            {"state": volume["state"], "members": len(volume["members"])}, geom,
        )  # fmt: skip


def _celsius(text: str) -> Optional[float]:
    match = re.match(r"^\s*(-?[\d.]+)C\s*$", text)
    return float(match.group(1)) if match else None


def parse_acpi_thermal(text: str) -> Dict[str, Dict[str, Optional[float]]]:
    """``sysctl hw.acpi.thermal`` -> {zone: {temperature, critical, passive}}."""
    zones: Dict[str, Dict[str, Optional[float]]] = {}
    for line in text.splitlines():
        match = re.match(
            r"^hw\.acpi\.thermal\.(tz\d+)\.(temperature|_CRT|_PSV):\s*(.+)$", line
        )
        if match:
            key = {"temperature": "temperature", "_CRT": "critical", "_PSV": "passive"}
            zones.setdefault(match.group(1), {})[key[match.group(2)]] = _celsius(
                match.group(3)
            )
    return zones


def collect_freebsd_temperatures(report: Report, run) -> None:
    rc, out = run(["sysctl", "hw.acpi.thermal"])
    zones = parse_acpi_thermal(out) if rc == 0 else {}
    rc_cpu, cpu_out = run(["sysctl", "-q", "dev.cpu"])
    cpus = re.findall(r"^dev\.cpu\.(\d+)\.temperature:\s*(-?[\d.]+)C", cpu_out, re.M)
    if not zones and not cpus:
        report.source("sysctl temperatures", ABSENT if rc_cpu != -1 else SOURCE_FAILED)
        return
    report.source("sysctl temperatures", RAN)
    for zone, values in zones.items():
        celsius = values.get("temperature")
        if not plausible(celsius):
            continue
        state, reasons = temperature_state(
            celsius, values.get("passive"), values.get("critical")
        )
        metrics = {
            "temperature_c": celsius,
            "high_c": values.get("passive"),
            "critical_c": values.get("critical"),
        }
        report.add(SENSOR, f"acpi/{zone}", f"ACPI {zone}", state, reasons,
                   {k: v for k, v in metrics.items() if plausible(v)}, "sysctl")  # fmt: skip
    for cpu, value in cpus:
        celsius = float(value)
        if plausible(celsius):
            report.add(SENSOR, f"cpu{cpu}", f"CPU {cpu}", OK, [],
                       {"temperature_c": celsius}, "sysctl")  # fmt: skip


# --- OpenBSD / NetBSD sensors ---------------------------------------------------

_SENSOR = re.compile(
    r"^hw\.sensors\.([a-z]+\d+)\.([a-z]+)(\d+)=(\S+)(?:\s+(\S+))?"
    r"(?:\s+\(([^)]*)\))?(?:,\s*(OK|WARNING|CRITICAL|UNKNOWN))?\s*$"
)
_SENSOR_STATES = {"OK": OK, "WARNING": WARNING, "CRITICAL": FAILED, "UNKNOWN": UNKNOWN}
# devices whose sensors describe a drive or a RAID volume
_DRIVE_DEVICES = ("nvme", "sd", "wd")
_ARRAY_DEVICES = ("softraid", "mfi", "mfii", "ami", "arc", "ciss", "mpii")


def parse_hw_sensors(text: str) -> List[Dict[str, object]]:
    sensors = []
    for line in text.splitlines():
        match = _SENSOR.match(line.strip())
        if not match:
            continue
        device, kind, index, value, unit, desc, status = match.groups()
        sensors.append(
            {
                "device": device,
                "type": kind,
                "index": int(index),
                "value": value,
                "unit": unit,
                "description": desc,
                "status": status,
            }
        )
    return sensors


def _sensor_value(sensor) -> Optional[float]:
    try:
        return float(str(sensor["value"]).rstrip("%"))
    except ValueError:
        return None


def _label(sensor) -> str:
    return sensor["description"] or f"{sensor['type']}{sensor['index']}"


def _sensor_reason(sensor) -> Dict[str, object]:
    """The kernel's own verdict on a sensor; its label is the kernel's text."""
    return reason(
        "sensor_status", sensor=_label(sensor), value=sensor["value"],
        status=sensor["status"],
    )  # fmt: skip


_DEVICE_METRICS = {
    "endurance used": "percent_used",
    "available spare": "available_spare",
}


def _device_metric(sensor, metrics: Dict[str, object]) -> None:
    label = _label(sensor)
    if sensor["type"] == "temp":
        metrics["temperature_c"] = _sensor_value(sensor)
    elif label in _DEVICE_METRICS:
        metrics[_DEVICE_METRICS[label]] = _sensor_value(sensor)
    elif sensor["type"] == "drive":
        metrics[f"drive{sensor['index']}"] = f"{sensor['value']} ({label})"


def _device_component(report: Report, device: str, sensors: List[Dict]) -> None:
    kind = ARRAY if device.rstrip("0123456789") in _ARRAY_DEVICES else DRIVE
    states, reasons, metrics = [], [], {}
    for sensor in sensors:
        _device_metric(sensor, metrics)
        state = _SENSOR_STATES.get(sensor["status"] or "")
        if state is None:
            continue
        states.append(state)
        if state != OK:
            reasons.append(_sensor_reason(sensor))
    state = worst(states) if states else UNKNOWN
    report.add(kind, device, device, state, reasons, metrics, "hw.sensors")


def _platform_sensor(report: Report, device: str, sensor) -> None:
    """A temperature, or anything else the kernel itself flags (a battery,
    a fan); the rest (frequencies, healthy batteries) is not a component."""
    status = _SENSOR_STATES.get(sensor["status"] or "")
    if sensor["type"] == "temp":
        celsius = _sensor_value(sensor)
        if plausible(celsius):
            report.add(
                SENSOR, f"{device}/temp{sensor['index']}",
                f"{device} {sensor['description'] or 'temperature'}",
                status or OK, [] if status in (None, OK) else [_sensor_reason(sensor)],
                {"temperature_c": celsius}, "hw.sensors",
            )  # fmt: skip
    elif status in (WARNING, FAILED):
        report.add(
            SENSOR, f"{device}/{sensor['type']}{sensor['index']}",
            f"{device} {_label(sensor)}", status, [_sensor_reason(sensor)], {},
            "hw.sensors",
        )  # fmt: skip


def collect_hw_sensors(report: Report, run) -> None:
    rc, out = run(["sysctl", "hw.sensors"])
    if rc != 0:
        report.source("hw.sensors", ABSENT if rc == -1 else SOURCE_FAILED, out)
        return
    report.source("hw.sensors", RAN)
    by_device: Dict[str, List[Dict]] = {}
    for sensor in parse_hw_sensors(out):
        by_device.setdefault(str(sensor["device"]), []).append(sensor)
    for device, sensors in by_device.items():
        base = device.rstrip("0123456789")
        if base in _DRIVE_DEVICES or base in _ARRAY_DEVICES:
            _device_component(report, device, sensors)
        else:
            for sensor in sensors:
                _platform_sensor(report, device, sensor)


def collect(report: Report, system: str, run, _read=None) -> None:
    if system == "FreeBSD":
        collect_freebsd_nvme(report, run)
        collect_freebsd_disks(report, run)
        collect_zfs(report, run)
        collect_geom(report, run, "gmirror")
        collect_geom(report, run, "graid")
        collect_freebsd_temperatures(report, run)
        return
    if system == "OpenBSD":
        collect_hw_sensors(report, run)
        return
    report.source("envstat", ABSENT, f"{system}: not collected yet")
    collect_zfs(report, run)
