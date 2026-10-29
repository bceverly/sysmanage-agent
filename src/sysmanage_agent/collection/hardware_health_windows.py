# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Windows hardware health (Phase 23.1 S1), one PowerShell call:

* drives ............ ``Get-PhysicalDisk`` health and operational status,
                      with ``Get-StorageReliabilityCounter`` (temperature,
                      wear, errors, power-on hours)
* Storage Spaces .... ``Get-VirtualDisk`` health
* temperatures ...... ACPI thermal zones (``MSAcpi_ThermalZoneTemperature``,
                      administrator), judged against each zone's own critical
                      and passive trip points
* machine checks .... WHEA-Logger events in the System log over the last 24
                      hours (``hardware_health_mce`` judges them)

What the S0 spike found on a real machine (an x13s, recorded): reliability
counters come back EMPTY for read / write errors and power-on hours -- not
measured, never 0 -- ``MSStorageDriver_FailurePredictStatus`` is "Not
supported" on NVMe, and absent thermal zones read a raw 0 or 2730 (0 C):
sentinels, dropped.  A trip point of 0 means the zone declares none.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

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
    WEAR_WARNING_PERCENT,
    Report,
    plausible,
    reason,
    temperature_state,
    worst,
)
from src.sysmanage_agent.collection.hardware_health_mce import add_machine_checks

WHEA = "WHEA-Logger"

SCRIPT = r"""
$ProgressPreference = 'SilentlyContinue'
$disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
    $r = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
    [ordered]@{
        id = [string]$_.DeviceId; name = [string]$_.FriendlyName
        media = [string]$_.MediaType; bus = [string]$_.BusType
        health = [string]$_.HealthStatus
        operational = @($_.OperationalStatus | ForEach-Object { [string]$_ })
        temperature = $r.Temperature; temperature_max = $r.TemperatureMax
        wear = $r.Wear; read_errors = $r.ReadErrorsTotal
        write_errors = $r.WriteErrorsTotal; power_on_hours = $r.PowerOnHours
    }
})
$vdisks = @(Get-VirtualDisk -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{
        id = [string]$_.UniqueId; name = [string]$_.FriendlyName
        health = [string]$_.HealthStatus
        operational = @($_.OperationalStatus | ForEach-Object { [string]$_ })
        resiliency = [string]$_.ResiliencySettingName
    }
})
$zones = @(Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ name = [string]$_.InstanceName; current = $_.CurrentTemperature
                critical = $_.CriticalTripPoint; passive = $_.PassiveTripPoint }
})
$whea = [ordered]@{ corrected = 0; fatal = 0; error = $null }
try {
    $events = @(Get-WinEvent -ErrorAction Stop -FilterHashtable @{
        LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'
        StartTime = (Get-Date).AddHours(-24) })
    $whea.corrected = @($events | Where-Object { $_.Level -eq 3 }).Count
    $whea.fatal = @($events | Where-Object { $_.Level -eq 1 -or $_.Level -eq 2 }).Count
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $whea.error = [string]$_.Exception.Message }
}
[ordered]@{ disks = $disks; virtual_disks = $vdisks; thermal_zones = $zones; whea = $whea } | ConvertTo-Json -Depth 4 -Compress
"""

_HEALTH = {"Healthy": OK, "Warning": WARNING, "Unhealthy": FAILED}


_SOURCE = "powershell storage"


def _decikelvin(value) -> Optional[float]:
    """ACPI thermal zones report tenths of a kelvin; 0 = no reading."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    return round(value / 10.0 - 273.15, 1)


def disk_state(disk: Dict[str, object]):
    state = _HEALTH.get(str(disk.get("health")), UNKNOWN)
    reasons: List[str] = []
    if state != OK:
        reasons.append(reason("health_status", status=disk.get("health") or None))
    operational = [s for s in disk.get("operational") or [] if s != "OK"]
    if operational:
        reasons.append(reason("operational_status", status=operational))
        state = worst([state, WARNING])
    wear = disk.get("wear")
    if isinstance(wear, int) and wear >= WEAR_WARNING_PERCENT:
        state = worst([state, WARNING])
        reasons.append(reason("endurance_used", percent=wear))
    for field in ("read_errors", "write_errors"):
        value = disk.get(field)
        if isinstance(value, int) and value > 0:
            state = worst([state, WARNING])
            reasons.append(reason(field, count=value))
    return state, reasons


def _disk(report: Report, disk: Dict[str, object]) -> None:
    state, reasons = disk_state(disk)
    temperature = disk.get("temperature")
    metrics = {
        # 0 from a reliability counter is "not reported", as on the x13s
        "temperature_c": temperature if plausible(temperature) else None,
        "percent_used": disk.get("wear"),
        "read_errors": disk.get("read_errors"),
        "write_errors": disk.get("write_errors"),
        "power_on_hours": disk.get("power_on_hours"),
        "bus": disk.get("bus") or None,
        "media": disk.get("media") or None,
    }
    report.add(
        DRIVE, f"disk{disk.get('id')}", str(disk.get("name") or ""), state,
        reasons, metrics, "Get-PhysicalDisk",
    )  # fmt: skip


def _virtual_disk(report: Report, vdisk: Dict[str, object]) -> None:
    state = _HEALTH.get(str(vdisk.get("health")), UNKNOWN)
    reasons = (
        [] if state == OK else [reason("health_status", status=vdisk.get("health"))]
    )
    operational = [s for s in vdisk.get("operational") or [] if s != "OK"]
    if operational:
        reasons.append(reason("operational_status", status=operational))
    report.add(
        ARRAY, str(vdisk.get("id") or vdisk.get("name")), str(vdisk.get("name") or ""),
        state, reasons, {"resiliency": vdisk.get("resiliency") or None},
        "Get-VirtualDisk",
    )  # fmt: skip


def _thermal_zone(report: Report, zone: Dict[str, object]) -> None:
    celsius = _decikelvin(zone.get("current"))
    if not plausible(celsius):
        return
    high, critical = _decikelvin(zone.get("passive")), _decikelvin(zone.get("critical"))
    state, reasons = temperature_state(celsius, high, critical)
    name = str(zone.get("name") or "").replace("ACPI\\", "")
    report.add(
        SENSOR, f"acpi/{name}", f"ACPI {name}", state, reasons,
        {"temperature_c": celsius,
         "high_c": high if plausible(high) else None,
         "critical_c": critical if plausible(critical) else None},
        "MSAcpi_ThermalZoneTemperature",
    )  # fmt: skip


def parse(data: Dict[str, object], report: Report) -> None:
    for disk in data.get("disks") or []:
        _disk(report, disk)
    for vdisk in data.get("virtual_disks") or []:
        _virtual_disk(report, vdisk)
    for zone in data.get("thermal_zones") or []:
        _thermal_zone(report, zone)
    _whea(report, data.get("whea"))


def _whea(report: Report, whea) -> None:
    """WHEA-Logger events of the last 24 hours: Warning is a corrected
    hardware error, Error / Critical an uncorrected one.  "No events were
    found" is zero (the script turns it into 0), not a failure."""
    if not isinstance(whea, dict):
        return  # an older script: not measured
    if whea.get("error"):
        report.source(WHEA, SOURCE_FAILED, str(whea["error"]))
        return
    corrected, fatal = whea.get("corrected"), whea.get("fatal")
    if not isinstance(corrected, int) or not isinstance(fatal, int):
        report.source(WHEA, SOURCE_FAILED, "unreadable WHEA counts")
        return
    report.source(WHEA, RAN)
    add_machine_checks(report, "whea", "Hardware errors (WHEA)", corrected, fatal, WHEA)


def collect(report: Report, _system, run, _read=None) -> None:
    # The script is passed as plain text (one ``-Command`` argument), never
    # base64-encoded: hiding a PowerShell payload that way is a malware tell,
    # and Microsoft Defender flagged the agent's installer in winget
    # validation from 3.11 on (2026-10-28) -- the release this collector
    # arrived in.  One argument is parsed as a whole, so multi-line blocks
    # work; it must hold no double quote, which Windows PowerShell 5.1
    # mangles in arguments (a test guards that).
    rc, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", SCRIPT])
    if rc != 0:
        report.source(_SOURCE, SOURCE_FAILED, out)
        return
    # No JSON at all is a failure, not "nothing found": an empty report
    # would read as healthy.
    start = out.find("{")
    try:
        data = json.loads(out[start:]) if start >= 0 else None
        if not isinstance(data, dict):
            raise ValueError("no report in the output")
    except ValueError as exc:
        report.source(_SOURCE, SOURCE_FAILED, f"unreadable output: {exc}")
        return
    report.source(_SOURCE, RAN)
    parse(data, report)
