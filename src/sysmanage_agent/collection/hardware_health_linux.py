# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Linux hardware health (Phase 23.1 S1), native first:

* NVMe drives ..... the SMART / health log through the kernel's admin ioctl
                    (root; no nvme-cli or smartmontools needed -- the S0 spike
                    found neither on any lab machine)
* other drives .... ``smartctl -j`` where installed, else ``unknown`` with
                    the reason -- never assumed healthy
* md arrays ....... ``/proc/mdstat`` (degraded ``[U_]``, failed ``(F)``
                    members, rebuild progress)
* ZFS pools ....... ``zpool`` where installed
* btrfs, LVM RAID . ``btrfs`` / ``lvs`` (hardware_health_linux_storage)
* temperatures .... hwmon sysfs, judged against the limits the hardware
                    declares (``temp*_max`` / ``temp*_crit``)
* memory .......... EDAC corrected / uncorrected error counts
"""

from __future__ import annotations

import ctypes
import os
import re
from typing import Dict, List, Optional

from src.sysmanage_agent.collection.hardware_health import (
    ABSENT,
    ARRAY,
    DRIVE,
    FAILED,
    MEMORY,
    OK,
    RAN,
    SENSOR,
    SOURCE_FAILED,
    UNKNOWN,
    WARNING,
    Report,
    collect_zfs,
    nvme_state,
    parse_nvme_log_page,
    plausible,
    reason,
    smartctl_drive,
    smartctl_source,
    temperature_state,
    worst,
)
from src.sysmanage_agent.collection.hardware_health_linux_storage import (
    collect_btrfs,
    collect_lvm_raid,
)
from src.sysmanage_agent.collection.hardware_health_privilege import escalates

SYS_NVME = "/sys/class/nvme"
SYS_BLOCK = "/sys/block"
SYS_HWMON = "/sys/class/hwmon"
SYS_EDAC = "/sys/devices/system/edac/mc"
PROC_MDSTAT = "/proc/mdstat"

# _IOWR('N', 0x41, struct nvme_passthru_cmd) -- the struct is 72 bytes.
NVME_IOCTL_ADMIN_CMD = 0xC0484E41
_GET_LOG_PAGE = 0x02
_SMART_LOG = 0x02
_LOG_BYTES = 512


class _NvmeAdminCmd(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """``struct nvme_passthru_cmd`` (linux/nvme_ioctl.h)."""

    _fields_ = [
        ("opcode", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("rsvd1", ctypes.c_uint16),
        ("nsid", ctypes.c_uint32),
        ("cdw2", ctypes.c_uint32),
        ("cdw3", ctypes.c_uint32),
        ("metadata", ctypes.c_uint64),
        ("addr", ctypes.c_uint64),
        ("metadata_len", ctypes.c_uint32),
        ("data_len", ctypes.c_uint32),
        ("cdw10", ctypes.c_uint32),
        ("cdw11", ctypes.c_uint32),
        ("cdw12", ctypes.c_uint32),
        ("cdw13", ctypes.c_uint32),
        ("cdw14", ctypes.c_uint32),
        ("cdw15", ctypes.c_uint32),
        ("timeout_ms", ctypes.c_uint32),
        ("result", ctypes.c_uint32),
    ]


def read_nvme_smart_log(device: str) -> bytes:
    """The SMART / health log of ``/dev/nvmeN`` (root).  Raises OSError."""
    buf = ctypes.create_string_buffer(_LOG_BYTES)
    cmd = _NvmeAdminCmd(
        opcode=_GET_LOG_PAGE,
        nsid=0xFFFFFFFF,
        addr=ctypes.cast(buf, ctypes.c_void_p).value,
        data_len=_LOG_BYTES,
        # number of dwords - 1 in the upper half, the log id in the lower
        cdw10=((_LOG_BYTES // 4 - 1) << 16) | _SMART_LOG,
        timeout_ms=5000,
    )
    # Linux only, and absent on Windows: importing it at the top made the
    # module (and every test that imports it) fail there.
    import fcntl  # pylint: disable=import-outside-toplevel

    fd = os.open(device, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd)
    finally:
        os.close(fd)
    return buf.raw


def _read(path: str) -> Optional[str]:
    """A sysfs / procfs file, or None -- some hwmon inputs raise ENXIO for an
    absent sensor (seen on two lab machines), which is "not there"."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _listdir(path: str) -> List[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# --- NVMe --------------------------------------------------------------------


def _nvme_through_smartctl(report: Report, run, read, controllers) -> None:
    """Unprivileged: the admin ioctl needs root, so read each controller's
    health log through ``smartctl`` (escalated by the agent's runner).  With
    no smartctl the drive is UNKNOWN as ``smartctl_absent`` -- the reason the
    server's smartmontools install offer (23.1 S6) reacts to -- instead of an
    unexplained "the health log could not be read"."""
    installed = run(["smartctl", "--version"])[0] != -1
    for ctrl in controllers:
        model = (read(f"{SYS_NVME}/{ctrl}/model") or "").strip() or None
        if installed:
            smartctl_drive(report, run, f"/dev/{ctrl}", ctrl, model)
        else:
            reasons = [reason("smartctl_absent")]
            report.add(DRIVE, ctrl, model, UNKNOWN, reasons, {}, None)
    if installed:
        report.source("nvme", RAN, "smartctl")
    else:
        report.source("nvme", SOURCE_FAILED, "not_privileged")


def collect_nvme(
    report: Report, read, listdir, smart_log=read_nvme_smart_log, run=None
):
    controllers = [c for c in listdir(SYS_NVME) if re.fullmatch(r"nvme\d+", c)]
    if not controllers:
        report.source("nvme", ABSENT)
        return
    if not _root() and run is not None:
        _nvme_through_smartctl(report, run, read, controllers)
        return
    if not _root():
        report.source("nvme", SOURCE_FAILED, "not_privileged")
    failures = []
    for ctrl in controllers:
        model = (read(f"{SYS_NVME}/{ctrl}/model") or "").strip() or None
        metrics: Dict[str, object] = {}
        if _root():
            try:
                metrics = parse_nvme_log_page(smart_log(f"/dev/{ctrl}"))
            except OSError as exc:
                failures.append(f"{ctrl}: {exc}")
        state, reasons = nvme_state(metrics)
        report.add(DRIVE, ctrl, model, state, reasons, metrics, "nvme")
    if _root():
        if failures:
            report.source("nvme", SOURCE_FAILED, "; ".join(failures))
        else:
            report.source("nvme", RAN)


# --- other drives through smartctl -------------------------------------------


def _sata_disks(read, listdir) -> List[str]:
    """Whole disks that are not NVMe, loop, ram, zram, md or device-mapper --
    nor paravirtual (virtio ``vd*``, Xen ``xvd*``): those have no SMART at
    all, and calling them "unknown, install smartmontools" would recommend
    a package that cannot help (the disk's health is the hypervisor's)."""
    disks = []
    for name in listdir(SYS_BLOCK):
        if re.match(r"(nvme|loop|ram|zram|md|dm-|sr|fd|vd|xvd)", name):
            continue
        if read(f"{SYS_BLOCK}/{name}/device/type") is None and not name.startswith(
            ("sd", "hd")
        ):
            continue
        disks.append(name)
    return disks


def collect_smartctl(report: Report, run, read, listdir) -> None:
    disks = _sata_disks(read, listdir)
    if not disks:
        return
    for disk in disks:
        model = (read(f"{SYS_BLOCK}/{disk}/device/model") or "").strip() or None
        smartctl_drive(report, run, f"/dev/{disk}", disk, model)
    smartctl_source(report, run)


# --- md software RAID ----------------------------------------------------------

_MD_LINE = re.compile(
    r"^(md\S+)\s*:\s*(\w+)\s+(?:\((\w+)\)\s+)?(raid\d+|linear)?\s*(.*)$"
)


def parse_mdstat(text: str) -> List[Dict[str, object]]:
    """``/proc/mdstat`` -> one entry per array."""
    arrays: List[Dict[str, object]] = []
    current: Optional[Dict[str, object]] = None
    for line in text.splitlines():
        match = _MD_LINE.match(line)
        if match:
            members = match.group(5).split()
            current = {
                "name": match.group(1),
                "activity": match.group(2),
                "level": match.group(4),
                "members": len(members),
                "failed_members": [m.split("[")[0] for m in members if "(F)" in m],
            }
            arrays.append(current)
            continue
        if current is None:
            continue
        slots = re.search(r"\[(\d+)/(\d+)\]\s+\[([U_]+)\]", line)
        if slots:
            current["raid_devices"] = int(slots.group(1))
            current["active_devices"] = int(slots.group(2))
            current["map"] = slots.group(3)
        rebuild = re.search(r"(recovery|resync|reshape|check)\s*=\s*([\d.]+)%", line)
        if rebuild:
            current["rebuild"] = rebuild.group(1)
            current["rebuild_percent"] = float(rebuild.group(2))
    return arrays


def md_state(array: Dict[str, object]):
    if array.get("activity") != "active":
        return FAILED, [reason("array_inactive", activity=array.get("activity"))]
    states, reasons = [OK], []
    raid, active = array.get("raid_devices"), array.get("active_devices")
    if isinstance(raid, int) and isinstance(active, int) and active < raid:
        states.append(WARNING)
        reasons.append(reason("array_degraded", active=active, total=raid))
    if array.get("failed_members"):
        states.append(WARNING)
        reasons.append(reason("failed_members", members=array["failed_members"]))
    if array.get("rebuild") == "recovery":
        reasons.append(reason("rebuilding", percent=array.get("rebuild_percent")))
    return worst(states), reasons


def collect_md(report: Report, read) -> None:
    text = read(PROC_MDSTAT)
    if text is None:
        report.source("mdstat", ABSENT)
        return
    report.source("mdstat", RAN)
    for array in parse_mdstat(text):
        state, reasons = md_state(array)
        metrics = {
            k: array.get(k)
            for k in ("level", "raid_devices", "active_devices", "rebuild_percent")
        }
        report.add(
            ARRAY, array["name"], array["name"], state, reasons, metrics, "mdstat"
        )


# --- hwmon temperatures --------------------------------------------------------


def _millidegrees(text: Optional[str]) -> Optional[float]:
    try:
        return int(text) / 1000.0 if text is not None else None
    except ValueError:
        return None


def _hwmon_sensor(report: Report, read, base: str, chip_name: str, sensor: str):
    """One ``tempN``: its reading against the limits the chip declares."""
    celsius = _millidegrees(read(f"{base}/{sensor}_input"))
    if not plausible(celsius):
        return
    high = _millidegrees(read(f"{base}/{sensor}_max"))
    critical = _millidegrees(read(f"{base}/{sensor}_crit"))
    label = read(f"{base}/{sensor}_label") or sensor
    state, reasons = temperature_state(celsius, high, critical)
    metrics = {
        "temperature_c": celsius,
        "high_c": high if plausible(high) else None,
        "critical_c": critical if plausible(critical) else None,
    }
    report.add(
        SENSOR, f"{chip_name}/{sensor}", f"{chip_name} {label}",
        state, reasons, metrics, "hwmon",
    )  # fmt: skip


def collect_hwmon(report: Report, read, listdir) -> None:
    chips = [c for c in listdir(SYS_HWMON) if c.startswith("hwmon")]
    if not chips:
        report.source("hwmon", ABSENT)
        return
    report.source("hwmon", RAN)
    for chip in chips:
        base = f"{SYS_HWMON}/{chip}"
        chip_name = read(f"{base}/name") or chip
        for entry in listdir(base):
            match = re.fullmatch(r"(temp\d+)_input", entry)
            if match:
                _hwmon_sensor(report, read, base, chip_name, match.group(1))


# --- EDAC memory errors --------------------------------------------------------


def edac_state(ce: Optional[int], ue: Optional[int]):
    """Uncorrected errors fail; corrected ones warn; unreadable is unknown."""
    if ce is None and ue is None:
        return UNKNOWN, [reason("memory_counts_unreadable")]
    if ue:
        return FAILED, [reason("memory_uncorrected", count=ue)]
    if ce:
        return WARNING, [reason("memory_corrected", count=ce)]
    return OK, []


def collect_edac(report: Report, read, listdir) -> None:
    controllers = [m for m in listdir(SYS_EDAC) if re.fullmatch(r"mc\d+", m)]
    if not controllers:
        report.source("edac", ABSENT)
        return
    report.source("edac", RAN)
    for ctrl in controllers:
        corrected = read(f"{SYS_EDAC}/{ctrl}/ce_count")
        uncorrected = read(f"{SYS_EDAC}/{ctrl}/ue_count")
        ce = int(corrected) if corrected and corrected.isdigit() else None
        ue = int(uncorrected) if uncorrected and uncorrected.isdigit() else None
        state, reasons = edac_state(ce, ue)
        metrics = {"corrected_errors": ce, "uncorrected_errors": ue}
        report.add(
            MEMORY, ctrl, f"memory controller {ctrl}", state, reasons, metrics, "edac"
        )


def collect(report: Report, _system, run, read=None, listdir=None) -> None:
    read = read or _read
    listdir = listdir or _listdir
    collect_nvme(report, read, listdir, run=run)
    collect_smartctl(report, run, read, listdir)
    collect_md(report, read)
    collect_zfs(report, run)
    collect_btrfs(report, run, read, root=True if escalates(run) else None)
    collect_lvm_raid(report, run)
    collect_hwmon(report, read, listdir)
    collect_edac(report, read, listdir)
    # pylint: disable-next=import-outside-toplevel  # machine checks (rasdaemon)
    from src.sysmanage_agent.collection import hardware_health_mce

    hardware_health_mce.collect_rasdaemon(report, run)
