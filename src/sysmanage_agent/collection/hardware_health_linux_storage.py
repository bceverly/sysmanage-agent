# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Linux hardware health (Phase 23.1): btrfs filesystems and LVM RAID volumes.

* btrfs ........ one ``pool`` per mounted btrfs filesystem: ``btrfs
                 filesystem show <mountpoint>`` (devices, MISSING ones) and
                 ``btrfs device stats <mountpoint>`` (per-device error
                 counters).  Root only: recorded on a real host, an
                 unprivileged ``btrfs filesystem show`` reports EVERY device
                 as ``size 0 ... MISSING`` on a perfectly healthy filesystem,
                 so without root the pools are ``unknown``, never judged.
* LVM RAID ..... ``lvs --reportformat json``: one ``array`` per RAID or
                 mirror LV (``vg/lv``); linear, striped, thin and other LVs
                 are not arrays and are ignored.

Behavior recorded on loop devices (btrfs-progs 6.17, LVM 2.03.31):

* a btrfs raid1 with one member gone mounts with ``-o degraded``; ``show``
  lists the member as ``path <missing disk> MISSING`` (older btrfs-progs
  print ``*** Some devices missing`` and omit the device instead -- both
  are handled).
* an LVM raid1 with one PV gone reports ``lv_health_status`` ``partial``.
  LVM's default ``activation_mode`` is ``degraded``, so the LV still
  activates and serves data from the surviving leg: like a degraded md
  array (``[U_]``) or a DEGRADED zpool, an ACTIVE partial LV is a WARNING.
  A partial LV that is NOT active is not serving data at all: FAILED.
* when the PV returns, the LV reports ``refresh needed`` (WARNING) until
  ``lvchange --refresh``; a ``--syncaction check`` that found differing
  legs reports ``mismatches exist`` (WARNING) with ``raid_mismatch_count``.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from src.sysmanage_agent.collection.hardware_health import (
    ABSENT,
    ARRAY,
    FAILED,
    OK,
    POOL,
    RAN,
    SOURCE_FAILED,
    UNKNOWN,
    WARNING,
    Report,
    reason,
    worst,
)

PROC_MOUNTS = "/proc/mounts"
BTRFS = "btrfs"
LVM = "lvm"
NOT_PRIVILEGED = "not_privileged"

# ``btrfs device stats`` counter -> the btrfs_device_errors parameter
_BTRFS_COUNTERS = {
    "write_io_errs": "write",
    "read_io_errs": "read",
    "flush_io_errs": "flush",
    "corruption_errs": "corruption",
    "generation_errs": "generation",
}
_BTRFS_STAT = re.compile(r"^\[(.+)\]\.(\w+)\s+(\d+)\s*$")
# ``devid 1 size 1.82TiB used 1.2TiB path /dev/sda``, parsed in linear steps.
# The old one-line pattern (``size\s+.*?\spath\s+(.+?)\s*$``) stacked
# overlapping lazy and greedy quantifiers that backtracked (Sonar S5852);
# _btrfs_device_fields keeps exactly what it captured.
_BTRFS_DEVICE_HEAD = re.compile(r"\s*devid\s+(\d+)\s+size\s")
_BTRFS_PATH_WORD = re.compile(r"\spath(?=\s)")
_BTRFS_LABEL = re.compile(r"^Label:\s+(?:'(.*)'|none)\s+uuid:\s+(\S+)")
_MISSING_DISK = "<missing disk>"

LVS_FIELDS = (
    "lv_name,vg_name,segtype,lv_health_status,sync_percent,"
    "raid_mismatch_count,lv_attr"
)
# raid1, raid4, raid5_ls/la/rs/ra/n, raid6_zr/nr/nc/..., raid10 -- and the
# old ``mirror`` type.  raid0 has no redundancy: not an array to judge.
_LVM_RAID = re.compile(r"(raid(10|1|4|5|6)(_\w+)?|mirror)")


def _root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# --- btrfs -------------------------------------------------------------------


def btrfs_mounts(text: str) -> List[str]:
    """``/proc/mounts`` -> one mountpoint per mounted btrfs device (subvolumes
    of one filesystem mount the same device more than once)."""
    seen, mountpoints = set(), []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] != "btrfs" or fields[0] in seen:
            continue
        seen.add(fields[0])
        # /proc/mounts escapes spaces and tabs as octal (\040, \011)
        mountpoints.append(
            re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[1])
        )
    return mountpoints


def parse_btrfs_show(text: str) -> Dict[str, object]:
    """``btrfs filesystem show <mountpoint>`` -> label, uuid, total device
    count, and the devices it lists (with their MISSING flag)."""
    show: Dict[str, object] = {"devices": [], "some_missing": False}
    for line in text.splitlines():
        label = _BTRFS_LABEL.match(line)
        if label:
            show["label"], show["uuid"] = label.group(1), label.group(2)
            continue
        total = re.search(r"Total devices\s+(\d+)", line)
        if total:
            show["total"] = int(total.group(1))
        elif "Some devices missing" in line:
            show["some_missing"] = True
        else:
            _btrfs_show_device(line, show["devices"])
    return show


def _btrfs_path_value(tail: str) -> Optional[str]:
    """``\\s+(.+?)\\s*$`` over ``tail`` (which starts with whitespace)."""
    value = tail.lstrip()
    if value:
        return value.rstrip()
    # all whitespace: \s+ gives one character back to the lazy group
    return tail[-1] if len(tail) >= 2 else None


def _btrfs_device_fields(line: str) -> Optional[Tuple[str, str]]:
    """(devid, path) as the old single pattern captured them, or None."""
    head = _BTRFS_DEVICE_HEAD.match(line)
    if not head:
        return None
    rest = line[head.end() :]
    run = len(rest) - len(rest.lstrip())  # what the greedy size\s+ also took
    pos = run
    while True:
        word = _BTRFS_PATH_WORD.search(rest, pos)
        if word is None:
            break
        value = _btrfs_path_value(rest[word.end() :])
        if value is not None:
            return head.group(1), value
        pos = word.start() + 1
    # Backtracking size\s+ by one character lets the last space of that run
    # be the \s before "path" (a device line with no size value).
    tail = rest[run + 4 :]
    if run and rest[run : run + 4] == "path" and tail[:1].isspace():
        value = _btrfs_path_value(tail)
        if value is not None:
            return head.group(1), value
    return None


def _btrfs_show_device(line: str, devices: List[Dict[str, object]]) -> None:
    fields = _btrfs_device_fields(line)
    if fields is None:
        return
    path, missing = fields[1], False
    if path.endswith(" MISSING"):
        path, missing = path[: -len(" MISSING")].strip(), True
    devid = int(fields[0])
    if path == _MISSING_DISK:
        path = f"devid {devid}"
    devices.append({"devid": devid, "path": path, "missing": missing})


def parse_btrfs_stats(text: str) -> Dict[str, Dict[str, int]]:
    """``btrfs device stats <mountpoint>`` -> {device: {write: n, ...}}."""
    stats: Dict[str, Dict[str, int]] = {}
    for line in text.splitlines():
        match = _BTRFS_STAT.match(line.strip())
        if match and match.group(2) in _BTRFS_COUNTERS:
            counters = stats.setdefault(match.group(1), {})
            counters[_BTRFS_COUNTERS[match.group(2)]] = int(match.group(3))
    return stats


def _btrfs_missing(show: Dict[str, object]) -> List[str]:
    """The devices a filesystem is missing: listed as MISSING, or (older
    btrfs-progs, ``*** Some devices missing``) not listed at all."""
    devices = show.get("devices") or []
    missing = [d["path"] for d in devices if d["missing"]]
    total = show.get("total")
    if isinstance(total, int) and len(devices) < total:
        listed = {d["devid"] for d in devices}
        unlisted = [n for n in range(1, total + 1) if n not in listed]
        missing += [f"devid {n}" for n in unlisted[: total - len(devices)]]
    if show.get("some_missing") and not missing:
        missing.append("unknown")
    return missing


def btrfs_state(
    show: Dict[str, object], stats: Dict[str, Dict[str, int]]
) -> Tuple[str, List[Dict[str, object]]]:
    """A btrfs filesystem's state from its devices and their error counters.

    The counters are cumulative since they were last reset (``btrfs device
    stats -z``), not since boot: an error from months ago still counts.  That
    is intended -- a nonzero counter stays a warning until an administrator
    has looked at it and reset it."""
    states, reasons = [OK], []
    missing = _btrfs_missing(show)
    for device in missing:
        states.append(FAILED)
        reasons.append(reason("device_not_online", device=device, state="missing"))
    for device, counters in stats.items():
        if any(counters.values()):
            if device == _MISSING_DISK and len(missing) == 1:
                device = missing[0]
            states.append(WARNING)
            reasons.append(
                reason(
                    "btrfs_device_errors",
                    device=device,
                    **{key: counters.get(key, 0) for key in _BTRFS_COUNTERS.values()},
                )
            )
    return worst(states), reasons


def _btrfs_metrics(mountpoint, show, stats) -> Dict[str, object]:
    metrics: Dict[str, object] = {
        "mountpoint": mountpoint,
        "total_devices": show.get("total"),
        "missing_devices": len(_btrfs_missing(show)) if show else None,
    }
    for key in _BTRFS_COUNTERS.values():
        metrics[f"{key}_errors"] = (
            sum(c.get(key, 0) for c in stats.values()) if stats else None
        )
    return metrics


def _btrfs_pool(report: Report, run, mountpoint: str, root: bool, seen: set):
    """One mounted filesystem; returns a failure detail, or None."""
    rc, out = run(["btrfs", "filesystem", "show", mountpoint])
    show = parse_btrfs_show(out) if rc == 0 else {}
    ident = str(show.get("uuid") or mountpoint)
    if ident in seen:
        return None
    seen.add(ident)
    name = show.get("label") or mountpoint
    if not root or not show.get("uuid"):
        # unprivileged, the device list is wrong (every device "MISSING")
        report.add(POOL, ident, name, UNKNOWN, [], {"mountpoint": mountpoint}, BTRFS)
        return None if not root else f"{mountpoint}: show rc={rc}"
    rc, out = run(["btrfs", "device", "stats", mountpoint])
    stats = parse_btrfs_stats(out) if rc == 0 else {}
    if not stats:
        report.add(POOL, ident, name, UNKNOWN, [], {"mountpoint": mountpoint}, BTRFS)
        return f"{mountpoint}: stats rc={rc}"
    state, reasons = btrfs_state(show, stats)
    metrics = _btrfs_metrics(mountpoint, show, stats)
    report.add(POOL, ident, name, state, reasons, metrics, BTRFS)
    return None


def _btrfs_unjudged(report: Report, mountpoints: List[str]) -> None:
    for mountpoint in mountpoints:
        report.add(POOL, mountpoint, mountpoint, UNKNOWN, [], {}, BTRFS)


def collect_btrfs(report: Report, run, read, root: Optional[bool] = None) -> None:
    """Every mounted btrfs filesystem.  Without btrfs-progs, or without root,
    the filesystems are ``unknown`` and the source says why."""
    root = _root() if root is None else root
    mountpoints = btrfs_mounts(read(PROC_MOUNTS) or "")
    if not mountpoints:
        report.source(BTRFS, ABSENT)
        return
    rc, _out = run(["btrfs", "--version"])
    if rc == -1:
        report.source(BTRFS, ABSENT, "btrfs-progs not installed")
        _btrfs_unjudged(report, mountpoints)
        return
    seen: set = set()
    failures = [_btrfs_pool(report, run, mp, root, seen) for mp in mountpoints]
    failures = [f for f in failures if f]
    if not root:
        report.source(BTRFS, SOURCE_FAILED, NOT_PRIVILEGED)
    elif failures:
        report.source(BTRFS, SOURCE_FAILED, "; ".join(failures))
    else:
        report.source(BTRFS, RAN)


# --- LVM RAID ----------------------------------------------------------------


def parse_lvs_json(text: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """``lvs --reportformat json`` -> (LVs, error log messages).  The output
    may carry stderr warnings around the JSON (the runner merges both).
    Raises ValueError when there is no JSON report at all."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON report")
    data, _end = json.JSONDecoder().raw_decode(text[start:])
    lvs: List[Dict[str, str]] = []
    for section in data.get("report") or []:
        lvs.extend(section.get("lv") or [])
    errors = [
        str(entry.get("log_message"))
        for entry in data.get("log") or []
        if entry.get("log_type") == "error"
    ]
    return lvs, errors


def is_lvm_raid(lv: Dict[str, str]) -> bool:
    return bool(_LVM_RAID.fullmatch(str(lv.get("segtype") or "")))


def _number(value) -> Optional[float]:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _lvm_health(health: str, active: bool) -> Tuple[str, List[Dict[str, object]]]:
    """``lv_health_status``: partial (a PV is missing) fails only when the LV
    is not serving data; refresh needed, mismatches exist and anything else
    LVM reports are warnings -- never ok."""
    if not health:
        return OK, []
    if health == "partial" and not active:
        return FAILED, [reason("array_state", state=health)]
    return WARNING, [reason("array_state", state=health)]


def lvm_state(lv: Dict[str, str]) -> Tuple[str, List[Dict[str, object]]]:
    attr = str(lv.get("lv_attr") or "")
    active = len(attr) > 4 and attr[4] == "a"
    health = str(lv.get("lv_health_status") or "").strip()
    state, reasons = _lvm_health(health, active)
    sync = _number(lv.get("sync_percent"))
    if sync is not None and sync < 100:
        state = worst([state, WARNING])
        reasons.append(reason("rebuilding", percent=sync))
    if not active and state == OK:
        # an inactive LV has no dm-raid status to read: nothing judged it
        return UNKNOWN, [reason("array_state", state="inactive")]
    return state, reasons


def _lvm_metrics(lv: Dict[str, str]) -> Dict[str, object]:
    mismatches = _number(lv.get("raid_mismatch_count"))
    return {
        "segtype": lv.get("segtype"),
        "health": str(lv.get("lv_health_status") or "").strip() or None,
        "sync_percent": _number(lv.get("sync_percent")),
        "mismatch_count": int(mismatches) if mismatches is not None else None,
        "attr": lv.get("lv_attr") or None,
    }


def collect_lvm_raid(report: Report, run) -> None:
    """Every RAID / mirror LV.  ``lvs`` fails unprivileged (it cannot take
    LVM's lock), which is a failed source, not "no arrays"."""
    rc, out = run(["lvs", "--reportformat", "json", "-o", LVS_FIELDS])
    if rc == -1:
        report.source(LVM, ABSENT)
        return
    try:
        lvs, errors = parse_lvs_json(out)
    except ValueError:
        report.source(LVM, SOURCE_FAILED, out.strip() or f"rc={rc}")
        return
    for lv in filter(is_lvm_raid, lvs):
        ident = f"{lv.get('vg_name')}/{lv.get('lv_name')}"
        state, reasons = lvm_state(lv)
        report.add(ARRAY, ident, ident, state, reasons, _lvm_metrics(lv), LVM)
    if rc != 0:
        detail = NOT_PRIVILEGED if "non-root" in out else "; ".join(errors)
        report.source(LVM, SOURCE_FAILED, detail or f"rc={rc}")
    else:
        report.source(LVM, RAN)
