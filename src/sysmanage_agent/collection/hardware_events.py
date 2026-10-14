# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Hardware events as they happen (Phase 23.1 S3).

The periodic report (every 15 minutes, or on a state change, through
send-on-change) is the floor; this is the ceiling.  Where the operating
system already announces a hardware problem, the agent listens, and on a
match re-collects its hardware health and sends it AT ONCE with the matching
lines as evidence:

* Linux ..... the kernel log (``/dev/kmsg``, root): I/O and medium errors,
              NVMe timeouts and resets, ATA exceptions, md disk failures,
              filesystem errors, machine checks, EDAC, thermal trips
* FreeBSD ... ``devd``'s event socket: ZFS state changes and errors, CAM
              errors, GEOM mirror / raid events, ACPI thermal
* Windows ... the System event log, every 30 seconds, from the last record
              seen: disk, storport / stornvme / storahci, NTFS, WHEA-Logger
              (machine checks), Kernel-Power 41 (unexpected loss of power)

Other systems (macOS, OpenBSD, NetBSD) have no source here yet and keep the
periodic report.  Matching is pure functions of the text, tested against
recordings; each source is a thin reader that yields lines.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess  # nosec B404
import xml.etree.ElementTree as ET  # nosec B405  # our own wevtutil output
from typing import Callable, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

STORAGE = "storage"
THERMAL = "thermal"
MEMORY = "memory"
POWER = "power"

_LINUX_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    (
        STORAGE,
        re.compile(
            r"I/O error|Buffer I/O error|critical medium error|blk_update_request"
            r"|nvme\d+n?\d*: .*(timeout|reset|I/O \d+ QID|failed)"
            r"|ata\d+(\.\d+)?: .*(failed command|exception Emask|hard resetting)"
            r"|md/raid\d*:.*(Disk failure|Operation continuing on)"
            r"|md: .*kicking non-fresh|EXT4-fs error|XFS .*(I/O error|[Cc]orruption)"
            r"|BTRFS (error|critical|warning).*(corrupt|error)",
        ),
    ),
    (
        THERMAL,
        re.compile(
            r"[Tt]emperature above threshold|cpu clock throttled"
            r"|thermal.*(critical|shutdown|emergency)",
        ),
    ),
    (
        MEMORY,
        re.compile(r"[Mm]achine [Cc]heck|\bmce: |EDAC .*(CE|UE)|Hardware Error"),
    ),
)


def classify_kernel_line(line: str) -> Optional[str]:
    """The category of a kernel log message, or None for one that is not a
    hardware problem."""
    for category, pattern in _LINUX_PATTERNS:
        if pattern.search(line):
            return category
    return None


def parse_kmsg_record(record: str) -> str:
    """``/dev/kmsg`` gives ``prio,seq,usec,flags;message``: the message."""
    head, sep, message = record.partition(";")
    return message.strip() if sep and "," in head else record.strip()


# ZFS vdev_state: 2 OFFLINE, 3 REMOVED, 4 CANT_OPEN, 5 FAULTED, 6 DEGRADED
# are problems; 7 HEALTHY is a disk coming back (a statechange too).
_ZFS_BAD_VDEV_STATES = {"2", "3", "4", "5", "6"}
_ZFS_ERROR_REPORTS = re.compile(
    r"ereport\.fs\.zfs\.(io|checksum|data|probe_failure|device|deadman)"
)
# SCSI sense keys that are the medium or the hardware: 3 MEDIUM ERROR,
# 4 HARDWARE ERROR.  NOT 2 NOT READY with ASC 3A -- "medium not present",
# which an EMPTY card reader on the lab FreeBSD box sends every few seconds.
_BAD_SENSE_KEYS = {0x03, 0x04}
_CAM_CMD_TIMEOUT = 0x0B


def _cam_problem(fields: Dict[str, str]) -> bool:
    """A CAM error that is the device failing, not an empty slot."""
    sense = fields.get("scsi_sense", "").strip('"').split()
    if len(sense) >= 2:
        try:
            return int(sense[1], 16) & 0x0F in _BAD_SENSE_KEYS
        except ValueError:
            return False
    try:
        status = int(fields.get("cam_status", "0").strip('"'), 16)
    except ValueError:
        return False
    return status & 0x3F == _CAM_CMD_TIMEOUT


def _zfs(fields: Dict[str, str]) -> Optional[str]:
    kind = fields.get("type", "")
    if kind == "resource.fs.zfs.statechange":
        return STORAGE if fields.get("vdev_state") in _ZFS_BAD_VDEV_STATES else None
    return STORAGE if _ZFS_ERROR_REPORTS.search(kind) else None


def _cam(fields: Dict[str, str]) -> Optional[str]:
    return STORAGE if fields.get("type") == "error" and _cam_problem(fields) else None


def _geom(fields: Dict[str, str]) -> Optional[str]:
    return STORAGE if fields.get("subsystem") in ("MIRROR", "RAID") else None


def _acpi(fields: Dict[str, str]) -> Optional[str]:
    return THERMAL if fields.get("subsystem") == "Thermal" else None


_DEVD_SYSTEMS = {"ZFS": _zfs, "CAM": _cam, "GEOM": _geom, "ACPI": _acpi}


def classify_devd_line(line: str) -> Optional[str]:
    """FreeBSD devd: ``!system=ZFS subsystem=ZFS type=...`` and friends --
    classified against what devd really sends (recorded on the lab box)."""
    fields = {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', line)}
    judge = _DEVD_SYSTEMS.get(fields.get("system", ""))
    return judge(fields) if judge else None


# Windows: provider -> category (any level), and the levels that count.
_WINDOWS_PROVIDERS = {
    "disk": STORAGE,
    "storport": STORAGE,
    "stornvme": STORAGE,
    "storahci": STORAGE,
    "Ntfs": STORAGE,
    "Microsoft-Windows-Ntfs": STORAGE,
    "Microsoft-Windows-WHEA-Logger": MEMORY,
    "Microsoft-Windows-Kernel-Power": POWER,
}
_WINDOWS_LEVELS = {"1", "2", "3"}  # critical, error, warning
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# Element paths, built once (plain concatenation, not formatting).
_SYSTEM = _NS + "System"
_PROVIDER = _NS + "Provider"
_RECORD = _NS + "EventRecordID"
_EVENT_ID = _NS + "EventID"
_LEVEL = _NS + "Level"
_MESSAGE = _NS + "RenderingInfo/" + _NS + "Message"
_DATA = _NS + "EventData/" + _NS + "Data"


def parse_wevtutil_xml(text: str) -> List[Dict[str, str]]:
    """``wevtutil qe ... /f:RenderedXml`` (events back to back, no root)."""
    events = []
    try:
        root = ET.fromstring(f"<Events>{text.strip()}</Events>")  # nosec B314
    except ET.ParseError:
        return events
    for node in root:
        system = node.find(_SYSTEM)
        if system is None:
            continue
        provider = system.find(_PROVIDER)
        events.append(
            {
                "record": (system.findtext(_RECORD) or "").strip(),
                "provider": provider.get("Name", "") if provider is not None else "",
                "event_id": (system.findtext(_EVENT_ID) or "").strip(),
                "level": (system.findtext(_LEVEL) or "").strip(),
                "message": _event_text(node),
            }
        )
    return events


def _event_text(node) -> str:
    """The rendered message -- or, for an event id the provider's message
    table does not know (recorded on the x13s), the event's data fields."""
    message = node.findtext(_MESSAGE) or ""
    if not message.strip():
        message = " ".join(d.text or "" for d in node.findall(_DATA))
    return " ".join(message.split())


def classify_windows_event(event: Dict[str, str]) -> Optional[str]:
    category = _WINDOWS_PROVIDERS.get(event.get("provider", ""))
    if category is None:
        return None
    if category == POWER:
        # Kernel-Power 41: the system rebooted without cleanly shutting down
        return POWER if event.get("event_id") == "41" else None
    return category if event.get("level") in _WINDOWS_LEVELS else None


def windows_query(after_record: int) -> str:
    """The XPath for new hardware events after ``after_record``."""
    providers = " or ".join(f"@Name='{p}'" for p in _WINDOWS_PROVIDERS)
    return f"*[System[Provider[{providers}] and EventRecordID > {int(after_record)}]]"


# --- the readers -----------------------------------------------------------------

Evidence = Dict[str, str]
LineSource = Callable[[Callable[[], bool]], Iterator[Evidence]]


def _evidence(source: str, category: str, text: str) -> Evidence:
    return {"source": source, "category": category, "text": text[:500]}


def linux_kmsg(
    stopped: Callable[[], bool], path: str = "/dev/kmsg"
) -> Iterator[Evidence]:
    """New kernel messages that are hardware problems (blocking; root)."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        os.lseek(fd, 0, os.SEEK_END)  # only what happens from now on
        while not stopped():
            try:
                record = os.read(fd, 8192).decode("utf-8", errors="replace")
            except BlockingIOError:
                _sleep(1.0, stopped)
                continue
            except OSError:  # EPIPE: records were overwritten; carry on
                continue
            message = parse_kmsg_record(record)
            category = classify_kernel_line(message)
            if category:
                yield _evidence("kernel", category, message)
    finally:
        os.close(fd)


def freebsd_devd(
    stopped: Callable[[], bool], path: str = "/var/run/devd.seqpacket.pipe"
) -> Iterator[Evidence]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.settimeout(1.0)
    try:
        sock.connect(path)
        while not stopped():
            try:
                data = sock.recv(8192)
            except socket.timeout:
                continue
            if not data:
                return
            line = data.decode("utf-8", errors="replace").strip()
            category = classify_devd_line(line)
            if category:
                yield _evidence("devd", category, line)
    finally:
        sock.close()


def _wevtutil(args: List[str]) -> str:
    result = subprocess.run(  # nosec B603 B607
        ["wevtutil", *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.stdout if result.returncode == 0 else ""


def windows_eventlog(
    stopped: Callable[[], bool], run=_wevtutil, interval: float = 30.0
) -> Iterator[Evidence]:
    """New System-log hardware events, polled from the last record seen."""
    latest = parse_wevtutil_xml(
        run(["qe", "System", "/c:1", "/rd:true", "/f:RenderedXml"])
    )
    last = int(latest[0]["record"]) if latest and latest[0]["record"].isdigit() else 0
    while not stopped():
        _sleep(interval, stopped)
        events = parse_wevtutil_xml(
            run(
                ["qe", "System", f"/q:{windows_query(last)}", "/f:RenderedXml", "/c:50"]
            )
        )
        for event in events:
            if event["record"].isdigit():
                last = max(last, int(event["record"]))
            category = classify_windows_event(event)
            if category:
                text = f"{event['provider']} {event['event_id']}: {event['message']}"
                yield _evidence("eventlog", category, text)


def _sleep(seconds: float, stopped: Callable[[], bool]) -> None:
    """Sleep in short steps so a stop is noticed promptly."""
    import time  # pylint: disable=import-outside-toplevel

    end = time.monotonic() + seconds
    while not stopped() and time.monotonic() < end:
        time.sleep(min(0.5, end - time.monotonic()))


def source_for(system: Optional[str] = None) -> Optional[Tuple[str, LineSource]]:
    """This platform's event source, or None (the periodic report only)."""
    system = system or platform.system()
    if system == "Linux":
        return "kernel", linux_kmsg
    if system == "FreeBSD":
        return "devd", freebsd_devd
    if system == "Windows":
        return "eventlog", windows_eventlog
    return None
