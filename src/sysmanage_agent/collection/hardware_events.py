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
              filesystem errors, machine checks, EDAC, thermal trips --
              AND the journal of the storage daemons (``journalctl -f`` for
              smartd, zed and ``mdadm --monitor`` only, never the kernel
              facility, so no kernel line arrives twice): SMART failures and
              pending / uncorrectable sectors, ZFS faults, md array failures
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

import json
import logging
import os
import platform
import queue
import re
import selectors
import socket
import subprocess  # nosec B404
import threading
import xml.etree.ElementTree as ET  # nosec B405  # our own wevtutil output
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from src.i18n import _

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


_KMSG_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def parse_kmsg_record(record: str) -> str:
    """``/dev/kmsg`` gives ``prio,seq,usec,flags;message``: the message --
    with the kernel's ``\\xHH`` escapes undone.  It escapes every
    non-printable byte, and some drivers print two lines as ONE message (md:
    "Disk failure on loop1, disabling device." + "Operation continuing on 1
    devices." arrived as "...device.\\x0amd/raid1:..." on 2026-10-14)."""
    head, sep, message = record.partition(";")
    text = message if sep and "," in head else record
    return _KMSG_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text).strip()


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


# --- smartd, zed and mdadm --monitor, through the journal ------------------------

JOURNAL_IDENTIFIERS = ("smartd", "zed", "mdadm", "mdmonitor")

_SMARTD = (
    (THERMAL, re.compile(r"Temperature \d+ Celsius reached (critical )?limit")),
    (
        STORAGE,
        re.compile(
            r"FAILED SMART self-check|SMART Failure|Failed SMART (usage )?Attribute"
            # only the attributes that mean damage: Raw_Read_Error_Rate and
            # Seek_Error_Rate move routinely on Seagate drives, and every
            # match is an operating-system event
            r"|SMART Prefailure Attribute: \d+ (Reallocated_Sector_Ct"
            r"|Reallocated_Event_Count|Current_Pending_Sector"
            r"|Offline_Uncorrectable|Reported_Uncorrect|End-to-End_Error) changed"
            r"|Currently unreadable \(pending\) sectors|Offline uncorrectable sectors"
            r"|ATA error count increased|Self-Test Log error count increased"
            r"|Critical Warning \(0x[0-9a-fA-F]+\)"
        ),
    ),
)
# smartd's all-clear: "No more Currently unreadable (pending) sectors,
# warning condition reset after 1 email" -- the same words, good news.
_SMARTD_CLEAR = re.compile(r"\bNo more |warning condition reset")
_MDADM = re.compile(r"\b(Fail|FailSpare|DegradedArray|SparesMissing) event detected")
# zed's all-syslog.sh: "eid=N class=<last part of the event class> ...
# vdev_state=<NAME>"; history_event, config_sync, scrub_finish ... are not.
_ZED_PROBLEM_CLASSES = {
    "io",
    "checksum",
    "data",
    "probe_failure",
    "deadman",
    "open_failed",
    "corrupt_data",
    "no_replicas",
}
_ZED_BAD_STATES = {"OFFLINE", "REMOVED", "CANT_OPEN", "FAULTED", "DEGRADED", "UNAVAIL"}


def _smartd(message: str) -> Optional[str]:
    if _SMARTD_CLEAR.search(message):
        return None
    for category, pattern in _SMARTD:
        if pattern.search(message):
            return category
    return None


def _zed(message: str) -> Optional[str]:
    fields = {k: v.strip("'") for k, v in re.findall(r"(\w+)=('[^']*'|\S+)", message)}
    kind = fields.get("class", "").rsplit(".", 1)[-1]
    if kind == "statechange":
        return STORAGE if fields.get("vdev_state") in _ZED_BAD_STATES else None
    return STORAGE if kind in _ZED_PROBLEM_CLASSES else None


def _mdadm(message: str) -> Optional[str]:
    return STORAGE if _MDADM.search(message) else None


_DAEMONS = {"smartd": _smartd, "zed": _zed, "mdadm": _mdadm, "mdmonitor": _mdadm}


def classify_daemon_line(identifier: str, message: str) -> Optional[str]:
    """The category of a storage daemon's journal message, or None for one
    that is not a hardware problem (temperature drift, a finished self-test,
    a rebuild that completed, ZFS history)."""
    judge = _DAEMONS.get(identifier)
    return judge(message) if judge else None


def parse_journal_record(line: str) -> Optional[Tuple[str, str]]:
    """One ``journalctl -o json`` line -> (identifier, message).  journald
    writes a message that is not valid UTF-8 as an array of byte values."""
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    message = record.get("MESSAGE")
    if isinstance(message, list):
        message = bytes(b & 0xFF for b in message if isinstance(b, int))
        message = message.decode("utf-8", errors="replace")
    if not isinstance(message, str):
        return None
    return str(record.get("SYSLOG_IDENTIFIER") or ""), message.strip()


def journal_command() -> List[str]:
    """New entries only, from the storage daemons only (never the kernel's:
    those already come from ``/dev/kmsg``)."""
    command = ["journalctl", "-f", "-n", "0", "-o", "json", "-q"]
    for identifier in JOURNAL_IDENTIFIERS:
        command += ["-t", identifier]
    return command


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


def linux_journal(
    stopped: Callable[[], bool], command: Optional[List[str]] = None
) -> Iterator[Evidence]:
    """New smartd / zed / mdadm journal entries that are hardware problems;
    nothing at all where there is no ``journalctl`` (no systemd)."""
    argv = command or journal_command()
    try:
        # pylint: disable-next=consider-using-with  # closed in _end()
        proc = subprocess.Popen(  # nosec B603 B607
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        return
    try:
        for line in _pipe_lines(proc.stdout, stopped):
            parsed = parse_journal_record(line)
            category = classify_daemon_line(*parsed) if parsed else None
            if category:
                identifier, message = parsed
                if not message.startswith(f"{identifier}:"):
                    message = f"{identifier}: {message}"
                yield _evidence("journal", category, message)
        if not stopped():
            raise RuntimeError(f"journalctl exited ({proc.wait(timeout=5)})")
    finally:
        _end(proc)


def _pipe_lines(stream, stopped: Callable[[], bool]) -> Iterator[str]:
    """Whole lines from a pipe, waking every second to notice a stop."""
    pending = b""
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while not stopped():
            if not selector.select(timeout=1.0):
                continue
            chunk = os.read(stream.fileno(), 65536)
            if not chunk:
                return
            *lines, pending = (pending + chunk).split(b"\n")
            for line in lines:
                yield line.decode("utf-8", errors="replace")


def _end(proc) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if proc.stdout:
        proc.stdout.close()


class _Done:  # pylint: disable=too-few-public-methods
    """A reader of a merged source has ended (``error`` if it failed)."""

    def __init__(self, name: str, error: Optional[BaseException] = None):
        self.name, self.error = name, error


def _feed(name: str, reader: LineSource, stopped, lines: "queue.Queue") -> None:
    try:
        for event in reader(stopped):
            lines.put(event)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        lines.put(_Done(name, exc))
        return
    lines.put(_Done(name))


def merged(*sources: Tuple[str, LineSource]) -> LineSource:
    """Several sources as one: each reader on its own thread.  A reader that
    ends quietly (no journalctl) just ends; one that fails while others still
    run is logged and the rest carry on; when the last one ends with a
    failure, that failure is the merged source's, as for a single source."""

    def read(stopped: Callable[[], bool]) -> Iterator[Evidence]:
        lines: "queue.Queue" = queue.Queue()
        for name, reader in sources:
            threading.Thread(
                target=_feed, args=(name, reader, stopped, lines), daemon=True
            ).start()
        live = len(sources)
        while live and not stopped():
            try:
                item = lines.get(timeout=0.5)
            except queue.Empty:
                continue
            if not isinstance(item, _Done):
                yield item
                continue
            live -= 1
            _ended(item, live)

    return read


def _ended(done: _Done, live: int) -> None:
    if done.error is None:
        return
    if not live:
        raise done.error
    logger.warning(_("Hardware event source %s stopped: %s"), done.name, done.error)


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
        return "kernel", merged(("kernel", linux_kmsg), ("journal", linux_journal))
    if system == "FreeBSD":
        return "devd", freebsd_devd
    if system == "Windows":
        return "eventlog", windows_eventlog
    return None
