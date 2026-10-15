# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""smartd, zed and mdadm --monitor through the journal, merged sources, and
WHEA-Logger in the Windows event-log reader (Phase 23.1).

* ``linux_journal_mdadm.jsonl`` is a REAL recording (beast, 2026-10-14,
  ``journalctl -o json -t mdadm``, trimmed to the fields below): the
  ``mdadm --monitor`` of mdmonitor.service watching the md RAID1 test array
  -- NewArray, DegradedArray, RebuildStarted / RebuildFinished,
  DeviceDisappeared, and the shell's "sendmail: not found" on its stdout.
  Only DegradedArray may count.
* Every smartd and zed line, the other mdadm events, and the WHEA-Logger
  event are CONSTRUCTED TEXT: no lab machine runs smartd or zed, and the
  x13s has never logged a WHEA event.  They follow the format strings of
  smartd (smartmontools 7.x), zed's all-syslog.sh (``eid=N class=<subclass>
  pool='...' vdev=... vdev_state=<NAME>``) and mdadm's Monitor.c
  (``<Event> event detected on md device <dev>[, component device <dev>]``).
"""

# pylint: disable=protected-access

import asyncio
import json
import logging
import sys
import threading
from pathlib import Path

import pytest

from src.sysmanage_agent.collection import hardware_events as he
from src.sysmanage_agent.communication.hardware_event_loop import HardwareEventLoop

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"

SMARTD_FAILURES = [
    "Device: /dev/sda [SAT], FAILED SMART self-check. BACK UP DATA NOW!",
    "Device: /dev/sda [SAT], SMART Prefailure Attribute: 5 Reallocated_Sector_Ct"
    " changed from 100 to 99",
    "Device: /dev/sda [SAT], 8 Currently unreadable (pending) sectors",
    "Device: /dev/sda [SAT], 8 Offline uncorrectable sectors",
    "Device: /dev/sdb, SMART Failure: DATA CHANNEL IMPENDING FAILURE DATA ERROR"
    " RATE TOO HIGH",
    "Device: /dev/sda [SAT], ATA error count increased from 0 to 3",
    "Device: /dev/sda [SAT], Self-Test Log error count increased from 0 to 1",
    "Device: /dev/sda [SAT], Failed SMART usage Attribute: 194 Temperature_Celsius.",
    "Device: /dev/nvme0, Critical Warning (0x04): Reliability",
]
SMARTD_BENIGN = [
    # constructed text: routine on Seagate drives, not damage
    "Device: /dev/sda [SAT], SMART Prefailure Attribute: 1 Raw_Read_Error_Rate"
    " changed from 117 to 118",
    "Device: /dev/sda [SAT], SMART Prefailure Attribute: 7 Seek_Error_Rate"
    " changed from 88 to 87",
    "Device: /dev/sda [SAT], SMART Usage Attribute: 194 Temperature_Celsius"
    " changed from 64 to 63",
    "Device: /dev/sda [SAT], SMART Usage Attribute: 190 Airflow_Temperature_Cel"
    " changed from 66 to 65",
    "Device: /dev/sda [SAT], Temperature changed +2 Celsius to 38 Celsius"
    " (Min/Max 25/45)",
    "Device: /dev/sda [SAT], previous self-test completed without error",
    "Device: /dev/sda [SAT], No more Currently unreadable (pending) sectors,"
    " warning condition reset after 1 email",
    "Device: /dev/sda [SAT], opened",
    "Monitoring 2 ATA/SATA, 0 SCSI/SAS and 1 NVMe devices",
]
ZED_FAILURES = [
    f"eid=14 class=statechange pool='tank' vdev=sdb1 vdev_state={state}"
    for state in ("FAULTED", "DEGRADED", "REMOVED", "UNAVAIL")
] + [
    "eid=9 class=io pool='tank' vdev=sdb1 size=131072 offset=4194304 priority=0"
    " err=5 flags=0x180880",
    "eid=10 class=checksum pool='tank' vdev=sdb1 algorithm=fletcher4",
    "eid=11 class=data pool='tank' priority=0 err=52",
]
ZED_BENIGN = [
    "eid=3 class=history_event pool='tank'",
    "eid=4 class=config_sync pool='tank'",
    "eid=5 class=scrub_finish pool='tank'",
    "eid=20 class=statechange pool='tank' vdev=sdb1 vdev_state=ONLINE",
    'Invoking "all-syslog.sh" eid=3 pid=1234',
    'Finished "all-syslog.sh" eid=3 pid=1234 time=0.004s exit=0',
]
MDADM_FAILURES = [
    "Fail event detected on md device /dev/md0, component device /dev/sdb1",
    "FailSpare event detected on md device /dev/md0, component device /dev/sdc1",
    "SparesMissing event detected on md device /dev/md0",
]


def _journal():
    return (FIXTURES / "linux_journal_mdadm.jsonl").read_text("utf-8").splitlines()


# --- classification ----------------------------------------------------------------


def test_smartd_failures_and_benign_lines():
    assert [he.classify_daemon_line("smartd", l) for l in SMARTD_FAILURES] == [
        he.STORAGE
    ] * len(SMARTD_FAILURES)
    assert not [l for l in SMARTD_BENIGN if he.classify_daemon_line("smartd", l)]
    assert (
        he.classify_daemon_line(
            "smartd",
            "Device: /dev/sda [SAT], Temperature 61 Celsius reached limit of 60"
            " Celsius (Min/Max 24/61)",
        )
        == he.THERMAL
    )


def test_zed_failures_and_benign_lines():
    assert [he.classify_daemon_line("zed", l) for l in ZED_FAILURES] == [
        he.STORAGE
    ] * len(ZED_FAILURES)
    assert not [l for l in ZED_BENIGN if he.classify_daemon_line("zed", l)]


def test_mdadm_recording_only_the_degraded_array_counts():
    parsed = [he.parse_journal_record(line) for line in _journal()]
    assert len(parsed) == 7 and all(parsed)
    hits = [m for i, m in parsed if he.classify_daemon_line(i, m)]
    assert hits == ["mdadm: DegradedArray event detected on md device /dev/md127"]
    for line in MDADM_FAILURES:
        assert he.classify_daemon_line("mdadm", line) == he.STORAGE
        assert he.classify_daemon_line("mdmonitor", line) == he.STORAGE


def test_only_the_storage_daemons_are_judged():
    assert he.classify_daemon_line("kernel", SMARTD_FAILURES[0]) is None
    assert he.classify_daemon_line("sshd", MDADM_FAILURES[0]) is None


def test_journal_record_parsing():
    assert he.parse_journal_record("not json") is None
    assert he.parse_journal_record("[1, 2]") is None
    assert he.parse_journal_record('{"SYSLOG_IDENTIFIER": "zed"}') is None
    # journald writes a message that is not UTF-8 as its bytes
    raw = json.dumps({"SYSLOG_IDENTIFIER": "smartd", "MESSAGE": list(b"ok \xff")})
    assert he.parse_journal_record(raw) == ("smartd", "ok \ufffd")


def test_journal_command_never_asks_for_the_kernel():
    command = he.journal_command()
    assert command[:7] == ["journalctl", "-f", "-n", "0", "-o", "json", "-q"]
    identifiers = command[8::2]
    assert identifiers == ["smartd", "zed", "mdadm", "mdmonitor"]
    assert command[7::2] == ["-t"] * 4


# --- the journal reader ------------------------------------------------------------


# The journal reader waits on a subprocess pipe with select(), which Windows
# supports only on sockets; the reader is Linux-only (journalctl), so these two
# cannot run on the Windows CI leg.
LINUX_PIPES = pytest.mark.skipif(
    sys.platform == "win32", reason="select() on a pipe; journalctl is Linux-only"
)


def _cat(lines):
    """A stand-in for journalctl that prints ``lines`` and exits."""
    script = "import sys; sys.stdout.write(sys.argv[1])"
    return [sys.executable, "-c", script, "".join(f"{l}\n" for l in lines)]


@LINUX_PIPES
def test_journal_reader_yields_hardware_lines_then_reports_the_exit():
    zed = json.dumps({"SYSLOG_IDENTIFIER": "zed", "MESSAGE": ZED_FAILURES[0]})
    events = []
    with pytest.raises(RuntimeError, match="journalctl exited"):
        for event in he.linux_journal(lambda: False, command=_cat(_journal() + [zed])):
            events.append(event)
    assert [e["text"] for e in events] == [
        "mdadm: DegradedArray event detected on md device /dev/md127",
        f"zed: {ZED_FAILURES[0]}",
    ]
    assert {e["source"] for e in events} == {"journal"}


def test_no_journalctl_is_silent():
    assert not list(
        he.linux_journal(lambda: False, command=["/nonexistent/journalctl"])
    )


@LINUX_PIPES
def test_a_stop_ends_a_quiet_journal():
    stop = threading.Event()
    timer = threading.Timer(0.3, stop.set)
    timer.start()
    sleeper = [sys.executable, "-c", "import time; time.sleep(30)"]
    assert not list(he.linux_journal(stop.is_set, command=sleeper))
    timer.join()


# --- merged sources ----------------------------------------------------------------


def _reader(events, hold=True, error=None):
    def reader(stopped):
        yield from events
        if error:
            raise error
        while hold and not stopped():
            threading.Event().wait(0.05)

    return reader


def _ev(text, source="kernel"):
    return {"source": source, "category": he.STORAGE, "text": text}


def test_merged_yields_from_both_until_stopped():
    stop = threading.Event()
    read = he.merged(
        ("kernel", _reader([_ev("I/O error, dev sda")])),
        ("journal", _reader([_ev("mdadm: Fail event", "journal")])),
    )
    seen = []
    for event in read(stop.is_set):
        seen.append(event["text"])
        if len(seen) == 2:
            stop.set()
    assert sorted(seen) == ["I/O error, dev sda", "mdadm: Fail event"]


def test_merged_carries_on_when_one_fails(caplog):
    def late(stopped):
        threading.Event().wait(0.3)  # after the kernel reader has failed
        yield _ev("zed: class=io", "journal")
        while not stopped():
            threading.Event().wait(0.05)

    stop = threading.Event()
    read = he.merged(
        ("kernel", _reader([], hold=False, error=PermissionError("/dev/kmsg"))),
        ("journal", late),
    )
    with caplog.at_level(logging.WARNING):
        events = []
        for event in read(stop.is_set):
            events.append(event)
            stop.set()
    assert [e["text"] for e in events] == ["zed: class=io"]
    assert "kernel" in caplog.text and "/dev/kmsg" in caplog.text


def test_merged_ends_when_every_source_ends_quietly():
    quiet = he.merged(("journal", _reader([], hold=False)))
    assert not list(quiet(lambda: False))


def test_merged_raises_when_the_last_source_fails():
    read = he.merged(
        ("journal", _reader([], hold=False)),  # no journalctl: ends quietly
        ("kernel", _reader([], hold=False, error=PermissionError("/dev/kmsg"))),
    )
    with pytest.raises(PermissionError):
        list(read(lambda: False))


def test_linux_runs_the_kernel_log_and_the_journal():
    name, reader = he.source_for("Linux")
    assert name == "kernel"
    assert reader.__qualname__.startswith("merged")


def test_the_loop_sends_one_report_from_a_merged_source():
    sent = []

    async def send(evidence):
        sent.append(evidence)

    source = he.merged(
        ("kernel", _reader([_ev("Buffer I/O error on dev sdb")])),
        ("journal", _reader([_ev("smartd: FAILED SMART self-check", "journal")])),
    )
    loop = HardwareEventLoop(send, lambda: True, ("kernel", source), debounce=0.3)

    async def scenario():
        task = asyncio.create_task(loop.run())
        await asyncio.sleep(1.0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())
    assert len(sent) == 1
    assert {e["source"] for e in sent[0]} == {"kernel", "journal"}


# --- Windows: WHEA-Logger in the event-log reader ----------------------------------


def test_whea_logger_events_are_hardware_errors():
    whea = {"provider": "Microsoft-Windows-WHEA-Logger", "event_id": "19"}
    assert he.classify_windows_event({**whea, "level": "3"}) == he.MEMORY  # corrected
    assert he.classify_windows_event({**whea, "level": "2"}) == he.MEMORY
    assert he.classify_windows_event({**whea, "level": "1"}) == he.MEMORY  # fatal
    assert he.classify_windows_event({**whea, "level": "4"}) is None  # information
    assert "@Name='Microsoft-Windows-WHEA-Logger'" in he.windows_query(10)
