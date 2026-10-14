# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Hardware events as they happen (Phase 23.1 S3).

Every fixture is a REAL recording (2026-10-14):

* devd on the lab FreeBSD box while a file-backed ZFS mirror had one side
  offlined and brought back -- and the box's EMPTY card reader (da0)
  reporting "medium not present" every few seconds, which must NOT count;
* the Linux kernel log on beast for a device-mapper error device and the md
  RAID1 member failed the day before, and 40 ordinary kernel lines;
* the x13s System log: a Kernel-General event, and a test "disk" error
  written with Write-EventLog (an event id with no message-table entry).

The classifier also met 68,000 real kernel lines from three machines with no
false positive (S3 notes in the ROADMAP).
"""

# pylint: disable=protected-access

import asyncio
from pathlib import Path

from src.sysmanage_agent.collection import hardware_events as he
from src.sysmanage_agent.communication.hardware_event_loop import (
    MAX_EVIDENCE,
    HardwareEventLoop,
)

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"


def _lines(name):
    return [
        line.strip()
        for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --- classification ---------------------------------------------------------------


def test_kernel_failures_and_ordinary_lines():
    failures = _lines("linux_kmsg_failures.txt")
    assert [he.classify_kernel_line(line) for line in failures] == [he.STORAGE] * 4
    assert not [
        l for l in _lines("linux_kmsg_benign.txt") if he.classify_kernel_line(l)
    ]
    assert (
        he.classify_kernel_line("mce: [Hardware Error]: CPU 0: Machine Check")
        == he.MEMORY
    )
    assert (
        he.classify_kernel_line(
            "CPU0: Core temperature above threshold, cpu clock throttled"
        )
        == he.THERMAL
    )


def test_kmsg_record_format():
    assert he.parse_kmsg_record("3,1234,5678901,-;Buffer I/O error on dev sda") == (
        "Buffer I/O error on dev sda"
    )
    assert he.parse_kmsg_record("no prefix at all") == "no prefix at all"
    # RECORDED 2026-10-14 (md RAID1 on loop devices, mdadm --fail): md prints
    # both lines as one message, and /dev/kmsg escapes the newline
    md = he.parse_kmsg_record(
        "2,1180,412345678,-;md/raid1:md100: Disk failure on loop1, disabling "
        "device.\\x0amd/raid1:md100: Operation continuing on 1 devices."
    )
    assert md.splitlines() == [
        "md/raid1:md100: Disk failure on loop1, disabling device.",
        "md/raid1:md100: Operation continuing on 1 devices.",
    ]
    assert he.classify_kernel_line(md) is not None


def test_devd_recording_only_the_failure_counts():
    lines = _lines("freebsd_devd_zfs_offline_online.txt")
    hits = [(he.classify_devd_line(l), l) for l in lines if he.classify_devd_line(l)]
    # one disk went OFFLINE (vdev_state=2); its return (7), the pool's
    # create / destroy / resilver and the empty card reader are not news
    assert len(hits) == 1
    assert hits[0][0] == he.STORAGE and "vdev_state=2" in hits[0][1]
    assert sum("system=CAM" in l for l in lines) == 4  # the card reader, ignored


def test_devd_real_device_errors():
    # constructed text in the recorded layout: sense key 3 (MEDIUM ERROR),
    # sense key 4 (HARDWARE ERROR), a command timeout with no sense data
    medium = '!system=CAM subsystem=periph type=error device=ada0 cam_status="0x4cc" scsi_sense="70 03 11 00"'
    hardware = '!system=CAM subsystem=periph type=error device=da1 cam_status="0x4cc" scsi_sense="70 04 44 00"'
    timeout = '!system=CAM subsystem=periph type=error device=ada1 cam_status="0x0b"'
    for line in (medium, hardware, timeout):
        assert he.classify_devd_line(line) == he.STORAGE
    zfs_io = "!system=ZFS subsystem=ZFS type=ereport.fs.zfs.io pool=tank"
    assert he.classify_devd_line(zfs_io) == he.STORAGE
    assert (
        he.classify_devd_line("!system=ACPI subsystem=Thermal type=\\_TZ_.TZ00")
        == he.THERMAL
    )
    assert he.classify_devd_line("!system=IFNET subsystem=em0 type=LINK_UP") is None


def test_windows_recordings():
    disk = he.parse_wevtutil_xml(
        (FIXTURES / "windows_event_disk_test.xml").read_text("utf-8")
    )
    assert disk[0]["provider"] == "disk" and disk[0]["level"] == "2"
    # no message-table entry: the event data is the text
    assert disk[0]["message"] == "SysManage 23.1 S3 test event -- not a real error"
    assert he.classify_windows_event(disk[0]) == he.STORAGE
    general = he.parse_wevtutil_xml(
        (FIXTURES / "windows_event_kernel_general.xml").read_text("utf-8")
    )
    assert general[0]["record"] == "22865"
    assert he.classify_windows_event(general[0]) is None
    assert he.parse_wevtutil_xml("not xml <<<") == []


def test_windows_power_and_levels():
    assert (
        he.classify_windows_event(
            {
                "provider": "Microsoft-Windows-Kernel-Power",
                "event_id": "41",
                "level": "1",
            }
        )
        == he.POWER
    )
    assert (
        he.classify_windows_event(
            {
                "provider": "Microsoft-Windows-Kernel-Power",
                "event_id": "109",
                "level": "4",
            }
        )
        is None
    )
    # an informational disk event is not a problem
    assert he.classify_windows_event({"provider": "disk", "level": "4"}) is None
    query = he.windows_query(22865)
    assert "EventRecordID > 22865" in query and "@Name='stornvme'" in query


def test_windows_poller_from_the_last_record():
    disk_xml = (FIXTURES / "windows_event_disk_test.xml").read_text("utf-8")
    general_xml = (FIXTURES / "windows_event_kernel_general.xml").read_text("utf-8")
    calls = []
    state = {"polls": 0}

    def run(args):
        calls.append(args)
        if "/c:1" in args:
            return general_xml  # the newest record when the poller starts
        state["polls"] += 1
        return disk_xml if state["polls"] == 1 else ""

    def stopped():
        return state["polls"] >= 2

    events = list(he.windows_eventlog(stopped, run=run, interval=0))
    assert [e["category"] for e in events] == [he.STORAGE]
    assert "disk 9999: SysManage" in events[0]["text"]
    queries = [a for a in calls if any(x.startswith("/q:") for x in a)]
    assert "EventRecordID > 22865" in queries[0][2]
    assert "EventRecordID > 22866" in queries[1][2]  # moved past what it saw


def test_kmsg_reader_reads_from_the_end(tmp_path):
    # a regular file stands in for /dev/kmsg: nothing before the open counts
    path = tmp_path / "kmsg"
    path.write_text("3,1,1,-;Buffer I/O error on dev sda, logical block 0\n")
    state = {"reads": 0}

    def stopped():
        state["reads"] += 1
        return state["reads"] > 3

    assert not list(he.linux_kmsg(stopped, path=str(path)))


def test_source_for():
    assert he.source_for("Linux")[0] == "kernel"
    assert he.source_for("FreeBSD")[0] == "devd"
    assert he.source_for("Windows")[0] == "eventlog"
    assert he.source_for("Darwin") is None


# --- the loop --------------------------------------------------------------------


def _evidence(text, category=he.STORAGE):
    return {"source": "kernel", "category": category, "text": text}


def _reader(events, hold=None):
    def reader(stopped):
        yield from events
        while hold is not None and not stopped():
            hold.wait(0.05)

    return reader


def test_a_burst_is_one_report_with_distinct_lines():
    sent = []

    async def send(evidence):
        sent.append(evidence)

    burst = [_evidence("Buffer I/O error on dev dm-1, logical block 0")] * 6
    burst.append(_evidence("Buffer I/O error on dev dm-1, logical block 1"))
    loop = HardwareEventLoop(
        send, lambda: True, ("kernel", _reader(burst)), debounce=0.2
    )

    async def scenario():
        task = asyncio.create_task(loop.run())
        await asyncio.sleep(0.6)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())
    assert len(sent) == 1
    assert [e["text"][-15:] for e in sent[0]] == ["logical block 0", "logical block 1"]


def test_a_storm_is_capped_and_rate_limited():
    sent = []

    async def send(evidence):
        sent.append(evidence)

    storm = [_evidence(f"I/O error, dev sda, sector {n}") for n in range(50)]
    loop = HardwareEventLoop(
        send, lambda: True, ("kernel", _reader(storm)), debounce=0.1, min_gap=10.0
    )

    async def scenario():
        task = asyncio.create_task(loop.run())
        await asyncio.sleep(0.5)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())
    assert len(sent) == 1 and len(sent[0]) == MAX_EVIDENCE


def test_an_unprivileged_agent_and_a_platform_without_a_source_do_nothing():
    sent = []

    async def send(evidence):
        sent.append(evidence)

    burst = [_evidence("Buffer I/O error on dev sda")]
    asyncio.run(
        HardwareEventLoop(send, lambda: False, ("kernel", _reader(burst))).run()
    )
    assert not sent


def test_a_source_that_fails_stops_the_loop_cleanly():
    sent = []

    async def send(evidence):
        sent.append(evidence)

    def broken(_stopped):
        raise PermissionError("Operation not permitted: /dev/kmsg")
        yield  # pylint: disable=unreachable

    asyncio.run(
        asyncio.wait_for(
            HardwareEventLoop(send, lambda: True, ("kernel", broken)).run(), timeout=5
        )
    )
    assert not sent
