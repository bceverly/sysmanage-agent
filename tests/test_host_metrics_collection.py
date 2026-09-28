# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Host metrics for the built-in graphs (Phase 21.5).

The property under test: a number the agent could not read is ABSENT, never
0 -- a chart would draw a missing reading as a real one -- and "the fullest
disk" means a persistent, writable local disk, not a squashfs snap image that
is always 100% full.
"""

import asyncio
from collections import namedtuple
from unittest.mock import AsyncMock, Mock, patch

from src.sysmanage_agent.collection import host_metrics_collection as hm
from src.sysmanage_agent.communication.data_collector import DataCollector

Part = namedtuple("Part", "device mountpoint fstype opts")
Usage = namedtuple("Usage", "total used free percent")
Swap = namedtuple("Swap", "total used free percent sin sout")
Mem = namedtuple("Mem", "total available percent used free")

PSUTIL = "src.sysmanage_agent.collection.host_metrics_collection.psutil"

PARTS = [
    Part("/dev/sda2", "/", "ext4", "rw,relatime"),
    Part("/dev/sdb1", "/var", "xfs", "rw"),
    Part("/dev/loop3", "/snap/core22/1380", "squashfs", "ro,nodev"),
    Part("tmpfs", "/run", "tmpfs", "rw"),
    Part("/dev/disk1s1", "/System/Volumes/Recovery", "apfs", "ro,local"),
]
USAGE = {
    "/": Usage(100, 40, 60, 40.0),
    "/var": Usage(100, 91, 9, 91.4567),
    "/snap/core22/1380": Usage(100, 100, 0, 100.0),
    "/run": Usage(100, 99, 1, 99.0),
    "/System/Volumes/Recovery": Usage(100, 98, 2, 98.0),
}


def _psutil(mock, swap_total=1024):
    mock.cpu_percent.return_value = 12.345
    mock.getloadavg.return_value = (1.5, 1.0, 0.5)
    mock.virtual_memory.return_value = Mem(100, 40, 60.0, 60, 40)
    mock.swap_memory.return_value = Swap(swap_total, 0, swap_total, 3.0, 0, 0)
    mock.disk_partitions.return_value = PARTS
    mock.disk_usage.side_effect = lambda path: USAGE[path]


def test_collects_the_five_series():
    with patch(PSUTIL) as mock:
        _psutil(mock)
        payload = hm.HostMetricsCollector().collect()
    assert payload["metrics"] == {
        hm.CPU_PERCENT: 12.35,
        hm.MEMORY_USED_PERCENT: 60.0,
        hm.SWAP_USED_PERCENT: 3.0,
        hm.LOAD_1M: 1.5,
        hm.DISK_USED_PERCENT_MAX: 91.46,
    }
    assert payload["collected_at"]


def test_fullest_disk_ignores_images_memory_and_read_only_mounts():
    # squashfs (100%), tmpfs (99%) and the read-only recovery volume (98%)
    # would all "win" if counted; /var at 91% is the real answer.
    with patch(PSUTIL) as mock:
        _psutil(mock)
        payload = hm.HostMetricsCollector().collect()
    assert payload["metrics"][hm.DISK_USED_PERCENT_MAX] == 91.46


def test_no_swap_is_absent_not_zero():
    with patch(PSUTIL) as mock:
        _psutil(mock, swap_total=0)
        payload = hm.HostMetricsCollector().collect()
    assert hm.SWAP_USED_PERCENT not in payload["metrics"]


def test_an_unreadable_metric_is_absent_and_the_rest_still_report():
    with patch(PSUTIL) as mock:
        _psutil(mock)
        mock.getloadavg.side_effect = OSError("not supported")
        mock.virtual_memory.side_effect = RuntimeError("boom")
        payload = hm.HostMetricsCollector().collect()
    assert hm.LOAD_1M not in payload["metrics"]
    assert hm.MEMORY_USED_PERCENT not in payload["metrics"]
    assert payload["metrics"][hm.CPU_PERCENT] == 12.35


def test_a_disk_that_cannot_be_measured_is_skipped():
    with patch(PSUTIL) as mock:
        _psutil(mock)

        def usage(path):
            if path == "/var":
                raise PermissionError(path)
            return USAGE[path]

        mock.disk_usage.side_effect = usage
        payload = hm.HostMetricsCollector().collect()
    assert payload["metrics"][hm.DISK_USED_PERCENT_MAX] == 40.0


def test_no_measurable_disk_means_no_disk_series():
    with patch(PSUTIL) as mock:
        _psutil(mock)
        mock.disk_partitions.return_value = [PARTS[2], PARTS[3]]
        payload = hm.HostMetricsCollector().collect()
    assert hm.DISK_USED_PERCENT_MAX not in payload["metrics"]


def test_cpu_is_primed_so_the_first_read_is_an_interval_mean():
    with patch(PSUTIL) as mock:
        _psutil(mock)
        collector = hm.HostMetricsCollector()
        assert mock.cpu_percent.call_count == 1  # the priming call
        collector.collect()
    # Never blocking: every call asks for "since last call", not a sleep.
    for call in mock.cpu_percent.call_args_list:
        assert call.kwargs == {"interval": None}


# -- the sender (DataCollectorSendersMixin._send_host_metrics_update) --------


def _collector(approved=True):
    agent = Mock()
    approval = Mock(host_id="host-1") if approved else None
    agent.registration_manager.get_host_approval_from_db.return_value = approval
    agent.create_message.side_effect = lambda kind, data: {"type": kind, "data": data}
    agent.send_message = AsyncMock(return_value=True)
    with patch(PSUTIL) as mock:
        _psutil(mock)
        dc = DataCollector(agent)
    dc.host_metrics_collector = Mock()
    dc.host_metrics_collector.collect.return_value = {
        "collected_at": "2026-09-28T12:00:00+00:00",
        "metrics": {hm.CPU_PERCENT: 5.0},
    }
    return dc, agent


def test_sender_sends_host_metrics_with_the_host_id():
    dc, agent = _collector()
    asyncio.run(dc._send_host_metrics_update())  # pylint: disable=protected-access
    message = agent.send_message.await_args.args[0]
    assert message["type"] == "host_metrics"
    assert message["data"]["host_id"] == "host-1"
    assert message["data"]["metrics"] == {hm.CPU_PERCENT: 5.0}


def test_sender_does_nothing_before_approval():
    dc, agent = _collector(approved=False)
    asyncio.run(dc._send_host_metrics_update())  # pylint: disable=protected-access
    agent.send_message.assert_not_awaited()
    dc.host_metrics_collector.collect.assert_not_called()
