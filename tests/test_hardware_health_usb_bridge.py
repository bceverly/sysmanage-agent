# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Drives behind an NVMe-to-USB bridge smartctl does not recognize.

nas read "Not judged" (2026-11-15): a Seagate One Touch SSD (USB ID
0bc2:ab73, a Realtek bridge) is not in smartctl's drive database, so smartctl
guessed ATA and read nothing, and the agent reported the drive unknown with
no reason at all.  ``-d sntrealtek`` reads it.  The fixtures are smartctl's
real output on nas, with serial numbers and identifiers removed."""

import json
from pathlib import Path

import pytest

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_linux as lnx

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"
UNREAD = (FIXTURES / "linux_smartctl_usb_bridge_unread.json").read_text()
REALTEK = (FIXTURES / "linux_smartctl_usb_sntrealtek.json").read_text()
PLAIN = "smartctl -j -H -A /dev/sde"


@pytest.fixture(autouse=True)
def _fresh_cache():
    hh._bridge_types.clear()  # pylint: disable=protected-access
    yield
    hh._bridge_types.clear()  # pylint: disable=protected-access


class Recorder:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, argv):
        self.calls.append(" ".join(argv))
        return self.answers.get(" ".join(argv), (2, UNREAD))


def _bridge(device_type):
    return f"smartctl -d {device_type} -j -H -A /dev/sde"


def _drive(report):
    return report.as_dict()["components"][0]


def test_an_unreadable_drive_says_why():
    state, reasons, metrics = hh.parse_smartctl_json(json.loads(UNREAD))
    assert (state, reasons, metrics) == (hh.UNKNOWN, [{"code": "smart_not_read"}], {})


def test_a_usb_drive_is_read_through_its_bridge():
    run = Recorder({_bridge("sntrealtek"): (0, REALTEK)})
    report = hh.Report()
    hh.smartctl_drive(report, run, "/dev/sde", "sde", "One Touch w/PW", usb=True)
    drive = _drive(report)
    assert drive["state"] == hh.OK
    assert drive["metrics"]["percent_used"] == 0
    assert run.calls == [PLAIN, _bridge("sntrealtek")]


def test_the_bridge_is_remembered_not_probed_again():
    run = Recorder({_bridge("sntasmedia"): (0, REALTEK)})
    hh.smartctl_drive(hh.Report(), run, "/dev/sde", "sde", "m", usb=True)
    run.calls.clear()
    report = hh.Report()
    hh.smartctl_drive(report, run, "/dev/sde", "sde", "m", usb=True)
    assert _drive(report)["state"] == hh.OK
    assert run.calls == [PLAIN, _bridge("sntasmedia")]


def test_no_bridge_reads_it_then_unknown_with_reason_and_no_reprobe():
    run = Recorder({})
    report = hh.Report()
    hh.smartctl_drive(report, run, "/dev/sde", "sde", "m", usb=True)
    assert _drive(report)["state"] == hh.UNKNOWN
    assert _drive(report)["reasons"] == [{"code": "smart_not_read"}]
    assert run.calls == [PLAIN] + [_bridge(t) for t in hh.USB_BRIDGE_TYPES]
    run.calls.clear()
    hh.smartctl_drive(hh.Report(), run, "/dev/sde", "sde", "m", usb=True)
    assert run.calls == [PLAIN]


def test_a_drive_not_on_usb_is_never_probed():
    run = Recorder({})
    hh.smartctl_drive(hh.Report(), run, "/dev/sde", "sde", "m")
    assert run.calls == [PLAIN]


def test_a_readable_usb_drive_needs_no_bridge():
    run = Recorder({PLAIN: (0, REALTEK)})
    hh.smartctl_drive(hh.Report(), run, "/dev/sde", "sde", "m", usb=True)
    assert run.calls == [PLAIN]


def test_linux_finds_usb_disks_from_sysfs():
    paths = {
        "/sys/block/sda": "/sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda",
        "/sys/block/sde": "/sys/devices/pci0000:00/0000:00:14.0/usb6/6-2/6-2:1.0/host10/target10:0:0/10:0:0:0/block/sde",
    }
    assert not lnx.usb_attached("sda", paths.get)
    assert lnx.usb_attached("sde", paths.get)

    sysfs = {"/sys/block/sda/device/model": "ST20000NM002C-3X",
             "/sys/block/sde/device/model": "One Touch w/PW"}  # fmt: skip
    run = Recorder({_bridge("sntrealtek"): (0, REALTEK),
                    "smartctl -j -H -A /dev/sda": (0, REALTEK),
                    "smartctl --version": (0, "smartctl 7.5")})  # fmt: skip
    report = hh.Report()
    lnx.collect_smartctl(report, run, sysfs.get, lambda _p: ["sda", "sde"], paths.get)
    states = {c["id"]: c["state"] for c in report.as_dict()["components"]}
    assert states == {"sda": hh.OK, "sde": hh.OK}
    assert not any(" -d " in call and "/dev/sda" in call for call in run.calls)
