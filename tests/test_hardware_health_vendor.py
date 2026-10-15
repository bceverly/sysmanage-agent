# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Vendor hardware RAID CLIs and the BMC (Phase 23.1).

No MegaRAID, Smart Array, Adaptec controller or BMC exists in the lab, so
EVERY fixture used here is constructed text: written from the vendors'
documented output formats (Broadcom StorCLI JSON, HPE ssacli and Microchip
arcconf text, the ipmitool man page's ``sdr elist`` / ``sel elist``
layouts), with made-up serials.  None of them is a recording.
"""

import json
from datetime import datetime
from pathlib import Path

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_vendor as vendor

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"
NOW = datetime(2026, 10, 14, 12, 0, 0)


def _fixture(name):
    return (FIXTURES / name).read_text()


def _runner(answers):
    calls = []

    def run(argv):
        calls.append(" ".join(argv))
        return answers.get(" ".join(argv), (-1, ""))

    run.calls = calls
    return run


def _collect(answers, system="Linux", exists=None, root=True):
    report = hh.Report()
    run = _runner(answers)
    vendor.collect(
        report,
        system,
        run,
        exists=exists or (lambda path: False),
        is_root=lambda: root,
        now=NOW,
    )
    result = report.as_dict()
    return (
        {c["id"]: c for c in result["components"]},
        {s["name"]: s for s in result["sources"]},
        run,
    )


def _codes(component):
    return [r["code"] for r in component["reasons"]]


# --- nothing installed ---------------------------------------------------------


def test_no_vendor_tools_reports_nothing():
    """Most hosts: no tool, no BMC -> no components and NO sources."""
    components, sources, run = _collect({})
    assert not components
    assert not sources
    # ipmitool is not even tried without a BMC device node
    assert not any(call.startswith("ipmitool") for call in run.calls)


# --- MegaRAID (storcli / perccli) ----------------------------------------------

_STORCLI = "storcli64 /call show all J"


def test_storcli_optimal():
    """Constructed text: StorCLI JSON, a RAID1 + global hot spare."""
    components, sources, _run = _collect(
        {_STORCLI: (0, _fixture("storcli_call_show_all_optimal.json"))}
    )
    assert sources == {"storcli": {"name": "storcli", "status": hh.RAN}}
    assert components["c0"]["kind"] == hh.SENSOR
    assert components["c0"]["state"] == hh.OK
    assert components["c0"]["metrics"]["cache_battery"] == "Optimal"
    assert components["c0/v0"]["kind"] == hh.ARRAY
    assert components["c0/v0"]["state"] == hh.OK
    assert components["c0/v0"]["metrics"]["members"] == 2
    for slot in ("c0/e252/s0", "c0/e252/s1", "c0/e252/s2"):
        assert components[slot]["kind"] == hh.DRIVE
        assert components[slot]["state"] == hh.OK
        assert components[slot]["source"] == "storcli"


def test_storcli_degraded_failed_rebuilding():
    """Constructed text: a degraded RAID1 rebuilding at 37 %, an offline
    RAID5 with a failed and an offlined member, a failed BBU, media errors
    and a predictive failure from ``/call/eall/sall show all J``."""
    components, sources, _run = _collect(
        {
            _STORCLI: (0, _fixture("storcli_call_show_all_degraded.json")),
            "storcli64 /call/eall/sall show all J": (
                0,
                _fixture("storcli_drives_show_all_degraded.json"),
            ),
            "storcli64 /call/eall/sall show rebuild J": (
                0,
                _fixture("storcli_rebuild.json"),
            ),
        }
    )
    assert sources["storcli"]["status"] == hh.RAN
    controller = components["c0"]
    assert controller["state"] == hh.FAILED
    assert controller["reasons"] == [
        {"code": "controller_status", "status": "Needs Attention"},
        {"code": "cache_battery", "status": "Failed"},
    ]
    degraded = components["c0/v0"]
    assert degraded["state"] == hh.WARNING
    assert {"code": "array_state", "state": "Dgrd"} in degraded["reasons"]
    assert {"code": "failed_members", "members": ["c0/e32/s1"]} in degraded["reasons"]
    assert {"code": "rebuilding", "percent": 37.0} in degraded["reasons"]
    offline = components["c0/v1"]
    assert offline["state"] == hh.FAILED
    assert {
        "code": "failed_members",
        "members": ["c0/e32/s3", "c0/e32/s4"],
    } in offline["reasons"]
    # an online drive with media errors is a warning, not a failed member
    assert components["c0/e32/s0"]["state"] == hh.WARNING
    assert components["c0/e32/s0"]["reasons"] == [{"code": "media_errors", "count": 12}]
    assert components["c0/e32/s0"]["metrics"]["other_errors"] == 3
    assert _codes(components["c0/e32/s2"]) == ["smart_failed"]
    assert components["c0/e32/s3"]["state"] == hh.FAILED
    assert components["c0/e32/s3"]["reasons"] == [
        {"code": "health_status", "status": "Failed"}
    ]
    assert components["c0/e32/s4"]["state"] == hh.WARNING
    assert _codes(components["c0/e32/s1"]) == ["health_status", "rebuilding"]


def test_storcli_without_detail_output_still_judges_states():
    """Constructed text: the detail and rebuild calls fail; drive states
    are still judged, and no rebuild percent is invented."""
    components, _sources, _run = _collect(
        {_STORCLI: (0, _fixture("storcli_call_show_all_degraded.json"))}
    )
    assert components["c0/e32/s0"]["state"] == hh.OK
    assert _codes(components["c0/e32/s1"]) == ["health_status"]
    assert "rebuilding" not in _codes(components["c0/v0"])


def test_perccli_shares_the_format_and_paths_are_tried():
    """Constructed text: perccli under /opt/MegaRAID, not on PATH."""
    components, sources, run = _collect(
        {
            "/opt/MegaRAID/perccli/perccli64 /call show all J": (
                0,
                _fixture("storcli_call_show_all_optimal.json"),
            )
        }
    )
    assert "storcli" not in sources
    assert sources["perccli"]["status"] == hh.RAN
    assert components["c0/v0"]["source"] == "perccli"
    assert run.calls[0] == _STORCLI


def test_storcli_no_controller_and_failures():
    """Constructed text: installed with no controller; garbage output; a
    controller whose command failed."""
    _components, sources, _run = _collect(
        {_STORCLI: (0, _fixture("storcli_no_controller.json"))}
    )
    assert sources["storcli"] == {
        "name": "storcli",
        "status": hh.RAN,
        "detail": "no controller",
    }
    _components, sources, _run = _collect({_STORCLI: (1, "Segmentation fault")})
    assert sources["storcli"]["status"] == hh.SOURCE_FAILED
    assert "Segmentation fault" in sources["storcli"]["detail"]
    failing = {
        "Controllers": [
            {"Command Status": {"Status": "Failure", "Description": "Un-supported"}}
        ]
    }
    components, sources, _run = _collect({_STORCLI: (0, json.dumps(failing))})
    assert sources["storcli"]["status"] == hh.SOURCE_FAILED
    assert sources["storcli"]["detail"] == "Un-supported"
    assert not components


def test_megaraid_direct_attached_drive_ids():
    assert vendor._megaraid_drive_id(1, "252:7") == "c1/e252/s7"
    assert vendor._megaraid_drive_id(0, " :3") == "c0/s3"
    assert vendor._megaraid_drive_id(0, "-:3") == "c0/s3"


# --- HPE Smart Array (ssacli) --------------------------------------------------

_SSACLI = "ssacli ctrl all show config detail"


def test_ssacli_ok():
    """Constructed text: a P440ar with one RAID1 logical drive.  The drive
    summary lines under Physical Drives / Mirror Group are not drives."""
    components, sources, _run = _collect(
        {_SSACLI: (0, _fixture("ssacli_config_detail_ok.txt"))}
    )
    assert sources["ssacli"]["status"] == hh.RAN
    assert set(components) == {"slot0", "slot0/ld1", "slot0/1I:1:1", "slot0/1I:1:2"}
    assert all(c["state"] == hh.OK for c in components.values())
    drive = components["slot0/1I:1:1"]
    assert drive["metrics"]["temperature_c"] == 31
    assert drive["metrics"]["model"] == "HP EG0300FCVBF"
    assert components["slot0/ld1"]["metrics"]["disk"] == "/dev/sda"


def test_ssacli_degraded_failed_rebuilding():
    """Constructed text: Interim Recovery Mode with a failed drive,
    Recovering at 62 % with a predictive failure, a failed logical drive,
    and a failed cache battery."""
    components, _sources, _run = _collect(
        {_SSACLI: (0, _fixture("ssacli_config_detail_degraded.txt"))}
    )
    controller = components["slot0"]
    assert controller["state"] == hh.FAILED
    assert controller["reasons"] == [
        {"code": "cache_battery", "status": "Failed (Replace Batteries)"}
    ]
    assert controller["metrics"]["cache_status"] == "Temporarily Disabled"
    ld1 = components["slot0/ld1"]
    assert ld1["state"] == hh.WARNING
    assert ld1["reasons"] == [
        {"code": "array_state", "state": "Interim Recovery Mode"},
        {"code": "failed_members", "members": ["slot0/1I:1:2"]},
    ]
    ld2 = components["slot0/ld2"]
    assert ld2["state"] == hh.WARNING
    assert {"code": "rebuilding", "percent": 62.0} in ld2["reasons"]
    assert {
        "code": "failed_members",
        "members": ["slot0/1I:1:3", "slot0/1I:1:4"],
    } in ld2["reasons"]
    assert components["slot0/ld3"]["state"] == hh.FAILED
    assert components["slot0/1I:1:2"]["state"] == hh.FAILED
    assert components["slot0/1I:1:3"]["state"] == hh.WARNING
    assert components["slot0/1I:1:3"]["reasons"] == [
        {"code": "health_status", "status": "Predictive Failure"}
    ]
    assert components["slot0/1I:1:4"]["state"] == hh.WARNING


def test_ssacli_failing():
    _components, sources, _run = _collect(
        {_SSACLI: (1, "Error: No controllers detected.")}
    )
    assert sources["ssacli"]["status"] == hh.SOURCE_FAILED
    assert "No controllers detected" in sources["ssacli"]["detail"]


# --- Microchip / Adaptec (arcconf) ---------------------------------------------

_ARCCONF = "arcconf getconfig 1 al"


def test_arcconf_optimal():
    """Constructed text: an ASR8805 with ZMM, one RAID1, an enclosure
    services device that is not a drive."""
    components, sources, _run = _collect(
        {_ARCCONF: (0, _fixture("arcconf_getconfig_ok.txt"))}
    )
    assert sources["arcconf"]["status"] == hh.RAN
    assert set(components) == {"c1", "c1/ld0", "c1/e0/s0", "c1/e0/s1"}
    assert all(c["state"] == hh.OK for c in components.values())
    assert components["c1"]["metrics"]["cache_battery"] == "ZMM Optimal"
    assert components["c1/e0/s0"]["metrics"]["smart_warnings"] == 0


def test_arcconf_degraded_failed_rebuilding_two_controllers():
    """Constructed text: a degraded RAID1 with a missing segment, a RAID5
    rebuilding at 45 %, a failed drive, a SMART-flagged drive, a failed
    battery; and "Controllers found: 2" asks for the second controller."""
    components, sources, run = _collect(
        {
            _ARCCONF: (0, _fixture("arcconf_getconfig_degraded.txt")),
            "arcconf getconfig 2 al": (0, _fixture("arcconf_getconfig_ok.txt")),
        }
    )
    assert sources["arcconf"]["status"] == hh.RAN
    assert "arcconf getconfig 2 al" in run.calls
    assert components["c1"]["state"] == hh.FAILED
    assert components["c1"]["reasons"] == [
        {"code": "cache_battery", "status": "Failed"}
    ]
    ld0 = components["c1/ld0"]
    assert ld0["state"] == hh.WARNING
    assert ld0["reasons"] == [
        {"code": "array_state", "state": "Degraded"},
        {"code": "failed_members", "members": ["Group 0, Segment 1"]},
    ]
    ld1 = components["c1/ld1"]
    assert ld1["state"] == hh.WARNING
    assert {"code": "rebuilding", "percent": 45.0} in ld1["reasons"]
    assert components["c1/e0/s1"]["state"] == hh.FAILED
    assert components["c1/e0/s2"]["reasons"] == [{"code": "smart_failed"}]
    assert components["c1/e0/s4"]["reasons"] == [
        {"code": "health_status", "status": "Rebuilding"}
    ]
    # the second controller, healthy
    assert components["c2"]["state"] == hh.OK
    assert components["c2/ld0"]["state"] == hh.OK


def test_arcconf_no_controller_and_failing():
    _components, sources, _run = _collect({_ARCCONF: (0, "Controllers found: 0\n")})
    assert sources["arcconf"]["detail"] == "no controller"
    _components, sources, _run = _collect(
        {_ARCCONF: (1, "Controllers found: 1\nInvalid controller number.")}
    )
    assert sources["arcconf"]["status"] == hh.SOURCE_FAILED


# --- the BMC (ipmitool) ----------------------------------------------------------

_SDR = "ipmitool sdr elist"
_SEL = "ipmitool sel elist"
_SEL_TIME = "ipmitool sel time get"


def _bmc(path):
    return path == "/dev/ipmi0"


def _ipmi(sel_fixture="ipmitool_sel_elist.txt", **kwargs):
    answers = {
        "ipmitool -V": (0, "ipmitool version 1.8.19"),
        _SDR: (0, _fixture("ipmitool_sdr_elist.txt")),
        _SEL: (0, _fixture(sel_fixture)),
        _SEL_TIME: (0, "10/14/2026 12:00:00"),
    }
    answers.update(kwargs.pop("answers", {}))
    return _collect(answers, exists=kwargs.pop("exists", _bmc), **kwargs)


def test_ipmitool_sensors():
    """Constructed text (ipmitool man page layout): thresholds crossed,
    a discrete power supply reading "Failure detected", ns sensors."""
    components, sources, _run = _ipmi()
    assert sources["ipmitool"]["status"] == hh.RAN
    cpu2 = components["bmc/CPU2 Temp"]
    assert cpu2["kind"] == hh.SENSOR
    assert cpu2["state"] == hh.FAILED
    assert cpu2["reasons"] == [
        {
            "code": "sensor_status",
            "sensor": "CPU2 Temp",
            "value": "98 degrees C",
            "status": "ucr",
        }
    ]
    assert cpu2["metrics"]["temperature_c"] == 98.0
    assert components["bmc/Peripheral Temp"]["state"] == hh.WARNING
    assert components["bmc/FAN2"]["state"] == hh.FAILED
    assert components["bmc/12V"]["state"] == hh.WARNING
    assert components["bmc/PS2 Status"]["state"] == hh.FAILED
    # ok temperature / fan / voltage / power supply sensors are reported
    for ok in ("bmc/CPU1 Temp", "bmc/FAN1", "bmc/Vcpu1", "bmc/PS1 Status"):
        assert components[ok]["state"] == hh.OK
    # no reading -> not measured, not reported; other ok discretes skipped
    for skipped in ("bmc/DIMMA1 Temp", "bmc/FAN3", "bmc/Watchdog2", "bmc/BMC Health"):
        assert skipped not in components


def test_sdr_capped_and_problems_first():
    lines = [f"Temp{i:03d} | {i:02X}h | ok | 3.1 | 40 degrees C" for i in range(100)]
    lines.append("Hot | FFh | cr | 3.1 | 99 degrees C")
    components = vendor.sdr_components("\n".join(lines))
    assert len(components) == vendor.MAX_BMC_SENSORS
    assert components[0]["id"] == "bmc/Hot"
    # a repeated name keeps both, the second with its sensor id
    twins = vendor.sdr_components(
        "Temp | 01h | ok | 3.1 | 40 degrees C\nTemp | 02h | ok | 3.2 | 41 degrees C"
    )
    assert [c["id"] for c in twins] == ["bmc/Temp", "bmc/Temp/02h"]


def test_sel_window_warning():
    """Constructed text: an uncorrectable ECC 2.5 days ago (outside the
    window), then within 24 h a correctable ECC and an AC loss (asserted;
    its deassertion is not another problem), and informational entries."""
    components, _sources, _run = _ipmi()
    sel = components["bmc/sel"]
    assert sel["name"] == "BMC event log"
    assert sel["state"] == hh.WARNING
    assert sel["reasons"] == [
        {
            "code": "sel_events",
            "count": 2,
            "last": "Power Supply AC lost (Power Supply #0xc9)",
        }
    ]
    assert sel["metrics"] == {"sel_entries": 8, "problem_events_24h": 2}


def test_sel_failure_in_window():
    """Constructed text: a power supply failure and a drive fault in the
    last 24 h -> failed."""
    components, _sources, _run = _ipmi("ipmitool_sel_elist_failure.txt")
    sel = components["bmc/sel"]
    assert sel["state"] == hh.FAILED
    assert sel["reasons"][0]["count"] == 3


def test_sel_all_outside_window_is_ok():
    """Constructed text: the same events judged a week later."""
    later = datetime(2026, 10, 21, 12, 0, 0)
    sel = vendor.sel_component(_fixture("ipmitool_sel_elist_failure.txt"), later)
    assert sel["state"] == hh.OK
    assert not sel["reasons"]
    assert sel["metrics"]["problem_events_24h"] == 0


def test_sel_uses_bmc_clock_and_falls_back_to_now():
    # the BMC clock unreadable -> the caller's now (NOW: 12:00 on 10/14)
    components, _sources, _run = _ipmi(answers={_SEL_TIME: (1, "")})
    assert components["bmc/sel"]["metrics"]["problem_events_24h"] == 2
    # the BMC's own clock is a week ahead -> nothing in its last 24 h
    components, _sources, _run = _ipmi(answers={_SEL_TIME: (0, "10/21/2026 12:00:00")})
    assert components["bmc/sel"]["state"] == hh.OK


def test_sel_two_digit_years_and_empty_log():
    assert vendor._sel_time("10/14/26", "08:00:00") == datetime(2026, 10, 14, 8)
    assert vendor._sel_time("Pre-Init", "0000000012") is None
    sel = vendor.sel_component("SEL has no entries", NOW)
    assert sel["state"] == hh.OK
    assert sel["metrics"]["sel_entries"] == 0


def test_event_severity():
    assert vendor.event_severity("Uncorrectable ECC") == hh.FAILED
    assert vendor.event_severity("Correctable ECC") == hh.WARNING
    assert vendor.event_severity("Upper Non-critical going high") == hh.WARNING
    assert vendor.event_severity("Upper Critical going high") == hh.FAILED
    assert vendor.event_severity("Presence detected") == hh.OK
    assert vendor.event_severity("Log area reset/cleared") == hh.OK


def test_ipmitool_not_root():
    components, sources, run = _ipmi(root=False)
    assert sources["ipmitool"] == {
        "name": "ipmitool",
        "status": hh.SOURCE_FAILED,
        "detail": "not_privileged",
    }
    assert not components
    assert _SDR not in run.calls


def test_ipmitool_absent_or_no_bmc_is_silent():
    # a BMC device but no ipmitool: nothing reported
    _components, sources, _run = _collect({}, exists=_bmc)
    assert not sources
    _components, sources, _run = _collect({}, exists=_bmc, root=False)
    assert not sources
    # ipmitool installed but no BMC device node: not run at all
    _components, sources, run = _collect(
        {"ipmitool -V": (0, "ipmitool version 1.8.19")}
    )
    assert not sources
    assert not run.calls or _SDR not in run.calls


def test_ipmitool_failing():
    components, sources, _run = _ipmi(
        answers={_SDR: (1, "Could not open device at /dev/ipmi0")}
    )
    assert sources["ipmitool"]["status"] == hh.SOURCE_FAILED
    assert "Could not open device" in sources["ipmitool"]["detail"]
    assert not components
    # sdr fine, sel failing: sensors kept, the source says what failed
    components, sources, _run = _ipmi(answers={_SEL: (1, "Get SEL Info failed")})
    assert sources["ipmitool"]["status"] == hh.SOURCE_FAILED
    assert "bmc/CPU2 Temp" in components
    assert "bmc/sel" not in components


def test_ipmitool_freebsd_and_windows():
    def freebsd_dev(path):
        return path == "/dev/ipmi"

    components, sources, _run = _ipmi(system="FreeBSD", exists=freebsd_dev)
    assert sources["ipmitool"]["status"] == hh.RAN
    assert "bmc/sel" in components
    # Windows: no device node; the installed tool is the test, no root check
    components, sources, _run = _ipmi(system="Windows", root=False)
    assert sources["ipmitool"]["status"] == hh.RAN
    _components, sources, _run = _collect({}, system="Windows", root=False)
    assert not sources


# --- one collector failing never stops the others --------------------------------


def test_a_crashing_parser_is_one_failed_source(monkeypatch):
    def boom(_text):
        raise ValueError("unexpected layout")

    monkeypatch.setattr(vendor, "ssacli_components", boom)
    components, sources, _run = _collect(
        {
            _SSACLI: (0, _fixture("ssacli_config_detail_ok.txt")),
            _ARCCONF: (0, _fixture("arcconf_getconfig_ok.txt")),
        }
    )
    assert sources["ssacli"]["status"] == hh.SOURCE_FAILED
    assert sources["ssacli"]["detail"] == "unexpected layout"
    assert sources["arcconf"]["status"] == hh.RAN
    assert "c1/ld0" in components


def test_dispatcher_runs_vendor_after_os(monkeypatch):
    """collect_hardware_health calls the vendor module on Linux, FreeBSD and
    Windows only, after the OS module."""
    seen = []
    monkeypatch.setattr(
        vendor, "collect", lambda report, system, run: seen.append(system)
    )
    for system in ("Windows", "OpenBSD", "Darwin"):
        hh.collect_hardware_health(system, _runner({}))
    assert seen == ["Windows"]
