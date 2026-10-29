# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Hardware health, read per OS (Phase 23.1 S1).

The fixtures are REAL recordings (2026-10-13): a FreeBSD box's NVMe log
(an aging Crucial P1 with 19 media errors), its healthy ZFS root, an OpenBSD
laptop's sensors, a MacBook Air, the x13s's storage cmdlets and thermal zones
(with the sentinel zones), and two failures CONSTRUCTED on lab machines --
a file-backed ZFS mirror (one side offlined; then one side corrupted and
scrubbed) and an md RAID1 on loop devices (one member failed; then
rebuilding).  Lines marked "constructed text" below are not recordings.
"""

# pylint: disable=unbalanced-tuple-unpacking  # (x,) = one-array mdstat

import json
import struct
from pathlib import Path

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_bsd as bsd
from src.sysmanage_agent.collection import hardware_health_linux as lnx
from src.sysmanage_agent.collection import hardware_health_macos as mac
from src.sysmanage_agent.collection import hardware_health_windows as win

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"


def _fixture(name):
    return (FIXTURES / name).read_text()


def _by_id(report):
    return {c["id"]: c for c in report.as_dict()["components"]}


def _sources(report):
    return {s["name"]: s for s in report.as_dict()["sources"]}


# --- core ------------------------------------------------------------------------


def test_worst_and_unknown_overall():
    assert hh.worst([hh.OK, hh.UNKNOWN, hh.WARNING]) == hh.WARNING
    assert hh.worst([hh.OK, hh.FAILED, hh.WARNING]) == hh.FAILED
    # nothing measured is never "ok"
    assert hh.Report().as_dict()["state"] == hh.UNKNOWN


def test_reasons_are_codes_not_sentences():
    # the server words them in the reader's language
    assert hh.reason("media_errors", count=3) == {"code": "media_errors", "count": 3}
    _state, reasons = hh.temperature_state(95.0, 80.0, 90.0)
    assert reasons == [{"code": "temperature_critical", "value": 95.0, "limit": 90.0}]


def test_metrics_never_carry_none():
    report = hh.Report()
    report.add(hh.DRIVE, "d", None, hh.OK, metrics={"a": 1, "b": None})
    component = report.as_dict()["components"][0]
    assert component["metrics"] == {"a": 1}
    assert component["name"] == "d"


def _smart_log(critical=0, kelvin=313, spare=100, used=3, media=0):
    raw = bytearray(512)
    raw[0] = critical
    struct.pack_into("<H", raw, 1, kelvin)
    raw[3], raw[4], raw[5] = spare, 10, used
    raw[160:176] = media.to_bytes(16, "little")
    raw[128:144] = (1234).to_bytes(16, "little")
    return bytes(raw)


def test_nvme_log_page_and_state():
    metrics = hh.parse_nvme_log_page(_smart_log())
    assert metrics["temperature_c"] == 39.9
    assert metrics["power_on_hours"] == 1234
    assert hh.nvme_state(metrics) == (hh.OK, [])
    # spare below threshold + read-only = failed, with both reasons
    state, reasons = hh.nvme_state(hh.parse_nvme_log_page(_smart_log(critical=0x09)))
    assert state == hh.FAILED and len(reasons) == 2
    state, _ = hh.nvme_state(hh.parse_nvme_log_page(_smart_log(critical=0x02)))
    assert state == hh.WARNING
    state, reasons = hh.nvme_state(hh.parse_nvme_log_page(_smart_log(used=95)))
    assert state == hh.WARNING
    assert reasons == [{"code": "endurance_used", "percent": 95}]
    assert hh.parse_nvme_log_page(b"short") == {}
    # not read at all: unknown, never ok
    assert hh.nvme_state({})[0] == hh.UNKNOWN


def test_nvmecontrol_logpage_recording():
    metrics = hh.parse_nvmecontrol_logpage(_fixture("freebsd_nvmecontrol_logpage2.txt"))
    assert metrics["critical_warning"] == 0
    assert metrics["temperature_c"] == 33.85
    assert metrics["percent_used"] == 5
    assert metrics["media_errors"] == 19
    state, reasons = hh.nvme_state(metrics)
    assert state == hh.WARNING
    assert reasons == [{"code": "media_errors", "count": 19}]


def test_smartctl_on_a_real_failing_drive():
    """RECORDED 2026-10-14: smartctl 7.5 on the FreeBSD box's aging Crucial P1
    (run from a fetched package, nothing installed).  The drive's own
    verdict is PASSED; its 19 media errors still make it a warning -- the
    same answer the native nvmecontrol path gives for the same drive."""
    recorded = json.loads(_fixture("freebsd_smartctl_nvme_media_errors.json"))
    assert recorded["smart_status"]["passed"] is True
    state, reasons, metrics = hh.parse_smartctl_json(recorded)
    assert state == hh.WARNING
    assert reasons == [{"code": "media_errors", "count": 19}]
    assert (metrics["percent_used"], metrics["power_on_hours"]) == (5, 16179)


def test_smartctl_json():
    ok = {"smart_status": {"passed": True}, "temperature": {"current": 31}}
    assert hh.parse_smartctl_json(ok)[0] == hh.OK
    failing = {
        "smart_status": {"passed": False},
        "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 48}}]},
    }
    state, reasons, metrics = hh.parse_smartctl_json(failing)
    assert state == hh.FAILED
    assert metrics["reallocated_sectors"] == 48
    assert reasons[0] == {"code": "smart_failed"}
    pending = {
        "smart_status": {"passed": True},
        "ata_smart_attributes": {"table": [{"id": 197, "raw": {"value": 8}}]},
    }
    assert hh.parse_smartctl_json(pending)[0] == hh.WARNING
    assert hh.parse_smartctl_json({})[0] == hh.UNKNOWN


def test_temperature_judged_only_by_declared_limits():
    assert hh.temperature_state(70.0, None, None) == (hh.OK, [])
    assert hh.temperature_state(85.0, 80.0, 90.0)[0] == hh.WARNING
    assert hh.temperature_state(95.0, 80.0, 90.0)[0] == hh.FAILED
    assert not hh.plausible(0.0) and not hh.plausible(-273.2)
    assert hh.plausible(36.0)


# --- ZFS (recordings, including the constructed failures) ------------------------


def test_zpool_online_recording():
    status = hh.parse_zpool_status(_fixture("freebsd_zpool_status_online.txt"))
    assert hh.zpool_state("ONLINE", status) == (hh.OK, [])


def test_zpool_degraded_recording():
    pools = hh.parse_zpool_list(_fixture("zfs_list_degraded.txt"))
    assert pools == {"sm23test": "DEGRADED", "zroot": "ONLINE"}
    status = hh.parse_zpool_status(_fixture("zfs_status_degraded.txt"))
    state, reasons = hh.zpool_state("DEGRADED", status)
    assert state == hh.WARNING
    assert any(
        r["code"] == "device_not_online"
        and r["device"].endswith("sm23zfs/b")
        and r["state"] == "OFFLINE"
        for r in reasons
    )


def test_zpool_repaired_checksums_are_not_healthy():
    # The pool says ONLINE -- but a member just had 211 checksum errors.
    status = hh.parse_zpool_status(_fixture("zfs_status_checksum_repaired.txt"))
    assert status["state"] == "ONLINE"
    assert status["cksum"] == 211
    state, reasons = hh.zpool_state("ONLINE", status)
    assert state == hh.WARNING
    assert reasons == [{"code": "device_errors", "read": 0, "write": 0, "cksum": 211}]


def test_zpool_faulted_and_data_errors():
    status = {"errors": "1 data errors, use '-v' for a list", "read": 0}
    assert hh.zpool_state("ONLINE", status)[0] == hh.FAILED
    assert hh.zpool_state("FAULTED", {})[0] == hh.FAILED
    assert hh._count("1.2K") == 1200  # pylint: disable=protected-access


def test_collect_zfs_absent_and_failed():
    report = hh.Report()
    hh.collect_zfs(report, lambda argv: (-1, ""))
    assert _sources(report)["zpool"]["status"] == hh.ABSENT
    report = hh.Report()
    hh.collect_zfs(report, lambda argv: (1, "permission denied"))
    assert _sources(report)["zpool"]["status"] == hh.SOURCE_FAILED


# --- Linux ---------------------------------------------------------------------------


def test_mdstat_recordings():
    assert lnx.parse_mdstat(_fixture("linux_mdstat_none.txt")) == []
    (clean,) = lnx.parse_mdstat(_fixture("linux_mdstat_clean.txt"))
    assert lnx.md_state(clean) == (hh.OK, [])
    (failed,) = lnx.parse_mdstat(_fixture("linux_mdstat_failed.txt"))
    state, reasons = lnx.md_state(failed)
    assert state == hh.WARNING
    assert {"code": "array_degraded", "active": 1, "total": 2} in reasons
    assert {"code": "failed_members", "members": ["loop11"]} in reasons
    (rebuilding,) = lnx.parse_mdstat(_fixture("linux_mdstat_recovery.txt"))
    state, reasons = lnx.md_state(rebuilding)
    assert state == hh.WARNING
    assert rebuilding["rebuild_percent"] == 0.1
    assert {"code": "rebuilding", "percent": 0.1} in reasons


def test_mdstat_inactive_array_failed():
    # constructed text: the format of an array that would not assemble
    (array,) = lnx.parse_mdstat("md0 : inactive sdb1[0](S)\n      1046528 blocks\n")
    assert lnx.md_state(array)[0] == hh.FAILED


def _sysfs(files):
    """read / listdir over a dict of path -> content (None = ENXIO)."""

    def read(path):
        return files.get(path)

    def listdir(path):
        prefix = path.rstrip("/") + "/"
        return sorted(
            {p[len(prefix) :].split("/")[0] for p in files if p.startswith(prefix)}
        )

    return read, listdir


def test_hwmon_limits_sentinels_and_enxio():
    read, listdir = _sysfs(
        {
            "/sys/class/hwmon/hwmon0/name": "coretemp",
            "/sys/class/hwmon/hwmon0/temp1_input": "97000",
            "/sys/class/hwmon/hwmon0/temp1_max": "95000",
            "/sys/class/hwmon/hwmon0/temp1_crit": "100000",
            "/sys/class/hwmon/hwmon0/temp1_label": "Package id 0",
            "/sys/class/hwmon/hwmon0/temp2_input": None,  # ENXIO, as recorded
            "/sys/class/hwmon/hwmon1/name": "acpitz",
            "/sys/class/hwmon/hwmon1/temp1_input": "53000",
            "/sys/class/hwmon/hwmon1/temp2_input": "0",  # sentinel
        }
    )
    report = hh.Report()
    lnx.collect_hwmon(report, read, listdir)
    components = _by_id(report)
    assert set(components) == {"coretemp/temp1", "acpitz/temp1"}
    package = components["coretemp/temp1"]
    assert package["state"] == hh.WARNING
    assert package["name"] == "coretemp Package id 0"
    assert components["acpitz/temp1"]["state"] == hh.OK


def test_edac_counts():
    read, listdir = _sysfs(
        {
            "/sys/devices/system/edac/mc/mc0/ce_count": "3",
            "/sys/devices/system/edac/mc/mc0/ue_count": "0",
            "/sys/devices/system/edac/mc/mc1/ce_count": "0",
            "/sys/devices/system/edac/mc/mc1/ue_count": "1",
        }
    )
    report = hh.Report()
    lnx.collect_edac(report, read, listdir)
    components = _by_id(report)
    assert components["mc0"]["state"] == hh.WARNING
    assert components["mc1"]["state"] == hh.FAILED
    report = hh.Report()
    lnx.collect_edac(report, *_sysfs({}))
    assert _sources(report)["edac"]["status"] == hh.ABSENT


def test_nvme_through_ioctl(monkeypatch):
    read, listdir = _sysfs({"/sys/class/nvme/nvme0/model": "Samsung SSD 990 PRO 4TB "})
    monkeypatch.setattr(lnx.os, "geteuid", lambda: 0, raising=False)
    report = hh.Report()
    lnx.collect_nvme(report, read, listdir, smart_log=lambda dev: _smart_log(media=2))
    drive = _by_id(report)["nvme0"]
    assert drive["state"] == hh.WARNING
    assert drive["name"] == "Samsung SSD 990 PRO 4TB"
    assert _sources(report)["nvme"]["status"] == hh.RAN


def test_nvme_unprivileged_is_unknown(monkeypatch):
    read, listdir = _sysfs({"/sys/class/nvme/nvme0/model": "Lexar SSD NM790 4TB"})
    monkeypatch.setattr(lnx.os, "geteuid", lambda: 1000, raising=False)
    report = hh.Report()
    lnx.collect_nvme(report, read, listdir)
    assert _by_id(report)["nvme0"]["state"] == hh.UNKNOWN
    assert _sources(report)["nvme"]["detail"] == "not_privileged"


def test_sata_without_smartctl_is_unknown():
    read, listdir = _sysfs(
        {
            "/sys/block/sda/device/model": "ST4000DM004",
            "/sys/block/loop0/x": "1",
            "/sys/block/vda/device/type": "0",  # virtio: no SMART, not a drive here
            "/sys/block/xvda/device/type": "0",
        }
    )
    report = hh.Report()
    lnx.collect_smartctl(report, lambda argv: (-1, ""), read, listdir)
    assert set(_by_id(report)) == {"sda"}
    drive = _by_id(report)["sda"]
    assert drive["state"] == hh.UNKNOWN
    assert drive["reasons"] == [{"code": "smartctl_absent"}]
    assert _sources(report)["smartctl"]["status"] == hh.ABSENT


# --- BSD ---------------------------------------------------------------------------


def test_freebsd_geom_disks_skip_nvme_and_empty_readers():
    disks = bsd.parse_geom_disks(_fixture("freebsd_geom_disk_list.txt"))
    assert [(d["name"], d["mediasize"]) for d in disks] == [
        ("nda0", 1000204886016),
        ("da0", 0),
    ]
    assert disks[1]["descr"] == "Generic- SD/MMC"
    calls = []

    def run(argv):
        calls.append(" ".join(argv))
        if argv[:2] == ["geom", "disk"]:
            return 0, _fixture("freebsd_geom_disk_list.txt")
        return -1, ""

    report = hh.Report()
    bsd.collect_freebsd_disks(report, run)
    # the lab box: NVMe is nvmecontrol's, the card reader is empty; and a
    # FreeBSD VM's virtio disk has no SMART
    vm = "Geom name: vtbd0\nProviders:\n1. Name: vtbd0\n   Mediasize: 21474836480 (20G)\n"  # constructed text
    assert bsd.parse_geom_disks(vm)[0]["name"] == "vtbd0"
    vm_report = hh.Report()
    bsd.collect_freebsd_disks(vm_report, _runner({"geom disk list": (0, vm)}))
    assert _by_id(vm_report) == {}
    assert _by_id(report) == {} and not any("smartctl" in c for c in calls)


def test_freebsd_sata_disk_through_smartctl():
    listing = "Geom name: ada0\nProviders:\n1. Name: ada0\n   Mediasize: 500107862016 (466G)\n   descr: Samsung SSD 860 EVO\n"  # constructed text
    smart = json.dumps({"smart_status": {"passed": True}})
    run = _runner(
        {
            "geom disk list": (0, listing),
            "smartctl -j -H -A /dev/ada0": (0, smart),
            "smartctl --version": (0, "smartctl 7.4"),
        }
    )
    report = hh.Report()
    bsd.collect_freebsd_disks(report, run)
    drive = _by_id(report)["ada0"]
    assert (drive["name"], drive["source"]) == ("Samsung SSD 860 EVO", "smartctl")
    assert _sources(report)["smartctl"]["status"] == hh.RAN
    absent = hh.Report()
    bsd.collect_freebsd_disks(absent, _runner({"geom disk list": (0, listing)}))
    assert _by_id(absent)["ada0"]["reasons"] == [{"code": "smartctl_absent"}]
    assert _sources(absent)["smartctl"]["status"] == hh.ABSENT


def _runner(answers):
    def run(argv):
        return answers.get(" ".join(argv), (-1, ""))

    return run


def test_freebsd_end_to_end_recordings():
    run = _runner(
        {
            "nvmecontrol devlist": (0, _fixture("freebsd_nvmecontrol_devlist.txt")),
            "nvmecontrol logpage -p 2 nvme0": (
                0,
                _fixture("freebsd_nvmecontrol_logpage2.txt"),
            ),
            "zpool list -H -o name,health": (0, _fixture("freebsd_zpool_list.txt")),
            "zpool status zroot": (0, _fixture("freebsd_zpool_status_online.txt")),
            "gmirror status -s": (
                1,
                "gmirror: Command 'status' not available; try 'load' first.",
            ),
            "graid status -s": (
                1,
                "graid: Command 'status' not available; try 'load' first.",
            ),
            "sysctl hw.acpi.thermal": (0, _fixture("freebsd_sysctl_acpi_thermal.txt")),
            "sysctl -q dev.cpu": (0, ""),
        }
    )
    result = hh.collect_hardware_health("FreeBSD", run)
    components = {c["id"]: c for c in result["components"]}
    assert result["state"] == hh.WARNING  # the aging drive
    assert components["nvme0"]["name"] == "CT1000P1SSD8"
    assert components["zroot"]["state"] == hh.OK
    zone = components["acpi/tz0"]
    assert zone["metrics"] == {"temperature_c": 40.1, "critical_c": 128.1}
    sources = {s["name"]: s for s in result["sources"]}
    assert sources["gmirror"]["status"] == hh.ABSENT
    assert sources["gmirror"]["detail"] == "class not loaded"


def test_geom_degraded():
    # constructed text in the documented `gmirror status -s` layout
    text = "mirror/gm0  DEGRADED  ada0 (ACTIVE)\nmirror/gm0  DEGRADED  ada1 (SYNCHRONIZING, 42%)\n"
    report = hh.Report()
    bsd.collect_geom(report, _runner({"gmirror status -s": (0, text)}), "gmirror")
    volume = _by_id(report)["mirror/gm0"]
    assert volume["state"] == hh.WARNING
    assert volume["metrics"]["members"] == 2


def test_openbsd_sensors_recording():
    report = hh.Report()
    run = _runner({"sysctl hw.sensors": (0, _fixture("openbsd_sysctl_hw_sensors.txt"))})
    bsd.collect_hw_sensors(report, run)
    components = _by_id(report)
    drive = components["nvme0"]
    assert drive["kind"] == hh.DRIVE and drive["state"] == hh.OK
    assert drive["metrics"] == {
        "temperature_c": 42.0,
        "percent_used": 1.0,
        "available_spare": 100.0,
    }
    assert components["cpu0/temp0"]["metrics"]["temperature_c"] == 53.0
    # batteries and frequencies the kernel calls OK are not components
    assert not any(c.startswith("acpibat") for c in components)


def test_openbsd_softraid_degraded():
    # constructed text in the hw.sensors softraid layout
    text = (
        "hw.sensors.softraid0.drive0=degraded (sd2), WARNING\n"
        "hw.sensors.acpibat0.watthour3=0.10 Wh (remaining capacity), CRITICAL\n"
    )
    report = hh.Report()
    bsd.collect_hw_sensors(report, _runner({"sysctl hw.sensors": (0, text)}))
    components = _by_id(report)
    assert components["softraid0"]["kind"] == hh.ARRAY
    assert components["softraid0"]["state"] == hh.WARNING
    assert components["acpibat0/watthour3"]["state"] == hh.FAILED


# --- Windows ---------------------------------------------------------------------------


def test_windows_recording():
    report = hh.Report()
    win.parse(json.loads(_fixture("windows_hw.json")), report)
    result = report.as_dict()
    disk = next(c for c in result["components"] if c["kind"] == hh.DRIVE)
    assert disk["state"] == hh.OK
    # empty reliability counters are not measured, never 0
    assert "read_errors" not in disk["metrics"]
    assert "power_on_hours" not in disk["metrics"]
    assert disk["metrics"]["temperature_c"] == 36
    zones = [c for c in result["components"] if c["kind"] == hh.SENSOR]
    # 38 zones recorded; the 0 / 2730 sentinels are dropped
    assert len(zones) == 33
    assert all(c["metrics"]["temperature_c"] > 1 for c in zones)


def test_windows_failures():
    data = {
        "disks": [
            {
                "id": "1",
                "name": "HDD",
                "health": "Unhealthy",
                "operational": ["Lost Communication"],
            }
        ],
        "virtual_disks": [
            {
                "id": "v",
                "name": "Pool",
                "health": "Warning",
                "operational": ["Degraded"],
            }
        ],
        "thermal_zones": [
            {"name": "ACPI\\TZ00_0", "current": 3832, "critical": 3780, "passive": 3680}
        ],
    }
    report = hh.Report()
    win.parse(data, report)
    components = _by_id(report)
    assert components["disk1"]["state"] == hh.FAILED
    assert components["v"]["state"] == hh.WARNING
    assert components["acpi/TZ00_0"]["state"] == hh.FAILED


def test_windows_collect_bad_output():
    report = hh.Report()
    win.collect(report, "Windows", lambda argv: (0, "not json"))
    assert _sources(report)["powershell storage"]["status"] == hh.SOURCE_FAILED


def test_windows_script_is_plain_text_never_encoded():
    """A base64-encoded PowerShell command is a malware tell: Microsoft
    Defender flagged the agent's installer in winget validation from 3.11
    on.  The script goes as one plain -Command argument."""
    seen = {}

    def run(argv):
        seen["argv"] = argv
        return 0, "{}"

    win.collect(hh.Report(), "Windows", run)
    assert seen["argv"] == [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        win.SCRIPT,
    ]
    assert not any("Encoded" in arg for arg in seen["argv"])


def test_windows_script_holds_no_double_quote():
    """Windows PowerShell 5.1 mangles double quotes inside a -Command
    argument; the script must keep to single quotes."""
    assert '"' not in win.SCRIPT


# --- macOS ------------------------------------------------------------------------------


def test_macos_recordings():
    run = _runner(
        {
            "diskutil list -plist physical": (
                0,
                _fixture("macos_diskutil_list_physical.plist"),
            ),
            "diskutil info -plist disk0": (
                0,
                _fixture("macos_diskutil_info_disk0.plist"),
            ),
            "pmset -g therm": (0, _fixture("macos_pmset_therm.txt")),
        }
    )
    result = hh.collect_hardware_health("Darwin", run)
    components = {c["id"]: c for c in result["components"]}
    assert components["disk0"]["state"] == hh.OK
    assert components["disk0"]["name"] == "APPLE SSD AP1024Q"
    assert components["thermal"]["state"] == hh.OK
    assert result["state"] == hh.OK


def test_macos_failing_and_throttled():
    comp = mac.disk_component({"DeviceIdentifier": "disk2", "SMARTStatus": "Failing"})
    assert comp["state"] == hh.FAILED
    assert mac.disk_component({"SMARTStatus": "Not Supported"})["state"] == hh.UNKNOWN
    # constructed text: the CPU_Speed_Limit block pmset prints when throttled
    state, reasons = mac.parse_pmset_therm(
        "CPU Power notify\n\tCPU_Speed_Limit \t= 62\n"
    )
    assert state == hh.WARNING
    assert reasons == [{"code": "cpu_speed_limited", "percent": 62}]


# --- the entry point ----------------------------------------------------------------------


def test_unknown_platform_and_never_raises(monkeypatch):
    result = hh.collect_hardware_health("Plan9", _runner({}))
    assert result["state"] == hh.UNKNOWN
    assert result["sources"][0]["status"] == hh.ABSENT

    def boom(*_args):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(bsd, "collect", boom)
    result = hh.collect_hardware_health("OpenBSD", _runner({}))
    assert result["sources"][-1] == {
        "name": "collector",
        "status": "failed",
        "detail": "kaboom",
    }
