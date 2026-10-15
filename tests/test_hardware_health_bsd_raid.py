# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""BSD RAID volumes and NetBSD sensors (Phase 23.1): bioctl, envstat, raidctl.

REAL recordings (2026-10-14, OpenBSD 7.9 on the t480 laptop, read-only):
``sysctl hw.sensors`` (``openbsd_sysctl_hw_sensors.txt``, no softraid volume
configured), ``bioctl softraid0`` as root (empty output, exit 0: softraid0
attaches with no volume) and unprivileged
(``openbsd_bioctl_softraid0_unprivileged.txt``).

CONSTRUCTED text (no spare disks on the t480, and the NetBSD VM is down):
every ``openbsd_bioctl_*`` volume fixture and ``netbsd_bioctl_mfi0_show.txt``
were generated with the exact printf formats of bio_inq() in OpenBSD
sbin/bioctl/bioctl.c and bio_show_volumes()/bio_show_disks() in NetBSD
sbin/bioctl/bioctl.c, with the BIOC_S* strings of sys/dev/biovar.h;
``netbsd_raidctl_s_*`` follow the raidctl(8) EXAMPLES and
rf_get_device_status() in sbin/raidctl/raidctl.c; ``netbsd_envstat_x.xml``
is a proplib XML plist with the keys and units sysmon_envsys(9) externalizes
(micro-kelvin temperatures, unsigned numbers in hex).
"""

# pylint: disable=unbalanced-tuple-unpacking  # (volume,) = one-volume output

from pathlib import Path

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_bsd as bsd
from src.sysmanage_agent.collection import hardware_health_bsd_raid as raid

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"


def _fixture(name):
    return (FIXTURES / name).read_text()


def _runner(answers):
    calls = []

    def run(argv):
        calls.append(" ".join(argv))
        return answers.get(" ".join(argv), (-1, ""))

    run.calls = calls
    return run


def _by_id(report):
    return {c["id"]: c for c in report.as_dict()["components"]}


def _sources(report):
    return {s["name"]: s for s in report.as_dict()["sources"]}


def _codes(component):
    return [r["code"] for r in component["reasons"]]


_SOFTRAID_SENSOR = "hw.sensors.softraid0.drive0=online (sd3), OK\n"


# --- OpenBSD bioctl ---------------------------------------------------------------


def test_openbsd_crypto_single_chunk_online_is_ok():
    # constructed text: a CRYPTO volume has no redundancy; Online is just ok
    (volume,) = raid.parse_openbsd_bioctl(
        _fixture("openbsd_bioctl_softraid0_crypto.txt")
    )
    assert volume["controller"] == "softraid0" and volume["volume"] == 0
    assert volume["level"] == "CRYPTO" and volume["device"] == "sd3"
    assert volume["members"] == [{"status": "Online", "name": "sd1a"}]
    assert raid.bio_volume_state(volume) == (hh.OK, [])


def test_openbsd_raid1_degraded():
    # constructed text: one chunk of the mirror offline, plus a healthy CRYPTO
    volumes = raid.parse_openbsd_bioctl(
        _fixture("openbsd_bioctl_softraid0_raid1_degraded.txt")
    )
    assert [v["level"] for v in volumes] == ["RAID1", "CRYPTO"]
    state, reasons = raid.bio_volume_state(volumes[0])
    assert state == hh.WARNING
    assert reasons == [
        {"code": "array_state", "state": "Degraded"},
        {"code": "array_degraded", "active": 1, "total": 2},
        {"code": "failed_members", "members": ["sd2a"]},
    ]
    assert raid.bio_volume_state(volumes[1])[0] == hh.OK


def test_openbsd_raid1_rebuild_with_percent_and_hot_spare():
    # constructed text: rebuilding at 42%, and a hot spare row (not a volume)
    (volume,) = raid.parse_openbsd_bioctl(
        _fixture("openbsd_bioctl_softraid0_raid1_rebuild.txt")
    )
    assert volume["percent"] == 42
    state, reasons = raid.bio_volume_state(volume)
    assert state == hh.WARNING
    assert {"code": "rebuilding", "percent": 42} in reasons
    assert {"code": "member_state", "member": "sd2a (Rebuild)"} in reasons


def test_openbsd_hardware_raid_failed_and_scrubbing():
    # constructed text: an mfi RAID0 offline with a failed disk; a RAID1 scrub
    report = hh.Report()
    run = _runner(
        {"bioctl mfi0": (0, _fixture("openbsd_bioctl_mfi0_failed.txt"))}
    )  # fmt: skip
    covered = raid.collect_bioctl(report, run, ["mfi0"], "OpenBSD")
    assert covered == {"mfi0"}
    components = _by_id(report)
    offline = components["mfi0/0"]
    assert offline["kind"] == hh.ARRAY and offline["state"] == hh.FAILED
    assert offline["name"] == "sd0 RAID0"
    # a hardware RAID disk is named by its location, not its model
    assert {"code": "failed_members", "members": ["32:0.0"]} in offline["reasons"]
    scrub = components["mfi0/1"]
    assert scrub["state"] == hh.OK and scrub["reasons"] == []
    # a scrub's percent is not a rebuild
    assert scrub["metrics"]["progress_percent"] == 7  # it is measured...
    assert "rebuilding" not in _codes(scrub)  # ...but not a reason
    assert _sources(report)["bioctl"]["status"] == hh.RAN


def test_openbsd_bioctl_replaces_the_softraid_sensor():
    report = hh.Report()
    run = _runner(
        {
            "sysctl hw.sensors": (0, _SOFTRAID_SENSOR),
            "bioctl softraid0": (0, _fixture("openbsd_bioctl_softraid0_crypto.txt")),
        }
    )
    bsd.collect(report, "OpenBSD", run)
    components = _by_id(report)
    assert "softraid0" not in components  # not reported twice
    assert components["softraid0/0"]["source"] == "bioctl"


def test_openbsd_unprivileged_bioctl_keeps_the_sensor():
    # recording: bioctl without root on the t480
    report = hh.Report()
    run = _runner(
        {
            "sysctl hw.sensors": (0, _SOFTRAID_SENSOR),
            "bioctl softraid0": (
                1,
                _fixture("openbsd_bioctl_softraid0_unprivileged.txt"),
            ),
        }
    )
    bsd.collect(report, "OpenBSD", run)
    components = _by_id(report)
    assert components["softraid0"]["source"] == "hw.sensors"
    source = _sources(report)["bioctl"]
    assert source["status"] == hh.SOURCE_FAILED
    assert "Permission denied" in source["detail"]


def test_openbsd_recording_has_no_raid_controller():
    # recording: the t480 has softraid0 attached but no volume, so no sensor
    # names a controller and bioctl is never run
    report = hh.Report()
    run = _runner(
        {"sysctl hw.sensors": (0, _fixture("openbsd_sysctl_hw_sensors.txt"))}
    )  # fmt: skip
    bsd.collect(report, "OpenBSD", run)
    assert not any(call.startswith("bioctl") for call in run.calls)
    source = _sources(report)["bioctl"]
    assert source["status"] == hh.ABSENT and source["detail"] == "no RAID volumes"
    assert _by_id(report)["nvme0"]["state"] == hh.OK


def test_openbsd_root_bioctl_with_no_volumes_keeps_the_sensor():
    # recording: `doas bioctl softraid0` printed nothing and exited 0
    report = hh.Report()
    run = _runner(
        {"sysctl hw.sensors": (0, _SOFTRAID_SENSOR), "bioctl softraid0": (0, "")}
    )
    bsd.collect(report, "OpenBSD", run)
    assert "softraid0" in _by_id(report)
    assert _sources(report)["bioctl"]["status"] == hh.RAN


def test_bioctl_absent():
    report = hh.Report()
    assert raid.collect_bioctl(report, _runner({}), ["softraid0"], "OpenBSD") == set()
    assert _sources(report)["bioctl"]["status"] == hh.ABSENT


# --- NetBSD bioctl ----------------------------------------------------------------


def test_netbsd_bioctl_show():
    # constructed text in the NetBSD bioctl "show" layout
    volumes = raid.parse_netbsd_bioctl(_fixture("netbsd_bioctl_mfi0_show.txt"), "mfi0")
    assert [v["device"] for v in volumes] == ["ld0", "ld1"]
    rebuilding = volumes[0]
    assert rebuilding["level"] == "RAID 1" and rebuilding["percent"] == 37.5
    assert [m["name"] for m in rebuilding["members"]] == ["0:0.0", "0:1.0"]
    state, reasons = raid.bio_volume_state(rebuilding)
    assert state == hh.WARNING
    assert {"code": "rebuilding", "percent": 37.5} in reasons
    assert raid.bio_volume_state(volumes[1]) == (hh.OK, [])


def test_netbsd_bioctl_skips_hot_spare_and_pass_through():
    # constructed text
    text = (
        "     0 Online       136G                  ld0 Pass through    N/A \n"
        "   0:0 Pass through 136G         0:0.0 noencl <SEAGATE ST3146356SS>\n"
        "     1 Online       136G                  sd2   Hot spare    N/A \n"
    )
    assert raid.parse_netbsd_bioctl(text, "mfi0") == []


# --- NetBSD envstat ---------------------------------------------------------------


def _envstat_report(skip=()):
    report = hh.Report()
    devices = raid.read_envstat(
        report, _runner({"envstat -x": (0, _fixture("netbsd_envstat_x.xml"))})
    )
    raid.add_envstat(report, devices, skip)
    return report


def test_envstat_temperatures_against_declared_limits():
    components = _by_id(_envstat_report())
    zone = components["acpitz0/temperature"]
    assert zone["kind"] == hh.SENSOR and zone["state"] == hh.OK
    assert zone["metrics"] == {"temperature_c": 52.0, "critical_c": 100.0}
    hot = components["coretemp0/cpu0 temperature"]
    assert hot["state"] == hh.WARNING
    assert hot["reasons"] == [
        {"code": "temperature_high", "value": 96.0, "limit": 90.0}
    ]
    # no limits declared: reported, never guessed at
    cool = components["coretemp1/cpu1 temperature"]
    assert cool["state"] == hh.OK and cool["metrics"] == {"temperature_c": 41.0}
    assert zone["source"] == "envstat"


def test_envstat_flagged_sensors_and_quiet_ones():
    components = _by_id(_envstat_report())
    fan = components["itesio0/CPU fan"]
    assert fan["state"] == hh.FAILED
    assert fan["reasons"] == [
        {"code": "sensor_status", "sensor": "CPU fan", "value": "0 RPM",
         "status": "critical-under"}
    ]  # fmt: skip
    battery = components["acpibat0/charge"]
    assert battery["state"] == hh.WARNING
    assert battery["reasons"][0]["value"] == "1.2 Wh"
    # an invalid voltage input, a healthy voltage and an indicator are not
    # components
    for ident in ("itesio0/VCORE B", "itesio0/+12V", "acpibat0/charging"):
        assert ident not in components


def test_envstat_drive_sensors():
    components = _by_id(_envstat_report())
    degraded = components["mfi0/ld0"]
    assert degraded["kind"] == hh.ARRAY and degraded["state"] == hh.FAILED
    assert degraded["reasons"] == [
        {"code": "sensor_status", "sensor": "ld0", "value": "degraded",
         "status": "critical"}
    ]  # fmt: skip
    assert components["mfi0/ld1"]["state"] == hh.OK
    # bioctl detailed mfi0: its drive sensors are left out
    skipped = _by_id(_envstat_report(skip={"mfi0"}))
    assert "mfi0/ld0" not in skipped and "acpitz0/temperature" in skipped


def test_envstat_kernel_state_without_declared_limit():
    # constructed text: the driver flags a temperature against a limit it did
    # not expose; the kernel's verdict stays
    sensor = {
        "type": "Temperature", "description": "board", "state": "critical-over",
        "cur-value": 273150000 + 88_000000,
    }  # fmt: skip
    report = hh.Report()
    raid.add_envstat(report, {"lm0": [sensor]})
    board = _by_id(report)["lm0/board"]
    assert board["state"] == hh.FAILED
    assert _codes(board) == ["sensor_status"]


def test_envstat_absent_failed_and_garbage():
    report = hh.Report()
    assert raid.read_envstat(report, _runner({})) == {}
    assert _sources(report)["envstat"]["status"] == hh.ABSENT
    for answer in ((1, "envstat: Permission denied"), (0, "not a plist")):
        report = hh.Report()
        assert raid.read_envstat(report, _runner({"envstat -x": answer})) == {}
        assert _sources(report)["envstat"]["status"] == hh.SOURCE_FAILED


# --- NetBSD raidctl ---------------------------------------------------------------


def test_raidctl_optimal():
    # constructed text from raidctl(8) EXAMPLES
    status = raid.parse_raidctl_status(_fixture("netbsd_raidctl_s_raid0_optimal.txt"))
    assert status["components"] == [("/dev/wd0e", "optimal"), ("/dev/wd1e", "optimal")]
    assert status["spares"] == [] and status["level"] == "1"
    assert status["parity"] == "clean" and status["recon_percent"] == 100
    assert raid.raidctl_state(status) == (hh.OK, [])


def test_raidctl_failed_component_dirty_parity():
    # constructed text from raidctl(8) EXAMPLES (RAID 5, one failed, a spare)
    status = raid.parse_raidctl_status(_fixture("netbsd_raidctl_s_raid1_failed.txt"))
    assert status["spares"] == [("/dev/sd4e", "spare")]
    state, reasons = raid.raidctl_state(status)
    assert state == hh.WARNING  # RAID 5 survives one member
    assert reasons == [
        {"code": "array_degraded", "active": 2, "total": 3},
        {"code": "failed_members", "members": ["/dev/sd2e"]},
        {"code": "array_state", "state": "parity DIRTY"},
    ]


def test_raidctl_reconstructing():
    # constructed text from raidctl(8) EXAMPLES
    status = raid.parse_raidctl_status(
        _fixture("netbsd_raidctl_s_raid1_reconstructing.txt")
    )
    state, reasons = raid.raidctl_state(status)
    assert state == hh.WARNING
    assert {"code": "rebuilding", "percent": 10} in reasons
    assert {"code": "member_state", "member": "/dev/sd2e (reconstructing)"} in reasons


def test_raidctl_beyond_tolerance_is_failed():
    def judged(level, statuses):
        status = {
            "components": [(f"/dev/wd{i}e", s) for i, s in enumerate(statuses)],
            "spares": [], "level": level,
        }  # fmt: skip
        return raid.raidctl_state(status)[0]

    assert judged("0", ["optimal", "failed"]) == hh.FAILED
    assert judged("1", ["failed", "failed"]) == hh.FAILED
    # RAID 1 pairs are columns 0/1 and 2/3: one loss in each pair survives
    assert judged("1", ["failed", "optimal", "optimal", "failed"]) == hh.WARNING
    assert judged("5", ["failed", "reconstructing", "optimal"]) == hh.FAILED
    assert judged(None, []) == hh.UNKNOWN


def test_netbsd_end_to_end():
    run = _runner(
        {
            "envstat -x": (0, _fixture("netbsd_envstat_x.xml")),
            "bioctl mfi0 show": (0, _fixture("netbsd_bioctl_mfi0_show.txt")),
            "sysctl -n hw.disknames": (0, "wd0 wd1 raid0 raid1 cd0 dk0"),
            "raidctl -s raid0": (0, _fixture("netbsd_raidctl_s_raid0_optimal.txt")),
            "raidctl -s raid1": (
                0,
                _fixture("netbsd_raidctl_s_raid1_reconstructing.txt"),
            ),
        }
    )
    result = hh.collect_hardware_health("NetBSD", run)
    components = {c["id"]: c for c in result["components"]}
    assert components["raid0"]["name"] == "raid0 RAID1"
    assert components["raid0"]["state"] == hh.OK
    assert "rebuild_percent" not in components["raid0"]["metrics"]
    assert components["raid1"]["metrics"]["rebuild_percent"] == 10
    # bioctl detailed mfi0, so the envstat drive sensors are not repeated
    assert "mfi0/0" in components and "mfi0/ld0" not in components
    assert result["state"] == hh.FAILED  # the CPU fan
    sources = {s["name"]: s["status"] for s in result["sources"]}
    assert sources["envstat"] == sources["bioctl"] == sources["raidctl"] == hh.RAN
    assert sources["zpool"] == hh.ABSENT


def test_netbsd_nothing_there():
    report = hh.Report()
    raid.collect_netbsd(report, _runner({"sysctl -n hw.disknames": (0, "wd0 cd0")}))
    sources = _sources(report)
    assert sources["envstat"]["status"] == hh.ABSENT
    assert sources["bioctl"]["detail"] == "no RAID volumes"
    assert sources["raidctl"]["detail"] == "no RAIDframe sets"
    assert report.as_dict()["state"] == hh.UNKNOWN  # not measured, not healthy


def test_raidctl_unprivileged():
    # constructed text: raidctl opens /dev/rraid0d, which needs privilege
    report = hh.Report()
    run = _runner(
        {
            "sysctl -n hw.disknames": (0, "wd0 raid0"),
            "raidctl -s raid0": (1, "raidctl: unable to open device file: raid0"),
        }
    )
    raid.collect_raidctl(report, run)
    assert _sources(report)["raidctl"]["status"] == hh.SOURCE_FAILED
    assert not report.components
