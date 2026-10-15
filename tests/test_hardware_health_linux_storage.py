# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""btrfs and LVM RAID health (Phase 23.1, Linux).

The fixtures are REAL recordings (2026-10-14, btrfs-progs 6.17.1, LVM
2.03.31) of throwaway devices built on loop devices on a lab workstation:

* a btrfs raid1 (label ``smhwtest``) on two loop devices -- healthy; then
  150 MiB of one member's backing file overwritten and ``btrfs scrub start
  -B`` run (25600 corruption_errs on that member, all corrected); then that
  member detached and the filesystem mounted ``-o degraded``.  The same
  ``show`` run unprivileged lists every device as ``size 0 ... MISSING``.
* an LVM raid1 ``smhwtest/r1`` on two loop PVs -- syncing (recovery rate
  limited), synced, one leg overwritten and ``--syncaction check`` run
  (``mismatches exist``), one PV detached (``partial``, inactive and then
  activated degraded), the PV reattached (``refresh needed``), and ``lvs``
  run unprivileged.  The workstation's own linear root LV is in every
  ``lvs`` recording and must be ignored.

Lines marked "constructed text" below are not recordings.
"""

# pylint: disable=unbalanced-tuple-unpacking  # (x,) = one-component reports

from pathlib import Path

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_linux as lnx
from src.sysmanage_agent.collection import hardware_health_linux_storage as st

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"
MNT = "/var/tmp/sm-hwtest/mnt"
UUID = "77035804-8931-44df-b41a-84a2a82ce7c2"
LVS = ["lvs", "--reportformat", "json", "-o", st.LVS_FIELDS]


def _fixture(name):
    return (FIXTURES / name).read_text()


def _runner(answers):
    def run(argv):
        return answers.get(" ".join(argv), (-1, ""))

    return run


def _sources(report):
    return {s["name"]: s for s in report.as_dict()["sources"]}


def _btrfs_run(show, stats):
    return _runner(
        {
            "btrfs --version": (0, "btrfs-progs v6.17.1"),
            f"btrfs filesystem show {MNT}": (0, _fixture(show)),
            f"btrfs device stats {MNT}": (0, _fixture(stats)),
        }
    )


def _btrfs(mounts, show, stats, root=True):
    report = hh.Report()
    reader = {st.PROC_MOUNTS: _fixture(mounts)}.get
    st.collect_btrfs(report, _btrfs_run(show, stats), reader, root=root)
    return report


# --- btrfs -----------------------------------------------------------------------


def test_btrfs_mounts_dedupe_and_unescape():
    assert st.btrfs_mounts(_fixture("linux_btrfs_mounts_healthy.txt")) == [MNT]
    # constructed text: two subvolumes of one filesystem, a space in a path
    text = (
        "/dev/sda2 / btrfs rw,subvol=/@ 0 0\n"
        "/dev/sda2 /home btrfs rw,subvol=/@home 0 0\n"
        "/dev/sdb1 /mnt/my\\040disk btrfs rw 0 0\n"
        "proc /proc proc rw 0 0\n"
    )
    assert st.btrfs_mounts(text) == ["/", "/mnt/my disk"]


def test_btrfs_healthy_recording():
    report = _btrfs(
        "linux_btrfs_mounts_healthy.txt",
        "linux_btrfs_show_healthy.txt",
        "linux_btrfs_stats_healthy.txt",
    )
    (pool,) = report.as_dict()["components"]
    assert (pool["kind"], pool["id"], pool["name"]) == (hh.POOL, UUID, "smhwtest")
    assert (pool["state"], pool["reasons"]) == (hh.OK, [])
    assert pool["metrics"]["total_devices"] == 2
    assert pool["metrics"]["missing_devices"] == 0
    assert pool["metrics"]["corruption_errors"] == 0
    assert _sources(report)["btrfs"]["status"] == hh.RAN


def test_btrfs_corruption_counters_recording():
    report = _btrfs(
        "linux_btrfs_mounts_healthy.txt",
        "linux_btrfs_show_healthy.txt",
        "linux_btrfs_stats_corrupted.txt",
    )
    (pool,) = report.as_dict()["components"]
    # the scrub corrected every block, but the counter stays until reset
    assert pool["state"] == hh.WARNING
    assert pool["reasons"] == [
        {
            "code": "btrfs_device_errors",
            "device": "/dev/loop11",
            "write": 0,
            "read": 0,
            "flush": 0,
            "corruption": 25600,
            "generation": 0,
        }
    ]
    assert pool["metrics"]["corruption_errors"] == 25600


def test_btrfs_missing_device_recording():
    show = st.parse_btrfs_show(_fixture("linux_btrfs_show_missing.txt"))
    assert show["devices"][1] == {"devid": 2, "path": "devid 2", "missing": True}
    report = _btrfs(
        "linux_btrfs_mounts_degraded.txt",
        "linux_btrfs_show_missing.txt",
        "linux_btrfs_stats_missing.txt",
    )
    (pool,) = report.as_dict()["components"]
    assert pool["state"] == hh.FAILED
    missing, errors = pool["reasons"]
    assert missing == {
        "code": "device_not_online",
        "device": "devid 2",
        "state": "missing",
    }
    # the stats name the gone device "<missing disk>": named after its devid
    assert errors["device"] == "devid 2" and errors["corruption"] == 25600
    assert pool["metrics"]["missing_devices"] == 1


def test_btrfs_old_progs_some_devices_missing():
    # constructed text: the older btrfs-progs format, missing device unlisted
    text = (
        "Label: none  uuid: 1111-2222\n"
        "\tTotal devices 3 FS bytes used 1.00GiB\n"
        "\tdevid    1 size 10.00GiB used 2.00GiB path /dev/sdb\n"
        "\tdevid    3 size 10.00GiB used 2.00GiB path /dev/sdd\n"
        "\t*** Some devices missing\n"
    )
    show = st.parse_btrfs_show(text)
    assert show["uuid"] == "1111-2222" and show.get("label") is None
    state, reasons = st.btrfs_state(show, {})
    assert state == hh.FAILED
    assert reasons == [
        {"code": "device_not_online", "device": "devid 2", "state": "missing"}
    ]
    # the warning line alone, with nothing to count against
    state, reasons = st.btrfs_state({"devices": [], "some_missing": True}, {})
    assert state == hh.FAILED and reasons[0]["device"] == "unknown"


def test_btrfs_not_root_is_unknown_not_missing():
    # unprivileged, show calls every device of a healthy filesystem MISSING
    show = st.parse_btrfs_show(_fixture("linux_btrfs_show_nonroot.txt"))
    assert all(d["missing"] for d in show["devices"])
    report = _btrfs(
        "linux_btrfs_mounts_healthy.txt",
        "linux_btrfs_show_nonroot.txt",
        "linux_btrfs_stats_healthy.txt",
        root=False,
    )
    (pool,) = report.as_dict()["components"]
    assert (pool["id"], pool["state"], pool["reasons"]) == (UUID, hh.UNKNOWN, [])
    source = _sources(report)["btrfs"]
    assert (source["status"], source["detail"]) == (hh.SOURCE_FAILED, "not_privileged")


def test_btrfs_absent_and_failing_tools():
    reader = {st.PROC_MOUNTS: _fixture("linux_btrfs_mounts_healthy.txt")}.get
    # no btrfs mounted at all: no pools, the source is absent
    report = hh.Report()
    st.collect_btrfs(report, _runner({}), {}.get, root=True)
    assert report.as_dict()["components"] == []
    assert _sources(report)["btrfs"]["status"] == hh.ABSENT
    # mounted but no btrfs-progs: the pool is unknown, never ok
    report = hh.Report()
    st.collect_btrfs(report, _runner({}), reader, root=True)
    (pool,) = report.as_dict()["components"]
    assert (pool["id"], pool["state"]) == (MNT, hh.UNKNOWN)
    assert _sources(report)["btrfs"]["status"] == hh.ABSENT
    # show works, stats fails
    report = hh.Report()
    run = _runner(
        {
            "btrfs --version": (0, "btrfs-progs v6.17.1"),
            f"btrfs filesystem show {MNT}": (
                0,
                _fixture("linux_btrfs_show_healthy.txt"),
            ),
            f"btrfs device stats {MNT}": (1, "ERROR: getting device info failed"),
        }
    )
    st.collect_btrfs(report, run, reader, root=True)
    (pool,) = report.as_dict()["components"]
    assert (pool["id"], pool["state"]) == (UUID, hh.UNKNOWN)
    assert _sources(report)["btrfs"]["status"] == hh.SOURCE_FAILED
    # show fails
    report = hh.Report()
    run = _runner({"btrfs --version": (0, ""), f"btrfs filesystem show {MNT}": (1, "")})
    st.collect_btrfs(report, run, reader, root=True)
    assert report.as_dict()["components"][0]["state"] == hh.UNKNOWN
    assert _sources(report)["btrfs"]["status"] == hh.SOURCE_FAILED


# --- LVM RAID --------------------------------------------------------------------


def _lvm(name, rc=0):
    report = hh.Report()
    st.collect_lvm_raid(report, _runner({" ".join(LVS): (rc, _fixture(name))}))
    return report


def _array(report):
    (array,) = report.as_dict()["components"]  # the linear root LV is ignored
    assert (array["kind"], array["id"], array["source"]) == (
        hh.ARRAY,
        "smhwtest/r1",
        "lvm",
    )
    return array


def test_lvm_synced_recording():
    report = _lvm("linux_lvs_synced.json")
    array = _array(report)
    assert (array["state"], array["reasons"]) == (hh.OK, [])
    assert array["metrics"] == {
        "segtype": "raid1",
        "sync_percent": 100.0,
        "mismatch_count": 0,
        "attr": "rwi-a-r---",
    }
    assert _sources(report)["lvm"]["status"] == hh.RAN


def test_lvm_syncing_recording():
    array = _array(_lvm("linux_lvs_syncing.json"))
    assert array["state"] == hh.WARNING
    assert array["reasons"] == [{"code": "rebuilding", "percent": 12.89}]


def test_lvm_mismatches_recording():
    array = _array(_lvm("linux_lvs_mismatches.json"))
    assert array["state"] == hh.WARNING
    assert array["reasons"] == [{"code": "array_state", "state": "mismatches exist"}]
    assert array["metrics"]["mismatch_count"] == 32768


def test_lvm_refresh_needed_recording():
    array = _array(_lvm("linux_lvs_refresh_needed.json"))
    assert array["state"] == hh.WARNING
    assert array["reasons"] == [{"code": "array_state", "state": "refresh needed"}]


def test_lvm_partial_recordings():
    # activated degraded (LVM's default activation_mode): still serving data
    array = _array(_lvm("linux_lvs_partial.json"))
    assert array["state"] == hh.WARNING
    assert array["reasons"] == [{"code": "array_state", "state": "partial"}]
    # not active: serving nothing
    array = _array(_lvm("linux_lvs_partial_inactive.json"))
    assert array["state"] == hh.FAILED
    assert array["reasons"] == [{"code": "array_state", "state": "partial"}]


def test_lvm_inactive_healthy_is_unknown():
    # constructed text: an inactive LV has no dm-raid status to judge
    lv = {"segtype": "raid5_ls", "lv_health_status": "", "lv_attr": "rwi---r---"}
    assert st.lvm_state(lv) == (
        hh.UNKNOWN,
        [{"code": "array_state", "state": "inactive"}],
    )


def test_lvm_raid_segtypes():
    for segtype in ("raid1", "raid4", "raid5_ls", "raid6_zr", "raid10", "mirror"):
        assert st.is_lvm_raid({"segtype": segtype}), segtype
    for segtype in ("linear", "striped", "raid0", "raid0_meta", "thin-pool", ""):
        assert not st.is_lvm_raid({"segtype": segtype}), segtype


def test_lvm_not_root_absent_and_garbage():
    report = _lvm("linux_lvs_nonroot.txt", rc=5)
    assert report.as_dict()["components"] == []
    source = _sources(report)["lvm"]
    assert (source["status"], source["detail"]) == (hh.SOURCE_FAILED, "not_privileged")
    report = hh.Report()
    st.collect_lvm_raid(report, _runner({}))
    assert _sources(report)["lvm"]["status"] == hh.ABSENT
    report = hh.Report()
    st.collect_lvm_raid(report, _runner({" ".join(LVS): (3, "  Unknown option")}))
    assert _sources(report)["lvm"] == {
        "name": "lvm",
        "status": hh.SOURCE_FAILED,
        "detail": "Unknown option",
    }


def test_linux_collect_runs_both(monkeypatch):
    monkeypatch.setattr(st, "_root", lambda: True)
    answers = {
        "btrfs --version": (0, "btrfs-progs v6.17.1"),
        f"btrfs filesystem show {MNT}": (0, _fixture("linux_btrfs_show_missing.txt")),
        f"btrfs device stats {MNT}": (0, _fixture("linux_btrfs_stats_missing.txt")),
        " ".join(LVS): (0, _fixture("linux_lvs_partial.json")),
    }
    files = {st.PROC_MOUNTS: _fixture("linux_btrfs_mounts_degraded.txt")}
    report = hh.Report()
    lnx.collect(report, "Linux", _runner(answers), files.get, lambda _path: [])
    by_id = {c["id"]: c for c in report.as_dict()["components"]}
    assert by_id[UUID]["state"] == hh.FAILED
    assert by_id["smhwtest/r1"]["state"] == hh.WARNING
    sources = _sources(report)
    assert sources["btrfs"]["status"] == sources["lvm"]["status"] == hh.RAN
