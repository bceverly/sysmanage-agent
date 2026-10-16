# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Drive health from an unprivileged (packaged) Linux agent.

Every drive on beast and nas read "not judged -- the health log could not be
read" (2026-10-16): the NVMe ioctl, smartctl, lvs, btrfs stats and ipmitool
all need root and the agent never escalated.  The default Linux runner now
runs those through ``sudo -n`` (allowlisted), NVMe falls back to smartctl
without root, and a missing smartctl says ``smartctl_absent`` -- the reason
the server's smartmontools install offer reacts to."""

import json
from pathlib import Path

import pytest

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_linux as lnx
from src.sysmanage_agent.collection import hardware_health_privilege as priv

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"


def _nvme_sysfs(path):
    return {"/sys/class/nvme/nvme0/model": "WDC PC SN730 SDBQNTY-512G-1001"}.get(path)


def _listdir(path):
    return ["nvme0"] if path == lnx.SYS_NVME else []


class Recorder:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, argv):
        self.calls.append(list(argv))
        return self.answers.get(" ".join(argv), (-1, ""))


# --- the escalating runner ---------------------------------------------------


@pytest.fixture
def resolved(monkeypatch):
    monkeypatch.setattr(priv, "_tool", lambda name: f"/usr/sbin/{name}")


def test_health_reads_go_through_sudo_with_the_exact_argv(resolved):
    plain = Recorder({"sudo -n /usr/sbin/smartctl -j -H -A /dev/sda": (0, "{}")})
    run = priv.privileged_runner(plain, root=False)
    assert run(["smartctl", "-j", "-H", "-A", "/dev/sda"]) == (0, "{}")
    assert plain.calls == [
        ["sudo", "-n", "/usr/sbin/smartctl", "-j", "-H", "-A", "/dev/sda"]
    ]
    assert priv.escalates(run)


def test_version_probes_and_other_tools_stay_unprivileged(resolved):
    plain = Recorder({})
    run = priv.privileged_runner(plain, root=False)
    run(["smartctl", "--version"])
    run(["ipmitool", "-V"])
    run(["zpool", "list"])
    assert plain.calls == [
        ["smartctl", "--version"],
        ["ipmitool", "-V"],
        ["zpool", "list"],
    ]


def test_a_refused_sudo_falls_back_to_the_plain_call(resolved):
    refused = "sudo: a password is required"
    plain = Recorder(
        {
            "sudo -n /usr/sbin/lvs --reportformat json": (1, refused),
            "lvs --reportformat json": (5, "WARNING: Running as a non-root user"),
        }
    )
    run = priv.privileged_runner(plain, root=False)
    assert run(["lvs", "--reportformat", "json"]) == (
        5,
        "WARNING: Running as a non-root user",
    )


def test_a_failing_tool_is_not_mistaken_for_a_refusal(resolved):
    # smartctl's exit status is a bit mask: nonzero for a sick disk is an answer
    plain = Recorder({"sudo -n /usr/sbin/smartctl -j -H -A /dev/sda": (8, '{"x": 1}')})
    run = priv.privileged_runner(plain, root=False)
    assert run(["smartctl", "-j", "-H", "-A", "/dev/sda"]) == (8, '{"x": 1}')
    assert len(plain.calls) == 1


def test_a_missing_tool_is_missing(monkeypatch):
    monkeypatch.setattr(priv, "_tool", lambda name: name)  # not found anywhere
    plain = Recorder({})
    run = priv.privileged_runner(plain, root=False)
    assert run(["smartctl", "-j", "-H", "-A", "/dev/sda"]) == (-1, "")
    assert not plain.calls


def test_root_runs_everything_plainly():
    plain = Recorder({})
    assert priv.privileged_runner(plain, root=True) is plain


# --- NVMe without root -----------------------------------------------------------


def test_unprivileged_nvme_is_judged_through_smartctl(monkeypatch):
    monkeypatch.setattr(lnx, "_root", lambda: False)
    recorded = (FIXTURES / "linux_smartctl_nvme_nas.json").read_text()
    run = Recorder(
        {
            "smartctl --version": (0, "smartctl 7.2"),
            "smartctl -j -H -A /dev/nvme0": (0, recorded),
        }
    )
    report = hh.Report()
    lnx.collect_nvme(report, _nvme_sysfs, _listdir, run=run)
    drive = report.as_dict()["components"][0]
    assert (drive["id"], drive["state"], drive["source"]) == (
        "nvme0",
        hh.OK,
        "smartctl",
    )
    assert drive["metrics"]["percent_used"] == 8
    assert drive["metrics"]["power_on_hours"] == 42767
    source = {s["name"]: s for s in report.as_dict()["sources"]}["nvme"]
    assert source["status"] == hh.RAN


def test_unprivileged_nvme_without_smartctl_asks_for_smartmontools(monkeypatch):
    monkeypatch.setattr(lnx, "_root", lambda: False)
    report = hh.Report()
    lnx.collect_nvme(report, _nvme_sysfs, _listdir, run=Recorder({}))
    drive = report.as_dict()["components"][0]
    assert drive["state"] == hh.UNKNOWN
    assert drive["reasons"] == [{"code": "smartctl_absent"}]


def test_root_still_reads_the_ioctl(monkeypatch):
    monkeypatch.setattr(lnx, "_root", lambda: True)
    run = Recorder({})
    report = hh.Report()
    lnx.collect_nvme(
        report, _nvme_sysfs, _listdir, smart_log=lambda _dev: bytes(512), run=run
    )
    assert report.as_dict()["components"][0]["source"] == "nvme"
    assert not run.calls


def test_the_recording_parses():
    state, reasons, metrics = hh.parse_smartctl_json(
        json.loads((FIXTURES / "linux_smartctl_nvme_nas.json").read_text())
    )
    assert (state, reasons) == (hh.OK, [])
    assert metrics["critical_warning"] == 0


# --- the allowlists ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["ubuntu", "centos", "opensuse"])
def test_the_sudoers_grants_exactly_the_health_reads(name):
    text = (Path(__file__).resolve().parents[1] / "installer" / name /
            "sysmanage-agent.sudoers").read_text()  # fmt: skip
    assert "NOPASSWD: SYSMANAGE_SMART_READ" in text, name
    for device in ("/dev/sda", "/dev/sdz", "/dev/nvme0", "/dev/nvme15"):
        assert f"/usr/sbin/smartctl -j -H -A {device}" in text, (name, device)
    # never a wildcard that would also allow -s / -t (drive settings, tests)
    rules = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "smartctl -j -H -A *" not in rules and "/dev/*" not in rules, name
    for rule in (
        "/usr/sbin/lvs --reportformat json -o " + hh_lvs_fields(),
        "/usr/bin/ipmitool sdr elist",
        "/usr/bin/ipmitool sel elist",
        "/usr/bin/ipmitool sel time get",
        "/usr/bin/btrfs device stats *",
        "/usr/sbin/btrfs filesystem show *",
    ):
        assert f"NOPASSWD: {rule}" in text, (name, rule)


def hh_lvs_fields():
    from src.sysmanage_agent.collection.hardware_health_linux_storage import (  # pylint: disable=import-outside-toplevel
        LVS_FIELDS,
    )

    return LVS_FIELDS.replace(",", "\\,")
