# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Machine checks: rasdaemon on Linux, WHEA-Logger on Windows (Phase 23.1).

* ``windows_hw_whea.json`` is a REAL recording (x13s, 2026-10-14) of the
  whole Windows hardware script with the WHEA count added: zero events in
  the last 24 hours -- and zero ever: Get-WinEvent threw
  ``NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand``,
  which the script turns into 0.
* The ``ras-mc-ctl --errors`` outputs below are CONSTRUCTED TEXT: rasdaemon
  is installed on no lab machine.  They follow the print statements of
  ras-mc-ctl 0.8.4 (``$id $time error: $msg, ..., mci $mcistatus_msg, ...``,
  ``No MCE errors.``) and the MCi_STATUS words compiled into its rasdaemon
  (``Corrected_error``, ``Uncorrected_error``, ``Processor_context_corrupt``).
"""

# pylint: disable=protected-access

import json
from datetime import datetime, timezone
from pathlib import Path

from src.sysmanage_agent.collection import hardware_health as hh
from src.sysmanage_agent.collection import hardware_health_linux as lnx
from src.sysmanage_agent.collection import hardware_health_mce as mce
from src.sysmanage_agent.collection import hardware_health_windows as win

FIXTURES = Path(__file__).parent / "fixtures" / "hardware_health"
NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)

# constructed text (see the module docstring)
RAS_NO_MCE = """\
No Memory errors.

No PCIe AER errors.

No Extlog errors.

No devlink errors.

No disk errors.

No Memory failure errors.

No MCE errors.

"""

RAS_MCE = """\
No Memory errors.

No PCIe AER errors.

MCE events:
1 2026-10-12 23:10:44 +0000 error: MEMORY CONTROLLER RD_CHANNEL1_ERR Transaction: Memory read error, CPU GenuineIntel, mcg mcgstatus=0, mci Corrected_error Error_enabled, mcgcap=0x01000c16, status=0x8c00004000010091, addr=0x7f3e1000, cpu=0x00000002, cpuid=0x000306c3, bank=0x00000007
2 2026-10-14 08:02:11 +0000 error: MEMORY CONTROLLER RD_CHANNEL1_ERR Transaction: Memory read error, CPU GenuineIntel, mcg mcgstatus=0, mci Corrected_error Error_enabled, mcgcap=0x01000c16, status=0x8c00004000010091, addr=0x7f3e1000, cpu=0x00000002, cpuid=0x000306c3, bank=0x00000007
3 2026-10-14 06:30:00 -0500 error: MEMORY CONTROLLER RD_CHANNEL0_ERR Transaction: Memory read error, CPU GenuineIntel, mcg mcgstatus=0, mci Corrected_error Error_enabled, mcgcap=0x01000c16, status=0x8c00004000010090, cpu=0x00000001, bank=0x00000007

"""

RAS_FATAL = RAS_MCE.replace(
    "3 2026-10-14 06:30:00 -0500",
    "4 2026-10-14 10:00:00 +0000 error: Generic CACHE Level-2 Generic Error,"
    " mcg mcgstatus=0x00000005, mci Uncorrected_error Error_enabled"
    " Processor_context_corrupt, bank=0x00000004\n3 2026-10-14 06:30:00 -0500",
)


def _runner(answers):
    calls = []

    def run(argv):
        calls.append(argv)
        return answers.get(argv[0], (-1, ""))

    run.calls = calls
    return run


def _component(report, ident):
    return next(c for c in report.components if c["id"] == ident)


def _sources(report):
    return {s["name"]: s for s in report.sources}


# --- the judgment ------------------------------------------------------------------


def test_machine_check_state():
    assert mce.machine_check_state(0, 0) == (hh.OK, [])
    assert mce.machine_check_state(3, 0) == (
        hh.WARNING,
        [{"code": "machine_checks", "count": 3}],
    )
    assert mce.machine_check_state(3, 1) == (
        hh.FAILED,
        [{"code": "machine_checks_fatal", "count": 1}],
    )


# --- rasdaemon ---------------------------------------------------------------------


def test_ras_errors_only_the_last_24_hours():
    # record 1 is 37 h old; 2 and 3 (11:30 UTC, written with its own zone) count
    assert mce.parse_ras_errors(RAS_MCE, NOW) == (2, 0)
    assert mce.parse_ras_errors(RAS_FATAL, NOW) == (2, 1)
    assert mce.parse_ras_errors(RAS_NO_MCE, NOW) == (0, 0)
    # a rasdaemon without MCE support (ARM) prints no MCE section at all
    assert mce.parse_ras_errors("No Memory errors.\n\n", NOW) is None


def test_rasdaemon_absent_adds_nothing():
    report = hh.Report()
    mce.collect_rasdaemon(report, _runner({}), now=lambda: NOW)
    assert not report.sources and not report.components


def test_rasdaemon_clean_corrected_and_fatal():
    clean = hh.Report()
    run = _runner({"ras-mc-ctl": (0, RAS_NO_MCE)})
    mce.collect_rasdaemon(clean, run, now=lambda: NOW)
    assert run.calls == [["ras-mc-ctl", "--errors", "--since=2026-10-13"]]
    assert _sources(clean)["rasdaemon"]["status"] == hh.RAN
    component = _component(clean, "mce")
    assert (component["kind"], component["name"], component["state"]) == (
        hh.MEMORY,
        "Machine checks",
        hh.OK,
    )
    assert component["metrics"] == {
        "corrected_errors": 0,
        "uncorrected_errors": 0,
        "window_hours": 24,
    }
    corrected = hh.Report()
    mce.collect_rasdaemon(
        corrected, _runner({"ras-mc-ctl": (0, RAS_MCE)}), now=lambda: NOW
    )
    assert _component(corrected, "mce")["state"] == hh.WARNING
    assert _component(corrected, "mce")["reasons"] == [
        {"code": "machine_checks", "count": 2}
    ]
    fatal = hh.Report()
    mce.collect_rasdaemon(
        fatal, _runner({"ras-mc-ctl": (0, RAS_FATAL)}), now=lambda: NOW
    )
    assert _component(fatal, "mce")["state"] == hh.FAILED
    assert _component(fatal, "mce")["reasons"] == [
        {"code": "machine_checks_fatal", "count": 1}
    ]
    assert fatal.as_dict()["state"] == hh.FAILED


def test_rasdaemon_failure_and_an_old_version():
    calls = []

    def old(argv):
        calls.append(argv)
        return (1, "Unknown option: since") if len(argv) == 3 else (0, RAS_MCE)

    report = hh.Report()
    mce.collect_rasdaemon(report, old, now=lambda: NOW)
    assert calls[1] == ["ras-mc-ctl", "--errors"]
    assert _component(report, "mce")["state"] == hh.WARNING
    broken = hh.Report()
    mce.collect_rasdaemon(
        broken,
        _runner({"ras-mc-ctl": (2, "unable to open database file")}),
        now=lambda: NOW,
    )
    assert _sources(broken)["rasdaemon"]["status"] == hh.SOURCE_FAILED
    assert not broken.components


def test_linux_collect_asks_rasdaemon(monkeypatch):
    seen = []
    monkeypatch.setattr(mce, "collect_rasdaemon", lambda report, run: seen.append(run))
    report = hh.Report()
    lnx.collect(
        report, "Linux", lambda argv: (-1, ""), lambda path: None, lambda path: []
    )
    assert len(seen) == 1
    assert "rasdaemon" not in _sources(report)


# --- Windows WHEA ------------------------------------------------------------------


def test_windows_whea_recording_is_zero():
    report = hh.Report()
    data = json.loads((FIXTURES / "windows_hw_whea.json").read_text("utf-8"))
    win.parse(data, report)
    component = _component(report, "whea")
    assert (component["kind"], component["name"], component["state"]) == (
        hh.MEMORY,
        "Hardware errors (WHEA)",
        hh.OK,
    )
    assert component["source"] == "WHEA-Logger"
    assert _sources(report)["WHEA-Logger"]["status"] == hh.RAN


def test_windows_whea_counts_and_failures():
    corrected = hh.Report()
    win.parse({"whea": {"corrected": 4, "fatal": 0, "error": None}}, corrected)
    assert _component(corrected, "whea")["reasons"] == [
        {"code": "machine_checks", "count": 4}
    ]
    fatal = hh.Report()
    win.parse({"whea": {"corrected": 4, "fatal": 2, "error": None}}, fatal)
    assert _component(fatal, "whea")["state"] == hh.FAILED
    assert _component(fatal, "whea")["reasons"] == [
        {"code": "machine_checks_fatal", "count": 2}
    ]
    failed = hh.Report()
    win.parse({"whea": {"corrected": 0, "fatal": 0, "error": "Access denied"}}, failed)
    assert _sources(failed)["WHEA-Logger"] == {
        "name": "WHEA-Logger",
        "status": hh.SOURCE_FAILED,
        "detail": "Access denied",
    }
    assert not failed.components
    garbled = hh.Report()
    win.parse({"whea": {"corrected": "x", "fatal": None}}, garbled)
    assert _sources(garbled)["WHEA-Logger"]["status"] == hh.SOURCE_FAILED
    older = hh.Report()  # a report from before the WHEA count: not measured
    win.parse({"disks": []}, older)
    assert not older.sources and not older.components


def test_windows_script_counts_whea_and_survives_none():
    assert "ProviderName = 'Microsoft-Windows-WHEA-Logger'" in win.SCRIPT
    assert "AddHours(-24)" in win.SCRIPT
    assert "NoMatchingEventsFound" in win.SCRIPT
    assert "whea = $whea" in win.SCRIPT
