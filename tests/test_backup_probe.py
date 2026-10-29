# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The "backup" capability probe and the restate contract module (Phase 24)."""

import os

import pytest

from src.sysmanage_agent.backup import restate_contract as contract
from src.sysmanage_agent.backup import restate_probe as probe

GOOD = {"version": "2.0.0.0", "job_keys": ["command", "repository"]}


@pytest.fixture(autouse=True)
def _fresh():
    probe.forget()
    yield
    probe.forget()


def _reason(found="/usr/sbin/restate", unit=True, system="Linux", fallback=None,
            nfs=True):  # fmt: skip
    return probe.unavailable_reason(
        lambda name: found if name == "restate" else None,
        system,
        ask=lambda executable: GOOD,
        unit_exists=lambda path: unit,
        exists=lambda path: path == fallback,
        nfs_exists=lambda path: nfs and path == "/sbin/mount.nfs4",
    )


def test_backup_is_not_applicable_where_no_runner_drives_it(monkeypatch):
    monkeypatch.setattr(probe, "features", lambda e, ask=None: GOOD)
    for system in ("Darwin", "Windows", "OpenBSD", "NetBSD", None):
        assert _reason(system=system) == probe.REASON_WRONG_PLATFORM


def test_freebsd_needs_no_systemd_unit(monkeypatch):
    # daemon(8) runs restate there; restate-job@.service is a Linux thing.
    monkeypatch.setattr(probe, "features", lambda e, ask=None: GOOD)
    assert _reason(system="FreeBSD", unit=False) is None


def test_freebsd_finds_restate_off_the_rc_path(monkeypatch):
    # FreeBSD's rc PATH has no /usr/local/sbin, where restate installs.
    monkeypatch.setattr(probe, "features", lambda e, ask=None: GOOD)
    found = "/usr/local/sbin/restate"
    assert probe.locate(lambda _n: None, lambda p: p == found) == found
    assert _reason(found=None, system="FreeBSD", fallback=found) is None
    assert _reason(found=None, system="FreeBSD") == probe.REASON_MISSING_TOOL


def test_no_restate_is_an_optional_missing_tool():
    assert _reason(found=None) == probe.REASON_MISSING_TOOL


def test_restate_without_its_unit_is_outdated(monkeypatch):
    monkeypatch.setattr(probe, "features", lambda e, ask=None: GOOD)
    assert _reason(unit=False) == probe.REASON_TOOL_OUTDATED


@pytest.mark.parametrize(
    "features",
    [None, {}, {"version": "1.5.0.1", "job_keys": []}, {"version": "2.0.0.0"},
     {"version": "two", "job_keys": []}],
)  # fmt: skip
def test_a_restate_too_old_to_drive_is_outdated(monkeypatch, features):
    monkeypatch.setattr(probe, "features", lambda e, ask=None: features)
    assert _reason() == probe.REASON_TOOL_OUTDATED


def test_a_current_restate_with_its_unit_is_usable(monkeypatch):
    monkeypatch.setattr(probe, "features", lambda e, ask=None: GOOD)
    assert _reason() is None


def test_linux_without_an_nfs_client_cannot_back_up(monkeypatch):
    """It could never mount its storage (nextcloud, 2026-10-29); Equip
    installs the client.  Missing restate is said first: Equip fixes both."""
    monkeypatch.setattr(probe, "features", lambda e, ask=None: GOOD)
    assert _reason(nfs=False) == probe.REASON_MISSING_NFS_CLIENT
    assert _reason(found=None, nfs=False) == probe.REASON_MISSING_TOOL
    assert _reason(system="FreeBSD", nfs=False) is None  # in the base system


def test_restate_is_asked_once_per_installed_binary(tmp_path):
    binary = tmp_path / "restate"
    binary.write_text("#!/bin/sh\n")
    calls = []

    def ask(executable):
        calls.append(executable)
        return GOOD

    assert probe.features(str(binary), ask) == GOOD
    assert probe.features(str(binary), ask) == GOOD
    assert len(calls) == 1
    os.utime(binary, (1, 1))  # an upgrade changes the mtime
    probe.features(str(binary), ask)
    assert len(calls) == 2


def test_a_missing_binary_has_no_features():
    assert probe.features("/nonexistent/restate", lambda e: GOOD) is None


# ---------------------------------------------------------------------------
# the contract module
# ---------------------------------------------------------------------------


def test_names_and_paths():
    pid = "3f2a0000-0000-4000-8000-0000000000c1"
    assert contract.job_name(pid, "capture") == f"{pid}.capture"
    assert (
        contract.job_path(pid, "capture") == f"/etc/restate/jobs.d/{pid}.capture.conf"
    )
    assert contract.unit_name(pid, "prune") == f"restate-job@{pid}.prune.service"
    assert contract.key_path(pid) == f"/etc/restate/keys/{pid}.asc"


def test_unit_installed_checks_every_unit_dir():
    seen = []
    assert not contract.unit_installed(lambda p: seen.append(p) or False)
    assert len(seen) == len(contract.UNIT_DIRS)
    assert contract.unit_installed(lambda p: p.startswith("/etc/systemd"))
    # a source build of restate installs here (t14, 2026-10-20)
    assert contract.unit_installed(
        lambda p: p == "/usr/local/lib/systemd/system/restate-job@.service"
    )


def test_render_job_puts_command_first_and_repeats_lists():
    text = contract.render_job(
        {"repository": "/mnt/b/h", "command": "capture", "append_only": True,
         "rules": ["/etc/restate/a", "/etc/restate/b"], "keep_last": 3}
    )  # fmt: skip
    lines = text.splitlines()
    assert lines[1] == "command = capture"
    assert "append_only = true" in lines
    assert lines.count("rules = /etc/restate/a") == 1
    assert "rules = /etc/restate/b" in lines
    assert "keep_last = 3" in lines


def test_render_job_refuses_a_newline_in_a_value():
    with pytest.raises(ValueError):
        contract.render_job({"command": "capture", "repository": "/mnt/x\nrules = /"})


def test_parse_features_and_unsupported_keys():
    assert contract.parse_features("not json") is None
    assert contract.parse_features("[1]") is None
    features = contract.parse_features('{"version": "2.0.0.0", "job_keys": ["a"]}')
    assert contract.features_usable(features)
    assert contract.unsupported_keys(features, ["a", "b", "b"]) == ["b"]


@pytest.mark.parametrize(
    "code,status",
    [(0, "ok"), (1, "different"), (2, "failed"), (3, "incomplete"),
     (4, "untrusted"), (5, "busy"), (9, "failed"), (None, "failed")],
)  # fmt: skip
def test_exit_codes_map_to_statuses(code, status):
    assert contract.status_for_exit(code) == status


def test_the_result_file_wins_over_the_unit_exit():
    result = contract.parse_result('{"schema": 1, "exit": 3, "status": "incomplete"}')
    assert contract.outcome(result, 0) == ("incomplete", 3)
    assert contract.outcome(None, 2) == ("failed", 2)
    assert contract.outcome(None, 0) == ("failed", 0)  # never ran
    assert contract.outcome({"exit": 1, "status": "bogus"}, 0) == ("different", 1)
    assert contract.outcome(None, None) == ("failed", None)


def test_parse_result_refuses_other_schemas_and_garbage():
    assert contract.parse_result('{"schema": 2, "exit": 0}') is None
    assert contract.parse_result("{") is None
    assert contract.parse_result("[]") is None
    assert contract.parse_result('{"exit": 0}') == {"exit": 0}  # schema defaults to 1


def test_last_progress_takes_the_newest_parsable_line():
    lines = ['{"phase": "walk"}', "garbage", '{"phase": "write", "paths": 9}', "[]"]
    assert contract.last_progress(lines) == {"phase": "write", "paths": 9}
    assert contract.last_progress([]) is None


# ``restate features --json`` job_keys from restate 2.0.0.1 (t14, 2026-10-20).
# The agent wrote ``progress_file`` -- the command-line option's name -- and
# every restate refused every job ("does not support: progress_file"), found
# only in the lab.  Every key the agent can render must be one restate takes.
RESTATE_2_0_JOB_KEYS = frozenset(
    [
        "all",
        "allow_unverified",
        "append_only",
        "baseline_content",
        "check_first",
        "command",
        "copy_to",
        "dry_run",
        "encrypt_to",
        "exclude",
        "include",
        "keep_daily",
        "keep_last",
        "keep_monthly",
        "keep_weekly",
        "metadata_only",
        "one_file_system",
        "progress",
        "quiesce",
        "quiesce_with",
        "read_all",
        "record",
        "report_group",
        "repository",
        "restore_root",
        "result",
        "root",
        "rules",
        "sign_with",
        "snapshot",
        "syslog",
        "tmpdir",
        "trusted_key",
        "whole_packs",
    ]
)


def test_every_key_the_agent_renders_is_a_restate_job_key():
    ours = (
        contract.BOOL_KEYS | contract.INT_KEYS | contract.LIST_KEYS
        | contract.SCALAR_KEYS
    )  # fmt: skip
    # Gated keys are sent only to a restate that lists them.
    assert sorted(ours - RESTATE_2_0_JOB_KEYS - contract.GATED_KEYS) == []
    assert not contract.GATED_KEYS & RESTATE_2_0_JOB_KEYS


def test_supports_reads_job_keys():
    assert contract.supports({"job_keys": ["create"]}, "create")
    assert not contract.supports({"job_keys": ["command"]}, "create")
    assert not contract.supports(None, "create")
