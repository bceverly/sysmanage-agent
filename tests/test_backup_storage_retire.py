# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Removing a moved host's old repository from the storage host (27.3):
only one the agent served itself for that policy, and how by what it is."""

# pylint: disable=protected-access,redefined-outer-name

import json
import os
import re
import sys
from unittest.mock import AsyncMock

import pytest

from src.sysmanage_agent.backup import proxy_access
from src.sysmanage_agent.backup import retire_mixin
from src.sysmanage_agent.backup import storage_retire as retire
from tests.backup_ops_support import (  # noqa: F401  pylint: disable=unused-import
    PID,
    RID,
    STORAGE_TARGET,
    _drain,
    _sent,
    agent,
    job_files,
    ops,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only feature")

REPO = "/srv/backups/restate/h-1"
NEW_REPO = "/srv/offsite/restate/h-1"
OTHER = "4c000000-0000-4000-8000-0000000000d2"


def _storage(target=None):
    return {"policy_id": PID, "role": "storage", "target": target or STORAGE_TARGET,
            "jobs": {"check": {"read_all": True}, "du": {}}}  # fmt: skip


def _present(monkeypatch, *paths):
    """These paths exist; the root probe finds the repository's marker
    when its path is one of them."""
    there = set(paths)
    monkeypatch.setattr(retire_mixin, "_exists", lambda path: path in there)
    marker = (
        REPO + "/" + retire.MARKER in there or NEW_REPO + "/" + retire.MARKER in there
    )
    state = retire.REPOSITORY if marker else retire.MISSING
    monkeypatch.setattr(retire_mixin.retire, "probe_state", lambda *a: state)
    return there


def _bare(ops):
    return [c[2:] if c[:2] == ["sudo", "-n"] else c for c in ops.fake.calls]


# --- what may be removed ---------------------------------------------------


def test_only_the_repository_the_policy_uses_here_is_forgotten():
    policies = {PID: {"role": "storage", "repository": REPO}}
    assert retire.check(policies, PID, REPO, forget=True)["repository"] == REPO
    for path, code in (("/srv/backups/restate/other", "not_ours"),
                       ("srv/backups/restate/h-1", "invalid_request"),
                       ("/srv/backups/restate/h-1/../x", "invalid_request"),
                       ("/srv", "invalid_request")):  # fmt: skip
        with pytest.raises(retire.RetireRefused) as refused:
            retire.check(policies, PID, path, forget=True)
        assert refused.value.code == code, path
    with pytest.raises(retire.RetireRefused) as refused:
        retire.check(policies, OTHER, REPO, forget=True)
    assert refused.value.code == "not_configured"
    host = {PID: {"role": "host", "repository": REPO}}
    with pytest.raises(retire.RetireRefused):
        retire.check(host, PID, REPO, forget=True)  # a backed-up host: never


def test_on_the_same_storage_host_only_a_former_repository_goes():
    policies = {PID: {"role": "storage", "repository": NEW_REPO, "former": [REPO]}}
    assert retire.check(policies, PID, REPO, forget=False)
    with pytest.raises(retire.RetireRefused) as refused:
        retire.check(policies, PID, NEW_REPO, forget=False)  # its current one
    assert refused.value.code == "not_ours"


def test_a_repository_another_policy_uses_is_never_removed():
    for other in (REPO + "/inner", "/srv/backups/restate"):
        policies = {PID: {"role": "storage", "repository": REPO},
                    OTHER: {"role": "storage", "repository": other}}  # fmt: skip
        with pytest.raises(retire.RetireRefused) as refused:
            retire.check(policies, PID, REPO, forget=True)
        assert refused.value.code == "in_use", other
    previous = {PID: {"role": "storage", "repository": REPO,
                      "previous": {"repository": REPO}}}  # fmt: skip
    with pytest.raises(retire.RetireRefused):
        retire.check(previous, PID, REPO, forget=True)


def test_a_configure_with_another_repository_remembers_the_old_one():
    old = {"role": "storage", "repository": REPO}
    new = {"role": "storage", "repository": NEW_REPO}
    assert retire.former(old, new) == [REPO]
    assert retire.former(dict(new, former=[REPO]), new) == [REPO]  # kept
    assert retire.former(dict(old, former=[NEW_REPO]), new) == [REPO]  # back again
    assert retire.former({"role": "host", "repository": REPO},
                         {"role": "host", "repository": NEW_REPO}) == []  # fmt: skip
    assert retire.former(None, new) == []


# --- how ------------------------------------------------------------------


def _plan(
    system="Linux",
    datasets=None,
    subvolume=False,
    state=retire.REPOSITORY,
):
    return retire.plan(REPO, system=system, state=state,
                       datasets=datasets or {}, is_subvolume=lambda p: subvolume)  # fmt: skip


def test_how_each_kind_of_repository_is_removed():
    zfs = _plan(datasets={REPO: "tank/backups/h-1"})
    assert zfs["commands"] == [["zfs", "destroy", "-r", "tank/backups/h-1"]]
    assert zfs["host_namespace"] is True
    thaw = ["chattr", "-a", "-i", "-R", REPO]
    assert _plan(subvolume=True)["commands"] == [
        thaw,
        ["btrfs", "subvolume", "delete", REPO],
    ]
    assert _plan()["commands"] == [thaw, ["rm", "-rf", "--", REPO]]
    assert _plan("FreeBSD")["commands"] == [["rm", "-rf", "--", REPO]]
    # The target's own dataset is never destroyed for one repository.
    assert _plan(datasets={REPO: "tank"})["kind"] == retire.storage_prepare.PLAIN


def test_a_directory_without_a_repository_is_left_alone_and_one_gone_is_done():
    with pytest.raises(retire.RetireRefused) as refused:
        _plan(state=retire.OTHER)
    assert refused.value.code == "not_a_repository"
    assert _plan(state=retire.MISSING)["kind"] == retire.GONE


def test_the_marker_is_looked_for_as_root():
    """The agent's account cannot enter a 0770 root:restate repository
    (lab, 2026-11-21: a real repository was refused as "not a restate
    repository"), so a privileged find looks."""
    assert retire.probe_argv(REPO)[:2] == ["find", REPO]
    marker = f"{REPO}/{retire.MARKER}\n"
    assert retire.probe_state(0, marker, "") == retire.REPOSITORY
    assert retire.probe_state(0, "", "") == retire.OTHER
    assert (
        retire.probe_state(1, "", f"find: '{REPO}': No such file or directory")
        == retire.MISSING
    )
    with pytest.raises(OSError):
        retire.probe_state(1, "", "find: Permission denied")


def test_the_freebsd_sudoers_rule_takes_exactly_a_repositorys_own_dataset():
    path = os.path.join(os.path.dirname(__file__), "..", "installer", "freebsd",
                        "sysmanage-agent.sudoers")  # fmt: skip
    with open(path, encoding="utf-8") as handle:
        rules = re.findall(r"/sbin/zfs (\^destroy .*\$)$", handle.read(), re.M)

    def ok(line):
        return any(re.fullmatch(rx.lstrip("^").rstrip("$"), line) for rx in rules)

    assert ok("destroy -r tank/backups/fed-ctrl.lab-20c7d0f8")
    assert ok("destroy -r tank/backups/t14-419718a7-enc")
    assert not ok("destroy -r tank/backups")
    assert not ok("destroy -r tank/backups/t14-419718a7 tank")


def test_linux_sudoers_destroy_in_the_hosts_namespace():
    for system in ("ubuntu", "centos", "opensuse"):
        with open(
            f"installer/{system}/sysmanage-agent.sudoers", encoding="utf-8"
        ) as handle:
            rules = handle.read()
        assert ("NOPASSWD: /usr/bin/nsenter --mount=/proc/1/ns/mnt -- "
                "/usr/sbin/zfs destroy -r *") in rules, system  # fmt: skip


# --- the agent runs it -----------------------------------------------------


@pytest.mark.asyncio
async def test_a_moved_hosts_repository_is_removed_and_the_policy_forgotten(
    ops, agent, job_files, monkeypatch, tmp_path
):
    monkeypatch.setattr(ops, "_zfs_datasets", AsyncMock(return_value={}))
    monkeypatch.setattr(ops, "_is_subvolume", lambda path: False)
    grants = tmp_path / "proxy.d"
    grants.mkdir()
    (grants / "h.conf").write_text(f"repository = {REPO}\noperations = append, read\n")
    (grants / "k.conf").write_text("repository = /srv/backups/restate/k-2\n")
    monkeypatch.setattr(proxy_access, "GRANTS_DIR", str(grants))
    assert (await ops.backup_configure(_storage()))["success"]
    job = str(job_files / f"{PID}.check.conf")
    export = retire.export_file(PID)
    _present(monkeypatch, REPO, REPO + "/" + retire.MARKER, job, export)
    ops.fake.calls.clear()
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "retire",
                                   "repository": REPO, "forget": True})  # fmt: skip
    assert answer["status"] == "started"
    await _drain(ops)
    bare = _bare(ops)
    assert bare.index(["chattr", "-a", "-i", "-R", REPO]) < bare.index(
        ["rm", "-rf", "--", REPO]
    )
    assert ["rm", "-f", "--", str(grants / "h.conf")] in bare
    assert ["rm", "-f", "--", str(grants / "k.conf")] not in bare
    assert ["rm", "-f", "--", job] in bare and ["exportfs", "-ra"] in bare
    report = _sent(agent, "backup_result")[-1]
    assert (report["action"], report["status"]) == ("retire", "ok")
    assert report["result"]["forgot"] is True
    with open(ops._state_file("policies.json"), encoding="utf-8") as handle:
        assert PID not in json.load(handle)


@pytest.mark.asyncio
async def test_a_request_for_anything_else_is_refused_at_once(ops, job_files):
    assert (await ops.backup_configure(_storage()))["success"]
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "retire",
                                   "repository": "/etc", "forget": True})  # fmt: skip
    assert answer["success"] is False and answer["reason"] == "invalid_request"
    answer = await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "retire",
                                   "repository": REPO, "forget": False})  # fmt: skip
    assert answer["reason"] == "not_ours"
    assert not ops._tasks


@pytest.mark.asyncio
async def test_a_move_on_the_same_storage_host_keeps_the_policy(
    ops, agent, job_files, monkeypatch
):
    monkeypatch.setattr(ops, "_zfs_datasets",
                        AsyncMock(return_value={REPO: "tank/backups/h-1"}))  # fmt: skip
    assert (await ops.backup_configure(_storage()))["success"]
    moved = {"mount_point": "/srv/offsite/restate", "repo_dir": "h-1"}
    assert (await ops.backup_configure(_storage(moved)))["success"]
    assert ops._policy(PID)["former"] == [REPO]
    _present(monkeypatch, REPO, REPO + "/" + retire.MARKER)
    ops.fake.calls.clear()
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "retire",
                          "repository": REPO})  # fmt: skip
    await _drain(ops)
    assert ["zfs", "destroy", "-r", "tank/backups/h-1"] in [
        [os.path.basename(c[0])] + c[1:] for c in _bare(ops)
    ]
    assert _sent(agent, "backup_result")[-1]["status"] == "ok"
    kept = ops._policy(PID)
    assert kept["repository"] == NEW_REPO and not kept.get("former")


@pytest.mark.asyncio
async def test_a_failed_removal_is_reported(ops, agent, job_files, monkeypatch):
    monkeypatch.setattr(ops, "_zfs_datasets", AsyncMock(return_value={}))
    monkeypatch.setattr(ops, "_is_subvolume", lambda path: False)
    assert (await ops.backup_configure(_storage()))["success"]
    _present(monkeypatch, REPO, REPO + "/" + retire.MARKER)
    ops.fake.fail[("rm", "-rf")] = (1, "Operation not permitted")
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "retire",
                          "repository": REPO, "forget": True})  # fmt: skip
    await _drain(ops)
    report = _sent(agent, "backup_result")[-1]
    assert report["status"] == "failed"
    assert "Operation not permitted" in report["result"]["errors"][0]
    assert ops._policy(PID) is not None  # nothing forgotten


def test_other_entries_naming_the_same_repository_go_with_it():
    """A move's copy there, or an off-site copy the server has dropped, is
    the same directory: forgotten with it.  A backed-up host's entry with
    that path still refuses."""
    policies = {PID: {"role": "storage", "repository": REPO},
                OTHER: {"role": "storage", "repository": REPO}}  # fmt: skip
    assert retire.check(policies, PID, REPO, forget=True)
    assert retire.sharers(policies, PID, REPO) == [OTHER]
    policies[OTHER]["role"] = "host"
    with pytest.raises(retire.RetireRefused):
        retire.check(policies, PID, REPO, forget=True)


@pytest.mark.asyncio
async def test_a_copy_entry_sharing_the_repository_is_forgotten_too(
    ops, agent, job_files, monkeypatch
):
    monkeypatch.setattr(ops, "_zfs_datasets", AsyncMock(return_value={}))
    monkeypatch.setattr(ops, "_is_subvolume", lambda path: False)
    assert (await ops.backup_configure(_storage()))["success"]
    copy = dict(_storage(), policy_id=OTHER)
    assert (await ops.backup_configure(copy))["success"]
    _present(monkeypatch, REPO, REPO + "/" + retire.MARKER)
    await ops.backup_run({"run_id": RID, "policy_id": PID, "action": "retire",
                          "repository": REPO, "forget": True})  # fmt: skip
    await _drain(ops)
    report = _sent(agent, "backup_result")[-1]
    assert report["status"] == "ok" and report["result"]["also_forgot"] == [OTHER]
    assert ops._policy(OTHER) is None and ops._policy(PID) is None
