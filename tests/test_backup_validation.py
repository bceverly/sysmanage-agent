# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Backup policy validation and job building (Phase 24).

A job file runs AS ROOT, so these are the tests that matter most: everything
the server sends is hostile until proven otherwise.
"""

import pytest

from src.sysmanage_agent.backup import job_builder as builder
from src.sysmanage_agent.backup import job_validation as v

PID = "3f2a0000-0000-4000-8000-0000000000c1"
RID = "7b1c0000-0000-4000-8000-0000000000aa"
NFS = "36 25 0:44 / /mnt/sysmanage-backup rw,relatime shared:1 - nfs4 nas:/srv rw\n"
KEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENB\n-----END PGP PUBLIC KEY BLOCK-----"
)


def _params(**over):
    params = {
        "policy_id": PID,
        "role": "host",
        "target": {"mount_point": "/mnt/sysmanage-backup", "repo_dir": "nas-1a2b3c4d"},
        "jobs": {"capture": {"quiesce": True}, "snapshots": {}},
    }
    params.update(over)
    return params


def _check(params, mountinfo=NFS, **fs):
    fs.setdefault("realpath", lambda p: p)
    fs.setdefault("isdir", lambda p: True)
    return v.check_policy(params, mountinfo=lambda: mountinfo, **fs)


def test_a_good_host_policy_is_normalized():
    policy = _check(_params(encrypt_key=KEY))
    assert policy["repository"] == "/mnt/sysmanage-backup/nas-1a2b3c4d"
    assert policy["jobs"]["capture"] == {"quiesce": True, "append_only": True}
    assert policy["encrypt_key"].endswith("BLOCK-----\n")


@pytest.mark.parametrize("action", ["prune", "check", "copy", "seal"])
def test_a_host_may_never_delete_or_rewrite_its_history(action):
    with pytest.raises(v.PolicyError, match="host policy may not run"):
        _check(_params(jobs={"capture": {}, action: {}}))


def test_a_host_capture_cannot_turn_append_only_off():
    with pytest.raises(v.PolicyError, match="append-only"):
        _check(_params(jobs={"capture": {"append_only": False}}))


def test_a_storage_policy_may_not_capture():
    with pytest.raises(v.PolicyError, match="storage policy may not run"):
        _check(_params(role="storage", jobs={"capture": {}}))


@pytest.mark.parametrize(
    "target,why",
    [
        ({"mount_point": "/etc", "repo_dir": "x"}, "outside"),
        ({"mount_point": "relative", "repo_dir": "x"}, "absolute"),
        ({"mount_point": "/mnt/../etc", "repo_dir": "x"}, "plain path"),
        ({"mount_point": "/mnt/sysmanage-backup", "repo_dir": "../x"}, "single"),
        ({"mount_point": "/mnt/sysmanage-backup", "repo_dir": "a/b"}, "single"),
        ({"mount_point": "/mnt/sysmanage-backup", "repo_dir": ".hidden"}, "single"),
        ({"mount_point": "/mnt/sysmanage-backup", "repo_dir": ""}, "single"),
        ("not a dict", "object"),
    ],
)
def test_hostile_targets_are_refused(target, why):
    with pytest.raises(v.PolicyError, match=why):
        _check(_params(target=target))


def test_a_host_target_must_be_an_nfs_mount_right_now():
    local = "36 25 0:44 / /mnt/sysmanage-backup rw - ext4 /dev/sda1 rw\n"
    with pytest.raises(v.PolicyError, match="NFS"):
        _check(_params(), mountinfo=local)
    with pytest.raises(v.PolicyError, match="NFS"):
        _check(_params(), mountinfo="")


def test_a_symlinked_repository_cannot_escape_the_mount():
    def realpath(path):
        return "/etc/evil" if path.endswith("nas-1a2b3c4d") else path

    with pytest.raises(v.PolicyError, match="escapes"):
        _check(_params(), realpath=realpath)


def test_mountinfo_escapes_are_decoded():
    text = "36 25 0:44 / /mnt/my\\040backup rw - nfs nas:/x rw\n"
    assert v.mount_types(text) == {"/mnt/my backup": "nfs"}


def test_a_storage_target_must_be_a_directory():
    with pytest.raises(v.PolicyError, match="directory"):
        _check(
            _params(role="storage", jobs={"prune": {"keep_last": 3}},
                    target={"mount_point": "/srv/backups/restate", "repo_dir": "h-1"}),
            isdir=lambda p: False,
        )  # fmt: skip


@pytest.mark.parametrize(
    "job,why",
    [
        ({"command": "rm"}, "may not set"),
        ({"repository": "/"}, "may not set"),
        ({"result": "/etc/shadow"}, "may not set"),
        ({"encrypt_to": "/tmp/k"}, "may not set"),
        ({"quiesce": "yes"}, "true or false"),
        ({"rules": ["/tmp/rules"]}, "outside"),
        ({"rules": "/etc/restate/r"}, "list"),
        ({"rules": ["/etc/restate/../shadow"]}, "plain path"),
        ({"quiesce_with": ["Nextcloud"]}, "a-z0-9"),
        ({"quiesce_with": ["a b"]}, "a-z0-9"),
        ({"tmpdir": "/tmp"}, "outside"),
    ],
)
def test_hostile_capture_keys_are_refused(job, why):
    with pytest.raises(v.PolicyError, match=why):
        _check(_params(jobs={"capture": job}))


@pytest.mark.parametrize(
    "job,why",
    [
        ({"keep_last": -1}, "range"),
        ({"keep_last": 10**6}, "range"),
        ({"keep_last": True}, "integer"),
        ({"keep_last": "3"}, "integer"),
        ({"read_all": True}, "may not set"),
    ],
)
def test_hostile_prune_keys_are_refused(job, why):
    with pytest.raises(v.PolicyError, match=why):
        _check(
            _params(role="storage", jobs={"prune": job},
                    target={"mount_point": "/srv/backups/restate", "repo_dir": "h-1"})
        )  # fmt: skip


@pytest.mark.parametrize(
    "seal,ok",
    [
        ({"mode": "none"}, True),
        ({"mode": "zfs_snapshot", "dataset": "tank/backups"}, True),
        ({"mode": "zfs_snapshot", "dataset": "-o evil"}, False),
        ({"mode": "zfs_snapshot", "dataset": "tank/../x"}, False),
        ({"mode": "zfs_snapshot", "dataset": "tank backups"}, False),
        ({"mode": "zfs_snapshot"}, False),
        ({"mode": "btrfs"}, False),
        ({"mode": "none", "extra": 1}, False),
        # btrfs: read-only snapshots of the subvolume, kept OUTSIDE it
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/backups/restate",
                "snapshot_dir": "/srv/backups/.snapshots",
            },
            True,
        ),
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/backups/restate",
                "snapshot_dir": "/srv/backups/restate/.snapshots",
            },
            False,
        ),  # nested
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/backups/restate",
                "snapshot_dir": "/srv/backups/restate",
            },
            False,
        ),  # the same tree
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/backups/../etc",
                "snapshot_dir": "/srv/snaps",
            },
            False,
        ),
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "srv/backups",
                "snapshot_dir": "/srv/snaps",
            },
            False,
        ),  # relative
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/backups/",
                "snapshot_dir": "/srv/snaps",
            },
            False,
        ),  # not normalized
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/-o evil",
                "snapshot_dir": "/srv/snaps",
            },
            False,
        ),
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/b",
                "snapshot_dir": "/srv/-r",
            },
            False,
        ),
        ({"mode": "btrfs_snapshot", "subvolume": "/", "snapshot_dir": "/srv/s"}, False),
        ({"mode": "btrfs_snapshot", "subvolume": "/srv/b"}, False),  # missing key
        (
            {
                "mode": "btrfs_snapshot",
                "subvolume": "/srv/b",
                "snapshot_dir": "/srv/s",
                "dataset": "tank",
            },
            False,
        ),  # a key from another mode
    ],
)
def test_seal_jobs(seal, ok):
    params = _params(role="storage", jobs={"seal": seal},
                     target={"mount_point": "/srv/backups/restate", "repo_dir": "h-1"})  # fmt: skip
    if ok:
        assert _check(params)["jobs"]["seal"]["mode"] == seal["mode"]
    else:
        with pytest.raises(v.PolicyError):
            _check(params)


@pytest.mark.parametrize(
    "key",
    [
        "not a key",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----",
        KEY + "\nPRIVATE KEY",
        "x" * (v.MAX_KEY_BYTES + 1),
        123,
    ],
    # Short ids: the oversized key as an id overflowed Windows' 32767-character
    # PYTEST_CURRENT_TEST environment variable (CI, 2026-10-20).
    ids=["not-a-key", "private-block", "private-trailer", "oversized", "not-text"],
)
def test_only_an_armored_public_key_is_accepted(key):
    with pytest.raises(v.PolicyError):
        _check(_params(encrypt_key=key))


@pytest.mark.parametrize(
    "bad",
    [{"policy_id": "nope"}, {"role": "admin"}, {"jobs": {}}, {"jobs": []}],
)
def test_malformed_requests_are_refused(bad):
    with pytest.raises(v.PolicyError):
        _check(_params(**bad))


def test_unknown_actions_are_refused():
    with pytest.raises(v.PolicyError, match="may not run"):
        _check(_params(jobs={"format_disk": {}}))


# ---------------------------------------------------------------------------
# building the job files
# ---------------------------------------------------------------------------


def test_the_agent_fills_the_keys_it_controls():
    policy = _check(_params(jobs={"capture": {}, "snapshots": {}, "estimate": {}}))
    jobs = builder.build_jobs(policy, state_dir="/var/lib/a", group="sysmanage-agent",
                              key_installed=True)  # fmt: skip
    capture = jobs["capture"]
    assert capture["command"] == "capture"
    assert capture["repository"] == "/mnt/sysmanage-backup/nas-1a2b3c4d"
    assert capture["encrypt_to"] == f"/etc/restate/keys/{PID}.asc"
    assert capture["result"] == f"/var/lib/a/backup/{PID}.capture.result.json"
    assert capture["progress"] == f"/var/lib/a/backup/{PID}.capture.progress.ndjson"
    assert capture["report_group"] == "sysmanage-agent"
    assert "repository" not in jobs["estimate"]  # estimate reads the live host
    assert "encrypt_to" not in jobs["snapshots"]


def test_seal_is_not_a_restate_job():
    policy = _check(
        _params(role="storage", jobs={"seal": {"mode": "none"}, "check": {}},
                target={"mount_point": "/srv/backups/restate", "repo_dir": "h-1"})
    )  # fmt: skip
    jobs = builder.build_jobs(policy, state_dir="/s", group="g", key_installed=False)
    assert set(jobs) == {"check"}


def test_a_restore_always_lands_in_the_agents_staging_dir():
    job = builder.build_restore_job(
        {"run_id": RID, "policy_id": PID, "snapshot": "repo::20261020T030000Z",
         "include": ["/home/bob/**"], "restore_root": "/", "dry_run": False},
        repository="/mnt/b/h", state_dir="/var/lib/a", group="g",
    )  # fmt: skip
    assert job["restore_root"] == f"/var/lib/a/restore/{RID}"
    assert job["include"] == ["/home/bob/**"]
    assert job["dry_run"] is False and job["check_first"] is True
    assert "allow_unverified" not in job and "trusted_key" not in job


def test_a_restore_is_a_dry_run_unless_told_otherwise():
    job = builder.build_restore_job(
        {"run_id": RID, "policy_id": PID}, repository="/r", state_dir="/s", group="g"
    )
    assert job["dry_run"] is True


def test_unsigned_snapshots_restore_only_when_explicitly_allowed():
    allowed = builder.build_restore_job(
        {"run_id": RID, "policy_id": PID, "allow_unverified": True},
        repository="/r", state_dir="/s", group="g",
    )  # fmt: skip
    assert allowed["allow_unverified"] is True
    keyed = builder.build_restore_job(
        {"run_id": RID, "policy_id": PID, "allow_unverified": True},
        repository="/r", state_dir="/s", group="g", trusted_key="/etc/restate/keys/k.asc",
    )  # fmt: skip
    assert keyed["trusted_key"] == ["/etc/restate/keys/k.asc"]
    assert "allow_unverified" not in keyed


@pytest.mark.parametrize(
    "bad",
    [
        {"dry_run": "no"},
        {"allow_unverified": 1},
        {"include": "/home"},
        {"include": ["a\nb"]},
        {"include": [""]},
        {"exclude": ["x" * 600]},
        {"snapshot": "../x"},
        {"run_id": "nope"},
    ],
)
def test_hostile_restore_requests_are_refused(bad):
    params = {"run_id": RID, "policy_id": PID}
    params.update(bad)
    with pytest.raises(v.PolicyError):
        builder.build_restore_job(params, repository="/r", state_dir="/s", group="g")


def test_storage_prune_and_check_are_keyless_and_share_one_record():
    """The NAS holds no private key: restate 2.0 can only prune whole packs and
    check metadata there, and check and prune must share one --record or the
    prune's own removals read as tampering (restate session, 2026-10-20)."""
    policy = {
        "policy_id": "3f2a0e8c-1b2d-4c5e-8f90-123456789abc",
        "repository": "/srv/backups/restate/nas-test-3f2a0e8c",
        "jobs": {"prune": {"keep_last": 14}, "check": {"read_all": True}},
    }
    jobs = builder.build_jobs(
        policy, state_dir="/var/lib/sysmanage-agent", group="sysmanage-agent",
        key_installed=False,
    )  # fmt: skip
    assert jobs["prune"]["whole_packs"] is True
    assert jobs["check"]["metadata_only"] is True and jobs["check"]["read_all"] is False
    assert jobs["prune"]["record"] == jobs["check"]["record"]
    assert jobs["check"]["record"].startswith("/var/lib/sysmanage-agent/backup/")


def test_a_server_cannot_choose_the_record_path():
    """record is a PATH restate writes as root: agent-chosen, never sent."""
    assert "record" not in v.SERVER_KEYS["check"]
    assert "record" not in v.BOOLS


# ---------------------------------------------------------------------------
# operator path rules (keep_paths / skip_paths -> the policy's rules file)
# ---------------------------------------------------------------------------


def _rules_policy(keep=None, skip=None):
    capture = {"quiesce": False}
    if keep is not None:
        capture["keep_paths"] = keep
    if skip is not None:
        capture["skip_paths"] = skip
    return {"policy_id": PID, "role": "host", "repository": "/mnt/b/h",
            "jobs": {"capture": capture, "estimate": {}, "snapshots": {}}}  # fmt: skip


def test_path_rules_become_a_rules_file_and_never_job_keys():
    policy = _rules_policy(
        keep=["/home/*/Downloads"], skip=["**/previews", "/home/*/.cache"]
    )
    text = builder.policy_rules(policy)
    lines = [l for l in text.splitlines() if not l.startswith("#")]
    # keeps first, leave-outs last: restate's last matching rule wins
    assert lines == ["state /home/*/Downloads", "expendable **/previews",
                     "expendable /home/*/.cache"]  # fmt: skip
    jobs = builder.build_jobs(policy, state_dir="/s", group="g", key_installed=False)
    for action in ("capture", "estimate"):
        assert jobs[action]["rules"] == [builder.rules_path(PID)]
        assert "keep_paths" not in jobs[action] and "skip_paths" not in jobs[action]
    assert "rules" not in jobs["snapshots"]
    assert builder.rules_path(PID).startswith("/etc/restate/")


def test_no_path_rules_means_no_rules_file():
    policy = _rules_policy(keep=[], skip=[])
    assert builder.policy_rules(policy) is None
    jobs = builder.build_jobs(policy, state_dir="/s", group="g", key_installed=False)
    assert "rules" not in jobs["capture"]


@pytest.mark.parametrize(
    "pattern",
    ["", " /lead", "/trail ", "/a\nstate /etc", "#comment", "/tab\there", "x" * 513, 7],
    ids=["empty", "leading-space", "trailing-space", "newline", "comment", "tab",
         "too-long", "not-text"],
)  # fmt: skip
def test_a_path_pattern_that_could_break_the_rules_file_is_refused(pattern):
    with pytest.raises(v.PolicyError):
        v.check_job("host", "capture", {"skip_paths": [pattern]})


def test_path_patterns_are_allowed_on_capture_and_estimate_only():
    ok = v.check_job("host", "capture", {"keep_paths": ["/srv/data dir/x"]})
    assert ok["keep_paths"] == ["/srv/data dir/x"]
    v.check_job("host", "estimate", {"skip_paths": ["*.iso"]})
    with pytest.raises(v.PolicyError):
        v.check_job("storage", "prune", {"skip_paths": ["*.iso"]})


def test_a_storage_du_job_takes_nothing_from_the_server():
    assert v.check_job("storage", "du", {}) == {}
    with pytest.raises(v.PolicyError):
        v.check_job("storage", "du", {"keep_last": 1})
    assert "du" not in v.ROLES["host"]
    policy = {"policy_id": PID, "role": "storage", "repository": "/srv/b/h",
              "jobs": {"du": {}}}  # fmt: skip
    job = builder.build_jobs(policy, state_dir="/s", group="g", key_installed=False)[
        "du"
    ]
    assert job["command"] == "du" and job["repository"] == "/srv/b/h"
    assert set(job) == {"command", "repository", "result", "progress", "report_group"}


@pytest.mark.parametrize("can_plan", [True, False], ids=["plan", "no-plan"])
def test_a_restore_preview_plans_from_the_index_when_restate_can(can_plan):
    params = {"run_id": "7b1c0000-0000-4000-8000-0000000000aa", "policy_id": PID,
              "snapshot": "20261021T153126Z", "dry_run": True}  # fmt: skip
    job = builder.build_restore_job(params, repository="/mnt/b/h", state_dir="/s",
                                    group="g", can_plan=can_plan)  # fmt: skip
    if can_plan:
        assert job.get("plan") is True
        assert "dry_run" not in job and "check_first" not in job
    else:
        assert job["dry_run"] is True and "plan" not in job
    real = dict(params, dry_run=False)
    job = builder.build_restore_job(real, repository="/mnt/b/h", state_dir="/s",
                                    group="g", can_plan=True)  # fmt: skip
    assert "plan" not in job and job["dry_run"] is False  # a real restore
