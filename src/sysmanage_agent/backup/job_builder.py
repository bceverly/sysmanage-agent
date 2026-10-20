# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Complete a validated policy into restate job files (server ROADMAP 24.2).

The server sends only the keys an operator chooses; the agent adds the ones
it must control itself -- which command runs, against which repository, and
where the result lands -- so the server can never point a root job at an
arbitrary path.
"""

import posixpath
from typing import Any, Dict, List, Optional

from src.sysmanage_agent.backup import job_validation as v
from src.sysmanage_agent.backup import restate_contract as contract

RESTORE_ACTION = "restore"
MAX_PATTERNS = 100
MAX_PATTERN = 512


def result_path(state_dir: str, policy_id: str, action: str) -> str:
    return posixpath.join(state_dir, "backup", f"{policy_id}.{action}.result.json")


def progress_path(state_dir: str, policy_id: str, action: str) -> str:
    return posixpath.join(state_dir, "backup", f"{policy_id}.{action}.progress.ndjson")


def restore_root(state_dir: str, run_id: str) -> str:
    return posixpath.join(state_dir, "restore", run_id)


def _reports(state_dir: str, policy_id: str, action: str, group: str) -> Dict[str, Any]:
    return {
        "result": result_path(state_dir, policy_id, action),
        "progress": progress_path(state_dir, policy_id, action),
        "report_group": group,
    }


RULES_DIR = "/etc/restate/rules.d"
# Keys that become the policy's rules file, never job keys.
_PATH_RULE_KEYS = ("keep_paths", "skip_paths")


def rules_path(policy_id: str) -> str:
    """The policy's own rules file: root-owned, under /etc/restate."""
    return posixpath.join(RULES_DIR, f"{policy_id}.rules")


def policy_rules(policy: Dict[str, Any]) -> Optional[str]:
    """The rules file for the operator's paths, or None when there are none.

    ``keep_paths`` are ``state`` (kept even where the built-in rules leave
    them out, e.g. ~/Downloads), ``skip_paths`` are ``expendable`` (left
    out, as restate treats caches).  restate's LAST matching rule wins, so
    the skips come after the keeps: a path matching both is left out.
    """
    capture = policy["jobs"].get("capture") or {}
    keep = capture.get("keep_paths") or []
    skip = capture.get("skip_paths") or []
    if not keep and not skip:
        return None
    lines = ["# Written by sysmanage-agent from the backup policy; replaced on"]
    lines.append("# every configure.  Later rules win: leave-outs follow keeps.")
    lines += [f"state {pattern}" for pattern in keep]
    lines += [f"expendable {pattern}" for pattern in skip]
    return "\n".join(lines) + "\n"


def record_path(state_dir: str, policy_id: str) -> str:
    """The repository-state record shared by ``check`` and ``prune``.

    restate's ``check --record`` reports each change once, then records what
    it saw; ``prune`` must use the SAME record or its own removals read as
    tampering on the next check (restate 2.0).  Agent-chosen, like result.
    """
    return posixpath.join(state_dir, "backup", f"{policy_id}.record")


# The storage host (the NAS) holds no private key, so restate can only prune
# whole packs and check metadata there (restate 2.0): forced, never left to
# the server, so a keyless repository is never asked for what needs the key.
_KEYLESS_STORAGE = {
    "prune": {"whole_packs": True},
    "check": {"metadata_only": True, "read_all": False},
}


def build_jobs(
    policy: Dict[str, Any],
    *,
    state_dir: str,
    group: str,
    key_installed: bool,
    can_create: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """``{action: full job}`` for every restate action in the policy.

    ``seal`` is not a restate job (the agent snapshots the NAS's dataset
    itself), so it is left out here.  ``can_create``: this restate takes the
    capture key ``create``, so a host's first capture makes its repository
    (over NFS only the HOST can: the storage side's files must belong to the
    export's mapped user).
    """
    jobs = {}
    for action, keys in policy["jobs"].items():
        if action == "seal":
            continue
        job = dict(keys)
        for key in _PATH_RULE_KEYS:
            job.pop(key, None)
        if action in ("capture", "estimate") and policy_rules(policy):
            job["rules"] = list(job.get("rules") or []) + [
                rules_path(policy["policy_id"])
            ]
        job["command"] = action
        if action != "estimate":  # estimate reads the live host, no repository
            job["repository"] = policy["repository"]
        if action == "capture" and key_installed:
            job["encrypt_to"] = contract.key_path(policy["policy_id"])
        if action == "capture" and can_create:
            job["create"] = True
        if action in _KEYLESS_STORAGE:
            job.update(_KEYLESS_STORAGE[action])
            job["record"] = record_path(state_dir, policy["policy_id"])
        job.update(_reports(state_dir, policy["policy_id"], action, group))
        jobs[action] = job
    return jobs


def _patterns(value: Any, what: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_PATTERNS:
        raise v.PolicyError(f"{what} must be a list of at most {MAX_PATTERNS}")
    for pattern in value:
        if (
            not isinstance(pattern, str)
            or not pattern
            or len(pattern) > MAX_PATTERN
            or any(ch in pattern for ch in "\n\r\x00")
        ):
            raise v.PolicyError(f"{what} patterns must be single-line text")
    return value


def build_restore_job(
    params: Any,
    *,
    repository: str,
    state_dir: str,
    group: str,
    trusted_key: Optional[str] = None,
) -> Dict[str, Any]:
    """A restore job into a staging directory the AGENT chooses.

    Never in place in this slice: ``restore_root`` is always
    ``<state>/restore/<run_id>``, whatever the server sends.  Unsigned
    snapshots are restored only when the server explicitly allows it.
    """
    if not isinstance(params, dict):
        raise v.PolicyError("parameters must be an object")
    run_id = v.check_uuid(params.get("run_id"), "run_id")
    policy_id = v.check_uuid(params.get("policy_id"), "policy_id")
    dry_run = params.get("dry_run", True)
    allow_unverified = params.get("allow_unverified", False)
    if not isinstance(dry_run, bool) or not isinstance(allow_unverified, bool):
        raise v.PolicyError("dry_run and allow_unverified must be true or false")
    job: Dict[str, Any] = {
        "command": RESTORE_ACTION,
        "repository": repository,
        "restore_root": restore_root(state_dir, run_id),
        "dry_run": dry_run,
        "check_first": True,
    }
    if params.get("snapshot"):
        job["snapshot"] = v.check_snapshot(params["snapshot"])
    include = _patterns(params.get("include"), "include")
    exclude = _patterns(params.get("exclude"), "exclude")
    if include:
        job["include"] = include
    if exclude:
        job["exclude"] = exclude
    if trusted_key:
        job["trusted_key"] = [trusted_key]
    elif allow_unverified:
        job["allow_unverified"] = True
    job.update(_reports(state_dir, policy_id, RESTORE_ACTION, group))
    return job
