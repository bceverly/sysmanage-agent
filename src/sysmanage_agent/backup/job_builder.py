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
NOT_AN_OBJECT = "parameters must be an object"


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
    # repack rewrites packs, so it shares the record like prune: its own
    # removals must not read as tampering on the next check.
    "repack": {},
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
        job = _action_keys(policy, action, keys)
        if action == "capture":
            job.update(_capture_keys(policy, key_installed, can_create))
        if action in _KEYLESS_STORAGE:
            job.update(_KEYLESS_STORAGE[action])
            job["record"] = record_path(state_dir, policy["policy_id"])
        if action == "protect":
            # After each capture, on the storage host: finished packs and
            # snapshots become root's and read-only, the directories sticky
            # and writable by the hosts' (mapped) group -- hosts append only.
            job["group"] = policy.get("service_account") or "restate"
        job.update(_reports(state_dir, policy["policy_id"], action, group))
        jobs[action] = job
    return jobs


def _action_keys(
    policy: Dict[str, Any], action: str, keys: Dict[str, Any]
) -> Dict[str, Any]:
    """The server's keys for ``action``, its rules file and repository."""
    job = {key: value for key, value in keys.items() if key not in _PATH_RULE_KEYS}
    if action in ("capture", "estimate") and policy_rules(policy):
        job["rules"] = list(job.get("rules") or []) + [rules_path(policy["policy_id"])]
    job["command"] = action
    if action != "estimate":  # estimate reads the live host, no repository
        job["repository"] = policy["repository"]
    return job


def _capture_keys(
    policy: Dict[str, Any], key_installed: bool, can_create: bool
) -> Dict[str, Any]:
    """What only a capture gets: the encryption key and ``create``."""
    extra: Dict[str, Any] = {}
    if key_installed:
        extra["encrypt_to"] = contract.key_path(policy["policy_id"])
    if can_create:
        extra["create"] = True
    return extra


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


_WILDCARDS = set("*?[")


def _in_place_includes(include: List[str]) -> List[str]:
    """An in-place restore names what it replaces: at least one pattern, each
    an absolute path whose first component is literal -- ``/etc/nginx`` or
    ``/home/*/.config``, never ``/``, ``/*`` or ``**/x``.  Putting a whole
    host back over itself is a rebuild (24.9, Enterprise), not a file
    restore."""
    if not include:
        raise v.PolicyError("a restore into place needs at least one path")
    for pattern in include:
        first = pattern.lstrip("/").split("/", 1)[0]
        if not pattern.startswith("/") or not first or _WILDCARDS & set(first):
            raise v.PolicyError(
                f"a restore into place needs specific paths, not {pattern!r}"
            )
    return include


def build_restore_job(
    params: Any,
    *,
    repository: str,
    state_dir: str,
    group: str,
    trusted_key: Optional[str] = None,
    can_plan: bool = False,
    decrypt_with: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """A restore job, into a staging directory the AGENT chooses or, with
    ``in_place``, over the host's own files.

    A preview (``dry_run``) becomes restate's ``plan`` when this restate
    takes it: the plan comes from the snapshot's index and the host's files,
    reading no pack, so it takes seconds; ``dry_run`` reads (and checks)
    every byte of the snapshot first.

    The server never chooses the root: it is ``<state>/restore/<run_id>``,
    or ``/`` for ``in_place`` (24.9).  In place, restate writes each file
    beside its destination, checks it against the snapshot's digest and
    renames it over the old one, never following a symbolic link, and
    ``check_first`` refuses a damaged snapshot before anything is written;
    the paths must be specific (``_in_place_includes``) and the agent's own
    state directory is always left out, so a restore cannot put back an old
    copy of the agent's database and host token.  Unsigned snapshots are
    restored only when the server explicitly allows it.
    """
    if not isinstance(params, dict):
        raise v.PolicyError(NOT_AN_OBJECT)
    run_id = v.check_uuid(params.get("run_id"), "run_id")
    policy_id = v.check_uuid(params.get("policy_id"), "policy_id")
    dry_run = params.get("dry_run", True)
    allow_unverified = params.get("allow_unverified", False)
    in_place = params.get("in_place", False)
    if not all(isinstance(x, bool) for x in (dry_run, allow_unverified, in_place)):
        raise v.PolicyError(
            "dry_run, allow_unverified and in_place must be true or false"
        )
    job: Dict[str, Any] = {
        "command": RESTORE_ACTION,
        "repository": repository,
        "restore_root": "/" if in_place else restore_root(state_dir, run_id),
        "dry_run": dry_run,
        "check_first": True,
    }
    if dry_run and can_plan:
        job["plan"] = True
        del job["dry_run"], job["check_first"]  # both read the packs
    if params.get("snapshot"):
        job["snapshot"] = v.check_snapshot(params["snapshot"])
    include = _patterns(params.get("include"), "include")
    exclude = _patterns(params.get("exclude"), "exclude")
    if in_place:
        include = _in_place_includes(include)
        exclude = exclude + [state_dir.rstrip("/") or "/"]
    if include:
        job["include"] = include
    if exclude:
        job["exclude"] = exclude
    if trusted_key:
        job["trusted_key"] = [trusted_key]
    elif allow_unverified:
        job["allow_unverified"] = True
    if decrypt_with:
        job["decrypt_with"] = list(decrypt_with)  # this run's key files
    job.update(_reports(state_dir, policy_id, RESTORE_ACTION, group))
    return job


LIST_ACTION = "list"
STATUS_ACTION = "status"
MAX_PATH = 4096


def _browse_path(value: Any) -> str:
    """An absolute, normalized path inside a snapshot (default ``/``)."""
    if value in (None, ""):
        return "/"
    if (
        not isinstance(value, str)
        or len(value) > MAX_PATH
        or not value.startswith("/")
        or posixpath.normpath(value) not in (value, value.rstrip("/"))
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise v.PolicyError("path must be an absolute, normalized path")
    return posixpath.normpath(value)


def build_list_job(
    params: Any,
    *,
    repository: str,
    state_dir: str,
    group: str,
    decrypt_with: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Browse one directory of a snapshot from its index alone (restate
    ``list``, 2.1.0.4+): no pack is read, so it takes seconds."""
    if not isinstance(params, dict):
        raise v.PolicyError(NOT_AN_OBJECT)
    policy_id = v.check_uuid(params.get("policy_id"), "policy_id")
    name = v.check_snapshot(params.get("snapshot"))
    job = {
        "command": LIST_ACTION,
        "snapshot": f"{repository}::{name}",
        "path": _browse_path(params.get("path")),
    }
    if decrypt_with:
        job["decrypt_with"] = list(decrypt_with)
    job.update(_reports(state_dir, policy_id, LIST_ACTION, group))
    return job


def build_status_job(
    params: Any,
    *,
    repository: str,
    state_dir: str,
    group: str,
    decrypt_with: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """What changed on this host since a snapshot (restate ``status`` as a
    job, 2.1.0.4+), the newest unless one is named.

    No classification keys: restate 2.2.0.2+ classifies the live tree by the
    rules the snapshot's capture recorded (``capture_rules`` in the result),
    and a ``rules`` key would REPLACE them.  2.2.0.1 refused ``rules`` in a
    status job outright; a snapshot from before 2.2.0.2 recorded no rules,
    so its status also lists what that capture left out (lab 2026-10-24).
    """
    if not isinstance(params, dict):
        raise v.PolicyError(NOT_AN_OBJECT)
    policy_id = v.check_uuid(params.get("policy_id"), "policy_id")
    job: Dict[str, Any] = {"command": STATUS_ACTION, "root": "/"}
    if params.get("snapshot"):
        job["snapshot"] = f"{repository}::{v.check_snapshot(params['snapshot'])}"
    else:
        job["repository"] = repository
    if decrypt_with:
        job["decrypt_with"] = list(decrypt_with)
    job.update(_reports(state_dir, policy_id, STATUS_ACTION, group))
    return job
