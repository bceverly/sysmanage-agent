# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The restate contract, in ONE place (server ROADMAP Phase 24).

Everything that depends on how restate itself behaves lives here and nowhere
else: where job files go, how a job file is written, what the feature probe
must say, what the result and progress files look like, and how exit codes
map to statuses.  restate is a separate project with its own releases, so a
change on its side is a change to this file only.

The contract was agreed with the restate project on 2026-10-20 for restate
2.0.0.0:

* ``restate features --json`` prints one JSON object: ``version``,
  ``job_keys`` (every key a job file may use), ``commands``, ``options``,
  ``hooks`` (the hooks present on this host).
* A job file is ``/etc/restate/jobs.d/<name>.conf``: one ``key = value`` per
  line, ``#`` comments, repeatable keys repeated.  It must be root-owned and
  not group- or world-writable; restate refuses an unknown key, a duplicated
  scalar or a bad value (exit 2).
* ``restate-job@.service`` runs ``/usr/sbin/restate run
  /etc/restate/jobs.d/%i.conf``.
* The result is one JSON object written atomically to the job's ``result``
  path; progress is NDJSON appended to the ``progress`` path.  restate runs with
  umask 077, so both are 0600 root unless ``report_group`` names a group --
  which is why every job names the agent's own group.
"""

import json
import os
import posixpath
from typing import Any, Dict, Iterable, List, Optional, Tuple

JOBS_DIR = "/etc/restate/jobs.d"
KEYS_DIR = "/etc/restate/keys"
UNIT_TEMPLATE = "restate-job@.service"
# Where a package or a local install puts the unit (any one will do).  A
# source build's ``make install`` uses /usr/local/lib/systemd/system, which
# systemd also loads from.
UNIT_DIRS = (
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
)

MIN_MAJOR = 2
RESULT_SCHEMA = 1

# Exit status -> result status (restate's own words, the server's too).
EXIT_STATUS = {
    0: "ok",
    1: "different",
    2: "failed",
    3: "incomplete",
    4: "untrusted",
    5: "busy",
}

# Every key the agent may render, by kind.  The probe's ``job_keys`` must
# list each one a job actually uses, or that restate is too old for it.
BOOL_KEYS = frozenset(
    {
        "all",
        "baseline_content",
        "quiesce",
        "one_file_system",
        "append_only",
        "read_all",
        "metadata_only",
        "record",
        "whole_packs",
        "dry_run",
        "check_first",
        "allow_unverified",
        "syslog",
    }
)
INT_KEYS = frozenset({"keep_last", "keep_daily", "keep_weekly", "keep_monthly"})
LIST_KEYS = frozenset({"rules", "quiesce_with", "include", "exclude", "trusted_key"})
SCALAR_KEYS = frozenset(
    {
        "command",
        "repository",
        "snapshot",
        "copy_to",
        "restore_root",
        "tmpdir",
        "encrypt_to",
        "result",
        "progress",
        "report_group",
        "sign_with",
    }
)


def job_name(policy_id: str, action: str) -> str:
    """``<policy uuid>.<action>``: the unit instance and the job file stem."""
    return f"{policy_id}.{action}"


def job_path(policy_id: str, action: str) -> str:
    return posixpath.join(JOBS_DIR, job_name(policy_id, action) + ".conf")


def key_path(policy_id: str) -> str:
    return posixpath.join(KEYS_DIR, policy_id + ".asc")


def unit_name(policy_id: str, action: str) -> str:
    return f"restate-job@{job_name(policy_id, action)}.service"


def unit_installed(exists=os.path.exists) -> bool:
    return any(exists(posixpath.join(d, UNIT_TEMPLATE)) for d in UNIT_DIRS)


# ---------------------------------------------------------------------------
# feature probe
# ---------------------------------------------------------------------------


def parse_features(stdout: str) -> Optional[Dict[str, Any]]:
    """The probe's JSON object, or None when it is not one."""
    try:
        data = json.loads(stdout or "")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _major(version: Any) -> int:
    try:
        return int(str(version).split(".", 1)[0])
    except ValueError:
        return 0


def features_usable(features: Optional[Dict[str, Any]]) -> bool:
    """A restate this agent can drive: major >= 2 and it lists its job keys."""
    if not features:
        return False
    keys = features.get("job_keys")
    return _major(features.get("version")) >= MIN_MAJOR and isinstance(keys, list)


def unsupported_keys(features: Dict[str, Any], keys: Iterable[str]) -> List[str]:
    """Keys a job uses that this restate does not list."""
    known = set(features.get("job_keys") or [])
    return sorted(k for k in set(keys) if k not in known)


# ---------------------------------------------------------------------------
# job files
# ---------------------------------------------------------------------------


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_job(job: Dict[str, Any]) -> str:
    """A job file's text.  ``command`` first; list keys one line per item.

    The values have been validated already (``backup.job_validation``); this
    only refuses what would break the line format itself.
    """
    lines = ["# Written by sysmanage-agent; replaced on every configure."]
    for key in ["command"] + sorted(k for k in job if k != "command"):
        values = job[key] if isinstance(job[key], list) else [job[key]]
        for value in values:
            text = _value(value)
            if "\n" in text or "\r" in text:
                raise ValueError(f"newline in job value for {key}")
            lines.append(f"{key} = {text}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# results and progress
# ---------------------------------------------------------------------------


def status_for_exit(code: Optional[int]) -> str:
    return EXIT_STATUS.get(code, "failed") if code is not None else "failed"


def parse_result(text: str) -> Optional[Dict[str, Any]]:
    """The result object, or None when the file is not a schema-1 result."""
    try:
        data = json.loads(text or "")
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("schema", RESULT_SCHEMA) != RESULT_SCHEMA:
        return None
    return data


def outcome(
    result: Optional[Dict[str, Any]], unit_exit: Optional[int]
) -> Tuple[str, Optional[int]]:
    """``(status, exit)``: the result file wins; the unit's exit is a fallback.

    A run that left no result is never ``ok``: a unit that never started also
    shows ``ExecMainStatus=0``.
    """
    if result is not None and isinstance(result.get("exit"), int):
        code = result["exit"]
        status = result.get("status")
        if status not in EXIT_STATUS.values():
            status = status_for_exit(code)
        return status, code
    if unit_exit == 0:
        return "failed", unit_exit
    return status_for_exit(unit_exit), unit_exit


def last_progress(lines: Iterable[str]) -> Optional[Dict[str, Any]]:
    """The newest parsable progress object among ``lines``."""
    latest = None
    for line in lines:
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict):
            latest = data
    return latest
