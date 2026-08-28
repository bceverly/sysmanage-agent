# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Parse config-management executor output into a result the server can store.

WHY WE SHIP OUR OWN CALLBACK RATHER THAN PARSE ANSIBLE'S HUMAN OUTPUT
---------------------------------------------------------------------
``ansible-core`` bundles only the default/junit/minimal/oneline/tree stdout
callbacks.  There is no ``json`` one, and ``tree`` writes per-host files that
overwrite each other, so neither reports per-task state usably.  Scraping the
default human-readable output would make our result schema hostage to
upstream's formatting.

So the agent ships a ~50-line JSON-lines callback (``ansible_callbacks/``) and
this module consumes it.  The schema is OURS, it stays stable across ansible
releases, and it needs no extra dependency -- which also keeps the air-gap
story clean.

WHAT "CHANGED" IS FOR
---------------------
Idempotency reporting is the point of the whole feature: an operator needs to
see that the second run of a profile changed nothing.  ``changed`` is therefore
carried per task AND aggregated, and it is taken from the executor's own
report rather than inferred from text.

ROBUSTNESS
----------
Ansible writes deprecation notices and warnings to stdout ALONGSIDE the
callback's JSON.  A parser that assumes every line is JSON would fail a run
because of a warning about a config option.  Non-JSON lines are counted and
skipped, never fatal.
"""

import json
from typing import Any, Dict, List

# Line-type discriminators emitted by the callback plugin.
TYPE_TASK = "task"
TYPE_RECAP = "recap"

# Per-task keys.  Declared as constants because the callback plugin runs inside
# ANSIBLE's interpreter and cannot import this module, so the contract lives in
# two files -- and a test asserts the plugin still emits exactly these.
KEY_TYPE = "type"
KEY_HOST = "host"
KEY_TASK = "task"
KEY_STATUS = "status"
KEY_CHANGED = "changed"
KEY_MSG = "msg"

STATUS_OK = "ok"
STATUS_CHANGED = "changed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_UNREACHABLE = "unreachable"

# Statuses that mean the run did not do what was asked.  ``unreachable`` counts
# even though pull-style targets localhost: a local connection can still fail
# (a missing interpreter, for one), and treating it as success would report a
# host as compliant when nothing ran.
FAILURE_STATUSES = frozenset({STATUS_FAILED, STATUS_UNREACHABLE})


def _empty_recap() -> Dict[str, int]:
    return {
        STATUS_OK: 0,
        STATUS_CHANGED: 0,
        STATUS_FAILED: 0,
        STATUS_SKIPPED: 0,
        STATUS_UNREACHABLE: 0,
    }


def _decode_line(line: str):
    """One stdout line as a record dict, or None when it is not one.

    Ansible warnings and deprecations share this stream, so an undecodable
    line is ordinary noise rather than a fault.
    """
    try:
        record = json.loads(line)
    except (ValueError, TypeError):
        return None
    return record if isinstance(record, dict) else None


def _task_of(record: Dict[str, Any]) -> Dict[str, Any]:
    """One task record in the shape the server ingests."""
    return {
        KEY_HOST: record.get(KEY_HOST),
        KEY_TASK: record.get(KEY_TASK),
        KEY_STATUS: record.get(KEY_STATUS),
        KEY_CHANGED: bool(record.get(KEY_CHANGED)),
        KEY_MSG: record.get(KEY_MSG),
    }


def _read_lines(stdout: str):
    """Split stdout into tasks, a recap if one arrived, and a noise count."""
    tasks: List[Dict[str, Any]] = []
    recap = _empty_recap()
    saw_recap = False
    unparsed = 0

    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        record = _decode_line(line)
        if record is None:
            unparsed += 1
            continue

        kind = record.get(KEY_TYPE)
        if kind == TYPE_TASK:
            tasks.append(_task_of(record))
        elif kind == TYPE_RECAP:
            saw_recap = True
            for status in recap:
                recap[status] = int(record.get(status) or 0)
        else:
            unparsed += 1

    return tasks, recap, saw_recap, unparsed


def parse_stream(stdout: str, exit_code: int = 0) -> Dict[str, Any]:
    """Turn the executor's stdout into a structured result.

    ``exit_code`` participates in the verdict rather than being trusted alone:
    the spike confirmed ansible-playbook exits 2 on task failure, but a run can
    also die before emitting any recap (bad playbook, missing interpreter), and
    then the ONLY evidence of failure is the exit code.
    """
    tasks, recap, saw_recap, unparsed = _read_lines(stdout)

    # Derive from the tasks when the recap never arrived, so a truncated run
    # still reports what it managed to do.
    if not saw_recap:
        for task in tasks:
            status = task.get(KEY_STATUS)
            if status in recap:
                recap[status] += 1

    failed = (
        exit_code != 0
        or recap[STATUS_FAILED] > 0
        or recap[STATUS_UNREACHABLE] > 0
        or any(task.get(KEY_STATUS) in FAILURE_STATUSES for task in tasks)
    )

    return {
        "success": not failed,
        "changed": any(task.get(KEY_CHANGED) for task in tasks)
        or recap[STATUS_CHANGED] > 0,
        "tasks": tasks,
        "recap": recap,
        "exit_code": exit_code,
        "unparsed_lines": unparsed,
    }
