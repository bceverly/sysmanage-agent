# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Read the four generic result SHAPES a spec can declare (Phase 20.1).

These are shape readers, not engine adapters.  Each answers the same two
questions -- did it succeed, and did anything change -- from a different
container, using rules the SPEC supplies.  Which flags produced that container,
and what the numbers mean, is the spec builder's business.

The spec carries the semantics as data.  For example the exit-code reader is
told which bits mean "changed" and which mean "failed" rather than knowing that
Puppet uses 2 and 4; a different engine with different bits needs no code here.
"""

import glob
import json
import os
from typing import Any, Dict, List, Optional

import yaml

from src.sysmanage_agent.operations import config_mgmt_results as results
from src.sysmanage_agent.operations import config_mgmt_spec as spec_mod


def read(
    spec: Dict[str, Any],
    code: int,
    stdout: str,
    stderr: str,
    workdir: str,
) -> Dict[str, Any]:
    """Turn a finished run into the shared result shape."""
    rules = spec.get("result") or {}
    fmt = rules.get("format")

    if fmt == spec_mod.FORMAT_JSON_LINES:
        parsed = results.parse_stream(stdout, code)
    elif fmt == spec_mod.FORMAT_JSON_STDOUT:
        parsed = _from_document(_load(stdout), rules, code)
    elif fmt == spec_mod.FORMAT_JSON_FILE:
        parsed = _from_document(_load_newest(workdir, rules), rules, code)
    elif fmt == spec_mod.FORMAT_YAML_FILE:
        parsed = _from_document(_load_newest(workdir, rules, _load_yaml), rules, code)
    else:
        parsed = _from_exit_code(rules, code)

    parsed["executor"] = spec.get("engine")
    if not parsed["success"] and stderr:
        parsed["stderr"] = stderr[-4000:]
    return parsed


def _load(text: str) -> Optional[Any]:
    try:
        return json.loads(text) if (text or "").strip() else None
    except ValueError:
        return None


class _TagTolerantLoader(yaml.SafeLoader):
    """A SafeLoader that reads tagged nodes as plain data.

    Puppet's report is Ruby-serialised YAML: the root carries
    ``!ruby/object:Puppet::Transaction::Report`` and inner nodes carry their own
    tags, which makes plain ``safe_load`` raise on the very first line.

    Still SafeLoader-derived on purpose -- an unknown tag degrades to the dict,
    list or scalar underneath it and NOTHING is instantiated from the document.
    ``yaml.unsafe_load`` would parse the same file by constructing whatever
    Ruby class the tag names, which is arbitrary object construction driven by
    a file written by a process on the managed host.
    """


def _ignore_tag(loader, _tag_suffix, node):
    """Return a tagged node's underlying container, dropping the tag."""
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_scalar(node)


_TagTolerantLoader.add_multi_constructor("", _ignore_tag)


def _load_yaml(handle) -> Optional[Any]:
    """Parse a YAML report, tolerating engine-specific tags."""
    return yaml.load(handle, Loader=_TagTolerantLoader)  # nosec B506 - see class


def _load_newest(workdir: str, rules: Dict[str, Any], parse=json.load) -> Optional[Any]:
    """The most recent report a run dropped in a directory.

    Chef's JsonFile handler names its report with a timestamp rather than
    writing to stdout, so the reader takes the newest match instead of a fixed
    path. ``report_glob`` is spec-supplied; the agent does not know Chef's
    naming convention.

    ``parse`` selects the document syntax, so the same newest-file search
    serves both the JSON and YAML shapes.
    """
    pattern = rules.get("report_glob") or "*.json"
    candidates = sorted(
        glob.glob(os.path.join(workdir, "**", pattern), recursive=True),
        key=os.path.getmtime,
        reverse=True,
    )
    if not candidates:
        return None
    try:
        with open(candidates[0], "r", encoding="utf-8") as handle:
            return parse(handle)
    except (OSError, ValueError, yaml.YAMLError):
        return None


def _dig(document: Any, path: Optional[str]) -> Any:
    """Follow a dotted path, treating a missing step as None.

    Deliberately tiny: dotted keys only, no wildcards or filters. A richer
    query language here would be the engine knowledge creeping back in.
    """
    if not path:
        return document
    current = document
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _no_output_result(code: int) -> Dict[str, Any]:
    """The verdict when a run produced no parsable body at all.

    A failing run may print nothing -- dsc does exactly this -- so the exit
    code has to carry the verdict when the body is missing.
    """
    return {
        "success": code == 0,
        "changed": False,
        "tasks": [],
        "recap": _empty_recap(),
        "exit_code": code,
        "unparsed_lines": 0,
        "reason": "no_output" if code != 0 else None,
    }


def _entries_of(document: Any, rules: Dict[str, Any]) -> List[Any]:
    """The per-resource entries in a document, however the engine nests them."""
    entries = _dig(document, rules.get("entries_path"))
    if isinstance(entries, dict):
        # Salt keys its entries by state id; the values are what matter.
        entries = list(entries.values())
    return entries if isinstance(entries, list) else []


def _status_of(ok: bool, changed: bool) -> str:
    """The task status word for one entry."""
    if not ok:
        return "failed"
    return "changed" if changed else "ok"


def _tasks_of(entries: List[Any], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One task record per entry, in the shape the server ingests."""
    changed_key = rules.get("changed_key") or "changed"
    success_key = rules.get("success_key")
    # Values of the per-entry success field that do NOT mean failure. Salt uses
    # None for "would change" in test mode, which is falsy -- treating it as a
    # bool reports every useful dry run as a failure, so the spec lists what
    # counts instead of the reader guessing.
    ok_values = rules.get("success_ok_values", [True, None])
    # Some engines express "changed" by the entry EXISTING at all rather than
    # by a field: Chef's report lists only updated resources, so every entry in
    # it is a change and none carries a changed flag.
    changed_when_present = bool(rules.get("changed_when_present"))
    name_key = rules.get("name_key") or "name"
    message_key = rules.get("message_key")

    tasks: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        changed = True if changed_when_present else bool(_dig(entry, changed_key))
        ok = True if success_key is None else _dig(entry, success_key) in ok_values
        tasks.append(
            {
                "host": "localhost",
                "task": _dig(entry, name_key),
                "status": _status_of(ok, changed),
                "changed": changed,
                "msg": _dig(entry, message_key),
            }
        )
    return tasks


def _recap_of(tasks: List[Dict[str, Any]]) -> Dict[str, int]:
    """Counts by status, in the recap shape the server stores."""
    return {
        "ok": sum(1 for t in tasks if t["status"] == "ok"),
        "changed": sum(1 for t in tasks if t["status"] == "changed"),
        "failed": sum(1 for t in tasks if t["status"] == "failed"),
        "skipped": 0,
        "unreachable": 0,
    }


def _from_document(document: Any, rules: Dict[str, Any], code: int) -> Dict[str, Any]:
    """Read a JSON document using spec-supplied field names."""
    if document is None:
        return _no_output_result(code)

    tasks = _tasks_of(_entries_of(document, rules), rules)

    # A document-level failure flag (dsc's hadErrors) when the spec names one.
    #
    # Guarded on the key being SET: _dig(doc, None) returns the whole document,
    # which is truthy, so an unguarded lookup reported every successful run as
    # a failure. Found by replaying real Salt captures through the reader.
    failed_key = rules.get("failed_key")
    doc_failed = bool(_dig(document, failed_key)) if failed_key else False
    any_failed = any(t["status"] == "failed" for t in tasks)

    return {
        "success": code == 0 and not any_failed and not doc_failed,
        "changed": any(t["changed"] for t in tasks),
        "tasks": tasks,
        "recap": _recap_of(tasks),
        "exit_code": code,
        "unparsed_lines": 0,
    }


def _from_exit_code(rules: Dict[str, Any], code: int) -> Dict[str, Any]:
    """Read a bitmasked exit code.

    Puppet's --detailed-exitcodes is the case: 2 means changes were made and 4
    means failures, so 6 means both. The BITS come from the spec -- the reader
    does not know they are Puppet's.
    """
    changed_bit = int(rules.get("changed_bit") or 0)
    failed_bit = int(rules.get("failed_bit") or 0)
    changed = bool(changed_bit and code & changed_bit)
    failed = bool(failed_bit and code & failed_bit)
    if not failed_bit:
        failed = code != 0
    return {
        "success": not failed,
        "changed": changed,
        "tasks": [],
        "recap": dict(_empty_recap(), changed=1 if changed else 0),
        "exit_code": code,
        "unparsed_lines": 0,
    }


def _empty_recap() -> Dict[str, int]:
    return {"ok": 0, "changed": 0, "failed": 0, "skipped": 0, "unreachable": 0}
