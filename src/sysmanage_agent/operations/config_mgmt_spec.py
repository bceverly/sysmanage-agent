# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Execute a server-supplied EXECUTION SPEC (Phase 20.1).

WHY THE AGENT NO LONGER KNOWS HOW TO DRIVE AN ENGINE
----------------------------------------------------
The first cut branched internally: ``_apply_with_ansible``, ``_apply_with_dsc``.
Adding Puppet, Salt and Chef the same way would have put the licensed adapters'
logic into this AGPL agent, where the only enforcement is the server declining
to dispatch -- and it would mean a new agent release on every managed host each
time a sixth engine is added.

So the agent stopped knowing about engines. It now receives a SPEC that says
what to run, what to feed it, and which SHAPE the results arrive in; the
knowledge of which flags to pass and what the exit codes mean is data, supplied
by whoever built the spec. ansible-core and DSC specs are built by the
open-source server; Puppet/Salt/Chef specs come from the Pro+
``config_management_engine``.

WHAT STAYS HERE, AND WHY THAT IS THE RIGHT LINE
-----------------------------------------------
Reading four generic result SHAPES is mechanical once you know the shape:
JSON-lines on stdout, one JSON document on stdout, a JSON file dropped in a
directory, and a bitmasked exit code. What is NOT mechanical -- and is
therefore not here -- is the measured knowledge that cost three days of
spikes:

  * that Puppet's ``--noop`` silently defeats ``--detailed-exitcodes``, so a
    dry run must be read from the last-run report instead;
  * that Salt reports ``result: None`` for "would change", which is falsy and
    turns every useful dry run into a reported failure if treated as a bool;
  * that Chef has no JSON formatter but a built-in ``JsonFile`` handler, and
    refuses to start without ``CHEF_LICENSE`` in its environment.

All of that lives in the spec builder.

SPEC SHAPE
----------
    {
      "engine":   "puppet",              # identity, for the result record
      "argv":     ["puppet", "apply", "{profile}", "--detailed-exitcodes"],
      "profile":  {"name": "site.pp", "content": "..."},   # optional
      "files":    [{"name": "client.rb", "content": "..."}],  # optional
      "stdin":    "@profile" | "<literal>" | null,
      "env":      {"CHEF_LICENSE": "accept"},              # optional
      "timeout":  1800,
      "result":   {"format": "...", ...}                   # see RESULT_FORMATS
    }

``{profile}`` and ``{workdir}`` in argv are substituted with real paths. Every
file is written into a 0700 temp directory that is removed afterwards, because
a profile can carry secrets and a world-readable temp file would expose them to
every local user for the life of the run.
"""

import os
import stat
import tempfile
from typing import Any, Dict, List, Optional, Tuple

# Result shapes the agent can read. Named rather than inferred so a spec is
# explicit about what it expects; an unknown format is an error the server can
# see rather than a silent misparse.
FORMAT_JSON_LINES = "json_lines"  # ansible: our callback, one object per line
FORMAT_JSON_STDOUT = "json_stdout"  # dsc, salt: one document on stdout
FORMAT_JSON_FILE = "json_file"  # chef: newest *.json under a directory
FORMAT_EXIT_CODE = "exit_code"  # puppet: meaning carried in the exit bits

RESULT_FORMATS = (
    FORMAT_JSON_LINES,
    FORMAT_JSON_STDOUT,
    FORMAT_JSON_FILE,
    FORMAT_EXIT_CODE,
)


class SpecError(ValueError):
    """A spec the agent cannot act on. Reported, never raised at the server."""


def validate(spec: Dict[str, Any]) -> Optional[str]:
    """Return a reason code if ``spec`` is unusable, else None."""
    if not isinstance(spec, dict):
        return "spec_not_an_object"
    argv = spec.get("argv")
    if not argv or not isinstance(argv, list) or not all(argv):
        return "spec_missing_argv"
    # argv only, never a shell string: nothing in a profile may become a
    # command, and the content-lifecycle work established this repo-wide.
    if any(not isinstance(a, str) for a in argv):
        return "spec_argv_not_strings"
    result = spec.get("result") or {}
    fmt = result.get("format")
    if fmt not in RESULT_FORMATS:
        return "spec_unknown_result_format"
    return None


def materialise(
    spec: Dict[str, Any], workdir: str
) -> Tuple[List[str], Optional[bytes]]:
    """Write the spec's files and resolve its argv and stdin.

    Returns ``(argv, stdin_bytes)``.  The workdir is created 0700 by the caller.
    """
    profile = spec.get("profile") or {}
    profile_path = ""
    if profile.get("content") is not None:
        # A relative path with directories is legitimate: Chef resolves a
        # runlist to cookbooks/<name>/recipes/default.rb, so the spec has to be
        # able to nest. Traversal out of the workdir is still refused.
        name = str(profile.get("name") or "profile")
        profile_path = _write_relative(workdir, name, str(profile["content"]))

    for extra in spec.get("files") or []:
        name = str(extra.get("name") or "")
        if not name:
            continue
        # Placeholders are substituted in the CONTENT of spec-supplied files
        # but never in the profile: these are engine configuration the spec
        # builder generated (Salt's minion file needs root_dir, Chef's
        # client.rb needs cookbook_path), whereas the profile is the operator's
        # own text and rewriting braces inside it would corrupt it.
        content = str(extra.get("content") or "").replace("{workdir}", workdir)
        _write_relative(workdir, name, content)

    argv = [
        arg.replace("{profile}", profile_path).replace("{workdir}", workdir)
        for arg in spec["argv"]
    ]

    stdin = spec.get("stdin")
    if stdin == "@profile":
        # Feeding the profile on stdin sidesteps the shell entirely, which is
        # what DSC needs: PowerShell 5.1 strips the quotes out of an inline
        # JSON argument and dsc then dies trying to parse it as YAML.
        stdin_bytes = str(profile.get("content") or "").encode("utf-8")
    elif isinstance(stdin, str):
        stdin_bytes = stdin.encode("utf-8")
    else:
        stdin_bytes = None
    return argv, stdin_bytes


def _write_relative(workdir: str, name: str, content: str) -> str:
    """Write ``name`` under ``workdir``, refusing to escape it.

    Nested names are allowed because some engines require a layout (Chef wants
    cookbooks/<name>/recipes/default.rb). Anything that resolves outside the
    workdir is collapsed to its basename rather than honoured: a spec is
    server-supplied, but a traversal in one must not be able to overwrite
    /etc/anything.
    """
    target = os.path.normpath(os.path.join(workdir, name))
    root = os.path.normpath(workdir)
    if not target.startswith(root + os.sep):
        target = os.path.join(root, os.path.basename(name))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    _write_private(target, content)
    return target


def _write_private(path: str, content: str) -> None:
    """Write a file only the agent user can read."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def make_workdir() -> str:
    """A 0700 scratch directory for one run's files."""
    workdir = tempfile.mkdtemp(prefix="sysmanage-cfg-")
    os.chmod(workdir, stat.S_IRWXU)
    return workdir


def child_env(spec: Dict[str, Any], base_env: Dict[str, str]) -> Dict[str, str]:
    """The environment for the child process.

    Spec-supplied values are layered ON TOP of the inherited environment rather
    than replacing it: an engine needs PATH and HOME as much as it needs its
    own variables, and Chef additionally refuses to start without CHEF_LICENSE
    -- which the spec supplies rather than the agent hardcoding.
    """
    env = dict(base_env)
    for key, value in (spec.get("env") or {}).items():
        env[str(key)] = str(value)
    return env
