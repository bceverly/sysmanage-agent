# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""JSON-lines stdout callback for ansible-playbook (Phase 20.1).

THIS FILE RUNS INSIDE ANSIBLE'S INTERPRETER, NOT THE AGENT'S.
------------------------------------------------------------
ansible-core loads callback plugins by path, in whatever Python it was
installed under -- which on macOS is Homebrew's vendored 3.14 while the system
python3 is 3.13, and on NetBSD is /usr/pkg/bin/python3.13.  So this module must
NOT import anything from ``sysmanage_agent``: the agent package is simply not
on that interpreter's path.  The result schema is therefore duplicated between
here and ``config_mgmt_results.py``, and a test pins the two together.

WHY IT EXISTS
-------------
ansible-core bundles no ``json`` stdout callback (only default/junit/minimal/
oneline/tree), and ``tree`` overwrites per host so it cannot report per-task
state.  Rather than take a dependency or scrape human-readable output whose
format is upstream's to change, ~50 lines here give us per-task
ok/changed/failed/skipped/unreachable plus a recap, in a schema we own.

Keep this file dependency-free beyond ansible itself and the stdlib.
"""

from __future__ import absolute_import, division, print_function

import json

from ansible.plugins.callback import CallbackBase

__metaclass__ = type  # pylint: disable=invalid-name


class CallbackModule(CallbackBase):
    """Emit one JSON object per line: a record per task, then a recap."""

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "sysmanage_json"

    def _emit(self, payload):
        """Write one compact JSON line.

        Uses the display object rather than print() so ansible's own stream
        handling stays in charge, and sorts keys so identical runs produce
        byte-identical output (useful when diffing two runs of a profile).
        """
        self._display.display(json.dumps(payload, sort_keys=True, default=str))

    def _task(self, result, status, changed=False):
        self._emit(
            {
                "type": "task",
                "host": result._host.get_name(),  # pylint: disable=protected-access
                "task": result._task.get_name(),  # pylint: disable=protected-access
                "status": status,
                "changed": bool(changed),
                # ``msg`` is whatever the module reported; it is diagnostic
                # only. Never parse it -- status and changed are the contract.
                "msg": result._result.get("msg"),  # pylint: disable=protected-access
            }
        )

    def v2_runner_on_ok(self, result):
        changed = bool(
            result._result.get("changed")  # pylint: disable=protected-access
        )
        # "changed" is its own status, not a flavour of ok: idempotency
        # reporting is the whole point, so the two must not collapse.
        self._task(result, "changed" if changed else "ok", changed)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._task(result, "failed")

    def v2_runner_on_skipped(self, result):
        self._task(result, "skipped")

    def v2_runner_on_unreachable(self, result):
        # Reachable even in pull-style: a local connection can still fail, and
        # calling that success would report a host compliant when nothing ran.
        self._task(result, "unreachable")

    # Our recap key -> the key ansible's own summary uses for it.
    #
    # These are NOT all the same word, and the one that differs is the one that
    # matters most: ansible reports failures under "failures", so reading
    # summary["failed"] silently yields 0 for every failed run.  Caught by
    # running a deliberately failing playbook -- the per-task line said
    # "failed" while the recap claimed zero failures.
    _STAT_KEYS = {
        "ok": "ok",
        "changed": "changed",
        "failed": "failures",
        "skipped": "skipped",
        "unreachable": "unreachable",
    }

    def v2_playbook_on_stats(self, stats):
        totals = dict.fromkeys(self._STAT_KEYS, 0)
        for host in stats.processed:
            summary = stats.summarize(host)
            for ours, theirs in self._STAT_KEYS.items():
                totals[ours] += summary.get(theirs, 0)
        # ansible counts a changed task in BOTH ok and changed; subtract so the
        # recap agrees with the per-task lines, which report one status each.
        totals["ok"] = max(0, totals["ok"] - totals["changed"])
        totals["type"] = "recap"
        self._emit(totals)
