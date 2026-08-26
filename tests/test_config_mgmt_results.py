# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Parsing config-management executor output (Phase 20.1).

The load-bearing property is IDEMPOTENCY REPORTING: an operator has to be able
to see that the second run of a profile changed nothing.  That verdict is taken
from the executor's own per-task ``changed`` flag, never inferred from text, so
the tests below pin the distinction between "ok" and "changed" rather than
treating them as two spellings of success.

The second property is that a run must not be reported as successful when it
did not run.  Ansible-core exits 2 on task failure, but a playbook that dies
before emitting any recap leaves the exit code as the only evidence -- so the
exit code participates in the verdict instead of being trusted alone.
"""

import json
import os

from src.sysmanage_agent.operations import config_mgmt_results as results

PLUGIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src",
    "sysmanage_agent",
    "operations",
    "ansible_callbacks",
    "sysmanage_json.py",
)


def task(host="localhost", name="t", status="ok", changed=False, msg=None):
    return json.dumps(
        {
            "type": "task",
            "host": host,
            "task": name,
            "status": status,
            "changed": changed,
            "msg": msg,
        }
    )


def recap(**counts):
    payload = {
        "type": "recap",
        "ok": 0,
        "changed": 0,
        "failed": 0,
        "skipped": 0,
        "unreachable": 0,
    }
    payload.update(counts)
    return json.dumps(payload)


class TestIdempotency:
    def test_a_run_that_changed_nothing_reports_changed_false(self):
        stream = "\n".join([task(status="ok"), task(status="ok"), recap(ok=2)])
        parsed = results.parse_stream(stream, 0)
        assert parsed["success"] is True
        assert parsed["changed"] is False

    def test_a_single_changed_task_makes_the_whole_run_changed(self):
        stream = "\n".join(
            [
                task(status="ok"),
                task(status="changed", changed=True),
                recap(ok=1, changed=1),
            ]
        )
        parsed = results.parse_stream(stream, 0)
        assert parsed["changed"] is True
        assert parsed["success"] is True

    def test_changed_is_a_status_of_its_own_not_a_flavour_of_ok(self):
        stream = "\n".join([task(status="changed", changed=True), recap(changed=1)])
        parsed = results.parse_stream(stream, 0)
        assert parsed["tasks"][0]["status"] == "changed"
        assert parsed["recap"]["changed"] == 1
        assert parsed["recap"]["ok"] == 0


class TestFailure:
    def test_a_failed_task_fails_the_run(self):
        stream = "\n".join([task(status="failed"), recap(failed=1)])
        parsed = results.parse_stream(stream, 2)
        assert parsed["success"] is False

    def test_unreachable_is_a_failure_even_though_we_target_localhost(self):
        # A local connection can still fail -- a missing interpreter, say --
        # and calling that success reports a host compliant when nothing ran.
        stream = "\n".join([task(status="unreachable"), recap(unreachable=1)])
        parsed = results.parse_stream(stream, 4)
        assert parsed["success"] is False

    def test_nonzero_exit_fails_the_run_even_with_no_failed_tasks(self):
        # A playbook that dies before emitting a recap leaves the exit code as
        # the only evidence that anything went wrong.
        parsed = results.parse_stream("", 2)
        assert parsed["success"] is False

    def test_a_clean_run_with_exit_zero_succeeds(self):
        parsed = results.parse_stream(recap(ok=1), 0)
        assert parsed["success"] is True

    def test_skipped_tasks_are_not_failures(self):
        stream = "\n".join([task(status="skipped"), recap(skipped=1)])
        assert results.parse_stream(stream, 0)["success"] is True


class TestRobustness:
    def test_ansible_warnings_on_stdout_do_not_break_the_parse(self):
        # Ansible writes deprecation notices to the SAME stream as the
        # callback. A parser that assumed every line was JSON would fail a
        # perfectly good run because of a config warning.
        stream = "\n".join(
            [
                "[DEPRECATION WARNING]: something will be removed in 2.23.",
                task(status="changed", changed=True),
                "[WARNING]: provided hosts list is empty",
                recap(changed=1),
            ]
        )
        parsed = results.parse_stream(stream, 0)
        assert parsed["success"] is True
        assert parsed["changed"] is True
        assert parsed["unparsed_lines"] == 2

    def test_blank_lines_are_not_counted_as_noise(self):
        parsed = results.parse_stream("\n\n" + recap(ok=1) + "\n\n", 0)
        assert parsed["unparsed_lines"] == 0

    def test_a_truncated_run_still_reports_what_it_managed(self):
        # No recap line: derive the counts from the task lines rather than
        # reporting an empty run.
        stream = "\n".join([task(status="ok"), task(status="changed", changed=True)])
        parsed = results.parse_stream(stream, 0)
        assert parsed["recap"]["ok"] == 1
        assert parsed["recap"]["changed"] == 1

    def test_json_that_is_not_an_object_is_noise_not_a_crash(self):
        parsed = results.parse_stream('[1,2,3]\n"str"\n' + recap(ok=1), 0)
        assert parsed["unparsed_lines"] == 2
        assert parsed["success"] is True

    def test_empty_output_is_handled(self):
        parsed = results.parse_stream("", 0)
        assert parsed["success"] is True
        assert parsed["tasks"] == []

    def test_none_output_is_handled(self):
        assert results.parse_stream(None, 0)["tasks"] == []


class TestSchemaDrift:
    """The plugin runs in ANSIBLE's interpreter and cannot import the parser.

    That duplication is deliberate and unavoidable -- ansible-core may be under
    Homebrew's python while the agent is under the system one -- so the two
    halves of the contract are pinned together here instead.
    """

    def test_plugin_emits_every_key_the_parser_reads(self):
        with open(PLUGIN, encoding="utf-8") as handle:
            source = handle.read()
        for key in (
            results.KEY_TYPE,
            results.KEY_HOST,
            results.KEY_TASK,
            results.KEY_STATUS,
            results.KEY_CHANGED,
            results.KEY_MSG,
        ):
            assert f'"{key}"' in source, f"plugin no longer emits {key!r}"

    def test_plugin_emits_every_status_the_parser_knows(self):
        with open(PLUGIN, encoding="utf-8") as handle:
            source = handle.read()
        for status in (
            results.STATUS_OK,
            results.STATUS_CHANGED,
            results.STATUS_FAILED,
            results.STATUS_SKIPPED,
            results.STATUS_UNREACHABLE,
        ):
            assert f'"{status}"' in source, f"plugin no longer emits {status!r}"

    def test_plugin_maps_ansible_failures_key_not_failed(self):
        # Ansible's AggregateStats.summarize() reports failures under
        # "failures".  Reading summary["failed"] returns 0 for EVERY failed
        # run -- which is exactly what shipped until a deliberately failing
        # playbook was run against the plugin: the per-task line said "failed"
        # while the recap claimed zero failures.  The per-task status and the
        # exit code still caught the failure, but the counts an operator reads
        # were wrong.
        with open(PLUGIN, encoding="utf-8") as handle:
            source = handle.read()
        assert '"failures"' in source, "recap must read ansible's 'failures' key"

    def test_plugin_does_not_import_the_agent(self):
        # It runs under ansible's interpreter, where sysmanage_agent is simply
        # not importable. This would fail at runtime, on a customer's host.
        with open(PLUGIN, encoding="utf-8") as handle:
            source = handle.read()
        assert "sysmanage_agent" not in source.split('"""', 2)[-1]
