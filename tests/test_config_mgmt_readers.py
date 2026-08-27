# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Generic result-shape readers (Phase 20.1).

These readers must stay ENGINE-AGNOSTIC: every rule that varies by engine
arrives in the spec. The fixtures below therefore use the real shapes measured
during the 2026-08-27 spikes, driven by the rules a Pro+ spec builder emits --
if a reader ever needs to special-case an engine by name, the licensed
knowledge has leaked back into this AGPL code.
"""

import json
import os

from src.sysmanage_agent.operations import config_mgmt_readers as readers

SALT_RULES = {
    "format": "json_stdout",
    "entries_path": "local",
    "changed_key": "changes",
    "success_key": "result",
    # Salt uses None for "would change" in test mode. It is FALSY, so a bool
    # check reports every useful dry run as a failure -- the spec enumerates
    # what counts as ok instead of the reader guessing.
    "success_ok_values": [True, None],
    "name_key": "__id__",
}
SALT = {"engine": "salt", "result": SALT_RULES}
PUPPET = {
    "engine": "puppet",
    "result": {"format": "exit_code", "changed_bit": 2, "failed_bit": 4},
}


def salt_doc(*entries):
    return json.dumps({"local": {str(i): e for i, e in enumerate(entries)}})


class TestSaltShape:
    def test_a_fresh_run_is_successful_and_changed(self):
        doc = salt_doc({"__id__": "d", "changes": {"x": 1}, "result": True})
        out = readers.read(SALT, 0, doc, "", "/tmp")
        assert out["success"] is True and out["changed"] is True

    def test_a_second_run_is_successful_and_unchanged(self):
        doc = salt_doc({"__id__": "d", "changes": {}, "result": True})
        out = readers.read(SALT, 0, doc, "", "/tmp")
        assert out["success"] is True and out["changed"] is False

    def test_a_dry_run_that_would_change_is_not_a_failure(self):
        # The trap. result is None here, which is falsy; treating it as a bool
        # turns the most useful dry run into a reported failure.
        doc = salt_doc({"__id__": "d", "changes": {"x": 1}, "result": None})
        out = readers.read(SALT, 0, doc, "", "/tmp")
        assert out["success"] is True
        assert out["changed"] is True

    def test_a_failed_state_fails_the_run(self):
        doc = salt_doc({"__id__": "b", "changes": {}, "result": False})
        out = readers.read(SALT, 1, doc, "", "/tmp")
        assert out["success"] is False
        assert out["recap"]["failed"] == 1

    def test_a_missing_document_failure_key_is_not_read_as_a_failure(self):
        # _dig(doc, None) returns the whole document, which is truthy. An
        # unguarded lookup reported EVERY successful run as failed; caught by
        # replaying real Salt captures.
        doc = salt_doc({"__id__": "d", "changes": {}, "result": True})
        assert readers.read(SALT, 0, doc, "", "/tmp")["success"] is True


class TestDocumentFailureFlag:
    def test_a_named_document_flag_fails_the_run(self):
        # dsc's hadErrors, supplied by name rather than known to the reader.
        spec = {
            "engine": "dsc",
            "result": {
                "format": "json_stdout",
                "entries_path": "results",
                "failed_key": "hadErrors",
                "changed_key": "result.changedProperties",
            },
        }
        doc = json.dumps({"hadErrors": True, "results": []})
        assert readers.read(spec, 0, doc, "", "/tmp")["success"] is False


class TestExitCodeShape:
    def test_the_bits_come_from_the_spec_not_the_reader(self):
        # Puppet's 2 = changed, 4 = failed. A different engine with different
        # bits needs no code here.
        assert readers.read(PUPPET, 0, "", "", "/tmp")["changed"] is False
        assert readers.read(PUPPET, 2, "", "", "/tmp")["changed"] is True
        assert readers.read(PUPPET, 4, "", "", "/tmp")["success"] is False

    def test_both_bits_set_means_changed_and_failed(self):
        out = readers.read(PUPPET, 6, "", "", "/tmp")
        assert out["changed"] is True and out["success"] is False

    def test_without_a_failed_bit_any_nonzero_is_a_failure(self):
        spec = {"engine": "x", "result": {"format": "exit_code"}}
        assert readers.read(spec, 1, "", "", "/tmp")["success"] is False
        assert readers.read(spec, 0, "", "", "/tmp")["success"] is True


class TestChangedWhenPresent:
    def test_an_entry_list_can_mean_changed_by_existing(self):
        # Chef's report lists ONLY updated resources, so every entry is a
        # change and none carries a changed flag.
        spec = {
            "engine": "chef",
            "result": {
                "format": "json_stdout",
                "entries_path": "updated_resources",
                "changed_when_present": True,
                "name_key": "id",
            },
        }
        doc = json.dumps({"updated_resources": [{"id": "/tmp/x"}]})
        out = readers.read(spec, 0, doc, "", "/tmp")
        assert out["changed"] is True and out["recap"]["changed"] == 1

        empty = json.dumps({"updated_resources": []})
        assert readers.read(spec, 0, empty, "", "/tmp")["changed"] is False


class TestFileShape:
    def test_the_newest_matching_report_is_read(self, tmp_path):
        # Chef timestamps its report name rather than writing to stdout, so
        # the reader takes the newest match. The glob is spec-supplied.
        old = tmp_path / "chef-run-report-1.json"
        new = tmp_path / "chef-run-report-2.json"
        old.write_text(json.dumps({"updated_resources": []}))
        new.write_text(json.dumps({"updated_resources": [{"id": "a"}]}))
        os.utime(str(old), (1, 1))
        spec = {
            "engine": "chef",
            "result": {
                "format": "json_file",
                "report_glob": "chef-run-report-*.json",
                "entries_path": "updated_resources",
                "changed_when_present": True,
                "name_key": "id",
            },
        }
        assert readers.read(spec, 0, "", "", str(tmp_path))["changed"] is True

    def test_a_missing_report_falls_back_to_the_exit_code(self, tmp_path):
        spec = {"engine": "chef", "result": {"format": "json_file"}}
        out = readers.read(spec, 1, "", "", str(tmp_path))
        assert out["success"] is False
        assert out["reason"] == "no_output"


class TestNoOutput:
    def test_a_failing_run_that_prints_nothing_still_fails(self):
        # dsc does exactly this: exit non-zero, empty stdout.
        spec = {"engine": "dsc", "result": {"format": "json_stdout"}}
        out = readers.read(spec, 2, "", "boom", "/tmp")
        assert out["success"] is False
        assert out["stderr"] == "boom"

    def test_stderr_is_kept_only_on_failure(self):
        spec = {"engine": "salt", "result": SALT_RULES}
        doc = salt_doc({"__id__": "d", "changes": {}, "result": True})
        assert "stderr" not in readers.read(spec, 0, doc, "noise", "/tmp")


class TestEngineAgnosticism:
    def test_no_engine_is_named_in_the_readers(self):
        # The whole point: if a reader special-cases an engine, the licensed
        # knowledge has leaked back into AGPL code.
        import ast  # pylint: disable=import-outside-toplevel

        with open(readers.__file__, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        docstrings = {
            ast.get_docstring(n, clean=False)
            for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef))
        }
        literals = [
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and n.value not in docstrings
        ]
        for engine in ("puppet", "salt", "chef", "hadErrors", "updated_resources"):
            assert engine not in literals, f"{engine} is hardcoded in the readers"
