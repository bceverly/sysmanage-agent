# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Server-supplied execution specs (Phase 20.1).

The spec exists so the agent stops knowing how to drive an engine: adding
Puppet/Salt/Chef as agent methods would put the licensed adapters' logic in
AGPL code and would need a new agent on every host for each engine added.

Two properties matter most.

**Secrets.** A profile can carry passwords and keys, so every file the spec
writes must be unreadable by other local users for the life of the run. A
world-readable temp file is the whole exposure.

**No shell, ever.** argv is a list of strings and nothing in a profile may
become a command.
"""

import os
import stat

from src.sysmanage_agent.operations import config_mgmt_spec as spec_mod


def spec(**over):
    base = {
        "engine": "puppet",
        "argv": ["puppet", "apply", "{profile}", "--detailed-exitcodes"],
        "profile": {"name": "site.pp", "content": "file { '/tmp/x': }"},
        "result": {"format": "exit_code"},
    }
    base.update(over)
    return base


class TestValidation:
    def test_a_good_spec_validates(self):
        assert spec_mod.validate(spec()) is None

    def test_a_spec_without_argv_is_refused(self):
        assert spec_mod.validate(spec(argv=[])) == "spec_missing_argv"

    def test_a_non_object_spec_is_refused(self):
        assert spec_mod.validate("puppet apply") == "spec_not_an_object"

    def test_argv_must_be_strings(self):
        # A dict or list smuggled into argv is a sign the server built the
        # spec wrong; better to refuse than to stringify something odd.
        assert spec_mod.validate(spec(argv=["puppet", {"x": 1}])) == (
            "spec_argv_not_strings"
        )

    def test_an_unknown_result_format_is_refused(self):
        # Named formats rather than inference: an unrecognised one is an error
        # the server can see, not a silent misparse.
        bad = spec(result={"format": "yaml_maybe"})
        assert spec_mod.validate(bad) == "spec_unknown_result_format"

    def test_every_declared_format_is_accepted(self):
        for fmt in spec_mod.RESULT_FORMATS:
            assert spec_mod.validate(spec(result={"format": fmt})) is None


class TestMaterialisation:
    def test_the_profile_is_written_and_substituted_into_argv(self, tmp_path):
        argv, _ = spec_mod.materialise(spec(), str(tmp_path))
        written = os.path.join(str(tmp_path), "site.pp")
        assert argv[2] == written
        assert os.path.isfile(written)

    def test_written_files_are_not_readable_by_other_users(self, tmp_path):
        # Profiles carry variables -- passwords, keys. This is the exposure.
        spec_mod.materialise(spec(), str(tmp_path))
        mode = os.stat(os.path.join(str(tmp_path), "site.pp")).st_mode
        assert not mode & stat.S_IRGRP
        assert not mode & stat.S_IROTH

    def test_extra_files_are_written_too(self, tmp_path):
        # Chef needs a client.rb alongside the recipe.
        spec_mod.materialise(
            spec(files=[{"name": "client.rb", "content": "log_level :warn"}]),
            str(tmp_path),
        )
        assert os.path.isfile(os.path.join(str(tmp_path), "client.rb"))

    def test_a_file_name_cannot_escape_the_workdir(self, tmp_path):
        # basename() the name: a spec is server-supplied, but a traversal in
        # one must not be able to overwrite /etc/anything.
        spec_mod.materialise(
            spec(files=[{"name": "../../evil.conf", "content": "x"}]), str(tmp_path)
        )
        assert os.path.isfile(os.path.join(str(tmp_path), "evil.conf"))
        assert not os.path.exists(os.path.join(str(tmp_path), "..", "..", "evil.conf"))

    def test_workdir_is_substituted(self, tmp_path):
        argv, _ = spec_mod.materialise(
            spec(argv=["chef-client", "--config", "{workdir}/client.rb"]), str(tmp_path)
        )
        assert argv[2] == f"{tmp_path}/client.rb"

    def test_stdin_can_carry_the_profile(self, tmp_path):
        # DSC needs this: PowerShell 5.1 strips the quotes out of an inline
        # JSON argument and dsc then dies parsing it as YAML.
        _, stdin = spec_mod.materialise(
            spec(stdin="@profile", profile={"name": "c.json", "content": '{"a":1}'}),
            str(tmp_path),
        )
        assert stdin == b'{"a":1}'

    def test_stdin_can_be_a_literal(self, tmp_path):
        _, stdin = spec_mod.materialise(spec(stdin="hello"), str(tmp_path))
        assert stdin == b"hello"

    def test_no_stdin_by_default(self, tmp_path):
        _, stdin = spec_mod.materialise(spec(), str(tmp_path))
        assert stdin is None

    def test_a_spec_with_no_profile_still_works(self, tmp_path):
        argv, _ = spec_mod.materialise(
            {"argv": ["salt-call", "--local", "state.apply"]}, str(tmp_path)
        )
        assert argv == ["salt-call", "--local", "state.apply"]


class TestWorkdir:
    def test_the_workdir_is_private(self):
        workdir = spec_mod.make_workdir()
        try:
            mode = os.stat(workdir).st_mode
            assert not mode & stat.S_IRGRP
            assert not mode & stat.S_IROTH
        finally:
            os.rmdir(workdir)


class TestEnvironment:
    def test_spec_env_layers_on_top_rather_than_replacing(self):
        # An engine needs PATH and HOME as much as its own variables.
        env = spec_mod.child_env(
            spec(env={"CHEF_LICENSE": "accept"}), {"PATH": "/usr/bin", "HOME": "/root"}
        )
        assert env["PATH"] == "/usr/bin"
        assert env["HOME"] == "/root"
        assert env["CHEF_LICENSE"] == "accept"

    def test_the_agent_hardcodes_no_engine_variables(self):
        """No engine's variable name may appear in EXECUTABLE code here.

        CHEF_LICENSE comes from the spec. If the agent set it itself that
        would be engine knowledge leaking back into AGPL code -- and the same
        for any future engine's variables.

        Checked via the AST rather than a substring search, because these
        names are legitimately DISCUSSED in the docstrings that explain why
        they are not hardcoded, and a naive grep cannot tell prose from code.
        """
        import ast  # pylint: disable=import-outside-toplevel

        with open(spec_mod.__file__, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())

        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc:
                    docstrings.add(doc)

        literals = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value not in docstrings
        ]
        for forbidden in ("CHEF_LICENSE", "ANSIBLE_STDOUT_CALLBACK", "--noop"):
            assert forbidden not in literals, f"{forbidden} is hardcoded in the agent"

    def test_a_spec_without_env_changes_nothing(self):
        env = spec_mod.child_env(spec(), {"PATH": "/usr/bin"})
        assert env == {"PATH": "/usr/bin"}


class TestPlaceholdersAndLayout:
    """Fixes found by running real engines through the spec (2026-08-27)."""

    def test_placeholders_are_substituted_in_generated_file_contents(self, tmp_path):
        # Salt's minion config needs root_dir to point at the workdir. argv-only
        # substitution left a literal "{workdir}" in the file, and salt-call
        # died with "expected str, bytes or os.PathLike object, not dict".
        spec_mod.materialise(
            spec(files=[{"name": "minion", "content": "root_dir: {workdir}\n"}]),
            str(tmp_path),
        )
        written = (tmp_path / "minion").read_text(encoding="utf-8")
        assert "{workdir}" not in written
        assert str(tmp_path) in written

    def test_placeholders_are_NOT_substituted_in_the_profile(self, tmp_path):
        # The profile is the operator's own text. Rewriting braces inside it
        # would corrupt a manifest that legitimately contains them.
        body = "notify { 'literal {workdir} stays': }"
        spec_mod.materialise(
            spec(profile={"name": "site.pp", "content": body}), str(tmp_path)
        )
        assert (tmp_path / "site.pp").read_text(encoding="utf-8") == body

    def test_a_nested_profile_path_is_created(self, tmp_path):
        # Chef resolves a runlist to cookbooks/<name>/recipes/default.rb, so
        # the spec must be able to nest rather than being flattened.
        argv, _ = spec_mod.materialise(
            spec(
                profile={
                    "name": "cookbooks/profile/recipes/default.rb",
                    "content": "directory '/tmp/x'",
                }
            ),
            str(tmp_path),
        )
        nested = tmp_path / "cookbooks" / "profile" / "recipes" / "default.rb"
        assert nested.is_file()
        assert argv[2] == str(nested)

    def test_a_nested_name_still_cannot_escape_the_workdir(self, tmp_path):
        # Nesting is allowed; traversal is not.
        spec_mod.materialise(
            spec(profile={"name": "../../../etc/evil.conf", "content": "x"}),
            str(tmp_path),
        )
        assert (tmp_path / "evil.conf").is_file()
        assert not os.path.exists("/etc/evil.conf")
