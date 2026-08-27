# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The config-management engine registry (Phase 20.1).

The contract this file defends is that an ENGINE NAME is a stable identity and
a BINARY is an implementation detail. Engine names are written into
`config_profile_run.executor`, into profile documents and into the API, so
changing one is a migration; changing which binary implements it must not be.
That is what makes a later Chef -> cinc-client move a one-line edit instead.
"""

import pytest

from src.sysmanage_agent.operations import config_mgmt_engines as engines


class TestIdentities:
    def test_engine_names_are_identities_not_binaries(self):
        # If any of these ever become "chef-client"/"salt-call", stored rows
        # and profile documents break.
        assert engines.CHEF == "chef"
        assert engines.SALT == "salt"
        assert engines.PUPPET == "puppet"
        assert engines.ANSIBLE == "ansible-core"
        assert engines.DSC == "dsc"

    def test_every_engine_carries_at_least_one_binary(self):
        for name, engine in engines.ENGINES.items():
            assert engine.binaries, f"{name} has no binary"
            assert isinstance(engine.binaries, tuple)

    def test_binaries_are_a_list_so_alternates_can_be_added(self):
        # The Chef -> cinc-client escape hatch: adding a second accepted binary
        # must not require touching anything else.
        assert isinstance(engines.ENGINES[engines.CHEF].binaries, tuple)

    def test_ansible_probes_the_playbook_runner_not_the_wrapper(self):
        # Some minimal packagings ship `ansible` without `ansible-playbook`,
        # and the pull path needs the playbook runner.
        assert engines.ENGINES[engines.ANSIBLE].binaries == ("ansible-playbook",)

    def test_salt_probes_the_masterless_entry_point(self):
        # `salt` is the master CLI and is useless to a pull-style agent.
        assert "salt-call" in engines.ENGINES[engines.SALT].binaries
        assert "salt" not in engines.ENGINES[engines.SALT].binaries


class TestDefaults:
    def test_windows_defaults_to_dsc(self):
        assert engines.default_engine("Windows") == engines.DSC

    @pytest.mark.parametrize(
        "system", ["Linux", "FreeBSD", "OpenBSD", "NetBSD", "Darwin"]
    )
    def test_posix_defaults_to_ansible(self, system):
        assert engines.default_engine(system) == engines.ANSIBLE

    def test_the_platform_answer_is_a_default_not_a_constraint(self):
        # Puppet, Salt and Chef all ship Windows agents. Treating DSC as the
        # only option on Windows is exactly the assumption this refactor
        # exists to remove.
        applicable = engines.applicable("Windows")
        for name in (engines.PUPPET, engines.SALT, engines.CHEF, engines.ANSIBLE):
            assert name in applicable

    def test_dsc_is_not_offered_off_windows(self):
        # The one genuinely platform-bound engine.
        assert engines.DSC not in engines.applicable("Linux")
        assert engines.DSC in engines.applicable("Windows")


class TestLookup:
    def test_a_named_engine_resolves(self):
        assert engines.get("salt").name == engines.SALT

    def test_lookup_is_case_and_space_insensitive(self):
        assert engines.get("  SALT ").name == engines.SALT

    def test_no_name_falls_back_to_the_platform_default(self):
        assert engines.get(None, "Windows").name == engines.DSC
        assert engines.get("", "Linux").name == engines.ANSIBLE

    def test_an_unknown_engine_is_none_rather_than_an_exception(self):
        # A profile naming an engine we do not implement is a bad request to
        # report, not a crash in the agent.
        assert engines.get("terraform") is None
