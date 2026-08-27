# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Finding this host's config-management executor (Phase 20.1).

Two properties matter more than the happy path.

First, **the vendored copy must win over PATH on Windows**.  dsc.exe ships in
the MSI at a version we have tested against; silently preferring whatever a
developer installed globally would mean a host runs an engine we never
validated, and it would do so invisibly.

Second, **nothing here may execute anything**.  This module feeds
capability_probes, whose design rules forbid subprocess execution because it
runs on every registration and every live query.  A well-meaning
`ansible --version` added here would make the whole capability report shell
out, so the prohibition is pinned by a test rather than left to a comment.
"""

import os
from unittest.mock import patch

import pytest

from src.sysmanage_agent.operations import config_mgmt_locator as locator

MOD = "src.sysmanage_agent.operations.config_mgmt_locator"


class TestExecutorName:
    def test_windows_uses_dsc(self):
        with patch(f"{MOD}.platform.system", return_value="Windows"):
            assert locator.executor_name() == "dsc"

    @pytest.mark.parametrize(
        "system", ["Linux", "FreeBSD", "OpenBSD", "NetBSD", "Darwin"]
    )
    def test_every_posix_platform_uses_ansible(self, system):
        with patch(f"{MOD}.platform.system", return_value=system):
            assert locator.executor_name() == "ansible-core"

    def test_names_match_the_servers_plan_builder(self):
        # The server decides what to INSTALL and this decides what to RUN; if
        # the two names drift, the prerequisite card and the executor describe
        # different things to the operator.
        assert locator.WINDOWS_EXECUTOR == "dsc"
        assert locator.POSIX_EXECUTOR == "ansible-core"


class TestPosixDiscovery:
    def test_found_when_ansible_playbook_is_on_path(self):
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which", return_value="/usr/bin/ansible-playbook"
        ):
            assert locator.find_executor() == "/usr/bin/ansible-playbook"
            assert locator.is_available() is True

    def test_absent_executor_is_none_not_an_exception(self):
        # A POSIX host without ansible-core is the ordinary case the server's
        # prerequisite card exists to surface -- not an error condition.
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which", return_value=None
        ):
            assert locator.find_executor() is None
            assert locator.is_available() is False

    def test_looks_for_ansible_playbook_not_ansible(self):
        # The pull-style path runs a PLAYBOOK against localhost.  Some minimal
        # packagings provide the `ansible` wrapper without the playbook runner,
        # and probing the wrong name would advertise a host that cannot run.
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which", return_value=None
        ) as which:
            locator.find_executor()
            which.assert_called_once_with("ansible-playbook")


class TestWindowsDiscovery:
    def test_vendored_copy_is_preferred_over_path(self, tmp_path):
        vendored = tmp_path / "dsc" / "dsc.exe"
        vendored.parent.mkdir()
        vendored.write_text("")
        with patch(f"{MOD}.platform.system", return_value="Windows"), patch(
            f"{MOD}._agent_install_root", return_value=str(tmp_path)
        ), patch(f"{MOD}.shutil.which", return_value="C:\\Other\\dsc.exe") as which:
            assert locator.find_executor() == str(vendored)
            # PATH must not even be consulted once the vendored copy is found.
            which.assert_not_called()

    def test_falls_back_to_path_when_nothing_is_vendored(self, tmp_path):
        with patch(f"{MOD}.platform.system", return_value="Windows"), patch(
            f"{MOD}._agent_install_root", return_value=str(tmp_path)
        ), patch(f"{MOD}.shutil.which", return_value="C:\\Tools\\dsc.exe"):
            assert locator.find_executor() == "C:\\Tools\\dsc.exe"

    def test_missing_everywhere_is_none(self, tmp_path):
        with patch(f"{MOD}.platform.system", return_value="Windows"), patch(
            f"{MOD}._agent_install_root", return_value=str(tmp_path)
        ), patch(f"{MOD}.shutil.which", return_value=None):
            assert locator.find_executor() is None

    def test_undeterminable_install_root_still_tries_path(self):
        # Never raise just because __file__ resolution failed; degrade to PATH.
        with patch(f"{MOD}.platform.system", return_value="Windows"), patch(
            f"{MOD}._agent_install_root", return_value=None
        ), patch(f"{MOD}.shutil.which", return_value="C:\\Tools\\dsc.exe"):
            assert locator.find_executor() == "C:\\Tools\\dsc.exe"

    def test_expected_msi_layout_is_a_dsc_subdirectory(self):
        # Mirrors the WiX <Directory Id="DSCFOLDER" Name="dsc"> group; if the
        # installer layout moves, this is what should fail first.
        with patch(f"{MOD}._agent_install_root", return_value=os.sep + "root"):
            assert locator._windows_candidates() == [
                os.path.join(os.sep + "root", "dsc", "dsc.exe")
            ]


class TestNoSideEffects:
    """capability_probes forbids subprocess; pin it rather than trusting it."""

    def test_discovery_never_shells_out(self):
        import subprocess  # pylint: disable=import-outside-toplevel

        with patch.object(subprocess, "run") as run, patch.object(
            subprocess, "Popen"
        ) as popen, patch.object(subprocess, "check_output") as check_output:
            for system in ("Linux", "Windows", "Darwin"):
                with patch(f"{MOD}.platform.system", return_value=system):
                    locator.find_executor()
                    locator.is_available()
            run.assert_not_called()
            popen.assert_not_called()
            check_output.assert_not_called()

    def test_module_does_not_import_subprocess_at_all(self):
        # The strongest form of the rule: you cannot accidentally shell out
        # from a module that never imported the means to do it.
        with open(locator.__file__, encoding="utf-8") as handle:
            source = handle.read()
        assert "import subprocess" not in source
        assert "os.system" not in source


class TestPerEngineLookup:
    """A host may run several engines; the locator answers per engine.

    The old API answered "which executor does this host use?" with one value
    derived from the platform. That was right while there was one engine per
    platform and wrong the moment an operator could choose.
    """

    def test_a_named_engine_is_found_independently_of_the_default(self):
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which",
            side_effect=lambda n: "/usr/bin/salt-call" if n == "salt-call" else None,
        ):
            assert locator.find_engine("salt") == "/usr/bin/salt-call"
            # ansible is the platform default and is absent; that must not
            # affect the answer for salt.
            assert locator.find_engine("ansible-core") is None

    def test_available_engines_reports_the_whole_set(self):
        present = {"salt-call": "/usr/bin/salt-call", "puppet": "/usr/bin/puppet"}
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which", side_effect=present.get
        ):
            assert locator.available_engines() == {
                "salt": "/usr/bin/salt-call",
                "puppet": "/usr/bin/puppet",
            }

    def test_a_salt_only_host_can_still_run_profiles(self):
        # The regression this refactor exists to prevent: keying availability
        # off the platform default would report this host as unable to run
        # config management at all.
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which",
            side_effect=lambda n: "/usr/bin/salt-call" if n == "salt-call" else None,
        ):
            assert locator.is_available() is True

    def test_a_host_with_nothing_installed_is_unavailable(self):
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which", return_value=None
        ):
            assert locator.is_available() is False
            assert locator.available_engines() == {}

    def test_an_unknown_engine_is_none_not_an_exception(self):
        with patch(f"{MOD}.platform.system", return_value="Linux"):
            assert locator.find_engine("terraform") is None

    def test_dsc_is_not_looked_for_off_windows(self):
        # It is the one platform-bound engine; probing for it on Linux would
        # report an engine that cannot run there.
        with patch(f"{MOD}.platform.system", return_value="Linux"), patch(
            f"{MOD}.shutil.which", return_value="/usr/bin/anything"
        ):
            assert "dsc" not in locator.available_engines()

    def test_the_vendored_windows_copy_still_wins_over_path(self, tmp_path):
        vendored = tmp_path / "dsc" / "dsc.exe"
        vendored.parent.mkdir()
        vendored.write_text("")
        with patch(f"{MOD}.platform.system", return_value="Windows"), patch(
            f"{MOD}._agent_install_root", return_value=str(tmp_path)
        ), patch(f"{MOD}.shutil.which", return_value="C:\\Other\\dsc.exe"):
            assert locator.find_engine("dsc") == str(vendored)
