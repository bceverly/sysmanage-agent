# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""BSD service control (2026-09-30).

Before this every enable/start a deployment plan sent to a BSD host failed
with "no service manager": ClamAV installed, its updater never ran.
"""

import os
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.collection.update_detection import UpdateDetector
from src.sysmanage_agent.core import bsd_service_control as bsd
from src.sysmanage_agent.core.agent_utils import MessageProcessor


def _sbin(name):
    return f"/usr/sbin/{name}"


class TestBuildCommand:
    def test_freebsd_enables_with_sysrc_and_runs_with_service(self):
        with patch("shutil.which", side_effect=_sbin):
            assert bsd.build_command("FreeBSD", "enable", "clamav_freshclam") == [
                "/usr/sbin/sysrc",
                "clamav_freshclam_enable=YES",
            ]
            assert bsd.build_command("FreeBSD", "disable", "clamav_clamd") == [
                "/usr/sbin/sysrc",
                "clamav_clamd_enable=NO",
            ]
            assert bsd.build_command("FreeBSD", "start", "clamav_clamd") == [
                "/usr/sbin/service",
                "clamav_clamd",
                "start",
            ]

    def test_openbsd_uses_rcctl_for_every_action(self):
        with patch("shutil.which", side_effect=_sbin):
            for action in ("enable", "disable", "start", "stop", "restart"):
                assert bsd.build_command("OpenBSD", action, "freshclam") == [
                    "/usr/sbin/rcctl",
                    action,
                    "freshclam",
                ]

    def test_netbsd_runs_the_rc_d_script_and_edits_rc_conf_in_process(self):
        assert bsd.build_command("NetBSD", "start", "freshclamd") == [
            "/etc/rc.d/freshclamd",
            "start",
        ]
        assert bsd.build_command("NetBSD", "enable", "freshclamd") is None

    def test_service_names_cannot_escape_rc_d_or_rc_conf(self):
        for bad in ("../x", "a b", "x;rm", "", "a\nb=YES"):
            assert not bsd.valid_service(bad), bad
        assert bsd.valid_service("clamav_freshclam")


class TestNetbsdEnable:
    def test_enable_installs_the_pkgsrc_script_and_sets_rc_conf(self, tmp_path):
        rc_d, examples = tmp_path / "rc.d", tmp_path / "examples"
        rc_d.mkdir()
        examples.mkdir()
        (examples / "freshclamd").write_text("#!/bin/sh\n")
        rc_conf = tmp_path / "rc.conf"
        rc_conf.write_text("sshd=YES\nfreshclamd=NO\n")
        ok, error = bsd.netbsd_set_enabled(
            "freshclamd", True, str(rc_conf), str(rc_d), str(examples)
        )
        assert ok, error
        assert (rc_d / "freshclamd").is_file()
        assert os.access(rc_d / "freshclamd", os.X_OK)
        assert rc_conf.read_text().splitlines() == ["sshd=YES", "freshclamd=YES"]
        # Idempotent.
        bsd.netbsd_set_enabled(
            "freshclamd", True, str(rc_conf), str(rc_d), str(examples)
        )
        assert rc_conf.read_text().count("freshclamd=") == 1

    def test_enable_without_any_script_says_so(self, tmp_path):
        ok, error = bsd.netbsd_set_enabled(
            "clamd", True, str(tmp_path / "rc.conf"), str(tmp_path), str(tmp_path)
        )
        assert not ok and "no rc.d script" in error


class TestServiceControlOnBsd:
    def setup_method(self):
        agent = Mock()
        agent.collect_roles = AsyncMock()
        self.processor = MessageProcessor(agent, Mock())

    @pytest.mark.asyncio
    async def test_freebsd_plan_actions_reach_sysrc_and_service(self):
        ok = Mock(returncode=0, stdout="", stderr="")
        with patch.object(bsd, "bsd_system", return_value="FreeBSD"), patch(
            "shutil.which", side_effect=_sbin
        ), patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ), patch(
            "src.sysmanage_agent.core.agent_utils.run_command_async",
            AsyncMock(return_value=ok),
        ) as run:
            enabled = await self.processor._handle_service_control(
                {"action": "enable", "services": ["clamav_freshclam"]}
            )
            started = await self.processor._handle_service_control(
                {"action": "start", "services": ["clamav_freshclam"]}
            )
        assert enabled["success"] and started["success"]
        argvs = [c.args[0] for c in run.call_args_list]
        assert ["/usr/sbin/sysrc", "clamav_freshclam_enable=YES"] in argvs
        assert ["/usr/sbin/service", "clamav_freshclam", "start"] in argvs

    @pytest.mark.asyncio
    async def test_a_bad_service_name_is_refused_before_anything_runs(self):
        with patch.object(bsd, "bsd_system", return_value="NetBSD"), patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ), patch(
            "src.sysmanage_agent.core.agent_utils.run_command_async", AsyncMock()
        ) as run:
            result = await self.processor._handle_service_control(
                {"action": "enable", "services": ["../../bin/sh"]}
            )
        assert not result["success"] and not run.called


def test_product_named_managers_reach_their_installers():
    detector = UpdateDetector()
    fake = Mock()
    fake._install_with_choco = Mock(return_value={"success": True})
    fake._install_with_pkg = Mock(return_value={"success": True})
    detector.detector = fake
    assert detector.install_package("clamav", "chocolatey")["success"]
    assert detector.install_package("clamav", "pkg_add")["success"]
    fake._install_with_choco.assert_called_once_with("clamav")
    fake._install_with_pkg.assert_called_once_with("clamav")
