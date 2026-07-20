# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for src.sysmanage_agent.core.agent_utils module (privileges).

Covers privilege detection and sudoers parsing/checking helpers. Split from
test_agent_utils_comprehensive.py to keep each file under the 1000-line limit.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.core.agent_utils import (
    MessageProcessor,
    _check_sudoers_privileges,
    _parse_sudoers_content,
    _parse_sudoers_line,
    _read_sudoers_file,
    _test_sudo_access,
    is_running_privileged,
)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Tests the POSIX privilege-detection path (os.geteuid + pwd); both are unavailable on Windows",
)
class TestPrivilegeDetectionAdvanced:
    """Advanced test cases for privilege detection functions."""

    @patch("sys.platform", "linux")
    def test_is_running_privileged_sysmanage_agent_user_with_sudoers(self):
        """Test privilege detection for sysmanage-agent user with sudoers."""
        mock_pwuid = Mock()
        mock_pwuid.pw_name = "sysmanage-agent"

        with patch("os.geteuid", return_value=1001):
            with patch("pwd.getpwuid", return_value=mock_pwuid):
                with patch(
                    "src.sysmanage_agent.core.agent_privileges._check_sudoers_privileges",
                    return_value=True,
                ):
                    result = is_running_privileged()
                    assert result is True

    @patch("sys.platform", "linux")
    def test_is_running_privileged_sysmanage_agent_user_without_sudoers(self):
        """Test privilege detection for sysmanage-agent user without sudoers."""
        mock_pwuid = Mock()
        mock_pwuid.pw_name = "sysmanage-agent"

        with patch("os.geteuid", return_value=1001):
            with patch("pwd.getpwuid", return_value=mock_pwuid):
                with patch(
                    "src.sysmanage_agent.core.agent_privileges._check_sudoers_privileges",
                    return_value=False,
                ):
                    result = is_running_privileged()
                    assert result is False

    @patch("sys.platform", "linux")
    def test_is_running_privileged_other_user(self):
        """Test privilege detection for other non-root user."""
        mock_pwuid = Mock()
        mock_pwuid.pw_name = "regular-user"

        with patch("os.geteuid", return_value=1000):
            with patch("pwd.getpwuid", return_value=mock_pwuid):
                result = is_running_privileged()
                assert result is False

    @patch("sys.platform", "linux")
    def test_is_running_privileged_pwd_exception(self):
        """Test privilege detection when pwd lookup fails."""
        with patch("os.geteuid", return_value=1001):
            with patch("pwd.getpwuid", side_effect=KeyError("No such user")):
                result = is_running_privileged()
                assert result is False


class TestSudoersPrivilegeChecking:
    """Test cases for sudoers privilege checking functions."""

    def test_check_sudoers_privileges_with_valid_file(self):
        """Test sudoers privilege checking with valid file content."""
        sudoers_content = (
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/apt"
        )

        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_privileges._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl", "apt"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True
                mock_parse.assert_called_once_with(sudoers_content, "sysmanage-agent")

    def test_check_sudoers_privileges_missing_systemctl(self):
        """Test sudoers privilege checking when systemctl is missing."""
        sudoers_content = "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/apt"

        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_privileges._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"apt"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is False

    def test_check_sudoers_privileges_missing_package_mgmt(self):
        """Test sudoers privilege checking when package manager is missing."""
        sudoers_content = "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl"

        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_privileges._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is False

    def test_check_sudoers_privileges_file_not_readable(self):
        """Test sudoers privilege checking when file is not readable."""
        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            return_value=None,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_privileges._test_sudo_access",
                return_value=True,
            ):
                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True

    def test_check_sudoers_privileges_exception(self):
        """Test sudoers privilege checking with exception."""
        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            side_effect=Exception("File error"),
        ):
            result = _check_sudoers_privileges("sysmanage-agent")

            assert result is False

    def test_check_sudoers_privileges_with_yum(self):
        """Test sudoers privilege checking with yum package manager."""
        sudoers_content = (
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/yum"
        )

        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_privileges._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl", "yum"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True

    def test_check_sudoers_privileges_with_dnf(self):
        """Test sudoers privilege checking with dnf package manager."""
        sudoers_content = (
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/dnf"
        )

        with patch(
            "src.sysmanage_agent.core.agent_privileges._read_sudoers_file",
            return_value=sudoers_content,
        ):
            with patch(
                "src.sysmanage_agent.core.agent_privileges._parse_sudoers_content"
            ) as mock_parse:
                mock_parse.return_value = {"systemctl", "dnf"}

                result = _check_sudoers_privileges("sysmanage-agent")

                assert result is True


class TestReadSudoersFile:
    """Test cases for _read_sudoers_file function."""

    def test_read_sudoers_file_success(self):
        """Test successful reading of sudoers file."""
        expected_content = "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl"

        with patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(
                            read=MagicMock(return_value=expected_content)
                        )
                    ),
                    __exit__=MagicMock(),
                )
            ),
        ):
            result = _read_sudoers_file("/etc/sudoers.d/sysmanage-agent")

            assert result == expected_content

    def test_read_sudoers_file_permission_error(self):
        """Test reading sudoers file with permission denied."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = _read_sudoers_file("/etc/sudoers.d/sysmanage-agent")

            assert result is None


class TestParseSudoersContent:
    """Test cases for _parse_sudoers_content function."""

    def test_parse_sudoers_content_full_privileges(self):
        """Test parsing sudoers content with full privileges."""
        content = """# Sudoers file for sysmanage-agent
sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl *
sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/apt *
"""
        result = _parse_sudoers_content(content, "sysmanage-agent")

        assert "systemctl" in result
        assert "apt" in result

    def test_parse_sudoers_content_empty(self):
        """Test parsing empty sudoers content."""
        content = ""
        result = _parse_sudoers_content(content, "sysmanage-agent")

        assert result == set()

    def test_parse_sudoers_content_comments_only(self):
        """Test parsing sudoers content with only comments."""
        content = """# This is a comment
# Another comment
"""
        result = _parse_sudoers_content(content, "sysmanage-agent")

        assert result == set()


class TestParseSudoersLine:
    """Test cases for _parse_sudoers_line function."""

    def test_parse_sudoers_line_empty(self):
        """Test parsing empty line."""
        result = _parse_sudoers_line("", "user", ["systemctl", "apt"])
        assert result == set()

    def test_parse_sudoers_line_comment(self):
        """Test parsing comment line."""
        result = _parse_sudoers_line(
            "# This is a comment", "user", ["systemctl", "apt"]
        )
        assert result == set()

    def test_parse_sudoers_line_no_nopasswd(self):
        """Test parsing line without NOPASSWD."""
        result = _parse_sudoers_line(
            "user ALL=(ALL) /usr/bin/systemctl", "user", ["systemctl", "apt"]
        )
        assert result == set()

    def test_parse_sudoers_line_different_user(self):
        """Test parsing line for different user."""
        result = _parse_sudoers_line(
            "other ALL=(ALL) NOPASSWD: /usr/bin/systemctl", "user", ["systemctl", "apt"]
        )
        assert result == set()

    def test_parse_sudoers_line_matching_commands(self):
        """Test parsing line with matching commands."""
        result = _parse_sudoers_line(
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/apt",
            "sysmanage-agent",
            ["systemctl", "apt"],
        )
        assert "systemctl" in result
        assert "apt" in result

    def test_parse_sudoers_line_partial_match(self):
        """Test parsing line with partial command match."""
        result = _parse_sudoers_line(
            "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl",
            "sysmanage-agent",
            ["systemctl", "apt"],
        )
        assert "systemctl" in result
        assert "apt" not in result

    def test_parse_sudoers_line_nopasswd_at_end_no_commands(self):
        """Test parsing line where NOPASSWD is at end with nothing after it."""
        # This covers line 907: when split produces only 1 part after NOPASSWD:
        result = _parse_sudoers_line(
            "sysmanage-agent ALL=(ALL) NOPASSWD:",
            "sysmanage-agent",
            ["systemctl", "apt"],
        )
        assert result == set()


class TestTestSudoAccess:
    """Test cases for _test_sudo_access function."""

    def test_test_sudo_access_success(self):
        """Test sudo access when command succeeds."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = _test_sudo_access()
            assert result is True

    def test_test_sudo_access_service_inactive(self):
        """Test sudo access when service is inactive (exit code 3)."""
        mock_result = Mock()
        mock_result.returncode = 3  # Service inactive is fine

        with patch("subprocess.run", return_value=mock_result):
            result = _test_sudo_access()
            assert result is True

    def test_test_sudo_access_auth_failed(self):
        """Test sudo access when authentication fails (exit code 255)."""
        mock_result = Mock()
        mock_result.returncode = 255  # sudo auth failed

        with patch("subprocess.run", return_value=mock_result):
            result = _test_sudo_access()
            assert result is False

    def test_test_sudo_access_exception(self):
        """Test sudo access when subprocess raises exception."""
        with patch("subprocess.run", side_effect=Exception("Command not found")):
            result = _test_sudo_access()
            assert result is False

    def test_test_sudo_access_timeout(self):
        """Test sudo access when command times out."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("sudo", 5)):
            result = _test_sudo_access()
            assert result is False


# ============================================================================
# Section 8.6 additions — enable/disable + platform-aware service control
# ============================================================================


class TestServiceControlNewActions:
    """Tests for the enable/disable actions and the platform-aware
    command builder added to service_control per ROADMAP Section 8.6."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.collect_roles = AsyncMock()
        self.mock_logger = Mock()
        self.processor = MessageProcessor(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action", ["enable", "disable"])
    async def test_enable_disable_accepted_as_valid_actions(self, action):
        """enable/disable should pass the action validator and run a command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.core.agent_utils.is_running_privileged",
            return_value=True,
        ), patch("shutil.which", return_value="/usr/bin/systemctl"), patch(
            "src.sysmanage_agent.core.agent_utils.run_command_async",
            return_value=mock_result,
        ) as mock_run:
            result = await self.processor._handle_service_control(
                {"action": action, "services": ["nginx"]}
            )

        assert result["success"] is True
        assert result["action"] == action
        # Confirm we actually invoked systemctl with the right action
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["/usr/bin/systemctl", action, "nginx"]

    @pytest.mark.asyncio
    async def test_invalid_action_still_rejected(self):
        """Actions outside the allowed set are still rejected after enable/disable were added."""
        result = await self.processor._handle_service_control(
            {"action": "reload", "services": ["nginx"]}
        )
        assert result["success"] is False
        # New error message lists every allowed action
        for verb in ("start", "stop", "restart", "enable", "disable"):
            assert verb in result["error"]


class TestBuildServiceControlCmd:
    """Tests for the static _build_service_control_cmd helper that picks
    the right service-manager invocation per host."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.processor = MessageProcessor(self.mock_agent, self.mock_logger)

    def _which_only(self, binary_name):
        """Return a side_effect that makes shutil.which find ONLY one binary."""

        def fake_which(name):
            return f"/usr/bin/{name}" if name == binary_name else None

        return fake_which

    def test_systemctl_used_when_available(self):
        """systemctl is preferred over everything else."""
        with patch("shutil.which", side_effect=self._which_only("systemctl")):
            cmd = self.processor._build_service_control_cmd("restart", "nginx")
        assert cmd == ["/usr/bin/systemctl", "restart", "nginx"]

    def test_openrc_start_uses_rc_service(self):
        """On Alpine/Gentoo (no systemctl), rc-service runs lifecycle actions."""

        def fake_which(name):
            return {
                "rc-service": "/sbin/rc-service",
                "rc-update": "/sbin/rc-update",
            }.get(name)

        with patch("shutil.which", side_effect=fake_which):
            cmd = self.processor._build_service_control_cmd("start", "nginx")
        assert cmd == ["/sbin/rc-service", "nginx", "start"]

    def test_openrc_enable_uses_rc_update(self):
        """On OpenRC, enable maps to `rc-update add <svc> default`."""

        def fake_which(name):
            return {
                "rc-service": "/sbin/rc-service",
                "rc-update": "/sbin/rc-update",
            }.get(name)

        with patch("shutil.which", side_effect=fake_which):
            cmd = self.processor._build_service_control_cmd("enable", "nginx")
        assert cmd == ["/sbin/rc-update", "add", "nginx", "default"]

    def test_openrc_disable_uses_rc_update_del(self):
        """disable maps to `rc-update del`."""

        def fake_which(name):
            return {
                "rc-service": "/sbin/rc-service",
                "rc-update": "/sbin/rc-update",
            }.get(name)

        with patch("shutil.which", side_effect=fake_which):
            cmd = self.processor._build_service_control_cmd("disable", "nginx")
        assert cmd == ["/sbin/rc-update", "del", "nginx", "default"]

    def test_macos_launchctl_restart_uses_kickstart(self):
        """On macOS, restart is `launchctl kickstart -k system/<svc>`."""
        with patch("shutil.which", side_effect=self._which_only("launchctl")):
            cmd = self.processor._build_service_control_cmd(
                "restart", "com.sysmanage.agent"
            )
        assert cmd == [
            "/usr/bin/launchctl",
            "kickstart",
            "-k",
            "system/com.sysmanage.agent",
        ]

    def test_macos_launchctl_enable_prefixed_with_domain(self):
        """launchctl enable/disable need a domain prefix (e.g. system/<svc>)."""
        with patch("shutil.which", side_effect=self._which_only("launchctl")):
            cmd = self.processor._build_service_control_cmd(
                "enable", "com.sysmanage.agent"
            )
        assert cmd == [
            "/usr/bin/launchctl",
            "enable",
            "system/com.sysmanage.agent",
        ]

    def test_windows_sc_disable_uses_config_start_disabled(self):
        """On Windows, disable maps to `sc.exe config <svc> start= disabled`."""

        def fake_which(name):
            # Note: on a non-Windows host shutil.which still resolves "sc" if
            # something happens to be on PATH; we mock to be deterministic.
            return "/usr/bin/sc.exe" if name == "sc.exe" else None

        with patch("shutil.which", side_effect=fake_which):
            cmd = self.processor._build_service_control_cmd("disable", "MyService")
        assert cmd == ["/usr/bin/sc.exe", "config", "MyService", "start=", "disabled"]

    def test_returns_none_when_no_supported_manager_present(self):
        """If nothing usable is on PATH, returns None so the caller errors out."""
        with patch("shutil.which", return_value=None):
            cmd = self.processor._build_service_control_cmd("start", "nginx")
        assert cmd is None
