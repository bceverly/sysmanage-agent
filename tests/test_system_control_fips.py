"""
Tests for SystemControl.fips_change — FIPS enable/disable execution (Phase 14.4).
"""

from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.operations.system_control import SystemControl


class TestFipsChange:
    """Tests for SystemControl.fips_change command execution."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock agent instance."""
        agent = Mock()
        agent.registration = Mock()
        agent.registration.get_fips_mode_info = Mock(
            return_value={"status": "enabled", "enabled": True}
        )
        agent.create_message = Mock(
            return_value={"message_type": "fips_compliance_update"}
        )
        agent.send_message = AsyncMock()
        return agent

    @pytest.fixture
    def control(self, mock_agent):
        """Create a SystemControl with a stubbed command runner."""
        control = SystemControl(mock_agent)
        # Stub the runner so no real command executes.
        control.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"exit_code": 0}}
        )
        return control

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_command(self, control):
        """Ubuntu Pro enable builds the pro-enable command."""
        result = await control.fips_change({"method": "ubuntu-pro"}, enable=True)
        cmd = control.execute_shell_command.call_args.args[0]["command"]
        assert cmd == "sudo pro enable fips --assume-yes"
        assert result["fips_action"] == "enable"
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_command(self, control):
        """Ubuntu Pro disable builds the pro-disable command."""
        await control.fips_change({"method": "ubuntu-pro"}, enable=False)
        cmd = control.execute_shell_command.call_args.args[0]["command"]
        assert cmd == "sudo pro disable fips --assume-yes"

    @pytest.mark.asyncio
    async def test_rhel_enable_command(self, control):
        """RHEL enable builds the fips-mode-setup command."""
        await control.fips_change({"method": "rhel"}, enable=True)
        cmd = control.execute_shell_command.call_args.args[0]["command"]
        assert cmd == "sudo fips-mode-setup --enable"

    @pytest.mark.asyncio
    async def test_windows_registry_command(self, control):
        """Windows enable sets the FipsAlgorithmPolicy registry value to 1."""
        result = await control.fips_change({"method": "windows"}, enable=True)
        cmd = control.execute_shell_command.call_args.args[0]["command"]
        assert "FipsAlgorithmPolicy" in cmd
        assert "/d 1 /f" in cmd
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_windows_disable_sets_zero(self, control):
        """Windows disable sets the registry value to 0."""
        await control.fips_change({"method": "windows"}, enable=False)
        cmd = control.execute_shell_command.call_args.args[0]["command"]
        assert "/d 0 /f" in cmd

    @pytest.mark.asyncio
    async def test_unsupported_method_errors(self, control):
        """An unknown method returns an error without running a command."""
        result = await control.fips_change({"method": "bogus"}, enable=True)
        assert result["success"] is False
        control.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_posture_is_resent(self, control, mock_agent):
        """After the change the current FIPS posture is resent to the server."""
        await control.fips_change({"method": "rhel"}, enable=True)
        mock_agent.registration.get_fips_mode_info.assert_called_once()
        mock_agent.create_message.assert_called_once_with(
            "fips_compliance_update", {"status": "enabled", "enabled": True}
        )
        mock_agent.send_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_failed_no_reboot(self, control):
        """A failed switch command does not claim a reboot is required."""
        control.execute_shell_command = AsyncMock(
            return_value={"success": False, "error": "boom"}
        )
        result = await control.fips_change({"method": "rhel"}, enable=True)
        assert result["success"] is False
        assert result["reboot_required"] is False

    @pytest.mark.asyncio
    async def test_resend_failure_ok(self, control, mock_agent):
        """A failed posture resend is swallowed; the change result stands."""
        mock_agent.send_message = AsyncMock(side_effect=RuntimeError("socket closed"))
        result = await control.fips_change({"method": "rhel"}, enable=True)
        assert result["success"] is True
