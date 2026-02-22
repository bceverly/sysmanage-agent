"""
Unit tests for src.sysmanage_agent.operations.firewall_bsd module.
Tests BSD firewall operations (PF, IPFW, NPF) on FreeBSD, OpenBSD, and NetBSD.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import asyncio
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_bsd import BSDFirewallOperations


class TestBSDFirewallOperationsInit:
    """Test cases for BSDFirewallOperations initialization."""

    def test_init_with_logger(self):
        """Test BSDFirewallOperations initialization with custom logger."""
        mock_agent = Mock()
        mock_logger = Mock()
        ops = BSDFirewallOperations(mock_agent, logger=mock_logger)

        assert ops.agent == mock_agent
        assert ops.logger == mock_logger
        assert ops.pf_ops is not None
        assert ops.ipfw_ops is not None
        assert ops.npf_ops is not None

    def test_init_without_logger(self):
        """Test BSDFirewallOperations initialization without logger."""
        mock_agent = Mock()
        ops = BSDFirewallOperations(mock_agent)

        assert ops.agent == mock_agent
        assert ops.logger is not None

    def test_init_creates_firewall_operation_handlers(self):
        """Test that initialization creates all firewall type handlers."""
        mock_agent = Mock()
        ops = BSDFirewallOperations(mock_agent)

        # Verify all handlers are created
        assert hasattr(ops, "pf_ops")
        assert hasattr(ops, "ipfw_ops")
        assert hasattr(ops, "npf_ops")


class TestBuildCommand:
    """Test cases for _build_command method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    def test_build_command_privileged(self):
        """Test building command when running as root."""
        with patch(
            "src.sysmanage_agent.operations.firewall_bsd.is_running_privileged",
            return_value=True,
        ):
            result = self.ops._build_command(["pfctl", "-d"])

        assert result == ["pfctl", "-d"]

    def test_build_command_not_privileged(self):
        """Test building command when not running as root."""
        with patch(
            "src.sysmanage_agent.operations.firewall_bsd.is_running_privileged",
            return_value=False,
        ):
            result = self.ops._build_command(["pfctl", "-d"])

        assert result == ["sudo", "pfctl", "-d"]

    def test_build_command_with_multiple_args(self):
        """Test building command with multiple arguments."""
        with patch(
            "src.sysmanage_agent.operations.firewall_bsd.is_running_privileged",
            return_value=False,
        ):
            result = self.ops._build_command(["service", "ipfw", "restart"])

        assert result == ["sudo", "service", "ipfw", "restart"]


class TestCheckCommandExists:
    """Test cases for _check_command_exists method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_check_command_exists_success(self):
        """Test checking for a command that exists."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await self.ops._check_command_exists("pfctl")

        assert result is True

    @pytest.mark.asyncio
    async def test_check_command_exists_not_found(self):
        """Test checking for a command that doesn't exist."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await self.ops._check_command_exists("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_check_command_exists_file_not_found(self):
        """Test checking command when 'which' itself is not found."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("which not found"),
        ):
            result = await self.ops._check_command_exists("pfctl")

        assert result is False

    @pytest.mark.asyncio
    async def test_check_command_exists_timeout(self):
        """Test checking command with timeout."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await self.ops._check_command_exists("pfctl")

        assert result is False


class TestRunFirewallCommand:
    """Test cases for _run_firewall_command method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_run_firewall_command_success(self):
        """Test running a firewall command successfully."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"output", b""))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            returncode, stdout, stderr = await self.ops._run_firewall_command(
                ["pfctl", "-d"]
            )

        assert returncode == 0
        assert stdout == "output"
        assert stderr == ""

    @pytest.mark.asyncio
    async def test_run_firewall_command_with_error(self):
        """Test running a firewall command that returns an error."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error message"))

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            returncode, stdout, stderr = await self.ops._run_firewall_command(
                ["pfctl", "-d"]
            )

        assert returncode == 1
        assert stdout == ""
        assert stderr == "error message"

    @pytest.mark.asyncio
    async def test_run_firewall_command_timeout(self):
        """Test running a firewall command that times out."""
        mock_proc = AsyncMock()
        mock_proc.kill = Mock()
        mock_proc.wait = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(subprocess.TimeoutExpired):
                await self.ops._run_firewall_command(["pfctl", "-d"], timeout=5)

        mock_proc.kill.assert_called_once()


class TestDisableIPFW:
    """Test cases for _disable_ipfw method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_ipfw_not_freebsd(self):
        """Test disabling IPFW on non-FreeBSD system."""
        self.ops.system = "OpenBSD"

        result = await self.ops._disable_ipfw()

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_ipfw_command_not_found(self):
        """Test disabling IPFW when ipfw command doesn't exist."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return False

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            result = await self.ops._disable_ipfw()

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_ipfw_success(self):
        """Test successfully disabling IPFW."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (0, "", "")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops._disable_ipfw()

        assert result is not None
        assert result["success"] is True
        assert "disabled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_disable_ipfw_failure(self):
        """Test failing to disable IPFW."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (1, "", "sysctl failed")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                result = await self.ops._disable_ipfw()

        assert result is not None
        assert result["success"] is False
        assert "Failed" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_ipfw_file_not_found(self):
        """Test disabling IPFW when command raises FileNotFoundError."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=FileNotFoundError(),
            ):
                result = await self.ops._disable_ipfw()

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_ipfw_timeout(self):
        """Test disabling IPFW when command times out."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=subprocess.TimeoutExpired(["sysctl"], 10),
            ):
                result = await self.ops._disable_ipfw()

        assert result is None


class TestDisableNPF:
    """Test cases for _disable_npf method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_npf_not_netbsd(self):
        """Test disabling NPF on non-NetBSD system."""
        self.ops.system = "FreeBSD"

        result = await self.ops._disable_npf()

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_npf_command_not_found(self):
        """Test disabling NPF when npfctl command doesn't exist."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return False

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            result = await self.ops._disable_npf()

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_npf_success(self):
        """Test successfully disabling NPF."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (0, "", "")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops._disable_npf()

        assert result is not None
        assert result["success"] is True
        assert "disabled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_disable_npf_failure(self):
        """Test failing to disable NPF."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (1, "", "npfctl failed")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                result = await self.ops._disable_npf()

        assert result is not None
        assert result["success"] is False
        assert "Failed" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_npf_timeout(self):
        """Test disabling NPF when command times out."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=subprocess.TimeoutExpired(["npfctl"], 10),
            ):
                result = await self.ops._disable_npf()

        assert result is None


class TestDisablePF:
    """Test cases for _disable_pf method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_pf_command_not_found(self):
        """Test disabling PF when pfctl command doesn't exist."""

        async def check_cmd(_cmd):
            return False

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            result = await self.ops._disable_pf()

        assert result is None

    @pytest.mark.asyncio
    async def test_disable_pf_success(self):
        """Test successfully disabling PF."""

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (0, "", "")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops._disable_pf()

        assert result is not None
        assert result["success"] is True
        assert "disabled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_disable_pf_failure(self):
        """Test failing to disable PF."""

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (1, "", "pfctl failed")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                result = await self.ops._disable_pf()

        assert result is not None
        assert result["success"] is False
        assert "Failed" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_pf_timeout(self):
        """Test disabling PF when command times out."""

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=subprocess.TimeoutExpired(["pfctl"], 10),
            ):
                result = await self.ops._disable_pf()

        assert result is None


class TestRestartIPFW:
    """Test cases for _restart_ipfw method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_ipfw_not_freebsd(self):
        """Test restarting IPFW on non-FreeBSD system."""
        self.ops.system = "OpenBSD"

        result = await self.ops._restart_ipfw()

        assert result is None

    @pytest.mark.asyncio
    async def test_restart_ipfw_command_not_found(self):
        """Test restarting IPFW when ipfw command doesn't exist."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return False

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            result = await self.ops._restart_ipfw()

        assert result is None

    @pytest.mark.asyncio
    async def test_restart_ipfw_success(self):
        """Test successfully restarting IPFW."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (0, "", "")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops._restart_ipfw()

        assert result is not None
        assert result["success"] is True
        assert "restarted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_restart_ipfw_failure(self):
        """Test failing to restart IPFW."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (1, "", "service failed")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                result = await self.ops._restart_ipfw()

        assert result is not None
        assert result["success"] is False
        assert "Failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_ipfw_timeout(self):
        """Test restarting IPFW when command times out."""
        self.ops.system = "FreeBSD"

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=subprocess.TimeoutExpired(["service"], 10),
            ):
                result = await self.ops._restart_ipfw()

        assert result is None


class TestRestartNPF:
    """Test cases for _restart_npf method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_npf_not_netbsd(self):
        """Test restarting NPF on non-NetBSD system."""
        self.ops.system = "FreeBSD"

        result = await self.ops._restart_npf()

        assert result is None

    @pytest.mark.asyncio
    async def test_restart_npf_command_not_found(self):
        """Test restarting NPF when npfctl command doesn't exist."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return False

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            result = await self.ops._restart_npf()

        assert result is None

    @pytest.mark.asyncio
    async def test_restart_npf_success(self):
        """Test successfully restarting NPF."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (0, "", "")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops._restart_npf()

        assert result is not None
        assert result["success"] is True
        assert "restarted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_restart_npf_failure(self):
        """Test failing to restart NPF."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (1, "", "npfctl failed")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                result = await self.ops._restart_npf()

        assert result is not None
        assert result["success"] is False
        assert "Failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_npf_timeout(self):
        """Test restarting NPF when command times out."""
        self.ops.system = "NetBSD"

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=subprocess.TimeoutExpired(["npfctl"], 10),
            ):
                result = await self.ops._restart_npf()

        assert result is None


class TestRestartPF:
    """Test cases for _restart_pf method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_pf_command_not_found(self):
        """Test restarting PF when pfctl command doesn't exist."""

        async def check_cmd(_cmd):
            return False

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            result = await self.ops._restart_pf()

        assert result is None

    @pytest.mark.asyncio
    async def test_restart_pf_success(self):
        """Test successfully restarting PF."""

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (0, "", "")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                with patch.object(
                    self.ops, "_send_firewall_status_update", new_callable=AsyncMock
                ):
                    result = await self.ops._restart_pf()

        assert result is not None
        assert result["success"] is True
        assert "restarted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_restart_pf_failure(self):
        """Test failing to restart PF."""

        async def check_cmd(_cmd):
            return True

        async def run_cmd(_cmd, _timeout=10):
            return (1, "", "pfctl failed")

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(self.ops, "_run_firewall_command", side_effect=run_cmd):
                result = await self.ops._restart_pf()

        assert result is not None
        assert result["success"] is False
        assert "Failed" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_pf_timeout(self):
        """Test restarting PF when command times out."""

        async def check_cmd(_cmd):
            return True

        with patch.object(self.ops, "_check_command_exists", side_effect=check_cmd):
            with patch.object(
                self.ops,
                "_run_firewall_command",
                side_effect=subprocess.TimeoutExpired(["pfctl"], 10),
            ):
                result = await self.ops._restart_pf()

        assert result is None


class TestEnableFirewall:
    """Test cases for enable_firewall method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_firewall_ipfw_freebsd(self):
        """Test enabling firewall with IPFW on FreeBSD."""
        self.ops.system = "FreeBSD"
        mock_result = {"success": True, "message": "IPFW enabled"}

        async def mock_check_cmd(cmd):
            return cmd == "ipfw"

        async def mock_enable_ipfw(_ports, _protocol):
            return mock_result

        with patch.object(
            self.ops, "_check_command_exists", side_effect=mock_check_cmd
        ):
            with patch.object(
                self.ops.ipfw_ops, "enable_ipfw_firewall", side_effect=mock_enable_ipfw
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_npf_netbsd(self):
        """Test enabling firewall with NPF on NetBSD."""
        self.ops.system = "NetBSD"
        mock_result = {"success": True, "message": "NPF enabled"}

        async def mock_check_cmd(cmd):
            return cmd == "npfctl"

        async def mock_enable_npf(_ports, _protocol):
            return mock_result

        with patch.object(
            self.ops, "_check_command_exists", side_effect=mock_check_cmd
        ):
            with patch.object(
                self.ops.npf_ops, "enable_npf_firewall", side_effect=mock_enable_npf
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_pf_openbsd(self):
        """Test enabling firewall with PF on OpenBSD."""
        self.ops.system = "OpenBSD"
        mock_result = {"success": True, "message": "PF enabled"}

        async def mock_check_cmd(cmd):
            return cmd == "pfctl"

        async def mock_enable_pf(_ports, _protocol):
            return mock_result

        with patch.object(
            self.ops, "_check_command_exists", side_effect=mock_check_cmd
        ):
            with patch.object(
                self.ops.pf_ops, "enable_pf_firewall", side_effect=mock_enable_pf
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_pf_fallback_freebsd(self):
        """Test enabling firewall falls back to PF on FreeBSD when IPFW not available."""
        self.ops.system = "FreeBSD"
        mock_result = {"success": True, "message": "PF enabled"}

        async def mock_check_cmd(cmd):
            # ipfw not available, pfctl is
            return cmd == "pfctl"

        async def mock_enable_pf(_ports, _protocol):
            return mock_result

        with patch.object(
            self.ops, "_check_command_exists", side_effect=mock_check_cmd
        ):
            with patch.object(
                self.ops.pf_ops, "enable_pf_firewall", side_effect=mock_enable_pf
            ):
                result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_no_supported_firewall(self):
        """Test enabling firewall when no supported firewall is found."""
        self.ops.system = "FreeBSD"

        async def mock_check_cmd(_cmd):
            return False

        with patch.object(
            self.ops, "_check_command_exists", side_effect=mock_check_cmd
        ):
            result = await self.ops.enable_firewall([8080], "tcp")

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestDisableFirewall:
    """Test cases for disable_firewall method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_disable_firewall_ipfw_success(self):
        """Test disabling IPFW firewall."""
        self.ops.system = "FreeBSD"

        async def mock_disable_ipfw():
            return {"success": True, "message": "IPFW disabled"}

        with patch.object(self.ops, "_disable_ipfw", side_effect=mock_disable_ipfw):
            result = await self.ops.disable_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_firewall_npf_success(self):
        """Test disabling NPF firewall when IPFW not available."""
        self.ops.system = "NetBSD"

        async def mock_disable_ipfw():
            return None

        async def mock_disable_npf():
            return {"success": True, "message": "NPF disabled"}

        with patch.object(self.ops, "_disable_ipfw", side_effect=mock_disable_ipfw):
            with patch.object(self.ops, "_disable_npf", side_effect=mock_disable_npf):
                result = await self.ops.disable_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_firewall_pf_success(self):
        """Test disabling PF firewall when IPFW and NPF not available."""
        self.ops.system = "OpenBSD"

        async def mock_disable_ipfw():
            return None

        async def mock_disable_npf():
            return None

        async def mock_disable_pf():
            return {"success": True, "message": "PF disabled"}

        with patch.object(self.ops, "_disable_ipfw", side_effect=mock_disable_ipfw):
            with patch.object(self.ops, "_disable_npf", side_effect=mock_disable_npf):
                with patch.object(self.ops, "_disable_pf", side_effect=mock_disable_pf):
                    result = await self.ops.disable_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_firewall_no_supported_firewall(self):
        """Test disabling firewall when no supported firewall is found."""
        self.ops.system = "FreeBSD"

        async def mock_disable_ipfw():
            return None

        async def mock_disable_npf():
            return None

        async def mock_disable_pf():
            return None

        with patch.object(self.ops, "_disable_ipfw", side_effect=mock_disable_ipfw):
            with patch.object(self.ops, "_disable_npf", side_effect=mock_disable_npf):
                with patch.object(self.ops, "_disable_pf", side_effect=mock_disable_pf):
                    result = await self.ops.disable_firewall()

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestRestartFirewall:
    """Test cases for restart_firewall method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_restart_firewall_ipfw_success(self):
        """Test restarting IPFW firewall."""
        self.ops.system = "FreeBSD"

        async def mock_restart_ipfw():
            return {"success": True, "message": "IPFW restarted"}

        with patch.object(self.ops, "_restart_ipfw", side_effect=mock_restart_ipfw):
            result = await self.ops.restart_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_firewall_npf_success(self):
        """Test restarting NPF firewall when IPFW not available."""
        self.ops.system = "NetBSD"

        async def mock_restart_ipfw():
            return None

        async def mock_restart_npf():
            return {"success": True, "message": "NPF restarted"}

        with patch.object(self.ops, "_restart_ipfw", side_effect=mock_restart_ipfw):
            with patch.object(self.ops, "_restart_npf", side_effect=mock_restart_npf):
                result = await self.ops.restart_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_firewall_pf_success(self):
        """Test restarting PF firewall when IPFW and NPF not available."""
        self.ops.system = "OpenBSD"

        async def mock_restart_ipfw():
            return None

        async def mock_restart_npf():
            return None

        async def mock_restart_pf():
            return {"success": True, "message": "PF restarted"}

        with patch.object(self.ops, "_restart_ipfw", side_effect=mock_restart_ipfw):
            with patch.object(self.ops, "_restart_npf", side_effect=mock_restart_npf):
                with patch.object(self.ops, "_restart_pf", side_effect=mock_restart_pf):
                    result = await self.ops.restart_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_firewall_no_supported_firewall(self):
        """Test restarting firewall when no supported firewall is found."""
        self.ops.system = "FreeBSD"

        async def mock_restart_ipfw():
            return None

        async def mock_restart_npf():
            return None

        async def mock_restart_pf():
            return None

        with patch.object(self.ops, "_restart_ipfw", side_effect=mock_restart_ipfw):
            with patch.object(self.ops, "_restart_npf", side_effect=mock_restart_npf):
                with patch.object(self.ops, "_restart_pf", side_effect=mock_restart_pf):
                    result = await self.ops.restart_firewall()

        assert result["success"] is False
        assert "No supported firewall" in result["error"]


class TestDeployFirewall:
    """Test cases for deploy_firewall method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_firewall_success(self):
        """Test deploying firewall successfully."""

        async def mock_enable(_ports, _proto):
            return {"success": True, "message": "Firewall deployed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(self.ops, "_get_local_server_ports", return_value=[]):
                with patch.object(self.ops, "enable_firewall", side_effect=mock_enable):
                    result = await self.ops.deploy_firewall()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_firewall_with_server_ports(self):
        """Test deploying firewall with local server ports."""
        captured_ports = []

        async def mock_enable(ports, _proto):
            captured_ports.extend(ports)
            return {"success": True, "message": "Firewall deployed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(self.ops, "_get_local_server_ports", return_value=[3000]):
                with patch.object(self.ops, "enable_firewall", side_effect=mock_enable):
                    result = await self.ops.deploy_firewall()

        assert result["success"] is True
        # Verify both ports are included
        assert 8080 in captured_ports
        assert 3000 in captured_ports

    @pytest.mark.asyncio
    async def test_deploy_firewall_deduplicates_ports(self):
        """Test deploying firewall deduplicates ports."""
        captured_ports = []

        async def mock_enable(ports, _proto):
            captured_ports.extend(ports)
            return {"success": True, "message": "Firewall deployed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops, "_get_local_server_ports", return_value=[8080, 3000]
            ):
                with patch.object(self.ops, "enable_firewall", side_effect=mock_enable):
                    result = await self.ops.deploy_firewall()

        assert result["success"] is True
        # Verify ports are deduplicated
        assert len(captured_ports) == len(set(captured_ports))

    @pytest.mark.asyncio
    async def test_deploy_firewall_exception(self):
        """Test deploying firewall with exception."""
        with patch.object(
            self.ops,
            "_get_agent_communication_ports",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.deploy_firewall()

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestApplyFirewallRoles:
    """Test cases for apply_firewall_roles method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_success(self):
        """Test applying firewall roles with PF."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = [{"port": 443, "tcp": True, "udp": False}]

        async def mock_pf_apply(_port_configs, _agent_ports, _errors):
            return {"success": True, "message": "PF roles applied"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "apply_firewall_roles_pf", side_effect=mock_pf_apply
            ):
                result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_ipfw_fallback(self):
        """Test applying firewall roles falls back to IPFW."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_apply(_port_configs, _agent_ports, _errors):
            return None

        async def mock_ipfw_apply(_port_configs, _agent_ports, _errors):
            return {"success": True, "message": "IPFW roles applied"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "apply_firewall_roles_pf", side_effect=mock_pf_apply
            ):
                with patch.object(
                    self.ops.ipfw_ops,
                    "apply_firewall_roles_ipfw",
                    side_effect=mock_ipfw_apply,
                ):
                    result = await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_fallback(self):
        """Test applying firewall roles falls back to NPF."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_apply(_port_configs, _agent_ports, _errors):
            return None

        async def mock_ipfw_apply(_port_configs, _agent_ports, _errors):
            return None

        async def mock_npf_apply(_port_configs, _agent_ports, _errors):
            return {"success": True, "message": "NPF roles applied"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "apply_firewall_roles_pf", side_effect=mock_pf_apply
            ):
                with patch.object(
                    self.ops.ipfw_ops,
                    "apply_firewall_roles_ipfw",
                    side_effect=mock_ipfw_apply,
                ):
                    with patch.object(
                        self.ops.npf_ops,
                        "apply_firewall_roles_npf",
                        side_effect=mock_npf_apply,
                    ):
                        result = await self.ops.apply_firewall_roles(
                            ipv4_ports, ipv6_ports
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_no_supported_firewall(self):
        """Test applying firewall roles when no firewall is found."""
        ipv4_ports = [{"port": 80, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_apply(_port_configs, _agent_ports, _errors):
            return None

        async def mock_ipfw_apply(_port_configs, _agent_ports, _errors):
            return None

        async def mock_npf_apply(_port_configs, _agent_ports, _errors):
            return None

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "apply_firewall_roles_pf", side_effect=mock_pf_apply
            ):
                with patch.object(
                    self.ops.ipfw_ops,
                    "apply_firewall_roles_ipfw",
                    side_effect=mock_ipfw_apply,
                ):
                    with patch.object(
                        self.ops.npf_ops,
                        "apply_firewall_roles_npf",
                        side_effect=mock_npf_apply,
                    ):
                        result = await self.ops.apply_firewall_roles(
                            ipv4_ports, ipv6_ports
                        )

        assert result["success"] is False
        assert "No supported firewall" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_combines_ports(self):
        """Test that apply_firewall_roles combines IPv4 and IPv6 ports."""
        ipv4_ports = [
            {"port": 80, "tcp": True, "udp": False},
            {"port": 53, "tcp": False, "udp": True},
        ]
        ipv6_ports = [
            {"port": 80, "tcp": True, "udp": True},  # Same port, different protocols
        ]

        captured_port_configs = {}

        async def mock_pf_apply(port_configs, _agent_ports, _errors):
            nonlocal captured_port_configs
            captured_port_configs = port_configs
            return {"success": True, "message": "PF roles applied"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "apply_firewall_roles_pf", side_effect=mock_pf_apply
            ):
                await self.ops.apply_firewall_roles(ipv4_ports, ipv6_ports)

        # Port 80 should have both tcp and udp enabled (combined from IPv4 and IPv6)
        assert captured_port_configs[80]["tcp"] is True
        assert captured_port_configs[80]["udp"] is True
        # Port 53 should only have udp
        assert captured_port_configs[53]["tcp"] is False
        assert captured_port_configs[53]["udp"] is True


class TestRemoveFirewallPorts:
    """Test cases for remove_firewall_ports method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}
        self.ops = BSDFirewallOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_success(self):
        """Test removing firewall ports with PF."""
        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_remove(_ports_to_remove, _preserved_ports, _errors):
            return {"success": True, "message": "Ports removed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "remove_firewall_ports_pf", side_effect=mock_pf_remove
            ):
                result = await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_ipfw_fallback(self):
        """Test removing firewall ports falls back to IPFW."""
        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_remove(_ports_to_remove, _preserved_ports, _errors):
            return None

        async def mock_ipfw_remove(_ports_to_remove, _preserved_ports, _errors):
            return {"success": True, "message": "Ports removed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "remove_firewall_ports_pf", side_effect=mock_pf_remove
            ):
                with patch.object(
                    self.ops.ipfw_ops,
                    "remove_firewall_ports_ipfw",
                    side_effect=mock_ipfw_remove,
                ):
                    result = await self.ops.remove_firewall_ports(
                        ipv4_ports, ipv6_ports
                    )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_fallback(self):
        """Test removing firewall ports falls back to NPF."""
        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_remove(_ports_to_remove, _preserved_ports, _errors):
            return None

        async def mock_ipfw_remove(_ports_to_remove, _preserved_ports, _errors):
            return None

        async def mock_npf_remove(_ports_to_remove, _preserved_ports, _errors):
            return {"success": True, "message": "Ports removed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "remove_firewall_ports_pf", side_effect=mock_pf_remove
            ):
                with patch.object(
                    self.ops.ipfw_ops,
                    "remove_firewall_ports_ipfw",
                    side_effect=mock_ipfw_remove,
                ):
                    with patch.object(
                        self.ops.npf_ops,
                        "remove_firewall_ports_npf",
                        side_effect=mock_npf_remove,
                    ):
                        result = await self.ops.remove_firewall_ports(
                            ipv4_ports, ipv6_ports
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_no_supported_firewall(self):
        """Test removing ports when no supported firewall is found."""
        ipv4_ports = [{"port": 9000, "tcp": True, "udp": False}]
        ipv6_ports = []

        async def mock_pf_remove(_ports_to_remove, _preserved_ports, _errors):
            return None

        async def mock_ipfw_remove(_ports_to_remove, _preserved_ports, _errors):
            return None

        async def mock_npf_remove(_ports_to_remove, _preserved_ports, _errors):
            return None

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "remove_firewall_ports_pf", side_effect=mock_pf_remove
            ):
                with patch.object(
                    self.ops.ipfw_ops,
                    "remove_firewall_ports_ipfw",
                    side_effect=mock_ipfw_remove,
                ):
                    with patch.object(
                        self.ops.npf_ops,
                        "remove_firewall_ports_npf",
                        side_effect=mock_npf_remove,
                    ):
                        result = await self.ops.remove_firewall_ports(
                            ipv4_ports, ipv6_ports
                        )

        assert result["success"] is False
        assert "No supported" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_preserves_agent_ports(self):
        """Test that agent communication ports and SSH are preserved."""
        ipv4_ports = [
            {"port": 22, "tcp": True, "udp": False},  # SSH should be preserved
            {"port": 8080, "tcp": True, "udp": False},  # Agent port should be preserved
            {"port": 9000, "tcp": True, "udp": False},  # This should be removed
        ]
        ipv6_ports = []

        captured_preserved_ports = set()

        async def mock_pf_remove(_ports_to_remove, preserved_ports, _errors):
            nonlocal captured_preserved_ports
            captured_preserved_ports = preserved_ports
            return {"success": True, "message": "Ports removed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "remove_firewall_ports_pf", side_effect=mock_pf_remove
            ):
                await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        # Verify preserved ports include SSH (22) and agent port (8080)
        assert 22 in captured_preserved_ports
        assert 8080 in captured_preserved_ports

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_combines_protocols(self):
        """Test that port protocols are combined from IPv4 and IPv6."""
        ipv4_ports = [
            {"port": 9000, "tcp": True, "udp": False},
        ]
        ipv6_ports = [
            {"port": 9000, "tcp": False, "udp": True},  # Same port, different protocol
        ]

        captured_ports_to_remove = {}

        async def mock_pf_remove(ports_to_remove, _preserved_ports, _errors):
            nonlocal captured_ports_to_remove
            captured_ports_to_remove = ports_to_remove
            return {"success": True, "message": "Ports removed"}

        with patch.object(
            self.ops, "_get_agent_communication_ports", return_value=([8080], "tcp")
        ):
            with patch.object(
                self.ops.pf_ops, "remove_firewall_ports_pf", side_effect=mock_pf_remove
            ):
                await self.ops.remove_firewall_ports(ipv4_ports, ipv6_ports)

        # Port 9000 should have both tcp and udp marked for removal
        assert captured_ports_to_remove[9000]["tcp"] is True
        assert captured_ports_to_remove[9000]["udp"] is True
