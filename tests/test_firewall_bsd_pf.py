"""
Unit tests for src.sysmanage_agent.operations.firewall_bsd_pf module.
Tests PF (Packet Filter) firewall operations for BSD systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_bsd_pf import PFFirewallOperations


class TestPFFirewallOperationsInit:
    """Test cases for PFFirewallOperations initialization."""

    def test_init(self):
        """Test PFFirewallOperations initialization."""
        mock_parent = Mock()
        mock_parent.logger = Mock()

        pf_ops = PFFirewallOperations(mock_parent)

        assert pf_ops.parent == mock_parent
        assert pf_ops.logger == mock_parent.logger


class TestEnablePFFirewall:
    """Test cases for enabling PF firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_success_new_config(self):
        """Test enabling PF firewall with new configuration (pf.conf doesn't exist)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Mock aiofiles.open: first call raises FileNotFoundError (read), rest succeed
        mock_write_file = AsyncMock()
        mock_write_file.__aenter__.return_value = mock_write_file
        mock_write_file.__aexit__.return_value = None
        mock_write_file.write = AsyncMock()

        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call is read - file doesn't exist
                raise FileNotFoundError("pf.conf not found")
            return mock_write_file

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_pf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled" in result["message"].lower()
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_existing_rules(self):
        """Test enabling PF firewall with existing rules."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        existing_rules = "# Existing rules\npass in proto tcp to port 22\n"

        mock_file = AsyncMock()
        mock_file.__aenter__.return_value = mock_file
        mock_file.__aexit__.return_value = None
        mock_file.read = AsyncMock(return_value=existing_rules)
        mock_file.write = AsyncMock()

        with patch("aiofiles.open", return_value=mock_file):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_adds_ssh_rule(self):
        """Test that SSH rule (port 22) is added if missing."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        existing_rules = "# No SSH rule\n"

        mock_file = AsyncMock()
        mock_file.__aenter__.return_value = mock_file
        mock_file.__aexit__.return_value = None
        mock_file.read = AsyncMock(return_value=existing_rules)
        mock_file.write = AsyncMock()

        with patch("aiofiles.open", return_value=mock_file):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True
        # Verify that write was called (rules were added)
        mock_file.write.assert_called()

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_skips_existing_port_rule(self):
        """Test that existing port rules are not duplicated."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        existing_rules = (
            "pass in proto tcp to port 22\npass in proto tcp to port 8080\n"
        )

        mock_file = AsyncMock()
        mock_file.__aenter__.return_value = mock_file
        mock_file.__aexit__.return_value = None
        mock_file.read = AsyncMock(return_value=existing_rules)
        mock_file.write = AsyncMock()

        with patch("aiofiles.open", return_value=mock_file):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True
        # Write should not be called since all rules already exist
        mock_file.write.assert_not_called()

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_permission_error_uses_sudo(self):
        """Test that sudo is used when permission error occurs."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # First open for reading succeeds with no existing rules
        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        # Second open for writing raises PermissionError
        mock_write_file = AsyncMock()
        mock_write_file.__aenter__.side_effect = PermissionError("Permission denied")

        open_call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            open_call_count[0] += 1
            if open_call_count[0] == 1:
                return mock_read_file
            raise PermissionError("Permission denied")

        with patch("aiofiles.open", side_effect=mock_open_side_effect):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True
        # Verify subprocess.run was called (for sudo and pfctl commands)
        assert mock_run.call_count >= 3

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_config_test_fails(self):
        """Test enabling PF when configuration test fails."""
        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        mock_result_fail = Mock()
        mock_result_fail.returncode = 1
        mock_result_fail.stderr = "Syntax error in pf.conf"

        with patch("aiofiles.open", return_value=mock_read_file):
            with patch("subprocess.run", return_value=mock_result_fail):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "configuration test failed" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_load_rules_fails(self):
        """Test enabling PF when loading rules fails."""
        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        # First call (config test) succeeds, second call (load rules) fails
        mock_result_success = Mock()
        mock_result_success.returncode = 0
        mock_result_success.stderr = ""

        mock_result_fail = Mock()
        mock_result_fail.returncode = 1
        mock_result_fail.stderr = "Failed to load rules"

        with patch("aiofiles.open", return_value=mock_read_file):
            with patch(
                "subprocess.run", side_effect=[mock_result_success, mock_result_fail]
            ):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Failed to load PF rules" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_enable_fails(self):
        """Test enabling PF when pfctl -e fails."""
        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        # Config test and load rules succeed, enable fails
        mock_result_success = Mock()
        mock_result_success.returncode = 0
        mock_result_success.stderr = ""

        mock_result_fail = Mock()
        mock_result_fail.returncode = 1
        mock_result_fail.stderr = "Failed to enable PF"

        with patch("aiofiles.open", return_value=mock_read_file):
            with patch(
                "subprocess.run",
                side_effect=[
                    mock_result_success,
                    mock_result_success,
                    mock_result_fail,
                ],
            ):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Failed to enable PF" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_already_enabled(self):
        """Test enabling PF when already enabled (success case)."""
        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        mock_result_success = Mock()
        mock_result_success.returncode = 0
        mock_result_success.stderr = ""

        # pfctl -e returns error with "already enabled" message
        mock_result_already_enabled = Mock()
        mock_result_already_enabled.returncode = 1
        mock_result_already_enabled.stderr = "pf already enabled"

        with patch("aiofiles.open", return_value=mock_read_file):
            with patch(
                "subprocess.run",
                side_effect=[
                    mock_result_success,
                    mock_result_success,
                    mock_result_already_enabled,
                ],
            ):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_multiple_ports(self):
        """Test enabling PF with multiple ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        mock_write_file = AsyncMock()
        mock_write_file.__aenter__.return_value = mock_write_file
        mock_write_file.__aexit__.return_value = None
        mock_write_file.write = AsyncMock()

        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_read_file
            return mock_write_file

        with patch("aiofiles.open", side_effect=mock_open_side_effect):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080, 3000], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_udp_protocol(self):
        """Test enabling PF with UDP protocol."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        mock_write_file = AsyncMock()
        mock_write_file.__aenter__.return_value = mock_write_file
        mock_write_file.__aexit__.return_value = None
        mock_write_file.write = AsyncMock()

        call_count = [0]

        def mock_open_side_effect_udp(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_read_file
            return mock_write_file

        with patch("aiofiles.open", side_effect=mock_open_side_effect_udp):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([53], "udp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_exception_handling(self):
        """Test exception handling in enable_pf_firewall."""
        with patch("aiofiles.open", side_effect=Exception("Unexpected error")):
            result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        self.mock_parent.logger.error.assert_called()


class TestApplyFirewallRolesPF:
    """Test cases for applying firewall roles using PF."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_not_available(self):
        """Test apply_firewall_roles when PF is not available."""
        mock_result = Mock()
        mock_result.returncode = 1  # pfctl -s info fails

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf({}, [], [])

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_success_no_ports(self):
        """Test apply_firewall_roles with no ports to configure."""
        # PF available check succeeds
        mock_result_available = Mock()
        mock_result_available.returncode = 0

        # Flush anchor succeeds
        mock_result_flush = Mock()
        mock_result_flush.returncode = 0

        with patch(
            "subprocess.run", side_effect=[mock_result_available, mock_result_flush]
        ):
            result = await self.pf_ops.apply_firewall_roles_pf({}, [8080], [])

        assert result["success"] is True
        assert "synchronized" in result["message"].lower()
        self.mock_parent._send_firewall_status_update.assert_called_once()
        self.mock_parent.logger.info.assert_any_call("No role ports to configure in PF")

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_success_with_ports(self):
        """Test apply_firewall_roles with ports to configure."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        port_configs = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
        }

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf(port_configs, [8080], [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_skips_preserved_ports(self):
        """Test that preserved ports (agent + SSH) are skipped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Include agent port 8080 and SSH port 22 in configs
        port_configs = {
            22: {"tcp": True, "udp": False},
            80: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},
        }

        with patch("subprocess.run", return_value=mock_result) as _mock_run:
            result = await self.pf_ops.apply_firewall_roles_pf(port_configs, [8080], [])

        assert result["success"] is True
        # Only port 80 should be added (22 and 8080 are preserved)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_tcp_and_udp(self):
        """Test apply_firewall_roles with both TCP and UDP ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        port_configs = {
            53: {"tcp": True, "udp": True},
        }

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf(port_configs, [8080], [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_add_rules_fails(self):
        """Test apply_firewall_roles when adding rules fails."""
        # PF available check succeeds
        mock_result_available = Mock()
        mock_result_available.returncode = 0

        # Flush anchor succeeds
        mock_result_flush = Mock()
        mock_result_flush.returncode = 0

        # Add rules fails
        mock_result_fail = Mock()
        mock_result_fail.returncode = 1
        mock_result_fail.stderr = "Failed to add rules"

        port_configs = {80: {"tcp": True, "udp": False}}

        with patch(
            "subprocess.run",
            side_effect=[mock_result_available, mock_result_flush, mock_result_fail],
        ):
            result = await self.pf_ops.apply_firewall_roles_pf(port_configs, [8080], [])

        assert result["success"] is False
        assert "Failed to add PF rules" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_with_existing_errors(self):
        """Test apply_firewall_roles with pre-existing errors."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        existing_errors = ["Previous error occurred"]

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf(
                {}, [8080], existing_errors
            )

        assert result["success"] is False
        assert "Previous error occurred" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_file_not_found(self):
        """Test apply_firewall_roles when pfctl is not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError("pfctl not found")):
            result = await self.pf_ops.apply_firewall_roles_pf({}, [8080], [])

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_timeout(self):
        """Test apply_firewall_roles when command times out."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="pfctl", timeout=5),
        ):
            result = await self.pf_ops.apply_firewall_roles_pf({}, [8080], [])

        assert result is None


class TestRemoveFirewallPortsPF:
    """Test cases for removing firewall ports using PF."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_not_available(self):
        """Test remove_firewall_ports when PF is not available."""
        mock_result = Mock()
        mock_result.returncode = 1  # pfctl -s info fails

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf({}, set(), [])

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_success(self):
        """Test remove_firewall_ports successfully."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            9000: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        assert "acknowledged" in result["message"].lower()
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_skips_preserved_ports(self):
        """Test that preserved ports are not removed."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            22: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},
            9000: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        # Verify logging for skipped ports
        self.mock_parent.logger.info.assert_any_call(
            "Skipping removal of preserved port %d (agent/SSH)", 22
        )
        self.mock_parent.logger.info.assert_any_call(
            "Skipping removal of preserved port %d (agent/SSH)", 8080
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_tcp_and_udp(self):
        """Test remove_firewall_ports with both TCP and UDP."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            53: {"tcp": True, "udp": True},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        # Verify logging for port removal request
        self.mock_parent.logger.info.assert_any_call(
            "PF: Requested removal of port %d (%s)", 53, "tcp/udp"
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_tcp_only(self):
        """Test remove_firewall_ports with TCP only."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            80: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        self.mock_parent.logger.info.assert_any_call(
            "PF: Requested removal of port %d (%s)", 80, "tcp"
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_udp_only(self):
        """Test remove_firewall_ports with UDP only."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            161: {"tcp": False, "udp": True},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        self.mock_parent.logger.info.assert_any_call(
            "PF: Requested removal of port %d (%s)", 161, "udp"
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_logs_manual_note(self):
        """Test that manual configuration note is logged."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        self.mock_parent.logger.info.assert_any_call(
            "PF firewall port removal requires manual /etc/pf.conf editing "
            "and pfctl -f /etc/pf.conf reload"
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_file_not_found(self):
        """Test remove_firewall_ports when pfctl is not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError("pfctl not found")):
            result = await self.pf_ops.remove_firewall_ports_pf({}, set(), [])

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_timeout(self):
        """Test remove_firewall_ports when command times out."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="pfctl", timeout=5),
        ):
            result = await self.pf_ops.remove_firewall_ports_pf({}, set(), [])

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_multiple_ports(self):
        """Test remove_firewall_ports with multiple ports."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
            53: {"tcp": True, "udp": True},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        # Verify logging was called for each port
        assert self.mock_parent.logger.info.call_count >= 3


class TestEnablePFFirewallEdgeCases:
    """Test edge cases for enable_pf_firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_empty_ports_list(self):
        """Test enabling PF with empty ports list."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_file = AsyncMock()
        mock_file.__aenter__.return_value = mock_file
        mock_file.__aexit__.return_value = None
        mock_file.read = AsyncMock(return_value="")
        mock_file.write = AsyncMock()

        call_count = [0]

        def mock_open_side_effect_empty(*_args, **_kwargs):
            call_count[0] += 1
            return mock_file

        with patch("aiofiles.open", side_effect=mock_open_side_effect_empty):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_pf_firewall_special_characters_in_rules(self):
        """Test enabling PF with existing complex rules."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Complex existing rules with various directives
        existing_rules = """
# PF configuration
set skip on lo0
block in all
pass out all keep state
pass in proto tcp to port 22
        """

        mock_file = AsyncMock()
        mock_file.__aenter__.return_value = mock_file
        mock_file.__aexit__.return_value = None
        mock_file.read = AsyncMock(return_value=existing_rules)
        mock_file.write = AsyncMock()

        call_count = [0]

        def mock_open_side_effect_special(*_args, **_kwargs):
            call_count[0] += 1
            return mock_file

        with patch("aiofiles.open", side_effect=mock_open_side_effect_special):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080], "tcp")

        assert result["success"] is True


class TestApplyFirewallRolesPFEdgeCases:
    """Test edge cases for apply_firewall_roles_pf."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_many_ports(self):
        """Test apply_firewall_roles with many ports."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # Create many ports
        port_configs = {i: {"tcp": True, "udp": False} for i in range(100, 200)}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf(port_configs, [8080], [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_empty_port_configs(self):
        """Test apply_firewall_roles with empty port configs."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf({}, [8080], [])

        assert result["success"] is True
        self.mock_parent.logger.info.assert_any_call("No role ports to configure in PF")

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_pf_all_preserved(self):
        """Test apply_firewall_roles when all ports are preserved."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # All ports in the config are agent or SSH ports
        port_configs = {
            22: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},
        }

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.apply_firewall_roles_pf(port_configs, [8080], [])

        assert result["success"] is True
        # Should log "No role ports to configure"
        self.mock_parent.logger.info.assert_any_call("No role ports to configure in PF")


class TestRemoveFirewallPortsPFEdgeCases:
    """Test edge cases for remove_firewall_ports_pf."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_empty_ports(self):
        """Test remove_firewall_ports with empty ports dictionary."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf({}, {22, 8080}, [])

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_all_preserved(self):
        """Test remove_firewall_ports when all ports are preserved."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            22: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True
        # Both ports should be logged as skipped
        assert self.mock_parent.logger.info.call_count >= 2

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_pf_no_protocols(self):
        """Test remove_firewall_ports when port has no protocols set."""
        mock_result = Mock()
        mock_result.returncode = 0

        ports_to_remove = {
            9000: {"tcp": False, "udp": False},
        }
        preserved_ports = {22, 8080}

        with patch("subprocess.run", return_value=mock_result):
            result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, preserved_ports, []
            )

        assert result["success"] is True


class TestPFFirewallOperationsIntegration:
    """Integration-style tests for PF firewall operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda cmd: cmd)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.pf_ops = PFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_full_enable_workflow(self):
        """Test complete enable workflow from empty config."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_read_file = AsyncMock()
        mock_read_file.__aenter__.return_value = mock_read_file
        mock_read_file.__aexit__.return_value = None
        mock_read_file.read = AsyncMock(return_value="")

        mock_write_file = AsyncMock()
        mock_write_file.__aenter__.return_value = mock_write_file
        mock_write_file.__aexit__.return_value = None
        mock_write_file.write = AsyncMock()

        call_count = [0]

        def mock_open_side_effect_workflow(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_read_file
            return mock_write_file

        with patch("aiofiles.open", side_effect=mock_open_side_effect_workflow):
            with patch("subprocess.run", return_value=mock_result):
                result = await self.pf_ops.enable_pf_firewall([8080, 3000], "tcp")

        assert result["success"] is True
        self.mock_parent.logger.info.assert_called()
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_and_remove_workflow(self):
        """Test applying and then removing firewall roles."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        # First, apply roles
        port_configs = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
        }

        with patch("subprocess.run", return_value=mock_result):
            apply_result = await self.pf_ops.apply_firewall_roles_pf(
                port_configs, [8080], []
            )

        assert apply_result["success"] is True

        # Then, remove one port
        ports_to_remove = {
            80: {"tcp": True, "udp": False},
        }

        with patch("subprocess.run", return_value=mock_result):
            remove_result = await self.pf_ops.remove_firewall_ports_pf(
                ports_to_remove, {22, 8080}, []
            )

        assert remove_result["success"] is True
