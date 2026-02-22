"""
Unit tests for src.sysmanage_agent.operations.firewall_bsd_ipfw module.
Tests IPFW (IP Firewall) operations for FreeBSD systems.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods
# pylint: disable=unused-argument,unused-variable

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.core.async_utils import AsyncProcessResult
from src.sysmanage_agent.operations.firewall_bsd_ipfw import IPFWFirewallOperations


class MockParent:
    """Mock parent BSDFirewallOperations for testing."""

    def __init__(self):
        self.logger = Mock()
        self._send_firewall_status_update = AsyncMock()

    def _build_command(self, command):
        """Return command as-is (simulating privileged mode)."""
        return command


class TestIPFWFirewallOperationsInit:
    """Test cases for IPFWFirewallOperations initialization."""

    def test_init(self):
        """Test IPFWFirewallOperations initialization."""
        mock_parent = MockParent()

        ipfw = IPFWFirewallOperations(mock_parent)

        assert ipfw.parent == mock_parent
        assert ipfw.logger == mock_parent.logger


class TestIsIPFWAvailable:
    """Test cases for checking IPFW availability."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_is_ipfw_available_true(self):
        """Test _is_ipfw_available returns True when ipfw list succeeds."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw._is_ipfw_available()

        assert result is True

    @pytest.mark.asyncio
    async def test_is_ipfw_available_false(self):
        """Test _is_ipfw_available returns False when ipfw list fails."""
        mock_result = AsyncProcessResult(
            returncode=1, stdout="", stderr="ipfw not found"
        )

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw._is_ipfw_available()

        assert result is False


class TestEnableIPFWFirewall:
    """Test cases for enabling IPFW firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_enable_firewall_success(self):
        """Test enabling firewall successfully."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        rc_conf_content = 'some_setting="value"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is True
        assert (
            "enabled" in result["message"].lower()
            or "successfully" in result["message"].lower()
        )
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_firewall_kldload_already_loaded(self):
        """Test enabling firewall when kernel module is already loaded (returncode=1)."""
        # kldload returns 1 if already loaded, which is fine
        mock_results = [
            AsyncProcessResult(
                returncode=1, stdout="", stderr="already loaded"
            ),  # kldload
            AsyncProcessResult(
                returncode=0, stdout="", stderr=""
            ),  # sysrc firewall_enable
            AsyncProcessResult(
                returncode=0, stdout="", stderr=""
            ),  # sysrc firewall_type
            AsyncProcessResult(
                returncode=0, stdout="", stderr=""
            ),  # service ipfw start
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # ipfw add ssh
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # ipfw add port
        ]
        call_index = [0]

        async def mock_run_command(*args, **kwargs):
            idx = call_index[0]
            call_index[0] += 1
            return mock_results[min(idx, len(mock_results) - 1)]

        rc_conf_content = 'some_setting="value"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_kldload_failure(self):
        """Test enabling firewall when kernel module load fails with unexpected error."""
        mock_results = [
            AsyncProcessResult(
                returncode=2, stdout="", stderr="module not found"
            ),  # kldload
            AsyncProcessResult(
                returncode=0, stdout="", stderr=""
            ),  # service ipfw start
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # ipfw add ssh
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # ipfw add port
        ]
        call_index = [0]

        async def mock_run_command(*args, **kwargs):
            idx = call_index[0]
            call_index[0] += 1
            return mock_results[min(idx, len(mock_results) - 1)]

        rc_conf_content = 'firewall_enable="YES"\n'  # Already enabled

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        # Should still succeed (kldload failure is a warning)
        assert result["success"] is True
        self.mock_parent.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_service_start_failure(self):
        """Test enabling firewall with service start failure."""
        mock_results = [
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # kldload
            AsyncProcessResult(
                returncode=1, stdout="", stderr="service start failed"
            ),  # service start
        ]
        call_index = [0]

        async def mock_run_command(*args, **kwargs):
            idx = call_index[0]
            call_index[0] += 1
            return mock_results[min(idx, len(mock_results) - 1)]

        rc_conf_content = 'firewall_enable="YES"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is False
        assert "error" in result
        assert "service start failed" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_firewall_rc_conf_not_enabled(self):
        """Test enabling firewall when rc.conf needs updating."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        rc_conf_content = 'some_setting="value"\n'  # No firewall_enable

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ) as mock_run:
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is True
        # Should have called sysrc to enable firewall
        call_args_list = [str(call) for call in mock_run.call_args_list]
        assert any(
            "sysrc" in str(call) and "firewall_enable" in str(call)
            for call in call_args_list
        )

    @pytest.mark.asyncio
    async def test_enable_firewall_rc_conf_read_exception(self):
        """Test enabling firewall when rc.conf read fails."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(side_effect=Exception("Permission denied"))
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        # Should still succeed (rc.conf error is a warning)
        assert result["success"] is True
        self.mock_parent.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_multiple_ports(self):
        """Test enabling firewall with multiple ports."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        rc_conf_content = 'firewall_enable="YES"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        call_count = [0]

        async def mock_run_command(*args, **kwargs):
            call_count[0] += 1
            return mock_result

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080, 8443, 3000], "tcp")

        assert result["success"] is True
        # kldload + service start + ssh rule + 3 port rules = 6 calls
        assert call_count[0] >= 5

    @pytest.mark.asyncio
    async def test_enable_firewall_ssh_rule_failure_warning(self):
        """Test enabling firewall when SSH rule fails (warning only)."""
        mock_results = [
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # kldload
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # service start
            AsyncProcessResult(
                returncode=1, stdout="", stderr="rule exists"
            ),  # ssh rule
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # port rule
        ]
        call_index = [0]

        async def mock_run_command(*args, **kwargs):
            idx = call_index[0]
            call_index[0] += 1
            return mock_results[min(idx, len(mock_results) - 1)]

        rc_conf_content = 'firewall_enable="YES"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is True
        self.mock_parent.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_port_rule_failure_warning(self):
        """Test enabling firewall when port rule fails (warning only)."""
        mock_results = [
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # kldload
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # service start
            AsyncProcessResult(returncode=0, stdout="", stderr=""),  # ssh rule
            AsyncProcessResult(
                returncode=1, stdout="", stderr="port rule failed"
            ),  # port rule
        ]
        call_index = [0]

        async def mock_run_command(*args, **kwargs):
            idx = call_index[0]
            call_index[0] += 1
            return mock_results[min(idx, len(mock_results) - 1)]

        rc_conf_content = 'firewall_enable="YES"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is True
        self.mock_parent.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_enable_firewall_exception(self):
        """Test enabling firewall with general exception."""
        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.ipfw.enable_ipfw_firewall([8080], "tcp")

        assert result["success"] is False
        assert "error" in result
        assert "Unexpected error" in result["error"]
        self.mock_parent.logger.error.assert_called()


class TestDeleteSysmanageIPFWRules:
    """Test cases for deleting SysManage IPFW rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_delete_sysmanage_ipfw_rules(self):
        """Test deleting SysManage IPFW rules in range 10000-19999."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        call_count = [0]

        async def mock_run_command(*args, **kwargs):
            call_count[0] += 1
            return mock_result

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=mock_run_command,
        ):
            await self.ipfw._delete_sysmanage_ipfw_rules()

        # Should call for each rule number from 10000 to 19999 (10000 calls)
        assert call_count[0] == 10000
        self.mock_parent.logger.info.assert_called()


class TestAddIPFWRule:
    """Test cases for adding IPFW rules."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_add_ipfw_rule_success(self):
        """Test adding IPFW rule successfully."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            await self.ipfw._add_ipfw_rule(10000, "tcp", 80, errors)

        assert not errors
        self.mock_parent.logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_add_ipfw_rule_failure(self):
        """Test adding IPFW rule with failure."""
        mock_result = AsyncProcessResult(returncode=1, stdout="", stderr="rule failed")
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            await self.ipfw._add_ipfw_rule(10000, "tcp", 80, errors)

        assert len(errors) == 1
        assert "80" in errors[0]
        assert "TCP" in errors[0]

    @pytest.mark.asyncio
    async def test_add_ipfw_rule_udp(self):
        """Test adding IPFW rule for UDP protocol."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ) as mock_run:
            await self.ipfw._add_ipfw_rule(10000, "udp", 53, errors)

        assert not errors
        # Verify UDP was passed
        call_args = mock_run.call_args[0][0]
        assert "udp" in call_args


class TestApplyFirewallRolesIPFW:
    """Test cases for applying firewall roles using IPFW."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_success(self):
        """Test applying firewall roles successfully."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        port_configs = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
        }
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                with patch.object(self.ipfw, "_add_ipfw_rule", new_callable=AsyncMock):
                    result = await self.ipfw.apply_firewall_roles_ipfw(
                        port_configs, agent_ports, errors
                    )

        assert result["success"] is True
        assert (
            "synchronized" in result["message"].lower() or "IPFW" in result["message"]
        )
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_ipfw_not_available(self):
        """Test apply_firewall_roles returns None when IPFW is not available."""
        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=False):
            result = await self.ipfw.apply_firewall_roles_ipfw(
                port_configs, agent_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_preserves_agent_ports(self):
        """Test that agent ports are preserved and not processed."""
        add_rule_calls = []

        async def mock_add_rule(rule_num, protocol, port, errors):
            add_rule_calls.append((rule_num, protocol, port))

        port_configs = {
            80: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},  # Agent port - should be skipped
            22: {"tcp": True, "udp": False},  # SSH port - should be skipped
        }
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                with patch.object(
                    self.ipfw, "_add_ipfw_rule", side_effect=mock_add_rule
                ):
                    result = await self.ipfw.apply_firewall_roles_ipfw(
                        port_configs, agent_ports, errors
                    )

        assert result["success"] is True
        # Only port 80 should be added (8080 and 22 are preserved)
        ports_added = [call[2] for call in add_rule_calls]
        assert 80 in ports_added
        assert 8080 not in ports_added
        assert 22 not in ports_added

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_tcp_and_udp(self):
        """Test applying firewall roles with both TCP and UDP."""
        add_rule_calls = []

        async def mock_add_rule(rule_num, protocol, port, errors):
            add_rule_calls.append((rule_num, protocol, port))

        port_configs = {
            53: {"tcp": True, "udp": True},  # DNS - both protocols
        }
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                with patch.object(
                    self.ipfw, "_add_ipfw_rule", side_effect=mock_add_rule
                ):
                    result = await self.ipfw.apply_firewall_roles_ipfw(
                        port_configs, agent_ports, errors
                    )

        assert result["success"] is True
        # Should have both TCP and UDP rules for port 53
        assert len(add_rule_calls) == 2
        protocols = [call[1] for call in add_rule_calls]
        assert "tcp" in protocols
        assert "udp" in protocols

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_with_errors(self):
        """Test applying firewall roles with some errors."""

        async def mock_add_rule(rule_num, protocol, port, errors):
            errors.append(f"Failed to add rule for port {port}")

        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                with patch.object(
                    self.ipfw, "_add_ipfw_rule", side_effect=mock_add_rule
                ):
                    result = await self.ipfw.apply_firewall_roles_ipfw(
                        port_configs, agent_ports, errors
                    )

        assert result["success"] is False
        assert "error" in result
        assert "80" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_file_not_found(self):
        """Test apply_firewall_roles returns None on FileNotFoundError."""
        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch.object(
            self.ipfw,
            "_is_ipfw_available",
            side_effect=FileNotFoundError("ipfw not found"),
        ):
            result = await self.ipfw.apply_firewall_roles_ipfw(
                port_configs, agent_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_timeout(self):
        """Test apply_firewall_roles returns None on TimeoutError."""
        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch.object(
            self.ipfw,
            "_is_ipfw_available",
            side_effect=asyncio.TimeoutError("timed out"),
        ):
            result = await self.ipfw.apply_firewall_roles_ipfw(
                port_configs, agent_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_rule_numbering(self):
        """Test that rule numbers are incremented correctly."""
        add_rule_calls = []

        async def mock_add_rule(rule_num, protocol, port, errors):
            add_rule_calls.append((rule_num, protocol, port))

        port_configs = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
            8000: {"tcp": True, "udp": True},  # Both protocols
        }
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                with patch.object(
                    self.ipfw, "_add_ipfw_rule", side_effect=mock_add_rule
                ):
                    await self.ipfw.apply_firewall_roles_ipfw(
                        port_configs, agent_ports, errors
                    )

        # Rule numbers should start at 10000 and increment
        rule_nums = [call[0] for call in add_rule_calls]
        assert rule_nums[0] == 10000
        for i in range(1, len(rule_nums)):
            assert rule_nums[i] == rule_nums[i - 1] + 1


class TestRemoveFirewallPortsIPFW:
    """Test cases for removing specific firewall ports using IPFW."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_success(self):
        """Test removing firewall ports successfully."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            9000: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        assert "IPFW" in result["message"]
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_ipfw_not_available(self):
        """Test remove_firewall_ports returns None when IPFW is not available."""
        mock_result = AsyncProcessResult(
            returncode=1, stdout="", stderr="ipfw not found"
        )

        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_preserves_ssh(self):
        """Test that SSH port 22 is preserved during removal."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            22: {"tcp": True, "udp": False},  # Should be skipped
            9000: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # Check logger was called for skipping preserved port
        info_calls = [str(call) for call in self.mock_parent.logger.info.call_args_list]
        assert any(
            "22" in str(call)
            and ("skip" in str(call).lower() or "preserv" in str(call).lower())
            for call in info_calls
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_preserves_agent_port(self):
        """Test that agent port is preserved during removal."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            8080: {"tcp": True, "udp": False},  # Agent port - should be skipped
            9000: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_tcp_and_udp(self):
        """Test removing ports with both TCP and UDP protocols."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            53: {"tcp": True, "udp": True},  # Both protocols
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # Check that both protocols were logged
        info_calls = [str(call) for call in self.mock_parent.logger.info.call_args_list]
        assert any(
            "tcp/udp" in str(call).lower()
            or ("tcp" in str(call).lower() and "udp" in str(call).lower())
            for call in info_calls
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_file_not_found(self):
        """Test remove_firewall_ports returns None on FileNotFoundError."""
        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=FileNotFoundError("ipfw not found"),
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_timeout(self):
        """Test remove_firewall_ports returns None on TimeoutError."""
        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            side_effect=asyncio.TimeoutError("timed out"),
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_empty_ports(self):
        """Test removing empty port list."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {}
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_only_tcp(self):
        """Test removing port with only TCP protocol."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            80: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # Should log tcp only
        info_calls = [str(call) for call in self.mock_parent.logger.info.call_args_list]
        assert any("tcp" in str(call).lower() for call in info_calls)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_only_udp(self):
        """Test removing port with only UDP protocol."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            53: {"tcp": False, "udp": True},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # Should log udp only
        info_calls = [str(call) for call in self.mock_parent.logger.info.call_args_list]
        assert any("udp" in str(call).lower() for call in info_calls)


class TestIPFWEdgeCases:
    """Test edge cases and error handling for IPFW operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = MockParent()
        self.ipfw = IPFWFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_enable_firewall_empty_ports_list(self):
        """Test enabling firewall with empty ports list."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        rc_conf_content = 'firewall_enable="YES"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_firewall_udp_protocol(self):
        """Test enabling firewall with UDP protocol."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")
        rc_conf_content = 'firewall_enable="YES"\n'

        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ) as mock_run:
            with patch("aiofiles.open", return_value=mock_file):
                result = await self.ipfw.enable_ipfw_firewall([53], "udp")

        assert result["success"] is True
        # Verify UDP was passed for the port rule
        call_args_list = [call[0][0] for call in mock_run.call_args_list]
        port_rule_calls = [
            args for args in call_args_list if "53" in [str(a) for a in args]
        ]
        assert any("udp" in [str(a) for a in call] for call in port_rule_calls)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_empty_port_configs(self):
        """Test applying firewall roles with empty port configs."""
        port_configs = {}
        agent_ports = [8080]
        errors = []

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                result = await self.ipfw.apply_firewall_roles_ipfw(
                    port_configs, agent_ports, errors
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_all_preserved(self):
        """Test applying firewall roles when all ports are preserved."""
        port_configs = {
            22: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},
        }
        agent_ports = [8080]
        errors = []

        add_rule_called = [False]

        async def mock_add_rule(rule_num, protocol, port, errors):
            add_rule_called[0] = True

        with patch.object(self.ipfw, "_is_ipfw_available", return_value=True):
            with patch.object(
                self.ipfw, "_delete_sysmanage_ipfw_rules", new_callable=AsyncMock
            ):
                with patch.object(
                    self.ipfw, "_add_ipfw_rule", side_effect=mock_add_rule
                ):
                    result = await self.ipfw.apply_firewall_roles_ipfw(
                        port_configs, agent_ports, errors
                    )

        assert result["success"] is True
        # _add_ipfw_rule should not have been called
        assert add_rule_called[0] is False

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_all_preserved(self):
        """Test removing firewall ports when all are preserved."""
        mock_result = AsyncProcessResult(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            22: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_ipfw.run_command_async",
            return_value=mock_result,
        ):
            result = await self.ipfw.remove_firewall_ports_ipfw(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # All ports should be logged as skipped
        info_calls = [str(call) for call in self.mock_parent.logger.info.call_args_list]
        skip_calls = [
            c for c in info_calls if "skip" in c.lower() or "preserv" in c.lower()
        ]
        assert len(skip_calls) >= 2


class TestIPFWBuildCommand:
    """Test the parent's _build_command integration."""

    def test_build_command_privileged(self):
        """Test _build_command returns command as-is in privileged mode."""
        mock_parent = MockParent()
        ipfw = IPFWFirewallOperations(mock_parent)

        # MockParent returns command as-is (simulating privileged)
        command = ["ipfw", "add", "allow", "tcp"]
        result = mock_parent._build_command(command)
        assert result == command

    def test_build_command_with_sudo(self):
        """Test _build_command adds sudo in non-privileged mode."""

        class MockParentWithSudo:
            """Mock parent that adds sudo to commands."""

            def __init__(self):
                self.logger = Mock()
                self._send_firewall_status_update = AsyncMock()

            def _build_command(self, command):
                return ["sudo"] + command

        mock_parent = MockParentWithSudo()
        ipfw = IPFWFirewallOperations(mock_parent)

        command = ["ipfw", "add", "allow", "tcp"]
        result = mock_parent._build_command(command)
        assert result == ["sudo", "ipfw", "add", "allow", "tcp"]
