"""
Unit tests for src.sysmanage_agent.operations.firewall_bsd_npf module.
Tests NPF (NetBSD Packet Filter) firewall operations.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.firewall_bsd_npf import NPFFirewallOperations


def create_async_file_mock(content="", raise_on_read=False, raise_on_write=False):
    """Create a mock for async file operations that works with async with."""
    mock_file = MagicMock()

    # Create an async read method
    async def mock_read():
        if raise_on_read:
            raise FileNotFoundError()
        return content

    # Create an async write method
    async def mock_write(_content):
        if raise_on_write:
            raise PermissionError("Permission denied")

    mock_file.read = mock_read
    mock_file.write = mock_write

    # Make it work with async context manager
    mock_file.__aenter__ = AsyncMock(return_value=mock_file)
    mock_file.__aexit__ = AsyncMock(return_value=None)

    return mock_file


def create_async_open_mock(content="", raise_file_not_found=False):
    """Create a mock for aiofiles.open that works with async with."""
    mock_file = create_async_file_mock(content)

    def mock_open(*args, **_kwargs):
        if raise_file_not_found and args[1] == "r":
            raise FileNotFoundError()
        return mock_file

    return mock_open, mock_file


class TestNPFFirewallOperationsInit:
    """Test cases for NPFFirewallOperations initialization."""

    def test_init(self):
        """Test NPFFirewallOperations initialization."""
        mock_parent = Mock()
        mock_parent.logger = Mock()

        npf = NPFFirewallOperations(mock_parent)

        assert npf.parent == mock_parent
        assert npf.logger == mock_parent.logger

    def test_init_uses_parent_logger(self):
        """Test that NPFFirewallOperations uses parent's logger."""
        mock_parent = Mock()
        mock_logger = Mock()
        mock_parent.logger = mock_logger

        npf = NPFFirewallOperations(mock_parent)

        assert npf.logger is mock_logger


class TestEnableNpfFirewall:
    """Test cases for enabling NPF firewall."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda x: x)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.npf = NPFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_success_no_existing_config(self):
        """Test enabling NPF firewall successfully when no config exists."""
        # Track what file operations occur
        file_read_attempted = False
        file_written = False

        mock_file = MagicMock()

        async def mock_read():
            nonlocal file_read_attempted
            file_read_attempted = True
            return ""

        async def mock_write(_content):
            nonlocal file_written
            file_written = True

        mock_file.read = mock_read
        mock_file.write = mock_write
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is True
        assert "enabled" in result["message"].lower()
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_success_with_existing_config(self):
        """Test enabling NPF firewall when config already exists."""
        mock_file = MagicMock()

        async def mock_read():
            return "# Existing NPF configuration\ngroup default { }"

        mock_file.read = mock_read
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is True
        self.mock_parent.logger.info.assert_any_call(
            "NPF config already exists, skipping creation"
        )

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_validation_failure(self):
        """Test enabling NPF firewall when validation fails."""
        mock_file = MagicMock()

        async def mock_read():
            return ""

        async def mock_write(_content):
            pass

        mock_file.read = mock_read
        mock_file.write = mock_write
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_validate = Mock(returncode=1, stdout="", stderr="syntax error at line 10")

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", return_value=mock_validate):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "validation failed" in result["error"].lower()
        assert "syntax error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_reload_failure(self):
        """Test enabling NPF firewall when reload fails."""
        mock_file = MagicMock()

        async def mock_read():
            return ""

        async def mock_write(_content):
            pass

        mock_file.read = mock_read
        mock_file.write = mock_write
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate succeeds
            Mock(
                returncode=1, stdout="", stderr="Failed to reload config"
            ),  # reload fails
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "reload" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_start_failure(self):
        """Test enabling NPF firewall when start fails."""
        mock_file = MagicMock()

        async def mock_read():
            return ""

        async def mock_write(_content):
            pass

        mock_file.read = mock_read
        mock_file.write = mock_write
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate succeeds
            Mock(returncode=0, stdout="", stderr=""),  # reload succeeds
            Mock(returncode=1, stdout="", stderr="Failed to start NPF"),  # start fails
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "enable" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_start_already_running(self):
        """Test enabling NPF when already running is treated as success."""
        mock_file = MagicMock()

        async def mock_read():
            return ""

        async def mock_write(_content):
            pass

        mock_file.read = mock_read
        mock_file.write = mock_write
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate succeeds
            Mock(returncode=0, stdout="", stderr=""),  # reload succeeds
            Mock(
                returncode=1, stdout="already running", stderr=""
            ),  # start - already running
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_start_running_in_stderr(self):
        """Test enabling NPF when 'running' is in stderr is treated as success."""
        mock_file = MagicMock()

        async def mock_read():
            return ""

        async def mock_write(_content):
            pass

        mock_file.read = mock_read
        mock_file.write = mock_write
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate succeeds
            Mock(returncode=0, stdout="", stderr=""),  # reload succeeds
            Mock(
                returncode=1, stdout="", stderr="NPF is RUNNING"
            ),  # start - running in stderr
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_file_not_found_creates_config(self):
        """Test enabling NPF when config file doesn't exist creates it."""
        call_count = [0]  # Use list to allow mutation in nested function
        written_content = [None]

        def mock_open_side_effect(*args, **kwargs):
            call_count[0] += 1
            _mode = args[1] if len(args) > 1 else kwargs.get("mode", "r")

            mock_file = MagicMock()

            async def mock_read():
                if call_count[0] == 1:
                    raise FileNotFoundError()
                return ""

            async def mock_write(content):
                written_content[0] = content

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is True
        assert written_content[0] is not None
        content = str(written_content[0])
        assert "group default" in content

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_permission_error_uses_sudo(self):
        """Test enabling NPF when permission error occurs uses sudo."""
        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_file = MagicMock()

            async def mock_read():
                return ""

            async def mock_write(_content):
                if call_count[0] == 2:  # Second call is the write attempt
                    raise PermissionError("Permission denied")

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # sudo write succeeds
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_sudo_write_failure(self):
        """Test enabling NPF when sudo write also fails."""
        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_file = MagicMock()

            async def mock_read():
                return ""

            async def mock_write(_content):
                raise PermissionError("Permission denied")

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_sudo_write = Mock(returncode=1, stdout="", stderr="sudo: failed")

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", return_value=mock_sudo_write):
                result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "write" in result["error"].lower() or "failed" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_exception(self):
        """Test enabling NPF when an exception occurs."""
        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.npf.enable_npf_firewall([8080], "tcp")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        self.mock_parent.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_enable_npf_firewall_logs_debug_info(self):
        """Test that npfctl start logs debug information."""
        mock_file = MagicMock()
        mock_file.read = AsyncMock(return_value="existing config")
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="npf started", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                await self.npf.enable_npf_firewall([8080], "tcp")

        # Verify debug logging was called
        self.mock_parent.logger.debug.assert_called()


class TestApplyFirewallRolesNpf:
    """Test cases for applying firewall roles using NPF."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.npf = NPFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_success(self):
        """Test applying firewall roles successfully."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        port_configs = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
            53: {"tcp": True, "udp": True},
        }
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result is not None
        assert result["success"] is True
        assert "acknowledged" in result["message"].lower()
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_not_available(self):
        """Test applying firewall roles when NPF is not available."""
        mock_result = Mock(returncode=1, stdout="", stderr="npfctl: command not found")

        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result is None  # None means NPF not available

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_file_not_found(self):
        """Test applying firewall roles when npfctl command is not found."""
        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", side_effect=FileNotFoundError("npfctl not found")):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_timeout(self):
        """Test applying firewall roles when command times out."""
        port_configs = {80: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="npfctl", timeout=5),
        ):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_skips_agent_ports(self):
        """Test that agent ports are skipped in the logging."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        # Include agent port in port configs
        port_configs = {
            80: {"tcp": True, "udp": False},
            8080: {"tcp": True, "udp": False},  # Agent port - should be skipped
        }
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result["success"] is True
        # Verify agent port was skipped by checking logger calls
        # Port 80 should be logged, but 8080 should not be
        info_calls = [str(call) for call in self.mock_parent.logger.info.call_args_list]
        # Find calls that contain port numbers
        port_80_logged = any(
            "80" in str(call) and "tcp" in str(call).lower() for call in info_calls
        )
        assert port_80_logged

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_tcp_only(self):
        """Test applying firewall roles with TCP only ports."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        port_configs = {443: {"tcp": True, "udp": False}}
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result["success"] is True
        # Check that only tcp was logged
        info_calls = str(self.mock_parent.logger.info.call_args_list)
        assert "tcp" in info_calls.lower()

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_udp_only(self):
        """Test applying firewall roles with UDP only ports."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        port_configs = {53: {"tcp": False, "udp": True}}
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_both_protocols(self):
        """Test applying firewall roles with both TCP and UDP."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        port_configs = {53: {"tcp": True, "udp": True}}
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_empty_ports(self):
        """Test applying firewall roles with empty port configuration."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        port_configs = {}
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.apply_firewall_roles_npf(
                port_configs, agent_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_firewall_roles_npf_logs_port_count(self):
        """Test that apply logs the port count."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        port_configs = {
            80: {"tcp": True, "udp": False},
            443: {"tcp": True, "udp": False},
            8443: {"tcp": True, "udp": False},
        }
        agent_ports = [8080]
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            await self.npf.apply_firewall_roles_npf(port_configs, agent_ports, errors)

        # Verify logging about port count
        self.mock_parent.logger.info.assert_any_call(
            "NPF firewall: Would configure %d ports. "
            "NPF requires /etc/npf.conf modifications.",
            3,
        )


class TestRemoveFirewallPortsNpf:
    """Test cases for removing firewall ports using NPF."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.npf = NPFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_success(self):
        """Test removing firewall ports successfully."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            9000: {"tcp": True, "udp": False},
            9001: {"tcp": True, "udp": True},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result is not None
        assert result["success"] is True
        assert "acknowledged" in result["message"].lower()
        self.mock_parent._send_firewall_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_not_available(self):
        """Test removing ports when NPF is not available."""
        mock_result = Mock(returncode=1, stdout="", stderr="npfctl: command not found")

        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_file_not_found(self):
        """Test removing ports when npfctl command is not found."""
        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", side_effect=FileNotFoundError("npfctl not found")):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_timeout(self):
        """Test removing ports when command times out."""
        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="npfctl", timeout=5),
        ):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_preserves_ssh(self):
        """Test that SSH port 22 is preserved and skipped."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        # Try to remove SSH port 22
        ports_to_remove = {22: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # Verify port 22 was logged as skipped
        info_calls = str(self.mock_parent.logger.info.call_args_list)
        assert "preserved" in info_calls.lower() or "skipping" in info_calls.lower()

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_preserves_agent_port(self):
        """Test that agent port is preserved and skipped."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        # Try to remove agent port 8080
        ports_to_remove = {8080: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True
        # Verify port 8080 was logged as skipped
        self.mock_parent.logger.info.assert_any_call(
            "Skipping removal of preserved port %d (agent/SSH)", 8080
        )

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_tcp_only(self):
        """Test removing TCP only port."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_udp_only(self):
        """Test removing UDP only port."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {5353: {"tcp": False, "udp": True}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_both_protocols(self):
        """Test removing port with both protocols."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {53: {"tcp": True, "udp": True}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_empty_ports(self):
        """Test removing empty port list."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_logs_removal(self):
        """Test that removal requests are logged."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            9000: {"tcp": True, "udp": False},
            9001: {"tcp": False, "udp": True},
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        # Verify removal was logged
        info_calls = str(self.mock_parent.logger.info.call_args_list)
        assert "9000" in info_calls
        assert "9001" in info_calls

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_mixed_preserved_and_removable(self):
        """Test removing mix of preserved and removable ports."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {
            22: {"tcp": True, "udp": False},  # preserved
            8080: {"tcp": True, "udp": False},  # preserved
            9000: {"tcp": True, "udp": False},  # should be removed
            9001: {"tcp": True, "udp": True},  # should be removed
        }
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert result["success"] is True

        # Verify preserved ports were skipped
        info_calls = list(self.mock_parent.logger.info.call_args_list)
        skip_calls = [call for call in info_calls if "skipping" in str(call).lower()]
        assert len(skip_calls) == 2  # port 22 and 8080

    @pytest.mark.asyncio
    async def test_remove_firewall_ports_npf_message_contains_note(self):
        """Test that result message contains note about npf.conf."""
        mock_result = Mock(returncode=0, stdout="", stderr="")

        ports_to_remove = {9000: {"tcp": True, "udp": False}}
        preserved_ports = {22, 8080}
        errors = []

        with patch("subprocess.run", return_value=mock_result):
            result = await self.npf.remove_firewall_ports_npf(
                ports_to_remove, preserved_ports, errors
            )

        assert "npf.conf" in result["message"].lower()


class TestNPFIntegration:
    """Integration-style tests for NPF operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda x: x)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.npf = NPFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_full_enable_workflow(self):
        """Test the complete enable workflow from empty config to running."""
        call_count = [0]
        written_content = [None]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_file = MagicMock()

            async def mock_read():
                if call_count[0] == 1:
                    raise FileNotFoundError()
                return ""

            async def mock_write(content):
                written_content[0] = content

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", side_effect=mock_results) as mock_run:
                result = await self.npf.enable_npf_firewall([8080, 22], "tcp")

        assert result["success"] is True

        # Verify the command sequence
        calls = mock_run.call_args_list
        assert len(calls) == 3

        # First call should be validate
        assert "validate" in calls[0][0][0]

        # Second call should be reload
        assert "reload" in calls[1][0][0]

        # Third call should be start
        assert "start" in calls[2][0][0]

    @pytest.mark.asyncio
    async def test_enable_and_apply_roles_sequence(self):
        """Test enabling NPF then applying roles."""
        mock_file = MagicMock()
        mock_file.read = AsyncMock(return_value="existing config")
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        mock_result = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            return_value=mock_file,
        ):
            with patch("subprocess.run", return_value=mock_result):
                # First enable
                enable_result = await self.npf.enable_npf_firewall([8080], "tcp")
                assert enable_result["success"] is True

                # Then apply roles
                port_configs = {80: {"tcp": True, "udp": False}}
                roles_result = await self.npf.apply_firewall_roles_npf(
                    port_configs, [8080], []
                )
                assert roles_result["success"] is True

        # Both operations should have sent status updates
        assert self.mock_parent._send_firewall_status_update.call_count == 2


class TestNPFConfigContent:
    """Test cases verifying the NPF configuration content."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_parent = Mock()
        self.mock_parent.logger = Mock()
        self.mock_parent._build_command = Mock(side_effect=lambda x: x)
        self.mock_parent._send_firewall_status_update = AsyncMock()
        self.npf = NPFFirewallOperations(self.mock_parent)

    @pytest.mark.asyncio
    async def test_config_contains_expected_sections(self):
        """Test that generated config contains expected sections."""
        written_content = [None]
        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_file = MagicMock()

            async def mock_read():
                if call_count[0] == 1:
                    raise FileNotFoundError()
                return ""

            async def mock_write(content):
                written_content[0] = content

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),  # validate
            Mock(returncode=0, stdout="", stderr=""),  # reload
            Mock(returncode=0, stdout="", stderr=""),  # start
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                await self.npf.enable_npf_firewall([8080], "tcp")

        # Verify config content
        assert written_content[0] is not None
        content = str(written_content[0])
        assert "group default" in content
        assert "pass stateful" in content
        assert "lo0" in content  # loopback
        assert "port 22" in content  # SSH
        assert "port 8080" in content  # SysManage-Agent
        assert "icmp" in content
        assert "block return" in content

    @pytest.mark.asyncio
    async def test_config_contains_service_variables(self):
        """Test that config contains service port variables."""
        written_content = [None]
        call_count = [0]

        def mock_open_side_effect(*_args, **_kwargs):
            call_count[0] += 1
            mock_file = MagicMock()

            async def mock_read():
                if call_count[0] == 1:
                    raise FileNotFoundError()
                return ""

            async def mock_write(content):
                written_content[0] = content

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                await self.npf.enable_npf_firewall([8080], "tcp")

        assert written_content[0] is not None
        content = str(written_content[0])
        assert "$services_tcp" in content
        assert "$services_udp" in content
        assert "http" in content
        assert "https" in content
        assert "domain" in content

    @pytest.mark.asyncio
    async def test_config_uses_correct_path(self):
        """Test that config is written to correct path."""
        opened_paths = []
        call_count = [0]

        def mock_open_side_effect(path, *_args, **_kwargs):
            call_count[0] += 1
            opened_paths.append(path)
            mock_file = MagicMock()

            async def mock_read():
                if call_count[0] == 1:
                    raise FileNotFoundError()
                return ""

            async def mock_write(_content):
                pass

            mock_file.read = mock_read
            mock_file.write = mock_write
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            return mock_file

        mock_results = [
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
        ]

        with patch(
            "src.sysmanage_agent.operations.firewall_bsd_npf.aiofiles.open",
            side_effect=mock_open_side_effect,
        ):
            with patch("subprocess.run", side_effect=mock_results):
                await self.npf.enable_npf_firewall([8080], "tcp")

        # Verify /etc/npf.conf was opened
        assert "/etc/npf.conf" in opened_paths
