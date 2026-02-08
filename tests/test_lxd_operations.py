"""
Comprehensive unit tests for LXD container operations.

Tests cover:
- LXD initialization
- Container lifecycle operations (start, stop, restart, delete)
- Container creation
- Status checks
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import json
import logging
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_lxd import LxdOperations
from src.sysmanage_agent.operations.child_host_lxd_container_creator import (
    LxdContainerCreator,
)
from src.sysmanage_agent.operations.child_host_types import LxdContainerConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_lxd_support = Mock(
        return_value={
            "available": True,
            "installed": True,
            "initialized": True,
            "user_in_group": True,
            "needs_install": False,
            "needs_init": False,
            "snap_available": True,
        }
    )
    return mock_checks


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    return mock


@pytest.fixture
def lxd_ops(mock_agent, logger, mock_virtualization_checks):
    """Create an LxdOperations instance for testing."""
    return LxdOperations(mock_agent, logger, mock_virtualization_checks)


@pytest.fixture
def lxd_creator(mock_agent, logger):
    """Create an LxdContainerCreator instance for testing."""
    return LxdContainerCreator(mock_agent, logger)


@pytest.fixture
def sample_lxd_config():
    """Create a sample LXD container configuration."""
    return LxdContainerConfig(
        distribution="ubuntu:22.04",
        container_name="test-container",
        hostname="test.example.com",
        username="admin",
        password_hash="$6$rounds=5000$...",
        server_url="https://server.example.com",
        agent_install_commands=["apt update", "apt install -y sysmanage-agent"],
    )


class TestLxdOperationsInit:
    """Tests for LxdOperations initialization."""

    def test_init_sets_agent(self, lxd_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert lxd_ops.agent == mock_agent

    def test_init_sets_logger(self, lxd_ops, logger):
        """Test that __init__ sets logger."""
        assert lxd_ops.logger == logger

    def test_init_sets_virtualization_checks(self, lxd_ops, mock_virtualization_checks):
        """Test that __init__ sets virtualization_checks."""
        assert lxd_ops.virtualization_checks == mock_virtualization_checks

    def test_init_creates_container_creator(self, lxd_ops):
        """Test that __init__ creates container_creator."""
        assert lxd_ops.container_creator is not None


class TestLxdOperationsInitializeLxd:
    """Tests for initialize_lxd method."""

    @pytest.mark.asyncio
    async def test_initialize_lxd_not_available(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd when LXD is not available."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": False,
            "installed": False,
            "initialized": False,
        }

        result = await lxd_ops.initialize_lxd({})

        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_initialize_lxd_already_initialized(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd when already initialized."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": True,
            "installed": True,
            "initialized": True,
            "user_in_group": True,
            "snap_available": True,
        }

        with patch.object(lxd_ops, "_configure_lxd_firewall") as mock_firewall:
            mock_firewall.return_value = {"success": True}
            result = await lxd_ops.initialize_lxd({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_initialize_lxd_install_via_snap(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd installing LXD via snap."""
        mock_virtualization_checks.check_lxd_support.side_effect = [
            {
                "available": True,
                "installed": False,
                "initialized": False,
                "user_in_group": False,
                "snap_available": True,
            },
            {
                "available": True,
                "installed": True,
                "initialized": True,
                "user_in_group": True,
                "snap_available": True,
            },
        ]

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            with patch.object(lxd_ops, "_configure_lxd_firewall") as mock_firewall:
                mock_firewall.return_value = {"success": True}
                result = await lxd_ops.initialize_lxd({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_initialize_lxd_snap_not_available(
        self, lxd_ops, mock_virtualization_checks
    ):
        """Test initialize_lxd when snap is not available."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": True,
            "installed": False,
            "initialized": False,
            "user_in_group": False,
            "snap_available": False,
        }

        result = await lxd_ops.initialize_lxd({})

        assert result["success"] is False
        assert "snap" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_initialize_lxd_timeout(self, lxd_ops, mock_virtualization_checks):
        """Test initialize_lxd with timeout."""
        mock_virtualization_checks.check_lxd_support.return_value = {
            "available": True,
            "installed": False,
            "initialized": False,
            "snap_available": True,
        }

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await lxd_ops.initialize_lxd({})

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestLxdOperationsStartChildHost:
    """Tests for start_child_host method."""

    @pytest.mark.asyncio
    async def test_start_container_no_name(self, lxd_ops):
        """Test starting container without name."""
        result = await lxd_ops.start_child_host({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_container_success(self, lxd_ops):
        """Test starting container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"
        assert result["child_type"] == "lxd"

    @pytest.mark.asyncio
    async def test_start_container_failure(self, lxd_ops):
        """Test starting container when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Container 'test-container' is already running"

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is False
        assert "already running" in result["error"]

    @pytest.mark.asyncio
    async def test_start_container_timeout(self, lxd_ops):
        """Test starting container with timeout."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_container_exception(self, lxd_ops):
        """Test starting container with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=Exception("Unexpected error"),
        ):
            result = await lxd_ops.start_child_host({"child_name": "test-container"})

        assert result["success"] is False
        assert "Unexpected error" in result["error"]


class TestLxdOperationsStopChildHost:
    """Tests for stop_child_host method."""

    @pytest.mark.asyncio
    async def test_stop_container_no_name(self, lxd_ops):
        """Test stopping container without name."""
        result = await lxd_ops.stop_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_stop_container_success(self, lxd_ops):
        """Test stopping container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.stop_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"
        assert result["child_type"] == "lxd"

    @pytest.mark.asyncio
    async def test_stop_container_failure(self, lxd_ops):
        """Test stopping container when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Container 'test-container' is not running"

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.stop_child_host({"child_name": "test-container"})

        assert result["success"] is False


class TestLxdOperationsRestartChildHost:
    """Tests for restart_child_host method."""

    @pytest.mark.asyncio
    async def test_restart_container_no_name(self, lxd_ops):
        """Test restarting container without name."""
        result = await lxd_ops.restart_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_restart_container_success(self, lxd_ops):
        """Test restarting container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.restart_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"

    @pytest.mark.asyncio
    async def test_restart_container_exception(self, lxd_ops):
        """Test restarting container with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            side_effect=Exception("Connection failed"),
        ):
            result = await lxd_ops.restart_child_host({"child_name": "test-container"})

        assert result["success"] is False


class TestLxdOperationsDeleteChildHost:
    """Tests for delete_child_host method."""

    @pytest.mark.asyncio
    async def test_delete_container_no_name(self, lxd_ops):
        """Test deleting container without name."""
        result = await lxd_ops.delete_child_host({})
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_container_success(self, lxd_ops):
        """Test deleting container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_ops.delete_child_host({"child_name": "test-container"})

        assert result["success"] is True
        assert result["child_name"] == "test-container"

    @pytest.mark.asyncio
    async def test_delete_container_force_used(self, lxd_ops):
        """Test that delete uses --force flag."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd.run_command_async",
            return_value=mock_result,
        ) as mock_cmd:
            await lxd_ops.delete_child_host({"child_name": "test-container"})

        # Verify --force was passed
        call_args = mock_cmd.call_args[0][0]
        assert "--force" in call_args


class TestLxdContainerCreatorValidateConfig:
    """Tests for LxdContainerCreator._validate_config method."""

    def test_validate_config_valid(self, lxd_creator):
        """Test validating a valid config."""
        # Use a Mock to provide all required attributes
        config = Mock()
        config.distribution = "ubuntu:22.04"
        config.container_name = "test-container"
        config.hostname = "test.example.com"
        config.username = "admin"
        config.password = "secret123"

        result = lxd_creator._validate_config(config)
        assert result["success"] is True

    def test_validate_config_no_distribution(self, lxd_creator):
        """Test validating config without distribution."""
        config = Mock()
        config.distribution = ""
        config.container_name = "test"
        config.hostname = "test.example.com"
        config.username = "admin"
        config.password = "secret"

        result = lxd_creator._validate_config(config)
        assert result["success"] is False
        assert "distribution" in result["error"].lower()

    def test_validate_config_no_container_name(self, lxd_creator):
        """Test validating config without container_name."""
        config = Mock()
        config.distribution = "ubuntu:22.04"
        config.container_name = ""
        config.hostname = "test.example.com"
        config.username = "admin"
        config.password = "secret"

        result = lxd_creator._validate_config(config)
        assert result["success"] is False
        assert "container name" in result["error"].lower()

    def test_validate_config_no_hostname(self, lxd_creator):
        """Test validating config without hostname."""
        config = Mock()
        config.distribution = "ubuntu:22.04"
        config.container_name = "test"
        config.hostname = ""
        config.username = "admin"
        config.password = "secret"

        result = lxd_creator._validate_config(config)
        assert result["success"] is False
        assert "hostname" in result["error"].lower()


class TestLxdContainerCreatorGetFqdnHostname:
    """Tests for LxdContainerCreator._get_fqdn_hostname method."""

    def test_fqdn_already_qualified(self, lxd_creator):
        """Test FQDN when hostname is already qualified."""
        result = lxd_creator._get_fqdn_hostname(
            "test.example.com", "https://server.example.com"
        )
        assert result == "test.example.com"

    def test_fqdn_derived_from_server(self, lxd_creator):
        """Test FQDN derived from server URL."""
        result = lxd_creator._get_fqdn_hostname("test", "https://server.example.com")
        assert result == "test.example.com"

    def test_fqdn_with_subdomain_server(self, lxd_creator):
        """Test FQDN with subdomain in server URL."""
        result = lxd_creator._get_fqdn_hostname("test", "https://api.prod.example.com")
        assert result == "test.example.com"

    def test_fqdn_invalid_server_url(self, lxd_creator):
        """Test FQDN with invalid server URL."""
        result = lxd_creator._get_fqdn_hostname("test", "not-a-url")
        # Should return original hostname
        assert result == "test"


class TestLxdContainerCreatorContainerExists:
    """Tests for LxdContainerCreator._container_exists method."""

    def test_container_exists_true(self, lxd_creator):
        """Test when container exists."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            result = lxd_creator._container_exists("test-container")

        assert result is True

    def test_container_exists_false(self, lxd_creator):
        """Test when container doesn't exist."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1)
            result = lxd_creator._container_exists("test-container")

        assert result is False

    def test_container_exists_exception(self, lxd_creator):
        """Test container_exists handles exceptions."""
        with patch("subprocess.run", side_effect=Exception("Error")):
            result = lxd_creator._container_exists("test-container")

        assert result is False


class TestLxdContainerCreatorWaitForContainerReady:
    """Tests for LxdContainerCreator._wait_for_container_ready method."""

    def test_wait_for_container_ready_success(self, lxd_creator):
        """Test waiting for container when it becomes ready."""
        container_info = [
            {
                "status": "Running",
                "state": {
                    "network": {
                        "eth0": {
                            "addresses": [{"family": "inet", "address": "10.0.0.5"}]
                        }
                    }
                },
            }
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0, stdout=json.dumps(container_info)
            )
            result = lxd_creator._wait_for_container_ready("test-container", timeout=5)

        assert result is True

    def test_wait_for_container_ready_timeout(self, lxd_creator):
        """Test waiting for container with timeout."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout="")
            with patch("time.time") as mock_time:
                # Simulate timeout by advancing time
                mock_time.side_effect = [0, 0.1, 2]
                result = lxd_creator._wait_for_container_ready(
                    "test-container", timeout=1
                )

        assert result is False


class TestLxdContainerCreatorCheckContainerHasIp:
    """Tests for LxdContainerCreator._check_container_has_ip method."""

    def test_has_ipv4_address(self, lxd_creator):
        """Test detecting IPv4 address."""
        container = {
            "state": {
                "network": {
                    "eth0": {
                        "addresses": [{"family": "inet", "address": "192.168.1.100"}]
                    }
                }
            }
        }
        result = lxd_creator._check_container_has_ip(container)
        assert result == "IPv4 192.168.1.100"

    def test_has_ipv6_address(self, lxd_creator):
        """Test detecting IPv6 address."""
        container = {
            "state": {
                "network": {
                    "eth0": {
                        "addresses": [{"family": "inet6", "address": "2001:db8::1"}]
                    }
                }
            }
        }
        result = lxd_creator._check_container_has_ip(container)
        assert result == "IPv6 2001:db8::1"

    def test_ignores_link_local_ipv6(self, lxd_creator):
        """Test that link-local IPv6 addresses are ignored."""
        container = {
            "state": {
                "network": {
                    "eth0": {"addresses": [{"family": "inet6", "address": "fe80::1"}]}
                }
            }
        }
        result = lxd_creator._check_container_has_ip(container)
        assert result is None

    def test_ignores_loopback(self, lxd_creator):
        """Test that loopback interface is ignored."""
        container = {
            "state": {
                "network": {
                    "lo": {"addresses": [{"family": "inet", "address": "127.0.0.1"}]}
                }
            }
        }
        result = lxd_creator._check_container_has_ip(container)
        assert result is None


class TestLxdContainerCreatorSetContainerHostname:
    """Tests for LxdContainerCreator._set_container_hostname method."""

    @pytest.mark.asyncio
    async def test_set_hostname_success(self, lxd_creator):
        """Test setting hostname successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._set_container_hostname(
                "test-container", "test.example.com"
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_set_hostname_exception(self, lxd_creator):
        """Test setting hostname with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            side_effect=Exception("Failed to execute"),
        ):
            result = await lxd_creator._set_container_hostname(
                "test-container", "test.example.com"
            )

        assert result["success"] is False


class TestLxdContainerCreatorCreateUser:
    """Tests for LxdContainerCreator._create_user method."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, lxd_creator):
        """Test creating user successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._create_user(
                "test-container", "admin", "password123"
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_user_already_exists(self, lxd_creator):
        """Test creating user when user already exists - continue to set password."""
        # First call (useradd) fails with "already exists", but continues
        mock_useradd = Mock()
        mock_useradd.returncode = 1
        mock_useradd.stdout = ""
        mock_useradd.stderr = "user 'admin' already exists"

        # Second call (chpasswd) succeeds
        mock_chpasswd = Mock()
        mock_chpasswd.returncode = 0
        mock_chpasswd.stdout = ""
        mock_chpasswd.stderr = ""

        # Third and fourth calls (usermod for sudo/wheel groups)
        mock_group = Mock()
        mock_group.returncode = 0
        mock_group.stdout = ""
        mock_group.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            side_effect=[mock_useradd, mock_chpasswd, mock_group, mock_group],
        ):
            result = await lxd_creator._create_user(
                "test-container", "admin", "password123"
            )

        # Should succeed since user exists and password was set
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_user_password_failure(self, lxd_creator):
        """Test creating user when password setting fails."""
        mock_useradd = Mock(returncode=0, stdout="", stderr="")
        mock_chpasswd = Mock(returncode=1, stdout="", stderr="chpasswd: failure")

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            side_effect=[mock_useradd, mock_chpasswd],
        ):
            result = await lxd_creator._create_user(
                "test-container", "admin", "password123"
            )

        assert result["success"] is False


class TestLxdContainerCreatorInstallAgent:
    """Tests for LxdContainerCreator._install_agent method."""

    @pytest.mark.asyncio
    async def test_install_agent_success(self, lxd_creator):
        """Test installing agent successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._install_agent(
                "test-container", ["apt update", "apt install -y sysmanage-agent"]
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_install_agent_command_failure_continues(self, lxd_creator):
        """Test that agent installation continues on command failure."""
        mock_fail = Mock(returncode=1, stdout="", stderr="error")
        mock_success = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            side_effect=[mock_fail, mock_success],
        ):
            result = await lxd_creator._install_agent(
                "test-container", ["failing-command", "working-command"]
            )

        # Should still succeed as it continues trying
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_install_agent_timeout(self, lxd_creator):
        """Test installing agent with timeout."""
        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await lxd_creator._install_agent(
                "test-container", ["apt install -y sysmanage-agent"]
            )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestLxdContainerCreatorStartAgentService:
    """Tests for LxdContainerCreator._start_agent_service method."""

    @pytest.mark.asyncio
    async def test_start_agent_service_success(self, lxd_creator):
        """Test starting agent service successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._start_agent_service("test-container")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_start_agent_service_failure(self, lxd_creator):
        """Test starting agent service when it fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = (
            "Failed to enable unit: Unit sysmanage-agent.service not found"
        )

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._start_agent_service("test-container")

        assert result["success"] is False


class TestLxdContainerCreatorLaunchContainer:
    """Tests for LxdContainerCreator._launch_container method."""

    @pytest.mark.asyncio
    async def test_launch_container_success(self, lxd_creator):
        """Test launching container successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._launch_container(
                "ubuntu:22.04", "test-container"
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_container_no_bridge(self, lxd_creator):
        """Test launching container when bridge is missing."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Device not found"

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            return_value=mock_result,
        ):
            result = await lxd_creator._launch_container(
                "ubuntu:22.04", "test-container"
            )

        assert result["success"] is False
        assert "lxdbr0" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_container_timeout(self, lxd_creator):
        """Test launching container with timeout."""
        mock_bridge_result = Mock(returncode=0, stdout="", stderr="")

        with patch(
            "src.sysmanage_agent.operations.child_host_lxd_container_creator.run_command_async",
            side_effect=[mock_bridge_result, asyncio.TimeoutError()],
        ):
            result = await lxd_creator._launch_container(
                "ubuntu:22.04", "test-container"
            )

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestLxdOperationsConfigureFirewall:
    """Tests for LxdOperations._configure_lxd_firewall method."""

    def test_configure_firewall_not_linux(self, lxd_ops):
        """Test configuring firewall on non-Linux."""
        with patch("platform.system", return_value="Darwin"):
            result = lxd_ops._configure_lxd_firewall()

        assert result["success"] is True
        assert "not needed" in result["message"].lower()

    def test_configure_firewall_success(self, lxd_ops):
        """Test configuring firewall successfully."""
        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.LinuxFirewallOperations"
            ) as mock_firewall:
                mock_instance = Mock()
                mock_instance.configure_lxd_firewall.return_value = {"success": True}
                mock_firewall.return_value = mock_instance
                result = lxd_ops._configure_lxd_firewall()

        assert result["success"] is True

    def test_configure_firewall_exception(self, lxd_ops):
        """Test configuring firewall with exception."""
        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.operations.firewall_linux.LinuxFirewallOperations",
                side_effect=Exception("Firewall error"),
            ):
                result = lxd_ops._configure_lxd_firewall()

        assert result["success"] is False


class TestLxdContainerCreatorCreateLxdContainer:
    """Tests for LxdContainerCreator.create_lxd_container method."""

    @pytest.mark.asyncio
    async def test_create_container_invalid_config(self, lxd_creator):
        """Test creating container with invalid config."""
        config = Mock()
        config.distribution = ""
        config.container_name = ""
        config.hostname = ""
        config.username = ""
        config.password = ""

        result = await lxd_creator.create_lxd_container(config)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_container_already_exists(
        self, lxd_creator, sample_lxd_config
    ):
        """Test creating container that already exists."""
        # Add password attribute that the code expects
        sample_lxd_config.password = "testpassword"

        with patch.object(lxd_creator, "_container_exists", return_value=True):
            with patch.object(lxd_creator, "_send_progress", return_value=None):
                result = await lxd_creator.create_lxd_container(sample_lxd_config)

        assert result["success"] is False
        assert "already exists" in result["error"]

    @pytest.mark.asyncio
    async def test_create_container_exception(self, lxd_creator, sample_lxd_config):
        """Test creating container with exception."""
        # Add password attribute
        sample_lxd_config.password = "testpassword"

        with patch.object(
            lxd_creator, "_validate_config", side_effect=Exception("Validation error")
        ):
            result = await lxd_creator.create_lxd_container(sample_lxd_config)

        assert result["success"] is False
