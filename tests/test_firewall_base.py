"""
Unit tests for src.sysmanage_agent.operations.firewall_base module.
Tests the base class for firewall operations.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.firewall_base import FirewallBase


class TestFirewallBaseInit:
    """Test cases for FirewallBase initialization."""

    def test_init_with_logger(self):
        """Test FirewallBase initialization with custom logger."""
        mock_agent = Mock()
        mock_logger = Mock()
        base = FirewallBase(mock_agent, logger=mock_logger)

        assert base.agent == mock_agent
        assert base.logger == mock_logger

    def test_init_without_logger(self):
        """Test FirewallBase initialization without logger."""
        mock_agent = Mock()
        base = FirewallBase(mock_agent)

        assert base.agent == mock_agent
        assert base.logger is not None

    def test_init_sets_system(self):
        """Test that system is set on initialization."""
        mock_agent = Mock()
        base = FirewallBase(mock_agent)

        assert base.system is not None


class TestGetAgentCommunicationPorts:
    """Test cases for _get_agent_communication_ports method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.base = FirewallBase(self.mock_agent)

    def test_get_agent_communication_ports_default(self):
        """Test getting default agent communication port."""
        self.mock_agent.config.get_server_config.return_value = {"port": 8080}

        ports, protocol = self.base._get_agent_communication_ports()

        assert ports == [8080]
        assert protocol == "tcp"

    def test_get_agent_communication_ports_custom(self):
        """Test getting custom agent communication port."""
        self.mock_agent.config.get_server_config.return_value = {"port": 9999}

        ports, protocol = self.base._get_agent_communication_ports()

        assert ports == [9999]
        assert protocol == "tcp"

    def test_get_agent_communication_ports_missing_port(self):
        """Test getting port when not specified (uses default)."""
        self.mock_agent.config.get_server_config.return_value = {}

        ports, protocol = self.base._get_agent_communication_ports()

        assert ports == [8080]
        assert protocol == "tcp"

    def test_get_agent_communication_ports_exception(self):
        """Test getting ports when exception occurs (falls back to default)."""
        self.mock_agent.config.get_server_config.side_effect = Exception("Config error")

        ports, protocol = self.base._get_agent_communication_ports()

        assert ports == [8080]
        assert protocol == "tcp"


class TestIsSysmanageServerProcess:
    """Test cases for _is_sysmanage_server_process method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.base = FirewallBase(self.mock_agent)

    def test_is_sysmanage_server_process_uvicorn(self):
        """Test detecting SysManage server with uvicorn."""
        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["python", "uvicorn", "main:app"]
        mock_proc.name.return_value = "python"

        assert self.base._is_sysmanage_server_process(mock_proc) is True

    def test_is_sysmanage_server_process_sysmanage(self):
        """Test detecting SysManage server with sysmanage in cmdline."""
        mock_proc = Mock()
        mock_proc.cmdline.return_value = [
            "python",
            "sysmanage_server",
            "--port",
            "8080",
        ]
        mock_proc.name.return_value = "python"

        assert self.base._is_sysmanage_server_process(mock_proc) is True

    def test_is_sysmanage_server_process_node(self):
        """Test detecting SysManage server with node process."""
        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["python", "some_script.py"]
        mock_proc.name.return_value = "node"

        assert self.base._is_sysmanage_server_process(mock_proc) is True

    def test_is_sysmanage_server_process_not_python(self):
        """Test detecting non-Python process."""
        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["nginx", "-c", "/etc/nginx.conf"]
        mock_proc.name.return_value = "nginx"

        assert self.base._is_sysmanage_server_process(mock_proc) is False

    def test_is_sysmanage_server_process_unrelated(self):
        """Test detecting unrelated Python process."""
        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["python", "other_app.py"]
        mock_proc.name.return_value = "python"

        assert self.base._is_sysmanage_server_process(mock_proc) is False


class TestCheckConnectionForServerPort:
    """Test cases for _check_connection_for_server_port method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.base = FirewallBase(self.mock_agent)

    def test_check_connection_not_listening(self):
        """Test checking connection that is not listening."""
        mock_conn = Mock()
        mock_conn.status = "ESTABLISHED"
        mock_conn.laddr.port = 8080
        server_ports = []

        self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert server_ports == []

    def test_check_connection_wrong_port(self):
        """Test checking connection on wrong port."""
        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 9999
        server_ports = []

        self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert server_ports == []

    def test_check_connection_already_known(self):
        """Test checking connection for port already known."""
        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        server_ports = [8080]

        self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert server_ports == [8080]  # No duplicate added

    def test_check_connection_sysmanage_server(self):
        """Test checking connection for SysManage server."""
        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 12345

        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["python", "uvicorn", "sysmanage:app"]
        mock_proc.name.return_value = "python"

        server_ports = []

        with patch("psutil.Process", return_value=mock_proc):
            self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert 8080 in server_ports

    def test_check_connection_non_sysmanage_server(self):
        """Test checking connection for non-SysManage server."""
        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 12345

        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["nginx", "-g", "daemon off;"]
        mock_proc.name.return_value = "nginx"

        server_ports = []

        with patch("psutil.Process", return_value=mock_proc):
            self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert server_ports == []

    def test_check_connection_no_such_process(self):
        """Test checking connection when process no longer exists."""
        import psutil

        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 12345

        server_ports = []

        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(12345)):
            self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert server_ports == []

    def test_check_connection_access_denied(self):
        """Test checking connection when access is denied."""
        import psutil

        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 12345

        server_ports = []

        with patch("psutil.Process", side_effect=psutil.AccessDenied(12345)):
            self.base._check_connection_for_server_port(mock_conn, server_ports)

        assert server_ports == []


class TestGetLocalServerPorts:
    """Test cases for _get_local_server_ports method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.base = FirewallBase(self.mock_agent)

    def test_get_local_server_ports_none_found(self):
        """Test getting local server ports when none are found."""
        mock_conn = Mock()
        mock_conn.status = "ESTABLISHED"
        mock_conn.laddr.port = 12345

        with patch("psutil.net_connections", return_value=[mock_conn]):
            ports = self.base._get_local_server_ports()

        assert ports == []

    def test_get_local_server_ports_found(self):
        """Test getting local server ports when server is running."""
        mock_conn = Mock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 12345

        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["python", "uvicorn", "sysmanage:app"]
        mock_proc.name.return_value = "python"

        with patch("psutil.net_connections", return_value=[mock_conn]):
            with patch("psutil.Process", return_value=mock_proc):
                ports = self.base._get_local_server_ports()

        assert 8080 in ports

    def test_get_local_server_ports_multiple(self):
        """Test getting multiple local server ports."""
        mock_conn1 = Mock()
        mock_conn1.status = "LISTEN"
        mock_conn1.laddr.port = 8080
        mock_conn1.pid = 12345

        mock_conn2 = Mock()
        mock_conn2.status = "LISTEN"
        mock_conn2.laddr.port = 3000
        mock_conn2.pid = 12346

        mock_proc = Mock()
        mock_proc.cmdline.return_value = ["python", "uvicorn", "sysmanage:app"]
        mock_proc.name.return_value = "python"

        with patch("psutil.net_connections", return_value=[mock_conn1, mock_conn2]):
            with patch("psutil.Process", return_value=mock_proc):
                ports = self.base._get_local_server_ports()

        assert 8080 in ports
        assert 3000 in ports

    def test_get_local_server_ports_exception(self):
        """Test getting local server ports when exception occurs."""
        with patch("psutil.net_connections", side_effect=Exception("Error")):
            ports = self.base._get_local_server_ports()

        assert ports == []


class TestSendFirewallStatusUpdate:
    """Test cases for _send_firewall_status_update method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.registration_manager.get_host_approval_from_db.return_value = (
            Mock(host_id=12345)
        )
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.message_handler.create_message.return_value = Mock()
        self.mock_agent.message_handler.queue_outbound_message = AsyncMock()
        self.base = FirewallBase(self.mock_agent)

    @pytest.mark.asyncio
    async def test_send_firewall_status_update_success(self):
        """Test sending firewall status update successfully."""
        mock_collector_class = Mock()
        mock_collector_instance = Mock()
        mock_collector_instance.collect_firewall_status.return_value = {
            "firewall_name": "ufw",
            "enabled": True,
            "tcp_open_ports": '["22", "80"]',
            "udp_open_ports": None,
            "ipv4_ports": None,
            "ipv6_ports": None,
        }
        mock_collector_class.return_value = mock_collector_instance

        with patch.dict(
            "sys.modules",
            {
                "src.sysmanage_agent.operations.firewall_collector": Mock(
                    FirewallCollector=mock_collector_class
                )
            },
        ):
            await self.base._send_firewall_status_update()

        self.mock_agent.message_handler.queue_outbound_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_firewall_status_update_no_host_approval(self):
        """Test sending firewall status update when host is not approved."""
        self.mock_agent.registration_manager.get_host_approval_from_db.return_value = (
            None
        )

        mock_collector_class = Mock()
        mock_collector_instance = Mock()
        mock_collector_instance.collect_firewall_status.return_value = {
            "firewall_name": "ufw"
        }
        mock_collector_class.return_value = mock_collector_instance

        with patch.dict(
            "sys.modules",
            {
                "src.sysmanage_agent.operations.firewall_collector": Mock(
                    FirewallCollector=mock_collector_class
                )
            },
        ):
            await self.base._send_firewall_status_update()

        # Should not queue message when not approved
        self.mock_agent.message_handler.queue_outbound_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_firewall_status_update_exception(self):
        """Test sending firewall status update when exception occurs."""
        # Create a mock module that raises when FirewallCollector is accessed
        mock_module = Mock()
        mock_module.FirewallCollector = Mock(side_effect=Exception("Collection error"))

        with patch.dict(
            "sys.modules",
            {"src.sysmanage_agent.operations.firewall_collector": mock_module},
        ):
            # Should not raise exception
            await self.base._send_firewall_status_update()


class TestDeployFirewall:
    """Test cases for deploy_firewall method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.base = FirewallBase(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_firewall_not_implemented(self):
        """Test that deploy_firewall raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            await self.base.deploy_firewall()
