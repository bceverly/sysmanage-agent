"""Tests for firewall base module."""

# pylint: disable=protected-access,import-outside-toplevel

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.firewall_base import FirewallBase


class TestFirewallBaseInit:
    """Tests for FirewallBase initialization."""

    def test_init_with_default_logger(self):
        """Test initialization with default logger."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)
        assert firewall_base.agent is mock_agent
        assert firewall_base.logger is not None
        assert firewall_base.system is not None

    def test_init_with_custom_logger(self):
        """Test initialization with custom logger."""
        mock_agent = MagicMock()
        custom_logger = logging.getLogger("test_logger")
        firewall_base = FirewallBase(mock_agent, logger=custom_logger)
        assert firewall_base.logger is custom_logger


class TestGetAgentCommunicationPorts:
    """Tests for _get_agent_communication_ports method."""

    def test_get_agent_communication_ports_success(self):
        """Test successful port detection."""
        mock_agent = MagicMock()
        mock_agent.config.get_server_config.return_value = {"port": 9000}

        firewall_base = FirewallBase(mock_agent)
        ports, protocol = firewall_base._get_agent_communication_ports()

        assert ports == [9000]
        assert protocol == "tcp"

    def test_get_agent_communication_ports_default(self):
        """Test default port when not configured."""
        mock_agent = MagicMock()
        mock_agent.config.get_server_config.return_value = {}

        firewall_base = FirewallBase(mock_agent)
        ports, protocol = firewall_base._get_agent_communication_ports()

        assert ports == [8080]
        assert protocol == "tcp"

    def test_get_agent_communication_ports_exception(self):
        """Test fallback when exception occurs."""
        mock_agent = MagicMock()
        mock_agent.config.get_server_config.side_effect = Exception("Config error")

        firewall_base = FirewallBase(mock_agent)
        ports, protocol = firewall_base._get_agent_communication_ports()

        assert ports == [8080]
        assert protocol == "tcp"


class TestIsSysmanageServerProcess:
    """Tests for _is_sysmanage_server_process method."""

    def test_is_sysmanage_server_process_uvicorn(self):
        """Test detection of uvicorn server process."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python", "-m", "uvicorn", "main:app"]
        mock_proc.name.return_value = "python"

        result = firewall_base._is_sysmanage_server_process(mock_proc)
        assert result is True

    def test_is_sysmanage_server_process_sysmanage(self):
        """Test detection of sysmanage server process."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python", "/path/to/sysmanage/server.py"]
        mock_proc.name.return_value = "python"

        result = firewall_base._is_sysmanage_server_process(mock_proc)
        assert result is True

    def test_is_sysmanage_server_process_node(self):
        """Test detection of node server process."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python", "some_script.py"]
        mock_proc.name.return_value = "node"

        result = firewall_base._is_sysmanage_server_process(mock_proc)
        assert result is True

    def test_is_sysmanage_server_process_not_python(self):
        """Test non-python process returns False."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["/bin/bash", "script.sh"]
        mock_proc.name.return_value = "bash"

        result = firewall_base._is_sysmanage_server_process(mock_proc)
        assert result is False

    def test_is_sysmanage_server_process_unrelated_python(self):
        """Test unrelated python process returns False."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python", "other_app.py"]
        mock_proc.name.return_value = "python"

        result = firewall_base._is_sysmanage_server_process(mock_proc)
        assert result is False


class TestCheckConnectionForServerPort:
    """Tests for _check_connection_for_server_port method."""

    def test_check_connection_non_listen_status(self):
        """Test that non-LISTEN connections are skipped."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_conn = MagicMock()
        mock_conn.status = "ESTABLISHED"

        server_ports = []
        firewall_base._check_connection_for_server_port(mock_conn, server_ports)
        assert not server_ports

    def test_check_connection_non_sysmanage_port(self):
        """Test that non-sysmanage ports are skipped."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_conn = MagicMock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 22

        server_ports = []
        firewall_base._check_connection_for_server_port(mock_conn, server_ports)
        assert not server_ports

    def test_check_connection_already_in_list(self):
        """Test that duplicate ports are not added."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_conn = MagicMock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080

        server_ports = [8080]
        firewall_base._check_connection_for_server_port(mock_conn, server_ports)
        assert server_ports == [8080]

    def test_check_connection_sysmanage_port_detected(self):
        """Test detection of sysmanage server port."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_conn = MagicMock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 1234

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python", "uvicorn", "main:app"]
        mock_proc.name.return_value = "python"

        with patch("psutil.Process", return_value=mock_proc):
            server_ports = []
            firewall_base._check_connection_for_server_port(mock_conn, server_ports)
            assert 8080 in server_ports

    def test_check_connection_no_such_process(self):
        """Test handling of NoSuchProcess exception."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_conn = MagicMock()
        mock_conn.status = "LISTEN"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 1234

        import psutil

        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(1234)):
            server_ports = []
            firewall_base._check_connection_for_server_port(mock_conn, server_ports)
            assert not server_ports


class TestGetLocalServerPorts:
    """Tests for _get_local_server_ports method."""

    def test_get_local_server_ports_success(self):
        """Test successful detection of local server ports."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        mock_conn1 = MagicMock()
        mock_conn1.status = "LISTEN"
        mock_conn1.laddr.port = 8080
        mock_conn1.pid = 1234

        mock_proc = MagicMock()
        mock_proc.cmdline.return_value = ["python", "uvicorn", "main:app"]
        mock_proc.name.return_value = "python"

        with patch("psutil.net_connections", return_value=[mock_conn1]):
            with patch("psutil.Process", return_value=mock_proc):
                ports = firewall_base._get_local_server_ports()
                assert 8080 in ports

    def test_get_local_server_ports_exception(self):
        """Test handling of exception during port detection."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        with patch("psutil.net_connections", side_effect=Exception("Access denied")):
            ports = firewall_base._get_local_server_ports()
            assert not ports


class TestSendFirewallStatusUpdate:
    """Tests for _send_firewall_status_update method."""

    @pytest.mark.asyncio
    async def test_send_firewall_status_update_success(self):
        """Test successful firewall status update."""
        mock_agent = MagicMock()
        mock_agent.registration_manager.get_host_approval_from_db.return_value = (
            MagicMock(host_id="test-host-id")
        )
        mock_agent.registration.get_system_info.return_value = {"hostname": "testhost"}
        mock_agent.message_handler.create_message.return_value = {"type": "test"}
        mock_agent.message_handler.queue_outbound_message = AsyncMock()

        firewall_base = FirewallBase(mock_agent)

        mock_collector_class = MagicMock()
        mock_collector_instance = MagicMock()
        mock_collector_instance.collect_firewall_status.return_value = {
            "firewall_name": "iptables",
            "enabled": True,
            "tcp_open_ports": [22, 80],
            "udp_open_ports": [53],
            "ipv4_ports": [],
            "ipv6_ports": [],
        }
        mock_collector_class.return_value = mock_collector_instance

        with patch.dict(
            "sys.modules",
            {
                "src.sysmanage_agent.operations.firewall_collector": MagicMock(
                    FirewallCollector=mock_collector_class
                )
            },
        ):
            await firewall_base._send_firewall_status_update()
            mock_agent.message_handler.queue_outbound_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_firewall_status_update_no_approval(self):
        """Test status update when host not approved."""
        mock_agent = MagicMock()
        mock_agent.registration_manager.get_host_approval_from_db.return_value = None

        firewall_base = FirewallBase(mock_agent)

        mock_collector_class = MagicMock()
        mock_collector_instance = MagicMock()
        mock_collector_instance.collect_firewall_status.return_value = {}
        mock_collector_class.return_value = mock_collector_instance

        with patch.dict(
            "sys.modules",
            {
                "src.sysmanage_agent.operations.firewall_collector": MagicMock(
                    FirewallCollector=mock_collector_class
                )
            },
        ):
            await firewall_base._send_firewall_status_update()
            # Should return early, no message queued
            assert not mock_agent.message_handler.queue_outbound_message.called

    @pytest.mark.asyncio
    async def test_send_firewall_status_update_exception(self):
        """Test handling of exception during status update."""
        mock_agent = MagicMock()
        mock_agent.registration_manager.get_host_approval_from_db.side_effect = (
            Exception("DB error")
        )

        firewall_base = FirewallBase(mock_agent)

        # Should not raise, just log error
        await firewall_base._send_firewall_status_update()


class TestDeployFirewall:
    """Tests for deploy_firewall method."""

    @pytest.mark.asyncio
    async def test_deploy_firewall_not_implemented(self):
        """Test that deploy_firewall raises NotImplementedError."""
        mock_agent = MagicMock()
        firewall_base = FirewallBase(mock_agent)

        with pytest.raises(NotImplementedError):
            await firewall_base.deploy_firewall()
