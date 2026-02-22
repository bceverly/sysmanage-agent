"""
Unit tests for src.sysmanage_agent.operations.child_host_bhyve_networking module.
Tests the BhyveNetworking class for bhyve NAT networking on FreeBSD.
"""

# pylint: disable=protected-access,redefined-outer-name

import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_networking import (
    BHYVE_BRIDGE_NAME,
    BHYVE_DHCP_END,
    BHYVE_DHCP_START,
    BHYVE_GATEWAY_IP,
    BHYVE_NETMASK,
    BHYVE_SUBNET,
    BhyveNetworking,
)


@pytest.fixture
def bhyve_networking():
    """Create a BhyveNetworking instance for testing."""
    logger = logging.getLogger(__name__)
    return BhyveNetworking(logger)


@pytest.fixture
def mock_run_subprocess():
    """Create a mock run_subprocess function."""
    mock_func = AsyncMock()
    mock_func.return_value = Mock(returncode=0, stdout="", stderr="")
    return mock_func


class TestBhyveNetworkingConstants:
    """Tests for module constants."""

    def test_bridge_name(self):
        """Test bridge name constant."""
        assert BHYVE_BRIDGE_NAME == "bridge1"

    def test_subnet(self):
        """Test subnet constant."""
        assert BHYVE_SUBNET == "10.0.100"

    def test_gateway_ip(self):
        """Test gateway IP constant."""
        assert BHYVE_GATEWAY_IP == "10.0.100.1"

    def test_netmask(self):
        """Test netmask constant."""
        assert BHYVE_NETMASK == "255.255.255.0"

    def test_dhcp_range(self):
        """Test DHCP range constants."""
        assert BHYVE_DHCP_START == "10.0.100.10"
        assert BHYVE_DHCP_END == "10.0.100.254"


class TestBhyveNetworkingInit:
    """Tests for BhyveNetworking initialization."""

    def test_init_with_logger(self):
        """Test BhyveNetworking initialization with logger."""
        mock_logger = Mock()
        networking = BhyveNetworking(mock_logger)
        assert networking.logger == mock_logger

    def test_init_sets_logger(self):
        """Test that init properly sets the logger attribute."""
        logger = logging.getLogger("test")
        networking = BhyveNetworking(logger)
        assert networking.logger is logger


class TestGetHostDnsServer:
    """Tests for get_host_dns_server method."""

    @pytest.mark.asyncio
    async def test_get_dns_server_success(self, bhyve_networking):
        """Test successful DNS server detection."""
        resolv_content = """# /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
"""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=resolv_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_get_dns_server_with_comment_in_line(self, bhyve_networking):
        """Test DNS server detection when IP has trailing comment attached."""
        # The # is directly attached to the IP without space
        resolv_content = """nameserver 1.1.1.1#Cloudflare
"""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=resolv_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_get_dns_server_empty_file(self, bhyve_networking):
        """Test DNS server detection with empty file."""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="")
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_dns_server_only_comments(self, bhyve_networking):
        """Test DNS server detection with only comments."""
        resolv_content = """# This is a comment
# Another comment
"""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=resolv_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_dns_server_malformed_nameserver_line(self, bhyve_networking):
        """Test DNS server detection with malformed nameserver line."""
        resolv_content = """nameserver
"""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=resolv_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_dns_server_file_not_found(self, bhyve_networking):
        """Test DNS server detection when file doesn't exist."""
        with patch("aiofiles.open", side_effect=FileNotFoundError()):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_dns_server_permission_error(self, bhyve_networking):
        """Test DNS server detection with permission error."""
        with patch("aiofiles.open", side_effect=PermissionError()):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_dns_server_generic_exception(self, bhyve_networking):
        """Test DNS server detection with generic exception."""
        with patch("aiofiles.open", side_effect=Exception("Test error")):
            result = await bhyve_networking.get_host_dns_server()

        assert result is None


class TestGetEgressInterface:
    """Tests for get_egress_interface method."""

    @pytest.mark.asyncio
    async def test_get_egress_interface_success(self, bhyve_networking):
        """Test successful egress interface detection."""
        route_output = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
        fib: 0
  interface: em0
      flags: <UP,GATEWAY,DONE,STATIC>
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = route_output

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await bhyve_networking.get_egress_interface()

        assert result == "em0"

    @pytest.mark.asyncio
    async def test_get_egress_interface_no_interface_line(self, bhyve_networking):
        """Test egress interface detection with no interface in output."""
        route_output = """   route to: default
destination: default
"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = route_output

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await bhyve_networking.get_egress_interface()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_egress_interface_command_failure(self, bhyve_networking):
        """Test egress interface detection when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await bhyve_networking.get_egress_interface()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_egress_interface_exception(self, bhyve_networking):
        """Test egress interface detection with exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            new_callable=AsyncMock,
            side_effect=Exception("Test error"),
        ):
            result = await bhyve_networking.get_egress_interface()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_egress_interface_malformed_output(self, bhyve_networking):
        """Test egress interface detection with malformed output."""
        route_output = """  interface:"""  # No value after colon
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = route_output

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_networking.run_command_async",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await bhyve_networking.get_egress_interface()

        # Should return empty string stripped from the malformed line
        assert result == ""


class TestSetupNatBridge:
    """Tests for setup_nat_bridge method."""

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_already_exists(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test setup when bridge already exists."""
        # Bridge exists (returncode 0), then config, then sysrc calls
        mock_run_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # ifconfig bridge1 - exists
            Mock(returncode=0, stdout="", stderr=""),  # ifconfig bridge1 inet...
            Mock(returncode=0, stdout="", stderr=""),  # sysrc cloned_interfaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc ifconfig_bridge1
        ]

        with patch("os.path.exists", return_value=False):
            result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is True
        assert "bridge1" in result["message"]

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_create_new(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test creating a new bridge."""
        mock_run_subprocess.side_effect = [
            Mock(
                returncode=1, stdout="", stderr=""
            ),  # ifconfig bridge1 - doesn't exist
            Mock(returncode=0, stdout="", stderr=""),  # ifconfig bridge1 create
            Mock(returncode=0, stdout="", stderr=""),  # ifconfig bridge1 inet...
            Mock(returncode=0, stdout="", stderr=""),  # sysrc cloned_interfaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc ifconfig_bridge1
        ]

        with patch("os.path.exists", return_value=False):
            result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is True
        assert result["bridge"] == "bridge1"
        assert result["gateway_ip"] == "10.0.100.1"

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_create_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test when bridge creation fails."""
        mock_run_subprocess.side_effect = [
            Mock(
                returncode=1, stdout="", stderr=""
            ),  # ifconfig bridge1 - doesn't exist
            Mock(
                returncode=1, stdout="", stderr="Permission denied"
            ),  # ifconfig bridge1 create fails
        ]

        result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_config_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test when bridge IP configuration fails."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # Bridge exists
            Mock(returncode=1, stdout="", stderr="Config failed"),  # Config fails
            Mock(returncode=0, stdout="", stderr=""),  # sysrc cloned_interfaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc ifconfig_bridge1
        ]

        with patch("os.path.exists", return_value=False):
            result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        # Should still succeed despite config warning
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_updates_rc_conf(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test that rc.conf is updated when bridge not in config."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # Bridge exists
            Mock(returncode=0, stdout="", stderr=""),  # Config bridge
            Mock(returncode=0, stdout="", stderr=""),  # sysrc cloned_interfaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc ifconfig_bridge1
        ]

        rc_conf_content = "# rc.conf content without bridge\n"
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_skips_rc_conf_update(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test that rc.conf update is skipped when bridge already configured."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # Bridge exists
            Mock(returncode=0, stdout="", stderr=""),  # Config bridge
        ]

        rc_conf_content = f"""cloned_interfaces="{BHYVE_BRIDGE_NAME}"
ifconfig_{BHYVE_BRIDGE_NAME}="inet {BHYVE_GATEWAY_IP} netmask {BHYVE_NETMASK}"
"""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=rc_conf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_nat_bridge_exception(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test setup with exception."""
        mock_run_subprocess.side_effect = Exception("Test error")

        result = await bhyve_networking.setup_nat_bridge(mock_run_subprocess)

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestSetupIpForwarding:
    """Tests for setup_ip_forwarding method."""

    @pytest.mark.asyncio
    async def test_setup_ip_forwarding_success(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test successful IP forwarding setup."""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="")
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=False):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_ip_forwarding(mock_run_subprocess)

        assert result["success"] is True
        assert "enabled" in result["message"]

    @pytest.mark.asyncio
    async def test_setup_ip_forwarding_already_in_sysctl(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test IP forwarding when already in sysctl.conf."""
        sysctl_content = "net.inet.ip.forwarding=1\n"
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=sysctl_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_ip_forwarding(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_ip_forwarding_permission_error(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test IP forwarding with permission error writing sysctl.conf."""
        # Create a mock that returns read file first, then raises on write
        mock_read_file = AsyncMock()
        mock_read_file.read = AsyncMock(return_value="")
        mock_read_file.__aenter__ = AsyncMock(return_value=mock_read_file)
        mock_read_file.__aexit__ = AsyncMock(return_value=None)

        mock_write_file = AsyncMock()
        mock_write_file.__aenter__ = AsyncMock(
            side_effect=PermissionError("Cannot write")
        )
        mock_write_file.__aexit__ = AsyncMock(return_value=None)

        call_count = [0]

        def mock_open_func(_path, mode, **_kwargs):
            call_count[0] += 1
            if mode == "r":
                return mock_read_file
            return mock_write_file  # Write mode

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", side_effect=mock_open_func):
                result = await bhyve_networking.setup_ip_forwarding(mock_run_subprocess)

        # Should still succeed with warning
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_ip_forwarding_exception(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test IP forwarding with exception."""
        mock_run_subprocess.side_effect = Exception("Test error")

        result = await bhyve_networking.setup_ip_forwarding(mock_run_subprocess)

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestSetupPfNat:
    """Tests for setup_pf_nat method."""

    @pytest.mark.asyncio
    async def test_setup_pf_nat_already_configured(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test pf NAT setup when already configured."""
        pf_content = "# bhyve NAT - already configured\n"
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=pf_content)
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = "em0"
            with patch("os.path.exists", return_value=True):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        assert result["success"] is True
        assert "already present" in result["message"]

    @pytest.mark.asyncio
    async def test_setup_pf_nat_new_config(self, bhyve_networking, mock_run_subprocess):
        """Test pf NAT setup with new configuration."""
        pf_content = ""  # Empty pf.conf
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=pf_content)
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = "em0"
            with patch("os.path.exists", return_value=True):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        assert result["success"] is True
        assert "configured" in result["message"]

    @pytest.mark.asyncio
    async def test_setup_pf_nat_append_to_existing(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test pf NAT setup appending to existing config."""
        pf_content = """# Existing pf.conf
set skip on lo0
pass in all
pass out all
# Some more config to make it longer than 50 chars
"""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=pf_content)
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = "em0"
            with patch("os.path.exists", return_value=True):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_pf_nat_no_egress_interface(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test pf NAT setup when no egress interface is detected."""
        pf_content = ""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=pf_content)
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = None  # No egress interface
            with patch("os.path.exists", return_value=False):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        # Should use "egress" as fallback
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_pf_nat_permission_error(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test pf NAT setup with permission error."""
        pf_content = ""
        mock_read_file = AsyncMock()
        mock_read_file.read = AsyncMock(return_value=pf_content)
        mock_read_file.__aenter__ = AsyncMock(return_value=mock_read_file)
        mock_read_file.__aexit__ = AsyncMock(return_value=None)

        mock_write_file = AsyncMock()
        mock_write_file.__aenter__ = AsyncMock(
            side_effect=PermissionError("Cannot write")
        )
        mock_write_file.__aexit__ = AsyncMock(return_value=None)

        def mock_open_func(_path, mode, **_kwargs):
            if mode == "r":
                return mock_read_file
            return mock_write_file

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = "em0"
            with patch("os.path.exists", return_value=True):
                with patch("aiofiles.open", side_effect=mock_open_func):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_setup_pf_nat_pf_start_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test pf NAT setup when pf service start fails."""
        pf_content = ""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=pf_content)
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        # Simulate pf start failure then onestart
        call_count = 0

        async def mock_subprocess(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            cmd = args[0] if args else kwargs.get("cmd", [])
            if "service" in cmd and "start" in cmd:
                return Mock(returncode=1, stdout="", stderr="")
            return Mock(returncode=0, stdout="", stderr="")

        mock_run_subprocess.side_effect = mock_subprocess

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = "em0"
            with patch("os.path.exists", return_value=False):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_pf_nat_pfctl_load_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test pf NAT setup when pfctl load fails with warning."""
        pf_content = ""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value=pf_content)
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        async def mock_subprocess(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("cmd", [])
            if "pfctl" in cmd and "-f" in cmd:
                return Mock(returncode=1, stdout="", stderr="Error loading rules")
            return Mock(returncode=0, stdout="", stderr="")

        mock_run_subprocess.side_effect = mock_subprocess

        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.return_value = "em0"
            with patch("os.path.exists", return_value=False):
                with patch("aiofiles.open", return_value=mock_file):
                    result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        # Should still succeed with warning
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_pf_nat_exception(self, bhyve_networking, mock_run_subprocess):
        """Test pf NAT setup with exception."""
        with patch.object(
            bhyve_networking, "get_egress_interface", new_callable=AsyncMock
        ) as mock_egress:
            mock_egress.side_effect = Exception("Test error")
            result = await bhyve_networking.setup_pf_nat(mock_run_subprocess)

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestSetupDhcpd:
    """Tests for setup_dhcpd method."""

    @pytest.mark.asyncio
    async def test_setup_dhcpd_success_dhcpd_installed(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup when dhcpd is already installed."""
        mock_file = AsyncMock()
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = "8.8.8.8"
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is True
        assert result["dns_server"] == "8.8.8.8"

    @pytest.mark.asyncio
    async def test_setup_dhcpd_install_dhcpd(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup when dhcpd needs to be installed."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=1, stdout="", stderr=""),  # which dhcpd - not installed
            Mock(returncode=0, stdout="", stderr=""),  # pkg install
            Mock(returncode=0, stdout="", stderr=""),  # sysrc dhcpd_ifaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc dhcpd_enable
            Mock(returncode=0, stdout="", stderr=""),  # service restart
        ]

        mock_file = AsyncMock()
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = "1.1.1.1"
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is True
        assert result["dns_server"] == "1.1.1.1"

    @pytest.mark.asyncio
    async def test_setup_dhcpd_install_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup when installation fails."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=1, stdout="", stderr=""),  # which dhcpd - not installed
            Mock(
                returncode=1, stdout="", stderr="Installation failed"
            ),  # pkg install fails
        ]

        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = "8.8.8.8"
            result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is False
        assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_setup_dhcpd_no_dns_fallback(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup with fallback DNS when none detected."""
        mock_file = AsyncMock()
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = None  # No DNS detected
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is True
        assert result["dns_server"] == "8.8.8.8"  # Fallback DNS

    @pytest.mark.asyncio
    async def test_setup_dhcpd_permission_error(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup with permission error writing config."""
        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = "8.8.8.8"
            with patch("aiofiles.open", side_effect=PermissionError("Cannot write")):
                result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_setup_dhcpd_restart_fails_then_start(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup when restart fails but start succeeds."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # which dhcpd
            Mock(returncode=0, stdout="", stderr=""),  # sysrc dhcpd_ifaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc dhcpd_enable
            Mock(returncode=1, stdout="", stderr=""),  # service restart fails
            Mock(returncode=0, stdout="", stderr=""),  # service start succeeds
        ]

        mock_file = AsyncMock()
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = "8.8.8.8"
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_dhcpd_restart_and_start_fail(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test dhcpd setup when both restart and start fail."""
        mock_run_subprocess.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # which dhcpd
            Mock(returncode=0, stdout="", stderr=""),  # sysrc dhcpd_ifaces
            Mock(returncode=0, stdout="", stderr=""),  # sysrc dhcpd_enable
            Mock(returncode=1, stdout="", stderr=""),  # service restart fails
            Mock(
                returncode=1, stdout="", stderr="Start failed"
            ),  # service start also fails
        ]

        mock_file = AsyncMock()
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.return_value = "8.8.8.8"
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        # Should still return success with warning logged
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_dhcpd_exception(self, bhyve_networking, mock_run_subprocess):
        """Test dhcpd setup with exception."""
        with patch.object(
            bhyve_networking, "get_host_dns_server", new_callable=AsyncMock
        ) as mock_dns:
            mock_dns.side_effect = Exception("Test error")
            result = await bhyve_networking.setup_dhcpd(mock_run_subprocess)

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestSetupNatNetworking:
    """Tests for setup_nat_networking method."""

    @pytest.mark.asyncio
    async def test_setup_nat_networking_success(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test complete NAT networking setup success."""
        with patch.object(
            bhyve_networking, "setup_nat_bridge", new_callable=AsyncMock
        ) as mock_bridge:
            mock_bridge.return_value = {"success": True, "message": "Bridge configured"}
            with patch.object(
                bhyve_networking, "setup_ip_forwarding", new_callable=AsyncMock
            ) as mock_forward:
                mock_forward.return_value = {
                    "success": True,
                    "message": "IP forwarding enabled",
                }
                with patch.object(
                    bhyve_networking, "setup_pf_nat", new_callable=AsyncMock
                ) as mock_pf:
                    mock_pf.return_value = {"success": True, "message": "pf configured"}
                    with patch.object(
                        bhyve_networking, "setup_dhcpd", new_callable=AsyncMock
                    ) as mock_dhcpd:
                        mock_dhcpd.return_value = {
                            "success": True,
                            "message": "dhcpd configured",
                        }
                        result = await bhyve_networking.setup_nat_networking(
                            mock_run_subprocess
                        )

        assert result["success"] is True
        assert result["bridge"] == "bridge1"
        assert result["gateway"] == "10.0.100.1"
        assert "10.0.100.0/24" in result["subnet"]
        assert "results" in result

    @pytest.mark.asyncio
    async def test_setup_nat_networking_bridge_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test NAT networking setup when bridge setup fails."""
        with patch.object(
            bhyve_networking, "setup_nat_bridge", new_callable=AsyncMock
        ) as mock_bridge:
            mock_bridge.return_value = {"success": False, "error": "Bridge failed"}
            result = await bhyve_networking.setup_nat_networking(mock_run_subprocess)

        assert result["success"] is False
        assert "Bridge failed" in result["error"]

    @pytest.mark.asyncio
    async def test_setup_nat_networking_forwarding_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test NAT networking setup continues when forwarding fails."""
        with patch.object(
            bhyve_networking, "setup_nat_bridge", new_callable=AsyncMock
        ) as mock_bridge:
            mock_bridge.return_value = {"success": True, "message": "Bridge configured"}
            with patch.object(
                bhyve_networking, "setup_ip_forwarding", new_callable=AsyncMock
            ) as mock_forward:
                mock_forward.return_value = {
                    "success": False,
                    "error": "Forwarding failed",
                }
                with patch.object(
                    bhyve_networking, "setup_pf_nat", new_callable=AsyncMock
                ) as mock_pf:
                    mock_pf.return_value = {"success": True, "message": "pf configured"}
                    with patch.object(
                        bhyve_networking, "setup_dhcpd", new_callable=AsyncMock
                    ) as mock_dhcpd:
                        mock_dhcpd.return_value = {
                            "success": True,
                            "message": "dhcpd configured",
                        }
                        result = await bhyve_networking.setup_nat_networking(
                            mock_run_subprocess
                        )

        # Should still succeed overall with warning
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_nat_networking_pf_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test NAT networking setup continues when pf fails."""
        with patch.object(
            bhyve_networking, "setup_nat_bridge", new_callable=AsyncMock
        ) as mock_bridge:
            mock_bridge.return_value = {"success": True, "message": "Bridge configured"}
            with patch.object(
                bhyve_networking, "setup_ip_forwarding", new_callable=AsyncMock
            ) as mock_forward:
                mock_forward.return_value = {
                    "success": True,
                    "message": "IP forwarding enabled",
                }
                with patch.object(
                    bhyve_networking, "setup_pf_nat", new_callable=AsyncMock
                ) as mock_pf:
                    mock_pf.return_value = {"success": False, "error": "pf failed"}
                    with patch.object(
                        bhyve_networking, "setup_dhcpd", new_callable=AsyncMock
                    ) as mock_dhcpd:
                        mock_dhcpd.return_value = {
                            "success": True,
                            "message": "dhcpd configured",
                        }
                        result = await bhyve_networking.setup_nat_networking(
                            mock_run_subprocess
                        )

        # Should still succeed overall with warning
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_setup_nat_networking_dhcpd_fails(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test NAT networking setup continues when dhcpd fails."""
        with patch.object(
            bhyve_networking, "setup_nat_bridge", new_callable=AsyncMock
        ) as mock_bridge:
            mock_bridge.return_value = {"success": True, "message": "Bridge configured"}
            with patch.object(
                bhyve_networking, "setup_ip_forwarding", new_callable=AsyncMock
            ) as mock_forward:
                mock_forward.return_value = {
                    "success": True,
                    "message": "IP forwarding enabled",
                }
                with patch.object(
                    bhyve_networking, "setup_pf_nat", new_callable=AsyncMock
                ) as mock_pf:
                    mock_pf.return_value = {"success": True, "message": "pf configured"}
                    with patch.object(
                        bhyve_networking, "setup_dhcpd", new_callable=AsyncMock
                    ) as mock_dhcpd:
                        mock_dhcpd.return_value = {
                            "success": False,
                            "error": "dhcpd failed",
                        }
                        result = await bhyve_networking.setup_nat_networking(
                            mock_run_subprocess
                        )

        # Should still succeed overall with warning
        assert result["success"] is True


class TestAddRcConfEntry:
    """Tests for _add_rc_conf_entry method."""

    @pytest.mark.asyncio
    async def test_add_rc_conf_entry_success(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test adding rc.conf entry successfully."""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="")
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking._add_rc_conf_entry(
                    "some_key=value", "some_key", mock_run_subprocess
                )

        assert result is True

    @pytest.mark.asyncio
    async def test_add_rc_conf_entry_already_exists(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test adding rc.conf entry when key already exists."""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value='some_key="existing_value"')
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking._add_rc_conf_entry(
                    "some_key=value", "some_key", mock_run_subprocess
                )

        assert result is True
        # sysrc should not be called since key exists
        mock_run_subprocess.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_rc_conf_entry_file_not_exists(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test adding rc.conf entry when file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await bhyve_networking._add_rc_conf_entry(
                "some_key=value", "some_key", mock_run_subprocess
            )

        assert result is True
        mock_run_subprocess.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_rc_conf_entry_exception(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test adding rc.conf entry with exception."""
        with patch("os.path.exists", side_effect=Exception("Test error")):
            result = await bhyve_networking._add_rc_conf_entry(
                "some_key=value", "some_key", mock_run_subprocess
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_add_rc_conf_entry_no_equals(
        self, bhyve_networking, mock_run_subprocess
    ):
        """Test adding rc.conf entry without equals sign."""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="")
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("os.path.exists", return_value=True):
            with patch("aiofiles.open", return_value=mock_file):
                result = await bhyve_networking._add_rc_conf_entry(
                    "some_key_without_equals", "some_key", mock_run_subprocess
                )

        assert result is True
        # sysrc should not be called since no equals sign
        mock_run_subprocess.assert_not_called()


class TestGetterMethods:
    """Tests for getter methods."""

    def test_get_bridge_name(self, bhyve_networking):
        """Test get_bridge_name returns correct value."""
        assert bhyve_networking.get_bridge_name() == "bridge1"

    def test_get_gateway_ip(self, bhyve_networking):
        """Test get_gateway_ip returns correct value."""
        assert bhyve_networking.get_gateway_ip() == "10.0.100.1"

    def test_get_subnet(self, bhyve_networking):
        """Test get_subnet returns correct value."""
        assert bhyve_networking.get_subnet() == "10.0.100.0/24"
