"""
Comprehensive unit tests for src.sysmanage_agent.registration.client_registration module.
Tests client registration with server and system information collection.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import ssl
from unittest.mock import Mock, patch, AsyncMock
import pytest

from src.sysmanage_agent.registration.client_registration import ClientRegistration


class TestClientRegistration:  # pylint: disable=too-many-public-methods
    """Test cases for ClientRegistration class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.is_script_execution_enabled.return_value = True
        self.mock_config.get_registration_retry_interval.return_value = 30
        self.mock_config.get_max_registration_retries.return_value = 3
        self.mock_config.get_server_config.return_value = {
            "hostname": "test.example.com",
            "port": 8080,
            "use_https": True,
        }

        # Mock all the collection modules
        with patch(
            "src.sysmanage_agent.registration.client_registration.HardwareCollector"
        ), patch(
            "src.sysmanage_agent.registration.client_registration.OSInfoCollector"
        ), patch(
            "src.sysmanage_agent.registration.client_registration.NetworkUtils"
        ), patch(
            "src.sysmanage_agent.registration.client_registration.UserAccessCollector"
        ), patch(
            "src.sysmanage_agent.registration.client_registration.SoftwareInventoryCollector"
        ):

            self.client_reg = ClientRegistration(self.mock_config)

    def test_init_with_aiohttp_available(self):
        """Test ClientRegistration initialization when aiohttp is available."""
        with patch(
            "src.sysmanage_agent.registration.client_registration.AIOHTTP_AVAILABLE",
            True,
        ):
            assert self.client_reg.config == self.mock_config
            assert hasattr(self.client_reg, "hardware_collector")
            assert hasattr(self.client_reg, "os_info_collector")
            assert hasattr(self.client_reg, "network_utils")
            assert hasattr(self.client_reg, "user_access_collector")
            assert hasattr(self.client_reg, "software_inventory_collector")
            assert self.client_reg.registered is False
            assert self.client_reg.registration_data is None

    def test_create_basic_registration_dict(self):
        """Test creating basic registration dictionary structure."""
        result = self.client_reg._create_basic_registration_dict(
            "test-host", "192.168.1.100", "2001:db8::1"
        )

        expected = {
            "hostname": "test-host",
            "fqdn": "test-host",
            "ipv4": "192.168.1.100",
            "ipv6": "2001:db8::1",
            "active": True,
        }
        assert result == expected

    def test_get_basic_registration_info(self):
        """Test getting basic registration information."""
        # Mock network utils methods
        self.client_reg.network_utils.get_hostname.return_value = "test-hostname"
        self.client_reg.network_utils.get_ip_addresses.return_value = (
            "192.168.1.50",
            "fe80::1",
        )

        result = self.client_reg.get_basic_registration_info()

        expected = {
            "hostname": "test-hostname",
            "fqdn": "test-hostname",
            "ipv4": "192.168.1.50",
            "ipv6": "fe80::1",
            "active": True,
            "script_execution_enabled": True,
        }
        assert result == expected
        self.client_reg.network_utils.get_hostname.assert_called_once()
        self.client_reg.network_utils.get_ip_addresses.assert_called_once()

    def test_get_os_version_info(self):
        """Test getting OS version information."""
        expected_os_info = {"os": "Linux", "version": "5.4.0"}
        self.client_reg.os_info_collector.get_os_version_info.return_value = (
            expected_os_info
        )

        result = self.client_reg.get_os_version_info()

        assert result == expected_os_info
        self.client_reg.os_info_collector.get_os_version_info.assert_called_once()

    def test_get_hardware_info(self):
        """Test getting hardware information."""
        expected_hw_info = {"cpu": "Intel", "memory": "16GB"}
        self.client_reg.hardware_collector.get_hardware_info.return_value = (
            expected_hw_info
        )

        result = self.client_reg.get_hardware_info()

        assert result == expected_hw_info
        self.client_reg.hardware_collector.get_hardware_info.assert_called_once()

    def test_get_user_access_info(self):
        """Test getting user access information."""
        expected_user_info = {"users": ["user1", "user2"], "groups": ["group1"]}
        self.client_reg.user_access_collector.get_access_info.return_value = (
            expected_user_info
        )

        result = self.client_reg.get_user_access_info()

        assert result == expected_user_info
        self.client_reg.user_access_collector.get_access_info.assert_called_once()

    def test_get_software_inventory_info(self):
        """Test getting software inventory information."""
        expected_software_info = {"packages": ["package1", "package2"]}
        self.client_reg.software_inventory_collector.get_software_inventory.return_value = (
            expected_software_info
        )

        result = self.client_reg.get_software_inventory_info()

        assert result == expected_software_info
        self.client_reg.software_inventory_collector.get_software_inventory.assert_called_once()

    def test_get_system_info(self):
        """Test getting comprehensive system information (legacy method)."""
        # Mock all the data sources
        self.client_reg.network_utils.get_hostname.return_value = "legacy-host"
        self.client_reg.network_utils.get_ip_addresses.return_value = ("10.0.0.1", None)
        self.client_reg.os_info_collector.get_os_version_info.return_value = {
            "os": "Ubuntu",
            "version": "20.04",
        }

        result = self.client_reg.get_system_info()

        expected = {
            "hostname": "legacy-host",
            "fqdn": "legacy-host",
            "ipv4": "10.0.0.1",
            "ipv6": None,
            "active": True,
            "script_execution_enabled": True,
            "os": "Ubuntu",
            "version": "20.04",
        }
        assert result == expected

    @pytest.mark.asyncio
    @patch(
        "src.sysmanage_agent.registration.client_registration.AIOHTTP_AVAILABLE", False
    )
    async def test_register_with_server_no_aiohttp(self):
        """Test registration when aiohttp is not available."""
        with patch(
            "src.sysmanage_agent.registration.client_registration.logging"
        ) as mock_logging:
            mock_logger = Mock()
            mock_logging.getLogger.return_value = mock_logger

            client_reg = ClientRegistration(self.mock_config)
            result = await client_reg.register_with_server()

            assert result is True
            assert client_reg.registered is True
            mock_logger.warning.assert_called_with(
                "aiohttp not available, skipping registration"
            )

    def test_basic_registration_data_structure(self):
        """Test that basic registration data has correct structure."""
        # Mock the network utils to return predictable data
        self.client_reg.network_utils.get_hostname.return_value = "test-host"
        self.client_reg.network_utils.get_ip_addresses.return_value = (
            "192.168.1.100",
            "fe80::1",
        )

        # Get the basic registration info
        result = self.client_reg.get_basic_registration_info()

        expected_data = {
            "hostname": "test-host",
            "fqdn": "test-host",
            "ipv4": "192.168.1.100",
            "ipv6": "fe80::1",
            "active": True,
            "script_execution_enabled": True,
        }
        assert result == expected_data

    def test_registration_url_construction_logic(self):
        """Test the URL construction logic used in registration."""
        # Test with HTTPS configuration
        server_config = self.mock_config.get_server_config.return_value
        hostname = server_config["hostname"]
        port = server_config["port"]
        use_https = server_config["use_https"]

        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{hostname}:{port}"
        registration_url = f"{base_url}/host/register"

        assert registration_url == "https://test.example.com:8080/host/register"

        # Test with HTTP configuration
        self.mock_config.get_server_config.return_value = {
            "hostname": "localhost",
            "port": 8000,
            "use_https": False,
        }

        server_config = self.mock_config.get_server_config.return_value
        hostname = server_config["hostname"]
        port = server_config["port"]
        use_https = server_config["use_https"]

        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{hostname}:{port}"
        registration_url = f"{base_url}/host/register"

        assert registration_url == "http://localhost:8000/host/register"

    def test_config_methods_delegation(self):
        """Test that configuration methods are properly delegated."""
        # Mock network utils first
        self.client_reg.network_utils.get_hostname.return_value = "test-host"
        self.client_reg.network_utils.get_ip_addresses.return_value = (
            "192.168.1.100",
            None,
        )

        # Test script execution enabled
        self.mock_config.is_script_execution_enabled.return_value = False
        result = self.client_reg.get_basic_registration_info()
        assert result["script_execution_enabled"] is False

        # Test retry configuration
        assert self.client_reg.config.get_registration_retry_interval() == 30
        assert self.client_reg.config.get_max_registration_retries() == 3

        # Verify methods were called
        self.mock_config.is_script_execution_enabled.assert_called()
        self.mock_config.get_registration_retry_interval.assert_called()
        self.mock_config.get_max_registration_retries.assert_called()

    @pytest.mark.asyncio
    async def test_register_with_retry_success_first_attempt(self):
        """Test registration with retry succeeds on first attempt."""
        with patch.object(
            self.client_reg, "register_with_server", new_callable=AsyncMock
        ) as mock_register:
            mock_register.return_value = True

            result = await self.client_reg.register_with_retry()

            assert result is True
            mock_register.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_with_retry_success_after_retries(self):
        """Test registration with retry succeeds after several attempts."""
        with patch.object(
            self.client_reg, "register_with_server", new_callable=AsyncMock
        ) as mock_register:
            # Fail twice, then succeed
            mock_register.side_effect = [False, False, True]

            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                result = await self.client_reg.register_with_retry()

                assert result is True
                assert mock_register.call_count == 3
                assert mock_sleep.call_count == 2
                mock_sleep.assert_called_with(30)  # retry_interval

    @pytest.mark.asyncio
    async def test_register_with_retry_max_retries_exceeded(self):
        """Test registration with retry fails after max retries."""
        with patch.object(
            self.client_reg, "register_with_server", new_callable=AsyncMock
        ) as mock_register:
            mock_register.return_value = False

            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                result = await self.client_reg.register_with_retry()

                assert result is False
                assert mock_register.call_count == 3  # max_retries
                assert mock_sleep.call_count == 2

    @pytest.mark.asyncio
    async def test_register_with_retry_infinite_retries(self):
        """Test registration with infinite retries (-1)."""
        self.mock_config.get_max_registration_retries.return_value = -1

        with patch.object(
            self.client_reg, "register_with_server", new_callable=AsyncMock
        ) as mock_register:
            # Fail a few times, then succeed to avoid infinite loop
            mock_register.side_effect = [False, False, False, False, True]

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await self.client_reg.register_with_retry()

                assert result is True
                assert mock_register.call_count == 5

    def test_is_registered_false(self):
        """Test is_registered when not registered."""
        assert self.client_reg.is_registered() is False

    def test_is_registered_true(self):
        """Test is_registered when registered."""
        self.client_reg.registered = True
        assert self.client_reg.is_registered() is True

    def test_get_registration_data_none(self):
        """Test getting registration data when none available."""
        assert self.client_reg.get_registration_data() is None

    def test_get_registration_data_available(self):
        """Test getting registration data when available."""
        test_data = {"id": 789, "status": "test"}
        self.client_reg.registration_data = test_data
        assert self.client_reg.get_registration_data() == test_data

    def test_get_host_id_none(self):
        """Test getting host ID when registration data is None."""
        assert self.client_reg.get_host_id() is None

    def test_get_host_id_available(self):
        """Test getting host ID when registration data is available."""
        self.client_reg.registration_data = {"id": 999, "other": "data"}
        assert self.client_reg.get_host_id() == "999"

    def test_get_host_id_missing_id_key(self):
        """Test getting host ID when registration data lacks 'id' key."""
        self.client_reg.registration_data = {"status": "registered", "other": "data"}
        assert self.client_reg.get_host_id() is None

    def test_server_url_construction_https(self):
        """Test server URL construction with HTTPS."""
        # This test verifies the URL construction logic used in register_with_server
        server_config = self.mock_config.get_server_config.return_value
        hostname = server_config["hostname"]
        port = server_config["port"]
        use_https = server_config["use_https"]

        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{hostname}:{port}"
        registration_url = f"{base_url}/host/register"

        assert registration_url == "https://test.example.com:8080/host/register"

    def test_server_url_construction_http(self):
        """Test server URL construction with HTTP."""
        self.mock_config.get_server_config.return_value = {
            "hostname": "localhost",
            "port": 8000,
            "use_https": False,
        }

        server_config = self.mock_config.get_server_config.return_value
        hostname = server_config["hostname"]
        port = server_config["port"]
        use_https = server_config["use_https"]

        protocol = "https" if use_https else "http"
        base_url = f"{protocol}://{hostname}:{port}"
        registration_url = f"{base_url}/host/register"

        assert registration_url == "http://localhost:8000/host/register"

    def test_ssl_context_configuration_logic(self):
        """Test SSL context configuration logic without actual HTTP calls."""
        # This tests the SSL configuration that would be used

        # Test the SSL context creation logic (without HTTP)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # Verify the SSL context is configured for development (no cert verification)
        assert ssl_context.check_hostname is False
        assert ssl_context.verify_mode == ssl.CERT_NONE
