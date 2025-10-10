"""
Test edge cases and error handling for client_registration.py.
Focused on improving test coverage by targeting uncovered paths.
"""

from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.registration.client_registration import ClientRegistration


class TestClientRegistrationEdgeCases:
    """Test edge cases for ClientRegistration class."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.mock_config = Mock()

        # Mock database session to prevent loading existing auth data
        with patch(
            "src.sysmanage_agent.registration.client_registration.get_db_session"
        ) as mock_db_session:
            # Mock the database session to return no existing auth data
            mock_session = Mock()
            mock_session.query.return_value.filter.return_value.first.return_value = (
                None
            )
            mock_db_session.return_value.__enter__.return_value = mock_session

            self.client_registration = ClientRegistration(self.mock_config)

    def test_init_without_aiohttp(self):
        """Test initialization when aiohttp is not available."""
        with patch(
            "src.sysmanage_agent.registration.client_registration.AIOHTTP_AVAILABLE",
            False,
        ):
            # Should not raise exception
            registration = ClientRegistration(self.mock_config)
            assert registration is not None

    def test_create_basic_registration_dict(self):
        """Test basic registration dictionary creation."""
        result = self.client_registration._create_basic_registration_dict(
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

    def test_get_basic_registration_info_script_execution_enabled(self):
        """Test basic registration info with script execution enabled."""
        self.mock_config.is_script_execution_enabled.return_value = True

        with patch.object(
            self.client_registration.network_utils,
            "get_hostname",
            return_value="test-host",
        ):
            with patch.object(
                self.client_registration.network_utils,
                "get_ip_addresses",
                return_value=("192.168.1.100", "2001:db8::1"),
            ):
                result = self.client_registration.get_basic_registration_info()

                assert result["script_execution_enabled"] is True
                assert result["hostname"] == "test-host"

    def test_get_basic_registration_info_script_execution_disabled(self):
        """Test basic registration info with script execution disabled."""
        self.mock_config.is_script_execution_enabled.return_value = False

        with patch.object(
            self.client_registration.network_utils,
            "get_hostname",
            return_value="test-host",
        ):
            with patch.object(
                self.client_registration.network_utils,
                "get_ip_addresses",
                return_value=("192.168.1.100", None),
            ):
                result = self.client_registration.get_basic_registration_info()

                assert result["script_execution_enabled"] is False
                assert result["ipv6"] is None

    def test_get_host_id_no_registration_data(self):
        """Test get_host_id when no registration data exists."""
        with patch.object(
            self.client_registration, "_get_stored_host_id", return_value=None
        ):
            assert self.client_registration.get_host_id() is None

    def test_get_host_id_with_registration_data(self):
        """Test get_host_id with valid registration data."""
        self.client_registration.registration_data = {"id": 12345}
        assert self.client_registration.get_host_id() == "12345"

    def test_get_registration_data_none(self):
        """Test get_registration_data when no data exists."""
        assert self.client_registration.get_registration_data() is None

    def test_is_registered_initially_false(self):
        """Test is_registered returns False initially."""
        assert not self.client_registration.is_registered()

    @pytest.mark.asyncio
    async def test_register_with_server_aiohttp_unavailable(self):
        """Test registration when aiohttp is not available."""
        with patch(
            "src.sysmanage_agent.registration.client_registration.AIOHTTP_AVAILABLE",
            False,
        ):
            result = await self.client_registration.register_with_server()

            assert result is True
            assert self.client_registration.registered is True

    @pytest.mark.asyncio
    async def test_register_with_server_client_error(self):
        """Test registration with client error response."""
        self.mock_config.get_server_config.return_value = {
            "hostname": "localhost",
            "port": 8000,
            "use_https": False,
        }

        # Create a complete mock for aiohttp
        mock_response = Mock()
        mock_response.status = 400

        async def mock_text():
            return "Bad Request"

        mock_response.text = mock_text

        # Mock the session context manager properly
        class MockSessionContext:
            """Mock session context for testing."""

            async def __aenter__(self):
                return mock_response

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        class MockSession:
            """Mock session for testing."""

            def post(self, *args, **kwargs):
                """Mock post method."""
                _ = args
                _ = kwargs
                return MockSessionContext()

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        with patch("aiohttp.ClientSession", return_value=MockSession()):
            with patch.object(
                self.client_registration,
                "get_basic_registration_info",
                return_value={"hostname": "test"},
            ):
                result = await self.client_registration.register_with_server()

                assert result is False
                assert not self.client_registration.registered

    @pytest.mark.asyncio
    async def test_register_with_server_exception(self):
        """Test registration with exception during HTTP request."""
        self.mock_config.get_server_config.return_value = {}

        with patch("aiohttp.ClientSession", side_effect=Exception("Connection error")):
            with patch.object(
                self.client_registration,
                "get_basic_registration_info",
                return_value={"hostname": "test"},
            ):
                result = await self.client_registration.register_with_server()

                assert result is False
                assert not self.client_registration.registered

    @pytest.mark.asyncio
    async def test_register_with_retry_max_retries_reached(self):
        """Test registration retry with max retries reached."""
        self.mock_config.get_registration_retry_interval.return_value = 0.1
        self.mock_config.get_max_registration_retries.return_value = 2

        call_count = [0]

        async def mock_register():
            call_count[0] += 1
            return False

        with patch.object(
            self.client_registration, "register_with_server", side_effect=mock_register
        ):
            result = await self.client_registration.register_with_retry()

            assert result is False
            assert call_count[0] == 2

    @pytest.mark.asyncio
    async def test_register_with_retry_infinite_retries(self):
        """Test registration retry with infinite retries (eventually succeeds)."""
        self.mock_config.get_registration_retry_interval.return_value = 0.1
        self.mock_config.get_max_registration_retries.return_value = -1  # Infinite

        call_count = [0]

        async def mock_register():
            call_count[0] += 1
            return call_count[0] >= 3  # Succeed on third attempt

        with patch.object(
            self.client_registration, "register_with_server", side_effect=mock_register
        ):
            result = await self.client_registration.register_with_retry()

            assert result is True
            assert call_count[0] == 3

    @pytest.mark.asyncio
    async def test_register_with_retry_first_attempt_success(self):
        """Test registration retry when first attempt succeeds."""
        self.mock_config.get_registration_retry_interval.return_value = 1
        self.mock_config.get_max_registration_retries.return_value = 5

        with patch.object(
            self.client_registration, "register_with_server", return_value=True
        ):
            result = await self.client_registration.register_with_retry()

            assert result is True

    def test_get_system_info_legacy_method(self):
        """Test get_system_info legacy method for backward compatibility."""
        mock_basic_info = {"hostname": "test", "ipv4": "192.168.1.1"}
        mock_os_info = {"platform": "Linux", "platform_release": "Ubuntu 20.04"}

        with patch.object(
            self.client_registration,
            "get_basic_registration_info",
            return_value=mock_basic_info,
        ):
            with patch.object(
                self.client_registration,
                "get_os_version_info",
                return_value=mock_os_info,
            ):
                self.mock_config.is_script_execution_enabled.return_value = True

                result = self.client_registration.get_system_info()

                # Should merge basic and OS info
                assert result["hostname"] == "test"
                assert result["platform"] == "Linux"
                assert result["script_execution_enabled"] is True

    def test_component_initialization(self):
        """Test that all component modules are properly initialized."""
        assert self.client_registration.hardware_collector is not None
        assert self.client_registration.os_info_collector is not None
        assert self.client_registration.network_utils is not None
        assert self.client_registration.user_access_collector is not None
        assert self.client_registration.software_inventory_collector is not None

    def test_delegation_methods(self):
        """Test that delegation methods call the appropriate components."""
        # Test OS version info delegation
        with patch.object(
            self.client_registration.os_info_collector,
            "get_os_version_info",
            return_value={"test": "data"},
        ) as mock_os:
            result = self.client_registration.get_os_version_info()
            mock_os.assert_called_once()
            assert result == {"test": "data"}

        # Test hardware info delegation
        with patch.object(
            self.client_registration.hardware_collector,
            "get_hardware_info",
            return_value={"cpu": "test"},
        ) as mock_hw:
            result = self.client_registration.get_hardware_info()
            mock_hw.assert_called_once()
            assert result == {"cpu": "test"}

        # Test user access info delegation
        with patch.object(
            self.client_registration.user_access_collector,
            "get_access_info",
            return_value={"users": []},
        ) as mock_user:
            result = self.client_registration.get_user_access_info()
            mock_user.assert_called_once()
            assert result == {"users": []}

        # Test software inventory delegation
        with patch.object(
            self.client_registration.software_inventory_collector,
            "get_software_inventory",
            return_value={"packages": []},
        ) as mock_sw:
            result = self.client_registration.get_software_inventory_info()
            mock_sw.assert_called_once()
            assert result == {"packages": []}
