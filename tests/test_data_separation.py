"""
Test data separation functionality - minimal registration vs comprehensive OS data.
"""

# pylint: disable=duplicate-code

from unittest.mock import Mock, patch, AsyncMock

import pytest

from src.sysmanage_agent.core.config import ConfigManager
from src.sysmanage_agent.registration.client_registration import ClientRegistration
from main import SysManageAgent


class TestDataSeparation:
    """Test data separation between minimal registration and OS version updates."""

    @pytest.fixture
    def mock_config(self, tmp_path):
        """Create a mock configuration manager."""
        config_file = tmp_path / "test_config.yaml"
        config_content = """
server:
  hostname: "test-server.example.com"
  port: 8000
  use_https: false
  api_path: "/api"

client:
  hostname_override: null

i18n:
  language: "en"
"""
        config_file.write_text(config_content)
        return ConfigManager(str(config_file))

    @pytest.fixture
    def mock_registration(self, mock_config):
        """Create a mock registration handler."""
        return ClientRegistration(mock_config)

    def test_get_basic_registration_info_minimal(self, mock_registration):
        """Test that get_basic_registration_info() returns only minimal data."""
        with patch.object(
            mock_registration.network_utils,
            "get_hostname",
            return_value="test-host.example.com",
        ), patch.object(
            mock_registration.network_utils,
            "get_ip_addresses",
            return_value=("192.168.1.100", "::1"),
        ):

            basic_info = mock_registration.get_basic_registration_info()

            # Should contain only minimal registration fields
            expected_fields = {"hostname", "fqdn", "ipv4", "ipv6", "active"}
            assert set(basic_info.keys()) == expected_fields

            assert basic_info["hostname"] == "test-host.example.com"
            assert basic_info["fqdn"] == "test-host.example.com"
            assert basic_info["ipv4"] == "192.168.1.100"
            assert basic_info["ipv6"] == "::1"
            assert basic_info["active"] is True

    def test_get_os_version_info_comprehensive(self, mock_registration):
        """Test that get_os_version_info() returns comprehensive OS data."""
        mock_os_info = {
            "platform": "Linux",
            "platform_release": "5.15.0-88-generic",
            "platform_version": "#98-Ubuntu SMP Mon Oct 2 15:29:04 UTC 2023",
            "architecture": "64bit",
            "processor": "x86_64",
            "machine_architecture": "x86_64",
            "python_version": "3.11.5",
            "os_info": {"distribution": "Ubuntu", "version": "5.15.0-88-generic"},
        }

        with patch.object(
            mock_registration.os_info_collector,
            "get_os_version_info",
            return_value=mock_os_info,
        ):

            os_info = mock_registration.get_os_version_info()

            # Should contain comprehensive OS version fields
            expected_fields = {
                "platform",
                "platform_release",
                "platform_version",
                "architecture",
                "processor",
                "machine_architecture",
                "python_version",
                "os_info",
            }
            assert set(os_info.keys()) == expected_fields

            assert os_info["platform"] == "Linux"
            assert os_info["platform_release"] == "5.15.0-88-generic"
            assert os_info["machine_architecture"] == "x86_64"
            assert os_info["processor"] == "x86_64"
            assert "os_info" in os_info

    def test_data_separation_no_overlap(self, mock_registration):
        """Test that basic registration and OS version data don't overlap."""
        mock_os_info = {
            "platform": "Darwin",
            "platform_release": "23.1.0",
            "platform_version": "Darwin Kernel Version 23.1.0",
            "architecture": "64bit",
            "processor": "arm",
            "machine_architecture": "arm64",
            "python_version": "3.11.5",
            "os_info": {"mac_version": "14.1.1"},
        }

        with patch.object(
            mock_registration.network_utils, "get_hostname", return_value="test-host"
        ), patch.object(
            mock_registration.network_utils,
            "get_ip_addresses",
            return_value=("10.0.0.1", None),
        ), patch.object(
            mock_registration.os_info_collector,
            "get_os_version_info",
            return_value=mock_os_info,
        ):

            basic_info = mock_registration.get_basic_registration_info()
            os_info = mock_registration.get_os_version_info()

            # Fields should not overlap between basic and OS version data
            basic_fields = set(basic_info.keys())
            os_fields = set(os_info.keys())

            assert basic_fields.isdisjoint(
                os_fields
            ), f"Basic and OS version data should not overlap. Common fields: {basic_fields & os_fields}"

    def test_get_system_info_combines_both(self, mock_registration):
        """Test that get_system_info() combines both basic and OS version data."""
        mock_os_info = {
            "platform": "Windows",
            "platform_release": "10",
            "platform_version": "10.0.19045",
            "architecture": "64bit",
            "processor": "Intel Core i7",
            "machine_architecture": "AMD64",
            "python_version": "3.11.5",
            "os_info": {"windows_version": "10", "windows_service_pack": "10.0.19045"},
        }

        with patch.object(
            mock_registration.network_utils,
            "get_hostname",
            return_value="combined-host",
        ), patch.object(
            mock_registration.network_utils,
            "get_ip_addresses",
            return_value=("172.16.0.1", "2001:db8::1"),
        ), patch.object(
            mock_registration.os_info_collector,
            "get_os_version_info",
            return_value=mock_os_info,
        ):

            system_info = mock_registration.get_system_info()
            basic_info = mock_registration.get_basic_registration_info()
            os_info = mock_registration.get_os_version_info()

            # System info should contain all fields from both
            for field in basic_info:
                assert field in system_info
                assert system_info[field] == basic_info[field]

            for field in os_info:
                assert field in system_info
                assert system_info[field] == os_info[field]

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_separate_message(self, tmp_path):
        """Test that send_initial_data_updates() sends OS data in separate message."""
        config_file = tmp_path / "test_config.yaml"
        config_content = """
server:
  hostname: "test-server.example.com"
  port: 8000

i18n:
  language: "en"
"""
        config_file.write_text(config_content)

        with patch("main.ClientRegistration") as mock_reg_class, patch(
            "main.set_language"
        ), patch("main.initialize_database", return_value=True):

            # Mock OS version and hardware data
            mock_registration = Mock()
            mock_registration.get_os_version_info.return_value = {
                "platform": "Linux",
                "platform_release": "5.15.0",
                "platform_version": "test version",
                "machine_architecture": "x86_64",
                "processor": "Intel",
                "python_version": "3.11.5",
                "architecture": "64bit",
                "os_info": {"distribution": "Ubuntu"},
            }
            mock_registration.get_hardware_info.return_value = {
                "cpu_vendor": "Intel",
                "cpu_model": "Core i7",
                "memory_total_mb": 16384,
                "storage_devices": [],
                "network_interfaces": [],
            }
            mock_registration.get_system_info.return_value = {
                "hostname": "test-host",
                "fqdn": "test-host.example.com",
                "ipv4": "192.168.1.100",
                "ipv6": None,
                "platform": "Linux",
            }
            mock_reg_class.return_value = mock_registration

            agent = SysManageAgent(str(config_file))

            # Mock the send_message method directly to track calls
            sent_messages = []

            async def mock_send_message(message):
                sent_messages.append(message)
                return True

            agent.send_message = mock_send_message
            agent.connected = True  # Set connected flag
            agent.logger = Mock()

            await agent.send_initial_data_updates()

            # Verify both OS version and hardware messages were sent (2 calls)
            assert len(sent_messages) == 2

            # Check the first call (OS version message)
            os_call_data = sent_messages[0]

            assert os_call_data["message_type"] == "os_version_update"
            assert os_call_data["data"]["platform"] == "Linux"
            assert os_call_data["data"]["machine_architecture"] == "x86_64"
            assert os_call_data["data"]["os_info"]["distribution"] == "Ubuntu"

            # Check the second call (hardware message)
            hardware_call_data = sent_messages[1]

            assert hardware_call_data["message_type"] == "hardware_update"
            assert hardware_call_data["data"]["cpu_vendor"] == "Intel"
            assert hardware_call_data["data"]["cpu_model"] == "Core i7"
            assert hardware_call_data["data"]["memory_total_mb"] == 16384
            assert hardware_call_data["data"]["hostname"] == "test-host"

    @pytest.mark.asyncio
    async def test_registration_uses_minimal_data_only(self, mock_registration):
        """Test that registration process uses only minimal data."""
        # Create proper async context manager mocks
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"id": 42, "status": "registered"})

        # Create async context manager for post response
        mock_post_context = AsyncMock()
        mock_post_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_post_context.__aexit__ = AsyncMock(return_value=None)

        # Create async context manager for session
        mock_session = AsyncMock()
        mock_session.post = Mock(return_value=mock_post_context)

        mock_session_context = AsyncMock()
        mock_session_context.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_context.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "aiohttp.ClientSession", return_value=mock_session_context
        ), patch.object(
            mock_registration.network_utils, "get_hostname", return_value="minimal-host"
        ), patch.object(
            mock_registration.network_utils,
            "get_ip_addresses",
            return_value=("1.2.3.4", None),
        ), patch(
            "ssl.create_default_context"
        ), patch(
            "aiohttp.TCPConnector"
        ):

            result = await mock_registration.register_with_server()

            assert result is True

            # Verify only minimal data was sent to server
            call_args = mock_session.post.call_args
            sent_data = call_args[1]["json"]  # Get the JSON data from kwargs

            expected_fields = {"hostname", "fqdn", "ipv4", "ipv6", "active"}
            assert set(sent_data.keys()) == expected_fields

            # Should NOT contain OS version fields
            os_fields = {
                "platform",
                "platform_release",
                "machine_architecture",
                "processor",
            }
            assert not any(field in sent_data for field in os_fields)

    def test_message_creation_os_version_update(self, tmp_path):
        """Test that OS version update messages are created correctly."""
        config_file = tmp_path / "test_config.yaml"
        config_content = """
server:
  hostname: "test-server.example.com"

i18n:
  language: "en"
"""
        config_file.write_text(config_content)

        with patch("main.ClientRegistration"), patch("main.set_language"), patch(
            "main.initialize_database", return_value=True
        ):

            agent = SysManageAgent(str(config_file))

            os_data = {
                "platform": "Darwin",
                "platform_release": "23.1.0",
                "machine_architecture": "arm64",
                "processor": "arm",
                "python_version": "3.11.5",
                "os_info": {"mac_version": "14.1"},
            }

            message = agent.create_message("os_version_update", os_data)

            assert message["message_type"] == "os_version_update"
            assert message["data"] == os_data
            assert "message_id" in message
            assert "timestamp" in message

    def test_architecture_specific_separation(self, mock_registration):
        """Test data separation works correctly for different architectures."""
        architectures = [
            ("x86_64", "Linux", "Linux"),
            ("arm64", "Darwin", "macOS"),
            ("aarch64", "Linux", "Linux"),
            ("riscv64", "Linux", "Linux"),
            ("AMD64", "Windows", "Windows"),
        ]

        for arch, _, expected_platform in architectures:
            mock_os_info = {
                "platform": expected_platform,
                "platform_release": "1.0.0",
                "platform_version": f"{expected_platform} Test Version",
                "architecture": "64bit",
                "processor": f"{arch} processor",
                "machine_architecture": arch,
                "python_version": "3.11.5",
                "os_info": {"arch_notes": f"Testing {arch}"},
            }

            with patch.object(
                mock_registration.network_utils,
                "get_hostname",
                return_value=f"{arch}-host",
            ), patch.object(
                mock_registration.network_utils,
                "get_ip_addresses",
                return_value=("10.0.0.1", None),
            ), patch.object(
                mock_registration.os_info_collector,
                "get_os_version_info",
                return_value=mock_os_info,
            ):

                basic_info = mock_registration.get_basic_registration_info()
                os_info = mock_registration.get_os_version_info()

                # Basic info should be consistent regardless of architecture
                assert basic_info["hostname"] == f"{arch}-host"
                assert basic_info["active"] is True

                # OS info should capture architecture-specific details
                assert os_info["machine_architecture"] == arch
                assert os_info["platform"] == expected_platform
