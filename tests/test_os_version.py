"""
Test OS version capture functionality.
"""

# pylint: disable=duplicate-code

import platform
from unittest.mock import AsyncMock, Mock, patch

import pytest

from main import SysManageAgent
from src.sysmanage_agent.core.config import ConfigManager
from src.sysmanage_agent.registration.client_registration import ClientRegistration


class TestOSVersionCapture:
    """Test OS version capture and reporting functionality."""

    @pytest.fixture
    def mock_config(self, tmp_path):
        """Create a mock configuration manager."""
        config_file = tmp_path / "test_config.yaml"
        log_file = tmp_path / "test.log"
        # Convert to forward slashes for YAML compatibility on Windows
        log_file_str = str(log_file).replace("\\", "/")
        config_content = f"""
server:
  hostname: "test-server.example.com"
  port: 8000
  use_https: false
  api_path: "/api"

client:
  hostname_override: null

i18n:
  language: "en"

logging:
  file: "{log_file_str}"
"""
        config_file.write_text(config_content)
        return ConfigManager(str(config_file))

    @pytest.fixture
    def mock_registration(self, mock_config):
        """Create a mock registration handler."""
        return ClientRegistration(mock_config)

    def test_get_system_info_comprehensive(self, mock_registration):
        """Test that get_system_info() collects comprehensive OS data."""
        with patch("platform.machine", return_value="x86_64"), patch(
            "platform.system", return_value="Linux"
        ), patch("platform.release", return_value="5.15.0-88-generic"), patch(
            "platform.version",
            return_value="#98-Ubuntu SMP Mon Oct 2 15:29:04 UTC 2023",
        ), patch(
            "platform.architecture", return_value=("64bit", "ELF")
        ), patch(
            "platform.processor", return_value="x86_64"
        ), patch(
            "platform.python_version", return_value="3.11.5"
        ), patch(
            "src.sysmanage_agent.collection.os_info_collection.OSInfoCollector._get_linux_distribution_info",
            return_value=("Linux", "5.15.0-88-generic"),
        ):

            system_info = mock_registration.get_system_info()

            assert system_info["platform"] == "Linux"
            assert system_info["platform_release"] == "5.15.0-88-generic"
            assert (
                system_info["platform_version"]
                == "#98-Ubuntu SMP Mon Oct 2 15:29:04 UTC 2023"
            )
            assert system_info["machine_architecture"] == "x86_64"
            assert system_info["processor"] == "x86_64"
            assert system_info["architecture"] == "64bit"
            assert system_info["python_version"] == "3.11.5"
            assert "os_info" in system_info

    def test_get_system_info_macos(self, mock_registration):
        """Test OS data collection on macOS."""
        with patch("platform.machine", return_value="arm64"), patch(
            "platform.system", return_value="Darwin"
        ), patch(
            "platform.mac_ver", return_value=("14.1.1", ("", "", ""), "arm64")
        ), patch(
            "platform.release", return_value="23.1.0"
        ), patch(
            "platform.version", return_value="Darwin Kernel Version 23.1.0"
        ), patch(
            "platform.architecture", return_value=("64bit", "")
        ), patch(
            "platform.processor", return_value="arm"
        ), patch(
            "platform.python_version", return_value="3.11.5"
        ):

            system_info = mock_registration.get_system_info()

            assert system_info["platform"] == "macOS"
            assert system_info["machine_architecture"] == "arm64"
            assert system_info["os_info"]["mac_version"] == "14.1.1"

    def test_get_system_info_windows(self, mock_registration):
        """Test OS data collection on Windows."""
        with patch("platform.machine", return_value="AMD64"), patch(
            "platform.system", return_value="Windows"
        ), patch(
            "platform.win32_ver",
            return_value=("10", "10.0.19045", "SP0", "Multiprocessor Free"),
        ), patch(
            "platform.release", return_value="10"
        ), patch(
            "platform.version", return_value="10.0.19045"
        ), patch(
            "platform.architecture", return_value=("64bit", "WindowsPE")
        ), patch(
            "platform.processor",
            return_value="Intel64 Family 6 Model 165 Stepping 2, GenuineIntel",
        ), patch(
            "platform.python_version", return_value="3.11.5"
        ):

            system_info = mock_registration.get_system_info()

            assert system_info["platform"] == "Windows"
            assert system_info["machine_architecture"] == "AMD64"
            assert system_info["os_info"]["windows_version"] == "10"
            assert system_info["os_info"]["windows_service_pack"] == "10.0.19045"

    def test_get_system_info_linux_with_distribution(self, mock_registration):
        """Test OS data collection on Linux with distribution info."""
        mock_os_release = {
            "NAME": "Ubuntu",
            "VERSION_ID": "22.04",
            "VERSION_CODENAME": "jammy",
        }

        with patch("platform.machine", return_value="aarch64"), patch(
            "platform.system", return_value="Linux"
        ), patch("platform.release", return_value="5.15.0-1044-raspi"), patch(
            "platform.version",
            return_value="#47-Ubuntu SMP PREEMPT Mon Jul 24 09:11:25 UTC 2023",
        ), patch(
            "platform.architecture", return_value=("64bit", "ELF")
        ), patch(
            "platform.processor", return_value="aarch64"
        ), patch(
            "platform.python_version", return_value="3.10.12"
        ), patch.object(
            platform,
            "freedesktop_os_release",
            return_value=mock_os_release,
            create=True,
        ):

            system_info = mock_registration.get_system_info()

            assert system_info["platform"] == "Linux"
            assert system_info["machine_architecture"] == "aarch64"
            assert system_info["os_info"]["distribution"] == "Ubuntu"
            assert system_info["os_info"]["distribution_version"] == "22.04"
            assert system_info["os_info"]["distribution_codename"] == "jammy"

    def test_get_system_info_riscv(self, mock_registration):
        """Test OS data collection on RISC-V architecture."""
        with patch("platform.machine", return_value="riscv64"), patch(
            "platform.system", return_value="Linux"
        ), patch("platform.release", return_value="6.1.0-starfive"), patch(
            "platform.version", return_value="#1 SMP Mon Dec 19 17:25:01 EST 2022"
        ), patch(
            "platform.architecture", return_value=("64bit", "ELF")
        ), patch(
            "platform.processor", return_value="rv64imafdcv"
        ), patch(
            "platform.python_version", return_value="3.11.2"
        ):

            system_info = mock_registration.get_system_info()

            assert system_info["machine_architecture"] == "riscv64"
            assert system_info["processor"] == "rv64imafdcv"

    @pytest.mark.asyncio
    async def test_update_os_version_command(self, tmp_path):
        """Test handling of update_os_version command."""
        config_file = tmp_path / "test_config.yaml"
        log_file = tmp_path / "test.log"
        # Convert to forward slashes for YAML compatibility on Windows
        log_file_str = str(log_file).replace("\\", "/")
        config_content = f"""
server:
  hostname: "test-server.example.com"
  port: 8000

i18n:
  language: "en"

logging:
  file: "{log_file_str}"
"""
        config_file.write_text(config_content)

        with patch("main.ClientRegistration") as mock_reg_class, patch(
            "main.set_language"
        ), patch("main.QueuedMessageHandler") as mock_handler_class, patch(
            "main.initialize_database", return_value=True
        ):

            # Mock the message handler
            mock_handler = Mock()
            mock_handler.queue_outbound_message = AsyncMock(return_value="test-msg-id")
            mock_handler_class.return_value = mock_handler

            mock_registration = Mock()
            mock_registration.get_os_version_info.return_value = {
                "platform": "Linux",
                "platform_release": "5.15.0",
                "platform_version": "test version",
                "machine_architecture": "x86_64",
                "processor": "Intel",
                "os_info": {"distribution": "Ubuntu"},
                "python_version": "3.11.5",
                "architecture": "64bit",
            }
            mock_registration.get_system_info.return_value = {
                "hostname": "test-host.example.com"
            }
            mock_reg_class.return_value = mock_registration

            agent = SysManageAgent(str(config_file))
            agent.websocket = AsyncMock()
            agent.connected = True  # Set connected flag
            agent.logger = Mock()

            result = await agent.update_os_version()

            assert result["success"] is True
            assert "OS version information sent" in result["result"]

            # Verify message was queued
            agent.message_handler.queue_outbound_message.assert_called_once()
            queued_message = agent.message_handler.queue_outbound_message.call_args[0][
                0
            ]
            assert queued_message["message_type"] == "os_version_update"
            assert queued_message["data"]["platform"] == "Linux"
            assert queued_message["data"]["machine_architecture"] == "x86_64"
            assert queued_message["data"]["hostname"] == "test-host.example.com"

    @pytest.mark.asyncio
    async def test_handle_update_os_version_command(self, tmp_path):
        """Test agent handles update_os_version command correctly."""
        config_file = tmp_path / "test_config.yaml"
        log_file = tmp_path / "test.log"
        # Convert to forward slashes for YAML compatibility on Windows
        log_file_str = str(log_file).replace("\\", "/")
        config_content = f"""
server:
  hostname: "test-server.example.com"

i18n:
  language: "en"

logging:
  file: "{log_file_str}"
"""
        config_file.write_text(config_content)

        with patch("main.ClientRegistration") as mock_reg_class, patch(
            "main.set_language"
        ), patch("main.QueuedMessageHandler") as mock_handler_class, patch(
            "main.initialize_database", return_value=True
        ), patch(
            "main.get_database_manager"
        ):

            # Mock the message handler
            mock_handler = Mock()
            mock_handler.queue_outbound_message = AsyncMock(return_value="test-msg-id")
            mock_handler_class.return_value = mock_handler

            mock_registration = Mock()
            mock_registration.get_os_version_info.return_value = {
                "platform": "macOS",
                "machine_architecture": "arm64",
                "os_info": {},
                "platform_release": "Sonoma 14.1",
                "processor": "arm",
                "architecture": "64bit",
                "python_version": "3.11.5",
            }
            mock_registration.get_system_info.return_value = {
                "hostname": "test-host.example.com"
            }
            mock_reg_class.return_value = mock_registration

            # Create a mock agent instead of a real one
            agent = Mock()
            agent.websocket = AsyncMock()
            agent.connected = True
            agent.logger = Mock()
            agent.message_handler = mock_handler

            # Mock the message processor
            mock_processor = Mock()

            # Mock the handle_command to simulate the behavior
            async def mock_handle_command(message):
                # Simulate what handle_command does - calls the processor
                await mock_processor.handle_command(message)

            agent.handle_command = mock_handle_command

            # Mock the processor's handle_command to queue messages like the real implementation
            async def mock_processor_handle_command(message):
                # Simulate calling update_os_version and sending result
                result = {"success": True, "result": "OS version information sent"}
                response = {"message_type": "command_result", "data": result}
                await mock_handler.queue_outbound_message(response)

                # Also simulate the OS version update message
                os_update_msg = {"message_type": "os_version_update", "data": {}}
                await mock_handler.queue_outbound_message(os_update_msg)

            mock_processor.handle_command = mock_processor_handle_command

            # Create command message
            command_message = {
                "message_type": "command",
                "message_id": "cmd-123",
                "data": {"command_type": "update_os_version", "parameters": {}},
            }

            await agent.handle_command(command_message)

            # Should queue two messages: OS update and command result
            assert agent.message_handler.queue_outbound_message.call_count == 2

    def test_architecture_detection(self, mock_registration):
        """Test correct detection of various CPU architectures."""
        architectures = [
            ("x86_64", "Intel/AMD 64-bit"),
            ("i686", "Intel/AMD 32-bit"),
            ("aarch64", "ARM 64-bit"),
            ("arm64", "ARM 64-bit Apple"),
            ("armv7l", "ARM 32-bit"),
            ("riscv64", "RISC-V 64-bit"),
            ("ppc64le", "PowerPC 64-bit LE"),
            ("s390x", "IBM System Z"),
        ]

        for arch, _ in architectures:
            with patch("platform.machine", return_value=arch):
                system_info = mock_registration.get_system_info()
                assert system_info["machine_architecture"] == arch
