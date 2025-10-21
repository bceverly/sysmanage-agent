"""
Unit tests for src.sysmanage_agent.operations.antivirus_service_manager module.
Tests service management operations for antivirus software.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_service_manager import (
    AntivirusServiceManager,
)


class TestAntivirusServiceManager:
    """Test cases for AntivirusServiceManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.websocket_client = Mock()
        self.mock_agent.websocket_client.send_message = AsyncMock()
        self.mock_agent.send_message = AsyncMock(return_value=True)
        self.mock_agent.create_message = Mock(
            return_value=Mock(to_dict=Mock(return_value={}))
        )
        self.service_manager = AntivirusServiceManager(self.mock_agent)

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_success(self):
        """Test successful antivirus status update."""
        status = {"software_name": "ClamAV", "version": "1.0.0"}

        await self.service_manager.send_antivirus_status_update(status)

        # Verify agent.send_message was called (queue-based sending)
        self.mock_agent.send_message.assert_called_once()
        # Verify create_message was called with correct type
        self.mock_agent.create_message.assert_called_once_with(
            "antivirus_status_update", {"antivirus_status": status}
        )

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_failure(self):
        """Test antivirus status update with exception."""
        self.mock_agent.send_message.side_effect = Exception("Connection error")
        status = {"software_name": "ClamAV"}

        # Should not raise exception
        await self.service_manager.send_antivirus_status_update(status)

    @pytest.mark.asyncio
    async def test_enable_antivirus_no_software_detected(self):
        """Test enable_antivirus when no antivirus is detected."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {}

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.service_manager.enable_antivirus({})

            assert result["success"] is False
            assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_linux_success(self):
        """Test enable_antivirus on Linux with systemctl."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.service_manager.enable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamav_freshclam"

    @pytest.mark.asyncio
    async def test_disable_antivirus_success(self):
        """Test disable_antivirus success."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=False):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.service_manager.disable_antivirus({})

                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_antivirus_no_software(self):
        """Test remove_antivirus when no software detected."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {}

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.service_manager.remove_antivirus({})

            assert result["success"] is False
            assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_unknown_software(self):
        """Test remove_antivirus with unknown software."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "UnknownAV"
        }

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.service_manager.remove_antivirus({})

            assert result["success"] is False
            assert "Unknown antivirus software" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_unsupported_platform(self):
        """Test remove_antivirus on unsupported platform."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Unknown"):
                    result = await self.service_manager.remove_antivirus({})

                    assert result["success"] is False
                    assert "Unsupported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_windows_service_not_configured(self):
        """Test enable_antivirus on Windows when service is not configured."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 1  # Service doesn't exist
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("platform.system", return_value="Windows"):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.service_manager.enable_antivirus({})

                    assert result["success"] is False
                    assert "manual service setup" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_netbsd_multiple_services(self):
        """Test enable_antivirus on NetBSD starting multiple services."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/pkg/bin/pkgin"
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.service_manager.enable_antivirus({})

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_antivirus_netbsd_warning(self):
        """Test disable_antivirus on NetBSD with service warning."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        # First service fails, second succeeds
        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Warning"))

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/pkg/bin/pkgin"
                with patch("platform.system", return_value="NetBSD"):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        side_effect=[mock_process_fail, mock_process_success],
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            result = await self.service_manager.disable_antivirus({})

                            # Last process determines success
                            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_antivirus_exception(self):
        """Test enable_antivirus with unexpected exception."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.service_manager.enable_antivirus({})

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_antivirus_exception(self):
        """Test disable_antivirus with unexpected exception."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.service_manager.disable_antivirus({})

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_exception(self):
        """Test remove_antivirus with unexpected exception."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_service_manager.AntivirusCollector",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.service_manager.remove_antivirus({})

            assert result["success"] is False
            assert "Unexpected error" in result["error"]
