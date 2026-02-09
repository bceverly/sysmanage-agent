"""
Tests for antivirus operations enable_antivirus method.
Tests enabling antivirus software on various platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_operations import AntivirusOperations


@pytest.fixture
def mock_agent():
    """Create a mock agent instance for testing."""
    agent = Mock()
    agent.send_message = AsyncMock(return_value=True)
    agent.create_message = Mock(return_value=Mock(to_dict=Mock(return_value={})))
    return agent


@pytest.fixture
def av_ops(mock_agent):
    """Create an AntivirusOperations instance for testing."""
    return AntivirusOperations(mock_agent)


class TestEnableAntivirus:
    """Tests for enable_antivirus method."""

    @pytest.mark.asyncio
    async def test_enable_no_antivirus_detected(self, av_ops):
        """Test enable fails when no antivirus is detected."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {}

            result = await av_ops.enable_antivirus({})

        assert result["success"] is False
        assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_unknown_software(self, av_ops):
        """Test enable fails for unknown software."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "unknown"
            }

            result = await av_ops.enable_antivirus({})

        assert result["success"] is False
        assert "Unknown antivirus software" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_clamav_linux_systemctl(self, av_ops):
        """Test enable ClamAV on Linux with systemctl."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_openbsd_rcctl(self, av_ops):
        """Test enable ClamAV on OpenBSD with rcctl."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/sbin/rcctl"

                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_macos_brew(self, av_ops):
        """Test enable ClamAV on macOS with brew services."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/opt/homebrew/bin/brew"

                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_windows(self, av_ops):
        """Test enable ClamAV on Windows."""
        mock_query_process = AsyncMock()
        mock_query_process.returncode = 0
        mock_query_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_process = AsyncMock()
        mock_start_process.returncode = 0
        mock_start_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("platform.system", return_value="Windows"):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        side_effect=[mock_query_process, mock_start_process],
                    ):
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_windows_service_not_configured(self, av_ops):
        """Test enable ClamAV on Windows when service is not configured."""
        mock_query_process = AsyncMock()
        mock_query_process.returncode = 1
        mock_query_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("platform.system", return_value="Windows"):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_query_process,
                    ):
                        result = await av_ops.enable_antivirus({})

        assert result["success"] is False
        assert "manual service setup" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_exception(self, av_ops):
        """Test enable handles exceptions."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector",
            side_effect=Exception("Collection failed"),
        ):
            result = await av_ops.enable_antivirus({})

        assert result["success"] is False
