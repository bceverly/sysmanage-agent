# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for src.sysmanage_agent.diagnostics.diagnostic_collector module.
Tests the DiagnosticCollector class for diagnostic data collection.
"""

# pylint: disable=protected-access,unused-argument,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.diagnostics.diagnostic_collector import DiagnosticCollector

_DIAG_AIOFILES_OPEN = (
    "src.sysmanage_agent.diagnostics.diagnostic_collector.aiofiles.open"
)


def _mock_aiofiles_open(read_data=""):
    """Create a mock for aiofiles.open that supports async context manager."""
    mock_file = AsyncMock()
    mock_file.read = AsyncMock(return_value=read_data)
    lines = [line + "\n" for line in read_data.split("\n")] if read_data else []
    mock_file.readlines = AsyncMock(return_value=lines)
    mock_file.write = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_file)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


def _mock_aiofiles_open_error(error=None):
    """Create a mock for aiofiles.open that raises on enter."""
    if error is None:
        error = IOError("File not found")
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(side_effect=error)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_ctx


class TestDiagnosticCollector:  # pylint: disable=too-many-public-methods
    """Test cases for DiagnosticCollector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.logger = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.running = True
        self.mock_agent.connected = True
        self.mock_agent.reconnect_attempts = 0
        self.mock_agent.last_ping = "2024-01-01T00:00:00Z"

        # Setup registration mock
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host",
            "platform": "Linux",
        }

        # Setup create_message and send_message
        self.mock_agent.create_message = Mock(
            return_value={"message_id": "msg-123", "message_type": "test"}
        )
        self.mock_agent.send_message = AsyncMock()

        self.collector = DiagnosticCollector(self.mock_agent)

    def test_init(self):
        """Test DiagnosticCollector initialization."""
        assert self.collector.agent == self.mock_agent
        assert self.collector.logger == self.mock_agent.logger
        assert self.collector.system_ops == self.mock_agent.system_ops
        assert self.collector.registration == self.mock_agent.registration

    # Test collect_diagnostics method
    @pytest.mark.asyncio
    async def test_collect_diagnostics_success_empty_types(self):
        """Test collect_diagnostics with empty collection types."""
        parameters = {"collection_id": "test-123", "collection_types": []}

        with patch.object(
            self.collector, "_send_diagnostic_result", new_callable=AsyncMock
        ) as mock_send:
            result = await self.collector.collect_diagnostics(parameters)

            assert result["success"] is True
            assert result["collection_id"] == "test-123"
            assert "message" in result
            mock_send.assert_called_once()

            # Verify diagnostic data structure
            call_args = mock_send.call_args[0][0]
            assert call_args["collection_id"] == "test-123"
            assert call_args["success"] is True
            assert call_args["hostname"] == "test-host"
            assert "timestamp" in call_args
            assert "collection_size_bytes" in call_args
            assert "files_collected" in call_args

    @pytest.mark.asyncio
    async def test_collect_diagnostics_success_with_types(self):
        """Test collect_diagnostics with collection types."""
        parameters = {
            "collection_id": "test-456",
            "collection_types": ["system_logs", "network_info"],
        }

        with patch.object(
            self.collector, "_collect_system_logs", new_callable=AsyncMock
        ) as mock_logs:
            with patch.object(
                self.collector, "_collect_network_info", new_callable=AsyncMock
            ) as mock_network:
                with patch.object(
                    self.collector,
                    "_send_diagnostic_result",
                    new_callable=AsyncMock,
                ) as mock_send:
                    mock_logs.return_value = {"logs": "test data"}
                    mock_network.return_value = {"interfaces": "eth0"}

                    result = await self.collector.collect_diagnostics(parameters)

                    assert result["success"] is True
                    assert result["collection_id"] == "test-456"
                    mock_logs.assert_called_once()
                    mock_network.assert_called_once()
                    mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_diagnostics_no_collection_id(self):
        """Test collect_diagnostics without collection_id."""
        parameters = {"collection_types": []}

        with patch.object(
            self.collector, "_send_diagnostic_result", new_callable=AsyncMock
        ) as mock_send:
            result = await self.collector.collect_diagnostics(parameters)

            assert result["success"] is True
            assert result["collection_id"] is None
            mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_diagnostics_exception(self):
        """Test collect_diagnostics handles exceptions."""
        parameters = {"collection_id": "test-error", "collection_types": []}

        with patch.object(
            self.collector.registration,
            "get_system_info",
            side_effect=Exception("Test error"),
        ):
            with patch.object(
                self.collector,
                "_send_diagnostic_error",
                new_callable=AsyncMock,
            ) as mock_send_error:
                result = await self.collector.collect_diagnostics(parameters)

                assert result["success"] is False
                assert "error" in result
                assert "Test error" in result["error"]
                # Check that error was sent - don't check exact exception type
                assert mock_send_error.called
                call_args = mock_send_error.call_args[0]
                assert call_args[0] == "test-error"
                assert isinstance(call_args[1], Exception)

    @pytest.mark.asyncio
    async def test_collect_diagnostics_exception_no_collection_id(self):
        """Test collect_diagnostics exception handling without collection_id."""
        parameters = {"collection_types": []}

        with patch.object(
            self.collector.registration,
            "get_system_info",
            side_effect=Exception("Test error"),
        ):
            with patch.object(
                self.collector,
                "_send_diagnostic_error",
                new_callable=AsyncMock,
            ) as mock_send_error:
                result = await self.collector.collect_diagnostics(parameters)

                assert result["success"] is False
                assert "error" in result
                mock_send_error.assert_not_called()

    # Test _collect_single_diagnostic_type method
    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_system_logs(self):
        """Test collecting system logs."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_system_logs", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"logs": "data"}
            await self.collector._collect_single_diagnostic_type(
                "system_logs", diagnostic_data
            )
            assert diagnostic_data["system_logs"] == {"logs": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_configuration_files(self):
        """Test collecting configuration files."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_configuration_files", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"config": "data"}
            await self.collector._collect_single_diagnostic_type(
                "configuration_files", diagnostic_data
            )
            assert diagnostic_data["configuration_files"] == {"config": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_network_info(self):
        """Test collecting network info."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_network_info", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"interfaces": "eth0"}
            await self.collector._collect_single_diagnostic_type(
                "network_info", diagnostic_data
            )
            assert diagnostic_data["network_info"] == {"interfaces": "eth0"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_process_info(self):
        """Test collecting process info."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_process_info", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"processes": "data"}
            await self.collector._collect_single_diagnostic_type(
                "process_info", diagnostic_data
            )
            assert diagnostic_data["process_info"] == {"processes": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_disk_usage(self):
        """Test collecting disk usage."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_disk_usage", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"disk": "data"}
            await self.collector._collect_single_diagnostic_type(
                "disk_usage", diagnostic_data
            )
            assert diagnostic_data["disk_usage"] == {"disk": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_environment_variables(self):
        """Test collecting environment variables."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_environment_variables", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"env": "data"}
            await self.collector._collect_single_diagnostic_type(
                "environment_variables", diagnostic_data
            )
            assert diagnostic_data["environment_variables"] == {"env": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_agent_logs(self):
        """Test collecting agent logs."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_agent_logs", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"agent_logs": "data"}
            await self.collector._collect_single_diagnostic_type(
                "agent_logs", diagnostic_data
            )
            assert diagnostic_data["agent_logs"] == {"agent_logs": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_error_logs(self):
        """Test collecting error logs."""
        diagnostic_data = {}
        with patch.object(
            self.collector, "_collect_error_logs", new_callable=AsyncMock
        ) as mock_collect:
            mock_collect.return_value = {"errors": "data"}
            await self.collector._collect_single_diagnostic_type(
                "error_logs", diagnostic_data
            )
            assert diagnostic_data["error_logs"] == {"errors": "data"}
            mock_collect.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_single_diagnostic_type_unknown(self):
        """Test collecting unknown diagnostic type."""
        diagnostic_data = {}
        await self.collector._collect_single_diagnostic_type(
            "unknown_type", diagnostic_data
        )
        assert "unknown_type" not in diagnostic_data
        self.collector.logger.warning.assert_called_once()

    # Test _collect_all_diagnostic_types method
    @pytest.mark.asyncio
    async def test_collect_all_diagnostic_types_success(self):
        """Test collecting all diagnostic types successfully."""
        collection_types = ["system_logs", "network_info"]
        diagnostic_data = {}

        with patch.object(
            self.collector, "_collect_single_diagnostic_type", new_callable=AsyncMock
        ) as mock_collect:
            await self.collector._collect_all_diagnostic_types(
                collection_types, diagnostic_data
            )
            assert mock_collect.call_count == 2

    @pytest.mark.asyncio
    async def test_collect_all_diagnostic_types_with_exception(self):
        """Test collecting diagnostic types with exception in one type."""
        collection_types = ["system_logs", "network_info"]
        diagnostic_data = {}

        with patch.object(
            self.collector, "_collect_single_diagnostic_type", new_callable=AsyncMock
        ) as mock_collect:
            # First call succeeds, second raises exception
            mock_collect.side_effect = [None, Exception("Collection error")]

            await self.collector._collect_all_diagnostic_types(
                collection_types, diagnostic_data
            )

            assert mock_collect.call_count == 2
            # Logger should have logged error for the second type
            assert self.collector.logger.error.called

    @pytest.mark.asyncio
    async def test_collect_all_diagnostic_types_empty_list(self):
        """Test collecting with empty types list."""
        collection_types = []
        diagnostic_data = {}

        with patch.object(
            self.collector, "_collect_single_diagnostic_type", new_callable=AsyncMock
        ) as mock_collect:
            await self.collector._collect_all_diagnostic_types(
                collection_types, diagnostic_data
            )
            mock_collect.assert_not_called()

    # Test _calculate_collection_statistics method
    def test_calculate_collection_statistics_with_dict_data(self):
        """Test statistics calculation with dict data."""
        diagnostic_data = {
            "collection_id": "test-123",
            "system_logs": {"logs": "some log data here"},
            "network_info": {"interfaces": "eth0"},
        }

        size, files = self.collector._calculate_collection_statistics(diagnostic_data)

        assert size > 0
        assert files == 0  # No 'files' key in dicts

    def test_calculate_collection_statistics_with_files(self):
        """Test statistics calculation with files in dict."""
        diagnostic_data = {
            "collection_id": "test-123",
            "config_files": {"files": ["file1.txt", "file2.txt", "file3.txt"]},
        }

        size, files = self.collector._calculate_collection_statistics(diagnostic_data)

        assert size > 0
        assert files == 3

    def test_calculate_collection_statistics_with_list_data(self):
        """Test statistics calculation with list data."""
        diagnostic_data = {
            "collection_id": "test-123",
            "processes": ["process1", "process2", "process3", "process4"],
        }

        size, files = self.collector._calculate_collection_statistics(diagnostic_data)

        assert size > 0
        assert files == 4

    def test_calculate_collection_statistics_empty_data(self):
        """Test statistics calculation with empty data."""
        diagnostic_data = {"collection_id": "test-123"}

        size, files = self.collector._calculate_collection_statistics(diagnostic_data)

        assert size == 0
        assert files == 0

    def test_calculate_collection_statistics_mixed_data(self):
        """Test statistics calculation with mixed data types."""
        diagnostic_data = {
            "collection_id": "test-123",
            "system_logs": {"logs": "data"},
            "processes": ["p1", "p2"],
            "config_files": {"files": ["f1", "f2", "f3"]},
            "simple_string": "ignored",
            "simple_number": 42,
        }

        size, files = self.collector._calculate_collection_statistics(diagnostic_data)

        assert size > 0
        assert files == 5  # 2 from processes list + 3 from config_files

    # Test _send_diagnostic_result method
    @pytest.mark.asyncio
    async def test_send_diagnostic_result_success(self):
        """Test sending diagnostic result successfully."""
        diagnostic_data = {
            "collection_id": "test-123",
            "success": True,
            "data": "test",
        }

        await self.collector._send_diagnostic_result(diagnostic_data)

        self.mock_agent.create_message.assert_called_once_with(
            "diagnostic_collection_result", diagnostic_data
        )
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_diagnostic_result_large_data(self):
        """Test sending large diagnostic result."""
        diagnostic_data = {
            "collection_id": "test-123",
            "success": True,
            "large_data": "x" * 10000,
        }

        await self.collector._send_diagnostic_result(diagnostic_data)

        self.mock_agent.create_message.assert_called_once()
        self.mock_agent.send_message.assert_called_once()

    # Test _send_diagnostic_error method
    @pytest.mark.asyncio
    async def test_send_diagnostic_error_success(self):
        """Test sending diagnostic error successfully."""
        collection_id = "test-123"
        error = Exception("Test error message")

        await self.collector._send_diagnostic_error(collection_id, error)

        self.mock_agent.create_message.assert_called_once()
        call_args = self.mock_agent.create_message.call_args[0]
        assert call_args[0] == "diagnostic_collection_result"
        assert call_args[1]["collection_id"] == collection_id
        assert call_args[1]["success"] is False
        assert "Test error message" in call_args[1]["error"]
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_diagnostic_error_send_fails(self):
        """Test handling when sending error message fails."""
        collection_id = "test-123"
        error = Exception("Original error")
        self.mock_agent.send_message = AsyncMock(side_effect=Exception("Send failed"))

        # Should not raise exception
        await self.collector._send_diagnostic_error(collection_id, error)

        self.collector.logger.error.assert_called()
