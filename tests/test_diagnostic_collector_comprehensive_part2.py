# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for diagnostics collection functionality (part 2).

Split from test_diagnostic_collector_comprehensive.py to keep files under the
line limit. Tests cover:
- Error handling and edge cases
- Windows event log collection
- Windows network commands
- Statistics calculation
- Diagnostic workflow
- Timing and performance
"""

# pylint: disable=protected-access,unused-argument,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from tests.test_diagnostic_collector_comprehensive import (
    _DIAG_AIOFILES_OPEN,
    _PLATFORM_SYSTEM,
    TestDiagnosticCollectorSetup,
    _mock_aiofiles_open,
    _mock_aiofiles_open_error,
)


class TestErrorHandling(TestDiagnosticCollectorSetup):
    """Tests for error handling scenarios."""

    @pytest.mark.asyncio
    async def test_collect_diagnostics_exception_handling(self, collector, mock_agent):
        """Test that exceptions during collection are handled gracefully."""
        parameters = {
            "collection_id": "test-error",
            "collection_types": ["system_logs"],
        }

        # Mock get_system_info to throw an exception early in the collection process
        mock_agent.registration.get_system_info.side_effect = Exception(
            "System info retrieval failed"
        )

        with patch.object(
            collector, "_send_diagnostic_error", new_callable=AsyncMock
        ) as mock_send_error:
            result = await collector.collect_diagnostics(parameters)

        # Should return failure and try to send error
        assert result["success"] is False
        assert "error" in result
        mock_send_error.assert_called_once()

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_disk_usage_command_failure(self, mock_platform, collector):
        """Test disk usage collection when all commands fail."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": False,
                "result": {"stdout": "", "stderr": "Command not found"},
            }
        )

        result = await collector._collect_disk_usage()

        # Should return empty dict rather than crash
        assert isinstance(result, dict)
        assert "filesystem_usage" not in result

    @pytest.mark.asyncio
    async def test_collect_process_info_command_timeout(self, collector):
        """Test process info collection when commands time out."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=asyncio.TimeoutError("Command timed out")
        )

        result = await collector._collect_process_info()

        assert "error" in result

    @pytest.mark.asyncio
    async def test_send_diagnostic_error_handles_send_failure(
        self, collector, mock_agent
    ):
        """Test that send failures during error reporting are handled."""
        mock_agent.send_message = AsyncMock(side_effect=Exception("Network error"))

        # Should not raise exception
        await collector._send_diagnostic_error("test-123", Exception("Original error"))

        collector.logger.error.assert_called()

    @pytest.mark.asyncio
    @patch(_PLATFORM_SYSTEM, return_value="Linux")
    async def test_collect_configuration_files_partial_failure(
        self, mock_platform, collector
    ):
        """Test configuration collection with partial command failures."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "network config"}},
                {
                    "success": False,
                    "result": {"stdout": "", "stderr": "Permission denied"},
                },
            ]
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("agent config")
        ):
            result = await collector._collect_configuration_files()

        assert "network_config" in result
        # ssh_config should not be present due to failure
        assert "agent_config" in result

    @pytest.mark.asyncio
    async def test_collect_agent_logs_missing_agent_attributes(
        self, collector, mock_agent
    ):
        """Test agent log collection when optional attributes are missing."""
        del mock_agent.reconnect_attempts
        del mock_agent.last_ping

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("Log line")):
            result = await collector._collect_agent_logs()

        assert result["agent_status"]["reconnect_attempts"] == 0
        assert result["agent_status"]["last_ping"] is None

    @pytest.mark.asyncio
    async def test_collect_error_logs_file_permission_denied(self, collector):
        """Test error log collection when file access is denied."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "system errors"}}
        )

        with patch(
            _DIAG_AIOFILES_OPEN,
            return_value=_mock_aiofiles_open_error(PermissionError("Access denied")),
        ):
            result = await collector._collect_error_logs()

        assert "agent_errors" in result
        assert "not accessible" in result["agent_errors"]


class TestWindowsEventLogCollection(TestDiagnosticCollectorSetup):
    """Tests for Windows Event Log collection."""

    @pytest.mark.asyncio
    async def test_collect_windows_event_log_success(self, collector):
        """Test successful Windows event log collection."""
        event_log_output = """[
    {"TimeCreated": "2024-01-01T10:00:00", "LevelDisplayName": "Information", "Id": 1000, "Message": "Service started"},
    {"TimeCreated": "2024-01-01T11:00:00", "LevelDisplayName": "Error", "Id": 1001, "Message": "Service failed"}
]"""

        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": event_log_output}}
        )

        result = await collector._collect_windows_event_log(
            "System", 100, "windows_system_log"
        )

        assert "windows_system_log" in result
        assert "Service started" in result["windows_system_log"]

    @pytest.mark.asyncio
    async def test_collect_windows_event_log_failure(self, collector):
        """Test Windows event log collection when command fails."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": False,
                "result": {"stdout": "", "stderr": "Access denied"},
            }
        )

        result = await collector._collect_windows_event_log(
            "Security", 50, "windows_security_log"
        )

        assert "windows_security_log" not in result

    @pytest.mark.asyncio
    async def test_collect_windows_security_log_requires_admin(self, collector):
        """Test Windows security log collection which requires admin privileges."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={
                "success": True,
                "result": {
                    "stdout": "Security logs not accessible - admin privileges required"
                },
            }
        )

        result = await collector._collect_windows_event_log(
            "Security", 50, "windows_security_log"
        )

        assert "windows_security_log" in result
        assert "admin privileges required" in result["windows_security_log"]


class TestWindowsNetworkCommands(TestDiagnosticCollectorSetup):
    """Tests for Windows network command collection."""

    @pytest.mark.asyncio
    async def test_collect_windows_network_command_success(self, collector):
        """Test successful Windows network command collection."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "ipconfig output"}}
        )

        result = await collector._collect_windows_network_command(
            "ipconfig /all", "interfaces", "network interfaces"
        )

        assert "interfaces" in result
        assert result["interfaces"] == "ipconfig output"

    @pytest.mark.asyncio
    async def test_collect_windows_network_command_failure(self, collector):
        """Test Windows network command collection when command fails."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": False, "result": {"stdout": ""}}
        )

        result = await collector._collect_windows_network_command(
            "netstat -an", "connections", "network connections"
        )

        assert "connections" not in result

    @pytest.mark.asyncio
    async def test_collect_windows_dns_config_with_fallback(self, collector):
        """Test Windows DNS config collection with fallback mechanism."""
        collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {
                    "success": False,
                    "result": {"stdout": ""},
                },  # ipconfig /displaydns fails
                {
                    "success": True,
                    "result": {"stdout": '[{"ServerAddresses": ["8.8.8.8"]}]'},
                },  # Get-DnsClientServerAddress succeeds
            ]
        )

        result = await collector._collect_windows_dns_config()

        assert "dns_config" in result
        assert "8.8.8.8" in result["dns_config"]

    @pytest.mark.asyncio
    async def test_collect_windows_dns_config_both_methods_fail(self, collector):
        """Test Windows DNS config when both methods fail."""
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": False, "result": {"stdout": ""}}
        )

        result = await collector._collect_windows_dns_config()

        assert "dns_config" in result
        assert "not available" in result["dns_config"]


class TestStatisticsCalculation(TestDiagnosticCollectorSetup):
    """Tests for collection statistics calculation."""

    def test_calculate_statistics_with_nested_files(self, collector):
        """Test statistics calculation with nested file structures."""
        diagnostic_data = {
            "collection_id": "test-123",
            "config_files": {
                "files": ["file1.conf", "file2.conf"],
                "other_key": "value",
            },
            "logs": {"files": ["log1.log", "log2.log", "log3.log"]},
        }

        size, files = collector._calculate_collection_statistics(diagnostic_data)

        assert size > 0
        assert files == 5  # 2 + 3 files

    def test_calculate_statistics_with_mixed_types(self, collector):
        """Test statistics calculation with various data types."""
        diagnostic_data = {
            "collection_id": "test-123",
            "string_value": "ignored",
            "number_value": 42,
            "boolean_value": True,
            "none_value": None,
            "list_data": ["item1", "item2", "item3"],
            "dict_data": {"nested": "value"},
        }

        _size, files = collector._calculate_collection_statistics(diagnostic_data)

        # Only list and dict should contribute
        assert files == 3  # 3 items in list

    def test_calculate_statistics_empty_collections(self, collector):
        """Test statistics with empty collections."""
        diagnostic_data = {
            "collection_id": "test-123",
            "empty_list": [],
            "empty_dict": {},
            "empty_files": {"files": []},
        }

        _size, files = collector._calculate_collection_statistics(diagnostic_data)

        assert files == 0


class TestDiagnosticWorkflow(TestDiagnosticCollectorSetup):
    """Tests for complete diagnostic collection workflow."""

    @pytest.mark.asyncio
    async def test_full_workflow_success(self, collector, mock_agent):
        """Test complete diagnostic workflow from request to result."""
        parameters = {
            "collection_id": "workflow-test-123",
            "collection_types": ["process_info", "disk_usage"],
        }

        # Mock all the collection methods
        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "test data"}}
        )

        result = await collector.collect_diagnostics(parameters)

        assert result["success"] is True
        assert result["collection_id"] == "workflow-test-123"
        mock_agent.create_message.assert_called()
        mock_agent.send_message.assert_called()

    @pytest.mark.asyncio
    async def test_workflow_with_unknown_collection_type(self, collector, mock_agent):
        """Test workflow handles unknown collection types gracefully."""
        parameters = {
            "collection_id": "unknown-type-test",
            "collection_types": ["unknown_type", "process_info"],
        }

        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "data"}}
        )

        result = await collector.collect_diagnostics(parameters)

        assert result["success"] is True
        # Should log warning for unknown type
        collector.logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_workflow_continues_after_collection_failure(
        self, collector, mock_agent
    ):
        """Test that workflow continues even if one collection type fails."""
        parameters = {
            "collection_id": "partial-failure-test",
            "collection_types": ["system_logs", "network_info", "process_info"],
        }

        call_count = 0

        async def mock_execute(params):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:  # First collection type (system_logs uses 3 commands)
                raise RuntimeError("Collection failed")
            return {"success": True, "result": {"stdout": "data"}}

        collector.system_ops.execute_shell_command = AsyncMock(side_effect=mock_execute)

        with patch(_PLATFORM_SYSTEM, return_value="Linux"):
            result = await collector.collect_diagnostics(parameters)

        # Should still succeed overall
        assert result["success"] is True


class TestTimingAndPerformance(TestDiagnosticCollectorSetup):
    """Tests related to timing and performance logging."""

    @pytest.mark.asyncio
    async def test_collection_timing_logged(self, collector):
        """Test that collection timing is properly logged."""
        parameters = {
            "collection_id": "timing-test",
            "collection_types": ["process_info"],
        }

        collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "data"}}
        )

        await collector.collect_diagnostics(parameters)

        # Check that timing-related log calls were made
        info_calls = [str(call) for call in collector.logger.info.call_args_list]
        assert any(
            "seconds" in str(call).lower() or "completed" in str(call).lower()
            for call in info_calls
        )

    @pytest.mark.asyncio
    async def test_send_timing_logged(self, collector, mock_agent):
        """Test that send timing is logged."""
        diagnostic_data = {
            "collection_id": "send-timing-test",
            "success": True,
            "data": "test",
        }

        await collector._send_diagnostic_result(diagnostic_data)

        info_calls = [str(call) for call in collector.logger.info.call_args_list]
        assert any(
            "sent" in str(call).lower() or "seconds" in str(call).lower()
            for call in info_calls
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
