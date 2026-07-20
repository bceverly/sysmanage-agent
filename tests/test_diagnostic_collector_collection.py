# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Additional unit tests for src.sysmanage_agent.diagnostics.diagnostic_collector module.
Split from test_diagnostic_collector.py to keep files under the line limit.
Covers platform-specific collection methods (_collect_system_logs,
_collect_configuration_files, _collect_network_info, _collect_process_info,
_collect_disk_usage, _collect_environment_variables, _collect_agent_logs,
_collect_error_logs) and full workflow tests.
"""

# pylint: disable=protected-access,unused-argument,attribute-defined-outside-init

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.diagnostics.diagnostic_collector import DiagnosticCollector
from tests.test_diagnostic_collector import (
    _DIAG_AIOFILES_OPEN,
    _mock_aiofiles_open,
    _mock_aiofiles_open_error,
)


class TestDiagnosticCollectorCollection:  # pylint: disable=too-many-public-methods
    """Test cases for DiagnosticCollector platform-specific collection methods."""

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

    # Test _collect_system_logs method
    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_system_logs_windows_success(self, mock_platform):
        """Test collecting system logs on Windows."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "log data"}}
        )

        result = await self.collector._collect_system_logs()

        assert "windows_system_log" in result
        assert "windows_application_log" in result
        assert "windows_security_log" in result
        assert self.collector.system_ops.execute_shell_command.call_count == 3

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_system_logs_windows_partial_failure(self, mock_platform):
        """Test collecting system logs on Windows with partial failures."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "system log"}},
                {"success": False, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": "security log"}},
            ]
        )

        result = await self.collector._collect_system_logs()

        assert "windows_system_log" in result
        assert result["windows_system_log"] == "system log"
        # Application log should not be present or be empty
        assert "windows_security_log" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_system_logs_linux_success(self, mock_platform):
        """Test collecting system logs on Linux."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "log data"}}
        )

        result = await self.collector._collect_system_logs()

        assert "journalctl_recent" in result
        assert "dmesg_recent" in result
        assert "auth_log" in result
        assert self.collector.system_ops.execute_shell_command.call_count == 3

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_system_logs_linux_failure(self, mock_platform):
        """Test collecting system logs on Linux with failures."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": False, "result": {"stdout": ""}}
        )

        result = await self.collector._collect_system_logs()

        # Should still return dict but without successful collections
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_system_logs_exception(self, mock_platform):
        """Test collecting system logs with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_system_logs()

        assert "error" in result
        assert "Test error" in result["error"]

    # Test _collect_configuration_files method
    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_configuration_files_windows(self, mock_platform):
        """Test collecting configuration files on Windows."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "config data"}}
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("agent config")
        ):
            result = await self.collector._collect_configuration_files()

            assert "network_config" in result
            assert "services_config" in result
            assert "firewall_config" in result
            assert "agent_config" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_configuration_files_linux(self, mock_platform):
        """Test collecting configuration files on Linux."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "config data"}}
        )

        with patch(
            _DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("agent config")
        ):
            result = await self.collector._collect_configuration_files()

            assert "network_config" in result
            assert "ssh_config" in result
            assert "agent_config" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_configuration_files_agent_config_not_readable(
        self, mock_platform
    ):
        """Test collecting configuration files when agent config is not readable."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "config data"}}
        )

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open_error()):
            result = await self.collector._collect_configuration_files()

            assert "agent_config" in result
            assert "not readable" in result["agent_config"]

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_configuration_files_exception(self, mock_platform):
        """Test collecting configuration files with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_configuration_files()

        assert "error" in result
        assert "Test error" in result["error"]

    # Test _collect_network_info method
    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_network_info_windows_success(self, mock_platform):
        """Test collecting network info on Windows."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "network data"}}
        )

        result = await self.collector._collect_network_info()

        assert "interfaces" in result
        assert "routes" in result
        assert "connections" in result
        assert "dns_config" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_network_info_windows_dns_fallback(self, mock_platform):
        """Test collecting network info on Windows with DNS fallback."""
        call_count = 0

        async def mock_execute(params):
            nonlocal call_count
            call_count += 1
            if call_count == 4:  # First DNS call
                return {"success": False, "result": {"stdout": ""}}
            if call_count == 5:  # Fallback DNS call
                return {"success": True, "result": {"stdout": "dns fallback"}}
            return {"success": True, "result": {"stdout": "network data"}}

        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=mock_execute
        )

        result = await self.collector._collect_network_info()

        assert "dns_config" in result
        assert result["dns_config"] == "dns fallback"

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_network_info_windows_dns_both_fail(self, mock_platform):
        """Test collecting network info on Windows when both DNS methods fail."""
        call_count = 0

        async def mock_execute(params):
            nonlocal call_count
            call_count += 1
            if call_count in [4, 5]:  # Both DNS calls
                return {"success": False, "result": {"stdout": ""}}
            return {"success": True, "result": {"stdout": "network data"}}

        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=mock_execute
        )

        result = await self.collector._collect_network_info()

        assert "dns_config" in result
        assert "not available" in result["dns_config"]

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_network_info_linux_success(self, mock_platform):
        """Test collecting network info on Linux."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "network data"}}
        )

        result = await self.collector._collect_network_info()

        assert "interfaces" in result
        assert "routes" in result
        assert "connections" in result
        assert "dns_config" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_network_info_exception(self, mock_platform):
        """Test collecting network info with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_network_info()

        assert "error" in result
        assert "Test error" in result["error"]

    # Test _collect_process_info method
    @pytest.mark.asyncio
    async def test_collect_process_info_success(self):
        """Test collecting process info successfully."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "process data"}}
        )

        result = await self.collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert "top_processes_memory" in result
        assert "system_load" in result
        assert "memory_info" in result
        assert self.collector.system_ops.execute_shell_command.call_count == 4

    @pytest.mark.asyncio
    async def test_collect_process_info_partial_failure(self):
        """Test collecting process info with partial failures."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "cpu data"}},
                {"success": False, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": "load data"}},
                {"success": True, "result": {"stdout": "memory data"}},
            ]
        )

        result = await self.collector._collect_process_info()

        assert "top_processes_cpu" in result
        assert result["top_processes_cpu"] == "cpu data"
        # Memory processes should not be in result or be empty
        assert "system_load" in result
        assert "memory_info" in result

    @pytest.mark.asyncio
    async def test_collect_process_info_exception(self):
        """Test collecting process info with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_process_info()

        assert "error" in result
        assert "Test error" in result["error"]

    # Test _collect_disk_usage method
    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_disk_usage_windows_success(self, mock_platform):
        """Test collecting disk usage on Windows."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "disk data"}}
        )

        result = await self.collector._collect_disk_usage()

        assert "filesystem_usage" in result
        assert "io_stats" in result
        assert "largest_directories" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_disk_usage_windows_partial_failure(self, mock_platform):
        """Test collecting disk usage on Windows with partial failures."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "filesystem data"}},
                {"success": False, "result": {"stdout": ""}},
                {"success": True, "result": {"stdout": "directory data"}},
            ]
        )

        result = await self.collector._collect_disk_usage()

        assert "filesystem_usage" in result
        # io_stats should not be present or empty
        assert "largest_directories" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_disk_usage_linux_success(self, mock_platform):
        """Test collecting disk usage on Linux."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "disk data"}}
        )

        result = await self.collector._collect_disk_usage()

        assert "filesystem_usage" in result
        assert "io_stats" in result
        assert "largest_directories" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_disk_usage_exception(self, mock_platform):
        """Test collecting disk usage with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_disk_usage()

        assert "error" in result
        assert "Test error" in result["error"]

    # Test _collect_environment_variables method
    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_environment_variables_windows_success(self, mock_platform):
        """Test collecting environment variables on Windows."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "env data"}}
        )

        result = await self.collector._collect_environment_variables()

        assert "safe_env_vars" in result
        assert "python_path" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_collect_environment_variables_windows_python_fail(
        self, mock_platform
    ):
        """Test collecting environment variables on Windows when Python fails."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=[
                {"success": True, "result": {"stdout": "env data"}},
                {"success": False, "result": {"stdout": ""}},
            ]
        )

        result = await self.collector._collect_environment_variables()

        assert "safe_env_vars" in result
        # python_path should not be present or empty

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_environment_variables_linux_success(self, mock_platform):
        """Test collecting environment variables on Linux."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "env data"}}
        )

        result = await self.collector._collect_environment_variables()

        assert "safe_env_vars" in result
        assert "python_path" in result

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_collect_environment_variables_exception(self, mock_platform):
        """Test collecting environment variables with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_environment_variables()

        assert "error" in result
        assert "Test error" in result["error"]

    # Test _collect_agent_logs method
    @pytest.mark.asyncio
    async def test_collect_agent_logs_success(self):
        """Test collecting agent logs successfully."""
        log_content = "\n".join([f"Log line {i}" for i in range(150)])

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open(log_content)):
            result = await self.collector._collect_agent_logs()

            assert "recent_logs" in result
            assert "agent_status" in result
            assert result["agent_status"]["running"] is True
            assert result["agent_status"]["connected"] is True

    @pytest.mark.asyncio
    async def test_collect_agent_logs_file_not_accessible(self):
        """Test collecting agent logs when file is not accessible."""
        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open_error()):
            result = await self.collector._collect_agent_logs()

            assert "recent_logs" in result
            assert "not accessible" in result["recent_logs"]
            assert "agent_status" in result

    @pytest.mark.asyncio
    async def test_collect_agent_logs_with_optional_attributes(self):
        """Test collecting agent logs with optional agent attributes."""
        # Remove optional attributes
        delattr(self.mock_agent, "reconnect_attempts")
        delattr(self.mock_agent, "last_ping")

        log_content = "Log line 1\nLog line 2"

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open(log_content)):
            result = await self.collector._collect_agent_logs()

            assert "agent_status" in result
            assert result["agent_status"]["reconnect_attempts"] == 0
            assert result["agent_status"]["last_ping"] is None

    @pytest.mark.asyncio
    async def test_collect_agent_logs_exception(self):
        """Test collecting agent logs with exception in outer try block."""
        # Patch datetime.now to raise an exception in the outer try block
        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open("test log")):
            with patch(
                "src.sysmanage_agent.diagnostics.diagnostic_collector.datetime"
            ) as mock_datetime:
                mock_datetime.now.side_effect = Exception("Test error")

                result = await self.collector._collect_agent_logs()

                assert "error" in result
                assert "Test error" in result["error"]

    # Test _collect_error_logs method
    @pytest.mark.asyncio
    async def test_collect_error_logs_success(self):
        """Test collecting error logs successfully."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "error data"}}
        )

        log_content = (
            "INFO: line 1\nERROR: error line\nDEBUG: line 2\nERROR: another error"
        )

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open(log_content)):
            result = await self.collector._collect_error_logs()

            assert "system_errors" in result
            assert "kernel_errors" in result
            assert "agent_errors" in result
            # Should only contain ERROR lines
            assert "ERROR" in result["agent_errors"]
            assert "INFO" not in result["agent_errors"]

    @pytest.mark.asyncio
    async def test_collect_error_logs_agent_file_not_accessible(self):
        """Test collecting error logs when agent file is not accessible."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "error data"}}
        )

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open_error()):
            result = await self.collector._collect_error_logs()

            assert "agent_errors" in result
            assert "not accessible" in result["agent_errors"]

    @pytest.mark.asyncio
    async def test_collect_error_logs_system_commands_fail(self):
        """Test collecting error logs when system commands fail."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": False, "result": {"stdout": ""}}
        )

        log_content = "ERROR: test error"

        with patch(_DIAG_AIOFILES_OPEN, return_value=_mock_aiofiles_open(log_content)):
            result = await self.collector._collect_error_logs()

            # Should still have agent_errors
            assert "agent_errors" in result

    @pytest.mark.asyncio
    async def test_collect_error_logs_exception(self):
        """Test collecting error logs with exception."""
        self.collector.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Test error")
        )

        result = await self.collector._collect_error_logs()

        assert "error" in result
        assert "Test error" in result["error"]

    # Integration tests
    @pytest.mark.asyncio
    async def test_full_diagnostic_collection_workflow(self):
        """Test full diagnostic collection workflow."""
        parameters = {
            "collection_id": "full-test-123",
            "collection_types": [
                "system_logs",
                "configuration_files",
                "network_info",
                "process_info",
                "disk_usage",
                "environment_variables",
                "agent_logs",
                "error_logs",
            ],
        }

        # Mock all collection methods
        with patch.object(
            self.collector, "_collect_system_logs", new_callable=AsyncMock
        ) as mock_system_logs:
            with patch.object(
                self.collector, "_collect_configuration_files", new_callable=AsyncMock
            ) as mock_config:
                with patch.object(
                    self.collector, "_collect_network_info", new_callable=AsyncMock
                ) as mock_network:
                    with patch.object(
                        self.collector, "_collect_process_info", new_callable=AsyncMock
                    ) as mock_process:
                        with patch.object(
                            self.collector,
                            "_collect_disk_usage",
                            new_callable=AsyncMock,
                        ) as mock_disk:
                            with patch.object(
                                self.collector,
                                "_collect_environment_variables",
                                new_callable=AsyncMock,
                            ) as mock_env:
                                with patch.object(
                                    self.collector,
                                    "_collect_agent_logs",
                                    new_callable=AsyncMock,
                                ) as mock_agent_logs:
                                    with patch.object(
                                        self.collector,
                                        "_collect_error_logs",
                                        new_callable=AsyncMock,
                                    ) as mock_error_logs:
                                        with patch.object(
                                            self.collector,
                                            "_send_diagnostic_result",
                                            new_callable=AsyncMock,
                                        ):
                                            # Set return values
                                            mock_system_logs.return_value = {
                                                "logs": "data"
                                            }
                                            mock_config.return_value = {
                                                "config": "data"
                                            }
                                            mock_network.return_value = {
                                                "network": "data"
                                            }
                                            mock_process.return_value = {
                                                "process": "data"
                                            }
                                            mock_disk.return_value = {"disk": "data"}
                                            mock_env.return_value = {"env": "data"}
                                            mock_agent_logs.return_value = {
                                                "agent": "data"
                                            }
                                            mock_error_logs.return_value = {
                                                "errors": "data"
                                            }

                                            result = await self.collector.collect_diagnostics(
                                                parameters
                                            )

                                            assert result["success"] is True
                                            # Verify all collection methods were called
                                            mock_system_logs.assert_called_once()
                                            mock_config.assert_called_once()
                                            mock_network.assert_called_once()
                                            mock_process.assert_called_once()
                                            mock_disk.assert_called_once()
                                            mock_env.assert_called_once()
                                            mock_agent_logs.assert_called_once()
                                            mock_error_logs.assert_called_once()

    @pytest.mark.asyncio
    async def test_diagnostic_collection_partial_failures(self):
        """Test diagnostic collection with some types failing."""
        parameters = {
            "collection_id": "partial-test-123",
            "collection_types": ["system_logs", "network_info", "process_info"],
        }

        with patch.object(
            self.collector, "_collect_system_logs", new_callable=AsyncMock
        ) as mock_system_logs:
            with patch.object(
                self.collector, "_collect_network_info", new_callable=AsyncMock
            ) as mock_network:
                with patch.object(
                    self.collector, "_collect_process_info", new_callable=AsyncMock
                ) as mock_process:
                    with patch.object(
                        self.collector,
                        "_send_diagnostic_result",
                        new_callable=AsyncMock,
                    ):
                        # First succeeds, second fails, third succeeds
                        mock_system_logs.return_value = {"logs": "data"}
                        mock_network.side_effect = Exception(
                            "Network collection failed"
                        )
                        mock_process.return_value = {"process": "data"}

                        result = await self.collector.collect_diagnostics(parameters)

                        # Should still succeed overall
                        assert result["success"] is True
                        mock_system_logs.assert_called_once()
                        mock_network.assert_called_once()
                        mock_process.assert_called_once()
