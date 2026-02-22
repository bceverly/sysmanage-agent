"""
Comprehensive unit tests for src.sysmanage_agent.operations.update_manager module.
Tests the UpdateManager class and its methods.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.update_manager import UpdateManager


class TestUpdateManager:
    """Test cases for UpdateManager class."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "test_message"})
        self.mock_agent.send_message = AsyncMock(return_value=True)
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()

    def test_init_creates_update_manager(self):
        """Test UpdateManager initialization creates instance correctly."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            manager = UpdateManager(self.mock_agent)

            assert manager.agent == self.mock_agent
            assert manager.logger is not None
            mock_update_ops.assert_called_once_with(self.mock_agent)

    def test_init_sets_update_ops(self):
        """Test UpdateManager initialization sets update_ops instance."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)

            assert manager.update_ops == mock_ops_instance

    def test_init_sets_logger(self):
        """Test UpdateManager initialization sets logger."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)

            assert manager.logger is not None
            assert hasattr(manager.logger, "info")
            assert hasattr(manager.logger, "error")
            assert hasattr(manager.logger, "debug")


class TestCheckUpdates:
    """Test cases for UpdateManager.check_updates method."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "test_message"})
        self.mock_agent.send_message = AsyncMock(return_value=True)

    @pytest.mark.asyncio
    async def test_check_updates_delegates_to_update_ops(self):
        """Test check_updates delegates to update_ops.check_updates."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.check_updates = AsyncMock(
                return_value={"success": True, "total_updates": 5}
            )
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            result = await manager.check_updates()

            mock_ops_instance.check_updates.assert_called_once()
            assert result["success"] is True
            assert result["total_updates"] == 5

    @pytest.mark.asyncio
    async def test_check_updates_returns_update_ops_result(self):
        """Test check_updates returns the result from update_ops."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            expected_result = {
                "success": True,
                "total_updates": 3,
                "result": "Update check completed",
                "available_updates": ["pkg1", "pkg2", "pkg3"],
            }
            mock_ops_instance = Mock()
            mock_ops_instance.check_updates = AsyncMock(return_value=expected_result)
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            result = await manager.check_updates()

            assert result == expected_result

    @pytest.mark.asyncio
    async def test_check_updates_handles_update_ops_failure(self):
        """Test check_updates handles failure from update_ops."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.check_updates = AsyncMock(
                return_value={"success": False, "error": "Failed to detect updates"}
            )
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            result = await manager.check_updates()

            assert result["success"] is False
            assert "error" in result


class TestApplyUpdates:
    """Test cases for UpdateManager.apply_updates method."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "test_message"})
        self.mock_agent.send_message = AsyncMock(return_value=True)

    @pytest.mark.asyncio
    async def test_apply_updates_delegates_to_update_ops(self):
        """Test apply_updates delegates to update_ops.apply_updates."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.apply_updates = AsyncMock(
                return_value={
                    "success": True,
                    "result": "Updates started in background",
                }
            )
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            parameters = {"package_names": ["pkg1", "pkg2"]}
            result = await manager.apply_updates(parameters)

            mock_ops_instance.apply_updates.assert_called_once_with(parameters)
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_updates_passes_parameters_correctly(self):
        """Test apply_updates passes parameters to update_ops."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.apply_updates = AsyncMock(return_value={"success": True})
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            parameters = {
                "package_names": ["nginx", "apache2"],
                "package_managers": ["apt", "apt"],
            }
            await manager.apply_updates(parameters)

            mock_ops_instance.apply_updates.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_apply_updates_with_new_format_packages(self):
        """Test apply_updates with new format packages array."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.apply_updates = AsyncMock(
                return_value={
                    "success": True,
                    "packages": ["nginx", "apache2"],
                }
            )
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            parameters = {
                "packages": [
                    {"package_name": "nginx", "package_manager": "apt"},
                    {"package_name": "apache2", "package_manager": "apt"},
                ]
            }
            result = await manager.apply_updates(parameters)

            mock_ops_instance.apply_updates.assert_called_once_with(parameters)
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apply_updates_handles_no_packages_error(self):
        """Test apply_updates handles no packages specified error."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.apply_updates = AsyncMock(
                return_value={
                    "success": False,
                    "error": "No packages specified for update",
                }
            )
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)
            parameters = {"package_names": []}
            result = await manager.apply_updates(parameters)

            assert result["success"] is False
            assert "error" in result


class TestCheckRebootStatus:
    """Test cases for UpdateManager.check_reboot_status method."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "reboot_status"})
        self.mock_agent.send_message = AsyncMock(return_value=True)

    @pytest.mark.asyncio
    async def test_check_reboot_status_success_reboot_required(self):
        """Test check_reboot_status when reboot is required."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector_instance = Mock()
                mock_detector_instance.check_reboot_required.return_value = True
                mock_detector.return_value = mock_detector_instance

                manager = UpdateManager(self.mock_agent)
                result = await manager.check_reboot_status()

                assert result["success"] is True
                assert result["reboot_required"] is True
                assert "timestamp" in result
                mock_detector_instance.check_reboot_required.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_reboot_status_success_no_reboot_required(self):
        """Test check_reboot_status when no reboot is required."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector_instance = Mock()
                mock_detector_instance.check_reboot_required.return_value = False
                mock_detector.return_value = mock_detector_instance

                manager = UpdateManager(self.mock_agent)
                result = await manager.check_reboot_status()

                assert result["success"] is True
                assert result["reboot_required"] is False
                assert "timestamp" in result

    @pytest.mark.asyncio
    async def test_check_reboot_status_timestamp_is_utc_iso_format(self):
        """Test check_reboot_status returns timestamp in UTC ISO format."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector_instance = Mock()
                mock_detector_instance.check_reboot_required.return_value = False
                mock_detector.return_value = mock_detector_instance

                manager = UpdateManager(self.mock_agent)
                result = await manager.check_reboot_status()

                # Verify timestamp is parseable as ISO format
                timestamp = result["timestamp"]
                parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                assert parsed_time.tzinfo is not None

    @pytest.mark.asyncio
    async def test_check_reboot_status_calls_send_reboot_status_update(self):
        """Test check_reboot_status calls send_reboot_status_update."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector_instance = Mock()
                mock_detector_instance.check_reboot_required.return_value = True
                mock_detector.return_value = mock_detector_instance

                manager = UpdateManager(self.mock_agent)
                manager.send_reboot_status_update = AsyncMock()

                await manager.check_reboot_status()

                manager.send_reboot_status_update.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_check_reboot_status_exception_handling(self):
        """Test check_reboot_status handles exceptions properly."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector.side_effect = Exception("Detector initialization failed")

                manager = UpdateManager(self.mock_agent)
                result = await manager.check_reboot_status()

                assert result["success"] is False
                assert "error" in result
                assert "Detector initialization failed" in result["error"]
                assert result["reboot_required"] is False

    @pytest.mark.asyncio
    async def test_check_reboot_status_detector_check_exception(self):
        """Test check_reboot_status handles detector.check_reboot_required exception."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector_instance = Mock()
                mock_detector_instance.check_reboot_required.side_effect = Exception(
                    "Permission denied checking reboot status"
                )
                mock_detector.return_value = mock_detector_instance

                manager = UpdateManager(self.mock_agent)
                result = await manager.check_reboot_status()

                assert result["success"] is False
                assert "error" in result
                assert "Permission denied" in result["error"]
                assert result["reboot_required"] is False


class TestSendRebootStatusUpdate:
    """Test cases for UpdateManager.send_reboot_status_update method."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(
            return_value={"type": "reboot_status_update"}
        )
        self.mock_agent.send_message = AsyncMock(return_value=True)

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_success_reboot_required(self):
        """Test send_reboot_status_update when reboot is required."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(True)

            self.mock_agent.create_message.assert_called_once()
            call_args = self.mock_agent.create_message.call_args
            assert call_args[0][0] == "reboot_status_update"
            message_data = call_args[0][1]
            assert message_data["hostname"] == "test-host"
            assert message_data["reboot_required"] is True
            assert "timestamp" in message_data

            self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_success_no_reboot(self):
        """Test send_reboot_status_update when reboot is not required."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(False)

            call_args = self.mock_agent.create_message.call_args
            message_data = call_args[0][1]
            assert message_data["reboot_required"] is False

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_gets_hostname(self):
        """Test send_reboot_status_update retrieves hostname from system info."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            self.mock_agent.registration.get_system_info.return_value = {
                "hostname": "production-server-01"
            }

            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(True)

            self.mock_agent.registration.get_system_info.assert_called_once()
            call_args = self.mock_agent.create_message.call_args
            message_data = call_args[0][1]
            assert message_data["hostname"] == "production-server-01"

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_hostname_fallback_unknown(self):
        """Test send_reboot_status_update uses 'unknown' when hostname not found."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            self.mock_agent.registration.get_system_info.return_value = {}

            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(True)

            call_args = self.mock_agent.create_message.call_args
            message_data = call_args[0][1]
            assert message_data["hostname"] == "unknown"

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_includes_timestamp(self):
        """Test send_reboot_status_update includes UTC timestamp."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(True)

            call_args = self.mock_agent.create_message.call_args
            message_data = call_args[0][1]
            assert "timestamp" in message_data

            # Verify timestamp is valid ISO format
            timestamp = message_data["timestamp"]
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            assert parsed_time.tzinfo is not None

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_creates_correct_message_type(self):
        """Test send_reboot_status_update creates message with correct type."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(False)

            self.mock_agent.create_message.assert_called_once()
            call_args = self.mock_agent.create_message.call_args
            assert call_args[0][0] == "reboot_status_update"

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_sends_message(self):
        """Test send_reboot_status_update sends message via agent."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            expected_message = {"type": "reboot_status_update", "data": {}}
            self.mock_agent.create_message.return_value = expected_message

            manager = UpdateManager(self.mock_agent)
            await manager.send_reboot_status_update(True)

            self.mock_agent.send_message.assert_called_once_with(expected_message)

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_exception_in_get_system_info(self):
        """Test send_reboot_status_update handles exception in get_system_info."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            self.mock_agent.registration.get_system_info.side_effect = Exception(
                "System info unavailable"
            )

            manager = UpdateManager(self.mock_agent)
            # Should not raise exception, just log it
            await manager.send_reboot_status_update(True)

            # Verify exception was handled gracefully
            self.mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_exception_in_create_message(self):
        """Test send_reboot_status_update handles exception in create_message."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            self.mock_agent.create_message.side_effect = Exception(
                "Message creation failed"
            )

            manager = UpdateManager(self.mock_agent)
            # Should not raise exception, just log it
            await manager.send_reboot_status_update(True)

            # Verify exception was handled gracefully
            self.mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_exception_in_send_message(self):
        """Test send_reboot_status_update handles exception in send_message."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            self.mock_agent.send_message = AsyncMock(
                side_effect=Exception("Network error")
            )

            manager = UpdateManager(self.mock_agent)
            # Should not raise exception, just log it
            await manager.send_reboot_status_update(True)

            # Verify send_message was attempted
            self.mock_agent.send_message.assert_called_once()


class TestUpdateManagerIntegration:
    """Integration-style tests for UpdateManager class."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "integration-test-host"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.mock_agent.send_message = AsyncMock(return_value=True)
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()

    @pytest.mark.asyncio
    async def test_check_reboot_status_full_flow(self):
        """Test full flow of check_reboot_status method."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector_instance = Mock()
                mock_detector_instance.check_reboot_required.return_value = True
                mock_detector.return_value = mock_detector_instance

                manager = UpdateManager(self.mock_agent)
                result = await manager.check_reboot_status()

                # Verify detector was created and called
                mock_detector.assert_called_once()
                mock_detector_instance.check_reboot_required.assert_called_once()

                # Verify result structure
                assert result["success"] is True
                assert result["reboot_required"] is True
                assert "timestamp" in result

                # Verify message was created and sent
                self.mock_agent.create_message.assert_called_once()
                self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_manager_methods_use_same_update_ops_instance(self):
        """Test that manager methods use the same update_ops instance."""
        with patch(
            "src.sysmanage_agent.operations.update_manager.UpdateOperations"
        ) as mock_update_ops:
            mock_ops_instance = Mock()
            mock_ops_instance.check_updates = AsyncMock(return_value={"success": True})
            mock_ops_instance.apply_updates = AsyncMock(return_value={"success": True})
            mock_update_ops.return_value = mock_ops_instance

            manager = UpdateManager(self.mock_agent)

            # Call both methods
            await manager.check_updates()
            await manager.apply_updates({"package_names": ["test"]})

            # Verify same instance was used
            assert mock_update_ops.call_count == 1
            mock_ops_instance.check_updates.assert_called_once()
            mock_ops_instance.apply_updates.assert_called_once()


class TestUpdateManagerLogging:
    """Test cases for UpdateManager logging behavior."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.mock_agent.send_message = AsyncMock(return_value=True)

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_logs_info(self):
        """Test send_reboot_status_update logs info message."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)
            manager.logger = Mock()

            await manager.send_reboot_status_update(True)

            # Verify info was logged
            manager.logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_logs_debug_on_success(self):
        """Test send_reboot_status_update logs debug message on success."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            manager = UpdateManager(self.mock_agent)
            manager.logger = Mock()

            await manager.send_reboot_status_update(False)

            # Verify debug was logged
            manager.logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_logs_error_on_exception(self):
        """Test send_reboot_status_update logs error on exception."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            self.mock_agent.registration.get_system_info.side_effect = Exception(
                "Test error"
            )

            manager = UpdateManager(self.mock_agent)
            manager.logger = Mock()

            await manager.send_reboot_status_update(True)

            # Verify error was logged
            manager.logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_check_reboot_status_logs_error_on_exception(self):
        """Test check_reboot_status logs error on exception."""
        with patch("src.sysmanage_agent.operations.update_manager.UpdateOperations"):
            with patch(
                "src.sysmanage_agent.operations.update_manager.UpdateDetector"
            ) as mock_detector:
                mock_detector.side_effect = Exception("Detector error")

                manager = UpdateManager(self.mock_agent)
                manager.logger = Mock()

                await manager.check_reboot_status()

                # Verify error was logged
                manager.logger.error.assert_called()
