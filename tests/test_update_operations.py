# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive tests for update_operations module.
Tests the UpdateOperations class and its methods.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.update_operations import UpdateOperations


class TestUpdateOperations:  # pylint: disable=protected-access
    """Test the UpdateOperations class."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_agent = Mock()  # pylint: disable=attribute-defined-outside-init
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info.return_value = {
            "hostname": "test-host"
        }
        self.mock_agent.create_message = Mock(return_value="test-message")
        self.mock_agent.send_message = AsyncMock(return_value=True)
        self.mock_agent.connected = True
        self.mock_agent.websocket = AsyncMock()

        # pylint: disable=attribute-defined-outside-init
        self.update_ops = UpdateOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_check_updates_success(self):
        """Test successful update check operation."""
        mock_update_info = {
            "total_updates": 5,
            "available_updates": ["package1", "package2"],
        }

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.get_available_updates.return_value = mock_update_info
            mock_detector.return_value = mock_detector_instance

            result = await self.update_ops.check_updates()

            assert result["success"] is True
            assert result["result"] == "Update check completed"
            assert result["total_updates"] == 5

            # Verify update detector was called
            mock_detector.assert_called_once()
            mock_detector_instance.get_available_updates.assert_called_once()

            # Verify message was created and sent
            self.mock_agent.create_message.assert_called_once()
            self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_updates_exception(self):
        """Test update check with exception handling."""
        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector.side_effect = Exception("Test error")

            result = await self.update_ops.check_updates()

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_updates_success(self):
        """Test successful update application initiation."""
        parameters = {
            "package_names": ["package1", "package2"],
            "package_managers": ["apt", "yum"],
        }

        with patch.object(self.update_ops, "_apply_updates_background"):
            result = await self.update_ops.apply_updates(parameters)

            assert result["success"] is True
            assert "Updates started in background" in result["result"]
            assert result["packages"] == ["package1", "package2"]

    @pytest.mark.asyncio
    async def test_apply_updates_no_packages(self):
        """Test update application with no packages specified."""
        parameters = {"package_names": []}

        result = await self.update_ops.apply_updates(parameters)

        assert result["success"] is False
        assert "No packages specified" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_updates_exception(self):
        """Test update application with exception."""
        parameters = {"package_names": ["package1"]}

        with patch("asyncio.create_task", side_effect=Exception("Test error")):
            result = await self.update_ops.apply_updates(parameters)

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_apply_updates_background_with_list_managers(self):
        """Test background update process with list-based package managers."""
        package_names = ["package1", "package2"]
        package_managers = ["apt", "yum"]

        mock_update_results = {"success": True, "results": ["updated1", "updated2"]}
        mock_fresh_updates = {"total_updates": 0, "available_updates": []}

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.apply_updates.return_value = mock_update_results
            mock_detector_instance.get_available_updates.return_value = (
                mock_fresh_updates
            )
            mock_detector.return_value = mock_detector_instance

            with patch("asyncio.get_event_loop") as mock_loop:
                # First call returns update results, second call returns fresh updates
                mock_loop.return_value.run_in_executor = AsyncMock(
                    side_effect=[mock_update_results, mock_fresh_updates]
                )

                await self.update_ops._apply_updates_background(
                    package_names, package_managers
                )

                # Verify the executor was called twice (once for updates, once for rescan)
                assert mock_loop.return_value.run_in_executor.call_count == 2

    @pytest.mark.asyncio
    async def test_apply_updates_background_with_dict_managers(self):
        """Test background update process with dict-based package managers."""
        package_names = ["package1", "package2"]
        package_managers = {"package1": "apt", "package2": "yum"}

        mock_update_results = {"success": True, "results": ["updated1", "updated2"]}
        mock_fresh_updates = {"total_updates": 0, "available_updates": []}

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.apply_updates.return_value = mock_update_results
            mock_detector_instance.get_available_updates.return_value = (
                mock_fresh_updates
            )
            mock_detector.return_value = mock_detector_instance

            with patch("asyncio.get_event_loop") as mock_loop:
                # First call returns update results, second call returns fresh updates
                mock_loop.return_value.run_in_executor = AsyncMock(
                    side_effect=[mock_update_results, mock_fresh_updates]
                )

                await self.update_ops._apply_updates_background(
                    package_names, package_managers
                )

                # Verify the executor was called twice (once for updates, once for rescan)
                assert mock_loop.return_value.run_in_executor.call_count == 2

    @pytest.mark.asyncio
    async def test_apply_updates_background_with_detection_fallback(self):
        """Test background update process with package manager detection fallback."""
        package_names = ["package1"]
        package_managers = None

        mock_update_results = {"success": True, "results": ["updated1"]}

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.apply_updates.return_value = mock_update_results
            mock_detector_instance._detect_package_managers.return_value = ["apt"]
            mock_detector.return_value = mock_detector_instance

            with patch("concurrent.futures.ThreadPoolExecutor"):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.run_in_executor = AsyncMock(
                        return_value=mock_update_results
                    )

                    await self.update_ops._apply_updates_background(
                        package_names, package_managers
                    )

                    # Verify detection was called
                    mock_detector_instance._detect_package_managers.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_updates_background_no_package_manager_detected(self):
        """Test background update process when no package manager is detected."""
        package_names = ["package1"]
        package_managers = None

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance._detect_package_managers.return_value = []
            mock_detector.return_value = mock_detector_instance

            await self.update_ops._apply_updates_background(
                package_names, package_managers
            )

            # Verify detection was called but no updates were applied
            mock_detector_instance._detect_package_managers.assert_called_once()
            mock_detector_instance.apply_updates.assert_not_called()

    @pytest.mark.asyncio
    async def test_apply_updates_background_no_valid_packages(self):
        """Test background update process when no valid packages are found."""
        package_names = ["package1", "package2"]
        package_managers = []  # Empty list, no managers - this will cause early return

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance._detect_package_managers.return_value = []
            mock_detector.return_value = mock_detector_instance

            await self.update_ops._apply_updates_background(
                package_names, package_managers
            )

            # Since empty package_managers list, should exit early with no valid packages found
            # The _detect_package_managers won't be called because we don't reach that logic path

    @pytest.mark.asyncio
    async def test_apply_updates_background_send_retry_logic(self):
        """Test background update process with message send retry logic."""
        package_names = ["package1"]
        package_managers = ["apt"]
        mock_update_results = {"success": True}
        mock_fresh_updates = {"total_updates": 0, "available_updates": []}

        # First attempt fails, second succeeds, third (fresh scan) succeeds
        self.mock_agent.send_message = AsyncMock(side_effect=[False, True, True])

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.apply_updates.return_value = mock_update_results
            mock_detector_instance.get_available_updates.return_value = (
                mock_fresh_updates
            )
            mock_detector.return_value = mock_detector_instance

            with patch("concurrent.futures.ThreadPoolExecutor"):
                with patch("asyncio.get_event_loop") as mock_loop:
                    # First call returns update results, second call returns fresh updates
                    mock_loop.return_value.run_in_executor = AsyncMock(
                        side_effect=[mock_update_results, mock_fresh_updates]
                    )

                    with patch("asyncio.sleep") as mock_sleep:
                        await self.update_ops._apply_updates_background(
                            package_names, package_managers
                        )

                        # Should have called send_message three times:
                        # 1. Update results (failed)
                        # 2. Update results retry (succeeded)
                        # 3. Fresh update scan (after successful send)
                        assert self.mock_agent.send_message.call_count == 3
                        mock_sleep.assert_called_once_with(10)

    @pytest.mark.asyncio
    async def test_apply_updates_background_disconnect_retry_logic(self):
        """Test background update process when agent is disconnected."""
        package_names = ["package1"]
        package_managers = ["apt"]
        mock_update_results = {"success": True}
        mock_fresh_updates = {"total_updates": 0, "available_updates": []}

        # Agent is initially disconnected, then connects
        self.mock_agent.connected = False
        self.mock_agent.websocket = None

        # Use a simple side effect that sets connection status
        def simulate_reconnection(*_args):
            self.mock_agent.connected = True
            self.mock_agent.websocket = Mock()

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.apply_updates.return_value = mock_update_results
            mock_detector_instance.get_available_updates.return_value = (
                mock_fresh_updates
            )
            mock_detector.return_value = mock_detector_instance

            with patch("asyncio.get_event_loop") as mock_loop:
                # First call returns update results, second call returns fresh updates
                mock_loop.return_value.run_in_executor = AsyncMock(
                    side_effect=[mock_update_results, mock_fresh_updates]
                )

                with patch(
                    "asyncio.sleep", side_effect=simulate_reconnection
                ) as mock_sleep:
                    await self.update_ops._apply_updates_background(
                        package_names, package_managers
                    )

                    # Should have called sleep for retry
                    mock_sleep.assert_called_with(10)
                    # Should send message twice after reconnection:
                    # 1. Update results
                    # 2. Fresh update scan
                    assert self.mock_agent.send_message.call_count == 2

    @pytest.mark.asyncio
    async def test_apply_updates_background_max_retries_exceeded(self):
        """Test background update process when max retries are exceeded."""
        package_names = ["package1"]
        package_managers = ["apt"]
        mock_update_results = {"success": True}

        # Agent remains disconnected
        self.mock_agent.connected = False
        self.mock_agent.websocket = None

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector_instance = Mock()
            mock_detector_instance.apply_updates.return_value = mock_update_results
            mock_detector.return_value = mock_detector_instance

            with patch("concurrent.futures.ThreadPoolExecutor"):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.run_in_executor = AsyncMock(
                        return_value=mock_update_results
                    )

                    with patch("asyncio.sleep") as mock_sleep:
                        # Reduce max_retries for faster test
                        with patch.object(self.update_ops, "_apply_updates_background"):
                            # Call the real method but with mocked internals
                            original_method = UpdateOperations._apply_updates_background
                            await original_method(
                                self.update_ops, package_names, package_managers
                            )

                        # Should eventually give up after retries
                        # Sleep should be called multiple times
                        assert mock_sleep.call_count > 0

    @pytest.mark.asyncio
    async def test_apply_updates_background_exception(self):
        """Test background update process with exception handling."""
        package_names = ["package1"]
        package_managers = ["apt"]

        with patch(
            "src.sysmanage_agent.operations.update_operations.UpdateDetector"
        ) as mock_detector:
            mock_detector.side_effect = Exception("Background test error")

            await self.update_ops._apply_updates_background(
                package_names, package_managers
            )

            # Should handle exception gracefully without crashing
            mock_detector.assert_called_once()


DBX_ID = "362301da643102b9f38477387e2193e57abaa590"
DBX = {
    "package_name": "Microsoft UEFI dbx (→ 20260707)",
    "bundle_id": DBX_ID,
    "device_id": DBX_ID,
    "package_manager": "fwupd",
}


class TestFirmwareNamesAreCheckedByDevice:  # pylint: disable=protected-access
    """fwupd installs by device id; its "name" is a display label.  Checking
    the label refused every firmware update and the request sat at "Update
    Requested" with no answer (beast, 2026-10-19)."""

    def setup_method(self):
        agent = Mock()
        agent.registration.get_system_info.return_value = {"hostname": "beast"}
        agent.create_message = Mock(side_effect=lambda kind, data: (kind, data))
        self.ops = UpdateOperations(
            agent
        )  # pylint: disable=attribute-defined-outside-init

    def test_a_firmware_label_passes_when_its_device_id_is_safe(self):
        packages = self.ops._validate_packages_from_list([DBX])
        assert packages[0]["device_id"] == DBX_ID  # carried to the applicator
        kept, refused = self.ops._drop_unsafe_names(packages)
        assert [p["name"] for p in kept] == [DBX["package_name"]] and not refused

    def test_a_hostile_device_id_is_still_refused(self):
        hostile = dict(DBX, bundle_id="--force", device_id="--force")
        packages = self.ops._validate_packages_from_list([hostile])
        kept, refused = self.ops._drop_unsafe_names(packages)
        assert not kept and refused[0]["package_manager"] == "fwupd"

    def test_a_non_firmware_name_is_still_checked_by_name(self):
        packages = [{"name": "-o APT::evil", "package_manager": "apt"}]
        kept, refused = self.ops._drop_unsafe_names(packages)
        assert not kept and refused[0]["package_name"] == "-o APT::evil"

    @pytest.mark.asyncio
    async def test_a_refused_batch_still_answers_the_server(self):
        """Nothing runnable is not silence: the refusal goes back as a failure,
        or the server shows "Update Requested" forever."""
        self.ops._send_update_results_with_retry = AsyncMock(return_value=True)
        self.ops._rescan_and_send_updates = AsyncMock()
        with patch("src.sysmanage_agent.operations.update_operations.UpdateDetector"):
            await self.ops._apply_updates_background(
                [],
                None,
                packages_list=[{"package_name": "-x", "package_manager": "apt"}],
            )
        (message,), _ = self.ops._send_update_results_with_retry.call_args
        kind, results = message
        assert kind == "update_apply_result"
        assert results["failed_packages"][0]["package_name"] == "-x"
