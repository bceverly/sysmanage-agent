# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for src.sysmanage_agent.operations.package_operations module.
Comprehensive tests for package installation, uninstallation, and batch operations.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,import-outside-toplevel

from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.package_operations import PackageOperations


class TestPackageOperations:
    """Test cases for PackageOperations class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.hostname = "test-host"
        self.mock_agent.platform = "Linux"
        self.mock_agent.ipv4 = "192.168.1.100"
        self.mock_agent.ipv6 = "::1"

        # Mock the registration.get_system_info() method
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info = Mock(
            return_value={
                "hostname": "test-host",
                "fqdn": "test-host.example.com",
            }
        )

        # Mock get_host_approval_from_db
        mock_host_approval = Mock()
        mock_host_approval.host_id = 12345
        self.mock_agent.get_host_approval_from_db = Mock(
            return_value=mock_host_approval
        )

        # Mock send_message — the agent's outbound queue path.  Both
        # _send_installation_completion and _send_installation_status_update
        # go through this; tests assert send_message rather than the
        # removed call_server_api HTTP helper.
        self.mock_agent.send_message = AsyncMock(return_value=True)

        self.package_ops = PackageOperations(self.mock_agent)

    def test_init(self):
        """Test PackageOperations initialization."""
        assert self.package_ops.agent_instance == self.mock_agent
        assert self.package_ops.logger is not None

    # ========================================================================
    # Tests for install_package method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_install_package_success_dict_result(self):
        """Test successful package installation with dict result."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {
                "success": True,
                "version": "1.2.3",
                "output": "Package installed successfully",
            }
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "vim",
                "package_manager": "apt",
                "installation_id": "test-uuid-123",
                "requested_by": "test-user",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is True
            assert result["package_name"] == "vim"
            assert result["installation_id"] == "test-uuid-123"
            assert result["installed_version"] == "1.2.3"
            assert result["error"] is None

            # Verify status update messages were sent
            assert self.mock_agent.send_message.call_count == 2
            calls = self.mock_agent.send_message.call_args_list
            assert calls[0][0][0]["status"] == "installing"
            assert calls[1][0][0]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_install_package_success_string_result(self):
        """Test successful package installation with string result."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = (
                "Package installed successfully"
            )
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "curl",
                "package_manager": "apt",
                "installation_id": "test-uuid-456",
                "requested_by": "admin",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is True
            assert result["package_name"] == "curl"
            assert result["installed_version"] is None

    @pytest.mark.asyncio
    async def test_install_package_failure_dict_result(self):
        """Test failed package installation with dict result."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {
                "success": False,
                "error": "Package not found in repository",
            }
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "nonexistent",
                "package_manager": "apt",
                "installation_id": "test-uuid-789",
                "requested_by": "user",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is False
            assert result["error"] == "Package not found in repository"
            assert self.mock_agent.send_message.call_count == 2
            calls = self.mock_agent.send_message.call_args_list
            assert calls[1][0][0]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_install_package_failure_string_result_with_error(self):
        """Test package installation failure detected from string with 'error'."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = (
                "Error: Package installation failed"
            )
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "badpkg",
                "installation_id": "test-error-123",
                "requested_by": "user",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is False
            assert result["error"] == "Error: Package installation failed"

    @pytest.mark.asyncio
    async def test_install_package_failure_string_result_with_failed(self):
        """Test package installation failure detected from string with 'failed'."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = "Failed to download package"
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "pkg",
                "installation_id": "test-failed-456",
                "requested_by": "user",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is False
            assert result["error"] == "Failed to download package"

    @pytest.mark.asyncio
    async def test_install_package_no_package_name(self):
        """Test package installation without package name."""
        parameters = {
            "package_manager": "apt",
            "installation_id": "test-uuid-no-name",
            "requested_by": "user",
        }

        result = await self.package_ops.install_package(parameters)

        assert result["success"] is False
        assert "No package name specified" in result["error"]
        assert self.mock_agent.send_message.call_count == 0

    @pytest.mark.asyncio
    async def test_install_package_exception(self):
        """Test package installation with exception."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.side_effect = Exception("Installation error")
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "pkg",
                "installation_id": "test-exception",
                "requested_by": "user",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is False
            assert "Installation error" in result["error"]
            assert self.mock_agent.send_message.call_count == 2
            calls = self.mock_agent.send_message.call_args_list
            assert calls[1][0][0]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_install_package_without_installation_id(self):
        """Test package installation without installation_id."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {"success": True}
            mock_detector_class.return_value = mock_detector

            parameters = {
                "package_name": "git",
                "package_manager": "apt",
                "requested_by": "user",
            }

            result = await self.package_ops.install_package(parameters)

            assert result["success"] is True
            # No status updates should be sent without installation_id
            assert self.mock_agent.send_message.call_count == 0

    # ========================================================================
    # Tests for install_packages method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_install_packages_success_apt(self):
        """Test successful installation of multiple apt packages."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.package_installation_helpers"
        ) as mock_helpers:
            # Mock helper functions
            mock_helpers.create_installation_tracking_record.return_value = (True, None)
            mock_helpers.validate_packages.return_value = (
                [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "curl", "package_manager": "apt"},
                ],
                [],
            )
            mock_helpers.group_packages_by_manager.return_value = {
                "apt": [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "curl", "package_manager": "apt"},
                ]
            }
            # install_apt_packages is async, return AsyncMock
            mock_helpers.install_apt_packages = AsyncMock(
                return_value=(
                    [
                        {"package_name": "vim", "installed_version": "8.2"},
                        {"package_name": "curl", "installed_version": "7.68"},
                    ],
                    [],
                    ["✓ vim installed successfully", "✓ curl installed successfully"],
                )
            )
            mock_helpers.update_installation_tracking_record.return_value = None

            parameters = {
                "request_id": "req-123",
                "packages": [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "curl", "package_manager": "apt"},
                ],
                "requested_by": "admin",
            }

            result = await self.package_ops.install_packages(parameters)

            assert result["success"] is True
            assert result["request_id"] == "req-123"
            assert len(result["successful_packages"]) == 2
            assert len(result["failed_packages"]) == 0
            # Completion notification flows through send_message → outbound queue
            self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_install_packages_success_non_apt(self):
        """Test successful installation of non-apt packages."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.package_installation_helpers"
        ) as mock_helpers:
            mock_helpers.create_installation_tracking_record.return_value = (True, None)
            mock_helpers.validate_packages.return_value = (
                [{"package_name": "htop", "package_manager": "dnf"}],
                [],
            )
            mock_helpers.group_packages_by_manager.return_value = {
                "dnf": [{"package_name": "htop", "package_manager": "dnf"}]
            }
            mock_helpers.install_non_apt_packages.return_value = (
                [{"package_name": "htop", "installed_version": "3.0"}],
                [],
                ["✓ htop installed successfully"],
            )
            mock_helpers.update_installation_tracking_record.return_value = None

            parameters = {
                "request_id": "req-456",
                "packages": [{"package_name": "htop", "package_manager": "dnf"}],
                "requested_by": "user",
            }

            result = await self.package_ops.install_packages(parameters)

            assert result["success"] is True
            assert len(result["successful_packages"]) == 1

    @pytest.mark.asyncio
    async def test_install_packages_mixed_success_failure(self):
        """Test package installation with mixed success and failure."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.package_installation_helpers"
        ) as mock_helpers:
            mock_helpers.create_installation_tracking_record.return_value = (True, None)
            mock_helpers.validate_packages.return_value = (
                [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "badpkg", "package_manager": "apt"},
                ],
                [],
            )
            mock_helpers.group_packages_by_manager.return_value = {
                "apt": [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "badpkg", "package_manager": "apt"},
                ]
            }
            mock_helpers.install_apt_packages = AsyncMock(
                return_value=(
                    [{"package_name": "vim", "installed_version": "8.2"}],
                    [{"package_name": "badpkg", "error": "Not found"}],
                    ["✓ vim installed successfully", "✗ badpkg failed: Not found"],
                )
            )
            mock_helpers.update_installation_tracking_record.return_value = None

            parameters = {
                "request_id": "req-789",
                "packages": [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "badpkg", "package_manager": "apt"},
                ],
                "requested_by": "user",
            }

            result = await self.package_ops.install_packages(parameters)

            assert result["success"] is False
            assert len(result["successful_packages"]) == 1
            assert len(result["failed_packages"]) == 1

    @pytest.mark.asyncio
    async def test_install_packages_no_request_id(self):
        """Test package installation without request_id."""
        parameters = {
            "packages": [{"package_name": "vim", "package_manager": "apt"}],
            "requested_by": "user",
        }

        result = await self.package_ops.install_packages(parameters)

        assert result["success"] is False
        assert "No request_id specified" in result["error"]

    @pytest.mark.asyncio
    async def test_install_packages_no_packages(self):
        """Test package installation without packages."""
        parameters = {
            "request_id": "req-empty",
            "packages": [],
            "requested_by": "user",
        }

        result = await self.package_ops.install_packages(parameters)

        assert result["success"] is False
        assert "No packages specified for installation" in result["error"]

    @pytest.mark.asyncio
    async def test_install_packages_tracking_record_creation_fails(self):
        """Test package installation when tracking record creation fails."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.package_installation_helpers"
        ) as mock_helpers:
            mock_helpers.create_installation_tracking_record.return_value = (
                False,
                "Database error",
            )

            parameters = {
                "request_id": "req-fail",
                "packages": [{"package_name": "vim", "package_manager": "apt"}],
                "requested_by": "user",
            }

            result = await self.package_ops.install_packages(parameters)

            assert result["success"] is False
            assert result["error"] == "Database error"

    @pytest.mark.asyncio
    async def test_install_packages_no_valid_packages(self):
        """Test package installation when no valid packages after validation."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.package_installation_helpers"
        ) as mock_helpers:
            mock_helpers.create_installation_tracking_record.return_value = (True, None)
            mock_helpers.validate_packages.return_value = (
                [],
                [{"package": {}, "error": "No package name"}],
            )

            parameters = {
                "request_id": "req-novalid",
                "packages": [{"package_manager": "apt"}],
                "requested_by": "user",
            }

            result = await self.package_ops.install_packages(parameters)

            assert result["success"] is True
            assert "No packages to install" in result["message"]
            assert len(result["success_packages"]) == 0

    @pytest.mark.asyncio
    async def test_install_packages_server_notification_fails(self):
        """Test package installation when server notification fails."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.package_installation_helpers"
        ) as mock_helpers:
            mock_helpers.create_installation_tracking_record.return_value = (True, None)
            mock_helpers.validate_packages.return_value = (
                [{"package_name": "vim", "package_manager": "apt"}],
                [],
            )
            mock_helpers.group_packages_by_manager.return_value = {
                "apt": [{"package_name": "vim", "package_manager": "apt"}]
            }
            mock_helpers.install_apt_packages = AsyncMock(
                return_value=(
                    [{"package_name": "vim", "installed_version": "8.2"}],
                    [],
                    ["✓ vim installed successfully"],
                )
            )
            mock_helpers.update_installation_tracking_record.return_value = None

            # Make queueing fail
            self.mock_agent.send_message.side_effect = Exception("Queue error")

            parameters = {
                "request_id": "req-notif-fail",
                "packages": [{"package_name": "vim", "package_manager": "apt"}],
                "requested_by": "user",
            }

            result = await self.package_ops.install_packages(parameters)

            # Should still return success for the installation itself
            assert result["success"] is True

    # ========================================================================
    # Tests for uninstall_packages method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_uninstall_packages_success_apt(self):
        """Test successful uninstallation of apt packages."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            # Mock database operations
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )

            # Mock _uninstall_packages_with_apt
            self.package_ops._uninstall_packages_with_apt = AsyncMock(
                return_value={"success": True, "output": "Packages removed"}
            )

            parameters = {
                "request_id": "uninstall-123",
                "packages": [
                    {"package_name": "vim", "package_manager": "apt"},
                    {"package_name": "curl", "package_manager": "apt"},
                ],
                "requested_by": "admin",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            assert result["success"] is True
            assert result["request_id"] == "uninstall-123"
            assert len(result["successful_packages"]) == 2
            assert len(result["failed_packages"]) == 0
            # Completion notification flows through send_message → outbound queue
            self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_uninstall_packages_failure_apt(self):
        """Test failed uninstallation of apt packages."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )

            self.package_ops._uninstall_packages_with_apt = AsyncMock(
                return_value={
                    "success": False,
                    "error": "Package not installed",
                }
            )

            parameters = {
                "request_id": "uninstall-fail",
                "packages": [
                    {"package_name": "notinstalled", "package_manager": "apt"}
                ],
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            assert result["success"] is False
            assert len(result["failed_packages"]) == 1
            assert "Package not installed" in result["failed_packages"][0]["error"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_non_apt_not_implemented(self):
        """Test uninstallation of non-apt packages (not implemented)."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            parameters = {
                "request_id": "uninstall-nonapt",
                "packages": [{"package_name": "htop", "package_manager": "dnf"}],
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            assert result["success"] is False
            assert len(result["failed_packages"]) == 1
            assert "not implemented" in result["failed_packages"][0]["error"].lower()

    @pytest.mark.asyncio
    async def test_uninstall_packages_auto_detection(self):
        """Test uninstallation with auto package manager detection."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )

            self.package_ops._uninstall_packages_with_apt = AsyncMock(
                return_value={"success": True}
            )

            parameters = {
                "request_id": "uninstall-auto",
                "packages": [{"package_name": "git", "package_manager": "auto"}],
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_uninstall_packages_no_request_id(self):
        """Test uninstallation without request_id."""
        parameters = {
            "packages": [{"package_name": "vim"}],
            "requested_by": "user",
        }

        result = await self.package_ops.uninstall_packages(parameters)

        assert result["success"] is False
        assert "No request_id specified" in result["error"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_no_packages(self):
        """Test uninstallation without packages."""
        parameters = {
            "request_id": "uninstall-empty",
            "packages": [],
            "requested_by": "user",
        }

        result = await self.package_ops.uninstall_packages(parameters)

        assert result["success"] is False
        assert "No packages specified for uninstallation" in result["error"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_invalid_package(self):
        """Test uninstallation with package missing name."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_tracking = Mock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )

            parameters = {
                "request_id": "uninstall-invalid",
                "packages": [{"package_manager": "apt"}],  # No package_name
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            # When there are no valid packages, failed_packages has 1 entry, so success is False
            assert result["success"] is False
            assert "No valid packages to uninstall" in result["uninstall_log"]
            assert len(result["failed_packages"]) == 1

    @pytest.mark.asyncio
    async def test_uninstall_packages_db_error_create(self):
        """Test uninstallation when database creation fails."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            mock_db_manager.return_value.get_session.side_effect = Exception(
                "DB connection failed"
            )

            parameters = {
                "request_id": "uninstall-dberr",
                "packages": [{"package_name": "vim", "package_manager": "apt"}],
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            assert result["success"] is False
            assert "Failed to store uninstall request" in result["error"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_db_error_update(self):
        """Test uninstallation when database update fails."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            # Mock successful creation
            mock_session_create = MagicMock()
            # Mock failed update (return None to simulate not finding record)
            mock_session_update = MagicMock()
            mock_session_update.query.return_value.filter_by.return_value.first.return_value = (
                None
            )

            # First call succeeds, second returns session that can't find record
            mock_db_manager.return_value.get_session.return_value.__enter__.side_effect = [
                mock_session_create,
                mock_session_update,
            ]

            self.package_ops._uninstall_packages_with_apt = AsyncMock(
                return_value={"success": True}
            )

            parameters = {
                "request_id": "uninstall-dbupdate",
                "packages": [{"package_name": "vim", "package_manager": "apt"}],
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            # Should still succeed even if update fails
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_uninstall_packages_notification_fails(self):
        """Test uninstallation when server notification fails."""
        with patch(
            "src.sysmanage_agent.operations.package_operations.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )

            self.package_ops._uninstall_packages_with_apt = AsyncMock(
                return_value={"success": True}
            )

            self.mock_agent.send_message.side_effect = Exception("Queue error")

            parameters = {
                "request_id": "uninstall-notif",
                "packages": [{"package_name": "vim", "package_manager": "apt"}],
                "requested_by": "user",
            }

            result = await self.package_ops.uninstall_packages(parameters)

            # Should still succeed
            assert result["success"] is True
