"""
Unit tests for src.sysmanage_agent.operations.package_installation_helpers module.
Comprehensive tests for helper functions used in package installation operations.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-lines

import logging
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.package_installation_helpers import (
    create_installation_tracking_record,
    group_packages_by_manager,
    install_apt_packages,
    install_non_apt_packages,
    update_installation_tracking_record,
    validate_packages,
)


class TestCreateInstallationTrackingRecord:
    """Test cases for create_installation_tracking_record function."""

    def test_create_tracking_record_success(self):
        """Test successful tracking record creation."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            packages = [
                {"package_name": "vim", "package_manager": "apt"},
                {"package_name": "curl", "package_manager": "apt"},
            ]

            success, error = create_installation_tracking_record(
                "req-123", "admin", packages
            )

            assert success is True
            assert error is None
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()

    def test_create_tracking_record_database_error(self):
        """Test tracking record creation with database error."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_db_manager.return_value.get_session.side_effect = Exception(
                "Database connection failed"
            )

            packages = [{"package_name": "vim", "package_manager": "apt"}]

            success, error = create_installation_tracking_record(
                "req-456", "user", packages
            )

            assert success is False
            assert "Failed to store installation request" in error
            assert "Database connection failed" in error

    def test_create_tracking_record_commit_error(self):
        """Test tracking record creation when commit fails."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_session.commit.side_effect = Exception("Commit failed")
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            packages = [{"package_name": "vim", "package_manager": "apt"}]

            success, error = create_installation_tracking_record(
                "req-789", "admin", packages
            )

            assert success is False
            assert "Failed to store installation request" in error

    def test_create_tracking_record_empty_packages(self):
        """Test tracking record creation with empty package list."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            success, error = create_installation_tracking_record(
                "req-empty", "user", []
            )

            assert success is True
            assert error is None
            mock_session.add.assert_called_once()


class TestUpdateInstallationTrackingRecord:
    """Test cases for update_installation_tracking_record function."""

    def test_update_tracking_record_success_completed(self):
        """Test successful tracking record update for completed state."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            update_installation_tracking_record(
                "req-123", True, "All packages installed successfully"
            )

            assert mock_tracking.status == "completed"
            assert mock_tracking.success == "true"
            assert mock_tracking.result_log == "All packages installed successfully"
            mock_session.commit.assert_called_once()

    def test_update_tracking_record_success_failed(self):
        """Test successful tracking record update for failed state."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            update_installation_tracking_record(
                "req-456", False, "Some packages failed to install"
            )

            assert mock_tracking.status == "failed"
            assert mock_tracking.success == "false"
            assert mock_tracking.result_log == "Some packages failed to install"

    def test_update_tracking_record_not_found(self):
        """Test tracking record update when record not found."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                None
            )
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            # Should not raise exception
            update_installation_tracking_record(
                "req-nonexistent", True, "Packages installed"
            )

            mock_session.commit.assert_not_called()

    def test_update_tracking_record_database_error(self):
        """Test tracking record update with database error."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_db_manager.return_value.get_session.side_effect = Exception(
                "Database error"
            )

            # Should not raise exception
            update_installation_tracking_record("req-error", True, "Packages installed")


class TestValidatePackages:
    """Test cases for validate_packages function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")

    def test_validate_packages_all_valid(self):
        """Test validation with all valid packages."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "curl", "package_manager": "apt"},
            {"package_name": "htop", "package_manager": "dnf"},
        ]

        valid, failed = validate_packages(packages, self.logger)

        assert len(valid) == 3
        assert len(failed) == 0
        assert valid[0]["package_name"] == "vim"
        assert valid[1]["package_name"] == "curl"
        assert valid[2]["package_name"] == "htop"

    def test_validate_packages_all_invalid(self):
        """Test validation with all invalid packages."""
        packages = [
            {"package_manager": "apt"},  # No package_name
            {"version": "1.0"},  # No package_name
            {},  # Empty dict
        ]

        valid, failed = validate_packages(packages, self.logger)

        assert len(valid) == 0
        assert len(failed) == 3
        for fail in failed:
            assert "No package name" in fail["error"]

    def test_validate_packages_mixed(self):
        """Test validation with mixed valid and invalid packages."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_manager": "apt"},  # Invalid
            {"package_name": "curl", "package_manager": "apt"},
            {},  # Invalid
        ]

        valid, failed = validate_packages(packages, self.logger)

        assert len(valid) == 2
        assert len(failed) == 2
        assert valid[0]["package_name"] == "vim"
        assert valid[1]["package_name"] == "curl"

    def test_validate_packages_empty_list(self):
        """Test validation with empty package list."""
        valid, failed = validate_packages([], self.logger)

        assert len(valid) == 0
        assert len(failed) == 0

    def test_validate_packages_empty_package_name(self):
        """Test validation with empty string package name."""
        packages = [
            {"package_name": "", "package_manager": "apt"},
        ]

        valid, failed = validate_packages(packages, self.logger)

        # Empty strings are falsy and filtered out
        assert len(valid) == 0
        assert len(failed) == 1

    def test_validate_packages_whitespace_package_name(self):
        """Test validation with whitespace-only package name."""
        # Note: The implementation treats non-empty whitespace as valid
        # This tests current behavior - whitespace strings are truthy in Python
        packages = [
            {"package_name": "   ", "package_manager": "apt"},
        ]

        valid, failed = validate_packages(packages, self.logger)

        # Whitespace-only strings are truthy and pass validation
        # (This may be undesirable behavior to fix in the implementation)
        assert len(valid) == 1
        assert len(failed) == 0

    def test_validate_packages_none_package_name(self):
        """Test validation with None package name."""
        packages = [{"package_name": None, "package_manager": "apt"}]

        valid, failed = validate_packages(packages, self.logger)

        assert len(valid) == 0
        assert len(failed) == 1

    def test_validate_packages_preserves_metadata(self):
        """Test that validation preserves package metadata."""
        packages = [
            {
                "package_name": "vim",
                "package_manager": "apt",
                "version": "8.2",
                "priority": "high",
            }
        ]

        valid, _failed = validate_packages(packages, self.logger)

        assert len(valid) == 1
        assert valid[0]["package_name"] == "vim"
        assert valid[0]["version"] == "8.2"
        assert valid[0]["priority"] == "high"


class TestGroupPackagesByManager:
    """Test cases for group_packages_by_manager function."""

    def test_group_single_manager(self):
        """Test grouping packages with single manager."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "curl", "package_manager": "apt"},
            {"package_name": "htop", "package_manager": "apt"},
        ]

        groups = group_packages_by_manager(packages)

        assert len(groups) == 1
        assert "apt" in groups
        assert len(groups["apt"]) == 3

    def test_group_multiple_managers(self):
        """Test grouping packages with multiple managers."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "htop", "package_manager": "dnf"},
            {"package_name": "curl", "package_manager": "apt"},
            {"package_name": "nginx", "package_manager": "zypper"},
        ]

        groups = group_packages_by_manager(packages)

        assert len(groups) == 3
        assert "apt" in groups
        assert "dnf" in groups
        assert "zypper" in groups
        assert len(groups["apt"]) == 2
        assert len(groups["dnf"]) == 1
        assert len(groups["zypper"]) == 1

    def test_group_auto_converts_to_apt(self):
        """Test that auto package manager converts to apt."""
        packages = [
            {"package_name": "vim", "package_manager": "auto"},
            {"package_name": "curl", "package_manager": "auto"},
        ]

        groups = group_packages_by_manager(packages)

        assert len(groups) == 1
        assert "apt" in groups
        assert len(groups["apt"]) == 2

    def test_group_missing_manager_defaults_to_apt(self):
        """Test that missing package_manager defaults to apt via auto."""
        packages = [
            {"package_name": "vim"},  # No package_manager
            {"package_name": "curl", "package_manager": "apt"},
        ]

        groups = group_packages_by_manager(packages)

        assert len(groups) == 1
        assert "apt" in groups
        assert len(groups["apt"]) == 2

    def test_group_empty_list(self):
        """Test grouping empty package list."""
        groups = group_packages_by_manager([])

        assert len(groups) == 0

    def test_group_preserves_package_order(self):
        """Test that grouping preserves package order within groups."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "curl", "package_manager": "apt"},
            {"package_name": "htop", "package_manager": "apt"},
        ]

        groups = group_packages_by_manager(packages)

        assert groups["apt"][0]["package_name"] == "vim"
        assert groups["apt"][1]["package_name"] == "curl"
        assert groups["apt"][2]["package_name"] == "htop"


class TestInstallAptPackages:
    """Test cases for install_apt_packages function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")

    @pytest.mark.asyncio
    async def test_install_apt_packages_all_success(self):
        """Test successful apt package installation."""
        mock_install_method = AsyncMock(
            return_value={
                "success": True,
                "versions": {"vim": "8.2", "curl": "7.68"},
                "output": "Packages installed",
            }
        )

        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "curl", "package_manager": "apt"},
        ]

        success, failed, log = await install_apt_packages(
            packages, mock_install_method, self.logger
        )

        assert len(success) == 2
        assert len(failed) == 0
        assert len(log) == 2
        assert success[0]["package_name"] == "vim"
        assert success[0]["installed_version"] == "8.2"
        assert success[1]["package_name"] == "curl"
        assert success[1]["installed_version"] == "7.68"
        assert "vim installed successfully" in log[0]
        assert "curl installed successfully" in log[1]

    @pytest.mark.asyncio
    async def test_install_apt_packages_all_failure(self):
        """Test failed apt package installation."""
        mock_install_method = AsyncMock(
            return_value={
                "success": False,
                "error": "Unable to locate package",
                "output": "E: Unable to locate package",
            }
        )

        packages = [
            {"package_name": "nonexistent1", "package_manager": "apt"},
            {"package_name": "nonexistent2", "package_manager": "apt"},
        ]

        success, failed, log = await install_apt_packages(
            packages, mock_install_method, self.logger
        )

        assert len(success) == 0
        assert len(failed) == 2
        assert len(log) == 2
        assert failed[0]["package_name"] == "nonexistent1"
        assert "Unable to locate package" in failed[0]["error"]
        assert "nonexistent1 failed" in log[0]
        assert "nonexistent2 failed" in log[1]

    @pytest.mark.asyncio
    async def test_install_apt_packages_missing_version(self):
        """Test apt package installation with missing version info."""
        mock_install_method = AsyncMock(
            return_value={
                "success": True,
                "versions": {},  # Empty versions dict
                "output": "Packages installed",
            }
        )

        packages = [{"package_name": "vim", "package_manager": "apt"}]

        success, _failed, _log = await install_apt_packages(
            packages, mock_install_method, self.logger
        )

        assert len(success) == 1
        assert success[0]["installed_version"] == "unknown"

    @pytest.mark.asyncio
    async def test_install_apt_packages_empty_list(self):
        """Test apt package installation with empty list."""
        mock_install_method = AsyncMock()

        _success, _failed, _log = await install_apt_packages(
            [], mock_install_method, self.logger
        )

        mock_install_method.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_install_apt_packages_preserves_result(self):
        """Test that install result is preserved in success/failed packages."""
        mock_result = {
            "success": True,
            "versions": {"vim": "8.2"},
            "output": "Full output here",
        }
        mock_install_method = AsyncMock(return_value=mock_result)

        packages = [{"package_name": "vim", "package_manager": "apt"}]

        success, _failed, _log = await install_apt_packages(
            packages, mock_install_method, self.logger
        )

        assert success[0]["result"] == mock_result


class TestInstallNonAptPackages:
    """Test cases for install_non_apt_packages function."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")

    def test_install_non_apt_packages_success(self):
        """Test successful non-apt package installation."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {
                "success": True,
                "installed_version": "3.0",
            }
            mock_detector_class.return_value = mock_detector

            packages = [
                {"package_name": "htop", "package_manager": "dnf"},
                {"package_name": "vim", "package_manager": "dnf"},
            ]

            success, failed, log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert len(success) == 2
            assert len(failed) == 0
            assert success[0]["package_name"] == "htop"
            assert success[0]["installed_version"] == "3.0"
            assert "htop installed successfully" in log[1]

    def test_install_non_apt_packages_failure(self):
        """Test failed non-apt package installation."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {
                "success": False,
                "error": "Package not found in repository",
            }
            mock_detector_class.return_value = mock_detector

            packages = [{"package_name": "nonexistent", "package_manager": "dnf"}]

            success, failed, log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert len(success) == 0
            assert len(failed) == 1
            assert failed[0]["package_name"] == "nonexistent"
            assert "Package not found" in failed[0]["error"]
            assert "nonexistent failed" in log[1]

    def test_install_non_apt_packages_exception(self):
        """Test non-apt package installation with exception."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.side_effect = Exception("Installation failed")
            mock_detector_class.return_value = mock_detector

            packages = [{"package_name": "pkg", "package_manager": "dnf"}]

            success, failed, _log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert len(success) == 0
            assert len(failed) == 1
            assert "Installation failed" in failed[0]["error"]

    def test_install_non_apt_packages_mixed_results(self):
        """Test non-apt package installation with mixed success/failure."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()

            def install_side_effect(package_name, _pkg_manager):
                if package_name == "success_pkg":
                    return {"success": True, "installed_version": "1.0"}
                return {"success": False, "error": "Failed"}

            mock_detector.install_package.side_effect = install_side_effect
            mock_detector_class.return_value = mock_detector

            packages = [
                {"package_name": "success_pkg", "package_manager": "dnf"},
                {"package_name": "fail_pkg", "package_manager": "dnf"},
            ]

            success, failed, _log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert len(success) == 1
            assert len(failed) == 1
            assert success[0]["package_name"] == "success_pkg"
            assert failed[0]["package_name"] == "fail_pkg"

    def test_install_non_apt_packages_empty_list(self):
        """Test non-apt package installation with empty list."""
        success, failed, log = install_non_apt_packages([], "dnf", self.logger)

        assert len(success) == 0
        assert len(failed) == 0
        assert len(log) == 0

    def test_install_non_apt_packages_unknown_error(self):
        """Test non-apt package installation with unknown error."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {
                "success": False,
                # No 'error' key
            }
            mock_detector_class.return_value = mock_detector

            packages = [{"package_name": "pkg", "package_manager": "dnf"}]

            _success, failed, _log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert len(failed) == 1
            assert "Unknown error" in failed[0]["error"]

    def test_install_non_apt_packages_log_format(self):
        """Test that installation log has proper format."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_detector.install_package.return_value = {
                "success": True,
                "installed_version": "1.0",
            }
            mock_detector_class.return_value = mock_detector

            packages = [{"package_name": "vim", "package_manager": "dnf"}]

            _success, _failed, log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert len(log) == 2
            assert "Installing vim..." in log[0]
            assert "vim installed successfully" in log[1]

    def test_install_non_apt_packages_preserves_result(self):
        """Test that install result is preserved."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.UpdateDetector"
        ) as mock_detector_class:
            mock_detector = Mock()
            mock_result = {
                "success": True,
                "installed_version": "1.0",
                "extra_info": "Some data",
            }
            mock_detector.install_package.return_value = mock_result
            mock_detector_class.return_value = mock_detector

            packages = [{"package_name": "vim", "package_manager": "dnf"}]

            success, _failed, _log = install_non_apt_packages(
                packages, "dnf", self.logger
            )

            assert success[0]["result"] == mock_result


class TestIntegration:
    """Integration tests for package installation helpers."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger("test")

    def test_full_validation_and_grouping_workflow(self):
        """Test complete workflow of validation and grouping."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "htop", "package_manager": "dnf"},
            {"package_manager": "apt"},  # Invalid - no name
            {"package_name": "curl", "package_manager": "auto"},
            {"package_name": "nginx"},  # No manager, defaults to apt
        ]

        # Step 1: Validate
        valid, failed = validate_packages(packages, self.logger)
        assert len(valid) == 4
        assert len(failed) == 1

        # Step 2: Group by manager
        groups = group_packages_by_manager(valid)
        assert len(groups) == 2
        assert "apt" in groups
        assert "dnf" in groups
        assert len(groups["apt"]) == 3  # vim, curl (auto->apt), nginx (default->apt)
        assert len(groups["dnf"]) == 1  # htop

    @pytest.mark.asyncio
    async def test_tracking_record_lifecycle(self):
        """Test complete lifecycle of tracking record."""
        with patch(
            "src.sysmanage_agent.operations.package_installation_helpers.get_database_manager"
        ) as mock_db_manager:
            mock_session = MagicMock()
            mock_tracking = Mock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = (
                mock_tracking
            )
            mock_db_manager.return_value.get_session.return_value.__enter__.return_value = (
                mock_session
            )

            packages = [{"package_name": "vim", "package_manager": "apt"}]

            # Step 1: Create tracking record
            success, error = create_installation_tracking_record(
                "req-lifecycle", "admin", packages
            )
            assert success is True
            assert error is None

            # Step 2: Update tracking record on completion
            update_installation_tracking_record(
                "req-lifecycle", True, "vim installed successfully"
            )
            assert mock_tracking.status == "completed"
            assert mock_tracking.success == "true"

    def test_multiple_package_managers_workflow(self):
        """Test workflow with packages for different managers."""
        packages = [
            {"package_name": "vim", "package_manager": "apt"},
            {"package_name": "htop", "package_manager": "dnf"},
            {"package_name": "curl", "package_manager": "apt"},
            {"package_name": "nginx", "package_manager": "zypper"},
            {"package_name": "git", "package_manager": "pacman"},
        ]

        valid, _failed = validate_packages(packages, self.logger)
        groups = group_packages_by_manager(valid)

        assert len(groups) == 4
        assert len(groups["apt"]) == 2
        assert len(groups["dnf"]) == 1
        assert len(groups["zypper"]) == 1
        assert len(groups["pacman"]) == 1
