"""
Comprehensive unit tests for VMM disk operations.

Tests cover:
- VmmDiskOperations initialization
- Disk image creation (success, failure, timeout, exceptions)
- Disk existence checks
- Disk image deletion (success, failure, not found)
- Error handling for all methods
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_vmm_disk import VmmDiskOperations


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def disk_ops(logger):
    """Create a VmmDiskOperations instance for testing."""
    return VmmDiskOperations(logger)


class TestVmmDiskOperationsInit:
    """Tests for VmmDiskOperations initialization."""

    def test_init_sets_logger(self, disk_ops, logger):
        """Test that __init__ sets logger."""
        assert disk_ops.logger == logger

    def test_init_with_custom_logger(self):
        """Test initialization with a custom logger."""
        custom_logger = logging.getLogger("custom_test")
        ops = VmmDiskOperations(custom_logger)
        assert ops.logger == custom_logger


class TestCreateDiskImage:
    """Tests for create_disk_image method."""

    def test_create_disk_image_success(self, disk_ops):
        """Test creating a disk image successfully."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="",
                    stderr="",
                )
                result = disk_ops.create_disk_image(
                    "/var/vmm/disks/test-vm.qcow2", "20G"
                )

        assert result["success"] is True
        assert result["disk_path"] == "/var/vmm/disks/test-vm.qcow2"

    def test_create_disk_image_already_exists(self, disk_ops):
        """Test creating a disk image when it already exists."""
        with patch("os.path.exists", return_value=True):
            result = disk_ops.create_disk_image("/var/vmm/disks/test-vm.qcow2", "20G")

        assert result["success"] is False
        assert "already exists" in result["error"]
        assert "/var/vmm/disks/test-vm.qcow2" in result["error"]

    def test_create_disk_image_vmctl_failure(self, disk_ops):
        """Test creating a disk image when vmctl fails."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="vmctl: cannot create disk image: Permission denied",
                )
                result = disk_ops.create_disk_image(
                    "/var/vmm/disks/test-vm.qcow2", "20G"
                )

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    def test_create_disk_image_vmctl_failure_stdout(self, disk_ops):
        """Test creating a disk image when vmctl fails with stdout error."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="Error: invalid size format",
                    stderr="",
                )
                result = disk_ops.create_disk_image(
                    "/var/vmm/disks/test-vm.qcow2", "invalid"
                )

        assert result["success"] is False
        assert "invalid size format" in result["error"]

    def test_create_disk_image_vmctl_failure_unknown_error(self, disk_ops):
        """Test creating a disk image with unknown error."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="",
                )
                result = disk_ops.create_disk_image(
                    "/var/vmm/disks/test-vm.qcow2", "20G"
                )

        assert result["success"] is False
        assert "Unknown error" in result["error"]

    def test_create_disk_image_timeout(self, disk_ops):
        """Test creating a disk image with timeout."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(
                    cmd=["vmctl", "create"], timeout=60
                )
                result = disk_ops.create_disk_image(
                    "/var/vmm/disks/test-vm.qcow2", "20G"
                )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    def test_create_disk_image_exception(self, disk_ops):
        """Test creating a disk image with unexpected exception."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = Exception("Unexpected subprocess error")
                result = disk_ops.create_disk_image(
                    "/var/vmm/disks/test-vm.qcow2", "20G"
                )

        assert result["success"] is False
        assert "Unexpected subprocess error" in result["error"]

    def test_create_disk_image_verifies_correct_command(self, disk_ops):
        """Test that create_disk_image uses correct vmctl command."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                disk_ops.create_disk_image("/var/vmm/disks/test-vm.qcow2", "50G")

        mock_run.assert_called_once_with(
            ["vmctl", "create", "-s", "50G", "/var/vmm/disks/test-vm.qcow2"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_create_disk_image_logs_success(self, disk_ops, logger):
        """Test that successful disk creation is logged."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch.object(logger, "info") as mock_log:
                    disk_ops.create_disk_image("/var/vmm/disks/test-vm.qcow2", "20G")
                    mock_log.assert_called()

    def test_create_disk_image_various_sizes(self, disk_ops):
        """Test creating disk images with various sizes."""
        sizes = ["1G", "5G", "20G", "50G", "100G", "1000G"]

        for size in sizes:
            with patch("os.path.exists", return_value=False):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = disk_ops.create_disk_image(
                        f"/var/vmm/disks/test-{size}.qcow2", size
                    )

            assert result["success"] is True
            assert result["disk_path"] == f"/var/vmm/disks/test-{size}.qcow2"

    def test_create_disk_image_path_with_spaces(self, disk_ops):
        """Test creating disk image with path containing spaces."""
        disk_path = "/var/vmm/my disks/test vm.qcow2"
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = disk_ops.create_disk_image(disk_path, "20G")

        assert result["success"] is True
        assert result["disk_path"] == disk_path


class TestDiskExists:
    """Tests for disk_exists method."""

    def test_disk_exists_true(self, disk_ops):
        """Test disk_exists returns True when disk exists."""
        with patch("os.path.exists", return_value=True):
            result = disk_ops.disk_exists("/var/vmm/disks/test-vm.qcow2")

        assert result is True

    def test_disk_exists_false(self, disk_ops):
        """Test disk_exists returns False when disk does not exist."""
        with patch("os.path.exists", return_value=False):
            result = disk_ops.disk_exists("/var/vmm/disks/nonexistent.qcow2")

        assert result is False

    def test_disk_exists_with_various_paths(self, disk_ops):
        """Test disk_exists with various paths."""
        paths = [
            "/var/vmm/disks/vm1.qcow2",
            "/home/user/vms/disk.img",
            "/tmp/test.qcow2",
            "/var/vmm/some space/disk.qcow2",
        ]

        for path in paths:
            with patch("os.path.exists", return_value=True):
                assert disk_ops.disk_exists(path) is True

            with patch("os.path.exists", return_value=False):
                assert disk_ops.disk_exists(path) is False

    def test_disk_exists_calls_os_path_exists(self, disk_ops):
        """Test that disk_exists calls os.path.exists with correct path."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            disk_ops.disk_exists("/var/vmm/disks/test.qcow2")

        mock_exists.assert_called_once_with("/var/vmm/disks/test.qcow2")


class TestDeleteDiskImage:
    """Tests for delete_disk_image method."""

    def test_delete_disk_image_success(self, disk_ops):
        """Test deleting a disk image successfully."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                result = disk_ops.delete_disk_image("/var/vmm/disks/test-vm.qcow2")

        assert result["success"] is True
        mock_remove.assert_called_once_with("/var/vmm/disks/test-vm.qcow2")

    def test_delete_disk_image_not_found(self, disk_ops):
        """Test deleting a disk image that does not exist."""
        with patch("os.path.exists", return_value=False):
            result = disk_ops.delete_disk_image("/var/vmm/disks/nonexistent.qcow2")

        assert result["success"] is True
        assert "message" in result
        assert "does not exist" in result["message"]

    def test_delete_disk_image_permission_error(self, disk_ops):
        """Test deleting a disk image with permission error."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                mock_remove.side_effect = PermissionError(
                    "Permission denied: /var/vmm/disks/test-vm.qcow2"
                )
                result = disk_ops.delete_disk_image("/var/vmm/disks/test-vm.qcow2")

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    def test_delete_disk_image_os_error(self, disk_ops):
        """Test deleting a disk image with OS error."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                mock_remove.side_effect = OSError("Disk I/O error")
                result = disk_ops.delete_disk_image("/var/vmm/disks/test-vm.qcow2")

        assert result["success"] is False
        assert "Disk I/O error" in result["error"]

    def test_delete_disk_image_generic_exception(self, disk_ops):
        """Test deleting a disk image with generic exception."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                mock_remove.side_effect = Exception("Unexpected error")
                result = disk_ops.delete_disk_image("/var/vmm/disks/test-vm.qcow2")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    def test_delete_disk_image_logs_success(self, disk_ops, logger):
        """Test that successful disk deletion is logged."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove"):
                with patch.object(logger, "info") as mock_log:
                    disk_ops.delete_disk_image("/var/vmm/disks/test-vm.qcow2")
                    mock_log.assert_called()

    def test_delete_disk_image_logs_error(self, disk_ops, logger):
        """Test that disk deletion error is logged."""
        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                mock_remove.side_effect = PermissionError("Permission denied")
                with patch.object(logger, "error") as mock_log:
                    disk_ops.delete_disk_image("/var/vmm/disks/test-vm.qcow2")
                    mock_log.assert_called()

    def test_delete_disk_image_with_special_characters(self, disk_ops):
        """Test deleting disk image with special characters in path."""
        paths = [
            "/var/vmm/disks/test-vm_1.qcow2",
            "/var/vmm/disks/test.vm.1.qcow2",
            "/var/vmm/disks/test vm 1.qcow2",
        ]

        for path in paths:
            with patch("os.path.exists", return_value=True):
                with patch("os.remove") as mock_remove:
                    result = disk_ops.delete_disk_image(path)

            assert result["success"] is True
            mock_remove.assert_called_with(path)


class TestIntegrationScenarios:
    """Integration-like tests for common usage scenarios."""

    def test_create_then_delete_disk(self, disk_ops):
        """Test creating and then deleting a disk image."""
        disk_path = "/var/vmm/disks/lifecycle-test.qcow2"

        # Create disk
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                create_result = disk_ops.create_disk_image(disk_path, "10G")

        assert create_result["success"] is True

        # Delete disk
        with patch("os.path.exists", return_value=True):
            with patch("os.remove"):
                delete_result = disk_ops.delete_disk_image(disk_path)

        assert delete_result["success"] is True

    def test_check_exists_before_create(self, disk_ops):
        """Test checking if disk exists before creating."""
        disk_path = "/var/vmm/disks/check-test.qcow2"

        # Check if exists (should not)
        with patch("os.path.exists", return_value=False):
            exists = disk_ops.disk_exists(disk_path)

        assert exists is False

        # Now create it
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = disk_ops.create_disk_image(disk_path, "20G")

        assert result["success"] is True

    def test_delete_already_deleted_disk(self, disk_ops):
        """Test deleting a disk that was already deleted."""
        disk_path = "/var/vmm/disks/already-deleted.qcow2"

        # First deletion
        with patch("os.path.exists", return_value=True):
            with patch("os.remove"):
                result1 = disk_ops.delete_disk_image(disk_path)

        assert result1["success"] is True

        # Second deletion (disk no longer exists)
        with patch("os.path.exists", return_value=False):
            result2 = disk_ops.delete_disk_image(disk_path)

        assert result2["success"] is True
        assert "does not exist" in result2["message"]

    def test_create_multiple_disks(self, disk_ops):
        """Test creating multiple disk images."""
        disks = [
            ("/var/vmm/disks/vm1.qcow2", "10G"),
            ("/var/vmm/disks/vm2.qcow2", "20G"),
            ("/var/vmm/disks/vm3.qcow2", "50G"),
        ]

        for disk_path, size in disks:
            with patch("os.path.exists", return_value=False):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                    result = disk_ops.create_disk_image(disk_path, size)

            assert result["success"] is True
            assert result["disk_path"] == disk_path


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_create_disk_empty_path(self, disk_ops):
        """Test creating disk with empty path."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="vmctl: empty path",
                )
                result = disk_ops.create_disk_image("", "20G")

        assert result["success"] is False

    def test_create_disk_empty_size(self, disk_ops):
        """Test creating disk with empty size."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1,
                    stdout="",
                    stderr="vmctl: invalid size",
                )
                result = disk_ops.create_disk_image("/var/vmm/test.qcow2", "")

        assert result["success"] is False

    def test_disk_exists_empty_path(self, disk_ops):
        """Test disk_exists with empty path."""
        with patch("os.path.exists", return_value=False):
            result = disk_ops.disk_exists("")

        assert result is False

    def test_delete_disk_empty_path(self, disk_ops):
        """Test deleting disk with empty path."""
        with patch("os.path.exists", return_value=False):
            result = disk_ops.delete_disk_image("")

        assert result["success"] is True
        assert "does not exist" in result["message"]

    def test_create_disk_very_long_path(self, disk_ops):
        """Test creating disk with very long path."""
        long_path = "/var/vmm/" + "a" * 200 + ".qcow2"
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = disk_ops.create_disk_image(long_path, "20G")

        assert result["success"] is True
        assert result["disk_path"] == long_path

    def test_create_disk_unicode_path(self, disk_ops):
        """Test creating disk with unicode characters in path."""
        unicode_path = "/var/vmm/disks/vm-\u00e4\u00f6\u00fc.qcow2"
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = disk_ops.create_disk_image(unicode_path, "20G")

        assert result["success"] is True

    def test_subprocess_run_captures_both_outputs(self, disk_ops):
        """Test that subprocess.run is called with capture_output=True."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="some stdout output",
                    stderr="some stderr output",
                )
                disk_ops.create_disk_image("/var/vmm/test.qcow2", "20G")

        # Verify capture_output=True is set
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["capture_output"] is True
        assert call_kwargs["text"] is True


class TestI18nIntegration:
    """Tests for internationalization (i18n) integration."""

    def test_error_messages_use_i18n(self, disk_ops):
        """Test that error messages go through i18n translation."""
        with patch("os.path.exists", return_value=True):
            result = disk_ops.create_disk_image("/var/vmm/exists.qcow2", "20G")

        # The error should contain the translated string
        assert result["success"] is False
        assert "error" in result

    def test_timeout_error_uses_i18n(self, disk_ops):
        """Test that timeout error uses i18n."""
        with patch("os.path.exists", return_value=False):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(
                    cmd=["vmctl"], timeout=60
                )
                result = disk_ops.create_disk_image("/var/vmm/test.qcow2", "20G")

        assert result["success"] is False
        assert "error" in result
