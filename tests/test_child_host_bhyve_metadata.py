"""
Tests for bhyve VM metadata helpers module.

This module tests functions for saving, loading, and deleting VM metadata
used by list_bhyve_vms() to provide additional VM information.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_metadata import (
    BHYVE_METADATA_DIR,
    delete_bhyve_metadata,
    load_bhyve_metadata,
    save_bhyve_metadata,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger instance."""
    logger = Mock()
    logger.info = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    return logger


@pytest.fixture
def temp_metadata_dir(tmp_path):
    """Create a temporary metadata directory."""
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    return metadata_dir


class TestBhyveMetadataConstants:
    """Tests for module constants."""

    def test_metadata_dir_path(self):
        """Test that BHYVE_METADATA_DIR is correctly set."""
        assert BHYVE_METADATA_DIR == "/vm/metadata"


class TestSaveBhyveMetadata:
    """Tests for save_bhyve_metadata function."""

    def test_save_metadata_creates_directory_if_not_exists(self, mock_logger, tmp_path):
        """Test that metadata directory is created if it doesn't exist."""
        new_metadata_dir = tmp_path / "new_metadata"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(new_metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="FreeBSD 14",
                vm_ip="192.168.1.100",
                logger=mock_logger,
            )

        assert result is True
        assert new_metadata_dir.exists()

    def test_save_metadata_success(self, mock_logger, tmp_path):
        """Test successful metadata save."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="FreeBSD 14.0-RELEASE",
                vm_ip="192.168.1.100",
                logger=mock_logger,
            )

        assert result is True

        # Verify the file was created
        metadata_file = metadata_dir / "test-vm.json"
        assert metadata_file.exists()

        # Verify the content
        with open(metadata_file, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)

        assert data["vm_name"] == "test-vm"
        assert data["hostname"] == "test-vm.example.com"
        assert data["vm_ip"] == "192.168.1.100"
        assert data["distribution"]["distribution_name"] == "FreeBSD"
        assert data["distribution"]["distribution_version"] == "14.0-RELEASE"
        assert data["distribution_string"] == "FreeBSD 14.0-RELEASE"

    def test_save_metadata_with_none_ip(self, mock_logger, tmp_path):
        """Test saving metadata with None IP address."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="Ubuntu 22.04",
                vm_ip=None,
                logger=mock_logger,
            )

        assert result is True

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)

        assert data["vm_ip"] is None

    def test_save_metadata_single_word_distribution(self, mock_logger, tmp_path):
        """Test saving metadata with single word distribution."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="Debian",
                vm_ip="10.0.0.5",
                logger=mock_logger,
            )

        assert result is True

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)

        assert data["distribution"]["distribution_name"] == "Debian"
        assert data["distribution"]["distribution_version"] == ""

    def test_save_metadata_empty_distribution(self, mock_logger, tmp_path):
        """Test saving metadata with empty distribution string."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="",
                vm_ip="10.0.0.5",
                logger=mock_logger,
            )

        assert result is True

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)

        # Empty string distribution doesn't enter the if block
        assert data["distribution"]["distribution_name"] == ""
        assert data["distribution"]["distribution_version"] == ""

    def test_save_metadata_multi_word_version(self, mock_logger, tmp_path):
        """Test saving metadata with multi-word version string."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="Windows Server 2022 Datacenter",
                vm_ip="10.0.0.5",
                logger=mock_logger,
            )

        assert result is True

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)

        assert data["distribution"]["distribution_name"] == "Windows"
        assert data["distribution"]["distribution_version"] == "Server 2022 Datacenter"

    def test_save_metadata_logs_success(self, mock_logger, tmp_path):
        """Test that successful save logs info message."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="FreeBSD 14",
                vm_ip="192.168.1.100",
                logger=mock_logger,
            )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0]
        assert "test-vm" in str(call_args)

    def test_save_metadata_permission_error(self, mock_logger):
        """Test handling of permission error when saving metadata."""
        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.Path.mkdir",
            side_effect=PermissionError("Permission denied"),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="test-vm.example.com",
                distribution="FreeBSD 14",
                vm_ip="192.168.1.100",
                logger=mock_logger,
            )

        assert result is False
        mock_logger.error.assert_called_once()

    def test_save_metadata_io_error_on_write(self, mock_logger, tmp_path):
        """Test handling of IO error when writing file."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            with patch("builtins.open", side_effect=IOError("Disk full")):
                result = save_bhyve_metadata(
                    vm_name="test-vm",
                    hostname="test-vm.example.com",
                    distribution="FreeBSD 14",
                    vm_ip="192.168.1.100",
                    logger=mock_logger,
                )

        assert result is False
        mock_logger.error.assert_called_once()

    def test_save_metadata_overwrites_existing(self, mock_logger, tmp_path):
        """Test that saving metadata overwrites existing file."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": "old-data"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = save_bhyve_metadata(
                vm_name="test-vm",
                hostname="new-hostname.example.com",
                distribution="FreeBSD 14",
                vm_ip="192.168.1.200",
                logger=mock_logger,
            )

        assert result is True

        with open(metadata_file, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)

        assert data["hostname"] == "new-hostname.example.com"
        assert data["vm_ip"] == "192.168.1.200"


class TestLoadBhyveMetadata:
    """Tests for load_bhyve_metadata function."""

    def test_load_metadata_success(self, mock_logger, tmp_path):
        """Test successful metadata load."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata = {
            "vm_name": "test-vm",
            "hostname": "test-vm.example.com",
            "vm_ip": "192.168.1.100",
            "distribution": {
                "distribution_name": "FreeBSD",
                "distribution_version": "14",
            },
            "distribution_string": "FreeBSD 14",
        }

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump(metadata, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = load_bhyve_metadata("test-vm", mock_logger)

        assert result is not None
        assert result["vm_name"] == "test-vm"
        assert result["hostname"] == "test-vm.example.com"
        assert result["vm_ip"] == "192.168.1.100"
        assert result["distribution"]["distribution_name"] == "FreeBSD"

    def test_load_metadata_file_not_exists(self, mock_logger, tmp_path):
        """Test loading metadata when file doesn't exist."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = load_bhyve_metadata("nonexistent-vm", mock_logger)

        assert result is None

    def test_load_metadata_directory_not_exists(self, mock_logger, tmp_path):
        """Test loading metadata when metadata directory doesn't exist."""
        nonexistent_dir = tmp_path / "nonexistent"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(nonexistent_dir),
        ):
            result = load_bhyve_metadata("test-vm", mock_logger)

        assert result is None

    def test_load_metadata_invalid_json(self, mock_logger, tmp_path):
        """Test loading metadata with invalid JSON file."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("not valid json {{{")

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = load_bhyve_metadata("test-vm", mock_logger)

        assert result is None
        mock_logger.debug.assert_called_once()

    def test_load_metadata_permission_error(self, mock_logger, tmp_path):
        """Test handling of permission error when loading metadata."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": "test-vm"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            with patch("builtins.open", side_effect=PermissionError("Access denied")):
                result = load_bhyve_metadata("test-vm", mock_logger)

        assert result is None
        mock_logger.debug.assert_called_once()

    def test_load_metadata_empty_file(self, mock_logger, tmp_path):
        """Test loading metadata from empty file."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        metadata_file.touch()  # Create empty file

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = load_bhyve_metadata("test-vm", mock_logger)

        assert result is None
        mock_logger.debug.assert_called_once()

    def test_load_metadata_with_special_characters_in_name(self, mock_logger, tmp_path):
        """Test loading metadata for VM with special characters in name."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        vm_name = "test-vm_123"
        metadata = {"vm_name": vm_name, "hostname": "test.example.com"}

        metadata_file = metadata_dir / f"{vm_name}.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump(metadata, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = load_bhyve_metadata(vm_name, mock_logger)

        assert result is not None
        assert result["vm_name"] == vm_name


class TestDeleteBhyveMetadata:
    """Tests for delete_bhyve_metadata function."""

    def test_delete_metadata_success(self, mock_logger, tmp_path):
        """Test successful metadata deletion."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": "test-vm"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = delete_bhyve_metadata("test-vm", mock_logger)

        assert result is True
        assert not metadata_file.exists()
        mock_logger.info.assert_called_once()

    def test_delete_metadata_file_not_exists(self, mock_logger, tmp_path):
        """Test deleting metadata when file doesn't exist."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = delete_bhyve_metadata("nonexistent-vm", mock_logger)

        # Should return True when file doesn't exist
        assert result is True
        # Should not log info (only logs when file was actually deleted)
        mock_logger.info.assert_not_called()

    def test_delete_metadata_directory_not_exists(self, mock_logger, tmp_path):
        """Test deleting metadata when metadata directory doesn't exist."""
        nonexistent_dir = tmp_path / "nonexistent"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(nonexistent_dir),
        ):
            result = delete_bhyve_metadata("test-vm", mock_logger)

        # Should return True when file/directory doesn't exist
        assert result is True

    def test_delete_metadata_permission_error(self, mock_logger, tmp_path):
        """Test handling of permission error when deleting metadata."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": "test-vm"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            with patch.object(
                Path, "unlink", side_effect=PermissionError("Access denied")
            ):
                result = delete_bhyve_metadata("test-vm", mock_logger)

        assert result is False
        mock_logger.error.assert_called_once()

    def test_delete_metadata_logs_error_on_exception(self, mock_logger, tmp_path):
        """Test that exceptions are logged as errors."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        metadata_file = metadata_dir / "test-vm.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": "test-vm"}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            with patch.object(Path, "unlink", side_effect=OSError("Some OS error")):
                result = delete_bhyve_metadata("test-vm", mock_logger)

        assert result is False
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[0]
        assert "test-vm" in str(call_args)

    def test_delete_metadata_with_special_characters_in_name(
        self, mock_logger, tmp_path
    ):
        """Test deleting metadata for VM with special characters in name."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        vm_name = "test-vm_123"
        metadata_file = metadata_dir / f"{vm_name}.json"
        with open(metadata_file, "w", encoding="utf-8") as file_handle:
            json.dump({"vm_name": vm_name}, file_handle)

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            result = delete_bhyve_metadata(vm_name, mock_logger)

        assert result is True
        assert not metadata_file.exists()


class TestSaveLoadDeleteIntegration:
    """Integration tests for the full save/load/delete workflow."""

    def test_save_then_load(self, mock_logger, tmp_path):
        """Test saving metadata then loading it back."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            # Save metadata
            save_result = save_bhyve_metadata(
                vm_name="integration-test-vm",
                hostname="integration.example.com",
                distribution="FreeBSD 14.0-RELEASE",
                vm_ip="10.0.0.50",
                logger=mock_logger,
            )
            assert save_result is True

            # Load metadata
            loaded = load_bhyve_metadata("integration-test-vm", mock_logger)

        assert loaded is not None
        assert loaded["vm_name"] == "integration-test-vm"
        assert loaded["hostname"] == "integration.example.com"
        assert loaded["vm_ip"] == "10.0.0.50"
        assert loaded["distribution"]["distribution_name"] == "FreeBSD"
        assert loaded["distribution"]["distribution_version"] == "14.0-RELEASE"

    def test_save_load_delete(self, mock_logger, tmp_path):
        """Test full workflow: save, load, delete."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            # Save
            save_result = save_bhyve_metadata(
                vm_name="workflow-test-vm",
                hostname="workflow.example.com",
                distribution="Ubuntu 22.04",
                vm_ip="192.168.1.50",
                logger=mock_logger,
            )
            assert save_result is True

            # Load
            loaded = load_bhyve_metadata("workflow-test-vm", mock_logger)
            assert loaded is not None

            # Delete
            delete_result = delete_bhyve_metadata("workflow-test-vm", mock_logger)
            assert delete_result is True

            # Verify deleted
            loaded_after_delete = load_bhyve_metadata("workflow-test-vm", mock_logger)
            assert loaded_after_delete is None

    def test_multiple_vms_metadata(self, mock_logger, tmp_path):
        """Test managing metadata for multiple VMs."""
        metadata_dir = tmp_path / "metadata"
        metadata_dir.mkdir()

        vm_data = [
            ("vm1", "vm1.example.com", "FreeBSD 14", "192.168.1.1"),
            ("vm2", "vm2.example.com", "Ubuntu 22.04", "192.168.1.2"),
            ("vm3", "vm3.example.com", "Debian 12", "192.168.1.3"),
        ]

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_metadata.BHYVE_METADATA_DIR",
            str(metadata_dir),
        ):
            # Save all VMs
            for vm_name, hostname, distribution, vm_ip in vm_data:
                result = save_bhyve_metadata(
                    vm_name=vm_name,
                    hostname=hostname,
                    distribution=distribution,
                    vm_ip=vm_ip,
                    logger=mock_logger,
                )
                assert result is True

            # Verify all can be loaded
            for vm_name, hostname, distribution, vm_ip in vm_data:
                loaded = load_bhyve_metadata(vm_name, mock_logger)
                assert loaded is not None
                assert loaded["hostname"] == hostname
                assert loaded["vm_ip"] == vm_ip

            # Delete one
            delete_bhyve_metadata("vm2", mock_logger)

            # Verify vm2 is gone but others remain
            assert load_bhyve_metadata("vm1", mock_logger) is not None
            assert load_bhyve_metadata("vm2", mock_logger) is None
            assert load_bhyve_metadata("vm3", mock_logger) is not None
