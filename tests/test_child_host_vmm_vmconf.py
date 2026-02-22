"""
Unit tests for src.sysmanage_agent.operations.child_host_vmm_vmconf module.
Tests VmConfManager class for /etc/vm.conf management on OpenBSD.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import subprocess
from pathlib import Path
from unittest.mock import Mock, mock_open, patch, MagicMock

from src.sysmanage_agent.operations.child_host_vmm_vmconf import VmConfManager


class TestVmConfManagerInit:
    """Test cases for VmConfManager initialization."""

    def test_init_with_logger(self):
        """Test VmConfManager initialization with logger."""
        mock_logger = Mock()
        manager = VmConfManager(mock_logger)
        assert manager.logger == mock_logger

    def test_vm_conf_path(self):
        """Test VM_CONF_PATH is correctly set."""
        mock_logger = Mock()
        manager = VmConfManager(mock_logger)
        assert str(manager.VM_CONF_PATH) == "/etc/vm.conf"


class TestPersistVm:
    """Test cases for persist_vm method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_persist_vm_new_vm_success(self):
        """Test persisting a new VM to vm.conf."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="1G",
                        enable=True,
                    )

        assert result is True
        # Verify file was opened for reading and appending
        assert mock_file.call_count == 2

    def test_persist_vm_already_defined(self):
        """Test persisting a VM that is already defined."""
        mock_file_content = (
            'vm "test-vm" {\n    memory 1G\n    disk "/var/vmm/test-vm.qcow2"\n}\n'
        )
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.persist_vm(
                    vm_name="test-vm",
                    disk_path="/var/vmm/test-vm.qcow2",
                    memory="1G",
                )

        assert result is True
        self.mock_logger.info.assert_called()

    def test_persist_vm_new_file(self):
        """Test persisting VM when vm.conf doesn't exist."""
        mock_file = mock_open()

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = False

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="1G",
                    )

        assert result is True

    def test_persist_vm_with_boot_device(self):
        """Test persisting VM with boot device specified."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="2G",
                        enable=False,
                        boot_device="/bsd.rd",
                    )

        assert result is True
        # Verify the boot line was included in the write
        handle = mock_file()
        write_calls = handle.write.call_args_list
        written_content = "".join(call[0][0] for call in write_calls)
        assert 'boot "/bsd.rd"' in written_content

    def test_persist_vm_without_enable(self):
        """Test persisting VM with enable=False."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="1G",
                        enable=False,
                    )

        assert result is True
        # Verify enable was not included
        handle = mock_file()
        write_calls = handle.write.call_args_list
        written_content = "".join(call[0][0] for call in write_calls)
        assert "    enable\n" not in written_content

    def test_persist_vm_with_enable(self):
        """Test persisting VM with enable=True."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="1G",
                        enable=True,
                    )

        assert result is True
        # Verify enable was included
        handle = mock_file()
        write_calls = handle.write.call_args_list
        written_content = "".join(call[0][0] for call in write_calls)
        assert "    enable\n" in written_content

    def test_persist_vm_exception_handling(self):
        """Test persist_vm handles exceptions gracefully."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.side_effect = Exception("Test error")

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            result = self.manager.persist_vm(
                vm_name="test-vm",
                disk_path="/var/vmm/test-vm.qcow2",
                memory="1G",
            )

        assert result is False
        self.mock_logger.error.assert_called()

    def test_persist_vm_file_read_error(self):
        """Test persist_vm handles file read errors."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch(
                "builtins.open", side_effect=PermissionError("Permission denied")
            ):
                result = self.manager.persist_vm(
                    vm_name="test-vm",
                    disk_path="/var/vmm/test-vm.qcow2",
                    memory="1G",
                )

        assert result is False
        self.mock_logger.error.assert_called()


class TestRemoveVm:
    """Test cases for remove_vm method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_remove_vm_not_found_no_file(self):
        """Test removing VM when vm.conf doesn't exist."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = False

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            result = self.manager.remove_vm("test-vm")

        assert result is True

    def test_remove_vm_success(self):
        """Test removing VM from vm.conf."""
        mock_file_content = """switch "local" {
    interface bridge0
}

vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    interface { switch "local" }
    owner root
    enable
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.remove_vm("test-vm")

        assert result is True
        self.mock_logger.info.assert_called()

    def test_remove_vm_not_defined(self):
        """Test removing VM that doesn't exist in vm.conf."""
        mock_file_content = """switch "local" {
    interface bridge0
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.remove_vm("nonexistent-vm")

        assert result is True

    def test_remove_vm_with_nested_braces(self):
        """Test removing VM that has nested braces (interface block)."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    interface { switch "local" }
    owner root
    enable
}

vm "other-vm" {
    memory 2G
    disk "/var/vmm/other-vm.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.remove_vm("test-vm")

        assert result is True

    def test_remove_vm_exception_handling(self):
        """Test remove_vm handles exceptions gracefully."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", side_effect=Exception("Test error")):
                result = self.manager.remove_vm("test-vm")

        assert result is False
        self.mock_logger.error.assert_called()

    def test_remove_vm_permission_error(self):
        """Test remove_vm handles permission errors."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch(
                "builtins.open", side_effect=PermissionError("Permission denied")
            ):
                result = self.manager.remove_vm("test-vm")

        assert result is False
        self.mock_logger.error.assert_called()


class TestVmDefined:
    """Test cases for vm_defined method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_vm_defined_no_file(self):
        """Test vm_defined when vm.conf doesn't exist."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = False

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            result = self.manager.vm_defined("test-vm")

        assert result is False

    def test_vm_defined_true(self):
        """Test vm_defined when VM is defined."""
        mock_file_content = 'vm "test-vm" {\n    memory 1G\n}\n'
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is True

    def test_vm_defined_false(self):
        """Test vm_defined when VM is not defined."""
        mock_file_content = 'vm "other-vm" {\n    memory 1G\n}\n'
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is False

    def test_vm_defined_exception_handling(self):
        """Test vm_defined handles exceptions gracefully."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", side_effect=Exception("Test error")):
                result = self.manager.vm_defined("test-vm")

        assert result is False

    def test_vm_defined_partial_match(self):
        """Test vm_defined doesn't match partial names."""
        mock_file_content = 'vm "test-vm-extended" {\n    memory 1G\n}\n'
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                # Should not match because we look for exact 'vm "test-vm"'
                result = self.manager.vm_defined("test-vm")

        # The check is for 'vm "test-vm"' which is not in 'vm "test-vm-extended"'
        assert result is False

    def test_vm_defined_empty_file(self):
        """Test vm_defined with empty vm.conf."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is False


class TestRemoveBootDevice:
    """Test cases for remove_boot_device method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_remove_boot_device_no_file(self):
        """Test remove_boot_device when vm.conf doesn't exist."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = False

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            result = self.manager.remove_boot_device("test-vm")

        assert result is False

    def test_remove_boot_device_success(self):
        """Test removing boot device from VM definition."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    boot "/bsd.rd"
    interface { switch "local" }
    owner root
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.remove_boot_device("test-vm")

        assert result is True
        self.mock_logger.info.assert_called()

    def test_remove_boot_device_no_boot_line(self):
        """Test remove_boot_device when no boot line exists."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    interface { switch "local" }
    owner root
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.remove_boot_device("test-vm")

        assert result is True
        # Verify info message about no boot device to remove
        self.mock_logger.info.assert_called()

    def test_remove_boot_device_vm_not_found(self):
        """Test remove_boot_device when VM is not in vm.conf."""
        mock_file_content = """vm "other-vm" {
    memory 1G
    disk "/var/vmm/other-vm.qcow2"
    boot "/bsd.rd"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.remove_boot_device("test-vm")

        # Returns True because no boot device to remove
        assert result is True

    def test_remove_boot_device_exception_handling(self):
        """Test remove_boot_device handles exceptions gracefully."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", side_effect=Exception("Test error")):
                result = self.manager.remove_boot_device("test-vm")

        assert result is False
        self.mock_logger.error.assert_called()

    def test_remove_boot_device_only_from_correct_vm(self):
        """Test that boot device is only removed from the correct VM."""
        mock_file_content = """vm "other-vm" {
    memory 2G
    boot "/bsd.rd"
}

vm "test-vm" {
    memory 1G
    boot "/bsd.rd"
}
"""
        mock_file = mock_open(read_data=mock_file_content)
        written_content = []

        def write_capture(content):
            written_content.append(content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                mock_file.return_value.write = write_capture
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.remove_boot_device("test-vm")

        assert result is True


class TestEnableVm:
    """Test cases for enable_vm method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_enable_vm_no_file(self):
        """Test enable_vm when vm.conf doesn't exist."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = False

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            result = self.manager.enable_vm("test-vm")

        assert result is False
        self.mock_logger.error.assert_called()

    def test_enable_vm_vm_not_found(self):
        """Test enable_vm when VM is not defined."""
        mock_file_content = """vm "other-vm" {
    memory 1G
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.enable_vm("test-vm")

        assert result is False
        self.mock_logger.error.assert_called()

    def test_enable_vm_already_enabled(self):
        """Test enable_vm when VM is already enabled."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    enable
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.enable_vm("test-vm")

        assert result is True
        self.mock_logger.info.assert_called()

    def test_enable_vm_success(self):
        """Test successfully enabling a VM."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    owner root
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.enable_vm("test-vm")

        assert result is True
        self.mock_logger.info.assert_called()

    def test_enable_vm_exception_handling(self):
        """Test enable_vm handles exceptions gracefully."""
        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", side_effect=Exception("Test error")):
                result = self.manager.enable_vm("test-vm")

        assert result is False
        self.mock_logger.error.assert_called()

    def test_enable_vm_no_match(self):
        """Test enable_vm when regex doesn't match."""
        # This tests the case where VM is mentioned but pattern doesn't match
        mock_file_content = 'vm "test-vm"'  # Malformed - no braces
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.enable_vm("test-vm")

        assert result is False


class TestReloadVmd:
    """Test cases for _reload_vmd method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_reload_vmd_success(self):
        """Test successful vmd reload."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "vmd reloaded"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = self.manager._reload_vmd()

        assert result["success"] is True
        mock_run.assert_called_once_with(
            ["rcctl", "reload", "vmd"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_reload_vmd_failure(self):
        """Test vmd reload failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "vmd: not running"

        with patch("subprocess.run", return_value=mock_result):
            result = self.manager._reload_vmd()

        assert result["success"] is False
        assert "error" in result
        self.mock_logger.warning.assert_called()

    def test_reload_vmd_failure_stdout_only(self):
        """Test vmd reload failure with only stdout message."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "vmd failed"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.manager._reload_vmd()

        assert result["success"] is False
        assert result["error"] == "vmd failed"

    def test_reload_vmd_timeout(self):
        """Test vmd reload timeout."""
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("rcctl", 30)
        ):
            result = self.manager._reload_vmd()

        assert result["success"] is False
        assert result["error"] == "timeout"
        self.mock_logger.warning.assert_called()

    def test_reload_vmd_exception(self):
        """Test vmd reload with unexpected exception."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = self.manager._reload_vmd()

        assert result["success"] is False
        assert "Unexpected error" in result["error"]
        self.mock_logger.warning.assert_called()

    def test_reload_vmd_permission_error(self):
        """Test vmd reload with permission error."""
        with patch("subprocess.run", side_effect=PermissionError("Permission denied")):
            result = self.manager._reload_vmd()

        assert result["success"] is False
        assert "Permission denied" in result["error"]


class TestVmConfManagerIntegration:
    """Integration-style tests for VmConfManager."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_persist_then_remove_vm(self):
        """Test persisting and then removing a VM."""
        # First, persist a new VM
        persist_content = ""
        mock_persist_file = mock_open(read_data=persist_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_persist_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    persist_result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="1G",
                    )

        assert persist_result is True

    def test_vm_definition_format(self):
        """Test that VM definition is formatted correctly."""
        mock_file_content = ""
        written_data = []

        def mock_write(data):
            written_data.append(data)

        mock_file = mock_open(read_data=mock_file_content)
        mock_file.return_value.write = mock_write

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    self.manager.persist_vm(
                        vm_name="my-vm",
                        disk_path="/var/vmm/my-vm.qcow2",
                        memory="2G",
                        enable=True,
                        boot_device="/bsd.rd",
                    )

        # Check the written content
        content = "".join(written_data)
        assert 'vm "my-vm"' in content
        assert "memory 2G" in content
        assert 'disk "/var/vmm/my-vm.qcow2"' in content
        assert 'boot "/bsd.rd"' in content
        assert 'interface { switch "local" }' in content
        assert "owner root" in content
        assert "enable" in content

    def test_special_characters_in_vm_name(self):
        """Test handling VM names with special regex characters."""
        mock_file_content = """vm "vm.test+name" {
    memory 1G
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("vm.test+name")

        assert result is True

    def test_remove_vm_with_special_characters(self):
        """Test removing VM with special regex characters in name."""
        mock_file_content = """vm "vm.test+name" {
    memory 1G
    disk "/var/vmm/test.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.remove_vm("vm.test+name")

        assert result is True

    def test_enable_vm_with_special_characters(self):
        """Test enabling VM with special regex characters in name."""
        mock_file_content = """vm "vm.test+name" {
    memory 1G
    disk "/var/vmm/test.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.enable_vm("vm.test+name")

        assert result is True


class TestEdgeCases:
    """Edge case tests for VmConfManager."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_empty_vm_name(self):
        """Test handling empty VM name."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("")

        assert result is False

    def test_whitespace_only_file(self):
        """Test handling vm.conf with only whitespace."""
        mock_file_content = "   \n\t\n   "
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is False

    def test_multiple_vms_in_file(self):
        """Test handling multiple VMs in vm.conf."""
        mock_file_content = """switch "local" {
    interface bridge0
}

vm "vm1" {
    memory 1G
    disk "/var/vmm/vm1.qcow2"
}

vm "vm2" {
    memory 2G
    disk "/var/vmm/vm2.qcow2"
}

vm "vm3" {
    memory 4G
    disk "/var/vmm/vm3.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                assert self.manager.vm_defined("vm1") is True
                assert self.manager.vm_defined("vm2") is True
                assert self.manager.vm_defined("vm3") is True
                assert self.manager.vm_defined("vm4") is False

    def test_unicode_in_paths(self):
        """Test handling unicode characters in paths."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm-\u00e9.qcow2",
                        memory="1G",
                    )

        assert result is True

    def test_large_memory_value(self):
        """Test handling large memory values."""
        mock_file_content = ""
        written_data = []

        def mock_write(data):
            written_data.append(data)

        mock_file = mock_open(read_data=mock_file_content)
        mock_file.return_value.write = mock_write

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="128G",
                    )

        assert result is True
        content = "".join(written_data)
        assert "memory 128G" in content

    def test_comments_in_vm_conf(self):
        """Test handling comments in vm.conf."""
        mock_file_content = """# This is a comment
switch "local" {
    interface bridge0
}

# VM for testing
vm "test-vm" {
    memory 1G
    # disk path
    disk "/var/vmm/test-vm.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is True

    def test_vm_with_multiple_interfaces(self):
        """Test VM definition with multiple interfaces."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    interface { switch "local" }
    interface { switch "external" }
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is True

    def test_vm_with_cdrom(self):
        """Test VM definition with cdrom device."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    cdrom "/var/vmm/install.iso"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                result = self.manager.vm_defined("test-vm")

        assert result is True

    def test_remove_boot_device_with_complex_path(self):
        """Test removing boot device with complex path."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
    boot "/bsd.rd/7.4/amd64/bsd.rd"
    interface { switch "local" }
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ):
                    result = self.manager.remove_boot_device("test-vm")

        assert result is True


class TestReloadVmdIntegration:
    """Test _reload_vmd integration with other methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.manager = VmConfManager(self.mock_logger)

    def test_persist_vm_calls_reload(self):
        """Test that persist_vm calls _reload_vmd."""
        mock_file_content = ""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ) as mock_reload:
                    self.manager.persist_vm(
                        vm_name="test-vm",
                        disk_path="/var/vmm/test-vm.qcow2",
                        memory="1G",
                    )

        mock_reload.assert_called_once()

    def test_remove_vm_calls_reload_when_changed(self):
        """Test that remove_vm calls _reload_vmd when content changes."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ) as mock_reload:
                    self.manager.remove_vm("test-vm")

        mock_reload.assert_called_once()

    def test_enable_vm_calls_reload(self):
        """Test that enable_vm calls _reload_vmd."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    disk "/var/vmm/test-vm.qcow2"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ) as mock_reload:
                    self.manager.enable_vm("test-vm")

        mock_reload.assert_called_once()

    def test_remove_boot_device_calls_reload_when_found(self):
        """Test that remove_boot_device calls _reload_vmd when boot line found."""
        mock_file_content = """vm "test-vm" {
    memory 1G
    boot "/bsd.rd"
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ) as mock_reload:
                    self.manager.remove_boot_device("test-vm")

        mock_reload.assert_called_once()

    def test_remove_boot_device_no_reload_when_not_found(self):
        """Test that remove_boot_device doesn't call _reload_vmd when no boot line."""
        mock_file_content = """vm "test-vm" {
    memory 1G
}
"""
        mock_file = mock_open(read_data=mock_file_content)

        mock_path = MagicMock(spec=Path)
        mock_path.exists.return_value = True

        with patch.object(VmConfManager, "VM_CONF_PATH", mock_path):
            with patch("builtins.open", mock_file):
                with patch.object(
                    self.manager, "_reload_vmd", return_value={"success": True}
                ) as mock_reload:
                    self.manager.remove_boot_device("test-vm")

        mock_reload.assert_not_called()
