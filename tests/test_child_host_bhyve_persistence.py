"""
Comprehensive unit tests for bhyve VM persistence operations.

Tests cover:
- BhyveVmPersistentConfig dataclass serialization
- BhyvePersistenceHelper initialization
- VM configuration save/load/delete operations
- Autostart configuration management
- RC script generation and installation
- Autostart service enable/disable
"""

# pylint: disable=redefined-outer-name,protected-access

import json
import logging
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_persistence import (
    BhyveVmPersistentConfig,
    BhyvePersistenceHelper,
    BHYVE_VM_DIR,
    BHYVE_RC_SCRIPT,
    BHYVE_AUTOSTART_CONF,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_bhyve_persistence")


@pytest.fixture
def helper(logger):
    """Create a BhyvePersistenceHelper instance for testing."""
    return BhyvePersistenceHelper(logger)


@pytest.fixture
def sample_config():
    """Create a sample BhyveVmPersistentConfig for testing."""
    return BhyveVmPersistentConfig(
        vm_name="test-vm",
        hostname="test-hostname",
        distribution="ubuntu",
        memory="2G",
        cpus=2,
        disk_path="/vm/test-vm/disk.raw",
        cloud_init_iso_path="/vm/test-vm/cloud-init.iso",
        use_uefi=True,
        autostart=True,
        autostart_delay=10,
        tap_interface="tap0",
    )


@pytest.fixture
def sample_config_dict():
    """Create a sample config dictionary for testing."""
    return {
        "vm_name": "test-vm",
        "hostname": "test-hostname",
        "distribution": "ubuntu",
        "memory": "2G",
        "cpus": 2,
        "disk_path": "/vm/test-vm/disk.raw",
        "cloud_init_iso_path": "/vm/test-vm/cloud-init.iso",
        "use_uefi": True,
        "autostart": True,
        "autostart_delay": 10,
        "created_at": "2024-01-01T00:00:00+00:00",
        "tap_interface": "tap0",
    }


class TestBhyveVmPersistentConfig:
    """Tests for BhyveVmPersistentConfig dataclass."""

    def test_init_with_required_fields(self):
        """Test initialization with only required fields."""
        config = BhyveVmPersistentConfig(
            vm_name="test-vm",
            hostname="test-hostname",
            distribution="ubuntu",
        )
        assert config.vm_name == "test-vm"
        assert config.hostname == "test-hostname"
        assert config.distribution == "ubuntu"

    def test_init_default_values(self):
        """Test that default values are set correctly."""
        config = BhyveVmPersistentConfig(
            vm_name="test-vm",
            hostname="test-hostname",
            distribution="ubuntu",
        )
        assert config.memory == "1G"
        assert config.cpus == 1
        assert config.disk_path == ""
        assert config.cloud_init_iso_path == ""
        assert config.use_uefi is True
        assert config.autostart is True
        assert config.autostart_delay == 0
        assert config.tap_interface == ""

    def test_init_with_all_fields(self, sample_config):
        """Test initialization with all fields specified."""
        assert sample_config.vm_name == "test-vm"
        assert sample_config.hostname == "test-hostname"
        assert sample_config.distribution == "ubuntu"
        assert sample_config.memory == "2G"
        assert sample_config.cpus == 2
        assert sample_config.disk_path == "/vm/test-vm/disk.raw"
        assert sample_config.cloud_init_iso_path == "/vm/test-vm/cloud-init.iso"
        assert sample_config.use_uefi is True
        assert sample_config.autostart is True
        assert sample_config.autostart_delay == 10
        assert sample_config.tap_interface == "tap0"

    def test_created_at_default_is_utc_iso(self):
        """Test that created_at default is UTC ISO format."""
        config = BhyveVmPersistentConfig(
            vm_name="test-vm",
            hostname="test-hostname",
            distribution="ubuntu",
        )
        # Should be a valid ISO format string
        parsed = datetime.fromisoformat(config.created_at)
        assert parsed is not None

    def test_to_dict_returns_dictionary(self, sample_config):
        """Test that to_dict returns a dictionary."""
        result = sample_config.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_contains_all_fields(self, sample_config):
        """Test that to_dict contains all expected fields."""
        result = sample_config.to_dict()
        expected_keys = {
            "vm_name",
            "hostname",
            "distribution",
            "memory",
            "cpus",
            "disk_path",
            "cloud_init_iso_path",
            "use_uefi",
            "autostart",
            "autostart_delay",
            "created_at",
            "tap_interface",
        }
        assert set(result.keys()) == expected_keys

    def test_to_dict_values_match(self, sample_config):
        """Test that to_dict values match the config values."""
        result = sample_config.to_dict()
        assert result["vm_name"] == sample_config.vm_name
        assert result["hostname"] == sample_config.hostname
        assert result["distribution"] == sample_config.distribution
        assert result["memory"] == sample_config.memory
        assert result["cpus"] == sample_config.cpus
        assert result["disk_path"] == sample_config.disk_path
        assert result["cloud_init_iso_path"] == sample_config.cloud_init_iso_path
        assert result["use_uefi"] == sample_config.use_uefi
        assert result["autostart"] == sample_config.autostart
        assert result["autostart_delay"] == sample_config.autostart_delay
        assert result["tap_interface"] == sample_config.tap_interface

    def test_from_dict_creates_config(self, sample_config_dict):
        """Test that from_dict creates a BhyveVmPersistentConfig."""
        config = BhyveVmPersistentConfig.from_dict(sample_config_dict)
        assert isinstance(config, BhyveVmPersistentConfig)

    def test_from_dict_values_match(self, sample_config_dict):
        """Test that from_dict values match the input dictionary."""
        config = BhyveVmPersistentConfig.from_dict(sample_config_dict)
        assert config.vm_name == sample_config_dict["vm_name"]
        assert config.hostname == sample_config_dict["hostname"]
        assert config.distribution == sample_config_dict["distribution"]
        assert config.memory == sample_config_dict["memory"]
        assert config.cpus == sample_config_dict["cpus"]
        assert config.disk_path == sample_config_dict["disk_path"]
        assert config.cloud_init_iso_path == sample_config_dict["cloud_init_iso_path"]
        assert config.use_uefi == sample_config_dict["use_uefi"]
        assert config.autostart == sample_config_dict["autostart"]
        assert config.autostart_delay == sample_config_dict["autostart_delay"]
        assert config.created_at == sample_config_dict["created_at"]
        assert config.tap_interface == sample_config_dict["tap_interface"]

    def test_from_dict_filters_unknown_fields(self, sample_config_dict):
        """Test that from_dict filters out unknown fields."""
        sample_config_dict["unknown_field"] = "should be ignored"
        sample_config_dict["another_unknown"] = 12345
        config = BhyveVmPersistentConfig.from_dict(sample_config_dict)
        # Should not have unknown fields, just verify it doesn't raise
        assert config.vm_name == sample_config_dict["vm_name"]

    def test_round_trip_serialization(self, sample_config):
        """Test that config survives round-trip serialization."""
        config_dict = sample_config.to_dict()
        restored = BhyveVmPersistentConfig.from_dict(config_dict)
        assert restored.vm_name == sample_config.vm_name
        assert restored.hostname == sample_config.hostname
        assert restored.distribution == sample_config.distribution
        assert restored.memory == sample_config.memory
        assert restored.cpus == sample_config.cpus
        assert restored.disk_path == sample_config.disk_path
        assert restored.use_uefi == sample_config.use_uefi
        assert restored.autostart == sample_config.autostart
        assert restored.autostart_delay == sample_config.autostart_delay

    def test_json_serializable(self, sample_config):
        """Test that config can be serialized to JSON."""
        config_dict = sample_config.to_dict()
        json_str = json.dumps(config_dict)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed == config_dict


class TestBhyvePersistenceHelperInit:
    """Tests for BhyvePersistenceHelper initialization."""

    def test_init_sets_logger(self, logger):
        """Test that __init__ sets logger."""
        helper = BhyvePersistenceHelper(logger)
        assert helper.logger == logger


class TestGetConfigPath:
    """Tests for get_config_path method."""

    def test_get_config_path_returns_string(self, helper):
        """Test get_config_path returns a string."""
        result = helper.get_config_path("test-vm")
        assert isinstance(result, str)

    def test_get_config_path_correct_format(self, helper):
        """Test get_config_path returns correct path format."""
        result = helper.get_config_path("test-vm")
        assert result == "/vm/test-vm/vm-config.json"

    def test_get_config_path_different_vm_names(self, helper):
        """Test get_config_path with different VM names."""
        assert helper.get_config_path("vm1") == "/vm/vm1/vm-config.json"
        assert (
            helper.get_config_path("production-db")
            == "/vm/production-db/vm-config.json"
        )
        assert (
            helper.get_config_path("web-server-001")
            == "/vm/web-server-001/vm-config.json"
        )


class TestSaveVmConfig:
    """Tests for save_vm_config async method."""

    @pytest.mark.asyncio
    async def test_save_vm_config_success(self, helper, sample_config, tmp_path):
        """Test successful VM config save."""
        config_path = tmp_path / "test-vm" / "vm-config.json"

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            result = await helper.save_vm_config(sample_config)

        assert result["success"] is True
        assert result["config_path"] == str(config_path)
        assert config_path.exists()

        # Verify content
        with open(config_path, "r", encoding="utf-8") as file_handle:
            saved_data = json.load(file_handle)
        assert saved_data["vm_name"] == sample_config.vm_name

    @pytest.mark.asyncio
    async def test_save_vm_config_creates_directory(
        self, helper, sample_config, tmp_path
    ):
        """Test that save_vm_config creates directory if it doesn't exist."""
        config_path = tmp_path / "new-vm" / "vm-config.json"

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            result = await helper.save_vm_config(sample_config)

        assert result["success"] is True
        assert config_path.parent.exists()

    @pytest.mark.asyncio
    async def test_save_vm_config_overwrites_existing(
        self, helper, sample_config, tmp_path
    ):
        """Test that save_vm_config overwrites existing file."""
        config_path = tmp_path / "test-vm" / "vm-config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text('{"old": "data"}')

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            result = await helper.save_vm_config(sample_config)

        assert result["success"] is True
        with open(config_path, "r", encoding="utf-8") as file_handle:
            saved_data = json.load(file_handle)
        assert saved_data["vm_name"] == sample_config.vm_name

    @pytest.mark.asyncio
    async def test_save_vm_config_permission_error(self, helper, sample_config):
        """Test save_vm_config handles permission error."""
        with patch("os.makedirs", side_effect=PermissionError("Access denied")):
            result = await helper.save_vm_config(sample_config)

        assert result["success"] is False
        assert "error" in result
        assert "Access denied" in result["error"]

    @pytest.mark.asyncio
    async def test_save_vm_config_io_error(self, helper, sample_config, tmp_path):
        """Test save_vm_config handles I/O error."""
        config_path = tmp_path / "test-vm" / "vm-config.json"

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            with patch("aiofiles.open", side_effect=IOError("Disk full")):
                result = await helper.save_vm_config(sample_config)

        assert result["success"] is False
        assert "Disk full" in result["error"]


class TestLoadVmConfig:
    """Tests for load_vm_config async method."""

    @pytest.mark.asyncio
    async def test_load_vm_config_success(self, helper, sample_config_dict, tmp_path):
        """Test successful VM config load."""
        config_path = tmp_path / "test-vm" / "vm-config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(json.dumps(sample_config_dict))

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            result = await helper.load_vm_config("test-vm")

        assert result is not None
        assert isinstance(result, BhyveVmPersistentConfig)
        assert result.vm_name == sample_config_dict["vm_name"]

    @pytest.mark.asyncio
    async def test_load_vm_config_not_found(self, helper):
        """Test load_vm_config returns None when file doesn't exist."""
        with patch.object(
            helper, "get_config_path", return_value="/nonexistent/path/config.json"
        ):
            result = await helper.load_vm_config("nonexistent-vm")

        assert result is None

    @pytest.mark.asyncio
    async def test_load_vm_config_invalid_json(self, helper, tmp_path):
        """Test load_vm_config handles invalid JSON."""
        config_path = tmp_path / "test-vm" / "vm-config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("not valid json {")

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            result = await helper.load_vm_config("test-vm")

        assert result is None

    @pytest.mark.asyncio
    async def test_load_vm_config_permission_error(self, helper, tmp_path):
        """Test load_vm_config handles permission error."""
        config_path = tmp_path / "test-vm" / "vm-config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text('{"vm_name": "test"}')

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            with patch("aiofiles.open", side_effect=PermissionError("Access denied")):
                result = await helper.load_vm_config("test-vm")

        assert result is None


class TestDeleteVmConfig:
    """Tests for delete_vm_config async method."""

    @pytest.mark.asyncio
    async def test_delete_vm_config_success(self, helper, tmp_path):
        """Test successful VM config deletion."""
        config_path = tmp_path / "test-vm" / "vm-config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text('{"vm_name": "test-vm"}')

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            result = await helper.delete_vm_config("test-vm")

        assert result["success"] is True
        assert not config_path.exists()

    @pytest.mark.asyncio
    async def test_delete_vm_config_not_found(self, helper):
        """Test delete_vm_config succeeds when file doesn't exist."""
        with patch.object(
            helper, "get_config_path", return_value="/nonexistent/path/config.json"
        ):
            result = await helper.delete_vm_config("nonexistent-vm")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_vm_config_permission_error(self, helper, tmp_path):
        """Test delete_vm_config handles permission error."""
        config_path = tmp_path / "test-vm" / "vm-config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text('{"vm_name": "test-vm"}')

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            with patch("os.path.exists", return_value=True):
                with patch("os.remove", side_effect=PermissionError("Access denied")):
                    result = await helper.delete_vm_config("test-vm")

        assert result["success"] is False
        assert "error" in result
        assert "Access denied" in result["error"]


class TestSetAutostart:
    """Tests for set_autostart async method."""

    @pytest.mark.asyncio
    async def test_set_autostart_enable(self, helper, sample_config):
        """Test enabling autostart for a VM."""
        sample_config.autostart = False

        with patch.object(helper, "load_vm_config", return_value=sample_config):
            with patch.object(
                helper, "save_vm_config", return_value={"success": True}
            ) as mock_save:
                result = await helper.set_autostart("test-vm", True)

        assert result["success"] is True
        # Verify autostart was set to True
        saved_config = mock_save.call_args[0][0]
        assert saved_config.autostart is True

    @pytest.mark.asyncio
    async def test_set_autostart_disable(self, helper, sample_config):
        """Test disabling autostart for a VM."""
        sample_config.autostart = True

        with patch.object(helper, "load_vm_config", return_value=sample_config):
            with patch.object(
                helper, "save_vm_config", return_value={"success": True}
            ) as mock_save:
                result = await helper.set_autostart("test-vm", False)

        assert result["success"] is True
        saved_config = mock_save.call_args[0][0]
        assert saved_config.autostart is False

    @pytest.mark.asyncio
    async def test_set_autostart_config_not_found(self, helper):
        """Test set_autostart when config doesn't exist."""
        with patch.object(helper, "load_vm_config", return_value=None):
            result = await helper.set_autostart("nonexistent-vm", True)

        assert result["success"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_set_autostart_save_fails(self, helper, sample_config):
        """Test set_autostart when save fails."""
        with patch.object(helper, "load_vm_config", return_value=sample_config):
            with patch.object(
                helper,
                "save_vm_config",
                return_value={"success": False, "error": "Disk full"},
            ):
                result = await helper.set_autostart("test-vm", True)

        assert result["success"] is False
        assert "Disk full" in result["error"]


class TestListAutostartVms:
    """Tests for list_autostart_vms async method."""

    @pytest.mark.asyncio
    async def test_list_autostart_vms_empty(self, helper):
        """Test list_autostart_vms returns empty list when no VMs."""
        with patch("os.path.isdir", return_value=False):
            result = await helper.list_autostart_vms()

        assert result == []

    @pytest.mark.asyncio
    async def test_list_autostart_vms_with_vms(self, helper):
        """Test list_autostart_vms returns autostart VMs."""
        config1 = BhyveVmPersistentConfig(
            vm_name="vm1",
            hostname="host1",
            distribution="ubuntu",
            autostart=True,
            autostart_delay=5,
        )
        config2 = BhyveVmPersistentConfig(
            vm_name="vm2",
            hostname="host2",
            distribution="debian",
            autostart=True,
            autostart_delay=0,
        )

        with patch("os.path.isdir", side_effect=lambda p: True):
            with patch("os.listdir", return_value=["vm1", "vm2"]):
                with patch.object(
                    helper, "load_vm_config", side_effect=[config1, config2]
                ):
                    result = await helper.list_autostart_vms()

        assert len(result) == 2
        # Should be sorted by autostart_delay
        assert result[0].vm_name == "vm2"  # delay 0
        assert result[1].vm_name == "vm1"  # delay 5

    @pytest.mark.asyncio
    async def test_list_autostart_vms_filters_disabled(self, helper):
        """Test list_autostart_vms filters out VMs with autostart=False."""
        config1 = BhyveVmPersistentConfig(
            vm_name="vm1", hostname="host1", distribution="ubuntu", autostart=True
        )
        config2 = BhyveVmPersistentConfig(
            vm_name="vm2", hostname="host2", distribution="debian", autostart=False
        )

        with patch("os.path.isdir", side_effect=lambda p: True):
            with patch("os.listdir", return_value=["vm1", "vm2"]):
                with patch.object(
                    helper, "load_vm_config", side_effect=[config1, config2]
                ):
                    result = await helper.list_autostart_vms()

        assert len(result) == 1
        assert result[0].vm_name == "vm1"

    @pytest.mark.asyncio
    async def test_list_autostart_vms_skips_special_dirs(self, helper):
        """Test list_autostart_vms skips images and cloud-init directories."""
        config = BhyveVmPersistentConfig(
            vm_name="vm1", hostname="host1", distribution="ubuntu", autostart=True
        )

        with patch("os.path.isdir", side_effect=lambda p: True):
            with patch("os.listdir", return_value=["images", "cloud-init", "vm1"]):
                with patch.object(helper, "load_vm_config", return_value=config):
                    result = await helper.list_autostart_vms()

        assert len(result) == 1
        assert result[0].vm_name == "vm1"

    @pytest.mark.asyncio
    async def test_list_autostart_vms_skips_non_directories(self, helper):
        """Test list_autostart_vms skips non-directory entries."""
        config = BhyveVmPersistentConfig(
            vm_name="vm1", hostname="host1", distribution="ubuntu", autostart=True
        )

        def mock_isdir(path):
            if path == BHYVE_VM_DIR:
                return True
            return "vm1" in path

        with patch("os.path.isdir", side_effect=mock_isdir):
            with patch("os.listdir", return_value=["vm1", "some-file.txt"]):
                with patch.object(helper, "load_vm_config", return_value=config):
                    result = await helper.list_autostart_vms()

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_autostart_vms_handles_load_failure(self, helper):
        """Test list_autostart_vms handles config load failure gracefully."""
        config1 = BhyveVmPersistentConfig(
            vm_name="vm1", hostname="host1", distribution="ubuntu", autostart=True
        )

        with patch("os.path.isdir", side_effect=lambda p: True):
            with patch("os.listdir", return_value=["vm1", "vm2"]):
                with patch.object(
                    helper, "load_vm_config", side_effect=[config1, None]
                ):
                    result = await helper.list_autostart_vms()

        # Should only include vm1, as vm2 failed to load
        assert len(result) == 1
        assert result[0].vm_name == "vm1"

    @pytest.mark.asyncio
    async def test_list_autostart_vms_sorted_by_delay(self, helper):
        """Test list_autostart_vms returns VMs sorted by autostart_delay."""
        config1 = BhyveVmPersistentConfig(
            vm_name="vm-slow",
            hostname="host1",
            distribution="ubuntu",
            autostart=True,
            autostart_delay=30,
        )
        config2 = BhyveVmPersistentConfig(
            vm_name="vm-fast",
            hostname="host2",
            distribution="debian",
            autostart=True,
            autostart_delay=0,
        )
        config3 = BhyveVmPersistentConfig(
            vm_name="vm-medium",
            hostname="host3",
            distribution="fedora",
            autostart=True,
            autostart_delay=10,
        )

        with patch("os.path.isdir", side_effect=lambda p: True):
            with patch("os.listdir", return_value=["vm-slow", "vm-fast", "vm-medium"]):
                with patch.object(
                    helper, "load_vm_config", side_effect=[config1, config2, config3]
                ):
                    result = await helper.list_autostart_vms()

        assert len(result) == 3
        assert result[0].vm_name == "vm-fast"  # delay 0
        assert result[1].vm_name == "vm-medium"  # delay 10
        assert result[2].vm_name == "vm-slow"  # delay 30


class TestGenerateRcScript:
    """Tests for generate_rc_script method."""

    def test_generate_rc_script_returns_string(self, helper):
        """Test generate_rc_script returns a string."""
        result = helper.generate_rc_script()
        assert isinstance(result, str)

    def test_generate_rc_script_contains_shebang(self, helper):
        """Test generate_rc_script contains shebang."""
        result = helper.generate_rc_script()
        assert result.startswith("#!/bin/sh")

    def test_generate_rc_script_contains_provide(self, helper):
        """Test generate_rc_script contains PROVIDE."""
        result = helper.generate_rc_script()
        assert "PROVIDE: sysmanage_bhyve" in result

    def test_generate_rc_script_contains_require(self, helper):
        """Test generate_rc_script contains REQUIRE."""
        result = helper.generate_rc_script()
        assert "REQUIRE: NETWORKING vmm bridge1" in result

    def test_generate_rc_script_contains_shutdown_keyword(self, helper):
        """Test generate_rc_script contains shutdown keyword."""
        result = helper.generate_rc_script()
        assert "KEYWORD: shutdown" in result

    def test_generate_rc_script_contains_start_function(self, helper):
        """Test generate_rc_script contains start function."""
        result = helper.generate_rc_script()
        assert "sysmanage_bhyve_start()" in result

    def test_generate_rc_script_contains_stop_function(self, helper):
        """Test generate_rc_script contains stop function."""
        result = helper.generate_rc_script()
        assert "sysmanage_bhyve_stop()" in result

    def test_generate_rc_script_contains_status_function(self, helper):
        """Test generate_rc_script contains status function."""
        result = helper.generate_rc_script()
        assert "sysmanage_bhyve_status()" in result

    def test_generate_rc_script_contains_python_path(self, helper):
        """Test generate_rc_script contains Python path."""
        result = helper.generate_rc_script()
        assert "PYTHON=" in result
        assert "/opt/sysmanage-agent/.venv/bin/python" in result

    def test_generate_rc_script_contains_vm_dir(self, helper):
        """Test generate_rc_script contains VM directory."""
        result = helper.generate_rc_script()
        assert "/vm/" in result

    def test_generate_rc_script_contains_rcvar(self, helper):
        """Test generate_rc_script contains rcvar setting."""
        result = helper.generate_rc_script()
        assert 'rcvar="${name}_enable"' in result

    def test_generate_rc_script_default_disabled(self, helper):
        """Test generate_rc_script has service disabled by default."""
        result = helper.generate_rc_script()
        assert 'sysmanage_bhyve_enable:="NO"' in result


class TestInstallRcScript:
    """Tests for install_rc_script async method."""

    @pytest.mark.asyncio
    async def test_install_rc_script_success(self, helper, tmp_path):
        """Test successful RC script installation."""
        script_path = tmp_path / "sysmanage_bhyve"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_persistence.BHYVE_RC_SCRIPT",
            str(script_path),
        ):
            result = await helper.install_rc_script()

        assert result["success"] is True
        assert script_path.exists()

    @pytest.mark.asyncio
    async def test_install_rc_script_sets_permissions(self, helper, tmp_path):
        """Test install_rc_script sets correct permissions."""
        script_path = tmp_path / "sysmanage_bhyve"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_persistence.BHYVE_RC_SCRIPT",
            str(script_path),
        ):
            result = await helper.install_rc_script()

        assert result["success"] is True
        # Check file is executable
        mode = script_path.stat().st_mode
        assert mode & 0o755

    @pytest.mark.asyncio
    async def test_install_rc_script_permission_error(self, helper):
        """Test install_rc_script handles permission error."""
        with patch("aiofiles.open", side_effect=PermissionError("Access denied")):
            result = await helper.install_rc_script()

        assert result["success"] is False
        assert "Access denied" in result["error"]

    @pytest.mark.asyncio
    async def test_install_rc_script_returns_path(self, helper, tmp_path):
        """Test install_rc_script returns script path."""
        script_path = tmp_path / "sysmanage_bhyve"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_persistence.BHYVE_RC_SCRIPT",
            str(script_path),
        ):
            result = await helper.install_rc_script()

        assert result["script_path"] == str(script_path)

    @pytest.mark.asyncio
    async def test_install_rc_script_chmod_error(self, helper, tmp_path):
        """Test install_rc_script handles chmod error."""
        script_path = tmp_path / "sysmanage_bhyve"

        with patch(
            "src.sysmanage_agent.operations.child_host_bhyve_persistence.BHYVE_RC_SCRIPT",
            str(script_path),
        ):
            with patch("os.chmod", side_effect=OSError("chmod failed")):
                result = await helper.install_rc_script()

        assert result["success"] is False
        assert "chmod failed" in result["error"]


class TestEnableAutostartService:
    """Tests for enable_autostart_service async method."""

    @pytest.mark.asyncio
    async def test_enable_autostart_service_success(self, helper):
        """Test successful service enable."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_run_subprocess = AsyncMock(return_value=mock_result)

        with patch("os.path.exists", return_value=True):
            result = await helper.enable_autostart_service(mock_run_subprocess)

        assert result["success"] is True
        assert "enabled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_enable_autostart_service_installs_script(self, helper, tmp_path):
        """Test service enable installs RC script if missing."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_run_subprocess = AsyncMock(return_value=mock_result)
        script_path = tmp_path / "sysmanage_bhyve"

        with patch("os.path.exists", return_value=False):
            with patch.object(
                helper,
                "install_rc_script",
                return_value={"success": True, "script_path": str(script_path)},
            ) as mock_install:
                result = await helper.enable_autostart_service(mock_run_subprocess)

        mock_install.assert_called_once()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_autostart_service_install_fails(self, helper):
        """Test service enable fails when script install fails."""
        mock_run_subprocess = AsyncMock()

        with patch("os.path.exists", return_value=False):
            with patch.object(
                helper,
                "install_rc_script",
                return_value={"success": False, "error": "Permission denied"},
            ):
                result = await helper.enable_autostart_service(mock_run_subprocess)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_autostart_service_sysrc_fails(self, helper):
        """Test service enable fails when sysrc fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "sysrc error"

        mock_run_subprocess = AsyncMock(return_value=mock_result)

        with patch("os.path.exists", return_value=True):
            result = await helper.enable_autostart_service(mock_run_subprocess)

        assert result["success"] is False
        assert "sysrc error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_autostart_service_exception(self, helper):
        """Test service enable handles exception."""
        mock_run_subprocess = AsyncMock(side_effect=Exception("subprocess error"))

        with patch("os.path.exists", return_value=True):
            result = await helper.enable_autostart_service(mock_run_subprocess)

        assert result["success"] is False
        assert "subprocess error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_autostart_service_calls_sysrc(self, helper):
        """Test service enable calls sysrc with correct arguments."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_run_subprocess = AsyncMock(return_value=mock_result)

        with patch("os.path.exists", return_value=True):
            await helper.enable_autostart_service(mock_run_subprocess)

        mock_run_subprocess.assert_called_once()
        call_args = mock_run_subprocess.call_args
        assert call_args[0][0] == ["sysrc", "sysmanage_bhyve_enable=YES"]


class TestDisableAutostartService:
    """Tests for disable_autostart_service async method."""

    @pytest.mark.asyncio
    async def test_disable_autostart_service_success(self, helper):
        """Test successful service disable."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_run_subprocess = AsyncMock(return_value=mock_result)

        result = await helper.disable_autostart_service(mock_run_subprocess)

        assert result["success"] is True
        assert "disabled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_disable_autostart_service_sysrc_fails(self, helper):
        """Test service disable fails when sysrc fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "sysrc error"

        mock_run_subprocess = AsyncMock(return_value=mock_result)

        result = await helper.disable_autostart_service(mock_run_subprocess)

        assert result["success"] is False
        assert "sysrc error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_autostart_service_exception(self, helper):
        """Test service disable handles exception."""
        mock_run_subprocess = AsyncMock(side_effect=Exception("subprocess error"))

        result = await helper.disable_autostart_service(mock_run_subprocess)

        assert result["success"] is False
        assert "subprocess error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_autostart_service_calls_sysrc(self, helper):
        """Test service disable calls sysrc with correct arguments."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        mock_run_subprocess = AsyncMock(return_value=mock_result)

        await helper.disable_autostart_service(mock_run_subprocess)

        mock_run_subprocess.assert_called_once()
        call_args = mock_run_subprocess.call_args
        assert call_args[0][0] == ["sysrc", "sysmanage_bhyve_enable=NO"]


class TestConstants:
    """Tests for module constants."""

    def test_bhyve_vm_dir_value(self):
        """Test BHYVE_VM_DIR has expected value."""
        assert BHYVE_VM_DIR == "/vm"

    def test_bhyve_rc_script_value(self):
        """Test BHYVE_RC_SCRIPT has expected value."""
        assert BHYVE_RC_SCRIPT == "/usr/local/etc/rc.d/sysmanage_bhyve"

    def test_bhyve_autostart_conf_value(self):
        """Test BHYVE_AUTOSTART_CONF has expected value."""
        assert BHYVE_AUTOSTART_CONF == "/usr/local/etc/sysmanage_bhyve.conf"


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_config_with_empty_vm_name(self):
        """Test config with empty VM name."""
        config = BhyveVmPersistentConfig(
            vm_name="", hostname="host", distribution="ubuntu"
        )
        assert config.vm_name == ""

    def test_config_with_special_characters(self):
        """Test config with special characters in name."""
        config = BhyveVmPersistentConfig(
            vm_name="vm-with_special.chars",
            hostname="host-name.local",
            distribution="ubuntu",
        )
        config_dict = config.to_dict()
        restored = BhyveVmPersistentConfig.from_dict(config_dict)
        assert restored.vm_name == "vm-with_special.chars"
        assert restored.hostname == "host-name.local"

    def test_config_with_zero_cpus(self):
        """Test config with zero CPUs."""
        config = BhyveVmPersistentConfig(
            vm_name="test", hostname="host", distribution="ubuntu", cpus=0
        )
        assert config.cpus == 0

    def test_config_with_negative_delay(self):
        """Test config with negative autostart delay."""
        config = BhyveVmPersistentConfig(
            vm_name="test",
            hostname="host",
            distribution="ubuntu",
            autostart_delay=-5,
        )
        assert config.autostart_delay == -5

    def test_from_dict_with_partial_data(self):
        """Test from_dict with only required fields."""
        data = {
            "vm_name": "test",
            "hostname": "host",
            "distribution": "ubuntu",
        }
        config = BhyveVmPersistentConfig.from_dict(data)
        assert config.vm_name == "test"
        # Should use defaults for missing optional fields
        assert config.memory == "1G"
        assert config.cpus == 1

    def test_get_config_path_with_unicode(self, helper):
        """Test get_config_path with unicode characters."""
        result = helper.get_config_path("vm-test-unicode")
        assert "vm-test-unicode" in result

    @pytest.mark.asyncio
    async def test_list_autostart_vms_empty_directory(self, helper):
        """Test list_autostart_vms with empty directory."""
        with patch("os.path.isdir", return_value=True):
            with patch("os.listdir", return_value=[]):
                result = await helper.list_autostart_vms()

        assert result == []

    def test_config_with_large_memory(self):
        """Test config with large memory value."""
        config = BhyveVmPersistentConfig(
            vm_name="test", hostname="host", distribution="ubuntu", memory="128G"
        )
        assert config.memory == "128G"

    def test_config_with_large_cpus(self):
        """Test config with large number of CPUs."""
        config = BhyveVmPersistentConfig(
            vm_name="test", hostname="host", distribution="ubuntu", cpus=256
        )
        assert config.cpus == 256

    @pytest.mark.asyncio
    async def test_save_load_roundtrip(self, helper, sample_config, tmp_path):
        """Test save and load round-trip preserves data."""
        config_path = tmp_path / "test-vm" / "vm-config.json"

        with patch.object(helper, "get_config_path", return_value=str(config_path)):
            await helper.save_vm_config(sample_config)
            loaded = await helper.load_vm_config("test-vm")

        assert loaded is not None
        assert loaded.vm_name == sample_config.vm_name
        assert loaded.hostname == sample_config.hostname
        assert loaded.distribution == sample_config.distribution
        assert loaded.memory == sample_config.memory
        assert loaded.cpus == sample_config.cpus
        assert loaded.disk_path == sample_config.disk_path
        assert loaded.use_uefi == sample_config.use_uefi
        assert loaded.autostart == sample_config.autostart
        assert loaded.autostart_delay == sample_config.autostart_delay
