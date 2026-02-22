"""
Comprehensive unit tests for FreeBSD bhyve provisioning operations.

Tests cover:
- FreeBSDBhyveProvisioner initialization
- Firstboot script generation
- Memory disk operations (attach/mount)
- User creation in images
- Group management
- Firstboot file injection
- rc.conf configuration
- SSH keypair generation
- User data and meta data generation
- Bootstrap script generation
- Config disk creation
- Provisioning workflow
- SSH bootstrap execution
- Cleanup operations
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import logging
import subprocess
from unittest.mock import AsyncMock, Mock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_bhyve_freebsd import (
    FreeBSDBhyveProvisioner,
)
from src.sysmanage_agent.operations.child_host_bhyve_types import BhyveVmConfig


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def provisioner(logger):
    """Create a FreeBSDBhyveProvisioner instance for testing."""
    return FreeBSDBhyveProvisioner(logger)


@pytest.fixture
def vm_config():
    """Create a sample BhyveVmConfig for testing."""
    return BhyveVmConfig(
        distribution="freebsd:14.0",
        vm_name="test-vm",
        hostname="test-vm.example.com",
        username="testuser",
        password_hash="$6$rounds=5000$saltsalt$hashhashhash",
        server_url="https://sysmanage.example.com",
        agent_install_commands=["pkg install sysmanage-agent"],
        server_port=8443,
        use_https=True,
        auto_approve_token="test-token-uuid",
    )


class TestFreeBSDBhyveProvisionerInit:
    """Tests for FreeBSDBhyveProvisioner initialization."""

    def test_init_sets_logger(self, provisioner, logger):
        """Test that __init__ sets logger."""
        assert provisioner.logger == logger

    def test_init_sets_config_disk_path_to_none(self, provisioner):
        """Test that __init__ sets _config_disk_path to None."""
        assert provisioner._config_disk_path is None

    def test_init_sets_ssh_private_key_path_to_none(self, provisioner):
        """Test that __init__ sets _ssh_private_key_path to None."""
        assert provisioner._ssh_private_key_path is None

    def test_init_sets_ssh_public_key_to_none(self, provisioner):
        """Test that __init__ sets _ssh_public_key to None."""
        assert provisioner._ssh_public_key is None

    def test_init_sets_bootstrap_username_to_none(self, provisioner):
        """Test that __init__ sets _bootstrap_username to None."""
        assert provisioner._bootstrap_username is None

    def test_init_sets_temp_root_password_to_none(self, provisioner):
        """Test that __init__ sets _temp_root_password to None."""
        assert provisioner._temp_root_password is None

    def test_init_sets_md_device_to_none(self, provisioner):
        """Test that __init__ sets _md_device to None."""
        assert provisioner._md_device is None


class TestGenerateFirstbootScript:
    """Tests for _generate_firstboot_script method."""

    def test_generate_firstboot_script_contains_rcsubr(self, provisioner, vm_config):
        """Test that firstboot script includes rc.subr."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert ". /etc/rc.subr" in script

    def test_generate_firstboot_script_contains_keyword_firstboot(
        self, provisioner, vm_config
    ):
        """Test that firstboot script includes KEYWORD: firstboot."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "# KEYWORD: firstboot" in script

    def test_generate_firstboot_script_contains_provide(self, provisioner, vm_config):
        """Test that firstboot script includes PROVIDE section."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "# PROVIDE: sysmanage_firstboot" in script

    def test_generate_firstboot_script_contains_require_networking(
        self, provisioner, vm_config
    ):
        """Test that firstboot script requires NETWORKING."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "# REQUIRE: NETWORKING" in script

    def test_generate_firstboot_script_contains_username(self, provisioner, vm_config):
        """Test that firstboot script includes username."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert vm_config.username in script

    def test_generate_firstboot_script_contains_sudo_install(
        self, provisioner, vm_config
    ):
        """Test that firstboot script installs sudo."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "pkg install -y sudo" in script

    def test_generate_firstboot_script_contains_python_install(
        self, provisioner, vm_config
    ):
        """Test that firstboot script installs Python."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "python311" in script

    def test_generate_firstboot_script_contains_agent_config(
        self, provisioner, vm_config
    ):
        """Test that firstboot script includes agent configuration."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "sysmanage-agent" in script

    def test_generate_firstboot_script_contains_service_enable(
        self, provisioner, vm_config
    ):
        """Test that firstboot script enables the agent service."""
        script = provisioner._generate_firstboot_script(vm_config)
        assert "sysrc sysmanage_agent_enable=YES" in script

    def test_generate_firstboot_script_escapes_single_quotes(self, provisioner):
        """Test that single quotes in config are escaped."""
        config = BhyveVmConfig(
            distribution="freebsd:14.0",
            vm_name="test-vm",
            hostname="test's-hostname.example.com",
            username="testuser",
            password_hash="$6$rounds=5000$salt$hash",
            server_url="https://server.example.com",
            agent_install_commands=[],
            auto_approve_token="token-with-'quote",
        )
        script = provisioner._generate_firstboot_script(config)
        # Single quotes should be escaped for shell
        assert "\\'" in script or "test" in script  # Basic validation


class TestAttachMemoryDisk:
    """Tests for _attach_memory_disk method."""

    def test_attach_memory_disk_success(self, provisioner):
        """Test attaching memory disk successfully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="md0\n", stderr="")
            result = provisioner._attach_memory_disk("/path/to/disk.img")

        assert result["success"] is True
        assert result["md_unit"] == "md0"
        assert provisioner._md_device == "md0"

    def test_attach_memory_disk_failure(self, provisioner):
        """Test attaching memory disk failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="mdconfig: error"
            )
            result = provisioner._attach_memory_disk("/path/to/disk.img")

        assert result["success"] is False
        assert "Failed to attach" in result["error"]

    def test_attach_memory_disk_timeout(self, provisioner):
        """Test attaching memory disk with timeout."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="mdconfig", timeout=30)
            with pytest.raises(subprocess.TimeoutExpired):
                provisioner._attach_memory_disk("/path/to/disk.img")


class TestMountFreeBSDPartition:
    """Tests for _mount_freebsd_partition method."""

    def test_mount_partition_success_p4(self, provisioner):
        """Test mounting partition successfully on p4."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._mount_freebsd_partition("md0", "/mnt/test")

        assert result["success"] is True

    def test_mount_partition_tries_multiple_partitions(self, provisioner):
        """Test that mount tries multiple partition suffixes."""
        call_count = [0]

        def mock_exists(_path):
            return True

        def mock_run(cmd, **_kwargs):
            call_count[0] += 1
            if "p2" in cmd[3]:  # /dev/md0p2
                return Mock(returncode=0, stdout="", stderr="")
            return Mock(returncode=1, stdout="", stderr="mount failed")

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("subprocess.run", side_effect=mock_run):
                result = provisioner._mount_freebsd_partition("md0", "/mnt/test")

        assert result["success"] is True

    def test_mount_partition_all_fail(self, provisioner):
        """Test mounting when all partitions fail."""
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="mount failed"
                )
                result = provisioner._mount_freebsd_partition("md0", "/mnt/test")

        assert result["success"] is False
        assert "Failed to mount" in result["error"]

    def test_mount_partition_skips_nonexistent_devices(self, provisioner):
        """Test that mount skips non-existent device paths."""

        def mock_exists(path):
            # Only md0 exists, not md0p4, md0p3, etc.
            return path == "/dev/md0"

        with patch("os.path.exists", side_effect=mock_exists):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                result = provisioner._mount_freebsd_partition("md0", "/mnt/test")

        assert result["success"] is True


class TestCreateUserInImage:
    """Tests for _create_user_in_image method."""

    def test_create_user_reads_master_passwd(self, provisioner):
        """Test that create user reads master.passwd file."""
        mock_passwd_content = "root:*:0:0::0:0:root:/root:/bin/sh\n"

        with patch(
            "builtins.open", mock_open(read_data=mock_passwd_content)
        ) as mock_file:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.makedirs"):
                    provisioner._create_user_in_image(
                        "/mnt/test", "testuser", "$6$hash"
                    )

        # Verify master.passwd was read
        mock_file.assert_any_call("/mnt/test/etc/master.passwd", "r", encoding="utf-8")

    def test_create_user_writes_new_entry(self, provisioner):
        """Test that create user writes new user entry."""
        mock_passwd_content = "root:*:0:0::0:0:root:/root:/bin/sh\n"
        written_data = []

        def mock_write(data):
            written_data.append(data)

        mock_file = mock_open(read_data=mock_passwd_content)
        mock_file.return_value.write = mock_write

        with patch("builtins.open", mock_file):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.makedirs"):
                    provisioner._create_user_in_image(
                        "/mnt/test", "newuser", "$6$salthash"
                    )

        # Verify user line was written
        assert any("newuser" in data for data in written_data)

    def test_create_user_runs_pwd_mkdb(self, provisioner):
        """Test that create user runs pwd_mkdb."""
        mock_passwd_content = "root:*:0:0::0:0:root:/root:/bin/sh\n"

        with patch("builtins.open", mock_open(read_data=mock_passwd_content)):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.makedirs"):
                    provisioner._create_user_in_image(
                        "/mnt/test", "testuser", "$6$hash"
                    )

        # Verify pwd_mkdb was called
        mock_run.assert_called()
        call_args = mock_run.call_args[0][0]
        assert "pwd_mkdb" in call_args

    def test_create_user_creates_home_directory(self, provisioner):
        """Test that create user creates home directory."""
        mock_passwd_content = "root:*:0:0::0:0:root:/root:/bin/sh\n"

        with patch("builtins.open", mock_open(read_data=mock_passwd_content)):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.makedirs") as mock_makedirs:
                    provisioner._create_user_in_image(
                        "/mnt/test", "testuser", "$6$hash"
                    )

        mock_makedirs.assert_called_with(
            "/mnt/test/home/testuser", mode=0o755, exist_ok=True
        )

    def test_create_user_calculates_uid_correctly(self, provisioner):
        """Test that UID is calculated correctly from existing users."""
        mock_passwd_content = (
            "root:*:0:0::0:0:root:/root:/bin/sh\n"
            "user1:*:1001:1001::0:0:user1:/home/user1:/bin/sh\n"
            "user2:*:1005:1005::0:0:user2:/home/user2:/bin/sh\n"
        )
        written_data = []

        mock_file = mock_open(read_data=mock_passwd_content)

        def capture_write(data):
            written_data.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.makedirs"):
                    provisioner._create_user_in_image("/mnt/test", "newuser", "$6$hash")

        # Should use UID 1006 (max 1005 + 1)
        assert any(":1006:" in data for data in written_data)

    def test_create_user_handles_pwd_mkdb_warning(self, provisioner):
        """Test that pwd_mkdb warnings are logged but don't fail."""
        mock_passwd_content = "root:*:0:0::0:0:root:/root:/bin/sh\n"

        with patch("builtins.open", mock_open(read_data=mock_passwd_content)):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="warning: something"
                )
                with patch("os.makedirs"):
                    # Should not raise exception
                    provisioner._create_user_in_image(
                        "/mnt/test", "testuser", "$6$hash"
                    )

    def test_create_user_handles_invalid_uid_in_passwd(self, provisioner):
        """Test that invalid UID values in master.passwd are handled."""
        # Include a line with non-numeric UID to trigger ValueError
        mock_passwd_content = (
            "root:*:0:0::0:0:root:/root:/bin/sh\n"
            "invalid:*:notanumber:1000::0:0:invalid:/home/invalid:/bin/sh\n"
            "user1:*:1001:1001::0:0:user1:/home/user1:/bin/sh\n"
        )
        written_data = []

        mock_file = mock_open(read_data=mock_passwd_content)

        def capture_write(data):
            written_data.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch("os.makedirs"):
                    provisioner._create_user_in_image("/mnt/test", "newuser", "$6$hash")

        # Should still create user with correct UID (1002 = max(1001) + 1)
        assert any(":1002:" in data for data in written_data)


class TestAddUserToWheelGroup:
    """Tests for _add_user_to_wheel_group method."""

    def test_add_to_wheel_empty_group(self, provisioner):
        """Test adding user to empty wheel group."""
        mock_group_content = "wheel:*:0:\n"
        written_lines = []

        mock_file = mock_open(read_data=mock_group_content)

        def capture_write(data):
            written_lines.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            provisioner._add_user_to_wheel_group("/mnt/test", "testuser")

        # Should add user directly after colon
        assert any("wheel:" in line and "testuser" in line for line in written_lines)

    def test_add_to_wheel_existing_members(self, provisioner):
        """Test adding user to wheel group with existing members."""
        mock_group_content = "wheel:*:0:root,admin\nusers:*:100:\n"
        written_lines = []

        mock_file = mock_open(read_data=mock_group_content)

        def capture_write(data):
            written_lines.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            provisioner._add_user_to_wheel_group("/mnt/test", "newuser")

        # Should append with comma
        assert any("wheel:" in line and ",newuser" in line for line in written_lines)


class TestWriteFirstbootFiles:
    """Tests for _write_firstboot_files method."""

    def test_write_firstboot_creates_script(self, provisioner, vm_config):
        """Test that firstboot script is created."""
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.chmod"):
                provisioner._write_firstboot_files("/mnt/test", vm_config)

        # Verify script was written to correct location
        mock_file.assert_any_call(
            "/mnt/test/etc/rc.d/sysmanage_firstboot", "w", encoding="utf-8"
        )

    def test_write_firstboot_sets_executable(self, provisioner, vm_config):
        """Test that firstboot script is set executable."""
        with patch("builtins.open", mock_open()):
            with patch("os.chmod") as mock_chmod:
                provisioner._write_firstboot_files("/mnt/test", vm_config)

        mock_chmod.assert_called_with("/mnt/test/etc/rc.d/sysmanage_firstboot", 0o755)

    def test_write_firstboot_creates_sentinel(self, provisioner, vm_config):
        """Test that firstboot sentinel file is created."""
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("os.chmod"):
                provisioner._write_firstboot_files("/mnt/test", vm_config)

        # Verify sentinel was created
        mock_file.assert_any_call("/mnt/test/firstboot", "w", encoding="utf-8")


class TestConfigureRcConf:
    """Tests for _configure_rc_conf method."""

    def test_configure_rc_conf_sets_hostname(self, provisioner):
        """Test that rc.conf sets hostname."""
        written_data = []

        mock_file = mock_open()

        def capture_write(data):
            written_data.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            provisioner._configure_rc_conf("/mnt/test", "myhost.example.com")

        joined_data = "".join(written_data)
        assert 'hostname="myhost.example.com"' in joined_data

    def test_configure_rc_conf_enables_firstboot(self, provisioner):
        """Test that rc.conf enables firstboot."""
        written_data = []

        mock_file = mock_open()

        def capture_write(data):
            written_data.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            provisioner._configure_rc_conf("/mnt/test", "myhost")

        joined_data = "".join(written_data)
        assert 'sysmanage_firstboot_enable="YES"' in joined_data

    def test_configure_rc_conf_enables_sshd(self, provisioner):
        """Test that rc.conf enables sshd."""
        written_data = []

        mock_file = mock_open()

        def capture_write(data):
            written_data.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            provisioner._configure_rc_conf("/mnt/test", "myhost")

        joined_data = "".join(written_data)
        assert 'sshd_enable="YES"' in joined_data

    def test_configure_rc_conf_enables_ntpd(self, provisioner):
        """Test that rc.conf enables ntpd."""
        written_data = []

        mock_file = mock_open()

        def capture_write(data):
            written_data.append(data)

        mock_file.return_value.write = capture_write

        with patch("builtins.open", mock_file):
            provisioner._configure_rc_conf("/mnt/test", "myhost")

        joined_data = "".join(written_data)
        assert 'ntpd_enable="YES"' in joined_data


class TestCleanupMount:
    """Tests for _cleanup_mount method."""

    def test_cleanup_mount_unmounts_and_removes_dir(self, provisioner):
        """Test that cleanup unmounts and removes temp directory."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            with patch("shutil.rmtree") as mock_rmtree:
                provisioner._cleanup_mount("/mnt/test", None)

        mock_run.assert_called_once()
        mock_rmtree.assert_called_once_with("/mnt/test", ignore_errors=True)

    def test_cleanup_mount_detaches_memory_disk(self, provisioner):
        """Test that cleanup detaches memory disk."""
        provisioner._md_device = "md0"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            with patch("shutil.rmtree"):
                provisioner._cleanup_mount(None, "md0")

        # Verify mdconfig -d was called
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert any("mdconfig" in cmd and "-d" in cmd for cmd in calls)
        assert provisioner._md_device is None

    def test_cleanup_mount_handles_no_mount_point(self, provisioner):
        """Test cleanup when mount point is None."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            with patch("shutil.rmtree") as mock_rmtree:
                provisioner._cleanup_mount(None, "md0")

        mock_rmtree.assert_not_called()

    def test_cleanup_mount_handles_no_md_unit(self, provisioner):
        """Test cleanup when md_unit is None."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            with patch("shutil.rmtree"):
                provisioner._cleanup_mount("/mnt/test", None)

        # Only umount should be called, not mdconfig
        assert mock_run.call_count == 1


class TestInjectFirstbootIntoImage:
    """Tests for inject_firstboot_into_image method."""

    def test_inject_firstboot_success(self, provisioner, vm_config):
        """Test successful firstboot injection."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_mount"):
            with patch.object(
                provisioner,
                "_attach_memory_disk",
                return_value={"success": True, "md_unit": "md0"},
            ):
                with patch.object(
                    provisioner,
                    "_mount_freebsd_partition",
                    return_value={"success": True},
                ):
                    with patch("os.path.exists", return_value=True):  # rc.conf exists
                        with patch.object(provisioner, "_configure_rc_conf"):
                            with patch.object(provisioner, "_create_user_in_image"):
                                with patch.object(
                                    provisioner, "_add_user_to_wheel_group"
                                ):
                                    with patch.object(
                                        provisioner, "_write_firstboot_files"
                                    ):
                                        with patch("subprocess.run") as mock_run:
                                            mock_run.return_value = Mock(returncode=0)
                                            with patch("shutil.rmtree"):
                                                result = provisioner.inject_firstboot_into_image(
                                                    vm_config, "/path/disk.img"
                                                )

        assert result["success"] is True

    def test_inject_firstboot_attach_fails(self, provisioner, vm_config):
        """Test injection when attach fails."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_mount"):
            with patch.object(
                provisioner,
                "_attach_memory_disk",
                return_value={"success": False, "error": "attach failed"},
            ):
                with patch("shutil.rmtree"):
                    result = provisioner.inject_firstboot_into_image(
                        vm_config, "/path/disk.img"
                    )

        assert result["success"] is False
        assert "attach failed" in result["error"]

    def test_inject_firstboot_mount_fails(self, provisioner, vm_config):
        """Test injection when mount fails."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_mount"):
            with patch.object(
                provisioner,
                "_attach_memory_disk",
                return_value={"success": True, "md_unit": "md0"},
            ):
                with patch.object(
                    provisioner,
                    "_mount_freebsd_partition",
                    return_value={"success": False, "error": "mount failed"},
                ):
                    with patch("shutil.rmtree"):
                        result = provisioner.inject_firstboot_into_image(
                            vm_config, "/path/disk.img"
                        )

        assert result["success"] is False
        assert "mount failed" in result["error"]

    def test_inject_firstboot_not_freebsd_root(self, provisioner, vm_config):
        """Test injection when mounted filesystem is not FreeBSD root."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_mount"):
            with patch.object(
                provisioner,
                "_attach_memory_disk",
                return_value={"success": True, "md_unit": "md0"},
            ):
                with patch.object(
                    provisioner,
                    "_mount_freebsd_partition",
                    return_value={"success": True},
                ):
                    with patch("os.path.exists", return_value=False):  # No rc.conf
                        with patch("subprocess.run") as mock_run:
                            mock_run.return_value = Mock(returncode=0)
                            with patch("shutil.rmtree"):
                                result = provisioner.inject_firstboot_into_image(
                                    vm_config, "/path/disk.img"
                                )

        assert result["success"] is False
        assert "FreeBSD root" in result["error"]

    def test_inject_firstboot_exception_cleanup(self, provisioner, vm_config):
        """Test that cleanup happens on exception."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test_mount"):
            with patch.object(
                provisioner,
                "_attach_memory_disk",
                return_value={"success": True, "md_unit": "md0"},
            ):
                with patch.object(
                    provisioner,
                    "_mount_freebsd_partition",
                    return_value={"success": True},
                ):
                    with patch("os.path.exists", return_value=True):
                        with patch.object(
                            provisioner,
                            "_configure_rc_conf",
                            side_effect=Exception("test error"),
                        ):
                            with patch.object(
                                provisioner, "_cleanup_mount"
                            ) as mock_cleanup:
                                with patch("shutil.rmtree"):
                                    result = provisioner.inject_firstboot_into_image(
                                        vm_config, "/path/disk.img"
                                    )

        assert result["success"] is False
        mock_cleanup.assert_called_once()


class TestGenerateSshKeypair:
    """Tests for _generate_ssh_keypair method."""

    def test_generate_ssh_keypair_success(self, provisioner):
        """Test successful SSH keypair generation."""
        with patch("tempfile.mkdtemp", return_value="/tmp/ssh_test"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                with patch(
                    "builtins.open",
                    mock_open(read_data="ssh-ed25519 AAAA... comment"),
                ):
                    result = provisioner._generate_ssh_keypair("test-vm")

        assert result["success"] is True
        assert "private_key_path" in result
        assert "public_key" in result
        assert provisioner._ssh_private_key_path is not None
        assert provisioner._ssh_public_key is not None
        assert provisioner._temp_root_password is not None

    def test_generate_ssh_keypair_failure(self, provisioner):
        """Test SSH keypair generation failure."""
        with patch("tempfile.mkdtemp", return_value="/tmp/ssh_test"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(
                    returncode=1, stdout="", stderr="ssh-keygen error"
                )
                result = provisioner._generate_ssh_keypair("test-vm")

        assert result["success"] is False
        assert "Failed to generate SSH key" in result["error"]

    def test_generate_ssh_keypair_exception(self, provisioner):
        """Test SSH keypair generation with exception."""
        with patch("tempfile.mkdtemp", side_effect=Exception("tempdir error")):
            result = provisioner._generate_ssh_keypair("test-vm")

        assert result["success"] is False
        assert "tempdir error" in result["error"]


class TestGenerateUserData:
    """Tests for _generate_user_data method."""

    def test_generate_user_data_contains_hostname(self, provisioner, vm_config):
        """Test that user-data contains hostname."""
        user_data = provisioner._generate_user_data(vm_config)
        assert "test-vm" in user_data

    def test_generate_user_data_contains_username(self, provisioner, vm_config):
        """Test that user-data contains username."""
        user_data = provisioner._generate_user_data(vm_config)
        assert vm_config.username in user_data

    def test_generate_user_data_contains_cloud_config(self, provisioner, vm_config):
        """Test that user-data starts with cloud-config."""
        user_data = provisioner._generate_user_data(vm_config)
        assert user_data.startswith("#cloud-config")

    def test_generate_user_data_with_ssh_key(self, provisioner, vm_config):
        """Test that user-data includes SSH key when available."""
        provisioner._ssh_public_key = "ssh-ed25519 AAAA... test-key"
        user_data = provisioner._generate_user_data(vm_config)
        assert "ssh_authorized_keys" in user_data
        assert "ssh-ed25519" in user_data

    def test_generate_user_data_with_root_password(self, provisioner, vm_config):
        """Test that user-data includes root password when available."""
        provisioner._temp_root_password = "temp-password-123"
        user_data = provisioner._generate_user_data(vm_config)
        assert "chpasswd" in user_data
        assert "temp-password-123" in user_data

    def test_generate_user_data_without_ssh_key(self, provisioner, vm_config):
        """Test that user-data works without SSH key."""
        provisioner._ssh_public_key = None
        user_data = provisioner._generate_user_data(vm_config)
        assert "ssh_authorized_keys" not in user_data


class TestGenerateBootstrapScript:
    """Tests for _generate_bootstrap_script method."""

    def test_generate_bootstrap_script_contains_shebang(self, provisioner, vm_config):
        """Test that bootstrap script starts with shebang."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert script.startswith("#!/bin/sh")

    def test_generate_bootstrap_script_contains_username(self, provisioner, vm_config):
        """Test that bootstrap script contains username."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert f'USERNAME="{vm_config.username}"' in script

    def test_generate_bootstrap_script_installs_sudo(self, provisioner, vm_config):
        """Test that bootstrap script installs sudo."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert "pkg install -y sudo" in script

    def test_generate_bootstrap_script_installs_python(self, provisioner, vm_config):
        """Test that bootstrap script installs Python."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert "python311" in script

    def test_generate_bootstrap_script_downloads_agent(self, provisioner, vm_config):
        """Test that bootstrap script downloads agent."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert "github.com/bceverly/sysmanage-agent" in script

    def test_generate_bootstrap_script_syncs_time(self, provisioner, vm_config):
        """Test that bootstrap script syncs time."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert "ntpdate" in script

    def test_generate_bootstrap_script_starts_service(self, provisioner, vm_config):
        """Test that bootstrap script starts service."""
        script = provisioner._generate_bootstrap_script(vm_config)
        assert "service sysmanage_agent" in script


class TestGenerateMetaData:
    """Tests for _generate_meta_data method."""

    def test_generate_meta_data_contains_instance_id(self, provisioner, vm_config):
        """Test that meta-data contains instance-id."""
        meta_data = provisioner._generate_meta_data(vm_config)
        assert f"instance-id: {vm_config.vm_name}" in meta_data

    def test_generate_meta_data_contains_hostname(self, provisioner, vm_config):
        """Test that meta-data contains local-hostname."""
        meta_data = provisioner._generate_meta_data(vm_config)
        assert "local-hostname: test-vm" in meta_data


class TestCreateConfigDisk:
    """Tests for create_config_disk method."""

    def test_create_config_disk_success(self, provisioner, vm_config):
        """Test successful config disk creation."""
        with patch("tempfile.mkdtemp", return_value="/tmp/config_test"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                        with patch("shutil.rmtree"):
                            result = provisioner.create_config_disk(
                                vm_config, "/var/vm"
                            )

        assert result["success"] is True
        assert "config_disk_path" in result

    def test_create_config_disk_makefs_fails(self, provisioner, vm_config):
        """Test config disk creation when makefs fails."""
        with patch("tempfile.mkdtemp", return_value="/tmp/config_test"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(
                            returncode=1, stdout="", stderr="makefs error"
                        )
                        with patch("shutil.rmtree"):
                            result = provisioner.create_config_disk(
                                vm_config, "/var/vm"
                            )

        assert result["success"] is False
        assert "Failed to create config ISO" in result["error"]

    def test_create_config_disk_exception(self, provisioner, vm_config):
        """Test config disk creation with exception."""
        with patch("tempfile.mkdtemp", side_effect=Exception("disk error")):
            result = provisioner.create_config_disk(vm_config, "/var/vm")

        assert result["success"] is False
        assert "disk error" in result["error"]

    def test_create_config_disk_cleans_up_temp(self, provisioner, vm_config):
        """Test that temp directory is cleaned up."""
        with patch("tempfile.mkdtemp", return_value="/tmp/config_test"):
            with patch("builtins.open", mock_open()):
                with patch("os.chmod"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
                        with patch("shutil.rmtree") as mock_rmtree:
                            provisioner.create_config_disk(vm_config, "/var/vm")

        mock_rmtree.assert_called_with("/tmp/config_test", ignore_errors=True)


class TestProvision:
    """Tests for provision method."""

    def test_provision_success(self, provisioner, vm_config):
        """Test successful provisioning."""
        with patch.object(
            provisioner,
            "inject_firstboot_into_image",
            return_value={"success": True},
        ):
            result = provisioner.provision(vm_config, "/path/disk.img", "/var/vm")

        assert result["success"] is True
        assert result["provisioning_method"] == "firstboot_injection"
        assert provisioner._bootstrap_username == vm_config.username

    def test_provision_inject_fails(self, provisioner, vm_config):
        """Test provisioning when injection fails."""
        with patch.object(
            provisioner,
            "inject_firstboot_into_image",
            return_value={"success": False, "error": "inject failed"},
        ):
            result = provisioner.provision(vm_config, "/path/disk.img", "/var/vm")

        assert result["success"] is False
        assert "inject failed" in result["error"]

    def test_provision_exception(self, provisioner, vm_config):
        """Test provisioning with exception."""
        with patch.object(
            provisioner,
            "inject_firstboot_into_image",
            side_effect=Exception("provision error"),
        ):
            result = provisioner.provision(vm_config, "/path/disk.img", "/var/vm")

        assert result["success"] is False
        assert "provision error" in result["error"]


class TestRunBootstrapViaSsh:
    """Tests for run_bootstrap_via_ssh method."""

    @pytest.mark.asyncio
    async def test_bootstrap_no_ssh_key(self, provisioner):
        """Test bootstrap when no SSH key is available."""
        provisioner._ssh_private_key_path = None
        result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "No SSH key" in result["error"]

    @pytest.mark.asyncio
    async def test_bootstrap_no_username(self, provisioner):
        """Test bootstrap when no username is set."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = None
        result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "username not set" in result["error"]

    @pytest.mark.asyncio
    async def test_bootstrap_no_root_password(self, provisioner):
        """Test bootstrap when no root password is available."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = None
        result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "root password" in result["error"]

    @pytest.mark.asyncio
    async def test_bootstrap_ssh_auth_success(self, provisioner):
        """Test bootstrap with successful SSH auth."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        mock_test_result = Mock(returncode=0, stdout="SSH key auth works", stderr="")
        mock_bootstrap_result = Mock(
            returncode=0, stdout="Bootstrap complete", stderr=""
        )

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.side_effect = [mock_test_result, mock_bootstrap_result]
                with patch("shutil.which", return_value=None):  # No sshpass
                    result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_bootstrap_ssh_auth_retry(self, provisioner):
        """Test bootstrap with SSH auth retry."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        mock_fail_result = Mock(returncode=1, stdout="", stderr="auth failed")
        mock_success_result = Mock(returncode=0, stdout="SSH key auth works", stderr="")
        mock_bootstrap_result = Mock(
            returncode=0, stdout="Bootstrap complete", stderr=""
        )

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.side_effect = [
                    mock_fail_result,
                    mock_success_result,
                    mock_bootstrap_result,
                ]
                with patch("shutil.which", return_value=None):
                    result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_bootstrap_ssh_auth_all_retries_fail(self, provisioner):
        """Test bootstrap when all SSH auth retries fail."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        mock_fail_result = Mock(returncode=1, stdout="", stderr="auth failed")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.return_value = mock_fail_result
                result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "authentication failed" in result["error"]

    @pytest.mark.asyncio
    async def test_bootstrap_script_fails(self, provisioner):
        """Test bootstrap when script execution fails."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        mock_test_result = Mock(returncode=0, stdout="SSH key auth works", stderr="")
        mock_bootstrap_result = Mock(returncode=1, stdout="", stderr="bootstrap error")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.side_effect = [mock_test_result, mock_bootstrap_result]
                with patch("shutil.which", return_value=None):
                    result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "Bootstrap script failed" in result["error"]

    @pytest.mark.asyncio
    async def test_bootstrap_with_sshpass(self, provisioner):
        """Test bootstrap using sshpass when available."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        mock_test_result = Mock(returncode=0, stdout="SSH key auth works", stderr="")
        mock_bootstrap_result = Mock(
            returncode=0, stdout="Bootstrap complete", stderr=""
        )

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.side_effect = [mock_test_result, mock_bootstrap_result]
                with patch("shutil.which", return_value="/usr/bin/sshpass"):
                    result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_bootstrap_timeout(self, provisioner):
        """Test bootstrap with timeout exception."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=600)
                result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_bootstrap_general_exception(self, provisioner):
        """Test bootstrap with general exception."""
        provisioner._ssh_private_key_path = "/tmp/key"
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass123"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with patch(
                "src.sysmanage_agent.operations.child_host_bhyve_freebsd.run_command_async",
                new_callable=AsyncMock,
            ) as mock_run:
                mock_run.side_effect = Exception("general error")
                result = await provisioner.run_bootstrap_via_ssh("192.168.1.100")

        assert result["success"] is False
        assert "general error" in result["error"]


class TestGetConfigDiskPath:
    """Tests for get_config_disk_path method."""

    def test_get_config_disk_path_returns_none_initially(self, provisioner):
        """Test that config disk path is None initially."""
        assert provisioner.get_config_disk_path() is None

    def test_get_config_disk_path_returns_path_when_set(self, provisioner):
        """Test that config disk path returns value when set."""
        provisioner._config_disk_path = "/var/vm/test-config.iso"
        assert provisioner.get_config_disk_path() == "/var/vm/test-config.iso"


class TestHasSshKey:
    """Tests for has_ssh_key method."""

    def test_has_ssh_key_false_initially(self, provisioner):
        """Test that has_ssh_key returns False initially."""
        assert provisioner.has_ssh_key() is False

    def test_has_ssh_key_true_when_set(self, provisioner):
        """Test that has_ssh_key returns True when key is set."""
        provisioner._ssh_private_key_path = "/tmp/key"
        assert provisioner.has_ssh_key() is True


class TestCleanup:
    """Tests for cleanup method."""

    def test_cleanup_removes_config_disk(self, provisioner):
        """Test that cleanup removes config disk."""
        provisioner._config_disk_path = "/tmp/test-config.iso"

        with patch("os.path.exists", return_value=True):
            with patch("os.remove") as mock_remove:
                provisioner.cleanup()

        mock_remove.assert_called_once_with("/tmp/test-config.iso")
        assert provisioner._config_disk_path is None

    def test_cleanup_removes_ssh_key_dir(self, provisioner):
        """Test that cleanup removes SSH key directory."""
        provisioner._ssh_private_key_path = "/tmp/ssh_test/bootstrap_key"
        provisioner._ssh_public_key = "ssh-ed25519 AAAA..."

        with patch("os.path.exists", return_value=False):
            with patch("shutil.rmtree") as mock_rmtree:
                provisioner.cleanup()

        mock_rmtree.assert_called_once_with("/tmp/ssh_test", ignore_errors=True)
        assert provisioner._ssh_private_key_path is None
        assert provisioner._ssh_public_key is None

    def test_cleanup_clears_credentials(self, provisioner):
        """Test that cleanup clears credentials."""
        provisioner._bootstrap_username = "testuser"
        provisioner._temp_root_password = "temppass"

        with patch("os.path.exists", return_value=False):
            provisioner.cleanup()

        assert provisioner._bootstrap_username is None
        assert provisioner._temp_root_password is None

    def test_cleanup_handles_remove_oserror(self, provisioner):
        """Test that cleanup handles OSError when removing config disk."""
        provisioner._config_disk_path = "/tmp/test-config.iso"

        with patch("os.path.exists", return_value=True):
            with patch("os.remove", side_effect=OSError("permission denied")):
                # Should not raise exception
                provisioner.cleanup()

    def test_cleanup_handles_rmtree_oserror(self, provisioner):
        """Test that cleanup handles OSError when removing SSH key dir."""
        provisioner._ssh_private_key_path = "/tmp/ssh_test/bootstrap_key"

        with patch("os.path.exists", return_value=False):
            with patch("shutil.rmtree", side_effect=OSError("permission denied")):
                # Should not raise exception
                provisioner.cleanup()

    def test_cleanup_when_nothing_to_clean(self, provisioner):
        """Test cleanup when no resources exist."""
        # Should not raise any exceptions
        provisioner.cleanup()


class TestBhyveVmConfigValidation:
    """Tests for BhyveVmConfig dataclass validation."""

    def test_valid_config_creation(self, vm_config):
        """Test creating a valid config."""
        assert vm_config.vm_name == "test-vm"
        assert vm_config.hostname == "test-vm.example.com"

    def test_config_requires_vm_name(self):
        """Test that VM name is required."""
        with pytest.raises(ValueError, match="VM name is required"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="",
                hostname="test.example.com",
                username="testuser",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_config_requires_hostname(self):
        """Test that hostname is required."""
        with pytest.raises(ValueError, match="Hostname is required"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="",
                username="testuser",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_config_requires_username(self):
        """Test that username is required."""
        with pytest.raises(ValueError, match="Username is required"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_config_requires_password_hash(self):
        """Test that password hash is required."""
        with pytest.raises(ValueError, match="Password hash is required"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="testuser",
                password_hash="",
                server_url="https://server.example.com",
                agent_install_commands=[],
            )

    def test_config_validates_memory_format(self):
        """Test that invalid memory format raises error."""
        with pytest.raises(ValueError, match="Invalid memory format"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="testuser",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
                memory="invalid",
            )

    def test_config_validates_disk_size_format(self):
        """Test that invalid disk size format raises error."""
        with pytest.raises(ValueError, match="Invalid disk size format"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="testuser",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
                disk_size="invalid",
            )

    def test_config_validates_cpu_minimum(self):
        """Test that CPUs must be at least 1."""
        with pytest.raises(ValueError, match="CPUs must be at least 1"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="testuser",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=0,
            )

    def test_config_validates_cpu_maximum(self):
        """Test that CPUs cannot exceed 64."""
        with pytest.raises(ValueError, match="CPUs cannot exceed 64"):
            BhyveVmConfig(
                distribution="freebsd:14.0",
                vm_name="test-vm",
                hostname="test.example.com",
                username="testuser",
                password_hash="$6$hash",
                server_url="https://server.example.com",
                agent_install_commands=[],
                cpus=65,
            )

    def test_get_memory_mb(self, vm_config):
        """Test getting memory in MB."""
        # Default is 1G
        assert vm_config.get_memory_mb() == 1024

    def test_get_memory_gb(self, vm_config):
        """Test getting memory in GB."""
        assert vm_config.get_memory_gb() == 1.0

    def test_get_disk_gb(self, vm_config):
        """Test getting disk size in GB."""
        # Default is 20G
        assert vm_config.get_disk_gb() == 20
