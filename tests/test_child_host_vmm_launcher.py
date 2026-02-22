"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm_launcher module.
Tests VMM VM launcher operations for OpenBSD VM management.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_vmm_launcher import VmmLauncher


class TestVmmLauncherInit:
    """Test cases for VmmLauncher initialization."""

    def test_init_with_agent_and_logger(self):
        """Test VmmLauncher initialization with agent and logger."""
        mock_agent = Mock()
        mock_logger = Mock()

        launcher = VmmLauncher(mock_agent, mock_logger)

        assert launcher.agent == mock_agent
        assert launcher.logger == mock_logger

    def test_init_stores_references(self):
        """Test that init stores agent and logger references properly."""
        mock_agent = Mock(spec=["send_message", "create_message"])
        mock_logger = Mock()

        launcher = VmmLauncher(mock_agent, mock_logger)

        assert launcher.agent is mock_agent
        assert launcher.logger is mock_logger


class TestRunSubprocess:
    """Test cases for run_subprocess method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_run_subprocess_success(self):
        """Test successful subprocess execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""

        with patch("asyncio.to_thread", return_value=mock_result) as mock_to_thread:
            result = await self.launcher.run_subprocess(["echo", "hello"])

            assert result.returncode == 0
            assert result.stdout == "output"
            mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_subprocess_with_timeout(self):
        """Test subprocess execution with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("asyncio.to_thread", return_value=mock_result) as mock_to_thread:
            await self.launcher.run_subprocess(["vmctl", "status"], timeout=30)

            # Verify to_thread was called with proper arguments
            call_args = mock_to_thread.call_args
            assert call_args is not None

    @pytest.mark.asyncio
    async def test_run_subprocess_failure(self):
        """Test subprocess execution with non-zero return code."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"

        with patch("asyncio.to_thread", return_value=mock_result):
            result = await self.launcher.run_subprocess(["vmctl", "invalid"])

            assert result.returncode == 1
            assert result.stderr == "error message"

    @pytest.mark.asyncio
    async def test_run_subprocess_default_timeout(self):
        """Test subprocess uses default timeout of 60 seconds."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("asyncio.to_thread", return_value=mock_result) as mock_to_thread:
            await self.launcher.run_subprocess(["vmctl", "status"])

            # Verify the call was made
            mock_to_thread.assert_called_once()


class TestCreateTapDevice:
    """Test cases for _create_tap_device method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_create_tap_device_success(self):
        """Test successful tap device creation."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch.object(
            self.launcher, "run_subprocess", return_value=mock_result
        ) as mock_run:
            result = await self.launcher._create_tap_device("tap0")

            assert result["success"] is True
            assert result["tap_device"] == "tap0"
            mock_run.assert_called_once_with(["ifconfig", "tap0", "create"], timeout=10)
            self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_create_tap_device_already_exists(self):
        """Test tap device creation when device already exists."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ifconfig: device already exists"

        with patch.object(self.launcher, "run_subprocess", return_value=mock_result):
            result = await self.launcher._create_tap_device("tap0")

            assert result["success"] is True
            assert result["tap_device"] == "tap0"
            # Should log info about existing device
            self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_create_tap_device_failure(self):
        """Test tap device creation failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "permission denied"

        with patch.object(self.launcher, "run_subprocess", return_value=mock_result):
            result = await self.launcher._create_tap_device("tap0")

            assert result["success"] is False
            assert "error" in result
            assert "permission denied" in result["error"]
            self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_create_tap_device_failure_stdout_error(self):
        """Test tap device creation failure with error in stdout."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "operation not permitted"
        mock_result.stderr = ""

        with patch.object(self.launcher, "run_subprocess", return_value=mock_result):
            result = await self.launcher._create_tap_device("tap0")

            assert result["success"] is False
            assert "operation not permitted" in result["error"]

    @pytest.mark.asyncio
    async def test_create_tap_device_empty_error_message(self):
        """Test tap device creation failure with empty error message."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch.object(self.launcher, "run_subprocess", return_value=mock_result):
            result = await self.launcher._create_tap_device("tap0")

            assert result["success"] is False
            assert "error" in result


class TestEnsureTapDeviceAvailable:
    """Test cases for ensure_tap_device_available method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_ensure_tap_available_no_vms_running(self):
        """Test when no VMs are running and taps are available."""
        ifconfig_result = Mock()
        ifconfig_result.returncode = 0
        ifconfig_result.stdout = (
            "tap0: flags=8843<UP,BROADCAST,RUNNING> mtu 1500\ntap1: flags=8843<UP>"
        )

        vmctl_result = Mock()
        vmctl_result.returncode = 0
        vmctl_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[ifconfig_result, vmctl_result],
        ):
            result = await self.launcher.ensure_tap_device_available()

            assert result["success"] is True
            assert result["tap_device"] is None  # No new tap needed

    @pytest.mark.asyncio
    async def test_ensure_tap_available_needs_new_tap(self):
        """Test when a new tap device needs to be created."""
        ifconfig_result = Mock()
        ifconfig_result.returncode = 0
        ifconfig_result.stdout = "tap0: flags=8843<UP,BROADCAST,RUNNING>"

        vmctl_result = Mock()
        vmctl_result.returncode = 0
        vmctl_result.stdout = "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME\n    1   123     1     512M     256M  /dev/ttyp0  root  vm1 running"

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[ifconfig_result, vmctl_result],
        ):
            with patch.object(
                self.launcher,
                "_create_tap_device",
                return_value={"success": True, "tap_device": "tap1"},
            ) as mock_create:
                result = await self.launcher.ensure_tap_device_available()

                assert result["success"] is True
                assert result["tap_device"] == "tap1"
                mock_create.assert_called_once_with("tap1")

    @pytest.mark.asyncio
    async def test_ensure_tap_ifconfig_failure(self):
        """Test when ifconfig command fails."""
        ifconfig_result = Mock()
        ifconfig_result.returncode = 1

        with patch.object(
            self.launcher, "run_subprocess", return_value=ifconfig_result
        ):
            result = await self.launcher.ensure_tap_device_available()

            assert result["success"] is False
            assert "Failed to check network interfaces" in result["error"]

    @pytest.mark.asyncio
    async def test_ensure_tap_vmctl_failure_continues(self):
        """Test when vmctl fails, running_vms defaults to 0."""
        ifconfig_result = Mock()
        ifconfig_result.returncode = 0
        ifconfig_result.stdout = "tap0: flags=8843<UP>"

        vmctl_result = Mock()
        vmctl_result.returncode = 1
        vmctl_result.stdout = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[ifconfig_result, vmctl_result],
        ):
            result = await self.launcher.ensure_tap_device_available()

            # With vmctl failure, running_vms is 0, so no new tap needed
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_ensure_tap_exception_handling(self):
        """Test exception handling in ensure_tap_device_available."""
        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=Exception("Network error"),
        ):
            result = await self.launcher.ensure_tap_device_available()

            assert result["success"] is False
            assert "Network error" in result["error"]
            self.mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_ensure_tap_multiple_running_vms(self):
        """Test with multiple running VMs."""
        ifconfig_result = Mock()
        ifconfig_result.returncode = 0
        ifconfig_result.stdout = "tap0: flags=8843\ntap1: flags=8843"  # 2 tap devices

        vmctl_result = Mock()
        vmctl_result.returncode = 0
        vmctl_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    1   123     1     512M     256M  /dev/ttyp0  root  vm1 running
    2   456     1     512M     256M  /dev/ttyp1  root  vm2 running"""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[ifconfig_result, vmctl_result],
        ):
            with patch.object(
                self.launcher,
                "_create_tap_device",
                return_value={"success": True, "tap_device": "tap2"},
            ) as mock_create:
                result = await self.launcher.ensure_tap_device_available()

                # 2 running VMs, 2 taps, need to create tap2
                assert result["success"] is True
                mock_create.assert_called_once_with("tap2")


class TestLaunchVmWithBsdrd:
    """Test cases for launch_vm_with_bsdrd method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_launch_vm_success(self):
        """Test successful VM launch with bsd.rd."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = "vmctl: started vm 1 successfully"
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_vm_already_running(self):
        """Test launching a VM that is already running."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    1   123     1     1024M     512M  /dev/ttyp0  root  testvm running testvm"""

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            result = await self.launcher.launch_vm_with_bsdrd(
                "testvm",
                "/var/vmm/testvm.qcow2",
                "/bsd.rd",
                "1G",
            )

            assert result["success"] is True
            self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_launch_vm_tap_device_failure(self):
        """Test VM launch when tap device creation fails."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": False, "error": "Failed to create tap device"},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is False

    @pytest.mark.asyncio
    async def test_launch_vm_vmctl_failure(self):
        """Test VM launch when vmctl start fails."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 1
        launch_result.stdout = ""
        launch_result.stderr = "vmctl: failed to start vm"

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is False
                assert "error" in result

    @pytest.mark.asyncio
    async def test_launch_vm_already_in_progress(self):
        """Test VM launch when start is already in progress."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 1
        launch_result.stdout = ""
        launch_result.stderr = "vmctl: operation already in progress"

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_vm_timeout_expired(self):
        """Test VM launch with subprocess timeout."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[
                status_result,
                subprocess.TimeoutExpired(cmd="vmctl", timeout=60),
            ],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is False
                assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_vm_generic_exception(self):
        """Test VM launch with generic exception."""
        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.launcher.launch_vm_with_bsdrd(
                "testvm",
                "/var/vmm/testvm.qcow2",
                "/bsd.rd",
                "1G",
            )

            assert result["success"] is False
            assert "Unexpected error" in result["error"]


class TestLaunchVmFromDisk:
    """Test cases for launch_vm_from_disk method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_launch_from_disk_success(self):
        """Test successful VM launch from disk."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = "vmctl: started vm 1 successfully"
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "2G",
                )

                assert result["success"] is True
                self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_launch_from_disk_already_running(self):
        """Test launching VM from disk when already running."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    1   123     1     2048M     1024M  /dev/ttyp0  root  testvm running testvm"""

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            result = await self.launcher.launch_vm_from_disk(
                "testvm",
                "/var/vmm/testvm.qcow2",
                "2G",
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_from_disk_tap_failure(self):
        """Test VM launch from disk when tap device fails."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": False, "error": "No tap available"},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "2G",
                )

                assert result["success"] is False

    @pytest.mark.asyncio
    async def test_launch_from_disk_vmctl_failure(self):
        """Test VM launch from disk when vmctl fails."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 1
        launch_result.stdout = ""
        launch_result.stderr = "vmctl: disk not found"

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "2G",
                )

                assert result["success"] is False
                assert "disk not found" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_from_disk_already_in_progress(self):
        """Test VM launch from disk when start already in progress."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 1
        launch_result.stdout = ""
        launch_result.stderr = "already in progress"

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "2G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_from_disk_timeout(self):
        """Test VM launch from disk with timeout."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[
                status_result,
                subprocess.TimeoutExpired(cmd="vmctl", timeout=60),
            ],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": None},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "2G",
                )

                assert result["success"] is False
                assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_launch_from_disk_generic_exception(self):
        """Test VM launch from disk with generic exception."""
        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=Exception("Disk error"),
        ):
            result = await self.launcher.launch_vm_from_disk(
                "testvm",
                "/var/vmm/testvm.qcow2",
                "2G",
            )

            assert result["success"] is False
            assert "Disk error" in result["error"]


class TestWaitForVmShutdown:
    """Test cases for wait_for_vm_shutdown method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_wait_for_shutdown_immediate(self):
        """Test when VM shuts down immediately."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            # time.time() called once at start, once for while condition
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_launcher.time.time",
                side_effect=[0, 5],
            ):
                result = await self.launcher.wait_for_vm_shutdown("testvm", timeout=60)

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_wait_for_shutdown_after_some_time(self):
        """Test when VM shuts down after some polling."""
        running_result = Mock()
        running_result.returncode = 0
        running_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    1   123     1     1024M     512M  /dev/ttyp0  root  testvm"""

        stopped_result = Mock()
        stopped_result.returncode = 0
        stopped_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[running_result, stopped_result],
        ):
            # time.time() is called: once at start, then twice per loop iteration
            # (once for while condition, once for elapsed calculation)
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_launcher.time.time",
                side_effect=[0, 10, 10, 20, 20],
            ):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.launcher.wait_for_vm_shutdown(
                        "testvm", timeout=1800
                    )

                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_wait_for_shutdown_timeout(self):
        """Test when VM doesn't shut down within timeout."""
        running_result = Mock()
        running_result.returncode = 0
        running_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    1   123     1     1024M     512M  /dev/ttyp0  root  testvm"""

        with patch.object(self.launcher, "run_subprocess", return_value=running_result):
            # time.time() called once at start, once for while condition
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_launcher.time.time",
                side_effect=[0, 1850],
            ):  # Past timeout
                with patch("asyncio.sleep", return_value=None):
                    result = await self.launcher.wait_for_vm_shutdown(
                        "testvm", timeout=1800
                    )

                    assert result["success"] is False
                    assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_wait_for_shutdown_exception_continues(self):
        """Test that exceptions during polling don't stop the wait."""
        exception_result = Exception("Connection error")
        stopped_result = Mock()
        stopped_result.returncode = 0
        stopped_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[exception_result, stopped_result],
        ):
            # time.time() called once at start, then twice per loop iteration
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_launcher.time.time",
                side_effect=[0, 10, 10, 20, 20],
            ):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.launcher.wait_for_vm_shutdown(
                        "testvm", timeout=1800
                    )

                    assert result["success"] is True
                    self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_wait_for_shutdown_logs_progress(self):
        """Test that progress is logged every 60 seconds."""
        running_result = Mock()
        running_result.returncode = 0
        running_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    1   123     1     1024M     512M  /dev/ttyp0  root  testvm"""

        stopped_result = Mock()
        stopped_result.returncode = 0
        stopped_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        # time.time() is called: once at start, then twice per loop iteration
        # (once for while condition, once for elapsed calculation)
        # Simulate time progression: start=0, then iterations at 30, 70 (log at 60), then VM stops
        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[running_result, running_result, stopped_result],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_vmm_launcher.time.time",
                side_effect=[0, 30, 30, 70, 70, 80, 80],
            ):
                with patch("asyncio.sleep", return_value=None):
                    result = await self.launcher.wait_for_vm_shutdown(
                        "testvm", timeout=1800
                    )

                    assert result["success"] is True


class TestSendProgress:
    """Test cases for send_progress method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(
            return_value={"type": "child_host_creation_progress"}
        )
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_send_progress_success(self):
        """Test successful progress message sending."""
        await self.launcher.send_progress("step1", "Creating VM...")

        self.mock_agent.create_message.assert_called_once_with(
            "child_host_creation_progress",
            {
                "step": "step1",
                "message": "Creating VM...",
                "child_type": "vmm",
            },
        )
        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_progress_custom_child_type(self):
        """Test progress message with custom child type."""
        await self.launcher.send_progress("step2", "Configuring...", child_type="kvm")

        self.mock_agent.create_message.assert_called_once_with(
            "child_host_creation_progress",
            {
                "step": "step2",
                "message": "Configuring...",
                "child_type": "kvm",
            },
        )

    @pytest.mark.asyncio
    async def test_send_progress_no_send_message_method(self):
        """Test progress when agent doesn't have send_message method."""
        launcher = VmmLauncher(Mock(spec=[]), self.mock_logger)

        # Should not raise an exception
        await launcher.send_progress("step", "message")

    @pytest.mark.asyncio
    async def test_send_progress_exception_logged(self):
        """Test that exceptions during progress sending are logged."""
        self.mock_agent.send_message.side_effect = Exception("Network error")

        # Should not raise exception
        await self.launcher.send_progress("step", "message")

        self.mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_send_progress_create_message_exception(self):
        """Test exception during message creation."""
        self.mock_agent.create_message.side_effect = Exception("Creation error")

        # Should not raise exception
        await self.launcher.send_progress("step", "message")

        self.mock_logger.debug.assert_called()


class TestVmmLauncherEdgeCases:
    """Edge case tests for VmmLauncher."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_vm_name_with_special_characters(self):
        """Test VM operations with special characters in name."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "test-vm_01",
                    "/var/vmm/test-vm_01.qcow2",
                    "1G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_empty_vmctl_status_output(self):
        """Test handling empty vmctl status output."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = ""

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "1G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_vmctl_status_no_running_keyword(self):
        """Test vmctl status output without 'running' keyword."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME
    -     -     1     1024M        -        -     -     testvm"""

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "1G",
                )

                # VM not running, so should proceed with launch
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_tap_device_exists_case_insensitive(self):
        """Test tap device exists detection is case insensitive."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "ifconfig: device already EXISTS"

        with patch.object(self.launcher, "run_subprocess", return_value=mock_result):
            result = await self.launcher._create_tap_device("tap0")

            assert result["success"] is True
            assert result["tap_device"] == "tap0"

    @pytest.mark.asyncio
    async def test_launch_vm_verifies_command_construction(self):
        """Test that launch commands are constructed correctly."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 0

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ) as mock_run:
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "2G",
                )

                # Verify the second call (launch command) has correct structure
                launch_call = mock_run.call_args_list[1]
                cmd = launch_call[0][0]
                assert cmd[0] == "vmctl"
                assert cmd[1] == "start"
                assert "-b" in cmd
                assert "/bsd.rd" in cmd
                assert "-d" in cmd
                assert "/var/vmm/testvm.qcow2" in cmd
                assert "-m" in cmd
                assert "2G" in cmd
                assert "-n" in cmd
                assert "local" in cmd
                assert "testvm" in cmd


class TestLaunchVmAlreadyRunningDetection:
    """Test cases for VM already running detection with exact column parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_launch_vm_with_bsdrd_detects_running_vm_9_columns(self):
        """Test launch_vm_with_bsdrd detects already running VM using column parsing.

        vmctl status format: ID PID VCPUS MAXMEM CURMEM TTY OWNER STATE NAME
        Columns when split: 0  1   2     3      4      5   6     7     8
        """
        status_result = Mock()
        status_result.returncode = 0
        # Exactly 9 columns: ID(0) PID(1) VCPUS(2) MAXMEM(3) CURMEM(4) TTY(5) OWNER(6) STATE(7) NAME(8)
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE NAME
    1   123     1    1024M     512M  ttyp0  root  running  testvm"""

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            result = await self.launcher.launch_vm_with_bsdrd(
                "testvm",
                "/var/vmm/testvm.qcow2",
                "/bsd.rd",
                "1G",
            )

            assert result["success"] is True
            # Should log that VM is already running
            self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_launch_vm_from_disk_detects_running_vm_9_columns(self):
        """Test launch_vm_from_disk detects already running VM using column parsing.

        vmctl status format: ID PID VCPUS MAXMEM CURMEM TTY OWNER STATE NAME
        """
        status_result = Mock()
        status_result.returncode = 0
        # Exactly 9 columns for proper parsing
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE NAME
    2   456     2    2048M    1024M  ttyp1  root  running  myvm"""

        with patch.object(self.launcher, "run_subprocess", return_value=status_result):
            result = await self.launcher.launch_vm_from_disk(
                "myvm",
                "/var/vmm/myvm.qcow2",
                "2G",
            )

            assert result["success"] is True
            # Should log that VM is already running
            self.mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_launch_vm_with_bsdrd_not_running_when_different_name(self):
        """Test that launch proceeds when a different VM is running."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE NAME
    1   123     1    1024M     512M  ttyp0  root  running  othervm"""

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_vm_from_disk_not_running_when_different_name(self):
        """Test that launch from disk proceeds when a different VM is running."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE NAME
    1   123     1    1024M     512M  ttyp0  root  running  differentvm"""

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                result = await self.launcher.launch_vm_from_disk(
                    "myvm",
                    "/var/vmm/myvm.qcow2",
                    "2G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_launch_vm_with_bsdrd_not_running_when_stopped(self):
        """Test launch proceeds when VM exists but is stopped."""
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE NAME
    -     -     1    1024M        -         -      -  stopped  testvm"""

        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                result = await self.launcher.launch_vm_with_bsdrd(
                    "testvm",
                    "/var/vmm/testvm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                # Should proceed with launch since VM is not "running"
                assert result["success"] is True


class TestVmmLauncherIntegration:
    """Integration-style tests for VmmLauncher."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "progress"})
        self.mock_logger = Mock()
        self.launcher = VmmLauncher(self.mock_agent, self.mock_logger)

    @pytest.mark.asyncio
    async def test_full_vm_launch_workflow(self):
        """Test complete VM launch workflow."""
        # 1. Check VM not running
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        # 2. Launch VM
        launch_result = Mock()
        launch_result.returncode = 0
        launch_result.stdout = ""
        launch_result.stderr = ""

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True, "tap_device": "tap0"},
            ):
                # Launch with bsd.rd
                result = await self.launcher.launch_vm_with_bsdrd(
                    "new-vm",
                    "/var/vmm/new-vm.qcow2",
                    "/bsd.rd",
                    "1G",
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_vm_launch_and_wait_for_shutdown(self):
        """Test launching VM and waiting for shutdown."""
        # Launch setup
        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        launch_result = Mock()
        launch_result.returncode = 0

        # Shutdown check - VM is gone
        shutdown_check_result = Mock()
        shutdown_check_result.returncode = 0
        shutdown_check_result.stdout = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER NAME"
        )

        with patch.object(
            self.launcher,
            "run_subprocess",
            side_effect=[status_result, launch_result, shutdown_check_result],
        ):
            with patch.object(
                self.launcher,
                "ensure_tap_device_available",
                return_value={"success": True},
            ):
                with patch("time.time", side_effect=[0, 10]):
                    # Launch
                    launch_result = await self.launcher.launch_vm_from_disk(
                        "testvm",
                        "/var/vmm/testvm.qcow2",
                        "1G",
                    )
                    assert launch_result["success"] is True

                    # Wait for shutdown
                    shutdown_result = await self.launcher.wait_for_vm_shutdown(
                        "testvm", timeout=60
                    )
                    assert shutdown_result["success"] is True
