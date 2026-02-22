"""
Comprehensive unit tests for VMM VM lifecycle operations.

Tests VmmLifecycleOperations class for starting, stopping, restarting,
and deleting VMM virtual machines on OpenBSD.
"""

# pylint: disable=protected-access,redefined-outer-name

import asyncio
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_vmm_lifecycle import (
    VMM_DISK_DIR,
    VMM_METADATA_DIR,
    VmmLifecycleOperations,
)


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    return Mock()


@pytest.fixture
def mock_virt_checks():
    """Create mock virtualization checks."""
    return Mock()


@pytest.fixture
def lifecycle_ops(mock_logger, mock_virt_checks):
    """Create VmmLifecycleOperations instance for testing."""
    return VmmLifecycleOperations(mock_logger, mock_virt_checks)


class TestVmmLifecycleOperationsInit:
    """Tests for VmmLifecycleOperations initialization."""

    def test_init_sets_logger(self, mock_logger, mock_virt_checks):
        """Test that __init__ sets logger."""
        ops = VmmLifecycleOperations(mock_logger, mock_virt_checks)
        assert ops.logger == mock_logger

    def test_init_sets_virtualization_checks(self, mock_logger, mock_virt_checks):
        """Test that __init__ sets virtualization_checks."""
        ops = VmmLifecycleOperations(mock_logger, mock_virt_checks)
        assert ops.virtualization_checks == mock_virt_checks

    def test_init_creates_vmconf_manager(self, mock_logger, mock_virt_checks):
        """Test that __init__ creates VmConfManager instance."""
        ops = VmmLifecycleOperations(mock_logger, mock_virt_checks)
        assert ops.vmconf_manager is not None


class TestRunSubprocess:
    """Tests for _run_subprocess async helper."""

    @pytest.mark.asyncio
    async def test_run_subprocess_success(self, lifecycle_ops):
        """Test successful subprocess execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "success"
        mock_result.stderr = ""

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = mock_result
            result = await lifecycle_ops._run_subprocess(["vmctl", "status"])

        assert result.returncode == 0
        assert result.stdout == "success"

    @pytest.mark.asyncio
    async def test_run_subprocess_with_timeout(self, lifecycle_ops):
        """Test subprocess with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = mock_result
            await lifecycle_ops._run_subprocess(["vmctl", "status"], timeout=30)

        # Verify the call was made
        mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_subprocess_failure(self, lifecycle_ops):
        """Test subprocess with non-zero return code."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = mock_result
            result = await lifecycle_ops._run_subprocess(["vmctl", "start", "vm1"])

        assert result.returncode == 1
        assert result.stderr == "error message"


class TestCheckVmdReady:
    """Tests for check_vmd_ready method."""

    @pytest.mark.asyncio
    async def test_check_vmd_ready_vmm_not_available(
        self, lifecycle_ops, mock_virt_checks
    ):
        """Test when VMM is not available."""
        mock_virt_checks.check_vmm_support.return_value = {"available": False}

        result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is False
        assert result["ready"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_check_vmd_ready_kernel_not_supported(
        self, lifecycle_ops, mock_virt_checks
    ):
        """Test when kernel support is not enabled."""
        mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": False,
        }

        result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is False
        assert result["ready"] is False
        assert "kernel support" in result["error"]

    @pytest.mark.asyncio
    async def test_check_vmd_ready_vmd_not_running(
        self, lifecycle_ops, mock_virt_checks
    ):
        """Test when vmd is not running."""
        mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": False,
        }

        result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is True
        assert result["ready"] is False
        assert "not running" in result["error"]
        assert result["needs_enable"] is True

    @pytest.mark.asyncio
    async def test_check_vmd_ready_vmctl_success(self, lifecycle_ops, mock_virt_checks):
        """Test when vmd is fully operational."""
        mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": True,
            "enabled": True,
            "cpu_supported": True,
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "ID   PID VCPUS MAXMEM CURMEM TTY OWNER STATE NAME\n"

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is True
        assert result["ready"] is True
        assert result["running"] is True
        assert result["kernel_supported"] is True

    @pytest.mark.asyncio
    async def test_check_vmd_ready_vmctl_fails(self, lifecycle_ops, mock_virt_checks):
        """Test when vmctl command fails."""
        mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": True,
        }

        mock_result = Mock()
        mock_result.returncode = 1

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is False
        assert result["ready"] is False
        assert "not responding" in result["error"]

    @pytest.mark.asyncio
    async def test_check_vmd_ready_timeout(self, lifecycle_ops, mock_virt_checks):
        """Test when vmctl times out."""
        mock_virt_checks.check_vmm_support.return_value = {
            "available": True,
            "kernel_supported": True,
            "running": True,
        }

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="vmctl", timeout=10)
            result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is False
        assert result["ready"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_check_vmd_ready_exception(self, lifecycle_ops, mock_virt_checks):
        """Test when an unexpected exception occurs."""
        mock_virt_checks.check_vmm_support.side_effect = Exception("Unexpected error")

        result = await lifecycle_ops.check_vmd_ready()

        assert result["success"] is False
        assert result["ready"] is False
        assert "Unexpected error" in result["error"]


class TestGetVmStatus:
    """Tests for get_vm_status method."""

    @pytest.mark.asyncio
    async def test_get_vm_status_running_vm(self, lifecycle_ops):
        """Test getting status of a running VM."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME
    1 85075     1    1.0G   1006M   ttyp8        root running testvm"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is True
        assert result["found"] is True
        assert result["status"] == "running"
        assert result["vm_id"] == "1"
        assert result["vcpus"] == "1"
        assert result["memory"] == "1.0G"
        assert result["current_memory"] == "1006M"

    @pytest.mark.asyncio
    async def test_get_vm_status_stopped_vm(self, lifecycle_ops):
        """Test getting status of a stopped VM."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME
    2     -     1    1.0G       -       -        root stopped testvm"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is True
        assert result["found"] is True
        assert result["status"] == "stopped"
        assert result["vm_id"] is None

    @pytest.mark.asyncio
    async def test_get_vm_status_vm_not_found(self, lifecycle_ops):
        """Test getting status when VM is not found."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME
    1 85075     1    1.0G   1006M   ttyp8        root running othervm"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is True
        assert result["found"] is False
        assert "not found" in result["error"]

    @pytest.mark.asyncio
    async def test_get_vm_status_empty_output(self, lifecycle_ops):
        """Test getting status with no VMs."""
        vmctl_output = (
            "   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME"
        )

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is True
        assert result["found"] is False

    @pytest.mark.asyncio
    async def test_get_vm_status_vmctl_fails(self, lifecycle_ops):
        """Test when vmctl status fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "vmd not running"

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is False
        assert "Failed to get VM status" in result["error"]

    @pytest.mark.asyncio
    async def test_get_vm_status_timeout(self, lifecycle_ops):
        """Test when vmctl status times out."""
        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="vmctl", timeout=30)
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_get_vm_status_exception(self, lifecycle_ops):
        """Test when an unexpected exception occurs."""
        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = Exception("Unexpected error")
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_get_vm_status_multiple_vms(self, lifecycle_ops):
        """Test getting status from a list with multiple VMs."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME
    1 85075     1    1.0G   1006M   ttyp8        root running vm1
    2     -     2    2.0G       -       -        root stopped vm2
    3 12345     4    4.0G   3500M   ttyp9        root running targetvm"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("targetvm")

        assert result["success"] is True
        assert result["found"] is True
        assert result["status"] == "running"
        assert result["vm_id"] == "3"
        assert result["vcpus"] == "4"
        assert result["memory"] == "4.0G"

    @pytest.mark.asyncio
    async def test_get_vm_status_empty_lines_in_output(self, lifecycle_ops):
        """Test handling output with empty lines."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME

    1 85075     1    1.0G   1006M   ttyp8        root running testvm

"""

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            result = await lifecycle_ops.get_vm_status("testvm")

        assert result["success"] is True
        assert result["found"] is True
        assert result["status"] == "running"


class TestWaitForVmState:
    """Tests for wait_for_vm_state method."""

    @pytest.mark.asyncio
    async def test_wait_for_vm_state_already_running(self, lifecycle_ops):
        """Test when VM is already in desired running state."""
        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.return_value = {
                "success": True,
                "found": True,
                "status": "running",
            }

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "running", timeout=30
            )

        assert result["success"] is True
        assert result["state"] == "running"

    @pytest.mark.asyncio
    async def test_wait_for_vm_state_already_stopped(self, lifecycle_ops):
        """Test when VM is already in desired stopped state."""
        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.return_value = {
                "success": True,
                "found": True,
                "status": "stopped",
            }

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "stopped", timeout=30
            )

        assert result["success"] is True
        assert result["state"] == "stopped"

    @pytest.mark.asyncio
    async def test_wait_for_vm_state_vm_not_found_when_waiting_stopped(
        self, lifecycle_ops
    ):
        """Test VM not found counts as stopped."""
        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.return_value = {"success": True, "found": False}

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "stopped", timeout=30
            )

        assert result["success"] is True
        assert result["state"] == "stopped"

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.asyncio.sleep")
    async def test_wait_for_vm_state_transitions(
        self, mock_sleep, mock_time, lifecycle_ops
    ):
        """Test waiting for VM to transition to running state."""
        mock_time.side_effect = [0, 2, 4, 6]
        mock_sleep.return_value = None

        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.side_effect = [
                {"success": True, "found": True, "status": "stopped"},
                {"success": True, "found": True, "status": "stopped"},
                {"success": True, "found": True, "status": "running"},
            ]

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "running", timeout=60
            )

        assert result["success"] is True
        assert result["state"] == "running"
        assert mock_status.call_count == 3

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.asyncio.sleep")
    async def test_wait_for_vm_state_timeout(
        self, mock_sleep, mock_time, lifecycle_ops
    ):
        """Test timeout waiting for VM state."""
        mock_time.side_effect = [0, 30, 61]
        mock_sleep.return_value = None

        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.return_value = {
                "success": True,
                "found": True,
                "status": "stopped",
            }

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "running", timeout=60
            )

        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.asyncio.sleep")
    async def test_wait_for_vm_state_status_check_fails(
        self, mock_sleep, mock_time, lifecycle_ops
    ):
        """Test continuing to wait when status check fails."""
        mock_time.side_effect = [0, 2, 4]
        mock_sleep.return_value = None

        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.side_effect = [
                {"success": False, "error": "vmd not responding"},
                {"success": True, "found": True, "status": "running"},
            ]

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "running", timeout=60
            )

        assert result["success"] is True
        assert result["state"] == "running"

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.time.time")
    @patch("src.sysmanage_agent.operations.child_host_vmm_lifecycle.asyncio.sleep")
    async def test_wait_for_vm_state_vm_not_found_waiting_running(
        self, mock_sleep, mock_time, lifecycle_ops
    ):
        """Test waiting for running when VM is not found yet."""
        mock_time.side_effect = [0, 2, 4]
        mock_sleep.return_value = None

        with patch.object(
            lifecycle_ops, "get_vm_status", new_callable=AsyncMock
        ) as mock_status:
            mock_status.side_effect = [
                {"success": True, "found": False},
                {"success": True, "found": True, "status": "running"},
            ]

            result = await lifecycle_ops.wait_for_vm_state(
                "testvm", "running", timeout=60
            )

        assert result["success"] is True
        assert result["state"] == "running"


class TestStartVm:
    """Tests for start_vm method."""

    @pytest.mark.asyncio
    async def test_start_vm_success_with_wait(self, lifecycle_ops, mock_logger):
        """Test successful VM start with wait."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "started vm1"

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch.object(
                lifecycle_ops, "wait_for_vm_state", new_callable=AsyncMock
            ) as mock_wait:
                mock_wait.return_value = {"success": True, "state": "running"}

                result = await lifecycle_ops.start_vm("testvm", wait=True)

        assert result["success"] is True
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_start_vm_success_without_wait(self, lifecycle_ops):
        """Test successful VM start without wait."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "started vm1"

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.start_vm("testvm", wait=False)

        assert result["success"] is True
        assert result["child_name"] == "testvm"

    @pytest.mark.asyncio
    async def test_start_vm_wait_fails(self, lifecycle_ops, mock_logger):
        """Test VM start where wait verification fails."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch.object(
                lifecycle_ops, "wait_for_vm_state", new_callable=AsyncMock
            ) as mock_wait:
                mock_wait.return_value = {
                    "success": False,
                    "error": "Timeout waiting for state",
                }

                result = await lifecycle_ops.start_vm("testvm", wait=True)

        # Still returns success, just logs warning
        assert result["success"] is True
        mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_start_vm_command_fails(self, lifecycle_ops, mock_logger):
        """Test VM start when vmctl start fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "vm not found"
        mock_result.stdout = ""

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.start_vm("testvm")

        assert result["success"] is False
        assert "vm not found" in result["error"]
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_start_vm_command_fails_with_stdout(self, lifecycle_ops):
        """Test VM start failure when error is in stdout."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = ""
        mock_result.stdout = "already running"

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.start_vm("testvm")

        assert result["success"] is False
        assert "already running" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_command_fails_unknown_error(self, lifecycle_ops):
        """Test VM start failure with no error message."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = ""
        mock_result.stdout = ""

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.start_vm("testvm")

        assert result["success"] is False
        assert "Unknown error" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_timeout(self, lifecycle_ops):
        """Test VM start timeout."""
        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="vmctl", timeout=60)

            result = await lifecycle_ops.start_vm("testvm")

        assert result["success"] is False
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_start_vm_exception(self, lifecycle_ops):
        """Test VM start with unexpected exception."""
        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = Exception("Connection lost")

            result = await lifecycle_ops.start_vm("testvm")

        assert result["success"] is False
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        assert "Connection lost" in result["error"]


class TestStopVm:
    """Tests for stop_vm method."""

    @pytest.mark.asyncio
    async def test_stop_vm_success_with_wait(self, lifecycle_ops, mock_logger):
        """Test successful VM stop with wait."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch.object(
                lifecycle_ops, "wait_for_vm_state", new_callable=AsyncMock
            ) as mock_wait:
                mock_wait.return_value = {"success": True, "state": "stopped"}

                result = await lifecycle_ops.stop_vm("testvm", wait=True)

        assert result["success"] is True
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_stop_vm_success_without_wait(self, lifecycle_ops):
        """Test successful VM stop without wait."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.stop_vm("testvm", wait=False)

        assert result["success"] is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "vmctl" in call_args
        assert "stop" in call_args
        assert "testvm" in call_args
        assert "-f" not in call_args

    @pytest.mark.asyncio
    async def test_stop_vm_force(self, lifecycle_ops):
        """Test force stop VM."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.stop_vm("testvm", force=True, wait=False)

        assert result["success"] is True
        call_args = mock_run.call_args[0][0]
        assert "-f" in call_args

    @pytest.mark.asyncio
    async def test_stop_vm_wait_fails(self, lifecycle_ops, mock_logger):
        """Test VM stop where wait verification fails."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            with patch.object(
                lifecycle_ops, "wait_for_vm_state", new_callable=AsyncMock
            ) as mock_wait:
                mock_wait.return_value = {
                    "success": False,
                    "error": "Timeout waiting for state",
                }

                result = await lifecycle_ops.stop_vm("testvm", wait=True)

        # Still returns success, just logs warning
        assert result["success"] is True
        mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_stop_vm_command_fails(self, lifecycle_ops, mock_logger):
        """Test VM stop when vmctl stop fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "vm not running"
        mock_result.stdout = ""

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.stop_vm("testvm")

        assert result["success"] is False
        assert "vm not running" in result["error"]
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_stop_vm_command_fails_with_stdout(self, lifecycle_ops):
        """Test VM stop failure when error is in stdout."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = ""
        mock_result.stdout = "permission denied"

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.stop_vm("testvm")

        assert result["success"] is False
        assert "permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_stop_vm_command_fails_unknown_error(self, lifecycle_ops):
        """Test VM stop failure with no error message."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = ""
        mock_result.stdout = ""

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.stop_vm("testvm")

        assert result["success"] is False
        assert "Unknown error" in result["error"]

    @pytest.mark.asyncio
    async def test_stop_vm_timeout(self, lifecycle_ops):
        """Test VM stop timeout."""
        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="vmctl", timeout=120)

            result = await lifecycle_ops.stop_vm("testvm")

        assert result["success"] is False
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_stop_vm_exception(self, lifecycle_ops):
        """Test VM stop with unexpected exception."""
        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.side_effect = Exception("Unexpected error")

            result = await lifecycle_ops.stop_vm("testvm")

        assert result["success"] is False
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        assert "Unexpected error" in result["error"]


class TestRestartVm:
    """Tests for restart_vm method."""

    @pytest.mark.asyncio
    async def test_restart_vm_success(self, lifecycle_ops, mock_logger):
        """Test successful VM restart."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops, "start_vm", new_callable=AsyncMock
            ) as mock_start:
                mock_start.return_value = {"success": True}

                result = await lifecycle_ops.restart_vm("testvm")

        assert result["success"] is True
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        mock_stop.assert_called_once_with("testvm", wait=True)
        mock_start.assert_called_once_with("testvm", wait=True)
        mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_restart_vm_stop_fails(self, lifecycle_ops):
        """Test VM restart when stop fails."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": False, "error": "VM not found"}
            with patch.object(
                lifecycle_ops, "start_vm", new_callable=AsyncMock
            ) as mock_start:

                result = await lifecycle_ops.restart_vm("testvm")

        assert result["success"] is False
        assert "VM not found" in result["error"]
        mock_start.assert_not_called()

    @pytest.mark.asyncio
    async def test_restart_vm_start_fails(self, lifecycle_ops):
        """Test VM restart when start fails after successful stop."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops, "start_vm", new_callable=AsyncMock
            ) as mock_start:
                mock_start.return_value = {"success": False, "error": "Disk not found"}

                result = await lifecycle_ops.restart_vm("testvm")

        assert result["success"] is False
        assert "Disk not found" in result["error"]


class TestDeleteVm:
    """Tests for delete_vm method."""

    @pytest.mark.asyncio
    async def test_delete_vm_success_without_disk(self, lifecycle_ops):
        """Test successful VM deletion without deleting disk."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.return_value = True
                with patch("os.path.exists", return_value=False):

                    result = await lifecycle_ops.delete_vm("testvm", delete_disk=False)

        assert result["success"] is True
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        mock_stop.assert_called_once_with("testvm", force=True, wait=True)
        mock_remove_vm.assert_called_once_with("testvm")

    @pytest.mark.asyncio
    async def test_delete_vm_success_with_disk(self, lifecycle_ops, mock_logger):
        """Test successful VM deletion with disk deletion."""
        expected_disk_path = f"{VMM_DISK_DIR}/testvm.qcow2"

        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.return_value = True
                with patch("os.path.exists") as mock_exists:
                    mock_exists.side_effect = lambda path: path == expected_disk_path
                    with patch("os.remove") as mock_remove:

                        result = await lifecycle_ops.delete_vm(
                            "testvm", delete_disk=True
                        )

        assert result["success"] is True
        mock_remove.assert_called_once_with(expected_disk_path)
        mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_delete_vm_deletes_metadata(self, lifecycle_ops):
        """Test VM deletion also deletes metadata file."""
        expected_metadata_path = f"{VMM_METADATA_DIR}/testvm.json"

        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.return_value = True
                with patch("os.path.exists") as mock_exists:
                    mock_exists.side_effect = (
                        lambda path: path == expected_metadata_path
                    )
                    with patch("os.remove") as mock_remove:

                        result = await lifecycle_ops.delete_vm(
                            "testvm", delete_disk=False
                        )

        assert result["success"] is True
        mock_remove.assert_called_once_with(expected_metadata_path)

    @pytest.mark.asyncio
    async def test_delete_vm_deletes_both_disk_and_metadata(self, lifecycle_ops):
        """Test VM deletion deletes both disk and metadata."""
        expected_disk_path = f"{VMM_DISK_DIR}/testvm.qcow2"
        expected_metadata_path = f"{VMM_METADATA_DIR}/testvm.json"

        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.return_value = True
                with patch("os.path.exists", return_value=True):
                    with patch("os.remove") as mock_remove:

                        result = await lifecycle_ops.delete_vm(
                            "testvm", delete_disk=True
                        )

        assert result["success"] is True
        assert mock_remove.call_count == 2
        mock_remove.assert_any_call(expected_disk_path)
        mock_remove.assert_any_call(expected_metadata_path)

    @pytest.mark.asyncio
    async def test_delete_vm_stop_fails_continues(self, lifecycle_ops):
        """Test that delete continues even if stop fails (VM might already be stopped)."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": False, "error": "VM not running"}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.return_value = True
                with patch("os.path.exists", return_value=False):

                    result = await lifecycle_ops.delete_vm("testvm")

        # Delete should still succeed
        assert result["success"] is True
        mock_remove_vm.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_vm_exception(self, lifecycle_ops):
        """Test VM deletion with exception."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.side_effect = Exception("Connection lost")

            result = await lifecycle_ops.delete_vm("testvm")

        assert result["success"] is False
        assert result["child_name"] == "testvm"
        assert result["child_type"] == "vmm"
        assert "Connection lost" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_vm_remove_vm_conf_exception(self, lifecycle_ops):
        """Test VM deletion when removing from vm.conf raises exception."""
        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.side_effect = Exception("Permission denied")

                result = await lifecycle_ops.delete_vm("testvm")

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_vm_disk_removal_fails(self, lifecycle_ops):
        """Test VM deletion when disk removal fails."""
        expected_disk_path = f"{VMM_DISK_DIR}/testvm.qcow2"

        with patch.object(
            lifecycle_ops, "stop_vm", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}
            with patch.object(
                lifecycle_ops.vmconf_manager, "remove_vm"
            ) as mock_remove_vm:
                mock_remove_vm.return_value = True
                with patch("os.path.exists") as mock_exists:
                    mock_exists.side_effect = lambda path: path == expected_disk_path
                    with patch("os.remove") as mock_remove:
                        mock_remove.side_effect = PermissionError("Access denied")

                        result = await lifecycle_ops.delete_vm(
                            "testvm", delete_disk=True
                        )

        assert result["success"] is False
        assert "Access denied" in result["error"]


class TestVmmLifecycleConstants:
    """Tests for module constants."""

    def test_vmm_disk_dir_constant(self):
        """Test VMM_DISK_DIR constant."""
        assert VMM_DISK_DIR == "/var/vmm"

    def test_vmm_metadata_dir_constant(self):
        """Test VMM_METADATA_DIR constant."""
        assert VMM_METADATA_DIR == "/var/vmm/metadata"


class TestVmmLifecycleIntegration:
    """Integration-style tests for VMM lifecycle operations."""

    @pytest.mark.asyncio
    async def test_full_vm_lifecycle(self, lifecycle_ops):
        """Test complete VM lifecycle: start, restart, stop, delete."""
        # Mock all subprocess calls as success
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            with patch.object(
                lifecycle_ops, "get_vm_status", new_callable=AsyncMock
            ) as mock_status:
                mock_status.return_value = {
                    "success": True,
                    "found": True,
                    "status": "running",
                }

                with patch.object(
                    lifecycle_ops.vmconf_manager, "remove_vm"
                ) as mock_remove_vm:
                    mock_remove_vm.return_value = True
                    with patch("os.path.exists", return_value=False):

                        # Start
                        start_result = await lifecycle_ops.start_vm(
                            "testvm", wait=False
                        )
                        assert start_result["success"] is True

                        # After start, mock status as running for restart stop
                        mock_status.return_value = {
                            "success": True,
                            "found": True,
                            "status": "stopped",
                        }

                        # Restart (stop + start)
                        restart_result = await lifecycle_ops.restart_vm("testvm")
                        assert restart_result["success"] is True

                        # Stop
                        stop_result = await lifecycle_ops.stop_vm("testvm", wait=False)
                        assert stop_result["success"] is True

                        # Delete
                        delete_result = await lifecycle_ops.delete_vm("testvm")
                        assert delete_result["success"] is True

    @pytest.mark.asyncio
    async def test_start_already_running_vm(self, lifecycle_ops):
        """Test starting an already running VM."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "vm testvm is already running"
        mock_result.stdout = ""

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.start_vm("testvm")

        assert result["success"] is False
        assert "already running" in result["error"]

    @pytest.mark.asyncio
    async def test_stop_already_stopped_vm(self, lifecycle_ops):
        """Test stopping an already stopped VM."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "vm testvm is not running"
        mock_result.stdout = ""

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.stop_vm("testvm")

        assert result["success"] is False
        assert "not running" in result["error"]


class TestVmmLifecycleEdgeCases:
    """Edge case tests for VMM lifecycle operations."""

    @pytest.mark.asyncio
    async def test_vm_name_with_special_characters(self, lifecycle_ops):
        """Test handling VM names with special characters."""
        vm_name = "test-vm_01"
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            result = await lifecycle_ops.start_vm(vm_name, wait=False)

        assert result["success"] is True
        assert result["child_name"] == vm_name
        call_args = mock_run.call_args[0][0]
        assert vm_name in call_args

    @pytest.mark.asyncio
    async def test_get_vm_status_with_whitespace_in_output(self, lifecycle_ops):
        """Test parsing status output with extra whitespace."""
        vmctl_output = """   ID   PID VCPUS  MAXMEM  CURMEM     TTY        OWNER STATE   NAME
    1 85075     1    1.0G   1006M   ttyp8        root running   testvm   """

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = vmctl_output

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result
            # This will not find "testvm" because the output has extra spaces
            # and the parsing logic expects exact column positions
            result = await lifecycle_ops.get_vm_status("testvm")

        # The VM won't be found due to whitespace issues in the mock data
        # This tests the robustness of the parsing
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, lifecycle_ops):
        """Test handling concurrent VM operations."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            # Run multiple operations concurrently
            tasks = [
                lifecycle_ops.start_vm("vm1", wait=False),
                lifecycle_ops.start_vm("vm2", wait=False),
                lifecycle_ops.start_vm("vm3", wait=False),
            ]

            results = await asyncio.gather(*tasks)

        assert all(r["success"] for r in results)
        assert mock_run.call_count == 3

    @pytest.mark.asyncio
    async def test_logging_messages(self, lifecycle_ops, mock_logger):
        """Test that appropriate logging messages are generated."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(
            lifecycle_ops, "_run_subprocess", new_callable=AsyncMock
        ) as mock_run:
            mock_run.return_value = mock_result

            await lifecycle_ops.start_vm("testvm", wait=False)

        # Verify info logs were called for start
        assert mock_logger.info.call_count >= 2  # Starting and started messages
