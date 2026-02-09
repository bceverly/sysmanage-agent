"""
Tests for Linux virtualization support check methods.
Tests KVM and LXD detection on Linux systems.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations._virtualization_linux import (
    LinuxVirtualizationMixin,
)


class VirtHelper(LinuxVirtualizationMixin):
    """Helper class that implements the mixin (not prefixed with Test)."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)


@pytest.fixture
def virt_helper():
    """Create a virtualization helper for testing."""
    return VirtHelper()


class TestIsUbuntu22OrNewer:
    """Tests for _is_ubuntu_22_or_newer method."""

    def test_ubuntu_22_04(self, virt_helper):
        """Test Ubuntu 22.04 detection."""
        os_release_content = 'ID=ubuntu\nVERSION_ID="22.04"\n'

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(
                    os_release_content.split("\n")
                )
                result = virt_helper._is_ubuntu_22_or_newer()

        assert result is True

    def test_ubuntu_24_04(self, virt_helper):
        """Test Ubuntu 24.04 detection."""
        os_release_content = 'ID=ubuntu\nVERSION_ID="24.04"\n'

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(
                    os_release_content.split("\n")
                )
                result = virt_helper._is_ubuntu_22_or_newer()

        assert result is True

    def test_ubuntu_20_04(self, virt_helper):
        """Test Ubuntu 20.04 (too old) detection."""
        os_release_content = 'ID=ubuntu\nVERSION_ID="20.04"\n'

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(
                    os_release_content.split("\n")
                )
                result = virt_helper._is_ubuntu_22_or_newer()

        assert result is False

    def test_not_ubuntu(self, virt_helper):
        """Test non-Ubuntu distribution."""
        os_release_content = 'ID=debian\nVERSION_ID="12"\n'

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(
                    os_release_content.split("\n")
                )
                result = virt_helper._is_ubuntu_22_or_newer()

        assert result is False

    def test_no_os_release_file(self, virt_helper):
        """Test when /etc/os-release doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = virt_helper._is_ubuntu_22_or_newer()

        assert result is False

    def test_exception_handling(self, virt_helper):
        """Test exception handling in version detection."""
        with patch("os.path.exists", side_effect=Exception("Error")):
            result = virt_helper._is_ubuntu_22_or_newer()

        assert result is False


class TestIsUserInLxdGroup:
    """Tests for _is_user_in_lxd_group method."""

    def test_user_in_lxd_group(self, virt_helper):
        """Test when user is in lxd group."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        mock_grp = Mock()
        mock_grp.gr_mem = ["testuser", "otheruser"]

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=1000):
                with patch("grp.getgrnam", return_value=mock_grp):
                    result = virt_helper._is_user_in_lxd_group()

        assert result is True

    def test_user_not_in_lxd_group(self, virt_helper):
        """Test when user is not in lxd group."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        mock_grp = Mock()
        mock_grp.gr_mem = ["otheruser"]

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=1000):
                with patch("grp.getgrnam", return_value=mock_grp):
                    result = virt_helper._is_user_in_lxd_group()

        assert result is False

    def test_lxd_group_not_exists(self, virt_helper):
        """Test when lxd group doesn't exist."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=1000):
                with patch("grp.getgrnam", side_effect=KeyError("lxd")):
                    result = virt_helper._is_user_in_lxd_group()

        assert result is False


class TestCheckLxdSupport:
    """Tests for check_lxd_support method."""

    def test_lxd_not_linux(self, virt_helper):
        """Test LXD check on non-Linux system."""
        with patch("platform.system", return_value="Darwin"):
            result = virt_helper.check_lxd_support()

        assert result["available"] is False
        assert result["installed"] is False

    def test_lxd_not_ubuntu_22(self, virt_helper):
        """Test LXD check on older Ubuntu."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                virt_helper, "_is_ubuntu_22_or_newer", return_value=False
            ):
                result = virt_helper.check_lxd_support()

        assert result["available"] is False

    def test_lxd_snap_installed(self, virt_helper):
        """Test LXD check when snap is installed."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(virt_helper, "_is_ubuntu_22_or_newer", return_value=True):
                with patch("shutil.which", return_value="/snap/bin/snap"):
                    with patch("subprocess.run") as mock_run:
                        # snap list lxd succeeds
                        mock_run.return_value = Mock(returncode=0, stdout="lxd 5.21")
                        with patch.object(
                            virt_helper, "_is_user_in_lxd_group", return_value=True
                        ):
                            result = virt_helper.check_lxd_support()

        assert result["available"] is True
        assert result["installed"] is True
        assert result["snap_available"] is True

    def test_lxd_not_installed_snap_available(self, virt_helper):
        """Test LXD check when LXD not installed but snap available."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(virt_helper, "_is_ubuntu_22_or_newer", return_value=True):
                with patch("shutil.which") as mock_which:

                    def which_side_effect(cmd):
                        if cmd == "snap":
                            return "/snap/bin/snap"
                        if cmd == "lxc":
                            return None
                        return None

                    mock_which.side_effect = which_side_effect

                    with patch("subprocess.run") as mock_run:
                        # snap list lxd fails - not installed
                        mock_run.return_value = Mock(returncode=1)
                        result = virt_helper.check_lxd_support()

        assert result["available"] is True
        assert result["installed"] is False
        assert result["needs_install"] is True
        assert result["snap_available"] is True

    def test_lxd_installed_not_initialized(self, virt_helper):
        """Test LXD check when installed but not initialized."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(virt_helper, "_is_ubuntu_22_or_newer", return_value=True):
                with patch("shutil.which", return_value="/snap/bin/snap"):
                    with patch("subprocess.run") as mock_run:

                        def run_side_effect(cmd, **_kwargs):
                            if "list" in cmd and "lxd" in cmd:
                                return Mock(returncode=0)
                            if "storage" in cmd:
                                # Empty storage list = not initialized
                                return Mock(returncode=0, stdout="[]")
                            return Mock(returncode=0)

                        mock_run.side_effect = run_side_effect
                        with patch.object(
                            virt_helper, "_is_user_in_lxd_group", return_value=True
                        ):
                            result = virt_helper.check_lxd_support()

        assert result["installed"] is True
        assert result["initialized"] is False
        assert result["needs_init"] is True

    def test_lxd_fully_initialized(self, virt_helper):
        """Test LXD check when fully initialized."""
        storage_pools = [{"name": "default", "driver": "dir"}]

        with patch("platform.system", return_value="Linux"):
            with patch.object(virt_helper, "_is_ubuntu_22_or_newer", return_value=True):
                with patch("shutil.which", return_value="/snap/bin/snap"):
                    with patch("subprocess.run") as mock_run:

                        def run_side_effect(cmd, **_kwargs):
                            if "list" in cmd and "lxd" in cmd:
                                return Mock(returncode=0)
                            if "storage" in cmd:
                                return Mock(
                                    returncode=0, stdout=json.dumps(storage_pools)
                                )
                            return Mock(returncode=0)

                        mock_run.side_effect = run_side_effect
                        with patch.object(
                            virt_helper, "_is_user_in_lxd_group", return_value=True
                        ):
                            result = virt_helper.check_lxd_support()

        assert result["installed"] is True
        assert result["initialized"] is True
        assert result["needs_init"] is False


class TestIsUserInKvmGroup:
    """Tests for _is_user_in_kvm_group method."""

    def test_user_in_kvm_group(self, virt_helper):
        """Test when user is in kvm group."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        mock_grp = Mock()
        mock_grp.gr_mem = ["testuser"]

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=1000):
                with patch("grp.getgrnam", return_value=mock_grp):
                    result = virt_helper._is_user_in_kvm_group()

        assert result is True

    def test_user_in_libvirt_group(self, virt_helper):
        """Test when user is in libvirt group."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        kvm_grp = Mock()
        kvm_grp.gr_mem = []

        libvirt_grp = Mock()
        libvirt_grp.gr_mem = ["testuser"]

        def grnam_side_effect(name):
            if name == "kvm":
                return kvm_grp
            if name == "libvirt":
                return libvirt_grp
            raise KeyError(name)

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=1000):
                with patch("grp.getgrnam", side_effect=grnam_side_effect):
                    result = virt_helper._is_user_in_kvm_group()

        assert result is True

    def test_root_user(self, virt_helper):
        """Test that root user always has access."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "root"

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=0):
                with patch("grp.getgrnam", side_effect=KeyError("kvm")):
                    result = virt_helper._is_user_in_kvm_group()

        assert result is True

    def test_user_not_in_any_group(self, virt_helper):
        """Test when user is not in any virtualization group."""
        mock_pwd = Mock()
        mock_pwd.pw_name = "testuser"

        mock_grp = Mock()
        mock_grp.gr_mem = []

        with patch("pwd.getpwuid", return_value=mock_pwd):
            with patch("os.getuid", return_value=1000):
                with patch("grp.getgrnam", return_value=mock_grp):
                    result = virt_helper._is_user_in_kvm_group()

        assert result is False


class TestCheckCpuVirtualizationFlags:
    """Tests for _check_cpu_virtualization_flags method."""

    def test_intel_vmx_present(self, virt_helper):
        """Test detecting Intel VMX CPU flag."""
        cpuinfo = "flags : vmx sse sse2 avx\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    cpuinfo
                )
                result = virt_helper._check_cpu_virtualization_flags()

        assert result is True

    def test_amd_svm_present(self, virt_helper):
        """Test detecting AMD SVM CPU flag."""
        cpuinfo = "flags : svm sse sse2\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    cpuinfo
                )
                result = virt_helper._check_cpu_virtualization_flags()

        assert result is True

    def test_no_virtualization_flags(self, virt_helper):
        """Test when no virtualization flags present."""
        cpuinfo = "flags : sse sse2 avx\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    cpuinfo
                )
                result = virt_helper._check_cpu_virtualization_flags()

        assert result is False

    def test_no_cpuinfo_file(self, virt_helper):
        """Test when /proc/cpuinfo doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = virt_helper._check_cpu_virtualization_flags()

        assert result is False


class TestGetCpuVendor:
    """Tests for _get_cpu_vendor method."""

    def test_intel_cpu(self, virt_helper):
        """Test detecting Intel CPU."""
        cpuinfo = "vendor_id : GenuineIntel\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    cpuinfo
                )
                result = virt_helper._get_cpu_vendor()

        assert result == "intel"

    def test_amd_cpu(self, virt_helper):
        """Test detecting AMD CPU."""
        cpuinfo = "vendor_id : AuthenticAMD\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    cpuinfo
                )
                result = virt_helper._get_cpu_vendor()

        assert result == "amd"

    def test_unknown_cpu(self, virt_helper):
        """Test when CPU vendor is unknown."""
        cpuinfo = "vendor_id : Unknown\n"

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    cpuinfo
                )
                result = virt_helper._get_cpu_vendor()

        assert result is None


class TestCheckKvmModulesLoaded:
    """Tests for _check_kvm_modules_loaded method."""

    def test_kvm_modules_loaded(self, virt_helper):
        """Test when KVM modules are loaded."""
        lsmod_output = "kvm_intel    123456  0\nkvm    654321  1 kvm_intel\n"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=lsmod_output)
            result = virt_helper._check_kvm_modules_loaded()

        assert result["loaded"] is True
        assert result["available"] is True

    def test_kvm_modules_not_loaded_but_available(self, virt_helper):
        """Test when KVM modules are not loaded but available."""
        lsmod_output = "some_other_module  123456  0\n"

        with patch("subprocess.run") as mock_run:

            def run_side_effect(cmd, **_kwargs):
                if "lsmod" in cmd:
                    return Mock(returncode=0, stdout=lsmod_output)
                if "modinfo" in cmd:
                    return Mock(returncode=0)
                return Mock(returncode=1)

            mock_run.side_effect = run_side_effect
            result = virt_helper._check_kvm_modules_loaded()

        assert result["loaded"] is False
        assert result["available"] is True

    def test_kvm_modules_not_available(self, virt_helper):
        """Test when KVM modules are not available."""
        lsmod_output = "some_other_module  123456  0\n"

        with patch("subprocess.run") as mock_run:

            def run_side_effect(cmd, **_kwargs):
                if "lsmod" in cmd:
                    return Mock(returncode=0, stdout=lsmod_output)
                if "modinfo" in cmd:
                    return Mock(returncode=1)
                return Mock(returncode=1)

            mock_run.side_effect = run_side_effect
            result = virt_helper._check_kvm_modules_loaded()

        assert result["loaded"] is False
        assert result["available"] is False


class TestCheckLibvirtdStatus:
    """Tests for _check_libvirtd_status method."""

    def test_libvirtd_enabled_and_running(self, virt_helper):
        """Test when libvirtd is enabled and running."""
        with patch("subprocess.run") as mock_run:

            def run_side_effect(cmd, **_kwargs):
                if "is-enabled" in cmd:
                    return Mock(returncode=0, stdout="enabled")
                if "is-active" in cmd:
                    return Mock(returncode=0, stdout="active")
                return Mock(returncode=1)

            mock_run.side_effect = run_side_effect
            result = virt_helper._check_libvirtd_status()

        assert result["enabled"] is True
        assert result["running"] is True

    def test_libvirtd_disabled(self, virt_helper):
        """Test when libvirtd is disabled."""
        with patch("subprocess.run") as mock_run:

            def run_side_effect(cmd, **_kwargs):
                if "is-enabled" in cmd:
                    return Mock(returncode=1, stdout="disabled")
                if "is-active" in cmd:
                    return Mock(returncode=1, stdout="inactive")
                return Mock(returncode=1)

            mock_run.side_effect = run_side_effect
            result = virt_helper._check_libvirtd_status()

        assert result["enabled"] is False
        assert result["running"] is False


class TestCheckDefaultNetworkExists:
    """Tests for _check_default_network_exists method."""

    def test_default_network_active(self, virt_helper):
        """Test when default network is active."""
        virsh_output = "Name:           default\nActive:         yes\n"

        with patch("shutil.which", return_value="/usr/bin/virsh"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=virsh_output)
                result = virt_helper._check_default_network_exists()

        assert result is True

    def test_default_network_inactive(self, virt_helper):
        """Test when default network is inactive."""
        virsh_output = "Name:           default\nActive:         no\n"

        with patch("shutil.which", return_value="/usr/bin/virsh"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=virsh_output)
                result = virt_helper._check_default_network_exists()

        assert result is False

    def test_default_network_not_found(self, virt_helper):
        """Test when default network doesn't exist."""
        with patch("shutil.which", return_value="/usr/bin/virsh"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="")
                result = virt_helper._check_default_network_exists()

        assert result is False

    def test_virsh_not_installed(self, virt_helper):
        """Test when virsh is not installed."""
        with patch("shutil.which", return_value=None):
            result = virt_helper._check_default_network_exists()

        assert result is False


class TestCheckKvmSupport:
    """Tests for check_kvm_support method."""

    def test_kvm_not_linux(self, virt_helper):
        """Test KVM check on non-Linux system."""
        with patch("platform.system", return_value="Darwin"):
            result = virt_helper.check_kvm_support()

        assert result["available"] is False

    def test_kvm_fully_available(self, virt_helper):
        """Test KVM check when fully available."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                virt_helper, "_check_cpu_virtualization_flags", return_value=True
            ):
                with patch.object(virt_helper, "_get_cpu_vendor", return_value="intel"):
                    with patch.object(
                        virt_helper,
                        "_check_kvm_modules_loaded",
                        return_value={"loaded": True, "available": True},
                    ):
                        with patch("os.path.exists", return_value=True):
                            with patch.object(
                                virt_helper, "_is_user_in_kvm_group", return_value=True
                            ):
                                with patch(
                                    "shutil.which", return_value="/usr/bin/virsh"
                                ):
                                    with patch.object(
                                        virt_helper,
                                        "_check_libvirtd_status",
                                        return_value={"enabled": True, "running": True},
                                    ):
                                        with patch.object(
                                            virt_helper,
                                            "_check_default_network_exists",
                                            return_value=True,
                                        ):
                                            result = virt_helper.check_kvm_support()

        assert result["available"] is True
        assert result["installed"] is True
        assert result["enabled"] is True
        assert result["running"] is True
        assert result["initialized"] is True
        assert result["cpu_supported"] is True
        assert result["kernel_supported"] is True
        assert result["user_in_group"] is True
        assert result["management"] == "libvirt"

    def test_kvm_needs_modprobe(self, virt_helper):
        """Test KVM check when modules need to be loaded."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                virt_helper, "_check_cpu_virtualization_flags", return_value=True
            ):
                with patch.object(virt_helper, "_get_cpu_vendor", return_value="intel"):
                    with patch.object(
                        virt_helper,
                        "_check_kvm_modules_loaded",
                        return_value={"loaded": False, "available": True},
                    ):
                        with patch("os.path.exists", return_value=False):
                            with patch.object(
                                virt_helper, "_is_user_in_kvm_group", return_value=True
                            ):
                                with patch(
                                    "shutil.which", return_value="/usr/bin/virsh"
                                ):
                                    with patch.object(
                                        virt_helper,
                                        "_check_libvirtd_status",
                                        return_value={"enabled": True, "running": True},
                                    ):
                                        result = virt_helper.check_kvm_support()

        assert result["available"] is True
        assert result["needs_modprobe"] is True
        assert result["modules_available"] is True
        assert result["modules_loaded"] is False

    def test_kvm_needs_install(self, virt_helper):
        """Test KVM check when libvirt needs to be installed."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                virt_helper, "_check_cpu_virtualization_flags", return_value=True
            ):
                with patch.object(virt_helper, "_get_cpu_vendor", return_value="intel"):
                    with patch.object(
                        virt_helper,
                        "_check_kvm_modules_loaded",
                        return_value={"loaded": True, "available": True},
                    ):
                        with patch("os.path.exists", return_value=True):
                            with patch.object(
                                virt_helper, "_is_user_in_kvm_group", return_value=False
                            ):
                                with patch("shutil.which", return_value=None):
                                    result = virt_helper.check_kvm_support()

        assert result["available"] is True
        assert result["installed"] is False
        assert result["needs_install"] is True

    def test_kvm_qemu_fallback(self, virt_helper):
        """Test KVM check with QEMU (no libvirt)."""
        with patch("platform.system", return_value="Linux"):
            with patch.object(
                virt_helper, "_check_cpu_virtualization_flags", return_value=True
            ):
                with patch.object(virt_helper, "_get_cpu_vendor", return_value="intel"):
                    with patch.object(
                        virt_helper,
                        "_check_kvm_modules_loaded",
                        return_value={"loaded": True, "available": True},
                    ):
                        with patch("os.path.exists", return_value=True):
                            with patch.object(
                                virt_helper, "_is_user_in_kvm_group", return_value=True
                            ):

                                def which_side_effect(cmd):
                                    if cmd == "virsh":
                                        return None
                                    if cmd == "qemu-system-x86_64":
                                        return "/usr/bin/qemu-system-x86_64"
                                    return None

                                with patch(
                                    "shutil.which", side_effect=which_side_effect
                                ):
                                    result = virt_helper.check_kvm_support()

        assert result["available"] is True
        assert result["installed"] is True
        assert result["management"] == "qemu"

    def test_kvm_exception_handling(self, virt_helper):
        """Test KVM check with exception."""
        with patch("platform.system", side_effect=Exception("Test error")):
            result = virt_helper.check_kvm_support()

        assert result["available"] is False


class TestDetectKvmAvailability:
    """Tests for _detect_kvm_availability method."""

    def test_dev_kvm_exists(self, virt_helper):
        """Test detection when /dev/kvm exists."""
        result = {
            "available": False,
            "kernel_supported": False,
            "modules_available": True,
            "cpu_supported": True,
            "needs_modprobe": False,
        }

        with patch("os.path.exists", return_value=True):
            virt_helper._detect_kvm_availability(result)

        assert result["available"] is True
        assert result["kernel_supported"] is True

    def test_modules_available_cpu_supported(self, virt_helper):
        """Test detection when modules available and CPU supported."""
        result = {
            "available": False,
            "kernel_supported": False,
            "modules_available": True,
            "cpu_supported": True,
            "needs_modprobe": False,
        }

        with patch("os.path.exists", return_value=False):
            virt_helper._detect_kvm_availability(result)

        assert result["available"] is True
        assert result["needs_modprobe"] is True


class TestDetectKvmManagement:
    """Tests for _detect_kvm_management method."""

    def test_libvirt_management(self, virt_helper):
        """Test detection with libvirt management."""
        result = {
            "installed": False,
            "management": None,
            "enabled": False,
            "running": False,
            "initialized": False,
            "needs_install": False,
            "needs_enable": False,
            "needs_init": False,
        }

        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/virsh"
            with patch.object(
                virt_helper,
                "_check_libvirtd_status",
                return_value={"enabled": True, "running": True},
            ):
                with patch.object(
                    virt_helper, "_check_default_network_exists", return_value=True
                ):
                    virt_helper._detect_kvm_management(result)

        assert result["installed"] is True
        assert result["management"] == "libvirt"
        assert result["initialized"] is True

    def test_qemu_management(self, virt_helper):
        """Test detection with QEMU management (no libvirt)."""
        result = {
            "installed": False,
            "management": None,
            "enabled": False,
            "running": False,
            "initialized": False,
            "needs_install": False,
            "needs_enable": False,
            "needs_init": False,
        }

        def which_side_effect(cmd):
            if cmd == "virsh":
                return None
            if cmd == "qemu-system-x86_64":
                return "/usr/bin/qemu-system-x86_64"
            return None

        with patch("shutil.which", side_effect=which_side_effect):
            virt_helper._detect_kvm_management(result)

        assert result["installed"] is True
        assert result["management"] == "qemu"

    def test_no_management(self, virt_helper):
        """Test detection with no management layer installed."""
        result = {
            "installed": False,
            "management": None,
            "enabled": False,
            "running": False,
            "initialized": False,
            "needs_install": False,
            "needs_enable": False,
            "needs_init": False,
        }

        with patch("shutil.which", return_value=None):
            virt_helper._detect_kvm_management(result)

        assert result["installed"] is False
        assert result["needs_install"] is True
