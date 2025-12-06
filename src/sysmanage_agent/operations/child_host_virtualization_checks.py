"""
Virtualization support check methods for child host operations.
"""

import grp
import json
import os
import platform
import pwd
import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict


class VirtualizationChecks:
    """Methods to check virtualization support on various platforms."""

    def __init__(self, logger):
        """Initialize with logger."""
        self.logger = logger

    def _decode_wsl_output(self, stdout: bytes, stderr: bytes) -> str:
        """
        Decode WSL command output which may be UTF-16LE encoded.

        wsl.exe outputs UTF-16LE on Windows, but subprocess with text=True
        expects UTF-8, resulting in garbled or empty output.

        Args:
            stdout: Raw stdout bytes
            stderr: Raw stderr bytes

        Returns:
            Combined decoded output as a string
        """
        combined = stdout + stderr
        if not combined:
            return ""

        # Try UTF-16LE first (what wsl.exe actually outputs)
        try:
            # Remove BOM if present
            if combined.startswith(b"\xff\xfe"):
                combined = combined[2:]
            decoded = combined.decode("utf-16-le")
            # Filter out null characters that may appear
            decoded = decoded.replace("\x00", "")
            if decoded.strip():
                return decoded
        except (UnicodeDecodeError, LookupError):
            pass

        # Fall back to UTF-8
        try:
            return combined.decode("utf-8")
        except UnicodeDecodeError:
            pass

        # Last resort: latin-1 (never fails)
        return combined.decode("latin-1")

    def check_wsl_support(self) -> Dict[str, Any]:
        """
        Check WSL (Windows Subsystem for Linux) support.

        Returns:
            Dict with WSL availability and status info
        """
        result = {
            "available": False,
            "enabled": False,
            "version": None,
            "needs_enable": False,
            "needs_bios_virtualization": False,
            "default_version": None,
        }

        try:
            # Check if running on Windows
            if platform.system().lower() != "windows":
                return result

            # Check if wsl.exe exists
            wsl_path = os.path.join(
                os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe"
            )
            if not os.path.exists(wsl_path):
                # WSL not available at all
                self.logger.debug("WSL executable not found at %s", wsl_path)
                return result

            # WSL binary exists, so WSL is potentially available
            result["available"] = True

            # Check WSL status using wsl --status
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            try:
                status_result = subprocess.run(  # nosec B603 B607
                    ["wsl", "--status"],
                    capture_output=True,
                    timeout=30,
                    check=False,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if hasattr(subprocess, "CREATE_NO_WINDOW")
                        else 0
                    ),
                )

                # Decode the UTF-16LE output from wsl.exe
                output = self._decode_wsl_output(
                    status_result.stdout, status_result.stderr
                )
                output_lower = output.lower()

                # Check for BIOS virtualization issues (actual hardware virtualization)
                # This is different from "Virtual Machine Platform" Windows feature
                if "bios" in output_lower and "virtualization" in output_lower:
                    result["enabled"] = False
                    result["needs_enable"] = False
                    result["needs_bios_virtualization"] = True
                    self.logger.warning(
                        "WSL requires BIOS virtualization to be enabled"
                    )
                    return result

                # Check for "Virtual Machine Platform" or other Windows features
                # that need to be enabled - these can be enabled via wsl --install
                if "virtual machine platform" in output_lower:
                    result["enabled"] = False
                    result["needs_enable"] = True
                    self.logger.info(
                        "WSL requires Virtual Machine Platform to be enabled"
                    )
                    return result

                # Check if WSL2 is working by looking for "Default Version:"
                # This should come before checking for "please enable" messages
                # because WSL1-related messages can appear even when WSL2 is working
                if status_result.returncode == 0 and "default version:" in output_lower:
                    result["enabled"] = True

                    # Parse default version from output
                    if (
                        "Default Version: 2" in output
                        or "Default Version: WSL 2" in output
                    ):
                        result["default_version"] = 2
                        result["version"] = "2"
                    elif (
                        "Default Version: 1" in output
                        or "Default Version: WSL 1" in output
                    ):
                        result["default_version"] = 1
                        result["version"] = "1"
                    else:
                        # Try to detect version from output
                        if "WSL 2" in output:
                            result["version"] = "2"
                            result["default_version"] = 2
                        else:
                            result["version"] = "2"  # Assume WSL 2 for modern Windows
                            result["default_version"] = 2

                    self.logger.info(
                        "WSL is enabled, default version: %s", result["default_version"]
                    )
                else:
                    # WSL exists but not enabled or needs configuration
                    result["enabled"] = False
                    result["needs_enable"] = True
                    self.logger.info("WSL is available but not fully enabled")

            except subprocess.TimeoutExpired:
                self.logger.warning("WSL status check timed out")
                result["enabled"] = False
                result["needs_enable"] = True

            except FileNotFoundError:
                # wsl command not found in PATH
                result["enabled"] = False
                result["needs_enable"] = True

        except Exception as error:
            self.logger.error("Error checking WSL support: %s", error)

        return result

    def check_hyperv_support(self) -> Dict[str, Any]:
        """
        Check Hyper-V support on Windows.

        Returns:
            Dict with Hyper-V availability info
        """
        result = {
            "available": False,
            "enabled": False,
        }

        try:
            if platform.system().lower() != "windows":
                return result

            # Check if Hyper-V is available using PowerShell
            ps_command = (
                "Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All "
                "-Online | Select-Object -ExpandProperty State"
            )

            ps_result = subprocess.run(  # nosec B603 B607
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            if ps_result.returncode == 0:
                state = ps_result.stdout.strip()
                result["available"] = True
                result["enabled"] = state.lower() == "enabled"

        except Exception as error:
            self.logger.debug("Error checking Hyper-V support: %s", error)

        return result

    def _is_ubuntu_22_or_newer(self) -> bool:
        """
        Check if the system is running Ubuntu 22.04 or newer.

        Returns:
            True if Ubuntu 22.04+, False otherwise
        """
        try:
            # Read /etc/os-release to get distribution info
            if not os.path.exists("/etc/os-release"):
                return False

            with open("/etc/os-release", "r", encoding="utf-8") as os_release_file:
                os_release = {}
                for line in os_release_file:
                    line = line.strip()
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os_release[key] = value.strip('"')

            # Check if it's Ubuntu
            if os_release.get("ID", "").lower() != "ubuntu":
                return False

            # Check version (VERSION_ID is like "22.04" or "24.04")
            version_id = os_release.get("VERSION_ID", "")
            if not version_id:
                return False

            try:
                major_version = float(version_id)
                return major_version >= 22.04
            except ValueError:
                return False

        except Exception as error:
            self.logger.debug("Error checking Ubuntu version: %s", error)
            return False

    def _is_user_in_lxd_group(self) -> bool:
        """
        Check if the current user is in the lxd group.

        Returns:
            True if user is in lxd group, False otherwise
        """
        try:
            # Get current user
            username = pwd.getpwuid(os.getuid()).pw_name

            # Check if lxd group exists and user is a member
            try:
                lxd_group = grp.getgrnam("lxd")
                return username in lxd_group.gr_mem
            except KeyError:
                # lxd group doesn't exist
                return False

        except Exception as error:
            self.logger.debug("Error checking lxd group membership: %s", error)
            return False

    def check_lxd_support(self) -> Dict[str, Any]:
        """
        Check LXD/LXC container support on Linux (Ubuntu 22.04+ only).

        Returns:
            Dict with LXD availability info including:
            - available: True if LXD can potentially be used (Ubuntu 22.04+)
            - installed: True if LXD snap is installed
            - initialized: True if LXD has been initialized (has storage pool)
            - user_in_group: True if current user is in lxd group
            - needs_install: True if LXD needs to be installed
            - needs_init: True if LXD needs initialization
            - snap_available: True if snap is available for installation
        """
        result = {
            "available": False,
            "installed": False,
            "initialized": False,
            "user_in_group": False,
            "needs_install": False,
            "needs_init": False,
            "snap_available": False,
        }

        try:
            if platform.system().lower() != "linux":
                return result

            # Only support Ubuntu 22.04+
            if not self._is_ubuntu_22_or_newer():
                self.logger.debug("LXD support requires Ubuntu 22.04 or newer")
                return result

            # Ubuntu 22.04+ can use LXD
            result["available"] = True

            # Check if snap is available (for installation)
            snap_path = shutil.which("snap")
            result["snap_available"] = snap_path is not None

            # Check if LXD snap is installed
            if snap_path:
                snap_result = subprocess.run(  # nosec B603 B607
                    ["snap", "list", "lxd"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                result["installed"] = snap_result.returncode == 0

            # If not installed via snap, check if lxc command exists anyway
            if not result["installed"]:
                lxc_path = shutil.which("lxc")
                if lxc_path:
                    result["installed"] = True

            if not result["installed"]:
                result["needs_install"] = True
                self.logger.info("LXD is not installed")
                return result

            # Check if user is in lxd group
            result["user_in_group"] = self._is_user_in_lxd_group()

            # Check if LXD is initialized by checking for storage pools
            try:
                storage_result = subprocess.run(  # nosec B603 B607
                    ["lxc", "storage", "list", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if storage_result.returncode == 0:
                    try:
                        storage_pools = json.loads(storage_result.stdout)
                        result["initialized"] = len(storage_pools) > 0
                    except json.JSONDecodeError:
                        result["initialized"] = False
                else:
                    result["initialized"] = False

            except Exception as storage_error:
                self.logger.debug("Error checking LXD storage: %s", storage_error)
                result["initialized"] = False

            if not result["initialized"]:
                result["needs_init"] = True
                self.logger.info("LXD is installed but not initialized")

            self.logger.info(
                "LXD support check: installed=%s, initialized=%s, user_in_group=%s",
                result["installed"],
                result["initialized"],
                result["user_in_group"],
            )

        except Exception as error:
            self.logger.debug("Error checking LXD support: %s", error)

        return result

    def check_kvm_support(self) -> Dict[str, Any]:
        """
        Check KVM/QEMU support on Linux.

        Returns:
            Dict with KVM availability info
        """
        result = {
            "available": False,
            "kvm_module_loaded": False,
            "libvirt_installed": False,
        }

        try:
            if platform.system().lower() != "linux":
                return result

            # Check if KVM kernel module is loaded
            if os.path.exists("/dev/kvm"):
                result["kvm_module_loaded"] = True
                result["available"] = True

            # Check if libvirt is installed
            virsh_path = shutil.which("virsh")
            if virsh_path:
                result["libvirt_installed"] = True

        except Exception as error:
            self.logger.debug("Error checking KVM support: %s", error)

        return result

    def check_bhyve_support(self) -> Dict[str, Any]:
        """
        Check bhyve support on FreeBSD.

        Returns:
            Dict with bhyve availability info
        """
        result = {
            "available": False,
        }

        try:
            if platform.system().lower() != "freebsd":
                return result

            # Check if bhyve is available
            bhyve_path = shutil.which("bhyve")
            if bhyve_path:
                result["available"] = True

        except Exception as error:
            self.logger.debug("Error checking bhyve support: %s", error)

        return result

    def check_vmm_support(self) -> Dict[str, Any]:
        """
        Check VMM/vmd support on OpenBSD.

        Returns:
            Dict with VMM availability info including:
            - available: True if VMM can potentially be used (OpenBSD with vmctl)
            - enabled: True if vmd is enabled in rc.conf
            - running: True if vmd daemon is currently running
            - initialized: True if vmd is ready to create VMs
            - kernel_supported: True if /dev/vmm device exists
            - needs_enable: True if vmd needs to be enabled
        """
        result = {
            "available": False,
            "enabled": False,
            "running": False,
            "initialized": False,
            "kernel_supported": False,
            "cpu_supported": False,
            "needs_enable": False,
        }

        try:
            if platform.system().lower() != "openbsd":
                return result

            # Check if vmctl is available
            vmctl_path = shutil.which("vmctl")
            if not vmctl_path:
                self.logger.debug("vmctl not found - VMM not available")
                return result

            result["available"] = True

            # Check CPU virtualization support (VMX for Intel, SVM for AMD)
            try:
                # On OpenBSD, the presence of /dev/vmm is the primary indicator
                # of CPU support since OpenBSD only creates it when VMX/SVM is available.
                # We also verify by checking if we can read the CPU vendor.
                vmm_check = subprocess.run(  # nosec B603 B607
                    ["sysctl", "hw.vendor"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if vmm_check.returncode == 0:
                    # CPU vendor detected, VMM support depends on /dev/vmm
                    result["cpu_supported"] = True
            except Exception as cpu_error:
                self.logger.debug("Error checking CPU virtualization: %s", cpu_error)

            # Check if kernel has VMM support (/dev/vmm exists)
            if os.path.exists("/dev/vmm"):
                result["kernel_supported"] = True
            else:
                self.logger.debug("/dev/vmm not found - kernel VMM support not enabled")
                result["needs_enable"] = True
                return result

            # Check if vmd is enabled using rcctl
            try:
                rcctl_result = subprocess.run(  # nosec B603 B607
                    ["rcctl", "get", "vmd", "flags"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                # If rcctl get vmd flags returns 0, vmd is enabled
                # If it returns non-zero or "NO", it's not enabled
                if rcctl_result.returncode == 0:
                    flags_output = rcctl_result.stdout.strip()
                    # "NO" means disabled, anything else means enabled
                    if flags_output.upper() != "NO":
                        result["enabled"] = True
            except subprocess.TimeoutExpired:
                self.logger.debug("Timeout checking vmd enabled status")
            except Exception as rcctl_error:
                self.logger.debug("Error checking vmd enabled status: %s", rcctl_error)

            # Check if vmd is running using rcctl check
            try:
                check_result = subprocess.run(  # nosec B603 B607
                    ["rcctl", "check", "vmd"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                # rcctl check returns 0 if service is running
                if check_result.returncode == 0:
                    result["running"] = True
                    result["initialized"] = True
            except subprocess.TimeoutExpired:
                self.logger.debug("Timeout checking vmd running status")
            except Exception as check_error:
                self.logger.debug("Error checking vmd running status: %s", check_error)

            # If not enabled and not running, it needs to be enabled
            if not result["enabled"] and not result["running"]:
                result["needs_enable"] = True

            self.logger.info(
                "VMM support check: available=%s, enabled=%s, running=%s, "
                "kernel_supported=%s, cpu_supported=%s",
                result["available"],
                result["enabled"],
                result["running"],
                result["kernel_supported"],
                result["cpu_supported"],
            )

        except Exception as error:
            self.logger.debug("Error checking VMM support: %s", error)

        return result

    def check_virtualbox_support(self) -> Dict[str, Any]:
        """
        Check VirtualBox support (cross-platform).

        Returns:
            Dict with VirtualBox availability info
        """
        result = {
            "available": False,
            "version": None,
        }

        try:
            # Check for VBoxManage
            vboxmanage = shutil.which("VBoxManage")
            if not vboxmanage:
                # On Windows, try common installation paths
                if platform.system().lower() == "windows":
                    common_paths = [
                        os.path.join(
                            os.environ.get("ProgramFiles", ""),
                            "Oracle",
                            "VirtualBox",
                            "VBoxManage.exe",
                        ),
                        os.path.join(
                            os.environ.get("ProgramFiles(x86)", ""),
                            "Oracle",
                            "VirtualBox",
                            "VBoxManage.exe",
                        ),
                    ]
                    for path in common_paths:
                        if os.path.exists(path):
                            vboxmanage = path
                            break

            if vboxmanage:
                result["available"] = True

                # Get version
                version_result = subprocess.run(  # nosec B603 B607
                    [vboxmanage, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if version_result.returncode == 0:
                    result["version"] = version_result.stdout.strip()

        except Exception as error:
            self.logger.debug("Error checking VirtualBox support: %s", error)

        return result
