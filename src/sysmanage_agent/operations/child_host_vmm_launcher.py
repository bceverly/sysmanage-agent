"""
VMM VM launcher operations for OpenBSD.

This module handles VM launch, shutdown monitoring, and tap device management.
Extracted from vm_creator to reduce module size.
"""

import asyncio
import subprocess  # nosec B404
import time
from typing import Any, Dict

from src.i18n import _


class VmmLauncher:
    """Handles VMM VM launch and monitoring operations."""

    def __init__(self, agent_instance, logger):
        """
        Initialize VM launcher.

        Args:
            agent_instance: Reference to main SysManageAgent
            logger: Logger instance
        """
        self.agent = agent_instance
        self.logger = logger

    async def run_subprocess(
        self,
        cmd: list,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess:
        """
        Run a subprocess command asynchronously.

        Uses asyncio.to_thread() to run the blocking subprocess.run call
        in a separate thread, preventing WebSocket keepalive timeouts.

        Args:
            cmd: Command and arguments as a list
            timeout: Timeout in seconds

        Returns:
            CompletedProcess instance with return code, stdout, stderr
        """
        return await asyncio.to_thread(
            subprocess.run,  # nosec B603 B607
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    async def ensure_tap_device_available(self) -> Dict[str, Any]:
        """
        Ensure a tap device is available for the new VM.

        VMD dynamically allocates tap devices from the pool. We need to ensure
        there's at least one tap device available before starting a new VM.

        Returns:
            Dict with success status and optional tap_device name
        """
        try:
            result = await self.run_subprocess(
                ["ifconfig", "-a"],
                timeout=10,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to check network interfaces"),
                }

            existing_count = result.stdout.count("tap")
            vmctl_result = await self.run_subprocess(["vmctl", "status"], timeout=10)
            running_vms = 0
            if vmctl_result.returncode == 0:
                for line in vmctl_result.stdout.strip().split("\n")[1:]:
                    if line.strip() and "running" in line:
                        running_vms += 1

            self.logger.info(
                _("Tap devices: %d existing, %d running VMs"),
                existing_count,
                running_vms,
            )

            if running_vms >= existing_count:
                new_tap = f"tap{existing_count}"
                self.logger.info(_("Creating new tap device: %s"), new_tap)
                create_result = await self.run_subprocess(
                    ["ifconfig", new_tap, "create"],
                    timeout=10,
                )
                if create_result.returncode != 0:
                    error_msg = create_result.stderr or create_result.stdout or ""
                    if "exists" in error_msg.lower():
                        self.logger.info(
                            _("Tap device %s already exists, continuing"), new_tap
                        )
                        return {"success": True, "tap_device": new_tap}
                    self.logger.error(_("Failed to create %s: %s"), new_tap, error_msg)
                    return {
                        "success": False,
                        "error": _("Failed to create tap device: %s") % error_msg,
                    }
                self.logger.info(_("Created tap device: %s"), new_tap)
                return {"success": True, "tap_device": new_tap}

            return {"success": True, "tap_device": None}

        except Exception as error:
            self.logger.error(_("Error ensuring tap device: %s"), error)
            return {"success": False, "error": str(error)}

    async def launch_vm_with_bsdrd(
        self,
        vm_name: str,
        disk_path: str,
        bsdrd_path: str,
        memory: str,
    ) -> Dict[str, Any]:
        """Launch VM with embedded bsd.rd boot using explicit command line.

        We do NOT use vm.conf during installation to avoid the install loop
        problem where vmd auto-restarts the VM from bsd.rd on reboot.
        Instead, we use explicit vmctl command line parameters.
        """
        try:
            status_result = await self.run_subprocess(["vmctl", "status"], timeout=10)
            if status_result.returncode == 0:
                for line in status_result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if (
                        len(parts) >= 9
                        and parts[8] == vm_name
                        and parts[7] == "running"
                    ):
                        self.logger.info(_("VM %s already running"), vm_name)
                        return {"success": True}

            tap_result = await self.ensure_tap_device_available()
            if not tap_result.get("success"):
                return tap_result

            cmd = [
                "vmctl",
                "start",
                "-b",
                bsdrd_path,
                "-d",
                disk_path,
                "-m",
                memory,
                "-n",
                "local",
                vm_name,
            ]
            self.logger.info(_("Launching VM with explicit params: %s"), " ".join(cmd))

            result = await self.run_subprocess(cmd, timeout=60)

            if result.returncode == 0:
                self.logger.info(_("VM %s launched with embedded bsd.rd"), vm_name)
                return {"success": True}

            error_msg = result.stderr or result.stdout or "Unknown error"
            if "already in progress" in error_msg.lower():
                self.logger.info(_("VM %s start in progress"), vm_name)
                return {"success": True}

            return {
                "success": False,
                "error": _("Failed to launch VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout launching VM"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def launch_vm_from_disk(
        self,
        vm_name: str,
        disk_path: str,
        memory: str,
    ) -> Dict[str, Any]:
        """Launch VM from disk using explicit command line.

        We use explicit vmctl command line parameters since the VM is not
        yet in vm.conf (we add it only after successful provisioning).
        """
        try:
            status_result = await self.run_subprocess(["vmctl", "status"], timeout=10)
            if status_result.returncode == 0:
                for line in status_result.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if (
                        len(parts) >= 9
                        and parts[8] == vm_name
                        and parts[7] == "running"
                    ):
                        self.logger.info(_("VM %s already running"), vm_name)
                        return {"success": True}

            tap_result = await self.ensure_tap_device_available()
            if not tap_result.get("success"):
                return tap_result

            cmd = [
                "vmctl",
                "start",
                "-d",
                disk_path,
                "-m",
                memory,
                "-n",
                "local",
                vm_name,
            ]

            self.logger.info(_("Launching VM from disk: %s"), " ".join(cmd))

            result = await self.run_subprocess(cmd, timeout=60)

            if result.returncode == 0:
                self.logger.info(_("VM %s launched from disk"), vm_name)
                return {"success": True}

            error_msg = result.stderr or result.stdout or "Unknown error"
            if "already in progress" in error_msg.lower():
                self.logger.info(_("VM %s start in progress"), vm_name)
                return {"success": True}

            return {
                "success": False,
                "error": _("Failed to launch VM: %s") % error_msg,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Timeout launching VM"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    async def wait_for_vm_shutdown(
        self, vm_name: str, timeout: int = 1800
    ) -> Dict[str, Any]:
        """Wait for VM to shutdown by polling vmctl status."""
        start_time = time.time()
        last_status_log = 0

        self.logger.info(_("Waiting for VM %s to shutdown..."), vm_name)

        while time.time() - start_time < timeout:
            try:
                result = await self.run_subprocess(["vmctl", "status"], timeout=10)

                if vm_name not in result.stdout:
                    self.logger.info(_("VM %s has shut down"), vm_name)
                    return {"success": True}

                elapsed = int(time.time() - start_time)
                if elapsed - last_status_log >= 60:
                    self.logger.info(
                        _("VM still running... (%d seconds elapsed)"), elapsed
                    )
                    last_status_log = elapsed

            except Exception as error:
                self.logger.debug("Error checking VM status: %s", error)

            await asyncio.sleep(10)

        return {
            "success": False,
            "error": _("Timeout waiting for VM to shutdown"),
        }

    async def send_progress(self, step: str, message: str, child_type: str = "vmm"):
        """Send progress update to server."""
        try:
            if hasattr(self.agent, "send_message"):
                progress_message = self.agent.create_message(
                    "child_host_creation_progress",
                    {
                        "step": step,
                        "message": message,
                        "child_type": child_type,
                    },
                )
                await self.agent.send_message(progress_message)
        except Exception as error:
            self.logger.debug("Failed to send progress update: %s", error)
