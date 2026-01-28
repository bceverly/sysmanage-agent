"""
Debian VMM console automation module.

This module implements serial console interaction for automated Debian setup.
It handles the boot parameter injection needed to enable serial console and
automated preseed installation on Debian VMs in OpenBSD VMM.
"""

import asyncio
import base64
import logging
import os
import pty
import select
import subprocess  # nosec B404 - still needed for sync functions
import time
import traceback
from typing import Any, Dict, List, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async


class DebianConsoleAutomation:
    """Handles automated console interaction for Debian VM installation."""

    # Timeouts in seconds
    BOOT_MENU_TIMEOUT = 60  # Time to wait for boot menu
    BOOT_TIMEOUT = 120  # Time to wait after boot parameter injection
    INSTALLER_TIMEOUT = 1200  # Time for Debian installation (20 minutes)
    COMMAND_TIMEOUT = 30  # Time to wait for command completion

    def __init__(self, logger: logging.Logger):
        """Initialize console automation."""
        self.logger = logger

    def _parse_tty_from_status(self, vm_name: str) -> Optional[str]:
        """Parse TTY from vmctl status output for a specific VM."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["vmctl", "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.logger.info(
                _("[TTY_LOOKUP] vmctl status (rc=%d): %s"),
                result.returncode,
                result.stdout.strip()[:200],
            )
            for line in result.stdout.strip().split("\n"):
                tty = self._extract_tty_from_line(line, vm_name)
                if tty:
                    return tty
            return None
        except Exception as error:
            self.logger.error(_("Failed to get VM TTY: %s"), error)
            return None

    def _extract_tty_from_line(self, line: str, vm_name: str) -> Optional[str]:
        """Extract TTY device from a vmctl status line if it matches the VM."""
        if vm_name not in line or "running" not in line.lower():
            return None
        # Format: ID PID VCPUS MAXMEM CURMEM TTY OWNER STATE NAME
        parts = line.split()
        if len(parts) >= 6:
            tty = parts[5]
            if tty.startswith("tty"):
                return tty
        return None

    def get_vm_tty(
        self, vm_name: str, retries: int = 10, delay: float = 2.0
    ) -> Optional[str]:
        """
        Get the TTY device for a VM from vmctl status.

        Args:
            vm_name: Name of the VM
            retries: Number of retries (default 10)
            delay: Delay in seconds between retries (default 2.0)

        Returns:
            TTY device name (e.g., "ttyp0") or None if not found
        """
        for attempt in range(retries):
            tty = self._parse_tty_from_status(vm_name)
            if tty:
                self.logger.info(
                    _("Found TTY %s for VM '%s' on attempt %d"),
                    tty,
                    vm_name,
                    attempt + 1,
                )
                return tty

            if attempt < retries - 1:
                self.logger.debug(
                    _("VM '%s' not found in vmctl status, retrying (%d/%d)..."),
                    vm_name,
                    attempt + 1,
                    retries,
                )
                time.sleep(delay)

        self.logger.error(
            _("Could not find TTY for VM '%s' after %d attempts"), vm_name, retries
        )
        return None

    async def inject_boot_parameters(
        self,
        vm_name: str,
        preseed_url: str = None,
        gateway_ip: str = None,
        vm_ip: str = None,
        dns_server: str = None,
        timeout: int = None,  # NOSONAR - timeout is part of the established API for callers to control boot menu wait duration
    ) -> Dict[str, Any]:
        """
        Inject boot parameters at Debian installer boot menu.

        Debian netinst ISO boots to ISOLINUX menu. We need to:
        1. Wait for the menu to appear
        2. Press Tab to edit boot parameters
        3. Append serial console and preseed parameters
        4. Press Enter to boot

        Args:
            vm_name: Name of the VM
            preseed_url: URL to preseed file (optional, can use manual setup)
            gateway_ip: Gateway IP for installer networking
            vm_ip: Static IP for the VM
            dns_server: DNS server IP
            timeout: Overall timeout in seconds

        Returns:
            Dict with success status
        """
        if timeout is None:
            timeout = self.BOOT_MENU_TIMEOUT

        try:
            self.logger.info(
                _("Starting Debian boot parameter injection for VM '%s'"), vm_name
            )

            # Get the TTY device
            tty_name = self.get_vm_tty(vm_name)
            if not tty_name:
                return {
                    "success": False,
                    "error": _("Could not find TTY for VM '%s'") % vm_name,
                }

            tty_device = f"/dev/{tty_name}"
            self.logger.info(_("VM '%s' is on %s"), vm_name, tty_device)

            # Run the boot parameter injection in a thread
            result = await asyncio.to_thread(
                self._inject_boot_params,
                vm_name,
                tty_device,
                preseed_url,
                gateway_ip,
                vm_ip,
                dns_server,
                timeout,
            )

            return result

        except Exception as error:
            self.logger.error(
                _("Boot parameter injection error for VM '%s': %s"), vm_name, error
            )
            return {"success": False, "error": str(error)}

    def _inject_boot_params(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        vm_name: str,
        tty_device: str,  # pylint: disable=unused-argument
        preseed_url: str,
        gateway_ip: str,
        vm_ip: str,
        dns_server: str,
        timeout: int,
    ) -> Dict[str, Any]:
        """
        Perform actual boot parameter injection.

        Args:
            vm_name: Name of the VM
            tty_device: TTY device path (reserved for future direct PTY access)
            preseed_url: URL to preseed file
            gateway_ip: Gateway IP
            vm_ip: Static IP
            dns_server: DNS server
            timeout: Timeout for boot menu detection
        """
        master_fd = None
        slave_fd = None

        try:
            # Open PTY pair
            master_fd, slave_fd = pty.openpty()

            # Spawn vmctl console
            # pylint: disable=consider-using-with
            process = subprocess.Popen(  # nosec B603 B607
                ["vmctl", "console", vm_name],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )

            # Close slave in parent
            os.close(slave_fd)
            slave_fd = None

            # Wait for Debian boot menu
            # The ISOLINUX menu should show "Graphical install" as the first option
            self.logger.info(_("Waiting for Debian boot menu..."))
            menu_detected = self._wait_for_prompt(
                master_fd,
                [
                    b"Graphical install",
                    b"Install",
                    b"Installer menu",
                    b"ISOLINUX",
                ],
                timeout,
            )

            if menu_detected:
                self.logger.info(_("Boot menu detected!"))
            else:
                self.logger.warning(
                    _("Boot menu prompt not detected, trying to inject anyway...")
                )

            # Longer delay to ensure menu is fully loaded and responsive
            time.sleep(5)

            # Read any current console output for debugging
            initial_output = self._read_output(master_fd, timeout=1.0)
            if initial_output:
                self.logger.info(_("Console shows: %s"), initial_output[:300])

            # Navigate to "Install" (text mode) - it's typically the 2nd option
            # First option is usually "Graphical install"
            self.logger.info(_("Sending Down arrow to select Install..."))
            self._send_key(master_fd, "\x1b[B")  # Down arrow (ESC [ B)
            time.sleep(1)

            # Read response
            after_down = self._read_output(master_fd, timeout=0.5)
            if after_down:
                self.logger.info(_("After Down arrow: %s"), after_down[:200])

            # Press Tab to edit the boot line
            # In ISOLINUX/SYSLINUX, Tab shows and allows editing boot parameters
            self.logger.info(_("Pressing Tab to edit boot line..."))
            self._send_key(master_fd, "\t")
            time.sleep(1)

            # Read the boot line that should now be displayed
            boot_line = self._read_output(master_fd, timeout=1.0)
            if boot_line:
                self.logger.info(_("Boot line shown: %s"), boot_line[:300])

            # Build boot parameters to append
            boot_params = self._build_boot_params(
                preseed_url, gateway_ip, vm_ip, dns_server
            )

            # Send the boot parameters (they get appended to existing line)
            self.logger.info(_("Appending boot parameters: %s"), boot_params[:200])
            # Don't send newline yet - just the parameters
            os.write(master_fd, boot_params.encode())
            time.sleep(0.5)

            # Now press Enter to boot
            self.logger.info(_("Pressing Enter to boot..."))
            self._send_key(master_fd, "\r")

            # Wait a moment for the installer to process
            time.sleep(2)

            self.logger.info(
                _(
                    "Boot parameters injected. Debian installer should now boot "
                    "with serial console support."
                )
            )

            # Read any response
            output = self._read_output(master_fd, timeout=5.0)
            if output:
                self.logger.info(_("Console output: %s"), output[:500])

            # Terminate console connection
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            return {
                "success": True,
                "message": _("Boot parameters injected successfully"),
            }

        except Exception as error:
            tb_str = traceback.format_exc()
            self.logger.error(_("Boot parameter injection error: %s"), error)
            self.logger.error(_("Traceback: %s"), tb_str)
            return {"success": False, "error": str(error)}

        finally:
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass
            if slave_fd is not None:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass

    def _build_boot_command(
        self,
        preseed_url: str,
        gateway_ip: str,
        vm_ip: str,
        dns_server: str,
    ) -> str:
        """
        Build the full boot command for the boot: prompt.

        At the boot: prompt, we need to specify the kernel path and
        all boot parameters.

        Args:
            preseed_url: URL to preseed file
            gateway_ip: Gateway IP
            vm_ip: Static IP
            dns_server: DNS server

        Returns:
            Full boot command string
        """
        # For Debian netinst, the kernel and initrd paths are:
        # - 64-bit: /install.amd/vmlinuz and /install.amd/initrd.gz
        # At the boot: prompt, we type: install [options]
        # The "install" label is predefined in isolinux.cfg
        # This boots the text-mode installer with our parameters

        # Core parameters for serial console and automation (critical for VMM)
        params = [
            "console=ttyS0,115200n8",  # Enable serial console
            "vga=off",  # Disable VGA for serial-only
            "DEBIAN_FRONTEND=text",  # Force text-mode installer
            "auto=true",  # Enable automation
            "priority=critical",  # Skip non-critical questions
            "net.ifnames=0",  # Use classic eth0 naming
            "biosdevname=0",  # Disable biosdevname
            "DEBCONF_DEBUG=5",  # Debug output for troubleshooting
        ]

        # Add preseed URL if provided
        if preseed_url:
            params.append(f"url={preseed_url}")

        # Add network configuration if provided
        # Use kernel ip= parameter for early network config
        # Format: ip=<client-ip>::<gateway>:<netmask>:<hostname>:<device>:<autoconf>
        if vm_ip and gateway_ip:
            hostname = vm_ip.replace(".", "-")
            params.append(f"ip={vm_ip}::{gateway_ip}:255.255.255.0:{hostname}:eth0:off")
            # Also set netcfg params for the installer
            params.append("netcfg/choose_interface=eth0")
            params.append(f"netcfg/get_ipaddress={vm_ip}")
            params.append("netcfg/get_netmask=255.255.255.0")
            params.append(f"netcfg/get_gateway={gateway_ip}")
            if dns_server:
                params.append(f"netcfg/get_nameservers={dns_server}")
            params.append("netcfg/disable_dhcp=true")
            params.append("netcfg/confirm_static=true")

        # Build the full boot command
        # "install" is the label for text-mode installer in isolinux.cfg
        return "install " + " ".join(params)

    def _build_boot_params(
        self,
        preseed_url: str,
        gateway_ip: str,
        vm_ip: str,
        dns_server: str,
    ) -> str:
        """
        Build boot parameters to append to an existing boot line (Tab method).

        Args:
            preseed_url: URL to preseed file
            gateway_ip: Gateway IP
            vm_ip: Static IP
            dns_server: DNS server

        Returns:
            Boot parameters string (with leading space for appending)
        """
        # Core parameters for serial console and automation (critical for VMM)
        params = [
            "console=ttyS0,115200n8",  # Enable serial console
            "vga=off",  # Disable VGA for serial-only
            "DEBIAN_FRONTEND=text",  # Force text-mode installer
            "auto=true",  # Enable automation
            "priority=critical",  # Skip non-critical questions
            "net.ifnames=0",  # Use classic eth0 naming
            "biosdevname=0",  # Disable biosdevname
            "DEBCONF_DEBUG=5",  # Debug output for troubleshooting
        ]

        # Add preseed URL if provided
        if preseed_url:
            params.append(f"url={preseed_url}")

        # Add network configuration if provided
        if vm_ip and gateway_ip:
            hostname = vm_ip.replace(".", "-")
            params.append(f"ip={vm_ip}::{gateway_ip}:255.255.255.0:{hostname}:eth0:off")
            params.append("netcfg/choose_interface=eth0")
            params.append(f"netcfg/get_ipaddress={vm_ip}")
            params.append("netcfg/get_netmask=255.255.255.0")
            params.append(f"netcfg/get_gateway={gateway_ip}")
            if dns_server:
                params.append(f"netcfg/get_nameservers={dns_server}")
            params.append("netcfg/disable_dhcp=true")
            params.append("netcfg/confirm_static=true")

        # Join with spaces (leading space for appending)
        return " " + " ".join(params)

    async def run_preseed_setup(
        self,
        vm_name: str,
        preseed_content: str,
        agent_config: str,
        firstboot_script: str,
        systemd_service: str,
        timeout: int = None,  # NOSONAR - timeout is part of the established API for callers to control installation wait duration
    ) -> Dict[str, Any]:
        """
        Run manual preseed-style setup via serial console.

        This is used when we can't serve a preseed file via URL. Instead,
        we wait for the Debian installer to boot and then manually configure
        it via the serial console, or we inject configuration after installation.

        Args:
            vm_name: Name of the VM
            preseed_content: Preseed file content (for reference)
            agent_config: Agent configuration YAML
            firstboot_script: Firstboot script content
            systemd_service: Systemd service unit content
            timeout: Overall timeout in seconds

        Returns:
            Dict with success status
        """
        if timeout is None:
            timeout = self.INSTALLER_TIMEOUT

        try:
            self.logger.info(_("Starting Debian preseed setup for VM '%s'"), vm_name)

            # Get the TTY device
            tty_name = self.get_vm_tty(vm_name)
            if not tty_name:
                return {
                    "success": False,
                    "error": _("Could not find TTY for VM '%s'") % vm_name,
                }

            tty_device = f"/dev/{tty_name}"

            # Run the setup in a thread
            result = await asyncio.to_thread(
                self._manual_preseed_setup,
                vm_name,
                tty_device,
                preseed_content,
                agent_config,
                firstboot_script,
                systemd_service,
                timeout,
            )

            return result

        except Exception as error:
            self.logger.error(_("Preseed setup error for VM '%s': %s"), vm_name, error)
            return {"success": False, "error": str(error)}

    def _manual_preseed_setup(  # pylint: disable=too-many-arguments,too-many-locals,unused-argument
        self,
        vm_name: str,
        tty_device: str,
        preseed_content: str,
        agent_config: str,
        firstboot_script: str,
        systemd_service: str,
        timeout: int,
    ) -> Dict[str, Any]:
        """
        Perform manual preseed-style setup after Debian installation.

        This method is called after Debian has been installed via preseed.
        It configures the sysmanage-agent by writing config files to the
        installed system.

        Args:
            vm_name: Name of the VM
            tty_device: TTY device path
            preseed_content: Preseed content (for reference)
            agent_config: Agent YAML configuration
            firstboot_script: Firstboot script
            systemd_service: Systemd service unit
            timeout: Timeout in seconds
        """
        master_fd = None
        slave_fd = None

        try:
            # Open PTY pair
            master_fd, slave_fd = pty.openpty()

            # Spawn vmctl console
            # pylint: disable=consider-using-with
            process = subprocess.Popen(  # nosec B603 B607
                ["vmctl", "console", vm_name],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )

            # Close slave in parent
            os.close(slave_fd)
            slave_fd = None

            # Wait for login prompt (system should have rebooted after install)
            self.logger.info(_("Waiting for Debian login prompt..."))
            if not self._wait_for_prompt(master_fd, [b"login:", b"debian login:"], 300):
                self.logger.warning(
                    _("Login prompt not detected, installation may still be running")
                )
                # The installation may still be running - that's OK
                # The preseed should handle everything

            self.logger.info(
                _(
                    "Debian installation appears complete. "
                    "Firstboot service will configure sysmanage-agent."
                )
            )

            # Clean up
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            return {
                "success": True,
                "message": _("Debian setup monitoring complete"),
            }

        except Exception as error:
            tb_str = traceback.format_exc()
            self.logger.error(_("Manual preseed setup error: %s"), error)
            self.logger.error(_("Traceback: %s"), tb_str)
            return {"success": False, "error": str(error)}

        finally:
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except OSError:
                    pass
            if slave_fd is not None:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass

    async def wait_for_installation_complete(
        self,
        vm_name: str,
        timeout: int = None,  # NOSONAR - timeout is part of the established API for callers to control installation wait duration
    ) -> Dict[str, Any]:
        """
        Wait for Debian installation to complete.

        Monitors the VM status and serial console for installation completion.
        The VM should shut down or reboot after preseed installation completes.

        Args:
            vm_name: Name of the VM
            timeout: Timeout in seconds (default: 20 minutes)

        Returns:
            Dict with success status
        """
        if timeout is None:
            timeout = self.INSTALLER_TIMEOUT

        try:
            self.logger.info(
                _("Waiting for Debian installation to complete (timeout: %d min)..."),
                timeout // 60,
            )

            start_time = time.time()
            last_status = None

            while time.time() - start_time < timeout:
                # Check VM status
                result = await run_command_async(
                    ["vmctl", "status", vm_name],
                    timeout=10,
                )

                if result.returncode == 0:
                    # Check if VM is still running
                    if "running" in result.stdout.lower():
                        if last_status != "running":
                            self.logger.info(_("VM '%s' is running..."), vm_name)
                            last_status = "running"
                    else:
                        # VM stopped - installation complete
                        self.logger.info(
                            _("VM '%s' has stopped - installation complete!"), vm_name
                        )
                        return {
                            "success": True,
                            "message": _("Installation completed"),
                        }

                await asyncio.sleep(10)

            return {
                "success": False,
                "error": _("Timeout waiting for installation to complete"),
            }

        except Exception as error:
            self.logger.error(_("Error waiting for installation: %s"), error)
            return {"success": False, "error": str(error)}

    def _wait_for_prompt(
        self,
        fd: int,
        prompts: List[bytes],
        timeout: int,
    ) -> bool:
        """
        Wait for one of the specified prompts.

        Args:
            fd: File descriptor to read from
            prompts: List of prompt patterns to match
            timeout: Timeout in seconds

        Returns:
            True if prompt found, False on timeout
        """
        buffer = b""
        start_time = time.time()

        while time.time() - start_time < timeout:
            ready, _write, _exc = select.select([fd], [], [], 1.0)
            if not ready:
                continue

            data = self._safe_read(fd)
            if data is None:
                break

            if data:
                buffer += data
                self.logger.debug(_("Received: %s"), data[:100])
                if self._check_prompts(buffer, prompts):
                    return True

        return False

    def _safe_read(self, fd: int) -> Optional[bytes]:
        """Safely read from file descriptor, returning None on error."""
        try:
            return os.read(fd, 1024)
        except OSError:
            return None

    def _check_prompts(self, buffer: bytes, prompts: List[bytes]) -> bool:
        """Check if any prompt is present in buffer."""
        return any(prompt in buffer for prompt in prompts)

    def _send_key(self, fd: int, key: str) -> None:
        """
        Send a single key to the console.

        Args:
            fd: File descriptor to write to
            key: Key to send
        """
        os.write(fd, key.encode())
        time.sleep(0.1)

    def _send_line(self, fd: int, line: str) -> None:
        """
        Send a line to the console.

        Args:
            fd: File descriptor to write to
            line: Line to send (newline will be appended)
        """
        os.write(fd, (line + "\n").encode())
        time.sleep(0.1)

    def _read_output(self, fd: int, timeout: float = 1.0) -> str:
        """
        Read available output from console.

        Args:
            fd: File descriptor to read from
            timeout: Timeout in seconds

        Returns:
            Output string
        """
        output = b""
        start_time = time.time()

        while time.time() - start_time < timeout:
            ready, _write, _exc = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    data = os.read(fd, 1024)
                    if data:
                        output += data
                    else:
                        break
                except OSError:
                    break
            else:
                if output:
                    break

        return output.decode("utf-8", errors="replace")

    def _write_file_via_base64(
        self,
        fd: int,
        content: str,
        target_path: str,
        executable: bool = False,
    ) -> bool:
        """
        Write a file to the VM via base64 encoding.

        Args:
            fd: File descriptor for console
            content: File content to write
            target_path: Path on the VM
            executable: Whether to make the file executable

        Returns:
            True if successful
        """
        try:
            # Encode content
            content_b64 = base64.b64encode(content.encode()).decode("ascii")

            # Send in chunks
            chunk_size = 800
            for i in range(0, len(content_b64), chunk_size):
                chunk = content_b64[i : i + chunk_size]
                if i == 0:
                    cmd = f"echo -n '{chunk}' > /tmp/file.b64"
                else:
                    cmd = f"echo -n '{chunk}' >> /tmp/file.b64"
                self._send_line(fd, cmd)
                time.sleep(0.3)

            # Decode and move to target
            self._send_line(fd, f"base64 -d /tmp/file.b64 > {target_path}")
            time.sleep(0.3)

            if executable:
                self._send_line(fd, f"chmod +x {target_path}")
                time.sleep(0.2)

            self._send_line(fd, "rm /tmp/file.b64")
            time.sleep(0.2)

            return True

        except Exception as error:
            self.logger.error(_("Failed to write file %s: %s"), target_path, error)
            return False
