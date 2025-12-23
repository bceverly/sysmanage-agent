"""
Alpine Linux VMM console automation module.

This module implements serial console interaction for automated Alpine setup.
It uses Python's pty module to interact with vmctl console.
"""

import asyncio
import base64
import logging
import os
import pty
import select
import subprocess  # nosec B404
import time
import traceback
from typing import Any, Dict, List, Optional

from src.i18n import _


class AlpineConsoleAutomation:
    """Handles automated console interaction for Alpine VM installation."""

    # Timeouts in seconds
    BOOT_TIMEOUT = 120  # Time to wait for boot
    LOGIN_TIMEOUT = 60  # Time to wait for login prompt
    COMMAND_TIMEOUT = 30  # Time to wait for command completion
    INSTALL_TIMEOUT = 600  # Time for full installation

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

        Retries multiple times to handle the race condition where the VM
        is launched but not yet fully registered in vmctl status.

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

    async def run_automated_setup(
        self,
        vm_name: str,
        setup_script: str,
        timeout: int = None,
    ) -> Dict[str, Any]:
        """
        Run automated setup via serial console.

        This method:
        1. Waits for the Alpine boot and login prompt
        2. Logs in as root
        3. Executes the setup script

        Args:
            vm_name: Name of the VM
            setup_script: Shell script to execute
            timeout: Overall timeout in seconds

        Returns:
            Dict with success status and any output
        """
        if timeout is None:
            timeout = self.INSTALL_TIMEOUT

        try:
            self.logger.info(_("Starting automated console setup for VM '%s'"), vm_name)

            # Get the TTY device
            tty_name = self.get_vm_tty(vm_name)
            if not tty_name:
                return {
                    "success": False,
                    "error": _("Could not find TTY for VM '%s'") % vm_name,
                }

            tty_device = f"/dev/{tty_name}"
            self.logger.info(_("VM '%s' is on %s"), vm_name, tty_device)

            # Run the console interaction in a thread to avoid blocking
            result = await asyncio.to_thread(
                self._console_interaction,
                vm_name,
                tty_device,
                setup_script,
                timeout,
            )

            return result

        except Exception as error:
            self.logger.error(
                _("Console automation error for VM '%s': %s"), vm_name, error
            )
            return {"success": False, "error": str(error)}

    def _console_interaction(  # pylint: disable=unused-argument
        self,
        vm_name: str,
        tty_device: str,
        setup_script: str,
        timeout: int,
    ) -> Dict[str, Any]:
        """
        Perform actual console interaction.

        This runs in a separate thread.

        Args:
            vm_name: Name of the VM
            tty_device: TTY device path (reserved for future direct PTY access)
            setup_script: Script content to execute
            timeout: Overall timeout (reserved for future use)
        """
        master_fd = None
        slave_fd = None

        try:
            # Open the PTY device
            # We use pty.openpty() to get a master/slave pair
            # Then we spawn vmctl console connected to our PTY
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

            # Close slave in parent process
            os.close(slave_fd)
            slave_fd = None

            # Wait for login prompt
            self.logger.info(_("Waiting for Alpine login prompt..."))
            if not self._wait_for_prompt(
                master_fd, [b"login:", b"localhost login:"], self.LOGIN_TIMEOUT
            ):
                # Maybe it's already at shell prompt?
                self.logger.warning(_("No login prompt, checking for shell prompt..."))

            # Send root login
            self.logger.info(_("Logging in as root..."))
            self._send_line(master_fd, "root")
            time.sleep(2)

            # Wait for shell prompt
            self.logger.info(_("Waiting for shell prompt..."))
            if not self._wait_for_prompt(master_fd, [b"#", b"$"], self.COMMAND_TIMEOUT):
                self.logger.warning(_("Shell prompt not detected, continuing anyway"))

            # Write the setup script to a file, then execute it
            # This is necessary because heredocs in the script don't work
            # when sent line-by-line via console. Instead, we:
            # 1. Base64 encode the script
            # 2. Send encoded chunks to the VM
            # 3. Decode and write to /tmp/setup.sh
            # 4. Execute the script file
            self.logger.info(_("Writing setup script to VM via base64..."))

            # Encode the entire script
            script_bytes = setup_script.encode("utf-8")
            script_b64 = base64.b64encode(script_bytes).decode("ascii")

            # Send base64 content in chunks (max ~800 chars per line to be safe)
            chunk_size = 800
            total_chunks = (len(script_b64) + chunk_size - 1) // chunk_size

            for i in range(0, len(script_b64), chunk_size):
                chunk = script_b64[i : i + chunk_size]
                chunk_num = i // chunk_size + 1

                if i == 0:
                    # First chunk - create file
                    cmd = f"echo -n '{chunk}' > /tmp/setup.b64"
                else:
                    # Subsequent chunks - append
                    cmd = f"echo -n '{chunk}' >> /tmp/setup.b64"

                self.logger.debug(
                    _("Sending base64 chunk %d/%d (%d bytes)"),
                    chunk_num,
                    total_chunks,
                    len(chunk),
                )
                self._send_line(master_fd, cmd)
                time.sleep(0.3)
                self._wait_for_prompt(master_fd, [b"#", b"$"], 5)

            # Decode base64 to script file
            self.logger.info(_("Decoding script file..."))
            self._send_line(master_fd, "base64 -d /tmp/setup.b64 > /tmp/setup.sh")
            time.sleep(0.5)
            self._wait_for_prompt(master_fd, [b"#", b"$"], 10)

            # Make executable
            self._send_line(master_fd, "chmod +x /tmp/setup.sh")
            time.sleep(0.3)
            self._wait_for_prompt(master_fd, [b"#", b"$"], 5)

            # Verify the script was written correctly
            self._send_line(master_fd, "wc -l /tmp/setup.sh")
            time.sleep(0.5)
            self._wait_for_prompt(master_fd, [b"#", b"$"], 5)

            # Execute the setup script
            # The script runs setup-disk and ends with reboot, so we don't
            # wait for completion here. The script will run in the background
            # and the VM will shut down when done. We just need to start it
            # and give it time to begin execution.
            self.logger.info(_("Executing setup script..."))
            self._send_line(master_fd, "sh /tmp/setup.sh")

            # Give the script time to start and read from the console
            # to confirm it's running (look for our echo statements)
            time.sleep(5)
            output = self._read_output(master_fd, timeout=3.0)
            if output:
                self.logger.info(_("Script output: %s"), output[:200])

            self.logger.info(
                _("Setup script started. VM will reboot when installation completes.")
            )

            # Clean up the console connection
            # Don't wait long - the script is running in the VM
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate gracefully
                process.kill()
                process.wait(timeout=5)

            return {
                "success": True,
                "message": _("Console automation completed"),
            }

        except Exception as error:
            tb_str = traceback.format_exc()
            self.logger.error(_("Console interaction error: %s"), error)
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
            # Check if data is available
            # Note: Don't use _ as throwaway variable - it shadows the i18n _ function
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

    def _send_line(self, fd: int, line: str) -> None:
        """
        Send a line to the console.

        Args:
            fd: File descriptor to write to
            line: Line to send (newline will be appended)
        """
        os.write(fd, (line + "\n").encode())
        time.sleep(0.1)  # Brief delay after sending

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
