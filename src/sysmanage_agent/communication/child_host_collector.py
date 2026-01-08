"""
Child host data collection for the SysManage agent.

This module handles child host (WSL/VM/container) status collection and
periodic heartbeat updates on Windows systems.
"""

import asyncio
import configparser
import logging
import os
import platform
import subprocess  # nosec B404
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from main import SysManageAgent


class ChildHostCollector:
    """Handles child host status collection and WSL keep-alive on Windows."""

    def __init__(self, agent_instance: "SysManageAgent"):
        """
        Initialize the ChildHostCollector.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        # Track persistent WSL keep-alive processes (distro_name -> Popen)
        self._wsl_keepalive_processes: dict = {}

    def _ensure_wslconfig(self) -> bool:
        """
        Ensure .wslconfig exists with settings to prevent WSL auto-shutdown.

        Configures:
        - [wsl2] vmIdleTimeout=-1: Prevents VM shutdown when idle
        - [wsl] autoStop=false: Prevents instance shutdown (WSL 2.6.x regression workaround)

        Uses case-preserving config parser since WSL settings may be case-sensitive.

        Returns:
            True if config was created/modified and WSL needs restart, False otherwise.
        """
        # Get current user's home directory
        user_home = Path(os.path.expanduser("~"))
        wslconfig_path = user_home / ".wslconfig"

        # Use a case-preserving ConfigParser (default lowercases keys)
        config = configparser.RawConfigParser()
        config.optionxform = str  # Preserve case for keys

        needs_update = False
        creating_new_file = not wslconfig_path.exists()

        # Read existing config if it exists
        if wslconfig_path.exists():
            try:
                config.read(str(wslconfig_path))
            except configparser.Error as parse_error:
                self.logger.warning(
                    "Could not parse existing .wslconfig: %s", parse_error
                )
                # Continue anyway, we'll add/update the sections

        # Check and set [wsl2] vmIdleTimeout=-1
        if not config.has_section("wsl2"):
            config.add_section("wsl2")
            needs_update = True

        # Check for correct case vmIdleTimeout, also detect lowercase version
        has_correct_timeout = config.has_option("wsl2", "vmIdleTimeout")
        has_lowercase_timeout = config.has_option("wsl2", "vmidletimeout")
        current_timeout = config.get("wsl2", "vmIdleTimeout", fallback=None)

        if has_lowercase_timeout and not has_correct_timeout:
            # Remove lowercase version, we'll add correct case
            config.remove_option("wsl2", "vmidletimeout")
            self.logger.info("Removing lowercase vmidletimeout, will add vmIdleTimeout")
            needs_update = True

        if current_timeout != "-1":
            config.set("wsl2", "vmIdleTimeout", "-1")
            needs_update = True

        # Check and set [wsl] autoStop=false (workaround for WSL 2.6.x regression)
        # See: https://github.com/microsoft/wsl/issues/13416
        if not config.has_section("wsl"):
            config.add_section("wsl")
            needs_update = True

        # Check for correct case autoStop, also detect lowercase version
        has_correct_autostop = config.has_option("wsl", "autoStop")
        has_lowercase_autostop = config.has_option("wsl", "autostop")
        current_autostop = config.get("wsl", "autoStop", fallback=None)

        if has_lowercase_autostop and not has_correct_autostop:
            # Remove lowercase version, we'll add correct case
            config.remove_option("wsl", "autostop")
            self.logger.info("Removing lowercase autostop, will add autoStop")
            needs_update = True

        if current_autostop != "false":
            config.set("wsl", "autoStop", "false")
            needs_update = True

        if not needs_update:
            self.logger.debug(".wslconfig already configured correctly")
            return False

        try:
            if creating_new_file:
                self.logger.info(
                    ".wslconfig not found, creating to prevent WSL auto-shutdown at %s",
                    wslconfig_path,
                )
            else:
                self.logger.info(
                    "Updating .wslconfig to prevent WSL auto-shutdown at %s",
                    wslconfig_path,
                )

            with open(wslconfig_path, "w", encoding="utf-8") as config_file:
                config.write(config_file)
            self.logger.info(".wslconfig saved successfully")
            return True
        except PermissionError:
            self.logger.error("Permission denied writing to %s", wslconfig_path)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to write .wslconfig: %s", error)

        return False

    def _restart_wsl(self):
        """
        Shutdown and restart WSL to apply .wslconfig changes.

        This performs a full WSL shutdown so the new vmIdleTimeout setting takes effect.
        """
        creationflags = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

        try:
            self.logger.info("Shutting down WSL to apply .wslconfig changes...")
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--shutdown"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode == 0:
                self.logger.info(
                    "WSL shutdown complete, new settings will apply on next start"
                )
            else:
                stderr = result.stderr.decode("utf-8", errors="ignore")
                self.logger.warning("WSL shutdown returned non-zero: %s", stderr)

        except subprocess.TimeoutExpired:
            self.logger.warning("WSL shutdown timed out")
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to shutdown WSL: %s", error)

    async def child_host_heartbeat(self):
        """
        Handle frequent child host status updates.

        This runs more frequently than the main data collector to ensure
        child host status (VMs, containers, WSL instances) is kept up to date
        in the UI. On Windows, also maintains persistent keep-alive processes
        for WSL instances to work around WSL 2.6.x regression.
        """
        self.logger.debug("Child host heartbeat started")

        os_type = platform.system().lower()

        # Windows-specific: WSL keep-alive setup
        if os_type == "windows":
            # Ensure .wslconfig exists with proper settings
            # If we had to create/modify it, restart WSL to apply the setting
            if self._ensure_wslconfig():
                self._restart_wsl()

            # Start persistent keep-alive processes for all WSL instances
            self.logger.info("Starting WSL keep-alive processes")
            self._ensure_keepalive_processes()

        # Send child host status every 60 seconds
        heartbeat_interval = 60  # 1 minute

        try:
            while self.agent.running:
                try:
                    await asyncio.sleep(heartbeat_interval)

                    # Windows-specific: Ensure keep-alive processes are still running
                    if os_type == "windows":
                        self._ensure_keepalive_processes()

                    await self.send_child_hosts_update()
                    self.logger.debug("AGENT_DEBUG: Child host heartbeat completed")
                except asyncio.CancelledError:
                    self.logger.debug("Child host heartbeat cancelled")
                    raise
                except Exception as error:
                    self.logger.error("Child host heartbeat error: %s", error)
                    # Continue the loop on non-critical errors
                    continue
        finally:
            # Clean up keep-alive processes when heartbeat stops (Windows only)
            if os_type == "windows":
                self.logger.info("Stopping WSL keep-alive processes")
            self._stop_all_keepalive_processes()

    def _get_wsl_distros(self) -> list:
        """
        Get list of all WSL distributions.

        Returns:
            List of distribution names.
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--list", "--quiet"],
                capture_output=True,
                timeout=10,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return []

            # Parse distributions (output is UTF-16LE on Windows)
            try:
                output = result.stdout.decode("utf-16-le").strip()
            except UnicodeDecodeError:
                output = result.stdout.decode("utf-8", errors="ignore").strip()

            return [
                line.strip()
                for line in output.splitlines()
                if line.strip() and not line.strip().startswith("Windows")
            ]

        except Exception as error:  # pylint: disable=broad-except
            self.logger.debug("Failed to get WSL distros: %s", error)
            return []

    def _start_keepalive_process(self, distro: str) -> bool:
        """
        Start a persistent keep-alive process for a WSL distribution.

        This runs 'sleep infinity' via wsl.exe which keeps the WSL instance
        running. This is a workaround for WSL 2.6.x regression where instances
        shut down even with active systemd services.
        See: https://github.com/microsoft/wsl/issues/13416

        Args:
            distro: Name of the WSL distribution.

        Returns:
            True if process started successfully, False otherwise.
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Start wsl.exe with sleep infinity - this keeps the instance alive
            # pylint: disable-next=consider-using-with
            process = subprocess.Popen(  # nosec B603 B607
                ["wsl", "-d", distro, "--", "sleep", "infinity"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )

            self._wsl_keepalive_processes[distro] = process
            self.logger.info("Started keep-alive process for WSL instance: %s", distro)
            return True

        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to start keep-alive for WSL instance %s: %s", distro, error
            )
            return False

    def _stop_keepalive_process(self, distro: str):
        """
        Stop the keep-alive process for a WSL distribution.

        Args:
            distro: Name of the WSL distribution.
        """
        process = self._wsl_keepalive_processes.pop(distro, None)
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
                self.logger.debug(
                    "Stopped keep-alive process for WSL instance: %s", distro
                )
            except subprocess.TimeoutExpired:
                process.kill()
                self.logger.warning(
                    "Had to kill keep-alive process for WSL instance: %s", distro
                )
            except Exception as error:  # pylint: disable=broad-except
                self.logger.debug("Error stopping keep-alive for %s: %s", distro, error)

    def _stop_all_keepalive_processes(self):
        """Stop all WSL keep-alive processes."""
        for distro in list(self._wsl_keepalive_processes.keys()):
            self._stop_keepalive_process(distro)

    def _ensure_keepalive_processes(self):
        """
        Ensure all WSL distributions have keep-alive processes running.

        Starts new processes for any distributions that don't have one,
        and cleans up processes for distributions that no longer exist.
        """
        current_distros = set(self._get_wsl_distros())

        # Stop processes for distributions that no longer exist
        for distro in list(self._wsl_keepalive_processes.keys()):
            if distro not in current_distros:
                self.logger.info(
                    "WSL distribution %s no longer exists, stopping keep-alive", distro
                )
                self._stop_keepalive_process(distro)

        # Start or restart processes for each distribution
        for distro in current_distros:
            if not distro:
                continue

            process = self._wsl_keepalive_processes.get(distro)

            # Check if process is still running
            if process is not None:
                poll_result = process.poll()
                if poll_result is not None:
                    # Process has exited, remove it so we start a new one
                    self.logger.debug(
                        "Keep-alive process for %s exited (code %s), restarting",
                        distro,
                        poll_result,
                    )
                    del self._wsl_keepalive_processes[distro]
                    process = None

            # Start process if not running
            if process is None:
                self._start_keepalive_process(distro)

    async def send_child_hosts_update(self):
        """Send child hosts (WSL/VM/container) status update."""
        # Collect child hosts on platforms that support virtualization
        # Windows: WSL, Hyper-V, VirtualBox
        # Linux: LXD, KVM, VirtualBox
        # OpenBSD: VMM
        # FreeBSD: bhyve
        os_type = platform.system().lower()
        if os_type not in ("windows", "linux", "openbsd", "freebsd"):
            return

        self.logger.debug("AGENT_DEBUG: Collecting child hosts data")

        try:
            # Use the child_host_ops to list child hosts
            if hasattr(self.agent, "child_host_ops"):
                result = await self.agent.child_host_ops.list_child_hosts({})

                if result.get("success", False):
                    child_hosts = result.get("child_hosts", [])

                    # Create message data
                    child_hosts_info = {
                        "success": True,
                        "child_hosts": child_hosts,
                        "count": len(child_hosts),
                        "hostname": self.agent.registration.get_system_info()[
                            "hostname"
                        ],
                    }

                    # Add host_id if available
                    host_approval = (
                        self.agent.registration_manager.get_host_approval_from_db()
                    )
                    if host_approval:
                        child_hosts_info["host_id"] = str(host_approval.host_id)

                    # Create and send message
                    child_hosts_message = self.agent.create_message(
                        "child_host_list_update", child_hosts_info
                    )
                    self.logger.debug(
                        "AGENT_DEBUG: Sending child hosts message: %s",
                        child_hosts_message["message_id"],
                    )
                    success = await self.agent.send_message(child_hosts_message)

                    if success:
                        self.logger.debug(
                            "AGENT_DEBUG: Child hosts data sent successfully (%d hosts)",
                            len(child_hosts),
                        )
                    else:
                        self.logger.warning("Failed to send child hosts data")
                else:
                    self.logger.debug(
                        "AGENT_DEBUG: Child hosts collection returned no success: %s",
                        result.get("error", "Unknown error"),
                    )
        except Exception as error:
            self.logger.error("Error collecting/sending child hosts data: %s", error)
