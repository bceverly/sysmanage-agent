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

    def _ensure_wslconfig(self) -> bool:
        """
        Ensure .wslconfig exists with vmIdleTimeout=-1 to prevent WSL auto-shutdown.

        Returns:
            True if config was created/modified and WSL needs restart, False otherwise.
        """
        # Get current user's home directory
        user_home = Path(os.path.expanduser("~"))
        wslconfig_path = user_home / ".wslconfig"

        config = configparser.ConfigParser()
        needs_restart = False
        creating_new_file = not wslconfig_path.exists()

        # Read existing config if it exists
        if wslconfig_path.exists():
            try:
                config.read(str(wslconfig_path))
            except configparser.Error as parse_error:
                self.logger.warning(
                    "Could not parse existing .wslconfig: %s", parse_error
                )
                # Continue anyway, we'll add/update the section

            # Check if already configured correctly
            if config.has_section("wsl2"):
                current_timeout = config.get("wsl2", "vmIdleTimeout", fallback=None)
                if current_timeout == "-1":
                    self.logger.debug(
                        ".wslconfig already configured with vmIdleTimeout=-1"
                    )
                    return False

        # Ensure [wsl2] section exists
        if not config.has_section("wsl2"):
            config.add_section("wsl2")

        # Set vmIdleTimeout=-1 to disable auto-shutdown
        config.set("wsl2", "vmIdleTimeout", "-1")

        try:
            if creating_new_file:
                self.logger.info(
                    ".wslconfig not found, creating with vmIdleTimeout=-1 to prevent "
                    "WSL auto-shutdown at %s",
                    wslconfig_path,
                )
            else:
                self.logger.info(
                    "Updating .wslconfig with vmIdleTimeout=-1 at %s",
                    wslconfig_path,
                )

            with open(wslconfig_path, "w", encoding="utf-8") as config_file:
                config.write(config_file)
            self.logger.info(".wslconfig saved successfully")
            needs_restart = True
        except PermissionError:
            self.logger.error("Permission denied writing to %s", wslconfig_path)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error("Failed to write .wslconfig: %s", error)

        return needs_restart

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
        Handle frequent child host status updates (Windows only).

        This runs more frequently than the main data collector to ensure
        child host status (WSL instances) is kept up to date in the UI.
        Also pokes WSL instances to keep them awake so their agents can
        send heartbeats.
        """
        # Only run on Windows where we have WSL
        if platform.system().lower() != "windows":
            self.logger.debug("Child host heartbeat skipped (not Windows)")
            return

        self.logger.debug("Child host heartbeat started")

        # Ensure .wslconfig exists with vmIdleTimeout=-1
        # If we had to create/modify it, restart WSL to apply the setting
        if self._ensure_wslconfig():
            self._restart_wsl()

        # Poke WSL instances immediately at startup to wake them up
        self.logger.debug("Poking WSL instances at startup")
        await self._poke_wsl_instances()

        # Send child host status every 60 seconds
        heartbeat_interval = 60  # 1 minute

        while self.agent.running:
            try:
                await asyncio.sleep(heartbeat_interval)

                # Poke running WSL instances to keep them awake
                await self._poke_wsl_instances()

                await self.send_child_hosts_update()
                self.logger.debug("AGENT_DEBUG: Child host heartbeat completed")
            except asyncio.CancelledError:
                self.logger.debug("Child host heartbeat cancelled")
                raise
            except Exception as error:
                self.logger.error("Child host heartbeat error: %s", error)
                # Continue the loop on non-critical errors
                continue

    async def _poke_wsl_instances(self):
        """
        Poke ALL WSL instances to wake them up and keep them running.

        WSL instances shut down when idle. By running a simple command in each
        instance, we wake them up so their sysmanage-agents can start and send
        heartbeats. This pokes ALL instances, not just running ones, to ensure
        stopped instances get woken up.
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Get list of ALL WSL instances (not just running)
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--list", "--quiet"],
                capture_output=True,
                timeout=10,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return

            # Parse distributions (output is UTF-16LE on Windows)
            try:
                output = result.stdout.decode("utf-16-le").strip()
            except UnicodeDecodeError:
                output = result.stdout.decode("utf-8", errors="ignore").strip()

            all_distros = [
                line.strip()
                for line in output.splitlines()
                if line.strip() and not line.strip().startswith("Windows")
            ]

            # Poke each instance to wake it up - this starts systemd which
            # starts the sysmanage-agent service
            for distro in all_distros:
                if not distro:
                    continue
                try:
                    subprocess.run(  # nosec B603 B607
                        ["wsl", "-d", distro, "--", "true"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                        creationflags=creationflags,
                    )
                    self.logger.debug("Poked WSL instance: %s", distro)
                except Exception:  # pylint: disable=broad-except  # nosec B110
                    pass  # Ignore errors for individual instances

        except Exception as error:  # pylint: disable=broad-except
            self.logger.debug("WSL poke failed: %s", error)

    async def send_child_hosts_update(self):
        """Send child hosts (WSL/VM/container) status update."""
        # Only collect child hosts on Windows (WSL) for now
        if platform.system().lower() != "windows":
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
