"""
Child host data collection for the SysManage agent.

This module handles child host (WSL/VM/container) status collection and
periodic heartbeat updates on Windows systems.
"""

import asyncio
import logging
import platform
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
            import subprocess  # nosec B404 # pylint: disable=import-outside-toplevel

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
