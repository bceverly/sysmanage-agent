"""
BSD-specific firewall operations for SysManage Agent.
Supports PF (Packet Filter), IPFW, and NPF on FreeBSD, OpenBSD, and NetBSD.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import asyncio
import subprocess  # nosec B404
from typing import Dict, List, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.operations.firewall_base import FirewallBase
from src.sysmanage_agent.operations.firewall_bsd_pf import PFFirewallOperations
from src.sysmanage_agent.operations.firewall_bsd_ipfw import IPFWFirewallOperations
from src.sysmanage_agent.operations.firewall_bsd_npf import NPFFirewallOperations

# Module-level constants for repeated strings
_NO_SUPPORTED_FIREWALL = _("No supported firewall found on this BSD system")


class BSDFirewallOperations(FirewallBase):
    """Manages firewall operations on BSD systems (FreeBSD, OpenBSD, NetBSD)."""

    def __init__(self, agent, logger=None):
        """Initialize BSD firewall operations with firewall type handlers."""
        super().__init__(agent, logger)
        self.pf_ops = PFFirewallOperations(self)
        self.ipfw_ops = IPFWFirewallOperations(self)
        self.npf_ops = NPFFirewallOperations(self)

    def _build_command(self, command: List[str]) -> List[str]:
        """
        Build a command with or without sudo based on privilege level.

        Args:
            command: The command to execute as a list

        Returns:
            The command with sudo prepended if not running privileged
        """
        if is_running_privileged():
            return command
        return ["sudo"] + command

    async def _check_command_exists(self, command: str) -> bool:
        """
        Check if a command exists on the system using 'which'.

        Args:
            command: The command name to check

        Returns:
            True if the command exists, False otherwise
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "which",
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            return proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError):
            return False

    async def _run_firewall_command(
        self,
        command: List[str],
        timeout: int = 10,  # NOSONAR - timeout parameter is for asyncio.wait_for
    ) -> tuple:
        """
        Run a firewall command asynchronously.

        Args:
            command: The command to execute as a list
            timeout: Timeout in seconds

        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise subprocess.TimeoutExpired(command, timeout) from exc

    async def _disable_ipfw(self) -> Optional[Dict]:
        """Disable IPFW firewall. Returns result dict or None if IPFW not available."""
        if self.system != "FreeBSD":
            return None
        if not await self._check_command_exists("ipfw"):
            return None

        self.logger.info("Disabling IPFW firewall")
        try:
            returncode, _, stderr = await self._run_firewall_command(
                self._build_command(["sysctl", "net.inet.ip.fw.enable=0"])
            )
            if returncode == 0:
                self.logger.info("IPFW firewall disabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("IPFW firewall disabled successfully"),
                }
            return {"success": False, "error": f"Failed to disable IPFW: {stderr}"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def _disable_npf(self) -> Optional[Dict]:
        """Disable NPF firewall. Returns result dict or None if NPF not available."""
        if self.system != "NetBSD":
            return None
        if not await self._check_command_exists("npfctl"):
            return None

        self.logger.info("Disabling NPF firewall")
        try:
            returncode, _, stderr = await self._run_firewall_command(
                self._build_command(["npfctl", "stop"])
            )
            if returncode == 0:
                self.logger.info("NPF firewall disabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("NPF firewall disabled successfully"),
                }
            return {"success": False, "error": f"Failed to disable NPF: {stderr}"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def _disable_pf(self) -> Optional[Dict]:
        """Disable PF firewall. Returns result dict or None if PF not available."""
        if not await self._check_command_exists("pfctl"):
            return None

        self.logger.info("Disabling PF firewall")
        try:
            returncode, _, stderr = await self._run_firewall_command(
                self._build_command(["pfctl", "-d"])
            )
            if returncode == 0:
                self.logger.info("PF firewall disabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("PF firewall disabled successfully"),
                }
            return {"success": False, "error": f"Failed to disable PF: {stderr}"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def _restart_ipfw(self) -> Optional[Dict]:
        """Restart IPFW firewall. Returns result dict or None if IPFW not available."""
        if self.system != "FreeBSD":
            return None
        if not await self._check_command_exists("ipfw"):
            return None

        self.logger.info("Restarting IPFW firewall")
        try:
            returncode, _, stderr = await self._run_firewall_command(
                self._build_command(["service", "ipfw", "restart"])
            )
            if returncode == 0:
                self.logger.info("IPFW firewall restarted successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("IPFW firewall restarted successfully"),
                }
            return {"success": False, "error": f"Failed to restart IPFW: {stderr}"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def _restart_npf(self) -> Optional[Dict]:
        """Restart NPF firewall. Returns result dict or None if NPF not available."""
        if self.system != "NetBSD":
            return None
        if not await self._check_command_exists("npfctl"):
            return None

        self.logger.info("Restarting NPF firewall")
        try:
            returncode, _, stderr = await self._run_firewall_command(
                self._build_command(["npfctl", "reload"])
            )
            if returncode == 0:
                self.logger.info("NPF firewall restarted successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("NPF firewall restarted successfully"),
                }
            return {"success": False, "error": f"Failed to restart NPF: {stderr}"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def _restart_pf(self) -> Optional[Dict]:
        """Restart PF firewall. Returns result dict or None if PF not available."""
        if not await self._check_command_exists("pfctl"):
            return None

        self.logger.info("Restarting PF firewall")
        try:
            returncode, _, stderr = await self._run_firewall_command(
                self._build_command(["pfctl", "-f", "/etc/pf.conf"])
            )
            if returncode == 0:
                self.logger.info("PF firewall restarted successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("PF firewall restarted successfully"),
                }
            return {"success": False, "error": f"Failed to restart PF: {stderr}"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def enable_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable firewall on BSD systems.

        Tries IPFW first (FreeBSD default), NPF (NetBSD default),
        then PF (OpenBSD default, also available on FreeBSD/NetBSD).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        # Try IPFW first (FreeBSD default)
        if self.system == "FreeBSD" and await self._check_command_exists("ipfw"):
            return await self.ipfw_ops.enable_ipfw_firewall(ports, protocol)

        # Try NPF (NetBSD default)
        if self.system == "NetBSD" and await self._check_command_exists("npfctl"):
            return await self.npf_ops.enable_npf_firewall(ports, protocol)

        # Try PF (OpenBSD default, also available on FreeBSD/NetBSD)
        if await self._check_command_exists("pfctl"):
            return await self.pf_ops.enable_pf_firewall(ports, protocol)

        return {
            "success": False,
            "error": _NO_SUPPORTED_FIREWALL,
        }

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on BSD systems.

        Tries IPFW first (FreeBSD default), NPF (NetBSD default),
        then PF (OpenBSD default, also available on FreeBSD/NetBSD).

        Returns:
            Dict with success status and message
        """
        # Try IPFW first (FreeBSD default)
        result = await self._disable_ipfw()
        if result is not None:
            return result

        # Try NPF (NetBSD default)
        result = await self._disable_npf()
        if result is not None:
            return result

        # Try PF (OpenBSD default, also available on FreeBSD/NetBSD)
        result = await self._disable_pf()
        if result is not None:
            return result

        return {
            "success": False,
            "error": _NO_SUPPORTED_FIREWALL,
        }

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on BSD systems.

        Tries IPFW first (FreeBSD default), NPF (NetBSD default),
        then PF (OpenBSD default, also available on FreeBSD/NetBSD).

        Returns:
            Dict with success status and message
        """
        # Try IPFW first (FreeBSD default)
        result = await self._restart_ipfw()
        if result is not None:
            return result

        # Try NPF (NetBSD default)
        result = await self._restart_npf()
        if result is not None:
            return result

        # Try PF (OpenBSD default, also available on FreeBSD/NetBSD)
        result = await self._restart_pf()
        if result is not None:
            return result

        return {
            "success": False,
            "error": _NO_SUPPORTED_FIREWALL,
        }

    async def deploy_firewall(self) -> Dict:
        """
        Deploy (enable) firewall on BSD systems.

        BSD firewalls are built into the kernel, so "deploy" means enabling them.
        - FreeBSD: Enable IPFW (built into kernel)
        - OpenBSD: Enable PF (built in)
        - NetBSD: Enable NPF (built in)

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Deploying firewall on BSD system")

            # Get agent communication ports
            ports, protocol = self._get_agent_communication_ports()

            # Also detect if server is running locally
            server_ports = self._get_local_server_ports()
            all_ports = list(set(ports + server_ports))

            self.logger.info("Ports to allow: %s (protocol: %s)", all_ports, protocol)

            # Deploy means enable on BSD systems (firewall software is built-in)
            return await self.enable_firewall(all_ports, protocol)

        except Exception as exc:
            self.logger.error("Error deploying firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Apply firewall roles by configuring open ports on BSD systems.

        Supports:
        - OpenBSD/FreeBSD: PF (packet filter)
        - FreeBSD: IPFW
        - NetBSD: NPF

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4
            ipv6_ports: List of {port, tcp, udp} for IPv6

        Returns:
            Dict with success status and message
        """
        self.logger.info("Applying firewall roles on BSD system (%s)", self.system)

        errors = []

        # Get agent communication ports (must always be open)
        agent_ports, _proto = self._get_agent_communication_ports()

        # Combine port configurations
        all_port_configs = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in all_port_configs:
                all_port_configs[port] = {"tcp": False, "udp": False}
            if tcp:
                all_port_configs[port]["tcp"] = True
            if udp:
                all_port_configs[port]["udp"] = True

        # Try PF first (OpenBSD, FreeBSD)
        pf_result = await self.pf_ops.apply_firewall_roles_pf(
            all_port_configs, agent_ports, errors
        )
        if pf_result is not None:
            return pf_result

        # Try IPFW (FreeBSD)
        ipfw_result = await self.ipfw_ops.apply_firewall_roles_ipfw(
            all_port_configs, agent_ports, errors
        )
        if ipfw_result is not None:
            return ipfw_result

        # Try NPF (NetBSD)
        npf_result = await self.npf_ops.apply_firewall_roles_npf(
            all_port_configs, agent_ports, errors
        )
        if npf_result is not None:
            return npf_result

        return {
            "success": False,
            "error": _NO_SUPPORTED_FIREWALL,
        }

    async def remove_firewall_ports(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Remove specific firewall ports on BSD systems.

        This removes only the specified ports from the firewall.
        Used when a firewall role is removed from a host.

        Supports:
        - PF (FreeBSD/OpenBSD)
        - IPFW (FreeBSD)
        - NPF (NetBSD)

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4 to remove
            ipv6_ports: List of {port, tcp, udp} for IPv6 to remove

        Returns:
            Dict with success status and message
        """
        self.logger.info("Removing specific firewall ports on BSD system")

        errors = []

        # Get agent communication ports (must always be preserved)
        agent_ports, _proto = self._get_agent_communication_ports()
        # Also preserve SSH port 22
        preserved_ports = set(agent_ports + [22])

        # Build list of ports to remove from both IPv4 and IPv6
        ports_to_remove = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in ports_to_remove:
                ports_to_remove[port] = {"tcp": False, "udp": False}
            if tcp:
                ports_to_remove[port]["tcp"] = True
            if udp:
                ports_to_remove[port]["udp"] = True

        self.logger.info(
            "Ports to remove: %s, Preserved (will not remove): %s",
            list(ports_to_remove.keys()),
            list(preserved_ports),
        )

        # Try PF first
        pf_result = await self.pf_ops.remove_firewall_ports_pf(
            ports_to_remove, preserved_ports, errors
        )
        if pf_result is not None:
            return pf_result

        # Try IPFW
        ipfw_result = await self.ipfw_ops.remove_firewall_ports_ipfw(
            ports_to_remove, preserved_ports, errors
        )
        if ipfw_result is not None:
            return ipfw_result

        # Try NPF (NetBSD) - just logs for now
        npf_result = await self.npf_ops.remove_firewall_ports_npf(
            ports_to_remove, preserved_ports, errors
        )
        if npf_result is not None:
            return npf_result

        return {
            "success": False,
            "error": _(  # pylint: disable=not-callable
                "No supported BSD firewall found on this system"
            ),
        }
