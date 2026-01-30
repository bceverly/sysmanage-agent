"""
PF (Packet Filter) firewall operations for BSD systems.

Supports OpenBSD, FreeBSD, and NetBSD systems that use PF.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

# pylint: disable=protected-access

import subprocess  # nosec B404
from typing import Dict, List, Optional

import aiofiles

from src.i18n import _  # pylint: disable=not-callable


class PFFirewallOperations:
    """Manages PF (Packet Filter) firewall operations."""

    def __init__(self, parent):
        """
        Initialize PF operations.

        Args:
            parent: Parent BSDFirewallOperations instance
        """
        self.parent = parent
        self.logger = parent.logger

    async def enable_pf_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable PF (Packet Filter) on BSD/macOS.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling PF firewall")

            # Check if PF config exists
            pf_conf = "/etc/pf.conf"
            try:
                async with aiofiles.open(pf_conf, "r", encoding="utf-8") as file_handle:
                    existing_rules = await file_handle.read()
            except FileNotFoundError:
                existing_rules = ""

            # Build rules to add
            rules_to_add = []

            # Always allow SSH (port 22)
            if "pass in proto tcp to port 22" not in existing_rules:
                rules_to_add.append("pass in proto tcp to port 22")

            # Add agent/server ports
            for port in ports:
                rule = f"pass in proto {protocol} to port {port}"
                if rule not in existing_rules:
                    rules_to_add.append(rule)

            if rules_to_add:
                # Append rules to pf.conf
                self.logger.info("Adding %d rules to pf.conf", len(rules_to_add))
                try:
                    async with aiofiles.open(
                        pf_conf, "a", encoding="utf-8"
                    ) as file_handle:
                        await file_handle.write("\n# SysManage Agent rules\n")
                        for rule in rules_to_add:
                            await file_handle.write(f"{rule}\n")
                except PermissionError:
                    # Try with sudo
                    rules_content = (
                        "\n# SysManage Agent rules\n" + "\n".join(rules_to_add) + "\n"
                    )
                    subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                        self.parent._build_command(
                            ["sh", "-c", f"echo '{rules_content}' >> {pf_conf}"]
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

            # Test the configuration
            result = subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                self.parent._build_command(["pfctl", "-nf", pf_conf]),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"PF configuration test failed: {result.stderr}",
                }

            # Load the rules
            result = subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                self.parent._build_command(["pfctl", "-f", pf_conf]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to load PF rules: {result.stderr}",
                }

            # Enable PF
            result = subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                self.parent._build_command(["pfctl", "-e"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Note: pfctl -e returns error if already enabled, so we check output
            if result.returncode == 0 or "already enabled" in result.stderr:
                self.logger.info("PF firewall enabled successfully")
                await self.parent._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("PF firewall enabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to enable PF: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error enabling PF firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles_pf(
        self, port_configs: Dict, agent_ports: List[int], errors: List[str]
    ) -> Optional[Dict]:
        """Apply firewall roles using PF (synchronize - add and remove rules)."""
        try:
            # Check if PF is available
            result = subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # PF not available

            self.logger.info("Synchronizing firewall roles using PF")

            # Preserved ports: agent communication + SSH (22)
            preserved_ports = set(agent_ports + [22])

            # First, flush the sysmanage anchor to remove old rules
            self.logger.info("Flushing PF sysmanage anchor")
            subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                ["pfctl", "-a", "sysmanage", "-F", "rules"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Build all rules at once for the anchor
            rules = []
            for port, protocols in port_configs.items():
                if port in preserved_ports:
                    continue  # Skip preserved ports

                if protocols["tcp"]:
                    rules.append(f"pass in quick proto tcp to port {port}")
                if protocols["udp"]:
                    rules.append(f"pass in quick proto udp to port {port}")

            # Apply all rules at once to the sysmanage anchor
            if rules:
                rules_content = "\n".join(rules) + "\n"
                self.logger.info("Adding %d PF rules to sysmanage anchor", len(rules))
                result = subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                    ["pfctl", "-a", "sysmanage", "-f", "-"],
                    input=rules_content,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add PF rules: {result.stderr}")
                    self.logger.warning("Failed to add PF rules: %s", result.stderr)
            else:
                self.logger.info("No role ports to configure in PF")

            await self.parent._send_firewall_status_update()

            if errors:
                return {
                    "success": False,
                    "error": "; ".join(errors),
                    "message": _("Some firewall rules failed to apply"),
                }

            return {
                "success": True,
                "message": _("Firewall roles synchronized successfully via PF"),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # PF not available

    async def remove_firewall_ports_pf(
        self, ports_to_remove: Dict, preserved_ports: set, _errors: List[str]
    ) -> Optional[Dict]:
        """Remove specific firewall ports using PF."""
        try:
            # Check if PF is available
            result = subprocess.run(  # nosec B603 B607  # noqa: ASYNC221  # NOSONAR - Sync subprocess acceptable for quick firewall commands
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # PF not available

            self.logger.info("Removing firewall ports using PF")

            # Log the removal (PF rules are managed in pf.conf)
            for port, protocols in ports_to_remove.items():
                if port in preserved_ports:
                    self.logger.info(
                        "Skipping removal of preserved port %d (agent/SSH)", port
                    )
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "PF: Requested removal of port %d (%s)", port, "/".join(proto_list)
                )

            self.logger.info(
                "PF firewall port removal requires manual /etc/pf.conf editing "
                "and pfctl -f /etc/pf.conf reload"
            )

            await self.parent._send_firewall_status_update()

            return {
                "success": True,
                "message": _(  # pylint: disable=not-callable
                    "Firewall port removal acknowledged on PF. "
                    "Note: PF requires manual /etc/pf.conf configuration."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # PF not available
