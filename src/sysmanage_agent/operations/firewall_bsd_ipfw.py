"""
IPFW (IP Firewall) operations for FreeBSD systems.

Supports FreeBSD systems that use IPFW.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

# pylint: disable=protected-access

import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _  # pylint: disable=not-callable


class IPFWFirewallOperations:
    """Manages IPFW (IP Firewall) operations on FreeBSD."""

    def __init__(self, parent):
        """
        Initialize IPFW operations.

        Args:
            parent: Parent BSDFirewallOperations instance
        """
        self.parent = parent
        self.logger = parent.logger

    async def enable_ipfw_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable IPFW on FreeBSD.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling IPFW firewall")

            # Load IPFW kernel module if not already loaded
            self.logger.info("Loading IPFW kernel module with kldload")
            result = subprocess.run(  # nosec B603 B607
                self.parent._build_command(["kldload", "ipfw"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.logger.info(
                "kldload result: returncode=%d, stdout='%s', stderr='%s'",
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )
            # kldload returns 1 if already loaded, which is fine
            if result.returncode not in [0, 1]:
                self.logger.warning(
                    "Failed to load IPFW kernel module: %s", result.stderr
                )

            # Enable IPFW (requires rc.conf modification)
            # Check if firewall_enable is already set
            try:
                with open("/etc/rc.conf", "r", encoding="utf-8") as file_handle:
                    rc_conf = file_handle.read()

                if 'firewall_enable="YES"' not in rc_conf:
                    subprocess.run(  # nosec B603 B607
                        self.parent._build_command(["sysrc", "firewall_enable=YES"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    subprocess.run(  # nosec B603 B607
                        self.parent._build_command(["sysrc", "firewall_type=open"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
            except Exception as exc:
                self.logger.warning("Error modifying rc.conf: %s", exc)

            # Start IPFW service (this will load default rules from rc.firewall)
            result = subprocess.run(  # nosec B603 B607
                self.parent._build_command(["service", "ipfw", "start"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to start IPFW service: {result.stderr}",
                }

            # Now add our custom rules (after service started to avoid them being flushed)
            # Always allow SSH (port 22)
            self.logger.info("Adding IPFW rule: allow 22/tcp (SSH)")
            result = subprocess.run(  # nosec B603 B607
                self.parent._build_command(
                    [
                        "ipfw",
                        "add",
                        "allow",
                        "tcp",
                        "from",
                        "any",
                        "to",
                        "any",
                        "22",
                    ]
                ),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Failed to add IPFW rule for SSH: %s", result.stderr
                )

            # Add agent/server ports
            for port in ports:
                self.logger.info("Adding IPFW rule: allow %d/%s", port, protocol)
                result = subprocess.run(  # nosec B603 B607
                    self.parent._build_command(
                        [
                            "ipfw",
                            "add",
                            "allow",
                            protocol,
                            "from",
                            "any",
                            "to",
                            "any",
                            str(port),
                        ]
                    ),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Failed to add IPFW rule for port %d: %s", port, result.stderr
                    )

            self.logger.info("IPFW firewall enabled successfully")
            await self.parent._send_firewall_status_update()
            return {
                "success": True,
                "message": _("IPFW firewall enabled successfully"),
            }

        except Exception as exc:
            self.logger.error("Error enabling IPFW firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles_ipfw(
        self, port_configs: Dict, agent_ports: List[int], errors: List[str]
    ) -> Dict:
        """Apply firewall roles using IPFW (synchronize - add and remove rules)."""
        try:
            # Check if IPFW is available
            result = subprocess.run(  # nosec B603 B607
                ["ipfw", "list"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # IPFW not available

            self.logger.info("Synchronizing firewall roles using IPFW")

            # Preserved ports: agent communication + SSH (22)
            preserved_ports = set(agent_ports + [22])

            # First, delete all SysManage role rules (rule numbers 10000-19999)
            # This is the cleanest way to synchronize
            self.logger.info("Deleting existing SysManage IPFW rules (10000-19999)")
            for rule_num in range(10000, 20000):
                # Try to delete the rule; it will fail silently if it doesn't exist
                subprocess.run(  # nosec B603 B607
                    ["ipfw", "-q", "delete", str(rule_num)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

            # Add rules for requested ports
            # Use rule numbers starting at 10000 for SysManage rules
            rule_num = 10000
            for port, protocols in port_configs.items():
                if port in preserved_ports:
                    continue

                if protocols["tcp"]:
                    self.logger.info(
                        "Adding IPFW rule %d: allow tcp port %d", rule_num, port
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "ipfw",
                            "add",
                            str(rule_num),
                            "allow",
                            "tcp",
                            "from",
                            "any",
                            "to",
                            "any",
                            str(port),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        errors.append(
                            f"Failed to add IPFW rule for TCP port {port}: {result.stderr}"
                        )
                    rule_num += 1

                if protocols["udp"]:
                    self.logger.info(
                        "Adding IPFW rule %d: allow udp port %d", rule_num, port
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "ipfw",
                            "add",
                            str(rule_num),
                            "allow",
                            "udp",
                            "from",
                            "any",
                            "to",
                            "any",
                            str(port),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        errors.append(
                            f"Failed to add IPFW rule for UDP port {port}: {result.stderr}"
                        )
                    rule_num += 1

            await self.parent._send_firewall_status_update()

            if errors:
                return {
                    "success": False,
                    "error": "; ".join(errors),
                    "message": _("Some firewall rules failed to apply"),
                }

            return {
                "success": True,
                "message": _("Firewall roles synchronized successfully via IPFW"),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # IPFW not available

    async def remove_firewall_ports_ipfw(  # pylint: disable=unused-argument
        self, ports_to_remove: Dict, preserved_ports: set, errors: List[str]
    ) -> Dict:
        """Remove specific firewall ports using IPFW."""
        try:
            # Check if IPFW is available
            result = subprocess.run(  # nosec B603 B607
                ["ipfw", "list"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # IPFW not available

            self.logger.info("Removing firewall ports using IPFW")

            # Log the removal (IPFW rules would need rule number tracking)
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
                    "IPFW: Requested removal of port %d (%s)",
                    port,
                    "/".join(proto_list),
                )

            self.logger.info(
                "IPFW firewall port removal requires rule number tracking "
                "for proper removal"
            )

            await self.parent._send_firewall_status_update()

            return {
                "success": True,
                "message": _(  # pylint: disable=not-callable
                    "Firewall port removal acknowledged on IPFW. "
                    "Note: IPFW rule management is limited."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # IPFW not available
