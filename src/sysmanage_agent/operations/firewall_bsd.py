"""
BSD-specific firewall operations for SysManage Agent.
Supports PF (Packet Filter), IPFW, and NPF on FreeBSD, OpenBSD, and NetBSD.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.operations.firewall_base import FirewallBase


class BSDFirewallOperations(FirewallBase):
    """Manages firewall operations on BSD systems (FreeBSD, OpenBSD, NetBSD)."""

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

    async def enable_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable firewall on BSD systems.

        Tries NPF first (NetBSD default), then PF (OpenBSD default, FreeBSD option),
        then IPFW (FreeBSD option).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        # Try NPF first (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "npfctl"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    return await self._enable_npf_firewall(ports, protocol)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try PF (OpenBSD default, FreeBSD option)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "pfctl"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                return await self._enable_pf_firewall(ports, protocol)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try IPFW (FreeBSD option)
        if self.system == "FreeBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "ipfw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    return await self._enable_ipfw_firewall(ports, protocol)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return {
            "success": False,
            "error": _("No supported firewall found on this BSD system"),
        }

    async def _enable_pf_firewall(self, ports: List[int], protocol: str) -> Dict:
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
                with open(pf_conf, "r", encoding="utf-8") as file_handle:
                    existing_rules = file_handle.read()
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
                    with open(pf_conf, "a", encoding="utf-8") as file_handle:
                        file_handle.write("\n# SysManage Agent rules\n")
                        for rule in rules_to_add:
                            file_handle.write(f"{rule}\n")
                except PermissionError:
                    # Try with sudo
                    rules_content = (
                        "\n# SysManage Agent rules\n" + "\n".join(rules_to_add) + "\n"
                    )
                    subprocess.run(  # nosec B603 B607
                        self._build_command(
                            ["sh", "-c", f"echo '{rules_content}' >> {pf_conf}"]
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

            # Test the configuration
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["pfctl", "-nf", pf_conf]),
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
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["pfctl", "-f", pf_conf]),
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
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["pfctl", "-e"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Note: pfctl -e returns error if already enabled, so we check output
            if result.returncode == 0 or "already enabled" in result.stderr:
                self.logger.info("PF firewall enabled successfully")
                await self._send_firewall_status_update()
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

    async def _enable_ipfw_firewall(self, ports: List[int], protocol: str) -> Dict:
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

            # Always allow SSH (port 22)
            self.logger.info("Adding IPFW rule: allow 22/tcp (SSH)")
            result = subprocess.run(  # nosec B603 B607
                self._build_command(
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
                    self._build_command(
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

            # Enable IPFW (requires rc.conf modification)
            # Check if firewall_enable is already set
            try:
                with open("/etc/rc.conf", "r", encoding="utf-8") as file_handle:
                    rc_conf = file_handle.read()

                if 'firewall_enable="YES"' not in rc_conf:
                    subprocess.run(  # nosec B603 B607
                        self._build_command(["sysrc", "firewall_enable=YES"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    subprocess.run(  # nosec B603 B607
                        self._build_command(["sysrc", "firewall_type=open"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
            except Exception as exc:
                self.logger.warning("Error modifying rc.conf: %s", exc)

            # Start IPFW service
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["service", "ipfw", "start"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("IPFW firewall enabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("IPFW firewall enabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to enable IPFW: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error enabling IPFW firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _enable_npf_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable NPF (NetBSD Packet Filter).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling NPF firewall")

            # Check if NPF config exists
            npf_conf = "/etc/npf.conf"
            try:
                with open(npf_conf, "r", encoding="utf-8") as file_handle:
                    existing_rules = file_handle.read()
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
                # Append rules to npf.conf
                self.logger.info("Adding %d rules to npf.conf", len(rules_to_add))
                try:
                    with open(npf_conf, "a", encoding="utf-8") as file_handle:
                        file_handle.write("\n# SysManage Agent rules\n")
                        for rule in rules_to_add:
                            file_handle.write(f"{rule}\n")
                except PermissionError:
                    # Try with sudo
                    rules_content = (
                        "\n# SysManage Agent rules\n" + "\n".join(rules_to_add) + "\n"
                    )
                    subprocess.run(  # nosec B603 B607
                        self._build_command(
                            ["sh", "-c", f"echo '{rules_content}' >> {npf_conf}"]
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

            # Validate the configuration
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["npfctl", "validate", npf_conf]),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"NPF configuration validation failed: {result.stderr}",
                }

            # Reload the configuration
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["npfctl", "reload", npf_conf]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to reload NPF configuration: {result.stderr}",
                }

            # Start NPF
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["npfctl", "start"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # npfctl start may fail with non-zero returncode if already running
            # Log the actual output to help debug
            self.logger.debug("npfctl start returncode: %s", result.returncode)
            self.logger.debug("npfctl start stdout: %s", result.stdout)
            self.logger.debug("npfctl start stderr: %s", result.stderr)

            if result.returncode != 0:
                # Check if it's already running - that's OK
                output_combined = (result.stdout + result.stderr).lower()
                if not any(msg in output_combined for msg in ["already", "running"]):
                    return {
                        "success": False,
                        "error": f"Failed to enable NPF: {result.stderr}",
                    }

            self.logger.info("NPF firewall enabled successfully")
            await self._send_firewall_status_update()
            return {
                "success": True,
                "message": _("NPF firewall enabled successfully"),
            }

        except Exception as exc:
            self.logger.error("Error enabling NPF firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on BSD systems.

        Tries NPF first (NetBSD default), then PF (OpenBSD default, FreeBSD option),
        then IPFW (FreeBSD option).

        Returns:
            Dict with success status and message
        """
        # Try NPF first (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "npfctl"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Disabling NPF firewall")
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["npfctl", "stop"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("NPF firewall disabled successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("NPF firewall disabled successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to disable NPF: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try PF (OpenBSD default, FreeBSD option)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "pfctl"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Disabling PF firewall")
                result = subprocess.run(  # nosec B603 B607
                    self._build_command(["pfctl", "-d"]),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("PF firewall disabled successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("PF firewall disabled successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to disable PF: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try IPFW (FreeBSD option)
        if self.system == "FreeBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "ipfw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Disabling IPFW firewall")
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["ipfw", "disable", "firewall"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("IPFW firewall disabled successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("IPFW firewall disabled successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to disable IPFW: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return {
            "success": False,
            "error": _("No supported firewall found on this BSD system"),
        }

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on BSD systems.

        Tries NPF first (NetBSD default), then PF (OpenBSD default, FreeBSD option),
        then IPFW (FreeBSD option).

        Returns:
            Dict with success status and message
        """
        # Try NPF first (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "npfctl"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Restarting NPF firewall")
                    # Reload configuration
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["npfctl", "reload"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("NPF firewall restarted successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("NPF firewall restarted successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to restart NPF: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try PF (OpenBSD default, FreeBSD option)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "pfctl"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Restarting PF firewall")
                # Reload PF rules
                result = subprocess.run(  # nosec B603 B607
                    self._build_command(["pfctl", "-f", "/etc/pf.conf"]),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("PF firewall restarted successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("PF firewall restarted successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to restart PF: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try IPFW (FreeBSD option)
        if self.system == "FreeBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "ipfw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Restarting IPFW firewall")
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["service", "ipfw", "restart"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("IPFW firewall restarted successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("IPFW firewall restarted successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to restart IPFW: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return {
            "success": False,
            "error": _("No supported firewall found on this BSD system"),
        }
