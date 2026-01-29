"""
KVM/libvirt networking operations for Linux hosts.

This module handles KVM network configuration including NAT and bridged modes.
"""

import asyncio
import os
import shutil
import subprocess  # nosec B404 # Required for system command execution
import tempfile
from typing import Any, Dict, Optional

from src.i18n import _

# Module-level constants for repeated string literals
_VM_NAME_REQUIRED = "VM name is required"
# NOSONAR - private subnet for VM networking (libvirt default)
_DEFAULT_NETWORK_XML = """<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>"""


class KvmNetworking:
    """KVM/libvirt networking operations."""

    def __init__(self, logger):
        """
        Initialize KVM networking operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def _define_network_from_xml(self, xml_path: str) -> bool:
        """
        Define a libvirt network from an XML file.

        Args:
            xml_path: Path to the XML file

        Returns:
            True if successful, False otherwise
        """
        define_result = subprocess.run(  # nosec B603 B607
            ["sudo", "virsh", "net-define", xml_path],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if define_result.returncode != 0:
            self.logger.warning(
                _("Could not define default network: %s"),
                define_result.stderr or define_result.stdout or "Unknown error",
            )
            return False
        return True

    def _define_default_network_from_temp(self) -> None:
        """Create and define default network from temporary XML file."""
        self.logger.info(_("Creating default network XML"))
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False
        ) as tmp_file:
            tmp_file.write(_DEFAULT_NETWORK_XML)
            tmp_path = tmp_file.name

        try:
            self._define_network_from_xml(tmp_path)
        finally:
            os.unlink(tmp_path)

    def _configure_network_autostart_and_start(self, network_name: str) -> None:
        """
        Enable autostart and start a libvirt network.

        Args:
            network_name: Name of the network to configure
        """
        # Enable autostart
        autostart_result = subprocess.run(  # nosec B603 B607
            ["sudo", "virsh", "net-autostart", network_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if autostart_result.returncode != 0:
            self.logger.warning(
                _("Could not set network autostart: %s"),
                autostart_result.stderr or autostart_result.stdout,
            )

        # Start the network
        start_result = subprocess.run(  # nosec B603 B607
            ["sudo", "virsh", "net-start", network_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if start_result.returncode != 0:
            # Might already be started
            if "already active" not in (start_result.stderr or "").lower():
                self.logger.warning(
                    _("Could not start network: %s"),
                    start_result.stderr or start_result.stdout,
                )

    def _verify_network_active(self, network_name: str) -> bool:
        """
        Verify that a libvirt network is active.

        Args:
            network_name: Name of the network to verify

        Returns:
            True if network is active, False otherwise
        """
        verify_result = subprocess.run(  # nosec B603 B607
            ["sudo", "virsh", "net-info", network_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return (
            verify_result.returncode == 0 and "active" in verify_result.stdout.lower()
        )

    def setup_default_network(self) -> Dict[str, Any]:
        """
        Set up the default libvirt network (virbr0).

        Returns:
            Dict with success status and message
        """
        try:
            virsh_path = shutil.which("virsh")
            if not virsh_path:
                return {
                    "success": False,
                    "error": _("virsh command not found after installation"),
                }

            # Check if default network exists
            check_result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "net-info", "default"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if check_result.returncode != 0:
                # Default network doesn't exist, try to define it
                self.logger.info(_("Creating default libvirt network"))
                default_network_xml = "/usr/share/libvirt/networks/default.xml"

                if os.path.exists(default_network_xml):
                    self._define_network_from_xml(default_network_xml)
                else:
                    self._define_default_network_from_temp()

            self._configure_network_autostart_and_start("default")

            if self._verify_network_active("default"):
                self.logger.info(_("Default libvirt network is active"))
                return {"success": True, "message": _("Default network configured")}

            return {
                "success": True,
                "message": _(
                    "Network setup attempted but may need manual verification"
                ),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Network setup timed out")}
        except Exception as error:
            self.logger.error(_("Error setting up default network: %s"), error)
            return {"success": False, "error": str(error)}

    def get_bridge_network_xml(self, name: str, bridge: str) -> str:
        """
        Generate libvirt network XML for bridged mode.

        Args:
            name: Name for the libvirt network
            bridge: Name of the existing Linux bridge to use

        Returns:
            XML string for the bridged network definition
        """
        return f"""<network>
  <name>{name}</name>
  <forward mode='bridge'/>
  <bridge name='{bridge}'/>
</network>"""

    def _parse_network_list_output(self, output: str) -> list:
        """
        Parse virsh net-list output into a list of network dictionaries.

        Args:
            output: Raw output from virsh net-list --all

        Returns:
            List of network dictionaries
        """
        networks = []
        lines = output.strip().split("\n")
        # Skip header lines (first two)
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2:
                networks.append(
                    {
                        "name": parts[0],
                        "state": parts[1] if len(parts) > 1 else "unknown",
                        "autostart": parts[2] if len(parts) > 2 else "no",
                        "persistent": parts[3] if len(parts) > 3 else "no",
                    }
                )
        return networks

    def list_networks(self) -> Dict[str, Any]:
        """
        List all libvirt networks.

        Returns:
            Dict with success status and list of networks
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "net-list", "--all"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr or _("Failed to list networks"),
                }

            networks = self._parse_network_list_output(result.stdout)
            return {"success": True, "networks": networks}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("List networks timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def list_linux_bridges(self) -> Dict[str, Any]:
        """
        List available Linux bridge interfaces.

        Returns:
            Dict with success status and list of bridge interfaces
        """
        try:
            bridges = []
            bridge_dir = "/sys/class/net"

            if os.path.isdir(bridge_dir):
                for iface in os.listdir(bridge_dir):
                    bridge_path = os.path.join(bridge_dir, iface, "bridge")
                    if os.path.isdir(bridge_path):
                        bridges.append(iface)

            return {"success": True, "bridges": bridges}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def _validate_bridge_exists(self, bridge: str) -> Optional[Dict[str, Any]]:
        """
        Validate that a Linux bridge interface exists.

        Args:
            bridge: Name of the bridge interface

        Returns:
            Error dict if validation fails, None if successful
        """
        bridges_result = self.list_linux_bridges()
        if not bridges_result.get("success"):
            return bridges_result

        if bridge not in bridges_result.get("bridges", []):
            return {
                "success": False,
                "error": _("Bridge interface '%s' does not exist") % bridge,
            }
        return None

    def _check_network_exists(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Check if a libvirt network already exists.

        Args:
            name: Name of the network to check

        Returns:
            Error dict if network exists, None if it doesn't
        """
        networks_result = self.list_networks()
        if networks_result.get("success"):
            for net in networks_result.get("networks", []):
                if net["name"] == name:
                    return {
                        "success": False,
                        "error": _("Network '%s' already exists") % name,
                    }
        return None

    def _define_network_from_xml_string(
        self, network_xml: str
    ) -> Optional[Dict[str, Any]]:
        """
        Define a libvirt network from an XML string.

        Args:
            network_xml: XML string defining the network

        Returns:
            Error dict if definition fails, None if successful
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False
        ) as tmp_file:
            tmp_file.write(network_xml)
            tmp_path = tmp_file.name

        try:
            define_result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "net-define", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        finally:
            os.unlink(tmp_path)

        if define_result.returncode != 0:
            return {
                "success": False,
                "error": define_result.stderr
                or define_result.stdout
                or _("Failed to define network"),
            }
        return None

    def create_bridge_network(self, name: str, bridge: str) -> Dict[str, Any]:
        """
        Create a libvirt network using an existing Linux bridge.

        Args:
            name: Name for the libvirt network
            bridge: Name of the existing Linux bridge interface

        Returns:
            Dict with success status and message
        """
        try:
            # Validate the bridge exists
            validation_error = self._validate_bridge_exists(bridge)
            if validation_error:
                return validation_error

            # Check if network already exists
            exists_error = self._check_network_exists(name)
            if exists_error:
                return exists_error

            # Generate and define network XML
            network_xml = self.get_bridge_network_xml(name, bridge)
            define_error = self._define_network_from_xml_string(network_xml)
            if define_error:
                return define_error

            # Configure autostart and start the network
            self._configure_network_autostart_and_start(name)

            self.logger.info(
                _("Created bridged network '%s' using bridge '%s'"), name, bridge
            )
            return {
                "success": True,
                "message": _("Bridged network '%s' created successfully") % name,
                "network_name": name,
                "bridge": bridge,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Network creation timed out")}
        except Exception as error:
            self.logger.error(_("Error creating bridged network: %s"), error)
            return {"success": False, "error": str(error)}

    async def setup_networking(
        self, parameters: dict
    ) -> dict:  # NOSONAR - async required by interface contract
        """
        Configure KVM networking based on the specified mode.

        Args:
            parameters: Dict with:
                - mode: 'nat' (default) or 'bridged'
                - network_name: Name for the network (default: 'default' for NAT)
                - bridge: Linux bridge interface name (required for bridged mode)

        Returns:
            Dict with success status and network details
        """
        await asyncio.sleep(0)  # Yield to event loop for interface consistency
        try:
            mode = parameters.get("mode", "nat").lower()
            network_name = parameters.get("network_name")
            bridge = parameters.get("bridge")

            self.logger.info(_("Setting up KVM networking in %s mode"), mode)

            if mode == "nat":
                # Use default NAT network
                result = self.setup_default_network()
                if result.get("success"):
                    return {
                        "success": True,
                        "message": _("NAT networking configured successfully"),
                        "mode": "nat",
                        "network_name": "default",
                        "subnet": "192.168.122.0/24",  # NOSONAR - libvirt default subnet
                    }
                return result

            if mode == "bridged":
                if not bridge:
                    # List available bridges
                    bridges_result = self.list_linux_bridges()
                    available = bridges_result.get("bridges", [])
                    return {
                        "success": False,
                        "error": _(
                            "Bridge interface name is required for bridged mode"
                        ),
                        "available_bridges": available,
                    }

                if not network_name:
                    network_name = f"bridge-{bridge}"

                result = self.create_bridge_network(network_name, bridge)
                if result.get("success"):
                    return {
                        "success": True,
                        "message": _("Bridged networking configured successfully"),
                        "mode": "bridged",
                        "network_name": network_name,
                        "bridge": bridge,
                    }
                return result

            return {
                "success": False,
                "error": _("Unknown network mode: %s. Use 'nat' or 'bridged'") % mode,
            }

        except Exception as error:
            self.logger.error(_("Error configuring KVM networking: %s"), error)
            return {"success": False, "error": str(error)}

    async def list_all_networks(
        self, _parameters: dict
    ) -> dict:  # NOSONAR - async required by interface contract
        """
        List all configured KVM/libvirt networks.

        Returns:
            Dict with success status and list of networks
        """
        await asyncio.sleep(0)  # Yield to event loop for interface consistency
        try:
            networks_result = self.list_networks()
            if not networks_result.get("success"):
                return networks_result

            # Also get available Linux bridges for reference
            bridges_result = self.list_linux_bridges()
            available_bridges = bridges_result.get("bridges", [])

            return {
                "success": True,
                "networks": networks_result.get("networks", []),
                "available_bridges": available_bridges,
            }

        except Exception as error:
            return {"success": False, "error": str(error)}
