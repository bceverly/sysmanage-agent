"""
bhyve VM persistence and autostart support for FreeBSD hosts.

This module handles:
- VM configuration persistence to JSON files
- VM autostart configuration
- RC script generation for boot-time VM startup
"""

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiofiles

from src.i18n import _

# Default paths
BHYVE_VM_DIR = "/vm"
BHYVE_RC_SCRIPT = "/usr/local/etc/rc.d/sysmanage_bhyve"
BHYVE_AUTOSTART_CONF = "/usr/local/etc/sysmanage_bhyve.conf"


@dataclass
class BhyveVmPersistentConfig:  # pylint: disable=too-many-instance-attributes
    """Persistent configuration for a bhyve VM that survives host reboot."""

    # VM identity
    vm_name: str
    hostname: str
    distribution: str

    # Hardware configuration
    memory: str = "1G"
    cpus: int = 1
    disk_path: str = ""
    cloud_init_iso_path: str = ""
    use_uefi: bool = True

    # Autostart configuration
    autostart: bool = True
    autostart_delay: int = 0  # Seconds to delay before starting this VM

    # Metadata
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tap_interface: str = ""  # Will be recreated on start

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BhyveVmPersistentConfig":
        """Create from dictionary (JSON deserialization)."""
        # Filter to only known fields
        known_fields = {
            "vm_name",
            "hostname",
            "distribution",
            "memory",
            "cpus",
            "disk_path",
            "cloud_init_iso_path",
            "use_uefi",
            "autostart",
            "autostart_delay",
            "created_at",
            "tap_interface",
        }
        filtered_data = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered_data)


class BhyvePersistenceHelper:
    """Helper class for bhyve VM persistence operations."""

    def __init__(self, logger):
        """Initialize persistence helper."""
        self.logger = logger

    def get_config_path(self, vm_name: str) -> str:
        """Get the path to a VM's config file."""
        return os.path.join(BHYVE_VM_DIR, vm_name, "vm-config.json")

    async def save_vm_config(self, config: BhyveVmPersistentConfig) -> Dict[str, Any]:
        """
        Save VM configuration to disk.

        Args:
            config: VM configuration to save

        Returns:
            Dict with success status
        """
        try:
            config_path = self.get_config_path(config.vm_name)
            config_dir = os.path.dirname(config_path)

            # Ensure directory exists
            os.makedirs(config_dir, exist_ok=True)

            # Write config as JSON
            config_json = json.dumps(config.to_dict(), indent=2)
            async with aiofiles.open(config_path, "w", encoding="utf-8") as config_file:
                await config_file.write(config_json)

            self.logger.info(_("Saved VM config: %s"), config_path)
            return {"success": True, "config_path": config_path}

        except Exception as error:
            self.logger.error(_("Failed to save VM config: %s"), error)
            return {"success": False, "error": str(error)}

    async def load_vm_config(self, vm_name: str) -> Optional[BhyveVmPersistentConfig]:
        """
        Load VM configuration from disk.

        Args:
            vm_name: Name of the VM

        Returns:
            BhyveVmPersistentConfig or None if not found
        """
        config_path = self.get_config_path(vm_name)

        if not os.path.exists(config_path):
            return None

        try:
            async with aiofiles.open(config_path, "r", encoding="utf-8") as config_file:
                content = await config_file.read()

            data = json.loads(content)
            return BhyveVmPersistentConfig.from_dict(data)

        except Exception as error:
            self.logger.error(_("Failed to load VM config for %s: %s"), vm_name, error)
            return None

    async def delete_vm_config(self, vm_name: str) -> Dict[str, Any]:
        """
        Delete VM configuration file.

        Args:
            vm_name: Name of the VM

        Returns:
            Dict with success status
        """
        config_path = self.get_config_path(vm_name)

        try:
            if os.path.exists(config_path):
                os.remove(config_path)
                self.logger.info(_("Removed VM config: %s"), config_path)
            return {"success": True}

        except Exception as error:
            self.logger.error(_("Failed to delete VM config: %s"), error)
            return {"success": False, "error": str(error)}

    async def set_autostart(self, vm_name: str, enabled: bool) -> Dict[str, Any]:
        """
        Enable or disable autostart for a VM.

        Args:
            vm_name: Name of the VM
            enabled: Whether to enable autostart

        Returns:
            Dict with success status
        """
        config = await self.load_vm_config(vm_name)
        if not config:
            return {
                "success": False,
                "error": _("VM config not found for %s") % vm_name,
            }

        config.autostart = enabled
        return await self.save_vm_config(config)

    async def list_autostart_vms(self) -> List[BhyveVmPersistentConfig]:
        """
        Get list of VMs configured for autostart.

        Returns:
            List of VM configs with autostart enabled, sorted by delay
        """
        autostart_vms = []

        if not os.path.isdir(BHYVE_VM_DIR):
            return autostart_vms

        for entry in os.listdir(BHYVE_VM_DIR):
            vm_dir = os.path.join(BHYVE_VM_DIR, entry)
            if not os.path.isdir(vm_dir):
                continue

            # Skip special directories
            if entry in ("images", "cloud-init"):
                continue

            config = await self.load_vm_config(entry)
            if config and config.autostart:
                autostart_vms.append(config)

        # Sort by autostart_delay
        autostart_vms.sort(key=lambda c: c.autostart_delay)
        return autostart_vms

    def generate_rc_script(self) -> str:
        """
        Generate the rc.d script content for bhyve autostart.

        Returns:
            RC script content as string
        """
        return """#!/bin/sh
#
# PROVIDE: sysmanage_bhyve
# REQUIRE: NETWORKING vmm bridge1
# KEYWORD: shutdown
#
# sysmanage_bhyve_enable (bool):  Set to YES to enable bhyve VM autostart
#                                  Default: NO
#

. /etc/rc.subr

name="sysmanage_bhyve"
rcvar="${name}_enable"
desc="SysManage bhyve VM autostart"

load_rc_config $name

: ${sysmanage_bhyve_enable:="NO"}

start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"

# Path to the sysmanage-agent venv python
PYTHON="/opt/sysmanage-agent/.venv/bin/python"
AGENT_DIR="/opt/sysmanage-agent"

sysmanage_bhyve_start()
{
    echo "Starting bhyve VMs via SysManage..."

    if [ ! -x "$PYTHON" ]; then
        echo "Warning: SysManage agent not found at $AGENT_DIR"
        # Fall back to scanning /vm directory manually
        for vm_dir in /vm/*/; do
            vm_name=$(basename "$vm_dir")
            # Skip special directories
            case "$vm_name" in
                images|cloud-init) continue ;;
            esac

            config_file="${vm_dir}vm-config.json"
            if [ -f "$config_file" ]; then
                # Check if autostart is enabled using grep
                if grep -q '"autostart": true' "$config_file" 2>/dev/null; then
                    echo "Starting VM: $vm_name"
                    # Basic startup - the proper way is via the agent
                    /usr/local/bin/bhyve_start_vm.sh "$vm_name" &
                fi
            fi
        done
        return 0
    fi

    # Use the agent's autostart functionality
    cd "$AGENT_DIR"
    "$PYTHON" -c "
import asyncio
import sys
sys.path.insert(0, '$AGENT_DIR')
from src.sysmanage_agent.operations.child_host_bhyve_persistence import BhyvePersistenceHelper
from src.sysmanage_agent.operations.child_host_bhyve_creation import BhyveCreationHelper
from src.sysmanage_agent.operations.child_host_bhyve_lifecycle import BhyveLifecycleHelper
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('bhyve_autostart')

async def start_vms():
    persistence = BhyvePersistenceHelper(logger)
    creation = BhyveCreationHelper(logger)
    lifecycle = BhyveLifecycleHelper(logger, creation)

    vms = await persistence.list_autostart_vms()
    for vm_config in vms:
        logger.info(f'Starting VM: {vm_config.vm_name}')
        result = await lifecycle.start_child_host({'child_name': vm_config.vm_name})
        if result.get('success'):
            logger.info(f'Started: {vm_config.vm_name}')
        else:
            logger.error(f'Failed to start {vm_config.vm_name}: {result.get(\"error\")}')
        # Respect autostart delay
        if vm_config.autostart_delay > 0:
            await asyncio.sleep(vm_config.autostart_delay)

asyncio.run(start_vms())
"
}

sysmanage_bhyve_stop()
{
    echo "Stopping bhyve VMs..."

    # Stop all running VMs
    for vmm_dev in /dev/vmm/*; do
        [ -e "$vmm_dev" ] || continue
        vm_name=$(basename "$vmm_dev")
        echo "Stopping VM: $vm_name"
        bhyvectl --vm="$vm_name" --force-poweroff 2>/dev/null
        bhyvectl --vm="$vm_name" --destroy 2>/dev/null
    done
}

sysmanage_bhyve_status()
{
    running_count=0
    for vmm_dev in /dev/vmm/*; do
        [ -e "$vmm_dev" ] || continue
        vm_name=$(basename "$vmm_dev")
        echo "Running: $vm_name"
        running_count=$((running_count + 1))
    done

    if [ $running_count -eq 0 ]; then
        echo "No bhyve VMs are running"
    else
        echo "Total: $running_count VM(s) running"
    fi
}

run_rc_command "$1"
"""

    async def install_rc_script(self) -> Dict[str, Any]:
        """
        Install the rc.d script for bhyve autostart.

        Returns:
            Dict with success status
        """
        try:
            script_content = self.generate_rc_script()

            # Write the script
            async with aiofiles.open(
                BHYVE_RC_SCRIPT, "w", encoding="utf-8"
            ) as script_file:
                await script_file.write(script_content)

            # Make executable
            os.chmod(BHYVE_RC_SCRIPT, 0o755)

            self.logger.info(_("Installed bhyve autostart script: %s"), BHYVE_RC_SCRIPT)
            return {"success": True, "script_path": BHYVE_RC_SCRIPT}

        except Exception as error:
            self.logger.error(_("Failed to install rc script: %s"), error)
            return {"success": False, "error": str(error)}

    async def enable_autostart_service(self, run_subprocess) -> Dict[str, Any]:
        """
        Enable the sysmanage_bhyve service in rc.conf.

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status
        """
        try:
            # Install the rc script if not present
            if not os.path.exists(BHYVE_RC_SCRIPT):
                install_result = await self.install_rc_script()
                if not install_result.get("success"):
                    return install_result

            # Enable in rc.conf using sysrc
            result = await run_subprocess(
                ["sysrc", "sysmanage_bhyve_enable=YES"],
                timeout=10,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to enable autostart service: %s")
                    % result.stderr,
                }

            self.logger.info(_("Enabled bhyve autostart service"))
            return {"success": True, "message": _("Autostart service enabled")}

        except Exception as error:
            self.logger.error(_("Error enabling autostart service: %s"), error)
            return {"success": False, "error": str(error)}

    async def disable_autostart_service(self, run_subprocess) -> Dict[str, Any]:
        """
        Disable the sysmanage_bhyve service in rc.conf.

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status
        """
        try:
            # Disable in rc.conf using sysrc
            result = await run_subprocess(
                ["sysrc", "sysmanage_bhyve_enable=NO"],
                timeout=10,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to disable autostart service: %s")
                    % result.stderr,
                }

            self.logger.info(_("Disabled bhyve autostart service"))
            return {"success": True, "message": _("Autostart service disabled")}

        except Exception as error:
            self.logger.error(_("Error disabling autostart service: %s"), error)
            return {"success": False, "error": str(error)}
