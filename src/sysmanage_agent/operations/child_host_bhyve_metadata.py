"""
bhyve VM metadata helpers for FreeBSD hosts.

This module contains functions for saving and loading VM metadata:
- Hostname and distribution info
- IP addresses
- Other VM metadata that isn't available from /dev/vmm

The metadata is used by list_bhyve_vms() to provide additional VM info.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from src.i18n import _

# Metadata directory for storing VM information
BHYVE_METADATA_DIR = "/vm/metadata"


def save_bhyve_metadata(
    vm_name: str,
    hostname: str,
    distribution: str,
    vm_ip: Optional[str],
    logger,
) -> bool:
    """
    Save bhyve VM metadata to JSON file for listing.

    This metadata is read by list_bhyve_vms() to provide hostname
    and distribution info that isn't available from /dev/vmm alone.

    Args:
        vm_name: Name of the VM
        hostname: VM hostname (FQDN)
        distribution: Distribution string (e.g., "FreeBSD 14")
        vm_ip: VM IP address (may be None if not yet known)
        logger: Logger instance

    Returns:
        True if successful, False otherwise
    """
    try:
        metadata_dir = Path(BHYVE_METADATA_DIR)
        metadata_dir.mkdir(parents=True, exist_ok=True)

        # Parse distribution string to extract name and version
        dist_name = distribution
        dist_version = ""
        if distribution:
            parts = distribution.split()
            if len(parts) >= 2:
                dist_name = parts[0]
                dist_version = " ".join(parts[1:])

        metadata = {
            "vm_name": vm_name,
            "hostname": hostname,
            "vm_ip": vm_ip,
            "distribution": {
                "distribution_name": dist_name,
                "distribution_version": dist_version,
            },
            "distribution_string": distribution,
        }

        metadata_file = metadata_dir / f"{vm_name}.json"
        with open(metadata_file, "w", encoding="utf-8") as metadata_fp:
            json.dump(metadata, metadata_fp, indent=2)

        logger.info(_("Saved bhyve VM metadata for '%s' to %s"), vm_name, metadata_file)
        return True

    except Exception as error:
        logger.error(_("Error saving bhyve VM metadata for '%s': %s"), vm_name, error)
        return False


def load_bhyve_metadata(vm_name: str, logger) -> Optional[Dict[str, Any]]:
    """
    Load bhyve VM metadata from JSON file.

    Args:
        vm_name: Name of the VM
        logger: Logger instance

    Returns:
        Dict with hostname, distribution, vm_ip, etc. or None if not found
    """
    try:
        metadata_file = Path(BHYVE_METADATA_DIR) / f"{vm_name}.json"
        if not metadata_file.exists():
            return None

        with open(metadata_file, "r", encoding="utf-8") as metadata_fp:
            return json.load(metadata_fp)

    except Exception as error:
        logger.debug("Error reading bhyve metadata for '%s': %s", vm_name, error)
        return None


def delete_bhyve_metadata(vm_name: str, logger) -> bool:
    """
    Delete bhyve VM metadata file.

    Called when a VM is deleted.

    Args:
        vm_name: Name of the VM
        logger: Logger instance

    Returns:
        True if deleted or didn't exist, False on error
    """
    try:
        metadata_file = Path(BHYVE_METADATA_DIR) / f"{vm_name}.json"
        if metadata_file.exists():
            metadata_file.unlink()
            logger.info(_("Deleted bhyve VM metadata for '%s'"), vm_name)
        return True

    except Exception as error:
        logger.error(_("Error deleting bhyve VM metadata for '%s': %s"), vm_name, error)
        return False
