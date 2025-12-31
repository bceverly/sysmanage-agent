"""
Ubuntu package constants for VMM child host creation.

This module contains version-specific package lists and URLs for each supported
Ubuntu Server version. Ubuntu uses a different installation system (Subiquity
with autoinstall) compared to Debian (debian-installer with preseed).

Key differences from Debian:
- Uses autoinstall YAML format instead of preseed
- Uses GRUB bootloader instead of ISOLINUX
- Uses netplan for network configuration instead of /etc/network/interfaces
- ISO is larger (~2.6GB live server vs ~650MB Debian netinst)
"""

import re
from typing import Optional

from src.i18n import _

# Supported Ubuntu versions for VMM child hosts
# Starting with 24.04 LTS (Noble Numbat) as it's the current LTS
SUPPORTED_UBUNTU_VERSIONS = ["24.04"]

# Version-specific package lists for each supported Ubuntu version
# These packages are installed via apt during autoinstall late-commands
# or via the firstboot script
REQUIRED_PACKAGES_BY_VERSION = {
    "24.04": [
        # Core Python
        "python3",
        "python3-pip",
        "python3-venv",
        # Required for sysmanage-agent
        "python3-websockets",
        "python3-yaml",
        "python3-aiohttp",
        "python3-cryptography",
        "python3-sqlalchemy",
        "python3-alembic",
        "python3-bcrypt",
        "python3-pydantic",
        # Additional dependencies
        "python3-cffi",
        "python3-greenlet",
        "python3-typing-extensions",
        "python3-mako",
        "python3-markupsafe",
        "python3-attr",
        "python3-multidict",
        "python3-yarl",
        "python3-frozenlist",
        "python3-aiosignal",
        "python3-idna",
        "python3-charset-normalizer",
        # System utilities
        "openssh-server",
        "sudo",
        "curl",
        "wget",
        "ca-certificates",
    ],
}

# Keep REQUIRED_PACKAGES for backwards compatibility (defaults to latest)
REQUIRED_PACKAGES = REQUIRED_PACKAGES_BY_VERSION["24.04"]

# Ubuntu Server ISO URLs
# Using the live-server ISO which includes Subiquity installer
# Note: These are larger than Debian netinst (~3.1GB vs ~650MB)
# Updated 2025-12-29: Current point release is 24.04.3
UBUNTU_ISO_URLS = {
    "24.04": "https://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso",
}

# Ubuntu mirror URLs for package installation
UBUNTU_MIRROR_URLS = {
    "24.04": "http://archive.ubuntu.com/ubuntu",
}

# Ubuntu codenames
UBUNTU_CODENAMES = {
    "24.04": "noble",
}

# Minimum packages to install during autoinstall
# Others are installed at firstboot to keep install time reasonable
AUTOINSTALL_PACKAGES = [
    "openssh-server",
    "sudo",
    "python3",
    "python3-pip",
    "curl",
    "wget",
    "ca-certificates",
]

# Network interface name on OpenBSD VMM
# Ubuntu with virtio uses enp0s2 (similar to Debian)
VMM_NETWORK_INTERFACE = "enp0s2"

# Kernel and initrd paths in Ubuntu Server ISO
# Different from Debian which uses /install.amd/
UBUNTU_ISO_KERNEL_PATH = "/casper/vmlinuz"
UBUNTU_ISO_INITRD_PATH = "/casper/initrd"

# GRUB configuration paths in Ubuntu ISO
UBUNTU_GRUB_CFG_PATH = "boot/grub/grub.cfg"
UBUNTU_LOOPBACK_CFG_PATH = "boot/grub/loopback.cfg"

# For legacy BIOS boot (if present)
UBUNTU_ISOLINUX_PATH = "isolinux/txt.cfg"


def extract_ubuntu_version(distribution: str, logger) -> Optional[str]:
    """
    Extract Ubuntu version from distribution string.

    Args:
        distribution: Distribution string (e.g., "Ubuntu 24.04", "ubuntu-24.04", "Noble")
        logger: Logger instance

    Returns:
        Version string (e.g., "24.04") or None if not found
    """
    # Map codenames to versions
    codename_map = {
        "noble": "24.04",
        "jammy": "22.04",
        "focal": "20.04",
    }

    dist_lower = distribution.lower()

    # Check for codenames first
    for codename, version in codename_map.items():
        if codename in dist_lower:
            if version in SUPPORTED_UBUNTU_VERSIONS:
                logger.info(_("Extracted Ubuntu version %s from codename"), version)
                return version

    # Try various patterns for version numbers
    patterns = [
        r"Ubuntu\s*(?:Server)?\s*(\d+\.\d+)",  # "Ubuntu 24.04" or "Ubuntu Server 24.04"
        r"ubuntu[_-]?(\d+\.\d+)",  # "ubuntu-24.04" or "ubuntu_24.04"
        r"(\d+\.\d+)",  # Just the version number
    ]

    for pattern in patterns:
        match = re.search(pattern, distribution, re.IGNORECASE)
        if match:
            version = match.group(1)
            if version in SUPPORTED_UBUNTU_VERSIONS:
                logger.info(_("Extracted Ubuntu version: %s"), version)
                return version

    logger.warning(_("Could not extract Ubuntu version from: %s"), distribution)
    return None
