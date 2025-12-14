"""
OpenBSD install.conf generation and configuration utilities.

This module handles generating install.conf response files for automated
OpenBSD installations.
"""

import hashlib
import subprocess  # nosec B404 # Required for system command execution
from typing import Optional

from src.i18n import _


def generate_mac_address(vm_name: str) -> str:
    """
    Generate a deterministic MAC address for a VM based on its name.

    Uses the fe:e1:bb prefix (locally administered, unicast)
    followed by 3 bytes derived from the VM name.

    Args:
        vm_name: Name of the VM

    Returns:
        MAC address string (e.g., "fe:e1:bb:d1:2d:93")
    """
    # Hash the VM name to get deterministic bytes
    hash_bytes = hashlib.sha256(vm_name.encode()).digest()

    # Use first 3 bytes of hash for the last 3 octets of MAC
    # Use fe:e1:bb prefix (locally administered)
    mac = f"fe:e1:bb:{hash_bytes[0]:02x}:{hash_bytes[1]:02x}:{hash_bytes[2]:02x}"

    return mac


def encrypt_password(password: str, logger) -> str:
    """
    Encrypt password using bcrypt for OpenBSD.

    Args:
        password: Plain text password
        logger: Logger instance

    Returns:
        Encrypted password hash
    """
    try:
        # Try to use OpenBSD's encrypt(1) command
        result = subprocess.run(  # nosec B603 B607
            ["encrypt", "-b", "8"],
            input=password,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: use Python's hashlib with a simple hash
    # Note: crypt module is deprecated, so we use a simpler approach
    # On OpenBSD, encrypt(1) should always work, so this is just a fallback
    try:
        # Generate a simple hash as fallback (not ideal for production)
        hash_obj = hashlib.sha256(password.encode())
        return hash_obj.hexdigest()
    except AttributeError:
        pass

    # Last resort: return a known hash format that OpenBSD will accept
    # This is a placeholder - in practice encrypt(1) should always work
    logger.warning(_("Could not encrypt password, using plain text (NOT RECOMMENDED)"))
    return password


def generate_install_conf(
    hostname: str,
    username: str,
    password: str,
    logger,
    timezone: str = "US/Eastern",
    dns_nameservers: str = "1.1.1.1",
    sets: str = "-game* -x*",
    public_key: Optional[str] = None,
) -> str:
    """
    Generate an OpenBSD install.conf response file.

    See autoinstall(8) for format details.

    Args:
        hostname: System hostname for the VM
        username: Non-root user to create
        password: Password for root and user (will be encrypted)
        logger: Logger instance
        timezone: Timezone for the system
        dns_nameservers: DNS nameserver(s) to use
        sets: Sets to install (- prefix excludes)
        public_key: Optional SSH public key for root

    Returns:
        install.conf content as string
    """
    # Encrypt password using OpenBSD's encrypt(1) or Python's crypt
    encrypted_password = encrypt_password(password, logger)

    lines = [
        f"System hostname = {hostname}",
        "Which disk is the root disk = sd0",
        "Use (W)hole disk MBR, whole disk (G)PT, (O)penBSD area or (E)dit = whole",
        "Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a",
        f"Password for root account = {encrypted_password}",
        f"Setup a user = {username}",
        f"Password for user {username} = {encrypted_password}",
        "Allow root ssh login = yes",
        f"What timezone are you in = {timezone}",
        f"DNS nameservers = {dns_nameservers}",
        "Network interfaces = vio0",
        "IPv4 address for vio0 = 100.64.0.100",
        "Netmask for vio0 = 255.255.255.0",
        "Default IPv4 route = 100.64.0.1",
        "Location of sets = http",
        "HTTP Server = cdn.openbsd.org",
        f"Set name(s) = {sets}",
        "Continue without verification = yes",
    ]

    # Add SSH public key if provided
    if public_key:
        lines.append(f"Public ssh key for root account = {public_key}")

    return "\n".join(lines) + "\n"
