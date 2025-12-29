"""
Debian package constants for VMM child host creation.

This module contains version-specific package lists and URLs for each supported
Debian version. Package versions may vary between releases.
"""

# Supported Debian versions for VMM child hosts
SUPPORTED_DEBIAN_VERSIONS = ["12"]

# Version-specific package lists for each supported Debian version
# These packages are installed via apt during the preseed late_command
# or via the firstboot script
REQUIRED_PACKAGES_BY_VERSION = {
    "12": [
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
REQUIRED_PACKAGES = REQUIRED_PACKAGES_BY_VERSION["12"]

# Debian ISO URLs - use netinst which is smaller and downloads packages
# Note: Debian 12 moved to archive after Debian 13 became "current"
DEBIAN_ISO_URLS = {
    "12": "https://cdimage.debian.org/cdimage/archive/12.9.0/amd64/iso-cd/debian-12.9.0-amd64-netinst.iso",
}

# Debian mirror URLs for package installation
DEBIAN_MIRROR_URLS = {
    "12": "https://deb.debian.org/debian",
}

# Debian codenames
DEBIAN_CODENAMES = {
    "12": "bookworm",
}

# Minimum packages to install during preseed (others installed at firstboot)
PRESEED_PACKAGES = [
    "openssh-server",
    "sudo",
    "python3",
    "python3-pip",
    "curl",
    "wget",
    "ca-certificates",
]
