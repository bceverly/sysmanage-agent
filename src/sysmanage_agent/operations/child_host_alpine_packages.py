"""
Alpine Linux package constants for VMM site tarball builder.

This module contains version-specific package lists for each supported
Alpine Linux version. Package versions vary between releases.
"""

# Supported Alpine Linux versions for VMM child hosts
SUPPORTED_ALPINE_VERSIONS = ["3.19", "3.20", "3.21"]

# Version-specific package lists for each supported Alpine version
# Alpine packages are simpler - no version numbers needed in most cases
# as apk handles dependencies automatically
REQUIRED_PACKAGES_BY_VERSION = {
    "3.19": [
        # Core Python
        "python3",
        "py3-pip",
        # Required for sysmanage-agent
        "py3-websockets",
        "py3-yaml",
        "py3-aiohttp",
        "py3-cryptography",
        "py3-sqlalchemy",
        "py3-alembic",
        "py3-bcrypt",
        "py3-pydantic",
        # Additional dependencies that may be needed
        "py3-cffi",
        "py3-greenlet",
        "py3-typing-extensions",
        "py3-mako",
        "py3-markupsafe",
        "py3-attrs",
        "py3-multidict",
        "py3-yarl",
        "py3-frozenlist",
        "py3-aiosignal",
        "py3-idna",
        "py3-charset-normalizer",
        "py3-async-timeout",
        # OpenRC for service management
        "openrc",
    ],
    "3.20": [
        # Core Python
        "python3",
        "py3-pip",
        # Required for sysmanage-agent
        "py3-websockets",
        "py3-yaml",
        "py3-aiohttp",
        "py3-cryptography",
        "py3-sqlalchemy",
        "py3-alembic",
        "py3-bcrypt",
        "py3-pydantic",
        # Additional dependencies that may be needed
        "py3-cffi",
        "py3-greenlet",
        "py3-typing-extensions",
        "py3-mako",
        "py3-markupsafe",
        "py3-attrs",
        "py3-multidict",
        "py3-yarl",
        "py3-frozenlist",
        "py3-aiosignal",
        "py3-idna",
        "py3-charset-normalizer",
        "py3-async-timeout",
        # OpenRC for service management
        "openrc",
    ],
    "3.21": [
        # Core Python
        "python3",
        "py3-pip",
        # Required for sysmanage-agent
        "py3-websockets",
        "py3-yaml",
        "py3-aiohttp",
        "py3-cryptography",
        "py3-sqlalchemy",
        "py3-alembic",
        "py3-bcrypt",
        "py3-pydantic",
        # Additional dependencies that may be needed
        "py3-cffi",
        "py3-greenlet",
        "py3-typing-extensions",
        "py3-mako",
        "py3-markupsafe",
        "py3-attrs",
        "py3-multidict",
        "py3-yarl",
        "py3-frozenlist",
        "py3-aiosignal",
        "py3-idna",
        "py3-charset-normalizer",
        "py3-async-timeout",
        # OpenRC for service management
        "openrc",
    ],
}

# Keep REQUIRED_PACKAGES for backwards compatibility (defaults to latest)
REQUIRED_PACKAGES = REQUIRED_PACKAGES_BY_VERSION["3.21"]

# Alpine ISO URLs - use alpine-virt which includes virtio drivers
ALPINE_ISO_URLS = {
    "3.19": "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-virt-3.19.7-x86_64.iso",
    "3.20": "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-virt-3.20.6-x86_64.iso",
    "3.21": "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-virt-3.21.3-x86_64.iso",
}

# Alpine repository URLs
ALPINE_REPO_URLS = {
    "3.19": "https://dl-cdn.alpinelinux.org/alpine/v3.19",
    "3.20": "https://dl-cdn.alpinelinux.org/alpine/v3.20",
    "3.21": "https://dl-cdn.alpinelinux.org/alpine/v3.21",
}
