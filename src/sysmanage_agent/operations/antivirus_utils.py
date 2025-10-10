"""
Antivirus Utilities Module for SysManage Agent

Common utility functions used across antivirus operations modules.
"""

import os


def get_brew_user():
    """Get the user that owns the Homebrew installation."""
    import pwd  # pylint: disable=import-outside-toplevel,import-error

    # Check both possible Homebrew locations
    brew_dirs = ["/opt/homebrew", "/usr/local/Homebrew"]
    for brew_dir in brew_dirs:
        if os.path.exists(brew_dir):
            try:
                stat_info = os.stat(brew_dir)
                return pwd.getpwuid(stat_info.st_uid).pw_name
            except (OSError, KeyError):
                continue

    # Fallback to SUDO_USER if available
    return os.environ.get("SUDO_USER")
