# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Privilege / sudoers detection helpers for the SysManage agent.

Extracted from ``agent_utils`` to keep that module small.  The names here
are re-exported from ``agent_utils`` for backwards compatibility, so
existing imports (and test patch targets such as
``agent_utils.is_running_privileged``) continue to resolve.
"""

import os
import subprocess  # nosec B404 # Required for sync shell execution
import sys
from typing import Optional

# Cache the privilege check.  ``is_running_privileged`` is called from
# every heartbeat / basic-info / data-collection cycle (see
# message_handler.create_basic_info_message), and the sudoers path
# inside the function spawns ``sudo -n systemctl is-active
# sysmanage-agent`` as a fallback whenever the sudoers file isn't
# directly readable — which is the default state (mode 0440, root-
# owned) when the agent runs as the unprivileged ``sysmanage-agent``
# user.  Without this cache we burn one fork+exec+pam-session per
# heartbeat (observed: multiple per second on a healthy agent), which
# floods auth.log + journalctl and steals CPU.  Privilege state
# genuinely cannot change while the process is running, so caching the
# first answer for the lifetime of the process is correct.  Use
# ``_reset_priv_cache_for_tests`` from unit tests that toggle
# os.geteuid / sudoers state mid-run.
_PRIVILEGED_CACHE: Optional[bool] = None


def _reset_priv_cache_for_tests() -> None:
    """Test-only hook to clear ``is_running_privileged``'s cached result."""
    global _PRIVILEGED_CACHE  # pylint: disable=global-statement
    _PRIVILEGED_CACHE = None


def is_running_privileged() -> bool:
    """
    Detect if the agent has the privileges needed for system management.

    For Unix systems, checks:
    1. If running as root (UID 0) - always privileged
    2. If sudoers file grants necessary permissions - privileged
    3. Otherwise - not privileged

    NOTE: ``True`` does NOT mean the process is running as root.  It can
    also mean the process is running as ``sysmanage-agent`` (uid != 0)
    with a sudoers fragment that permits passwordless ``apt``/``systemctl``/
    etc.  Code that shells out to root-only commands MUST still prefix
    those commands with ``sudo`` (or use a helper such as
    ``linux_update_applicators._sudo_prefix()``) — do NOT use this flag
    as a "skip sudo when True" signal.  The flag exists for the server's
    benefit (the heartbeat reports it so the server knows whether the
    agent can fulfil privileged operations); it is not a euid check.

    Result is cached for the lifetime of the process — privileges
    cannot change without a restart and the sudoers-file probe is too
    expensive to repeat on every heartbeat.

    Returns:
        bool: True if the agent can execute privileged ops via root
              OR sudoers, False otherwise.
    """
    global _PRIVILEGED_CACHE  # pylint: disable=global-statement
    if _PRIVILEGED_CACHE is not None:
        return _PRIVILEGED_CACHE
    _PRIVILEGED_CACHE = _compute_running_privileged()
    return _PRIVILEGED_CACHE


def _compute_running_privileged() -> bool:
    """Uncached worker for ``is_running_privileged``.

    Split out so the cache wrapper above stays a 3-line lookup; this
    function is exactly the previous body of ``is_running_privileged``.
    """
    try:
        if sys.platform == "win32":
            # Windows - check if running as administrator
            import ctypes  # pylint: disable=import-outside-toplevel

            return ctypes.windll.shell32.IsUserAnAdmin() != 0

        # Unix-like systems - check if running as root (UID 0)
        if os.geteuid() == 0:
            return True

        # Check if running as sysmanage-agent user with sudoers privileges
        try:
            import pwd  # pylint: disable=import-outside-toplevel,import-error

            current_user = pwd.getpwuid(os.geteuid()).pw_name

            # If running as sysmanage-agent, check sudoers file
            if current_user == "sysmanage-agent":
                return _check_sudoers_privileges(current_user)

        except (
            Exception
        ):  # nosec B110 # Intentionally ignore - fall through to return False
            pass

        # Not root and no sudoers privileges
        return False

    except Exception:
        # If we can't determine privilege level, assume non-privileged for security
        return False


def _check_sudoers_privileges(username: str) -> bool:
    """
    Check if user has sufficient sudo privileges by parsing sudoers file.

    Args:
        username: Username to check

    Returns:
        bool: True if user has necessary sudo privileges, False otherwise
    """
    sudoers_path = f"/etc/sudoers.d/{username}"

    try:
        # Try to read sudoers file
        # Note: os.path.exists() may return False due to directory permissions
        # even if the file exists, so we always try to read and fall back to testing
        content = _read_sudoers_file(sudoers_path)
        if content is None:
            # Can't read sudoers file (doesn't exist or permission denied)
            # Try to infer from running actual sudo commands
            return _test_sudo_access()

        # Parse sudoers content for NOPASSWD privileges
        granted_commands = _parse_sudoers_content(content, username)

        # Consider privileged if we have systemctl and package management
        has_systemctl = "systemctl" in granted_commands
        has_package_mgmt = any(
            cmd in granted_commands for cmd in ["apt", "yum", "dnf", "zypper"]
        )

        return has_systemctl and has_package_mgmt

    except Exception:
        # If we can't parse sudoers, assume no privileges
        return False


def _read_sudoers_file(sudoers_path: str) -> Optional[str]:
    """
    Read sudoers file content.

    Args:
        sudoers_path: Path to sudoers file

    Returns:
        File content as str, or None if unable to read
    """
    try:
        with open(sudoers_path, "r", encoding="utf-8") as sudoers_file:
            return sudoers_file.read()
    except PermissionError:
        return None


def _parse_sudoers_content(content: str, username: str) -> set:
    """
    Parse sudoers content to extract granted commands.

    Args:
        content: Sudoers file content
        username: Username to check for

    Returns:
        set: Set of granted command names
    """
    required_commands = [
        "systemctl",  # Service management
        "apt",  # Package management
    ]

    granted_commands = set()
    for line in content.split("\n"):
        line_commands = _parse_sudoers_line(line.strip(), username, required_commands)
        granted_commands.update(line_commands)

    return granted_commands


def _parse_sudoers_line(line: str, username: str, required_commands: list) -> set:
    """Parse a single sudoers line for NOPASSWD grants matching the given username.

    Args:
        line: A single stripped line from the sudoers file
        username: Username to match against
        required_commands: List of command names to look for

    Returns:
        Set of matched command names found in this line
    """
    if not line or line.startswith("#"):
        return set()

    if "NOPASSWD:" not in line or username not in line:
        return set()

    parts = line.split("NOPASSWD:")
    if len(parts) <= 1:
        return set()

    command_part = parts[1].strip()
    return {cmd for cmd in required_commands if cmd in command_part}


def _test_sudo_access() -> bool:
    """
    Test if current user has sudo access by trying a safe command.

    Returns:
        bool: True if user has sudo access, False otherwise
    """
    try:
        # Try running a safe sudo command with -n (non-interactive)
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "-n", "systemctl", "is-active", "sysmanage-agent"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        # If command succeeded (regardless of exit code), we have sudo access
        # Exit code 1 means we could run sudo, just the service check failed
        # Exit code 1 or 3 from systemctl is fine, it means sudo worked
        # Only if sudo itself fails (e.g., password required) we don't have access
        return result.returncode not in [
            255
        ]  # 255 typically means sudo authentication failed

    except Exception:
        return False
