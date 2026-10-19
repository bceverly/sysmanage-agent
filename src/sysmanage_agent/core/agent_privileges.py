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
# directly readable -- which is the default state (mode 0440, root-
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
    ``linux_update_applicators._sudo_prefix()``) -- do NOT use this flag
    as a "skip sudo when True" signal.  The flag exists for the server's
    benefit (the heartbeat reports it so the server knows whether the
    agent can fulfill privileged operations); it is not a euid check.

    Result is cached for the lifetime of the process -- privileges
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
            # The normal case for a packaged agent: sudo requires
            # /etc/sudoers.d to be root-only, so the agent can never read its
            # own fragment.  Ask sudo instead -- ``sudo -n -l`` lists the
            # caller's own grants without a password.  (Falling straight
            # through to ``sudo -n true`` reported every packaged agent as
            # unprivileged: ``true`` is not on the allowlist, so it is refused,
            # and the UI then disabled reboot, roles, accounts... 2026-10-15.)
            listing = _sudo_listing()
            if listing is None:
                return _test_sudo_access()
            return _grants_suffice(_parse_sudo_listing(listing))

        # Parse sudoers content for NOPASSWD privileges
        return _grants_suffice(_parse_sudoers_content(content, username))

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
    required_commands = list(_REQUIRED_COMMANDS)

    granted_commands = set()
    for line in content.split("\n"):
        line_commands = _parse_sudoers_line(line.strip(), username, required_commands)
        granted_commands.update(line_commands)

    return granted_commands


# The sudoers tag that marks a password-free grant.
_NOPASSWD = "NOPASSWD:"


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

    if _NOPASSWD not in line or username not in line:
        return set()

    parts = line.split(_NOPASSWD)
    if len(parts) <= 1:
        return set()

    command_part = parts[1].strip()
    return {cmd for cmd in required_commands if cmd in command_part}


# Service management plus ANY package manager (an RPM host's allowlist names
# dnf / yum / zypper, never apt -- the old list only looked for apt).
_PACKAGE_MANAGERS = ("apt", "yum", "dnf", "zypper")
_REQUIRED_COMMANDS = ("systemctl",) + _PACKAGE_MANAGERS
_FULL_SUDO = "ALL"


def _grants_suffice(granted_commands: set) -> bool:
    """Privileged = service control and a package manager (or full sudo)."""
    if _FULL_SUDO in granted_commands:
        return True
    return "systemctl" in granted_commands and any(
        cmd in granted_commands for cmd in _PACKAGE_MANAGERS
    )


def _sudo_listing() -> Optional[str]:
    """``sudo -n -l``: the caller's own NOPASSWD grants, or None."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "-n", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:  # pylint: disable=broad-except
        return None
    return result.stdout if result.returncode == 0 else None


def _parse_sudo_listing(listing: str) -> set:
    """The command names granted NOPASSWD in a ``sudo -l`` listing, e.g.
    ``    (ALL) NOPASSWD: /usr/bin/apt, /usr/bin/systemctl restart *``."""
    granted: set = set()
    for line in listing.splitlines():
        if _NOPASSWD not in line:
            continue
        for spec in line.split(_NOPASSWD, 1)[1].split(","):
            command = spec.strip().split(" ", 1)[0]
            if command == _FULL_SUDO:
                granted.add(_FULL_SUDO)
                continue
            name = command.rsplit("/", 1)[-1]
            if name in _REQUIRED_COMMANDS:
                granted.add(name)
    return granted


def _test_sudo_access() -> bool:
    """
    Test whether this user actually has non-interactive sudo.

    Returns:
        bool: True only when sudo demonstrably worked.

    WHY ``true`` AND NOT A REAL COMMAND
    -----------------------------------
    This used to run ``sudo -n systemctl is-active sysmanage-agent`` and accept
    ANY exit code except 255.  That conflates two unrelated outcomes:

      * sudo was DENIED -- ``sudo -n`` exits 1 with "a password is required";
      * sudo worked and the COMMAND returned non-zero -- ``systemctl is-active``
        exits 3 for an inactive unit, 4 for an unknown one.

    Both land in "not 255", so a host where sudo is refused reported itself as
    privileged.  That flag drives whether the server believes a host can patch,
    restart services or reboot for a re-provision, so a false positive is worse
    than a false negative: work gets dispatched that cannot possibly succeed.

    ``true`` cannot fail on its own.  Its exit status is therefore purely a
    statement about sudo, which is the only thing being asked.
    """
    try:
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0

    except Exception:
        return False


def escalate_service_cmd(cmd: list) -> list:
    """Prefix ``sudo -n`` to a service-manager argv when not root.

    A packaged agent runs unprivileged; ``systemctl enable/start`` then asked
    polkit for interactive authentication and every antivirus plan's service
    step failed (beast, 2026-10-16).  The sudoers allowlists grant
    ``/usr/bin/systemctl {start,stop,restart,enable,disable} *``.  As root
    (Alpine's OpenRC unit) and on Windows (sc.exe) nothing is added.
    """
    if not cmd or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return list(cmd)
    if cmd[0].replace("\\", "/").rsplit("/", 1)[-1].lower() in ("sc", "sc.exe"):
        return list(cmd)
    return ["sudo", "-n"] + list(cmd)
