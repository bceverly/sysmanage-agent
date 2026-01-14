"""
Unified agent configuration generator for child host creation.

This module provides a single function to generate sysmanage-agent configuration
files for all supported operating systems. OS-specific differences (like available
shells) are handled within this module.

Supported OS types:
- ubuntu: Ubuntu Linux (bash, dash, sh)
- debian: Debian Linux (bash, dash, sh)
- alpine: Alpine Linux (sh, ash, bash)
- freebsd: FreeBSD (sh, csh, tcsh)
- openbsd: OpenBSD (sh, ksh)
- netbsd: NetBSD (sh, ksh)
- macos: macOS (sh, bash, zsh)
- windows: Windows (powershell, cmd)
"""

from typing import Optional, List


# Shell configurations by OS type
OS_SHELLS = {
    "ubuntu": ["sh", "bash", "dash"],
    "debian": ["sh", "bash", "dash"],
    "alpine": ["sh", "ash", "bash"],
    "freebsd": ["sh", "csh", "tcsh"],
    "openbsd": ["sh", "ksh"],
    "netbsd": ["sh", "ksh"],
    "macos": ["sh", "bash", "zsh"],
    "windows": ["powershell", "cmd"],
    # Generic Linux fallback
    "linux": ["sh", "bash"],
}

# Default database paths by OS type
OS_DATABASE_PATHS = {
    "windows": "C:\\ProgramData\\SysManage\\agent.db",
    # All Unix-like systems use the same path
    "default": "/var/lib/sysmanage-agent/agent.db",
}

# Default log paths by OS type
OS_LOG_PATHS = {
    "windows": "C:\\ProgramData\\SysManage\\logs\\agent.log",
    # All Unix-like systems use the same path
    "default": "/var/log/sysmanage-agent/agent.log",
}


def get_shells_for_os(os_type: str) -> List[str]:
    """
    Get the list of allowed shells for a given OS type.

    Args:
        os_type: Operating system type (ubuntu, debian, alpine, freebsd, etc.)

    Returns:
        List of shell names available on that OS
    """
    return OS_SHELLS.get(os_type.lower(), OS_SHELLS["linux"])


def get_database_path_for_os(os_type: str) -> str:
    """
    Get the default database path for a given OS type.

    Args:
        os_type: Operating system type

    Returns:
        Database file path appropriate for the OS
    """
    if os_type.lower() == "windows":
        return OS_DATABASE_PATHS["windows"]
    return OS_DATABASE_PATHS["default"]


def get_log_path_for_os(os_type: str) -> str:
    """
    Get the default log path for a given OS type.

    Args:
        os_type: Operating system type

    Returns:
        Log file path appropriate for the OS
    """
    if os_type.lower() == "windows":
        return OS_LOG_PATHS["windows"]
    return OS_LOG_PATHS["default"]


def generate_agent_config(
    hostname: str,
    port: int,
    use_https: bool,
    os_type: str = "linux",
    auto_approve_token: Optional[str] = None,
    verify_ssl: bool = False,
) -> str:
    """
    Generate sysmanage-agent configuration file content.

    This is the unified configuration generator used by all child host creation
    modules (bhyve, KVM, VMM, LXD, WSL, etc.).

    Args:
        hostname: SysManage server hostname
        port: SysManage server port
        use_https: Whether to use HTTPS for server connection
        os_type: Operating system type for shell configuration
                 (ubuntu, debian, alpine, freebsd, openbsd, netbsd, macos, windows)
        auto_approve_token: Optional UUID token for automatic host approval
        verify_ssl: Whether to verify SSL certificates (default: False for VMs)

    Returns:
        Configuration file content as string
    """
    # Get OS-specific settings
    shells = get_shells_for_os(os_type)
    db_path = get_database_path_for_os(os_type)
    log_path = get_log_path_for_os(os_type)

    # Format shells as YAML list
    shells_yaml = "\n".join(f'    - "{shell}"' for shell in shells)

    # Build auto_approve section if token provided
    auto_approve_section = ""
    if auto_approve_token:
        auto_approve_section = f"""
# Auto-approval token for automatic host approval
auto_approve:
  token: "{auto_approve_token}"
"""

    # Determine OS name for comment
    os_name = os_type.capitalize()
    if os_type.lower() in ("ubuntu", "debian", "alpine"):
        os_name = f"{os_name} Linux"
    elif os_type.lower() in ("freebsd", "openbsd", "netbsd"):
        os_name = os_type.upper() if os_type.lower() == "freebsd" else os_name

    return f"""# sysmanage-agent configuration
# Auto-generated for {os_name}

# Server connection settings
server:
  hostname: "{hostname}"
  port: {port}
  use_https: {str(use_https).lower()}

# Security settings
security:
  verify_ssl: {str(verify_ssl).lower()}
{auto_approve_section}
# Client identification settings
client:
  registration_retry_interval: 30
  max_registration_retries: 10
  update_check_interval: 3600

# Internationalization settings
i18n:
  language: "en"

# Logging configuration
logging:
  level: "INFO|WARNING|ERROR|CRITICAL"
  file: "{log_path}"
  format: "[%(asctime)s UTC] %(name)s - %(levelname)s - %(message)s"

# WebSocket connection settings
websocket:
  auto_reconnect: true
  reconnect_interval: 5
  ping_interval: 60

# Database configuration
database:
  path: "{db_path}"
  auto_migrate: true

# Script execution configuration
script_execution:
  enabled: true
  timeout: 300
  max_concurrent: 3
  allowed_shells:
{shells_yaml}
  user_restrictions:
    allow_user_switching: false
    allowed_users: []
  security:
    restricted_paths:
      - "/etc/passwd"
      - "/etc/shadow"
      - "/etc/ssh/"
      - "/home/*/.ssh/"
      - "/root/.ssh/"
      - "*.key"
      - "*.pem"
    audit_logging: true
    require_approval: false
"""


def gen_agent_config_shell_cmds(
    hostname: str,
    port: int,
    use_https: bool,
    os_type: str = "linux",
    auto_approve_token: Optional[str] = None,
    verify_ssl: bool = False,
    config_path: str = "/etc/sysmanage-agent/sysmanage-agent.yaml",
) -> str:
    """
    Generate shell echo commands to write sysmanage-agent configuration.

    This is useful for serial console automation (e.g., Alpine VMM install)
    where heredocs don't work reliably.

    Args:
        hostname: SysManage server hostname
        port: SysManage server port
        use_https: Whether to use HTTPS for server connection
        os_type: Operating system type for shell configuration
        auto_approve_token: Optional UUID token for automatic host approval
        verify_ssl: Whether to verify SSL certificates (default: False for VMs)
        config_path: Path to write the config file

    Returns:
        Shell script section that creates the config file using echo commands
    """
    # Get the YAML config content
    config_content = generate_agent_config(
        hostname=hostname,
        port=port,
        use_https=use_https,
        os_type=os_type,
        auto_approve_token=auto_approve_token,
        verify_ssl=verify_ssl,
    )

    # Convert each line to an echo command
    lines = config_content.split("\n")
    echo_commands = []

    # First line creates the file, rest append
    first = True
    for line in lines:
        # Escape double quotes and backslashes for shell
        escaped_line = line.replace("\\", "\\\\").replace('"', '\\"')
        if first:
            echo_commands.append(f'echo "{escaped_line}" > {config_path}')
            first = False
        else:
            echo_commands.append(f'echo "{escaped_line}" >> {config_path}')

    return "\n".join(echo_commands)
