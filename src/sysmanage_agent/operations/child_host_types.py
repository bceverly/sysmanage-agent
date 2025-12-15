"""
Type definitions for child host operations.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class LxdContainerConfig:
    """Configuration for creating an LXD container."""

    distribution: str
    container_name: str
    hostname: str
    username: str
    password_hash: str  # Pre-hashed password (bcrypt)
    server_url: str
    agent_install_commands: List[str]
    server_port: int = 8443
    use_https: bool = True


@dataclass
class VmmServerConfig:
    """Server connection configuration for VMM VM."""

    server_url: str
    server_port: int = 8443
    use_https: bool = True


@dataclass
class VmmResourceConfig:
    """Resource allocation configuration for VMM VM."""

    memory: str = "1G"
    disk_size: str = "20G"
    cpus: int = 1


@dataclass
class VmmVmConfig:  # pylint: disable=too-many-instance-attributes
    """Configuration for creating a VMM virtual machine on OpenBSD."""

    distribution: str
    vm_name: str
    hostname: str
    username: str
    password_hash: str  # Pre-hashed user password (bcrypt)
    agent_install_commands: List[str]
    iso_url: str = ""  # URL to download install ISO
    root_password_hash: str = (
        ""  # Pre-hashed root password (bcrypt), uses password_hash if empty
    )
    server_config: VmmServerConfig = field(default_factory=lambda: VmmServerConfig(""))
    resource_config: VmmResourceConfig = field(default_factory=VmmResourceConfig)

    # Convenience properties for backward compatibility
    @property
    def server_url(self) -> str:
        """Get server URL."""
        return self.server_config.server_url

    @property
    def server_port(self) -> int:
        """Get server port."""
        return self.server_config.server_port

    @property
    def use_https(self) -> bool:
        """Get use_https setting."""
        return self.server_config.use_https

    @property
    def memory(self) -> str:
        """Get memory allocation."""
        return self.resource_config.memory

    @property
    def disk_size(self) -> str:
        """Get disk size."""
        return self.resource_config.disk_size

    @property
    def cpus(self) -> int:
        """Get CPU count."""
        return self.resource_config.cpus
