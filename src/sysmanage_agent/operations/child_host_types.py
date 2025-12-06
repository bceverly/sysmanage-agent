"""
Type definitions for child host operations.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class LxdContainerConfig:
    """Configuration for creating an LXD container."""

    distribution: str
    container_name: str
    hostname: str
    username: str
    password: str
    server_url: str
    agent_install_commands: List[str]
    server_port: int = 8443
    use_https: bool = True
