"""
KVM/libvirt type definitions for child host operations.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class KvmVmConfig:  # pylint: disable=too-many-instance-attributes
    """Configuration for creating a KVM virtual machine."""

    # Required fields
    distribution: str
    vm_name: str
    hostname: str
    username: str
    password_hash: str  # Pre-hashed password for security
    server_url: str
    agent_install_commands: List[str]

    # Optional fields with defaults
    memory: str = "2G"  # Memory allocation (e.g., "2G", "4096M")
    disk_size: str = "20G"  # Disk size (e.g., "20G", "50G")
    cpus: int = 2  # Number of vCPUs
    server_port: int = 8443
    use_https: bool = True
    cloud_image_url: str = ""  # URL to cloud image
    iso_url: str = ""  # URL to installation ISO (fallback)
    use_cloud_init: bool = True
    network: str = "default"  # libvirt network name
    disk_format: str = "qcow2"  # Disk image format
    auto_approve_token: Optional[str] = None  # Token for auto-approval
    child_host_id: Optional[str] = None  # ID for status updates

    # Computed paths (set during creation)
    disk_path: str = field(default="", init=False)
    cloud_init_iso_path: str = field(default="", init=False)
    cloud_image_path: str = field(default="", init=False)

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.vm_name:
            raise ValueError("VM name is required")
        if not self.hostname:
            raise ValueError("Hostname is required")
        if not self.username:
            raise ValueError("Username is required")
        if not self.password_hash:
            raise ValueError("Password hash is required")
        if not self.distribution:
            raise ValueError("Distribution is required")

        # Validate memory format
        if not self._parse_memory_mb(self.memory):
            raise ValueError(f"Invalid memory format: {self.memory}")

        # Validate disk size format
        if not self._parse_disk_gb(self.disk_size):
            raise ValueError(f"Invalid disk size format: {self.disk_size}")

        # Validate CPUs
        if self.cpus < 1:
            raise ValueError("CPUs must be at least 1")
        if self.cpus > 64:
            raise ValueError("CPUs cannot exceed 64")

    def _parse_memory_mb(self, memory: str) -> int:
        """Parse memory string to MB. Returns 0 if invalid."""
        try:
            memory = memory.upper().strip()
            if memory.endswith("G"):
                return int(float(memory[:-1]) * 1024)
            if memory.endswith("M"):
                return int(memory[:-1])
            if memory.endswith("GB"):
                return int(float(memory[:-2]) * 1024)
            if memory.endswith("MB"):
                return int(memory[:-2])
            # Assume MB if no suffix
            return int(memory)
        except (ValueError, TypeError):
            return 0

    def _parse_disk_gb(self, disk_size: str) -> int:
        """Parse disk size string to GB. Returns 0 if invalid."""
        try:
            disk_size = disk_size.upper().strip()
            if disk_size.endswith("G"):
                return int(disk_size[:-1])
            if disk_size.endswith("T"):
                return int(float(disk_size[:-1]) * 1024)
            if disk_size.endswith("GB"):
                return int(disk_size[:-2])
            if disk_size.endswith("TB"):
                return int(float(disk_size[:-2]) * 1024)
            # Assume GB if no suffix
            return int(disk_size)
        except (ValueError, TypeError):
            return 0

    def get_memory_mb(self) -> int:
        """Get memory in MB."""
        return self._parse_memory_mb(self.memory)

    def get_memory_gb(self) -> float:
        """Get memory in GB."""
        return self._parse_memory_mb(self.memory) / 1024.0

    def get_disk_gb(self) -> int:
        """Get disk size in GB."""
        return self._parse_disk_gb(self.disk_size)
