"""
Hardware collection module for SysManage Agent.
Handles platform-specific hardware information gathering.
"""

import json
import logging
import platform
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.hardware_collector_bsd import HardwareCollectorBSD
from src.sysmanage_agent.collection.hardware_collector_linux import (
    HardwareCollectorLinux,
)
from src.sysmanage_agent.collection.hardware_collector_macos import (
    HardwareCollectorMacOS,
)
from src.sysmanage_agent.collection.hardware_collector_windows import (
    HardwareCollectorWindows,
)

logger = logging.getLogger(__name__)


class HardwareCollector:
    """Collects hardware information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.system = platform.system()
        self.collector = None

        # Initialize platform-specific collector
        if self.system == "Darwin":  # macOS
            self.collector = HardwareCollectorMacOS()
        elif self.system == "Linux":
            self.collector = HardwareCollectorLinux()
        elif self.system == "Windows":
            self.collector = HardwareCollectorWindows()
        elif self.system in ("OpenBSD", "FreeBSD", "NetBSD"):
            self.collector = HardwareCollectorBSD()
        else:
            logger.warning(_("Unsupported platform: %s"), self.system)

    def __getattr__(self, name):
        """Delegate attribute access to the platform-specific collector."""
        if self.collector is not None:
            return getattr(self.collector, name)
        raise AttributeError(
            f"'{type(self).__name__}' object has no attribute '{name}'"
        )

    def get_hardware_info(self) -> Dict[str, Any]:
        """Get comprehensive hardware information formatted for database storage."""

        if self.collector is None:
            return {
                "hardware_details": json.dumps(
                    {"error": _("Unsupported platform: %s") % self.system}
                ),
                "storage_details": json.dumps([]),
                "network_details": json.dumps([]),
            }

        try:
            # Get information from platform-specific collector
            cpu_info = self.collector.get_cpu_info()
            memory_info = self.collector.get_memory_info()
            storage_info = self.collector.get_storage_info()
            network_info = self.collector.get_network_info()

            # Format data for database storage
            hardware_data = {
                # Individual CPU fields for easy querying
                "cpu_vendor": cpu_info.get("vendor", ""),
                "cpu_model": cpu_info.get("model", ""),
                "cpu_cores": (
                    cpu_info.get("cores", 0) if cpu_info.get("cores") else None
                ),
                "cpu_threads": (
                    cpu_info.get("threads", 0) if cpu_info.get("threads") else None
                ),
                "cpu_frequency_mhz": (
                    cpu_info.get("frequency_mhz", 0)
                    if cpu_info.get("frequency_mhz")
                    else None
                ),
                # Individual memory fields for easy querying
                "memory_total_bytes": (
                    memory_info.get("total_bytes", 0)
                    if memory_info.get("total_bytes")
                    else None
                ),
                "memory_available_bytes": (
                    memory_info.get("available_bytes", 0)
                    if memory_info.get("available_bytes")
                    else None
                ),
                # Detailed JSON for complex data
                "hardware_details": json.dumps(
                    {
                        "cpu": cpu_info,
                        "memory": memory_info,
                    }
                ),
                "storage_details": json.dumps(storage_info),
                "network_details": json.dumps(network_info),
            }

            return hardware_data

        except Exception as error:
            logger.error(_("Failed to collect hardware information: %s"), str(error))
            return {
                "hardware_details": json.dumps({"error": str(error)}),
                "storage_details": json.dumps([]),
                "network_details": json.dumps([]),
            }
