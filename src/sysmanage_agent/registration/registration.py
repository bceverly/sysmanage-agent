"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.

This module provides backward compatibility while delegating to the modular implementation.
"""

from src.sysmanage_agent.registration.client_registration import (
    ClientRegistration as ModularClientRegistration,
)


# For backward compatibility, we re-export the main class
class ClientRegistration(ModularClientRegistration):
    """
    Handles client registration with the SysManage server.

    This is a thin wrapper around the modular ClientRegistration implementation
    for backward compatibility with existing code that imports from this module.
    """

    # Expose methods that tests expect for backward compatibility
    def get_hostname(self) -> str:
        """Get the hostname, with optional override from config."""
        return self.network_utils.get_hostname()

    def get_ip_addresses(self):
        """Get both IPv4 and IPv6 addresses of the machine."""
        return self.network_utils.get_ip_addresses()

    # Use parent's get_basic_registration_info which includes all fields
    # (is_privileged, enabled_shells, script_execution_enabled, etc.)
