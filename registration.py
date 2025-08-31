"""
Client registration module for SysManage Agent.
Handles initial registration and periodic re-registration with the server.

This module provides backward compatibility while delegating to the modular implementation.
"""

from client_registration import ClientRegistration as ModularClientRegistration


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

    # Override to use mockable methods for testing compatibility
    def get_basic_registration_info(self):
        """Get minimal system information for initial registration."""
        hostname = self.get_hostname()
        ipv4, ipv6 = self.get_ip_addresses()
        return self._create_basic_registration_dict(hostname, ipv4, ipv6)
