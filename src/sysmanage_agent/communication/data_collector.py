"""
Data collection and periodic update management for the SysManage agent.

This module handles all data collection operations and periodic updates
sent to the SysManage server, including system information, packages,
certificates, roles, and other monitoring data.
"""

import asyncio
import logging
import platform
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.operations.firewall_collector import FirewallCollector
from src.sysmanage_agent.collection.graylog_collector import GraylogCollector


class DataCollector:
    """Handles data collection and periodic updates for the SysManage agent."""

    def __init__(self, agent_instance):
        """
        Initialize the DataCollector.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.firewall_collector = FirewallCollector(self.logger)
        self.graylog_collector = GraylogCollector(self.logger)

    async def send_initial_data_updates(
        self,
    ):  # pylint: disable=too-many-branches,too-many-statements
        """Send initial data updates after WebSocket connection."""
        try:
            self.logger.info(_("Sending initial OS version data..."))

            # Send OS version data
            os_info = self.agent.registration.get_os_version_info()
            system_info = self.agent.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]
            os_message = self.agent.create_message("os_version_update", os_info)
            await self.agent.send_message(os_message)
            self.logger.debug("AGENT_DEBUG: OS version message sent")

            # Allow queue processing tasks to run
            await asyncio.sleep(0)

            self.logger.info(_("Sending initial hardware data..."))

            # Send hardware data
            hardware_info = self.agent.registration.get_hardware_info()
            system_info = self.agent.registration.get_system_info()
            hardware_info["hostname"] = system_info["hostname"]
            hardware_message = self.agent.create_message(
                "hardware_update", hardware_info
            )
            await self.agent.send_message(hardware_message)
            self.logger.debug("AGENT_DEBUG: Hardware message sent")

            # Allow time for the large hardware message to be sent before sending more data
            await asyncio.sleep(2)

            self.logger.info(_("Sending initial user access data..."))

            # Send user access data
            user_access_info = self.agent.registration.get_user_access_info()
            system_info = self.agent.registration.get_system_info()
            user_access_info["hostname"] = system_info["hostname"]
            user_access_message = self.agent.create_message(
                "user_access_update", user_access_info
            )
            await self.agent.send_message(user_access_message)
            self.logger.debug("AGENT_DEBUG: User access message sent")

            # Allow time for the large user access message to be sent before sending more data
            await asyncio.sleep(2)

            self.logger.info(_("Sending initial software inventory data..."))

            # Send software inventory data
            software_info = self.agent.registration.get_software_inventory_info()
            system_info = self.agent.registration.get_system_info()
            software_info["hostname"] = system_info["hostname"]
            software_message = self.agent.create_message(
                "software_inventory_update", software_info
            )
            await self.agent.send_message(software_message)
            self.logger.debug("AGENT_DEBUG: Software inventory message sent")

            self.logger.info(_("Sending initial update check..."))

            # Send initial update check
            try:
                update_result = await self.agent.check_updates()
                if update_result.get("total_updates", 0) > 0:
                    self.logger.info(
                        "Found %d available updates during initial check",
                        update_result["total_updates"],
                    )
                else:
                    self.logger.info("No updates found during initial check")
            except Exception as error:
                self.logger.error("Failed to perform initial update check: %s", error)

            # Allow time for update check to complete before collecting certificates
            await asyncio.sleep(2)

            self.logger.info(_("Collecting initial certificate data..."))

            # Collect and send certificate data
            try:
                certificate_result = await self.collect_certificates()
                if certificate_result.get("success", False):
                    cert_count = certificate_result.get("certificate_count", 0)
                    if cert_count > 0:
                        self.logger.info(
                            "Found and sent %d certificates during initial collection",
                            cert_count,
                        )
                    else:
                        self.logger.info(
                            "No certificates found during initial collection"
                        )
                else:
                    error_msg = certificate_result.get("error", "Unknown error")
                    self.logger.warning("Certificate collection failed: %s", error_msg)
            except Exception as error:
                self.logger.error(
                    "Failed to perform initial certificate collection: %s", error
                )

            # Collect and send role data
            try:
                role_result = await self.collect_roles()
                if role_result.get("success", False):
                    role_count = role_result.get("role_count", 0)
                    if role_count > 0:
                        self.logger.info(
                            "Found and sent %d server roles during initial collection",
                            role_count,
                        )
                    else:
                        self.logger.info(
                            "No server roles found during initial collection"
                        )
                else:
                    error_msg = role_result.get("error", "Unknown error")
                    self.logger.warning("Role collection failed: %s", error_msg)
            except Exception as error:
                self.logger.error(
                    "Failed to perform initial role collection: %s", error
                )

            # Send third-party repository data
            try:
                self.logger.info(_("Collecting initial third-party repository data..."))
                await self._send_third_party_repository_update()
            except Exception as error:
                self.logger.error(
                    "Failed to send initial third-party repository data: %s", error
                )

            # Send firewall status data
            try:
                self.logger.info(_("Collecting initial firewall status data..."))
                await self._send_firewall_status_update()
            except Exception as error:
                self.logger.error(
                    "Failed to send initial firewall status data: %s", error
                )

            # Send Graylog status data
            try:
                self.logger.info(_("Collecting initial Graylog status data..."))
                await self._send_graylog_status_update()
            except Exception as error:
                self.logger.error(
                    "Failed to send initial Graylog status data: %s", error
                )

            # Send child hosts (WSL/VM/container) data
            try:
                self.logger.info(_("Collecting initial child hosts data..."))
                await self._send_child_hosts_update()
            except Exception as error:
                self.logger.error("Failed to send initial child hosts data: %s", error)

            self.logger.info(_("Initial data updates sent successfully"))
        except Exception as error:
            self.logger.error(_("Failed to send initial data updates: %s"), error)

    async def update_os_version(self) -> Dict[str, Any]:
        """Gather and send updated OS version information to the server."""
        try:
            # Get fresh OS version info
            os_info = self.agent.registration.get_os_version_info()
            # Add hostname to OS data for server processing
            system_info = self.agent.registration.get_system_info()
            os_info["hostname"] = system_info["hostname"]

            # Create OS version message
            os_message = self.agent.create_message("os_version_update", os_info)

            # Send OS version update to server
            await self.agent.send_message(os_message)

            return {"success": True, "result": "OS version information sent"}
        except Exception as error:
            self.logger.error("Failed to update OS version: %s", error)
            return {"success": False, "error": str(error)}

    async def update_hardware(self) -> Dict[str, Any]:
        """Gather and send updated hardware information to the server."""
        try:
            # Get fresh hardware info
            hardware_info = self.agent.registration.get_hardware_info()
            # Add hostname to hardware data for server processing
            system_info = self.agent.registration.get_system_info()
            hardware_info["hostname"] = system_info["hostname"]

            # Create hardware message
            hardware_message = self.agent.create_message(
                "hardware_update", hardware_info
            )

            # Send hardware update to server
            await self.agent.send_message(hardware_message)

            return {"success": True, "result": "Hardware information sent"}
        except Exception as error:
            self.logger.error("Failed to update hardware: %s", error)
            return {"success": False, "error": str(error)}

    async def update_user_access(self) -> Dict[str, Any]:
        """Gather and send updated user access information to the server."""
        try:
            # Get fresh user access info
            user_access_info = self.agent.registration.get_user_access_info()
            # Add hostname to user access data for server processing
            system_info = self.agent.registration.get_system_info()
            user_access_info["hostname"] = system_info["hostname"]

            # Create user access message
            user_access_message = self.agent.create_message(
                "user_access_update", user_access_info
            )

            # Send user access update to server
            await self.agent.send_message(user_access_message)

            return {"success": True, "result": "User access information sent"}
        except Exception as error:
            self.logger.error("Failed to update user access: %s", error)
            return {"success": False, "error": str(error)}

    async def _send_software_inventory_update(self):
        """Send software inventory update."""
        self.logger.debug("AGENT_DEBUG: Collecting software inventory data")
        software_info = self.agent.registration.get_software_inventory_info()
        software_info["hostname"] = self.agent.registration.get_system_info()[
            "hostname"
        ]

        # Add host_id if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            software_info["host_id"] = str(host_approval.host_id)

        software_message = self.agent.create_message(
            "software_inventory_update", software_info
        )
        self.logger.debug(
            "AGENT_DEBUG: Sending periodic software inventory message: %s",
            software_message["message_id"],
        )
        success = await self.agent.send_message(software_message)
        if success:
            self.logger.debug(
                "AGENT_DEBUG: Periodic software inventory sent successfully"
            )
        else:
            self.logger.warning("Failed to send periodic software inventory data")

    async def _send_user_access_update(self):
        """Send user access update."""
        self.logger.debug("AGENT_DEBUG: Collecting user access data")
        user_info = self.agent.registration.get_user_access_info()
        user_info["hostname"] = self.agent.registration.get_system_info()["hostname"]

        # Add host_id if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            user_info["host_id"] = str(host_approval.host_id)

        user_message = self.agent.create_message("user_access_update", user_info)
        self.logger.debug(
            "AGENT_DEBUG: Sending periodic user access message: %s",
            user_message["message_id"],
        )
        success = await self.agent.send_message(user_message)
        if success:
            self.logger.debug(
                "AGENT_DEBUG: Periodic user access data sent successfully"
            )
        else:
            self.logger.warning("Failed to send periodic user access data")

    async def _send_hardware_update(self):
        """Send hardware update."""
        self.logger.debug("AGENT_DEBUG: Collecting hardware data")
        hardware_info = self.agent.registration.get_hardware_info()
        hardware_info["hostname"] = self.agent.registration.get_system_info()[
            "hostname"
        ]

        # Add host_id if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            hardware_info["host_id"] = str(host_approval.host_id)

        hardware_message = self.agent.create_message("hardware_update", hardware_info)
        self.logger.debug(
            "AGENT_DEBUG: Sending periodic hardware message: %s",
            hardware_message["message_id"],
        )
        success = await self.agent.send_message(hardware_message)
        if success:
            self.logger.debug("AGENT_DEBUG: Periodic hardware data sent successfully")
        else:
            self.logger.warning("Failed to send periodic hardware data")

    async def _send_certificate_update(self):
        """Send certificate update."""
        self.logger.debug("AGENT_DEBUG: Collecting certificate data")
        certificate_result = await self.collect_certificates()
        if certificate_result.get("success", False):
            cert_count = certificate_result.get("certificate_count", 0)
            if cert_count > 0:
                self.logger.debug(
                    "AGENT_DEBUG: Periodic certificate collection found and sent %d certificates",
                    cert_count,
                )
            else:
                self.logger.debug(
                    "AGENT_DEBUG: No certificates found during periodic collection"
                )
        else:
            error_msg = certificate_result.get("error", "Unknown error")
            self.logger.warning("Periodic certificate collection failed: %s", error_msg)

    async def _send_role_update(self):
        """Send role update."""
        self.logger.debug("AGENT_DEBUG: Collecting role data")
        role_result = await self.collect_roles()
        if role_result.get("success", False):
            role_count = role_result.get("role_count", 0)
            if role_count > 0:
                self.logger.debug(
                    "AGENT_DEBUG: Periodic role collection found and sent %d server roles",
                    role_count,
                )
            else:
                self.logger.debug(
                    "AGENT_DEBUG: No server roles found during periodic collection"
                )
        else:
            error_msg = role_result.get("error", "Unknown error")
            self.logger.warning("Periodic role collection failed: %s", error_msg)

    async def _send_os_version_update(self):
        """Send OS version update."""
        self.logger.debug("AGENT_DEBUG: About to collect OS version info")
        os_info = self.agent.registration.get_os_version_info()
        self.logger.debug("AGENT_DEBUG: OS info collected: %s", os_info)

        os_message = {
            "message_type": "os_version_update",
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": os_info,
        }

        self.logger.debug(
            "AGENT_DEBUG: Sending periodic OS version message: %s",
            os_message["message_id"],
        )
        success = await self.agent.send_message(os_message)

        if success:
            self.logger.debug("AGENT_DEBUG: Periodic OS version data sent successfully")
        else:
            self.logger.warning("Failed to send periodic OS version data")

    async def _send_reboot_status_update(self):
        """Send reboot status update."""
        self.logger.debug("AGENT_DEBUG: Checking reboot status")
        result = await self.agent.update_manager.check_reboot_status()
        self.logger.debug(
            "AGENT_DEBUG: Reboot required: %s", result.get("reboot_required", False)
        )
        self.logger.debug("AGENT_DEBUG: Periodic reboot status sent successfully")

    async def _send_third_party_repository_update(self):
        """Send third-party repository update."""
        self.logger.debug("AGENT_DEBUG: Collecting third-party repository data")

        # Call system_ops to list repositories
        repo_result = await self.agent.system_ops.list_third_party_repositories({})

        if not repo_result.get("success", False):
            error_msg = repo_result.get("error", "Unknown error")
            self.logger.warning(
                "Failed to collect third-party repositories: %s", error_msg
            )
            return

        repositories = repo_result.get("repositories", [])

        # Create message data
        repo_info = {
            "repositories": repositories,
            "count": len(repositories),
            "hostname": self.agent.registration.get_system_info()["hostname"],
        }

        # Add host_id if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            repo_info["host_id"] = str(host_approval.host_id)

        # Create and send message
        repo_message = self.agent.create_message(
            "third_party_repository_update", repo_info
        )
        self.logger.debug(
            "AGENT_DEBUG: Sending third-party repository message: %s",
            repo_message["message_id"],
        )
        success = await self.agent.send_message(repo_message)

        if success:
            self.logger.debug(
                "AGENT_DEBUG: Third-party repository data sent successfully (%d repositories)",
                len(repositories),
            )
        else:
            self.logger.warning("Failed to send third-party repository data")

    async def _send_antivirus_status_update(self):
        """Send antivirus status update."""
        self.logger.debug("AGENT_DEBUG: Collecting antivirus status data")

        antivirus_info = self.agent.antivirus_collector.collect_antivirus_status()

        # Add host_id if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            antivirus_message_data = {
                "host_id": str(host_approval.host_id),
                "software_name": antivirus_info["software_name"],
                "install_path": antivirus_info["install_path"],
                "version": antivirus_info["version"],
                "enabled": antivirus_info["enabled"],
            }

            antivirus_message = self.agent.create_message(
                "antivirus_status_update", antivirus_message_data
            )
            self.logger.debug(
                "AGENT_DEBUG: Sending antivirus status message: %s",
                antivirus_message["message_id"],
            )
            success = await self.agent.send_message(antivirus_message)
            if success:
                self.logger.debug(
                    "AGENT_DEBUG: Antivirus status data sent successfully"
                )
            else:
                self.logger.warning("Failed to send antivirus status data")
        else:
            self.logger.warning("Cannot send antivirus status data: no host approval")

    async def _send_firewall_status_update(self):
        """Send firewall status update."""
        self.logger.debug("AGENT_DEBUG: Collecting firewall status data")

        firewall_info = self.firewall_collector.collect_firewall_status()

        # Add host_id and hostname if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            firewall_message_data = {
                "hostname": self.agent.registration.get_system_info()["hostname"],
                "host_id": str(host_approval.host_id),
                "firewall_name": firewall_info["firewall_name"],
                "enabled": firewall_info["enabled"],
                "tcp_open_ports": firewall_info["tcp_open_ports"],
                "udp_open_ports": firewall_info["udp_open_ports"],
                "ipv4_ports": firewall_info.get("ipv4_ports"),
                "ipv6_ports": firewall_info.get("ipv6_ports"),
            }

            firewall_message = self.agent.create_message(
                "firewall_status_update", firewall_message_data
            )
            self.logger.debug(
                "AGENT_DEBUG: Sending firewall status message: %s",
                firewall_message["message_id"],
            )
            success = await self.agent.send_message(firewall_message)
            if success:
                self.logger.debug("AGENT_DEBUG: Firewall status data sent successfully")
            else:
                self.logger.warning("Failed to send firewall status data")
        else:
            self.logger.warning("Cannot send firewall status data: no host approval")

    async def _send_child_hosts_update(self):
        """Send child hosts (WSL/VM/container) status update."""
        # Only collect child hosts on Windows (WSL) for now
        if platform.system().lower() != "windows":
            return

        self.logger.debug("AGENT_DEBUG: Collecting child hosts data")

        try:
            # Use the child_host_ops to list child hosts
            if hasattr(self.agent, "child_host_ops"):
                result = await self.agent.child_host_ops.list_child_hosts({})

                if result.get("success", False):
                    child_hosts = result.get("child_hosts", [])

                    # Create message data
                    child_hosts_info = {
                        "success": True,
                        "child_hosts": child_hosts,
                        "count": len(child_hosts),
                        "hostname": self.agent.registration.get_system_info()[
                            "hostname"
                        ],
                    }

                    # Add host_id if available
                    host_approval = (
                        self.agent.registration_manager.get_host_approval_from_db()
                    )
                    if host_approval:
                        child_hosts_info["host_id"] = str(host_approval.host_id)

                    # Create and send message
                    child_hosts_message = self.agent.create_message(
                        "child_host_list_update", child_hosts_info
                    )
                    self.logger.debug(
                        "AGENT_DEBUG: Sending child hosts message: %s",
                        child_hosts_message["message_id"],
                    )
                    success = await self.agent.send_message(child_hosts_message)

                    if success:
                        self.logger.debug(
                            "AGENT_DEBUG: Child hosts data sent successfully (%d hosts)",
                            len(child_hosts),
                        )
                    else:
                        self.logger.warning("Failed to send child hosts data")
                else:
                    self.logger.debug(
                        "AGENT_DEBUG: Child hosts collection returned no success: %s",
                        result.get("error", "Unknown error"),
                    )
        except Exception as error:
            self.logger.error("Error collecting/sending child hosts data: %s", error)

    async def _send_graylog_status_update(self):
        """Send Graylog attachment status update."""
        self.logger.debug("AGENT_DEBUG: Collecting Graylog attachment status data")

        graylog_info = self.graylog_collector.collect_graylog_status()

        # Add host_id and hostname if available
        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if host_approval:
            graylog_message_data = {
                "hostname": self.agent.registration.get_system_info()["hostname"],
                "host_id": str(host_approval.host_id),
                "is_attached": graylog_info["is_attached"],
                "target_hostname": graylog_info["target_hostname"],
                "target_ip": graylog_info["target_ip"],
                "mechanism": graylog_info["mechanism"],
                "port": graylog_info["port"],
            }

            graylog_message = self.agent.create_message(
                "graylog_status_update", graylog_message_data
            )
            self.logger.debug(
                "AGENT_DEBUG: Sending Graylog status message: %s",
                graylog_message["message_id"],
            )
            success = await self.agent.send_message(graylog_message)
            if success:
                self.logger.debug("AGENT_DEBUG: Graylog status data sent successfully")
            else:
                self.logger.warning("Failed to send Graylog status data")
        else:
            self.logger.warning("Cannot send Graylog status data: no host approval")

    async def _collect_and_send_periodic_data(self):
        """Collect and send all periodic data updates."""
        if not (self.agent.running and self.agent.connected):
            return

        self.logger.debug("AGENT_DEBUG: Starting periodic data collection")

        # Send software inventory update
        try:
            await self._send_software_inventory_update()
        except Exception as error:
            self.logger.error("Error collecting/sending software inventory: %s", error)

        # Send user access update
        try:
            await self._send_user_access_update()
        except Exception as error:
            self.logger.error("Error collecting/sending user access data: %s", error)

        # Send hardware update
        try:
            await self._send_hardware_update()
        except Exception as error:
            self.logger.error("Error collecting/sending hardware data: %s", error)

        # Send certificate update
        try:
            await self._send_certificate_update()
        except Exception as error:
            self.logger.error("Error collecting/sending certificate data: %s", error)

        # Send role update
        try:
            await self._send_role_update()
        except Exception as error:
            self.logger.error("Error collecting/sending role data: %s", error)

        # Send OS version update
        try:
            await self._send_os_version_update()
        except Exception as error:
            self.logger.error("Error collecting/sending OS version data: %s", error)

        # Send reboot status update
        try:
            await self._send_reboot_status_update()
        except Exception as error:
            self.logger.error("Error collecting/sending reboot status: %s", error)

        # Send third-party repository update
        try:
            await self._send_third_party_repository_update()
        except Exception as error:
            self.logger.error(
                "Error collecting/sending third-party repository data: %s", error
            )

        # Send antivirus status update
        try:
            await self._send_antivirus_status_update()
        except Exception as error:
            self.logger.error("Error collecting/sending antivirus status: %s", error)

        # Send firewall status update
        try:
            await self._send_firewall_status_update()
        except Exception as error:
            self.logger.error("Error collecting/sending firewall status: %s", error)

        # Send Graylog status update
        try:
            await self._send_graylog_status_update()
        except Exception as error:
            self.logger.error("Error collecting/sending Graylog status: %s", error)

        # Send child hosts (WSL/VM/container) status update
        try:
            await self._send_child_hosts_update()
        except Exception as error:
            self.logger.error("Error collecting/sending child hosts data: %s", error)

    async def data_collector(self):
        """Handle periodic data collection and sending."""
        self.logger.debug("Data collector started")

        # Send periodic data updates every 5 minutes
        data_collection_interval = 300  # 5 minutes

        while self.agent.running:
            try:
                await asyncio.sleep(data_collection_interval)
                await self._collect_and_send_periodic_data()
                self.logger.debug("AGENT_DEBUG: Periodic data collection completed")
            except asyncio.CancelledError:
                # Graceful shutdown - re-raise to propagate cancellation
                self.logger.debug("Data collector cancelled")
                raise
            except Exception as error:
                self.logger.error("Data collector error: %s", error)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def package_collector(self):
        """Handle periodic package collection."""
        await self.agent.package_collection_scheduler.run_package_collection_loop()

    async def update_checker(self):
        """Handle periodic update checking."""
        await self.agent.update_checker_util.run_update_checker_loop()

    async def collect_available_packages(self) -> Dict[str, Any]:
        """Collect and send available packages from all package managers using pagination."""
        try:
            # Trigger package collection
            success = (
                await self.agent.package_collection_scheduler.perform_package_collection()
            )
            if not success:
                return {"success": False, "error": "Package collection failed"}

            # Get packages for transmission
            packages = (
                self.agent.package_collection_scheduler.package_collector.get_packages_for_transmission()
            )

            # Get current OS information from registration system
            system_info = self.agent.registration.get_system_info()
            os_info = system_info.get("os_info", {})

            # Determine OS name and version
            # Try Linux-specific fields first, then fall back to platform fields for FreeBSD/other systems
            os_name = os_info.get("distribution") or system_info.get(
                "platform", "Unknown"
            )
            os_version = os_info.get("distribution_version") or system_info.get(
                "platform_release", "Unknown"
            )

            # Calculate total packages
            total_packages = sum(
                len(pkg_list) for pkg_list in packages["package_managers"].values()
            )

            # Send packages using pagination to avoid large message issues
            success = await self._send_available_packages_paginated(
                packages["package_managers"], os_name, os_version, total_packages
            )

            if success:
                return {
                    "success": True,
                    "message": f"Successfully sent {total_packages} packages using pagination",
                    "total_packages": total_packages,
                }
            return {"success": False, "error": "Failed to send paginated packages"}

        except Exception as error:
            self.logger.error(_("Error collecting available packages: %s"), error)
            return {"success": False, "error": str(error)}

    async def _send_available_packages_paginated(
        self,
        package_managers: Dict[str, list],
        os_name: str,
        os_version: str,
        total_packages: int,
    ) -> bool:
        """Send available packages using pagination to avoid large message issues."""
        batch_id = str(uuid.uuid4())
        batch_size = 1000  # Send packages in batches of 1000

        try:
            # Send batch start message
            batch_start_message = self.agent.create_message(
                "available_packages_batch_start",
                {
                    "batch_id": batch_id,
                    "os_name": os_name,
                    "os_version": os_version,
                    "package_managers": list(package_managers.keys()),
                    "total_packages": total_packages,
                },
            )
            await self.agent.send_message(batch_start_message)
            self.logger.info(
                "Started packages batch %s with %d total packages",
                batch_id,
                total_packages,
            )

            # Send packages in batches for each package manager
            for manager_name, packages_list in package_managers.items():
                if not packages_list:
                    continue

                # Split packages into batches
                for i in range(0, len(packages_list), batch_size):
                    batch_packages = packages_list[i : i + batch_size]

                    batch_message = self.agent.create_message(
                        "available_packages_batch",
                        {
                            "batch_id": batch_id,
                            "package_managers": {manager_name: batch_packages},
                        },
                    )
                    await self.agent.send_message(batch_message)
                    self.logger.info(
                        "Sent batch with %d packages from %s (batch %s, packages %d-%d)",
                        len(batch_packages),
                        manager_name,
                        batch_id,
                        i + 1,
                        i + len(batch_packages),
                    )

            # Send batch end message
            batch_end_message = self.agent.create_message(
                "available_packages_batch_end",
                {
                    "batch_id": batch_id,
                    "total_packages": total_packages,
                },
            )
            await self.agent.send_message(batch_end_message)
            self.logger.info("Completed packages batch %s", batch_id)

            return True

        except Exception as error:
            self.logger.error(
                "Error sending paginated packages for batch %s: %s", batch_id, error
            )
            return False

    async def collect_certificates(self) -> Dict[str, Any]:
        """Collect SSL certificates from the system and send to server."""
        try:
            # Certificate collection can work in unprivileged mode for most system certificates
            # Only some certificates in restricted directories may require privileged access
            if not is_running_privileged():
                self.logger.info(
                    _(
                        "Running certificate collection in unprivileged mode - some certificates may not be accessible"
                    )
                )

            self.logger.info(_("Collecting SSL certificates from system"))

            # Collect certificate data
            certificates = self.agent.certificate_collector.collect_certificates()

            if not certificates:
                self.logger.info(_("No certificates found on system"))
                return {
                    "success": True,
                    "result": "No certificates found",
                    "certificate_count": 0,
                }

            self.logger.info(_("Found %d certificates"), len(certificates))

            # Send certificate data to server
            system_info = self.agent.registration.get_system_info()
            certificate_message = self.agent.create_message(
                "host_certificates_update",
                {
                    "hostname": system_info.get("fqdn", socket.gethostname()),
                    "certificates": certificates,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                },
            )

            await self.agent.send_message(certificate_message)

            return {
                "success": True,
                "result": f"Collected and sent {len(certificates)} certificates",
                "certificate_count": len(certificates),
            }

        except Exception as error:
            self.logger.error(_("Error collecting certificates: %s"), error)
            return {"success": False, "error": str(error)}

    async def collect_roles(self) -> Dict[str, Any]:
        """Collect server roles from the system and send to server."""
        try:
            self.logger.info(_("Collecting server roles"))

            # Collect role data
            roles = self.agent.role_detector.detect_roles()

            if not roles:
                self.logger.info(_("No server roles detected on system"))
                return {
                    "success": True,
                    "result": "No server roles detected",
                    "role_count": 0,
                }

            self.logger.info(_("Found %d server roles"), len(roles))

            # Get hostname for server validation
            system_info = self.agent.registration.get_system_info()
            hostname = system_info["hostname"]

            # Create role data message
            role_message = self.agent.create_message(
                "role_data",
                {
                    "hostname": hostname,
                    "roles": roles,
                    "role_count": len(roles),
                    "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )

            # Send role data to server
            await self.agent.send_message(role_message)

            return {
                "success": True,
                "result": f"Collected and sent {len(roles)} server roles",
                "role_count": len(roles),
            }

        except Exception as error:
            self.logger.error(_("Error collecting roles: %s"), error)
            return {"success": False, "error": str(error)}
