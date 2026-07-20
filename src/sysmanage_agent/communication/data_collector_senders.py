# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Periodic telemetry senders for the SysManage agent DataCollector.

Split out of ``data_collector.py`` to keep each module within the 1000-line
limit.  ``DataCollectorSendersMixin`` is mixed into ``DataCollector`` and relies
on attributes that ``DataCollector`` sets up (``agent``, ``logger``, and the
``*_collector`` helpers) plus its ``collect_certificates`` / ``collect_roles``
methods.
"""

import asyncio
import uuid
from datetime import datetime, timezone

from src.i18n import _

_UNKNOWN_ERROR = "Unknown error"


class DataCollectorSendersMixin:
    """Per-telemetry "send update" methods used by periodic + initial collection."""

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
            self.logger.warning(_("Failed to send periodic software inventory data"))

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
            self.logger.warning(_("Failed to send periodic user access data"))

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
            self.logger.warning(_("Failed to send periodic hardware data"))

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
            error_msg = certificate_result.get("error", _UNKNOWN_ERROR)
            self.logger.warning(
                _("Periodic certificate collection failed: %s"), error_msg
            )

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
            error_msg = role_result.get("error", _UNKNOWN_ERROR)
            self.logger.warning(_("Periodic role collection failed: %s"), error_msg)

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
            self.logger.warning(_("Failed to send periodic OS version data"))

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
            error_msg = repo_result.get("error", _UNKNOWN_ERROR)
            self.logger.warning(
                _("Failed to collect third-party repositories: %s"), error_msg
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
            self.logger.warning(_("Failed to send third-party repository data"))

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
                self.logger.warning(_("Failed to send antivirus status data"))
        else:
            self.logger.warning(
                _("Cannot send antivirus status data: no host approval")
            )

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
                self.logger.warning(_("Failed to send firewall status data"))
        else:
            self.logger.warning(_("Cannot send firewall status data: no host approval"))

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
                self.logger.warning(_("Failed to send Graylog status data"))
        else:
            self.logger.warning(_("Cannot send Graylog status data: no host approval"))

    async def _send_process_update(self):
        """Collect running processes and send a snapshot to the server."""
        self.logger.debug("AGENT_DEBUG: Collecting running process data")

        host_approval = self.agent.registration_manager.get_host_approval_from_db()
        if not host_approval:
            self.logger.warning(_("Cannot send process data: no host approval"))
            return

        # Collection samples CPU over ~0.5s, so run it off the event loop.
        processes, truncated = await asyncio.to_thread(
            self.process_collector.collect_processes
        )

        process_message = self.agent.create_message(
            "process_status_update",
            {
                "hostname": self.agent.registration.get_system_info()["hostname"],
                "host_id": str(host_approval.host_id),
                "processes": processes,
                "process_count": len(processes),
                "truncated": truncated,
                "collected_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        self.logger.debug(
            "AGENT_DEBUG: Sending process status message: %s",
            process_message["message_id"],
        )
        success = await self.agent.send_message(process_message)
        if success:
            self.logger.debug(
                "AGENT_DEBUG: Process data sent successfully (%d processes)",
                len(processes),
            )
        else:
            self.logger.warning(_("Failed to send process status data"))
