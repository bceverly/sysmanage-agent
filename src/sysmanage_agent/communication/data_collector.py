# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Data collection and periodic update management for the SysManage agent.

This module handles all data collection operations and periodic updates
sent to the SysManage server, including system information, packages,
certificates, roles, and other monitoring data.
"""

import asyncio
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict

from src.database import run_ledger
from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.communication import send_on_change
from src.sysmanage_agent.core import schedule_jitter
from src.sysmanage_agent.operations.firewall_collector import FirewallCollector
from src.sysmanage_agent.collection.graylog_collector import GraylogCollector
from src.sysmanage_agent.collection.process_collection import ProcessCollector
from src.sysmanage_agent.collection.host_metrics_collection import (
    HostMetricsCollector,
)
from src.sysmanage_agent.communication.child_host_collector import ChildHostCollector
from src.sysmanage_agent.communication.data_collector_catalog import (
    DataCollectorCatalogMixin,
)
from src.sysmanage_agent.communication.data_collector_senders import (
    _UNKNOWN_ERROR,
    DataCollectorSendersMixin,
)


class DataCollector(DataCollectorCatalogMixin, DataCollectorSendersMixin):
    """Handles data collection and periodic updates for the SysManage agent."""

    # How long an identical catalog is considered "already delivered".  Short
    # enough that a server which genuinely needs the catalog again gets it
    # quickly, long enough that a re-request loop cannot cost gigabytes.
    CATALOG_RESEND_COOLDOWN_SECONDS = 3600

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
        self.process_collector = ProcessCollector(self.logger)
        self.host_metrics_collector = HostMetricsCollector(self.logger)
        self.child_host_collector = ChildHostCollector(agent_instance)
        # Resend guard for the available-packages catalog.  See
        # _catalog_resend_is_pointless() for why this exists; kept in memory on
        # purpose, because the storm it defends against happens WITHIN one agent
        # process (reconnects re-create tasks, not the process), and a fresh
        # process must always send once.
        self._catalog_fingerprint = None
        self._catalog_sent_at = None

    async def send_initial_data_updates(
        self,
    ):  # pylint: disable=too-many-branches,too-many-statements
        """Send initial data updates after WebSocket connection."""
        try:
            await self._send_initial_core_data()
            await self._send_initial_update_check()
            await self._send_initial_supplementary_data()
            self.logger.info("Initial data updates sent successfully")
        except Exception as error:
            self.logger.error(_("Failed to send initial data updates: %s"), error)

    async def _send_initial_core_data(self):
        """Send initial OS version, hardware, user access, and software data."""
        self.logger.info("Sending initial OS version data...")

        # Send OS version data
        os_info = self.agent.registration.get_os_version_info()
        system_info = self.agent.registration.get_system_info()
        os_info["hostname"] = system_info["hostname"]
        os_message = self.agent.create_message("os_version_update", os_info)
        await self.agent.send_message(os_message)
        self.logger.debug("AGENT_DEBUG: OS version message sent")

        # Send FIPS compliance-mode posture (Phase 14.4)
        fips_info = self.agent.registration.get_fips_mode_info()
        fips_message = self.agent.create_message("fips_compliance_update", fips_info)
        await self.agent.send_message(fips_message)
        self.logger.debug("AGENT_DEBUG: FIPS compliance message sent")

        # Allow queue processing tasks to run
        await asyncio.sleep(0)

        self.logger.info("Sending initial hardware data...")

        # Send hardware data
        hardware_info = self.agent.registration.get_hardware_info()
        system_info = self.agent.registration.get_system_info()
        hardware_info["hostname"] = system_info["hostname"]
        hardware_message = self.agent.create_message("hardware_update", hardware_info)
        await self.agent.send_message(hardware_message)
        self.logger.debug("AGENT_DEBUG: Hardware message sent")

        # Allow time for the large hardware message to be sent before sending more data
        await asyncio.sleep(2)

        self.logger.info("Sending initial user access data...")

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

        self.logger.info("Sending initial software inventory data...")

        # Send software inventory data
        software_info = self.agent.registration.get_software_inventory_info()
        system_info = self.agent.registration.get_system_info()
        software_info["hostname"] = system_info["hostname"]
        software_message = self.agent.create_message(
            "software_inventory_update", software_info
        )
        await self.agent.send_message(software_message)
        self.logger.debug("AGENT_DEBUG: Software inventory message sent")

    async def _send_initial_update_check(self):
        """Send initial update check and collect certificates and roles."""
        await self._initial_update_check()
        # Allow time for update check to complete before collecting certificates
        await asyncio.sleep(2)
        await self._initial_certificates()
        await self._initial_roles()

    async def _initial_update_check(self):
        self.logger.info("Sending initial update check...")
        try:
            # A package-manager refresh is expensive: on a reconnect run it only
            # if it is due (or the server asked), not because we connected
            # (Phase 22.1).
            interval = self.agent.config.get_update_check_interval()
            if not (
                send_on_change.is_forced()
                or run_ledger.is_due(run_ledger.UPDATE_CHECK, interval)
            ):
                self.logger.info("Update check ran recently; not repeating it")
                update_result = {}
            else:
                update_result = await self.agent.check_updates()
            if update_result.get("total_updates", 0) > 0:
                self.logger.info(
                    "Found %d available updates during initial check",
                    update_result["total_updates"],
                )
            else:
                self.logger.info("No updates found during initial check")
        except Exception as error:
            self.logger.error(_("Failed to perform initial update check: %s"), error)

    async def _initial_certificates(self):
        self.logger.info("Collecting initial certificate data...")
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
                    self.logger.info("No certificates found during initial collection")
            else:
                error_msg = certificate_result.get("error", _UNKNOWN_ERROR)
                self.logger.warning(_("Certificate collection failed: %s"), error_msg)
        except Exception as error:
            self.logger.error(
                _("Failed to perform initial certificate collection: %s"), error
            )

    async def _initial_roles(self):
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
                    self.logger.info("No server roles found during initial collection")
            else:
                error_msg = role_result.get("error", _UNKNOWN_ERROR)
                self.logger.warning(_("Role collection failed: %s"), error_msg)
        except Exception as error:
            self.logger.error(_("Failed to perform initial role collection: %s"), error)

    async def _send_initial_supplementary_data(self):
        """Send initial third-party repos, firewall, Graylog, and child host data."""
        try:
            self.logger.info("Collecting initial third-party repository data...")
            await self._send_third_party_repository_update()
        except Exception as error:
            self.logger.error(
                _("Failed to send initial third-party repository data: %s"), error
            )

        try:
            self.logger.info("Collecting initial firewall status data...")
            await self._send_firewall_status_update()
        except Exception as error:
            self.logger.error(
                _("Failed to send initial firewall status data: %s"), error
            )

        try:
            self.logger.info("Collecting initial Graylog status data...")
            await self._send_graylog_status_update()
        except Exception as error:
            self.logger.error(
                _("Failed to send initial Graylog status data: %s"), error
            )

        try:
            self.logger.info("Collecting initial process data...")
            await self._send_process_update()
        except Exception as error:
            self.logger.error(_("Failed to send initial process data: %s"), error)

        try:
            self.logger.info("Collecting initial child hosts data...")
            await self.child_host_collector.send_child_hosts_update()
        except Exception as error:
            self.logger.error(_("Failed to send initial child hosts data: %s"), error)

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
            self.logger.error(_("Failed to update OS version: %s"), error)
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
            await self.send_requested_hardware_health()  # its health too
            return {"success": True, "result": "Hardware information sent"}
        except Exception as error:
            self.logger.error(_("Failed to update hardware: %s"), error)
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
            self.logger.error(_("Failed to update user access: %s"), error)
            return {"success": False, "error": str(error)}

    async def collect_processes(self) -> Dict[str, Any]:
        """On-demand process collection (server 'refresh' command)."""
        try:
            await self._send_process_update()
            return {"success": True, "result": "Process information sent"}
        except Exception as error:
            self.logger.error(_("Error collecting processes: %s"), error)
            return {"success": False, "error": str(error)}

    async def kill_process(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Terminate a process on this host, then re-send a fresh snapshot."""
        pid = parameters.get("pid")
        if pid is None:
            return {"success": False, "error": _("Missing required parameter: pid")}
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return {"success": False, "error": _("Invalid pid: %s") % pid}

        result = await asyncio.to_thread(
            self.process_collector.kill_process,
            pid,
            force=bool(parameters.get("force", False)),
            expected_name=parameters.get("expected_name"),
        )

        # Refresh the server's view regardless of outcome so the UI reflects
        # reality (the process may have died, spawned children, etc.).
        try:
            await self._send_process_update()
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.warning(_("Failed to refresh processes after kill: %s"), error)

        return result

    async def _collect_and_send_periodic_data(self):
        """Collect and send all periodic data updates."""
        if not (self.agent.running and self.agent.connected):
            return

        self.logger.debug("AGENT_DEBUG: Starting periodic data collection")

        # Each snapshot is independent: one failing must not stop the rest.
        steps = (
            (
                self._send_software_inventory_update,
                _("Error collecting/sending software inventory: %s"),
            ),
            (
                self._send_user_access_update,
                _("Error collecting/sending user access data: %s"),
            ),
            (
                self._send_hardware_update,
                _("Error collecting/sending hardware data: %s"),
            ),
            (
                self._send_certificate_update,
                _("Error collecting/sending certificate data: %s"),
            ),
            (self._send_role_update, _("Error collecting/sending role data: %s")),
            (
                self._send_os_version_update,
                _("Error collecting/sending OS version data: %s"),
            ),
            (
                self._send_reboot_status_update,
                _("Error collecting/sending reboot status: %s"),
            ),
            (
                self._send_third_party_repository_update,
                _("Error collecting/sending third-party repository data: %s"),
            ),
            (
                self._send_antivirus_status_update,
                _("Error collecting/sending antivirus status: %s"),
            ),
            (
                self._send_firewall_status_update,
                _("Error collecting/sending firewall status: %s"),
            ),
            (
                self._send_graylog_status_update,
                _("Error collecting/sending Graylog status: %s"),
            ),
            (self._send_process_update, _("Error collecting/sending process data: %s")),
            (
                self._send_host_metrics_update,
                _("Error collecting/sending host metrics: %s"),
            ),
            (
                self._send_time_status_update,
                _("Error collecting/sending clock status: %s"),
            ),
            (
                self._send_hardware_health_update,
                _("Error collecting/sending hardware health: %s"),
            ),
            (
                self._send_compliance_evidence_update,
                _("Error collecting/sending compliance evidence: %s"),
            ),
            (
                self.child_host_collector.send_child_hosts_update,
                _("Error collecting/sending child hosts data: %s"),
            ),
        )
        for send, message in steps:
            try:
                await send()
            except Exception as error:  # pylint: disable=broad-exception-caught
                self.logger.error(message, error)

    async def data_collector(self):
        """Handle periodic data collection and sending."""
        self.logger.debug("Data collector started")

        # Wait for the WebSocket handshake to complete before the
        # first collection -- otherwise ``_collect_and_send_periodic_data``
        # sees ``self.agent.connected == False`` and bails silently,
        # which is why fresh installs show "OS Updated: never" on the
        # server even hours after the agent connected.  Poll briefly
        # (1s interval, 60s ceiling) and then fire the first collect.
        if not await self._wait_for_connection(60):
            return
        await self._initial_periodic_collection()

        # Send periodic data updates every 5 minutes
        data_collection_interval = 300  # 5 minutes

        while self.agent.running:
            try:
                await asyncio.sleep(schedule_jitter.jittered(data_collection_interval))
                await self._collect_and_send_periodic_data()
                self.logger.debug("AGENT_DEBUG: Periodic data collection completed")
            except asyncio.CancelledError:
                # Graceful shutdown - re-raise to propagate cancellation
                self.logger.debug("Data collector cancelled")
                raise
            except Exception as error:
                self.logger.error(_("Data collector error: %s"), error)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def _wait_for_connection(self, seconds: int) -> bool:
        """Poll once a second until connected; False if the agent stopped."""
        for _tick in range(seconds):
            if not self.agent.running:
                return False
            if self.agent.connected:
                break
            await asyncio.sleep(1)
        return True

    async def _initial_periodic_collection(self):
        if not (self.agent.running and self.agent.connected):
            return
        try:
            # A moment's random wait, so a fleet reconnecting together
            # (a server restart) does not collect together (Phase 22.1).
            await asyncio.sleep(schedule_jitter.connect_splay())
            # ...and no earlier than a busy server asked (server 22.2).
            held = schedule_jitter.initial_reports_wait()
            if held > 0:
                await asyncio.sleep(held)
            self.logger.info("Initial periodic data collection (post-connect)")
            await self._collect_and_send_periodic_data()
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Initial data collection error: %s"), error)

    async def child_host_heartbeat(self):
        """Delegate to child_host_collector for frequent child host status updates."""
        return await self.child_host_collector.child_host_heartbeat()

    async def package_collector(self):
        """Handle periodic package collection."""
        await self.agent.package_collection_scheduler.run_package_collection_loop()

    async def update_checker(self):
        """Handle periodic update checking."""
        await self.agent.update_checker_util.run_update_checker_loop()

    async def collect_certificates(self) -> Dict[str, Any]:
        """Collect SSL certificates from the system and send to server."""
        try:
            # Certificate collection can work in unprivileged mode for most system certificates
            # Only some certificates in restricted directories may require privileged access
            if not is_running_privileged():
                self.logger.info(
                    "Running certificate collection in unprivileged mode - some certificates may not be accessible"
                )

            self.logger.info("Collecting SSL certificates from system")

            # Collect certificate data
            certificates = await asyncio.to_thread(
                self.agent.certificate_collector.collect_certificates
            )

            if not certificates:
                self.logger.info("No certificates found on system")
                return {
                    "success": True,
                    "result": "No certificates found",
                    "certificate_count": 0,
                }

            self.logger.info("Found %d certificates", len(certificates))

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
            self.logger.info("Collecting server roles")

            # Collect role data
            roles = await asyncio.to_thread(self.agent.role_detector.detect_roles)

            if not roles:
                self.logger.info("No server roles detected on system")
                return {
                    "success": True,
                    "result": "No server roles detected",
                    "role_count": 0,
                }

            self.logger.info("Found %d server roles", len(roles))

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
