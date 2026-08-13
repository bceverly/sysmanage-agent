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
import hashlib
import logging
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.operations.firewall_collector import FirewallCollector
from src.sysmanage_agent.collection.graylog_collector import GraylogCollector
from src.sysmanage_agent.collection.process_collection import ProcessCollector
from src.sysmanage_agent.collection.package_delta import (
    MODE_DELTA,
    build_delta_plan,
)
from src.sysmanage_agent.communication.child_host_collector import ChildHostCollector
from src.sysmanage_agent.communication.data_collector_senders import (
    _UNKNOWN_ERROR,
    DataCollectorSendersMixin,
)


class DataCollector(DataCollectorSendersMixin):
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
        self.logger.info("Sending initial update check...")

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
            self.logger.error(_("Failed to perform initial update check: %s"), error)

        # Allow time for update check to complete before collecting certificates
        await asyncio.sleep(2)

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

        # Send software inventory update
        try:
            await self._send_software_inventory_update()
        except Exception as error:
            self.logger.error(
                _("Error collecting/sending software inventory: %s"), error
            )

        # Send user access update
        try:
            await self._send_user_access_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending user access data: %s"), error)

        # Send hardware update
        try:
            await self._send_hardware_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending hardware data: %s"), error)

        # Send certificate update
        try:
            await self._send_certificate_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending certificate data: %s"), error)

        # Send role update
        try:
            await self._send_role_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending role data: %s"), error)

        # Send OS version update
        try:
            await self._send_os_version_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending OS version data: %s"), error)

        # Send reboot status update
        try:
            await self._send_reboot_status_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending reboot status: %s"), error)

        # Send third-party repository update
        try:
            await self._send_third_party_repository_update()
        except Exception as error:
            self.logger.error(
                _("Error collecting/sending third-party repository data: %s"), error
            )

        # Send antivirus status update
        try:
            await self._send_antivirus_status_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending antivirus status: %s"), error)

        # Send firewall status update
        try:
            await self._send_firewall_status_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending firewall status: %s"), error)

        # Send Graylog status update
        try:
            await self._send_graylog_status_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending Graylog status: %s"), error)

        # Send running-process snapshot
        try:
            await self._send_process_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending process data: %s"), error)

        # Send child hosts (WSL/VM/container) status update
        try:
            await self.child_host_collector.send_child_hosts_update()
        except Exception as error:
            self.logger.error(_("Error collecting/sending child hosts data: %s"), error)

    async def data_collector(self):
        """Handle periodic data collection and sending."""
        self.logger.debug("Data collector started")

        # Wait for the WebSocket handshake to complete before the
        # first collection — otherwise ``_collect_and_send_periodic_data``
        # sees ``self.agent.connected == False`` and bails silently,
        # which is why fresh installs show "OS Updated: never" on the
        # server even hours after the agent connected.  Poll briefly
        # (1s interval, 60s ceiling) and then fire the first collect.
        for _tick in range(60):
            if not self.agent.running:
                return
            if self.agent.connected:
                break
            await asyncio.sleep(1)

        if self.agent.running and self.agent.connected:
            try:
                self.logger.info("Initial periodic data collection (post-connect)")
                await self._collect_and_send_periodic_data()
            except Exception as error:  # pylint: disable=broad-exception-caught
                self.logger.error(_("Initial data collection error: %s"), error)

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
                self.logger.error(_("Data collector error: %s"), error)
                # Don't break the loop on non-critical errors, but return to trigger reconnection
                return

    async def child_host_heartbeat(self):
        """Delegate to child_host_collector for frequent child host status updates."""
        return await self.child_host_collector.child_host_heartbeat()

    async def package_collector(self):
        """Handle periodic package collection."""
        await self.agent.package_collection_scheduler.run_package_collection_loop()

    async def update_checker(self):
        """Handle periodic update checking."""
        await self.agent.update_checker_util.run_update_checker_loop()

    @staticmethod
    def _catalog_fingerprint_of(package_managers: Dict[str, list]) -> str:
        """Stable fingerprint of the catalog we would transmit.

        Covers exactly what the server stores (manager, name, version), so a
        description-only change does not force a full resend, and any real
        change does.
        """
        hasher = hashlib.sha256()
        for manager in sorted(package_managers):
            hasher.update(f"\x00{manager}\x00".encode("utf-8"))
            entries = package_managers[manager] or []
            for pkg in sorted(
                entries, key=lambda p: (p.get("name", ""), p.get("version", ""))
            ):
                hasher.update(
                    f"{pkg.get('name', '')}\x1f{pkg.get('version', '')}\x1e".encode(
                        "utf-8"
                    )
                )
        return hasher.hexdigest()

    def _catalog_resend_is_pointless(self, fingerprint: str) -> bool:
        """True when re-sending this identical catalog would be pure waste.

        WHY THIS GUARD EXISTS
        ---------------------
        Sending the catalog is SERVER-commanded (`collect_available_packages`),
        and the server asks whenever an OS/version has no rows.  For two years a
        field-comparison bug rejected every Linux batch, so the rows never
        appeared, so the server asked again -- 78,979 messages / 9.4 GB in eight
        days, 83% of everything this agent sent, for a catalog that never
        landed.  The server-side bug is fixed, but the agent should not be able
        to be driven into that again by ANY server-side re-request loop, so it
        refuses to re-ship a byte-identical catalog it has just sent.

        The cooldown is deliberately short relative to the collection interval:
        a genuine reason to re-request (the server really did lose the catalog)
        must still be honoured promptly, so this caps a storm rather than
        suppressing legitimate traffic.  Skipping is also SAFE-BY-DESIGN only
        because it is time-bounded -- an unbounded "already sent it" cache would
        have HIDDEN the very bug that motivated this.
        """
        if self._catalog_fingerprint is None or self._catalog_sent_at is None:
            return False
        if fingerprint != self._catalog_fingerprint:
            return False
        elapsed = (datetime.now(timezone.utc) - self._catalog_sent_at).total_seconds()
        return elapsed < self.CATALOG_RESEND_COOLDOWN_SECONDS

    async def collect_available_packages(self, parameters=None) -> Dict[str, Any]:
        """Collect and send available packages, skipping what the server has.

        ``parameters`` may carry ``known_fingerprint`` -- the fingerprint of the
        catalog the SERVER already holds for this host.  When our freshly
        scanned catalog hashes to the same value there is nothing to tell it, so
        ~89k packages (~11 MB) are not transmitted.

        The fingerprint arrives on the COMMAND rather than as a reply because
        the server has no working path to answer an agent mid-exchange:
        ``route_inbound_message`` discards handler return values, which is how
        1,023 payload messages were once shipped into a batch the server had
        already rejected without ever saying so.
        """
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

            # Refuse to re-ship a catalog we just shipped unchanged.  This is
            # the agent's own protection against a server-side re-request loop
            # (see _catalog_resend_is_pointless), which once cost 9.4 GB.
            fingerprint = self._catalog_fingerprint_of(packages["package_managers"])

            # The server told us what it already holds.  Matching means it is
            # already current, so send nothing at all -- this is what removes
            # the once-per-cycle retransmission of an unchanged catalog, and it
            # works across agent restarts (unlike the in-memory guard below).
            known = (parameters or {}).get("known_fingerprint")
            if known and known == fingerprint:
                self.logger.info(
                    "Skipping available-packages send: server already holds this "
                    "catalog (%d packages, fingerprint %s)",
                    total_packages,
                    fingerprint[:12],
                )
                # A confirmed match is PROOF of what the server holds -- stronger
                # evidence than a send we merely believe succeeded.  Recording it
                # as the delivered snapshot means the very next change can go as
                # a delta, instead of needing a full ~11 MB send first purely to
                # establish a base we already knew.
                self.agent.package_collection_scheduler.package_collector.replace_sent_snapshot(
                    packages["package_managers"], fingerprint
                )
                # Treat as delivered: the server demonstrably has it, so the
                # local guard should not force a resend moments later either.
                self._catalog_fingerprint = fingerprint
                self._catalog_sent_at = datetime.now(timezone.utc)
                return {
                    "success": True,
                    "skipped": True,
                    "reason": "server_already_current",
                    "message": "Server already holds this catalog; nothing sent",
                    "total_packages": total_packages,
                }

            if self._catalog_resend_is_pointless(fingerprint):
                # Deliberately does NOT record a delivered snapshot, unlike the
                # server-confirmed skip above.  This branch is a purely LOCAL
                # rate limit -- it means "we sent this recently", not "the server
                # has it".  Treating it as proof of delivery would let a delta be
                # computed against a base the server may never have received,
                # which is exactly the desynchronisation the fingerprint check
                # exists to prevent.
                self.logger.info(
                    "Skipping available-packages send: %d packages unchanged since "
                    "the last send less than %ds ago (fingerprint %s)",
                    total_packages,
                    self.CATALOG_RESEND_COOLDOWN_SECONDS,
                    fingerprint[:12],
                )
                return {
                    "success": True,
                    "skipped": True,
                    "message": "Catalog unchanged since last send; not re-sent",
                    "total_packages": total_packages,
                }

            # Decide between a delta and a full catalog.  A delta is only valid
            # against a base BOTH sides agree on, so the plan is derived from
            # our delivered snapshot and the fingerprint the server reports --
            # never from optimism.  See collection/package_delta.
            collector = self.agent.package_collection_scheduler.package_collector
            snapshot, snap_fp, snap_at = collector.get_sent_snapshot()
            plan = build_delta_plan(
                current=packages["package_managers"],
                snapshot=snapshot,
                snapshot_fingerprint=snap_fp,
                server_fingerprint=known,
                snapshot_sent_at=snap_at,
            )

            outcome = await self._attempt_delta(
                plan,
                packages,
                os_name,
                os_version,
                total_packages,
                snap_fp,
                fingerprint,
                collector,
            )
            if outcome is not None:
                return outcome

            # Send packages using pagination to avoid large message issues
            success = await self._send_available_packages_paginated(
                packages["package_managers"],
                os_name,
                os_version,
                total_packages,
                catalog_fingerprint=fingerprint,
            )

            if success:
                # Record ONLY on success, so a failed send is retried rather
                # than silently suppressed by the guard above.  The snapshot is
                # what future deltas diff against, so it too is written only
                # when the server actually received this catalog.
                collector.replace_sent_snapshot(
                    packages["package_managers"], fingerprint
                )
                self._catalog_fingerprint = fingerprint
                self._catalog_sent_at = datetime.now(timezone.utc)
                return {
                    "success": True,
                    "mode": "full",
                    "message": f"Successfully sent {total_packages} packages using pagination",
                    "total_packages": total_packages,
                }
            return {"success": False, "error": "Failed to send paginated packages"}

        except Exception as error:
            self.logger.error(_("Error collecting available packages: %s"), error)
            return {"success": False, "error": str(error)}

    async def _attempt_delta(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        plan,
        packages,
        os_name,
        os_version,
        total_packages,
        base_fingerprint,
        fingerprint,
        collector,
    ):
        """Send a delta if the plan allows one; return None to fall through.

        Returning None rather than raising or signalling is what keeps the
        caller readable: EVERY way a delta can be declined -- the plan says
        full, the diff is empty, or the send itself failed -- ends with the
        full-catalog path, which is always correct and merely larger.
        """
        if plan["mode"] != MODE_DELTA:
            self.logger.info(
                "Sending full catalog (%d packages): %s",
                total_packages,
                plan["reason"],
            )
            return None

        if not plan["puts"] and not plan["takes"]:
            # Base agreed and nothing changed.  The fingerprint check in the
            # caller normally catches this; reaching here means the server
            # reported an older fingerprint for an identical catalog, so there
            # is still nothing to send.
            self._mark_delivered(fingerprint)
            return {
                "success": True,
                "skipped": True,
                "reason": plan["reason"],
                "message": "No catalog changes to send",
                "total_packages": total_packages,
            }

        if not await self._send_available_packages_delta(
            plan, os_name, os_version, base_fingerprint, fingerprint
        ):
            self.logger.warning(
                "Delta send failed; falling back to a full catalog send"
            )
            return None

        collector.replace_sent_snapshot(packages["package_managers"], fingerprint)
        self._mark_delivered(fingerprint)
        return {
            "success": True,
            "mode": "delta",
            "puts": len(plan["puts"]),
            "takes": len(plan["takes"]),
            "message": (
                f"Sent {len(plan['puts'])} put(s) and "
                f"{len(plan['takes'])} take(s) instead of "
                f"{total_packages} packages"
            ),
            "total_packages": total_packages,
        }

    def _mark_delivered(self, fingerprint: str) -> None:
        """Record that the server now holds this catalog (in-memory guard)."""
        self._catalog_fingerprint = fingerprint
        self._catalog_sent_at = datetime.now(timezone.utc)

    async def _send_available_packages_delta(
        self,
        plan: dict,
        os_name: str,
        os_version: str,
        base_fingerprint: str,
        new_fingerprint: str,
    ) -> bool:
        """Send only what changed: puts (added/changed) and takes (removed).

        ``base_fingerprint`` identifies the catalog this diff was computed
        against.  The server refuses the delta unless that is the catalog it
        actually holds, which is what stops a diff being applied to the wrong
        base and silently corrupting its copy.  A refusal is recoverable: the
        caller falls back to sending the whole catalog.
        """
        try:
            message = self.agent.create_message(
                "available_packages_delta",
                {
                    "os_name": os_name,
                    "os_version": os_version,
                    "base_fingerprint": base_fingerprint,
                    "new_fingerprint": new_fingerprint,
                    "puts": plan["puts"],
                    "takes": plan["takes"],
                },
            )
            await self.agent.send_message(message)
            self.logger.info(
                "Sent package delta: %d put(s), %d take(s) (base %s -> %s)",
                len(plan["puts"]),
                len(plan["takes"]),
                (base_fingerprint or "none")[:12],
                (new_fingerprint or "none")[:12],
            )
            return True
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Error sending package delta: %s"), error)
            return False

    async def _send_available_packages_paginated(
        self,
        package_managers: Dict[str, list],
        os_name: str,
        os_version: str,
        total_packages: int,
        catalog_fingerprint: str = None,
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
                    # Persisted by the server only when the batch COMPLETES, so
                    # it can hand it back on the next collect command and we can
                    # skip re-sending an identical catalog.
                    "catalog_fingerprint": catalog_fingerprint,
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
                _("Error sending paginated packages for batch %s: %s"), batch_id, error
            )
            return False

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
            certificates = self.agent.certificate_collector.collect_certificates()

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
            roles = self.agent.role_detector.detect_roles()

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
