# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Agent start-up lifecycle mixin.

The steps ``SysManageAgent.run()`` takes BEFORE it has a connection: say what
this agent thinks it is, start the pre-connection background services, and
report which authentication it will actually use.

Extracted from main.py for two reasons.  ``run()`` had grown to a cognitive
complexity of 18 against a limit of 15 (SonarQube, main.py:870) — it was doing
banner logging, service start-up, registration, certificate reporting and the
reconnect loop in one body.  And main.py sits against a hard 1000-line gate, so
the extraction has to leave the file rather than just move within it.
"""

import asyncio

from src.i18n import _
from src.sysmanage_agent.collection.public_ip_fetcher import public_ip_refresh_service
from src.sysmanage_agent.core.agent_utils import reconcile_inflight_journal


class AgentLifecycleMixin:
    """Pre-connection start-up steps for :class:`SysManageAgent`."""

    def _log_startup_banner(self, system_info):
        """What this agent thinks it is, before anything can go wrong."""
        self.logger.info("Starting SysManage Agent")
        self.logger.info("Agent ID: %s", self.agent_id)
        self.logger.info("Hostname: %s", system_info["hostname"])
        self.logger.info("Platform: %s", system_info["platform"])
        self.logger.info("IPv4: %s", system_info["ipv4"])
        self.logger.info("IPv6: %s", system_info["ipv6"])

    async def _start_background_services(self):
        """Pre-connection housekeeping.  Neither failure is fatal.

        Both are wrapped individually and deliberately: an agent that cannot
        reconcile its journal, or cannot learn its public IP, is degraded but
        still worth having online.  Refusing to start would turn a cosmetic
        problem into an unmanaged host.
        """
        # Phase 11.6: reconcile any in-flight subprocess journal entries left
        # behind by a prior agent run.  Runs before the WebSocket is
        # established so dead subprocesses get a synthetic command_result
        # queued for delivery as soon as we connect, clearing the server's
        # DISPATCHED row instead of leaving it hung forever.
        try:
            await reconcile_inflight_journal(self)
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.error(_("In-flight journal reconciliation failed: %s"), error)

        # Phase 12.7: launch the public-IP refresh service.  Fires an immediate
        # fetch so the first heartbeat carries the value, then re-fetches every
        # 24h to catch dynamic-IP rotations.  On airgapped agents the fetch
        # silently returns None and the heartbeat just omits public_ip — no
        # penalty.
        try:
            self._public_ip_task = asyncio.create_task(public_ip_refresh_service())
            self.logger.info("Public-IP refresh service started")
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.logger.warning("Failed to start public-IP refresh service: %s", error)

    def _log_certificate_status(self):
        """Say which authentication the agent will actually be using."""
        if self.cert_store.has_certificates():
            self.logger.info(
                "Valid certificates found - secure authentication available"
            )
        else:
            self.logger.info("No certificates found - using token-based authentication")
            self.logger.info(
                "For enhanced security, approve this host to enable certificate-based auth"
            )
