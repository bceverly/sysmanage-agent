# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Network discovery operations -- Phase 21.6 S1.

OFF until the server turns it on.  Listening to a network is not something an
agent should start doing on its own: the server enables it (when the
Enterprise ``asset_discovery_engine`` is licensed and an operator asks for
it) with the ``configure_network_discovery`` command, whose presence in the
command map is what advertises the ``network_discovery`` capability.

Contract
--------
* Server -> agent: ``command_type="configure_network_discovery"`` with
  ``parameters={"enabled": bool, "report_interval_seconds": int}``.
* Agent -> server, every interval while enabled:
  ``message_type="network_discovery_report"`` (see the server's
  ``network_discovery_handlers`` for the payload).

The setting is persisted to ``~/.sysmanage-agent/network_discovery.json`` so a
restarted agent resumes listening without waiting for the server to repeat
itself -- and, just as important, stays OFF if it was turned off.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.collection import network_sweep
from src.sysmanage_agent.collection.network_discovery_collection import (
    NetworkDiscoveryCollector,
    local_interfaces,
)

DEFAULT_INTERVAL_SECONDS = 300
MIN_INTERVAL_SECONDS = 60
MAX_INTERVAL_SECONDS = 3600


def state_path() -> Path:
    """Where the enabled/disabled decision survives a restart."""
    home = (
        os.environ.get("HOME")
        or os.environ.get("USERPROFILE")
        or os.path.expanduser("~")
    )
    return Path(home) / ".sysmanage-agent" / "network_discovery.json"


def _clamp_interval(value: Any) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS
    return max(MIN_INTERVAL_SECONDS, min(MAX_INTERVAL_SECONDS, seconds))


class NetworkDiscoveryOperations:
    """Owns the collector and the report loop."""

    def __init__(self, agent_instance, collector: Optional[Any] = None):
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self.collector = collector or NetworkDiscoveryCollector()
        self.enabled = False
        self.interval = DEFAULT_INTERVAL_SECONDS
        self._sweeping = False

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------

    def load_persisted(self) -> None:
        """Resume the server's last decision; absent or unreadable = off."""
        try:
            data = json.loads(state_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.interval = _clamp_interval(data.get("report_interval_seconds"))
        if data.get("enabled") is True:
            self._set_enabled(True)

    def _persist(self) -> None:
        path = state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"enabled": self.enabled, "report_interval_seconds": self.interval}
        descriptor, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as out:
                json.dump(payload, out)
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _set_enabled(self, enabled: bool) -> Dict[str, str]:
        self.enabled = enabled
        if enabled:
            return self.collector.start()
        self.collector.stop()
        return {}

    # ------------------------------------------------------------------
    # command handler
    # ------------------------------------------------------------------

    async def configure_network_discovery(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Turn listening on or off, and set how often to report."""
        enabled = parameters.get("enabled") is True
        self.interval = _clamp_interval(
            parameters.get("report_interval_seconds", self.interval)
        )
        methods = await asyncio.to_thread(self._set_enabled, enabled)
        try:
            self._persist()
        except OSError as error:
            # Still applied for this run; it just will not survive a restart.
            self.logger.warning(
                _("Network discovery setting could not be saved: %s"), error
            )
        return {
            "success": True,
            "enabled": self.enabled,
            "report_interval_seconds": self.interval,
            "methods": methods,
        }

    # ------------------------------------------------------------------
    # report loop
    # ------------------------------------------------------------------

    async def run_report_loop(self) -> None:
        """Report what was heard, every interval, while enabled.

        Runs per connection (the agent recreates its tasks on reconnect); the
        collector itself keeps listening across reconnects, so a bounced
        WebSocket loses no sightings -- they arrive with the next report.
        """
        while True:
            await asyncio.sleep(self.interval)
            if not (self.enabled and self.collector.running):
                continue
            try:
                await self.send_report()
            except Exception as error:  # pylint: disable=broad-except
                self.logger.error(
                    _("Error sending network discovery report: %s"), error
                )

    async def send_report(self) -> bool:
        """Snapshot the collector and send one report."""
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if not approval:
            self.logger.warning(
                _("Cannot send network discovery report: no host approval")
            )
            return False
        payload = await asyncio.to_thread(self.collector.snapshot)
        payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message("network_discovery_report", payload)
        sent = await self.agent.send_message(message)
        if sent:
            self.logger.debug(
                "network discovery report sent (%d devices)",
                len(payload["observations"]),
            )
        else:
            self.logger.warning(_("Failed to send network discovery report"))
        return bool(sent)

    # ------------------------------------------------------------------
    # active sweep (S4)
    # ------------------------------------------------------------------

    async def run_network_sweep(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Sweep one on-link network the server asked for, then report it.

        Re-checks the range here (on-link, IPv4, bounded) even though the
        server validated it: this is the host that puts the traffic out.
        A refusal is reported too, so the operator's run record closes.
        """
        run_id = str(parameters.get("run_id") or "")
        interfaces = await asyncio.to_thread(local_interfaces)
        verdict = network_sweep.check(parameters.get("cidr"), interfaces)
        reason = verdict["reason"]
        if reason is None and self._sweeping:
            reason = "busy"
        if reason is None and not self.enabled:
            reason = "discovery_disabled"
        if reason is not None:
            await self._send_sweep_report(
                run_id, verdict["cidr"], "refused", 0, [], reason
            )
            return {
                "success": False,
                "run_id": run_id,
                "status": "refused",
                "reason": reason,
            }
        self._sweeping = True
        try:
            rate = network_sweep.clamp_rate(parameters.get("rate"))
            own_ip = next(
                i["ip"] for i in interfaces if i["name"] == verdict["interface"]
            )
            probed = await asyncio.to_thread(
                network_sweep.sweep, verdict["cidr"], rate, own_ip
            )
            found = await asyncio.to_thread(
                network_sweep.observations_in, verdict["cidr"], verdict["interface"]
            )
        finally:
            self._sweeping = False
        status = "completed" if found is not None else "failed"
        await self._send_sweep_report(
            run_id, verdict["cidr"], status, probed, found or [],
            None if found is not None else "cache_unreadable",
        )  # fmt: skip
        return {"success": found is not None, "run_id": run_id, "status": status}

    async def _send_sweep_report(  # pylint: disable=too-many-positional-arguments
        self, run_id, cidr, status, probed, observations, reason
    ) -> None:
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if not approval:
            self.logger.warning(
                _("Cannot send network discovery report: no host approval")
            )
            return
        methods = dict(getattr(self.collector, "methods", None) or {})
        methods["sweep"] = "ok"
        payload = {
            "host_id": str(approval.host_id),
            "interfaces": await asyncio.to_thread(local_interfaces),
            "methods": methods,
            "window_seconds": None,
            "observations": observations,
            "sweep": {
                "run_id": run_id, "cidr": cidr, "status": status,
                "probed": probed, "reason": reason,
            },  # fmt: skip
        }
        message = self.agent.create_message("network_discovery_report", payload)
        if not await self.agent.send_message(message):
            self.logger.warning(_("Failed to send network discovery report"))
