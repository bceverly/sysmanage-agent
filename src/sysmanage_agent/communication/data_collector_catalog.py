# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
The available-packages catalog for the SysManage agent DataCollector:
collecting it, deciding between a delta and a full send, and recording what
the server holds.

Split out of ``data_collector.py`` to keep each module within the 1000-line
limit.  ``DataCollectorCatalogMixin`` is mixed into ``DataCollector`` and relies
on its ``agent`` and ``logger`` and on ``CATALOG_RESEND_COOLDOWN_SECONDS``.

Every step that reads, hashes, diffs or writes the catalog (about 100,000
rows) runs in a worker thread, never on the event loop, which also answers the
server's websocket keepalive pings (ubiquiti, 121,420 packages on a 2011 CPU,
2026-10-31).
"""

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.package_delta import (
    MODE_DELTA,
    build_delta_plan,
)


class DataCollectorCatalogMixin:
    """Available-packages catalog: collect, delta or full send, bookkeeping."""

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
        must still be honored promptly, so this caps a storm rather than
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
            # Off the event loop, like every step below that touches ~100k
            # rows: on ubiquiti (121k packages, a 2011 CPU) these ran for tens
            # of seconds in the loop and the websocket keepalive timed out.
            packages = await asyncio.to_thread(
                self.agent.package_collection_scheduler.package_collector.get_packages_for_transmission
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
            fingerprint = await asyncio.to_thread(
                self._catalog_fingerprint_of, packages["package_managers"]
            )

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
                await asyncio.to_thread(
                    self.agent.package_collection_scheduler.package_collector.replace_sent_snapshot,
                    packages["package_managers"],
                    fingerprint,
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
            snapshot, snap_fp, snap_at = await asyncio.to_thread(
                collector.get_sent_snapshot
            )
            plan = await asyncio.to_thread(
                build_delta_plan,
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
                await asyncio.to_thread(
                    collector.replace_sent_snapshot,
                    packages["package_managers"],
                    fingerprint,
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

        Returning None rather than raising or signaling is what keeps the
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

        await asyncio.to_thread(
            collector.replace_sent_snapshot, packages["package_managers"], fingerprint
        )
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
