# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Query-pack command handling -- ROADMAP Phase 21.1, slice S4.

The thin seam between a dispatched ``run_query_pack`` command and
``collection/query_pack_runner``, which does the work. Split the way every
other operation module here is: the runner knows facts and SQL and nothing
about commands; this knows the command envelope and nothing about SQL.

WHY THE WORK GOES TO A THREAD
-----------------------------
Running a pack materializes tables from real collectors -- reading the account
database, enumerating packages, stat-ing mounts -- and that is seconds of
blocking, synchronous work. On the event loop it would stall the agent's
WebSocket, its heartbeat and every other command for the duration, which on a
large host is long enough for the server to mark it down. So it runs in the
default executor and the loop stays responsive.
"""

import asyncio
import logging
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.collection.query_pack_runner import run_pack

logger = logging.getLogger(__name__)


class QueryPackOperations:
    """Executes query packs on behalf of the server."""

    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

    async def run_query_pack(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Run one dispatched pack and return its per-query outcomes.

        A pack with no queries is refused rather than reported as a clean run
        with nothing in it: an empty result set that nobody asked for is
        indistinguishable from a host that answered "nothing", which is the
        one confusion this whole phase exists to prevent.
        """
        pack = parameters or {}
        if not pack.get("queries") and not pack.get("not_covered"):
            return {"success": False, "error": _("The query pack has no queries.")}

        try:
            config = getattr(self.agent, "config", None)
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, run_pack, pack, config)
        except Exception as error:  # pylint: disable=broad-except
            self.logger.error(_("Failed to run query pack: %s"), error)
            return {"success": False, "error": str(error)}

        self.logger.info(
            "Ran query pack %s: %d result(s)",
            pack.get("pack_name"),
            len(result.get("results") or []),
        )
        return {"success": True, "result": result}
