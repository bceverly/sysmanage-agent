# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Stub ChildHostOperations for post-legacy-delete agent startup.

Drop-in replacement for ``operations/child_host_operations.ChildHostOperations``
that survives the import in ``main.py`` without depending on any of
the legacy ``child_host_*`` cluster.

When the legacy ``child_host_operations.py`` is eventually removed,
``main.py`` swaps its import:

    # before:
    from src.sysmanage_agent.operations.child_host_operations import ChildHostOperations
    # after:
    from src.sysmanage_agent.operations.child_host_ops_stub import ChildHostOperations

After the swap, the agent starts cleanly and ``agent.child_host_ops``
is a stub object that:

* Returns ``{"success": True, "child_hosts": [], "count": 0}`` for
  read-only listing/enumeration calls so the periodic listing flow
  doesn't crash.  (The non-stub ``ChildHostReporter`` path runs the
  shell directly, so this fallback is only for callers that go
  through the dispatcher.)
* Returns ``{"success": False, "error": _("child host management
  requires Pro+"), "code": "feature_not_licensed"}`` for write/lifecycle
  commands.  In Pro+ deployments the server doesn't send these
  command_types — it sends ``apply_deployment_plan`` instead — so this
  branch only fires in OSS-only deployments where the user shouldn't
  be hitting child-host endpoints anyway.

The class is intentionally minimal: same method names as the legacy
class, all returning friendly dicts, no real work.  This keeps
``agent_utils.CommandDispatcher.handlers`` from KeyErroring on any
legacy command_type.

The methods are ``async`` because the dispatcher in
``agent_utils._dispatch_command`` unconditionally awaits the handler
(``return await handler(parameters)``).  Each method opens with a
single ``await asyncio.sleep(0)`` to genuinely yield to the event loop
once — that satisfies static analyzers (no ``async`` without ``await``)
at near-zero runtime cost, and avoids per-method linter suppressions.
"""

import asyncio
import logging
import platform
from typing import Any, Dict
from src.i18n import _


def _feature_not_licensed() -> Dict[str, Any]:
    """Standard ``feature_not_licensed`` response dict.

    Built per-call so the localized message reflects the current locale
    at request time (the agent's i18n loader picks the active locale
    from the agent config, which can change at runtime).
    """
    return {
        "success": False,
        "error": _("Child host management requires Pro+ (engine path)."),
        "code": "feature_not_licensed",
    }


class ChildHostOperations:
    """Stub mimicking the legacy ChildHostOperations public surface.

    Every method is async-callable (the dispatcher awaits them) and
    returns a stable dict.  No state, no I/O, no legacy imports.
    """

    def __init__(self, _agent_instance):
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Read-only / capability probes
    # ------------------------------------------------------------------

    async def check_virtualization_support(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Capability probe — returns an empty/no-types dict.

        The Pro+ engine's ``build_check_virtualization_support_plan``
        is the live path; this stub only fires in OSS-only
        deployments where the operator isn't expected to drive
        virtualization.
        """
        await asyncio.sleep(0)
        return {
            "success": True,
            "supported_types": [],
            "capabilities": {},
            "reboot_required": False,
            "platform": platform.system().lower(),
        }

    async def list_child_hosts(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Empty listing — the active reporter bypasses this method.

        ``communication/child_host_reporter.ChildHostReporter`` runs
        the listing shell directly and ships ``child_host_list_update``
        without going through the dispatcher.  This stub exists only
        so the dispatcher's ``"list_child_hosts"`` mapping doesn't
        break if a server still sends the legacy command_type.
        """
        await asyncio.sleep(0)
        return {
            "success": True,
            "child_hosts": [],
            "count": 0,
        }

    async def autostart_child_hosts(
        self,
    ) -> None:  # NOSONAR - async required by dispatcher interface
        """Background task hook called from main.py after each reconnect.

        The legacy implementation enumerated bhyve VMs persisted with
        ``autostart=true`` and ran ``vm start <name>`` for each.  Under
        the engine path, vm-bhyve's own rc.d script (enabled by
        ``build_bhyve_init_plan``) auto-starts those VMs at parent boot
        — no agent-side action needed.  This stub method exists so
        ``main.py:_autostart_child_hosts`` doesn't AttributeError on
        startup; it intentionally does nothing.
        """
        await asyncio.sleep(0)
        return None

    # ------------------------------------------------------------------
    # Write / lifecycle ops — all return feature-not-licensed
    # ------------------------------------------------------------------

    async def create_child_host(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``create_child_host`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def enable_wsl(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``enable_wsl`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def initialize_lxd(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``initialize_lxd`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def initialize_vmm(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``initialize_vmm`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def initialize_kvm(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``initialize_kvm`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def initialize_bhyve(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``initialize_bhyve`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def disable_bhyve(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``disable_bhyve`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def enable_kvm_modules(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``enable_kvm_modules`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def disable_kvm_modules(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``disable_kvm_modules`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def start_child_host(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``start_child_host`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def stop_child_host(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``stop_child_host`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def restart_child_host(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``restart_child_host`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def delete_child_host(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``delete_child_host`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def update_child_agent(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``update_child_agent`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def setup_kvm_networking(
        self, _parameters: Dict[str, Any]
    ) -> Dict[str, Any]:  # NOSONAR - async required by dispatcher interface
        """Stub for ``setup_kvm_networking`` — returns ``feature_not_licensed``."""
        await asyncio.sleep(0)
        return _feature_not_licensed()

    async def list_kvm_networks(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Read-only network list — empty in stub."""
        await asyncio.sleep(0)
        return {"success": True, "networks": []}
