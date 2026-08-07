# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Agent capability advertisement — ROADMAP Phase 19.

WHY THIS EXISTS
---------------
Not every platform can run the *full* agent.  A native library may have no
build for a given architecture, or a very old target OS may lack a
prerequisite — alpine/freebsd/openbsd/netbsd already run reduced-capability
agents today.  Without advertisement the server happily dispatches a command
the agent cannot route, and the operator learns about it as a runtime failure
("Unknown command type: ...") long after the fact.

WHERE THE TRUTH COMES FROM
--------------------------
The capability set is DERIVED from the agent's own command-handler map
(``AgentUtils._get_command_handlers``), never hand-maintained.  That is the
same dict ``_dispatch_command`` routes on, so "advertised" and "actually
dispatchable" are the same set by construction.  A hand-written list would
drift the moment a handler is renamed or a build drops one, and a capability
list that lies is worse than none — it is exactly the silent-degradation this
feature exists to prevent.

WHAT IS SENT
------------
``build_capability_report`` returns both views, because they serve different
consumers and neither substitutes for the other:

* ``commands`` — the exact command types this build can route.  The SERVER
  gates dispatch on this; precision matters more than legibility.
* ``capabilities`` — those commands folded into human-meaningful GROUPS
  ("packages", "virtualization", ...).  The UI shows these; 67 raw command
  names is not a thing an operator can read, and groups survive a handler
  being renamed.
* ``unavailable`` — group -> machine-readable reason CODE, never prose.
  Translation happens server-side where the catalogs live; an agent has no
  business deciding what language an operator reads.

FORWARD COMPATIBILITY
---------------------
``schema_version`` is carried so capabilities can be added later without
breaking an older server, which is expected to ignore groups it does not know
(mirrors how federation ingests a site's ``capabilities`` metadata).  A
baseline agent advertises everything it can route, so nothing regresses for
hosts that already exist.
"""

from typing import Any, Dict, Iterable, List, Mapping

# Bump when the SHAPE of the report changes (new top-level keys, changed
# semantics) — not when a capability is added, which is the normal case and
# must not require a server change.
CAPABILITY_SCHEMA_VERSION = 1

# Reason codes for an unavailable group.  Codes, not sentences: the server
# owns the translation (see the module docstring).
REASON_NO_HANDLER = "no_handler"

# group -> the command types that implement it.
#
# Grouping is deliberate.  The gate needs exact command types, but an operator
# staring at a host-detail screen needs to know "this agent can't do
# virtualization", not that eleven specific command strings are absent.
CAPABILITY_GROUPS: Dict[str, tuple] = {
    "inventory": (
        "get_system_info",
        "update_os_version",
        "update_hardware",
        "update_user_access",
        "collect_roles",
    ),
    "packages": (
        "install_package",
        "install_packages",
        "uninstall_packages",
        "collect_available_packages",
        "enable_package_manager",
    ),
    "os_updates": (
        "update_system",
        "check_updates",
        "apply_updates",
        "check_reboot_status",
    ),
    "os_upgrade": ("os_release_upgrade",),
    "repositories": (
        "list_third_party_repositories",
        "add_third_party_repository",
        "delete_third_party_repositories",
        "enable_third_party_repositories",
        "disable_third_party_repositories",
    ),
    "gpg_keys": ("install_gpg_key", "remove_gpg_key"),
    "services": ("restart_service", "service_control", "get_service_status"),
    "power": ("reboot_system", "shutdown_system"),
    "processes": ("collect_processes", "kill_process"),
    "scripts": ("execute_script",),
    "shell": ("execute_shell",),
    "diagnostics": ("collect_diagnostics",),
    "certificates": ("collect_certificates",),
    "users_groups": (
        "create_host_user",
        "create_host_group",
        "delete_host_user",
        "delete_host_group",
    ),
    "hostname": ("change_hostname",),
    "fips": ("fips_enable", "fips_disable"),
    "ubuntu_pro": (
        "ubuntu_pro_attach",
        "ubuntu_pro_detach",
        "ubuntu_pro_enable_service",
        "ubuntu_pro_disable_service",
    ),
    "custom_metrics": ("sync_custom_metrics",),
    "deployment": (
        "deploy_files",
        "execute_command_sequence",
        "apply_deployment_plan",
    ),
    "agent_update": ("update_agent",),
    "virtualization": (
        "check_virtualization_support",
        "enable_wsl",
        "initialize_lxd",
        "initialize_vmm",
        "initialize_kvm",
        "initialize_bhyve",
        "disable_bhyve",
        "enable_kvm_modules",
        "disable_kvm_modules",
        "setup_kvm_networking",
        "list_kvm_networks",
    ),
    "child_hosts": (
        "list_child_hosts",
        "create_child_host",
        "start_child_host",
        "stop_child_host",
        "restart_child_host",
        "delete_child_host",
        "update_child_agent",
    ),
}


def command_to_group() -> Dict[str, str]:
    """Reverse index: command type -> the group that owns it."""
    index: Dict[str, str] = {}
    for group, commands in CAPABILITY_GROUPS.items():
        for command in commands:
            index[command] = group
    return index


def ungrouped_commands(available: Iterable[str]) -> List[str]:
    """Command types this build routes that no group claims.

    Not an error — a new handler simply has not been grouped yet, and it is
    still gated correctly because gating reads ``commands``.  Surfaced so the
    drift is visible instead of silent; a test asserts it stays empty.
    """
    index = command_to_group()
    return sorted(c for c in available if c not in index)


def build_capability_report(handlers: Mapping[str, Any]) -> Dict[str, Any]:
    """Describe what this agent build can actually do.

    ``handlers`` is the live command-handler map — pass
    ``AgentUtils._get_command_handlers()``.  Deriving from it is the whole
    point: see the module docstring.

    A group counts as supported when AT LEAST ONE of its commands is routable.
    Partial support is reported rather than hidden, because a build missing one
    of eleven virtualization commands still does virtualization, and claiming
    otherwise would be as wrong as claiming full support.  Per-command
    precision is preserved in ``commands`` for the dispatch gate.
    """
    available = {str(name) for name in handlers}
    supported: List[str] = []
    partial: Dict[str, List[str]] = {}
    unavailable: Dict[str, str] = {}

    for group, commands in CAPABILITY_GROUPS.items():
        present = [c for c in commands if c in available]
        if not present:
            unavailable[group] = REASON_NO_HANDLER
            continue
        supported.append(group)
        missing = [c for c in commands if c not in available]
        if missing:
            partial[group] = sorted(missing)

    return {
        "schema_version": CAPABILITY_SCHEMA_VERSION,
        "capabilities": sorted(supported),
        "commands": sorted(available),
        "unavailable": dict(sorted(unavailable.items())),
        "partial": dict(sorted(partial.items())),
    }
