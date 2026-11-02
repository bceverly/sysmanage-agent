# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Scripts on a host that requires approval for them.

``script_execution.security.require_approval: true`` in the agent's
configuration makes the host run only scripts the server approved: the
agent reports the setting (``script_approval_required``), the server sends
that host's scripts only through the Professional+ approval workflow, and
here the agent refuses any script that does not carry the approval's id.

A script reaches the agent two ways: the legacy ``execute_script`` command
(its ``approval_id`` parameter) and a deploy plan the server marks
``"kind": "script"`` (its ``approval_id`` key).  Every other deploy plan --
package installs, configuration files, services -- is not a script and is
never held here.
"""

from typing import Any, Dict, Optional

from src.i18n import _

SCRIPT_PLAN_KIND = "script"


def _required(agent) -> bool:
    """True only for a real yes: ``true`` in the YAML, or a quoted "true"."""
    try:
        value = agent.config.is_script_approval_required()
    except AttributeError:
        return False  # no configuration (a stub agent): nothing to enforce
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "on", "1")
    return value is True


def _refused() -> Dict[str, Any]:
    return {
        "success": False,
        "error": _(
            "This host requires approval for scripts, and this script was not "
            "approved. Run it from a saved script that goes through approval."
        ),
    }


def check_script(agent, parameters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The refusal for an ``execute_script`` command, or None to run it."""
    if _required(agent) and not parameters.get("approval_id"):
        return _refused()
    return None


def check_plan(agent, parameters: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The refusal for a deploy plan, or None to run it.  Only a plan marked
    as a script is held; an unmarked plan is never a script."""
    plan = parameters.get("plan") or parameters
    if not isinstance(plan, dict) or plan.get("kind") != SCRIPT_PLAN_KIND:
        return None
    if _required(agent) and not (
        plan.get("approval_id") or parameters.get("approval_id")
    ):
        return _refused()
    return None
