"""
Thin script-execution shim for the SysManage agent.

Phase 5 migration (ROADMAP §5.1): all script orchestration — saved-script
library, version history, multi-host execution, multi-shell selection,
scheduled triggers, approval workflows — now lives in the server-side
Pro+ ``automation_engine`` Cython module.  The open-source server has
its own ``script_plan_builder`` for ad-hoc one-shot runs.

Both server-side paths emit the same declarative deploy-plan shape, which
the agent already knows how to run via ``apply_deployment_plan`` (Phase 3
generic deployment handlers, ROADMAP §8.6).

This file used to contain ~328 lines of agent-side shell pathfinding,
script-file creation, subprocess invocation, and timeout handling — all
of which are now redundant because the server picks the shell and the
target script path before sending the plan.

What's left: a translator that takes the legacy ``execute_script``
message (still emitted by older server builds and by user-triggered
ad-hoc runs from the UI before the Pro+ automation_engine is loaded)
and reformats it into a deploy plan for the existing
``apply_deployment_plan`` handler.
"""

import logging
import os
import tempfile
from typing import Any, Dict
from uuid import uuid4

from src.i18n import _


class ScriptOperations:
    """Translates legacy script-execution messages into deploy plans."""

    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

    async def execute_script(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate legacy ``execute_script`` parameters into a deploy plan
        and run it via the generic ``apply_deployment_plan`` handler.

        Parameters (all from the existing message contract):
            script_content (required): the script body, already rendered
                with any parameter substitutions performed server-side.
            shell_type: bash | zsh | sh | ksh | powershell | cmd; defaults
                to "bash" (server now picks this; the default is a fallback
                for older server builds that didn't send shell_type).
            timeout: per-script timeout in seconds; default 300, capped at
                the agent's configured maximum.
            working_directory: ignored — server-built deploy plans don't
                support cwd today; the script body should ``cd`` itself
                before doing the work.

        Returns:
            The standard ``{success, ...}`` shape, surfacing the apply
            result so existing message-bus consumers don't need changes.
        """
        script_content = parameters.get("script_content")
        if not script_content:
            return {
                "success": False,
                "error": _("Missing required parameter 'script_content'"),
            }

        shell = parameters.get("shell_type") or "bash"
        timeout = int(parameters.get("timeout") or 300)
        try:
            max_timeout = self.agent.config.get_max_script_timeout()
            if timeout > max_timeout:
                self.logger.warning(
                    _("Script timeout capped at %d seconds"), max_timeout
                )
                timeout = max_timeout
        except Exception:  # nosec B110
            # Config not available (e.g. tests with stub agents) — keep
            # the requested timeout as-is.
            pass

        plan = self._build_plan(script_content, shell, timeout)
        try:
            result = await self.agent.apply_deployment_plan({"plan": plan})
        except AttributeError:
            return {
                "success": False,
                "error": _(
                    "Agent does not expose apply_deployment_plan; upgrade required"
                ),
            }
        except Exception as exc:
            self.logger.error(_("Script delegation failed: %s"), exc)
            return {"success": False, "error": str(exc)}

        # Surface the per-command outcome so legacy callers see the same
        # shape they used to.  The first command in the plan is the
        # interpreter invocation; its returncode + output are what callers
        # care about.
        return self._extract_legacy_shape(result)

    @staticmethod
    def _build_plan(content: str, shell: str, timeout: int) -> Dict[str, Any]:
        """Build the same deploy-plan shape the server emits."""
        if shell == "powershell":
            script_path = f"C:/Windows/Temp/sysmanage_script_{uuid4().hex}.ps1"
            argv = [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path,
            ]
            cleanup = [
                "powershell",
                "-Command",
                f"Remove-Item -Force '{script_path}'",
            ]
        elif shell == "cmd":
            script_path = f"C:/Windows/Temp/sysmanage_script_{uuid4().hex}.bat"
            argv = ["cmd.exe", "/c", script_path]
            cleanup = ["cmd.exe", "/c", "del", script_path]
        else:
            # POSIX shells.  Use the platform's secure temp directory rather
            # than hardcoding /tmp; combined with uuid4().hex (128 bits) and
            # the deploy_files handler's atomic sibling-temp + rename with
            # mode 0o700, this is symlink-safe by construction.
            script_path = os.path.join(
                tempfile.gettempdir(),
                f"sysmanage_script_{uuid4().hex}.sh",
            )
            argv = [f"/bin/{shell}", script_path]
            cleanup = ["rm", "-f", script_path]
        return {
            "files": [{"path": script_path, "content": content, "mode": 0o700}],
            "commands": [
                {
                    "argv": argv,
                    "timeout": timeout,
                    "ignore_errors": False,
                    "description": f"run sysmanage script via {shell}",
                },
                {
                    "argv": cleanup,
                    "timeout": 10,
                    "ignore_errors": True,
                    "description": "remove temporary script file",
                },
            ],
        }

    @staticmethod
    def _extract_legacy_shape(result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reshape an ``apply_deployment_plan`` result into the legacy
        ``execute_script`` response shape so callers see no behaviour change.
        """
        if not result.get("success"):
            return {
                "success": False,
                "error": ", ".join(result.get("errors") or [])
                or "Script execution failed",
            }
        cmd_results = (result.get("results") or {}).get("commands") or []
        # First command is the interpreter; second is the cleanup.
        run_result = cmd_results[0] if cmd_results else {}
        return {
            "success": run_result.get("success", True),
            "exit_code": run_result.get("returncode", 0),
            "stdout": run_result.get("stdout", ""),
            "stderr": run_result.get("stderr", ""),
        }
