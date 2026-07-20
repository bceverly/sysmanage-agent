# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Deployment-plan execution mixin for the SysManage agent.

Houses the ``apply_deployment_plan`` handler and all of its per-phase
helpers (package install/remove, file deploy delegation, command exec
with the in-flight-journal heartbeat watchdog, and service actions).
``GenericDeployment`` mixes this in so every method remains accessible
on the class exactly as before.

Shared byte-decoding helpers live in ``generic_deployment_helpers`` and
are imported by both this module and ``generic_deployment`` to avoid a
circular import.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations import inflight_journal
from src.sysmanage_agent.operations.generic_deployment_helpers import (
    _decode_command_output,
)


def _parse_pkg_entry(entry: Any) -> tuple:
    """Normalise a plan-package entry into (name, manager, error_msg)."""
    if isinstance(entry, str):
        return entry, None, None
    if isinstance(entry, dict):
        name = entry.get("name")
        if not name:
            return None, None, "Package entry missing 'name'"
        return name, entry.get("manager"), None
    return None, None, f"Bad package entry: {entry!r}"


def _all_pkg_install_optional(pkgs: list) -> bool:
    """A package list is 'all optional' if every entry has optional=True."""
    for entry in pkgs:
        if isinstance(entry, dict) and entry.get("optional") is True:
            continue
        return False
    return bool(pkgs)


def _plan_result(
    success: bool, results: Dict[str, Any], errors: list, failed_step: Optional[str]
) -> Dict[str, Any]:
    """Build the final apply_deployment_plan response."""
    return {
        "success": success,
        "results": results,
        "errors": errors,
        "failed_step": failed_step,
    }


class GenericDeploymentPlanMixin:
    """Deployment-plan execution methods for ``GenericDeployment``."""

    # ================================================================
    # apply_deployment_plan handler
    # ================================================================

    async def apply_deployment_plan(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a complete declarative deployment plan.

        A "deployment plan" is what the open-source server's plan_builder
        modules and the Pro+ Cython engines (firewall_orchestration_engine,
        av_management_engine) emit. The agent runs the plan in this order:

            1. packages          (install via existing install_package handler)
            2. files             (atomic deploy via existing deploy_files)
            3. commands          (subprocess.exec, argv-style)
            4. service_actions   (start/stop/restart/enable/disable)
            5. packages_to_remove (uninstall via existing handler)

        Stops on first hard failure unless the failing step has
        ignore_errors=True. The order keeps "install before configure
        before start"; removal happens last so a service is stopped
        cleanly before its package goes.

        Parameters:
            plan: dict with optional keys:
                packages           : list of str OR list of {manager, name, args}
                files              : list of file specs (deploy_files schema)
                commands           : list of command specs:
                    - argv: list[str]              (required)
                    - sudo: bool                    (default False)
                    - elevated: bool                (Windows only; informational)
                    - timeout: int seconds          (default 60)
                    - ignore_errors: bool           (default False)
                    - description: str              (for logs)
                service_actions    : list of {service, action}
                packages_to_remove : same shape as packages

        Returns:
            {success, results: {packages, files, commands, service_actions,
                                packages_to_remove}, errors: [...]}
        """
        plan = parameters.get("plan") or parameters
        # The dispatcher injects ``_message_id`` into parameters so the
        # in-flight journal (Phase 11.6) can name its file by it.  The
        # heartbeat watchdog refreshes the journal every 30s while any
        # subprocess in the plan runs, and a clean exit clears it.
        message_id = parameters.get("_message_id")
        self._current_plan_message_id = message_id
        results: Dict[str, Any] = {}
        errors: list = []

        # Each phase returns the failed-step name on a hard failure, or
        # None to continue.  Sequenced this way so the dispatcher itself
        # stays trivially flat (Sonar cognitive complexity).
        phases = (
            self._phase_install_packages,
            self._phase_deploy_files,
            self._phase_run_commands,
            self._phase_service_actions,
            self._phase_remove_packages,
        )
        try:
            for phase in phases:
                failed_step = await phase(plan, results, errors)
                if failed_step:
                    return _plan_result(False, results, errors, failed_step)

            return _plan_result(True, results, errors, None)
        finally:
            # Always clear the journal on any plan exit (success, hard
            # failure, or exception).  The synthetic-result path is only
            # taken when the agent restarts mid-plan; if we got here at
            # all, ``handle_command`` is about to send a real result.
            if message_id:
                inflight_journal.journal_clear(message_id)
            self._current_plan_message_id = None

    async def _phase_install_packages(
        self, plan: Dict[str, Any], results: Dict[str, Any], errors: list
    ) -> Optional[str]:
        pkgs = plan.get("packages") or []
        if not pkgs:
            return None
        pkg_results, pkg_errors = await self._apply_plan_packages(pkgs, install=True)
        results["packages"] = pkg_results
        errors.extend(pkg_errors)
        if pkg_errors and not _all_pkg_install_optional(pkgs):
            return "packages"
        return None

    async def _phase_deploy_files(
        self, plan: Dict[str, Any], results: Dict[str, Any], errors: list
    ) -> Optional[str]:
        files = plan.get("files") or []
        if not files:
            return None
        files_result = await self.deploy_files({"files": files})
        results["files"] = files_result
        if not files_result.get("success"):
            errors.extend(files_result.get("errors", []))
            return "files"
        return None

    async def _phase_run_commands(
        self, plan: Dict[str, Any], results: Dict[str, Any], errors: list
    ) -> Optional[str]:
        cmds = plan.get("commands") or []
        if not cmds:
            return None
        cmd_results, cmd_errors, hard_fail = await self._apply_plan_commands(cmds)
        results["commands"] = cmd_results
        errors.extend(cmd_errors)
        return "commands" if hard_fail else None

    async def _phase_service_actions(
        self, plan: Dict[str, Any], results: Dict[str, Any], errors: list
    ) -> Optional[str]:
        svc_actions = plan.get("service_actions") or []
        if not svc_actions:
            return None
        svc_results, svc_errors = await self._apply_plan_service_actions(svc_actions)
        results["service_actions"] = svc_results
        errors.extend(svc_errors)
        return "service_actions" if svc_errors else None

    async def _phase_remove_packages(
        self, plan: Dict[str, Any], results: Dict[str, Any], errors: list
    ) -> Optional[str]:
        pkgs_rm = plan.get("packages_to_remove") or []
        if not pkgs_rm:
            return None
        rm_results, rm_errors = await self._apply_plan_packages(pkgs_rm, install=False)
        results["packages_to_remove"] = rm_results
        errors.extend(rm_errors)
        return "packages_to_remove" if rm_errors else None

    async def _apply_plan_packages(self, pkgs: list, install: bool) -> tuple:
        """
        Install or uninstall a list of packages from a plan.

        Each entry can be a bare string (auto-detect package manager) or
        a dict like {"manager": "pkg", "name": "clamav"} for platforms
        with multiple managers.
        """
        results = []
        errors = []
        for entry in pkgs:
            pkg_name, pkg_mgr, parse_error = _parse_pkg_entry(entry)
            if parse_error:
                errors.append(parse_error)
                continue
            result, error_msg = await self._apply_one_plan_package(
                pkg_name, pkg_mgr, install
            )
            results.append(result)
            if error_msg:
                errors.append(error_msg)
        return results, errors

    async def _apply_one_plan_package(
        self, pkg_name: str, pkg_mgr: Optional[str], install: bool
    ) -> tuple:
        """Install or uninstall a single package; return (result, error_msg)."""
        action_name = "install" if install else "remove"
        try:
            if install:
                result = await self.agent.install_package(
                    {
                        "package_name": pkg_name,
                        "package_manager": pkg_mgr or "auto",
                    }
                )
            else:
                # uninstall_packages takes a list — wrap the single entry
                # so the manager hint flows through.
                result = await self.agent.uninstall_packages(
                    {
                        "packages": [
                            {
                                "package_name": pkg_name,
                                "package_manager": pkg_mgr or "auto",
                            }
                        ],
                    }
                )
        except Exception as exc:
            return (
                {"name": pkg_name, "success": False, "error": str(exc)},
                f"Package {action_name} exception for {pkg_name}: {exc}",
            )

        success = bool(result.get("success", False))
        entry = {
            "name": pkg_name,
            "manager": pkg_mgr,
            "success": success,
            "result": result,
        }
        if success:
            return entry, None
        return (
            entry,
            f"Package {action_name} failed for "
            f"{pkg_name}: {result.get('error') or result}",
        )

    async def _apply_plan_commands(self, commands: list) -> tuple:
        """
        Run each plan command via asyncio.create_subprocess_exec.

        Stops on the first command whose `ignore_errors` is False AND that
        returned nonzero. Returns (per-command results, accumulated errors,
        hard_fail bool).
        """
        results = []
        errors = []
        for spec in commands:
            result, error_msg, hard_fail = await self._run_one_plan_command(spec)
            results.append(result)
            if error_msg:
                errors.append(error_msg)
            if hard_fail:
                return results, errors, True
        return results, errors, False

    async def _run_one_plan_command(self, spec: Dict[str, Any]) -> tuple:
        """
        Run a single plan command spec.

        Returns (result_dict, error_msg_or_None, hard_fail_bool).  Splits
        the command-shape validation, exec, timeout and exception handling
        into separate steps so the per-spec branching never accumulates
        Sonar's cognitive-complexity threshold.
        """
        argv = spec.get("argv") or []
        ignore_errors = bool(spec.get("ignore_errors", False))

        if not argv or not isinstance(argv, list):
            return (
                {"argv": argv, "success": False, "error": _("no argv")},
                f"Plan command missing/invalid 'argv': {spec!r}",
                not ignore_errors,
            )

        timeout = int(spec.get("timeout", 60))
        description = spec.get("description") or " ".join(argv)
        # Phase 11 B7 — engine plan-description envelope.  Pro+ engines
        # may emit ``description_key`` + ``description_params`` alongside
        # the legacy English ``description`` so the OSS frontend can
        # localize the description.  We pass these through verbatim
        # (no validation, no rendering) — the OSS resolver decides how
        # to display them.
        description_key = spec.get("description_key")
        description_params = spec.get("description_params")
        run_argv = list(argv)
        # ``os.geteuid`` is Unix-only.  On Windows ``spec.get("sudo")``
        # is meaningless anyway — there's no sudo — so short-circuit
        # the whole branch when ``geteuid`` isn't available.
        if spec.get("sudo") and hasattr(os, "geteuid") and os.geteuid() != 0:
            run_argv = ["sudo", "-n"] + run_argv

        envelope_extras = {}
        if description_key:
            envelope_extras["description_key"] = description_key
            envelope_extras["description_params"] = description_params or {}

        try:
            return await self._exec_plan_command(
                argv,
                run_argv,
                description=description,
                timeout=timeout,
                ignore_errors=ignore_errors,
                envelope_extras=envelope_extras,
            )
        except FileNotFoundError as exc:
            return (
                {
                    "argv": argv,
                    "description": description,
                    "success": False,
                    "error": _("FileNotFoundError: %s") % (exc),
                    **envelope_extras,
                },
                f"Command '{description}' not found: {exc}",
                not ignore_errors,
            )
        except Exception as exc:
            return (
                {
                    "argv": argv,
                    "description": description,
                    "success": False,
                    "error": str(exc),
                    **envelope_extras,
                },
                f"Command '{description}' exception: {exc}",
                not ignore_errors,
            )

    async def _heartbeat_watchdog(self, message_id: str) -> None:
        """Refresh the in-flight journal heartbeat every 30 s while a subprocess runs.

        Cancelled by ``_exec_plan_command``'s ``finally`` block once the
        subprocess returns or times out.  No try/except for
        ``CancelledError`` here — the journal is stateless from the
        watchdog's perspective (``journal_heartbeat`` is a single
        atomic file write owned by ``_exec_plan_command``'s lifetime),
        so we let the cancellation propagate naturally.  This satisfies
        both SonarQube ``python:S7483`` (no silent swallowing) and
        pylint ``W0706`` (no pointless catch-and-rethrow).
        """
        while True:
            await asyncio.sleep(inflight_journal.HEARTBEAT_INTERVAL_SECONDS)
            inflight_journal.journal_heartbeat(message_id)

    @staticmethod
    def _safe_cwd_and_env() -> tuple:
        """Compute a (cwd, env) pair safe for a plan subprocess.

        Debian/Ubuntu give unprivileged system users
        ``HOME=/nonexistent`` by convention.  When systemd's unit for
        sysmanage-agent inherits that as its WorkingDirectory,
        ``os.getcwd()`` raises ``OSError: [Errno 13] Permission denied:
        '/nonexistent'`` *before* we even reach
        ``create_subprocess_exec`` (this was the root cause of the
        phase-11 offline-mirror auto-apply ``apt-get update`` failure
        on test2404, 2026-05-17).  We also override ``HOME`` for the
        child: sudo's PAM ``session`` module chdirs into the caller's
        ``$HOME`` and fails the entire call with EACCES when that dir
        doesn't exist.
        """
        try:
            safe_cwd = os.getcwd()
            if not os.access(safe_cwd, os.R_OK | os.X_OK):
                raise OSError("cwd not accessible")
        except OSError:
            # ``tempfile.gettempdir()`` resolves ``$TMPDIR`` / ``$TEMP`` /
            # ``$TMP`` and falls back to the platform default without a
            # hardcoded literal.  See the matching shim in
            # ``_write_via_sudo`` for the full rationale.
            safe_cwd = tempfile.gettempdir()

        safe_env = os.environ.copy()
        home = safe_env.get("HOME", "")
        if not home or not os.path.isdir(home):
            safe_env["HOME"] = safe_cwd
        return safe_cwd, safe_env

    async def _spawn_and_communicate(
        self,
        *,
        argv: list,
        run_argv: list,
        description: str,
        timeout: int,  # NOSONAR S7497 - asyncio.timeout() needs 3.11+, we support 3.9
        safe_cwd: str,
        safe_env: dict,
    ) -> Optional[tuple]:
        """Spawn ``run_argv`` and return ``(returncode, stdout, stderr)``,
        or ``None`` on timeout (process already killed + reaped).

        Wraps the spawn in the Phase 11.6 in-flight-journal write + 30 s
        heartbeat watchdog so an agent restart mid-subprocess can clear
        the server's DISPATCHED row instead of hanging forever.
        """
        message_id = self._current_plan_message_id
        if message_id:
            inflight_journal.journal_write(
                message_id=message_id,
                plan={"argv": list(argv), "description": description},
                command_argv=list(run_argv),
                working_dir=safe_cwd,
            )

        proc = await asyncio.create_subprocess_exec(
            *run_argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=safe_cwd,
            env=safe_env,
        )
        if message_id and proc.pid:
            inflight_journal.journal_set_pid(message_id, proc.pid)

        watchdog_task = (
            asyncio.create_task(self._heartbeat_watchdog(message_id))
            if message_id
            else None
        )
        try:
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return None
        finally:
            if watchdog_task is not None:
                watchdog_task.cancel()
                try:
                    await watchdog_task
                except (
                    asyncio.CancelledError,
                    Exception,
                ):  # pylint: disable=broad-exception-caught
                    pass

        return proc.returncode or 0, stdout, stderr

    async def _exec_plan_command(
        self,
        argv: list,
        run_argv: list,
        *,
        description: str,
        timeout: int,  # NOSONAR S7497 - asyncio.timeout() needs 3.11+, we support 3.9
        ignore_errors: bool,
        envelope_extras: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Spawn the subprocess and translate the exit/timeout into a result tuple.

        Uses ``asyncio.wait_for`` for the timeout because this codebase still
        supports Python 3.9/3.10 where ``asyncio.timeout()`` (the structured
        replacement Sonar S7497 prefers) is not available.  The NOSONAR on
        the ``timeout`` parameter line above suppresses the rule until the
        minimum supported Python is bumped to 3.11.

        The cwd/HOME sanitisation and the subprocess-with-watchdog dance
        are factored into ``_safe_cwd_and_env`` and
        ``_spawn_and_communicate`` to keep this function's cognitive
        complexity under Sonar's threshold.
        """
        safe_cwd, safe_env = self._safe_cwd_and_env()
        extras = envelope_extras or {}

        outcome = await self._spawn_and_communicate(
            argv=argv,
            run_argv=run_argv,
            description=description,
            timeout=timeout,
            safe_cwd=safe_cwd,
            safe_env=safe_env,
        )
        if outcome is None:
            return (
                {
                    "argv": argv,
                    "description": description,
                    "success": False,
                    "error": _("timeout"),
                    **extras,
                },
                f"Command '{description}' timed out after {timeout}s",
                not ignore_errors,
            )

        returncode, stdout, stderr = outcome
        cmd_ok = returncode == 0
        # UTF-16LE-aware decode so wsl.exe output (always UTF-16LE on
        # Windows) doesn't come back as garbled null-littered bytes.
        stdout_str = _decode_command_output(stdout, argv=run_argv)
        stderr_str = _decode_command_output(stderr, argv=run_argv)
        result = {
            "argv": argv,
            "description": description,
            "returncode": returncode,
            "stdout": stdout_str[-2000:],
            "stderr": stderr_str[-2000:],
            "success": cmd_ok,
            **extras,
        }
        if cmd_ok:
            return result, None, False
        err_msg = f"Command '{description}' exited {returncode}: {stderr_str[:300]}"
        return result, err_msg, not ignore_errors

    async def _apply_plan_service_actions(self, actions: list) -> tuple:
        """
        Run each {service, action} pair through the agent's service control.

        Groups by action so we issue one service_control call per action
        with a list of services — matches the existing handler shape.
        """
        # Group: {action: [service, ...]}
        grouped: Dict[str, list] = {}
        for entry in actions:
            action = entry.get("action")
            service = entry.get("service")
            if not action or not service:
                continue
            grouped.setdefault(action, []).append(service)

        results = []
        errors = []
        # Preserved order: enable/disable before start/stop/restart so the
        # boot-time configuration is settled first.
        action_order = ["enable", "disable", "stop", "start", "restart"]
        for action in action_order:
            services = grouped.get(action) or []
            if not services:
                continue
            # Re-use the existing MessageProcessor service_control handler
            # the agent already exposes for the "service_control" command type.
            handler = getattr(
                getattr(self.agent, "message_processor", None),
                "_handle_service_control",
                None,
            )
            if handler is None:
                errors.append(
                    f"No service_control handler available for action '{action}'"
                )
                continue
            try:
                result = await handler({"action": action, "services": services})
                results.append(
                    {
                        "action": action,
                        "services": services,
                        "success": bool(result.get("success", False)),
                        "result": result,
                    }
                )
                if not result.get("success", False):
                    errors.append(
                        f"service_control {action} failed for {services}: "
                        f"{result.get('error') or result}"
                    )
            except Exception as exc:
                errors.append(
                    f"service_control {action} exception for {services}: {exc}"
                )
                results.append(
                    {
                        "action": action,
                        "services": services,
                        "success": False,
                        "error": str(exc),
                    }
                )
        return results, errors
