# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Run a configuration profile locally (Phase 20.1).

PULL-STYLE, NOT PUSH
--------------------
The server ships the profile down the existing WebSocket and the agent applies
it to ITSELF.  Nothing here opens a port, and the ansible invocation pins
``-c local`` so a stray ``hosts:`` entry in a profile can never turn into an
outbound SSH attempt.  That is the Phase 19 "443 only" guarantee, enforced at
the point of use rather than assumed.

TWO EXECUTORS, ONE RESULT SHAPE
-------------------------------
POSIX runs ``ansible-playbook``; Windows runs ``dsc.exe``.  Both are
subprocessed with an argv list and both hand back the same dict, so the server
and the UI never branch on platform.

OBSERVED BEHAVIOUR, NOT ASSUMED (both validated against real binaries,
ansible-core 2.21.3 and dsc 3.2.3, 2026-08-26):

* ``dsc`` writes its structured logs to STDERR with ANSI colour codes, and its
  results as one JSON document on STDOUT.  Merging the streams corrupts the
  parse -- so the two are captured separately, and only stdout is parsed.
* A failing ``dsc`` run exits non-zero and prints NOTHING to stdout, so its
  verdict cannot come from the JSON alone; the exit code has to carry it.
* ``ansible-playbook`` emits our JSON-lines callback on stdout, interleaved
  with its own warnings, which is why the parser tolerates non-JSON lines.
* ``dsc``'s ``changedProperties`` reports resource STATE deltas, not side
  effects: ``RunCommandOnSet`` really did run its command while reporting
  ``changedProperties: []``.  That is correct desired-state semantics, but it
  means "changed" answers "did the declared state move", not "did anything
  happen".
"""

import asyncio
import json
import os
import platform
import shutil
import stat
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from src.i18n import _
from src.sysmanage_agent.core import aiofiles_compat as aiofiles
from src.sysmanage_agent.operations import config_mgmt_locator as locator
from src.sysmanage_agent.operations import config_mgmt_readers as readers
from src.sysmanage_agent.operations import config_mgmt_results as results
from src.sysmanage_agent.operations import config_mgmt_spec as spec_mod

# Generous, because a profile may install packages.  The server can override.
DEFAULT_TIMEOUT_SECONDS = 1800

# Reason codes, not sentences: the SERVER owns translation, matching the
# convention capability_probes established.
REASON_NO_EXECUTOR = "executor_missing"
REASON_BAD_SPEC = "spec_invalid"
REASON_EMPTY_PROFILE = "profile_empty"
REASON_TIMEOUT = "timeout"


def _callback_plugin_dir() -> str:
    """Directory holding the JSON-lines callback we ship."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "ansible_callbacks")


def _ansible_env() -> Dict[str, str]:
    """Environment for the ansible child.

    ``NOCOLOR``/``FORCE_COLOR`` are not cosmetic: ANSI escapes injected into the
    callback's output would break ``json.loads`` on every line.  Ansible only
    colourises for a TTY today, so this never fired in testing -- which is
    exactly why it is set explicitly rather than left to chance.
    """
    env = os.environ.copy()
    env.update(
        {
            "ANSIBLE_STDOUT_CALLBACK": "sysmanage_json",
            "ANSIBLE_CALLBACK_PLUGINS": _callback_plugin_dir(),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_FORCE_COLOR": "0",
            # Don't litter the host with .retry files it will never use.
            "ANSIBLE_RETRY_FILES_ENABLED": "0",
            # We target localhost on purpose; the warning is pure noise that
            # the parser would otherwise count as unparsed output.
            "ANSIBLE_LOCALHOST_WARNING": "False",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "False",
        }
    )
    return env


def _safe_cwd_and_env(env: Dict[str, str]) -> Tuple[str, Dict[str, str]]:
    """A working directory and HOME the child can actually use.

    Mirrors generic_deployment_plan: a deleted cwd makes the spawn itself fail,
    and a missing HOME breaks anything that wants a config directory.
    """
    try:
        safe_cwd = os.getcwd()
        if not os.access(safe_cwd, os.R_OK | os.X_OK):
            raise OSError("cwd not accessible")
    except OSError:
        safe_cwd = tempfile.gettempdir()
    home = env.get("HOME", "")
    if not home or not os.path.isdir(home):
        env["HOME"] = safe_cwd
    return safe_cwd, env


class ConfigMgmtOperations:
    """Applies configuration profiles with the host's native executor."""

    def __init__(self, agent):
        self.agent = agent
        self.logger = agent.logger

    async def apply_config_profile(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply one profile and report what it did.

        Never raises for an ordinary failure -- a host without an executor, an
        empty profile or a failing playbook all come back as a result dict, so
        the server records an outcome instead of a dropped command.
        """
        profile = parameters.get("profile") or {}
        check_mode = bool(parameters.get("check_mode"))
        timeout = int(parameters.get("timeout") or DEFAULT_TIMEOUT_SECONDS)

        # Echoed onto every outcome below. The server records the run from the
        # RESULT message, and nothing in that message carries the command's
        # parameters, so without this the stored run has no profile name and no
        # profile id -- which is why the profile column was always empty and
        # why a stored profile could not be linked to the runs it produced.
        # Same shape as package_compliance_operations, which echoes them too.
        echo = {
            key: parameters.get(key)
            for key in ("profile_id", "profile_name")
            if parameters.get(key) is not None
        }

        # A server-supplied SPEC takes precedence. It is how any engine beyond
        # the two the agent knows natively gets driven -- see config_mgmt_spec
        # for why that indirection exists. ansible-core and DSC keep their
        # built-in paths: they are the free engines, so their flags living in
        # this AGPL file costs nothing, and keeping them means an older agent
        # still works when the server has not started sending specs.
        spec = parameters.get("spec")
        if spec:
            return {**await self._apply_with_spec(spec, timeout), **echo}

        executor = locator.find_executor()
        if not executor:
            self.logger.warning(
                _("Config profile requested but no executor is installed")
            )
            return {**self._failure(REASON_NO_EXECUTOR), **echo}

        if platform.system() == "Windows":
            outcome = await self._apply_with_dsc(executor, profile, check_mode, timeout)
        else:
            outcome = await self._apply_with_ansible(
                executor, profile, check_mode, timeout
            )
        return {**outcome, **echo}

    @staticmethod
    def _failure(reason: str, **extra) -> Dict[str, Any]:
        payload = {
            "success": False,
            "changed": False,
            "reason": reason,
            "tasks": [],
        }
        payload.update(extra)
        return payload

    async def _spawn(
        self,
        argv: List[str],
        *,
        stdin_bytes: Optional[bytes],
        timeout: int,  # NOSONAR S7497 - asyncio.timeout() needs 3.11+, floor is 3.9
        env: Dict[str, str],
        cwd: str,
    ) -> Optional[Tuple[int, str, str]]:
        """Run argv, return (rc, stdout, stderr), or None on timeout.

        stdout and stderr are kept SEPARATE. dsc writes ANSI-coloured logs to
        stderr, and folding them into stdout corrupts the JSON parse.
        """
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            # Reap it: an unwaited child is the Popen leak fixed on the BSDs.
            await proc.wait()
            return None
        return (
            proc.returncode,
            (stdout or b"").decode("utf-8", errors="replace"),
            (stderr or b"").decode("utf-8", errors="replace"),
        )

    async def _apply_with_spec(
        self,
        spec: Dict[str, Any],
        timeout: int,  # NOSONAR S7497 - asyncio.timeout() needs 3.11+, floor is 3.9
    ) -> Dict[str, Any]:
        """Run a server-supplied execution spec.

        The agent contributes process handling and file hygiene; every decision
        about WHAT to run and how to read it comes from the spec.
        """
        problem = spec_mod.validate(spec)
        if problem:
            self.logger.warning(_("Refusing an unusable config spec: %s"), problem)
            return self._failure(REASON_BAD_SPEC, detail=problem)

        engine = spec.get("engine")
        executable = locator.find_engine(engine)
        if not executable:
            self.logger.warning(
                _("Config profile requested but no executor is installed")
            )
            return self._failure(REASON_NO_EXECUTOR, executor=engine)

        workdir = spec_mod.make_workdir()
        try:
            argv, stdin_bytes = spec_mod.materialise(spec, workdir)
            # Resolve the engine's own binary to the path we actually found,
            # so a spec never has to guess where it lives.
            argv[0] = executable

            env = spec_mod.child_env(spec, os.environ.copy())
            cwd, env = _safe_cwd_and_env(env)
            spawned = await self._spawn(
                argv,
                stdin_bytes=stdin_bytes,
                timeout=int(spec.get("timeout") or timeout),
                env=env,
                cwd=cwd,
            )
            if spawned is None:
                return self._failure(REASON_TIMEOUT, timeout=timeout, executor=engine)

            code, stdout, stderr = spawned
            return readers.read(spec, code, stdout, stderr, workdir)
        finally:
            self._cleanup_tree(workdir)

    def _cleanup_tree(self, workdir: str) -> None:
        """Remove a run's whole scratch tree; never mask the real result."""
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except OSError:
            self.logger.debug("Could not remove %s", workdir)

    async def _apply_with_ansible(
        self,
        executor: str,
        profile: Dict[str, Any],
        check_mode: bool,
        timeout: int,  # NOSONAR S7497 - asyncio.timeout() needs 3.11+, floor is 3.9
    ) -> Dict[str, Any]:
        """Run a playbook against localhost via a temp file."""
        playbook = profile.get("playbook")
        if not playbook or not str(playbook).strip():
            return self._failure(REASON_EMPTY_PROFILE)

        env = _ansible_env()
        cwd, env = _safe_cwd_and_env(env)

        # Owner-only dir: a profile can carry secrets, and a world-readable
        # temp file would expose them to every local user for the life of the
        # run. mkdtemp already promises this; the chmod restates it so the
        # guarantee survives someone swapping in a plain mkdir.
        workdir = tempfile.mkdtemp(prefix="sysmanage-cfg-")
        os.chmod(workdir, stat.S_IRWXU)
        path = os.path.join(workdir, "profile.yml")
        try:
            async with aiofiles.open(path, "w", encoding="utf-8") as handle:
                await handle.write(str(playbook))

            argv = [
                executor,
                "-i",
                "localhost,",
                # Pinned, not inherited from the profile: this is what keeps a
                # stray `hosts:` from becoming an outbound SSH connection.
                "-c",
                "local",
                path,
            ]
            if check_mode:
                argv.append("--check")

            spawned = await self._spawn(
                argv, stdin_bytes=None, timeout=timeout, env=env, cwd=cwd
            )
            if spawned is None:
                return self._failure(REASON_TIMEOUT, timeout=timeout)

            code, stdout, stderr = spawned
            parsed = results.parse_stream(stdout, code)
            parsed["executor"] = locator.POSIX_EXECUTOR
            parsed["check_mode"] = check_mode
            if not parsed["success"]:
                parsed["stderr"] = stderr[-4000:]
            return parsed
        finally:
            self._cleanup(workdir, path)

    def _cleanup(self, workdir: str, path: str) -> None:
        """Remove the profile and its directory; never mask the real result."""
        for remove, target in ((os.unlink, path), (os.rmdir, workdir)):
            try:
                remove(target)
            except OSError:
                self.logger.debug("Could not remove %s", target)

    async def _apply_with_dsc(
        self,
        executor: str,
        profile: Dict[str, Any],
        check_mode: bool,
        timeout: int,  # NOSONAR S7497 - asyncio.timeout() needs 3.11+, floor is 3.9
    ) -> Dict[str, Any]:
        """Apply a DSC v3 config document over stdin.

        ``--file -`` rather than ``--input <json>``: PowerShell 5.1 strips the
        embedded double quotes from an inline JSON argument, dsc then falls
        back to parsing it as YAML and dies.  Feeding stdin sidesteps the shell
        entirely (confirmed on Windows 11 ARM64 during the spike).
        """
        resources = profile.get("resources")
        if not resources:
            return self._failure(REASON_EMPTY_PROFILE)

        document = {
            "$schema": "https://aka.ms/dsc/schemas/v3/bundled/config/document.json",
            "resources": resources,
        }
        # `test` reports desired-vs-actual without changing anything, which is
        # the DSC equivalent of ansible's --check.
        operation = "test" if check_mode else "set"
        argv = [executor, "config", operation, "--file", "-"]

        env = os.environ.copy()
        cwd, env = _safe_cwd_and_env(env)
        spawned = await self._spawn(
            argv,
            stdin_bytes=json.dumps(document).encode("utf-8"),
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        if spawned is None:
            return self._failure(REASON_TIMEOUT, timeout=timeout)

        code, stdout, stderr = spawned
        return self._parse_dsc(code, stdout, stderr, check_mode)

    def _parse_dsc(
        self, code: int, stdout: str, stderr: str, check_mode: bool
    ) -> Dict[str, Any]:
        """Turn a dsc result document into the shared result shape."""
        parsed: Optional[Dict[str, Any]] = None
        try:
            parsed = json.loads(stdout) if stdout.strip() else None
        except ValueError:
            parsed = None

        if parsed is None:
            # A failing dsc run prints nothing at all to stdout, so the exit
            # code is the only evidence there is.
            return self._failure(
                "dsc_no_output" if code != 0 else "dsc_unparsable_output",
                executor=locator.WINDOWS_EXECUTOR,
                exit_code=code,
                check_mode=check_mode,
                stderr=stderr[-4000:],
            )

        entries = parsed.get("results") or []
        tasks = []
        changed_any = False
        for entry in entries:
            result = entry.get("result") or {}
            # State delta, not side effect -- see the module docstring.
            changed = bool(result.get("changedProperties"))
            changed_any = changed_any or changed
            tasks.append(
                {
                    "host": "localhost",
                    "task": entry.get("name") or entry.get("type"),
                    "status": "changed" if changed else "ok",
                    "changed": changed,
                    "msg": None,
                }
            )

        had_errors = bool(parsed.get("hadErrors"))
        success = code == 0 and not had_errors
        payload = {
            "success": success,
            "changed": changed_any,
            "tasks": tasks,
            "recap": {
                "ok": sum(1 for t in tasks if not t["changed"]),
                "changed": sum(1 for t in tasks if t["changed"]),
                "failed": 0 if success else 1,
                "skipped": 0,
                "unreachable": 0,
            },
            "exit_code": code,
            "unparsed_lines": 0,
            "executor": locator.WINDOWS_EXECUTOR,
            "check_mode": check_mode,
        }
        if not success:
            payload["stderr"] = stderr[-4000:]
        return payload
