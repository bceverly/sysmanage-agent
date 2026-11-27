# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Old kernels and unneeded packages, removed safely (ROADMAP 27.8).

``apt autoremove`` is not trusted with kernels.  Debian's list of kernels to
keep is written when a kernel is INSTALLED, so after a reboot into a new
kernel it happily removes the one the host last booted successfully -- the
only fallback if the new one misbehaves, and the one Livepatch may have been
keeping safe.  So:

* the SERVER decides which kernels are protected, from the boot history only
  it holds (a kernel is proven only by a boot that stayed up); the agent adds
  the running kernel and the newest installed one whatever it is told;
* ``plan`` simulates (``apt-get -s``) and reports exactly what would go: the
  packages autoremove would drop and every package of an old kernel, minus
  anything belonging to a protected kernel;
* ``apply`` removes an explicit list -- never a bare ``autoremove`` -- after
  simulating that list and refusing if apt would take anything else with it;
* afterwards every protected kernel must still have its image and initramfs.

Debian and Ubuntu (apt) today; elsewhere the result says "unsupported".
Results go back as ``package_cleanup_result`` (``run_id`` names the run).
"""

import asyncio
import logging
import os
import re
import shutil
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from src.i18n import _
from src.sysmanage_agent.collection import kernel_state

logger = logging.getLogger(__name__)

_APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
# "Remv linux-image-6.8.0-139-generic [6.8.0-139.139]" / "Purg ..."
_SIM_LINE = re.compile(r"^(?:Remv|Purg) (\S+)")
# The "major.minor.patch-abi" a kernel package carries in its name.
_ABI = re.compile(r"(\d+\.\d+\.\d+-\d+)")
# Kernel packages, by name: never linux-firmware, linux-libc-dev or a meta
# package (linux-generic), which carry no ABI and keep the newest current.
_KERNEL_PACKAGE = re.compile(r"^linux-[a-z0-9.+-]*?\d+\.\d+\.\d+-\d+")
TIMEOUT = 1800


def abi_of(text: str) -> Optional[str]:
    """``6.8.0-151`` from a kernel release or a kernel package's name."""
    match = _ABI.search(text or "")
    return match.group(1) if match else None


def is_kernel_package(name: str) -> bool:
    return bool(_KERNEL_PACKAGE.match(name or "")) and not name.startswith(
        ("linux-libc-dev", "linux-firmware")
    )


def simulated_removals(output: str) -> List[str]:
    """Package names an ``apt-get -s`` run would remove, in order."""
    names = []
    for line in (output or "").splitlines():
        match = _SIM_LINE.match(line.strip())
        name = match.group(1).split(":")[0] if match else None
        if name and name not in names:
            names.append(name)
    return names


def protected_abis(releases: Iterable[str]) -> Set[str]:
    """The ABIs of the protected kernels, plus the running and newest
    installed kernels -- kept whatever the server says."""
    found = {abi_of(r) for r in releases or []}
    found.add(abi_of(kernel_state.running_release()))
    installed = kernel_state.installed_releases()
    if installed:
        found.add(abi_of(installed[0]))
    return {a for a in found if a}


def build_plan(
    autoremove: List[str], installed: List[str], keep: Set[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(remove, kept)``: what goes, and each kernel package kept and why."""
    remove, kept, seen = [], [], set()
    candidates = list(autoremove) + [n for n in installed if is_kernel_package(n)]
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        abi = abi_of(name) if is_kernel_package(name) else None
        if abi and abi in keep:
            kept.append({"name": name, "kernel": abi, "reason": "protected"})
            continue
        if abi or name in autoremove:
            remove.append({"name": name, "kernel": abi,
                           "reason": "old_kernel" if abi else "unneeded"})  # fmt: skip
    return remove, kept


def boot_path_problems(keep: Set[str], boot_dir: str = "/boot") -> List[str]:
    """Protected kernels whose image or initramfs is missing after removal."""
    problems = []
    for release in kernel_state.installed_releases(boot_dir):
        if abi_of(release) not in keep:
            continue
        for name in (f"vmlinuz-{release}", f"initrd.img-{release}"):
            if not os.path.exists(os.path.join(boot_dir, name)):
                problems.append(name)
    if not any(abi_of(r) in keep for r in kernel_state.installed_releases(boot_dir)):
        problems.append(_("no protected kernel is installed"))
    return problems


def unavailable_reason(_lookup=None, system: Optional[str] = None) -> Optional[str]:
    """Capability probe: the cleanup applies to apt hosts only today, so any
    other host is ``wrong_platform`` (not applicable, never "limited")."""
    import platform  # pylint: disable=import-outside-toplevel

    if (system or platform.system()) != "Linux":
        return "wrong_platform"
    if not (shutil.which("apt-get") and shutil.which("dpkg-query")):
        return "wrong_platform"
    return None


def _unsupported_text() -> Optional[str]:
    if unavailable_reason():
        return _("Package cleanup needs apt (Debian or Ubuntu)")
    return None


class PackageCleanup:
    """The agent's half of the package and kernel cleanup."""

    def __init__(self, agent_instance):
        self.agent = agent_instance
        self._tasks: set = set()

    async def _run(self, argv: List[str]) -> Tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, **_APT_ENV},
        )  # fmt: skip
        try:
            out, _err = await asyncio.wait_for(proc.communicate(), TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            return 124, _("timed out")
        return proc.returncode, (out or b"").decode("utf-8", "replace")

    async def _installed(self) -> List[str]:
        code, out = await self._run(
            ["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\n"]
        )
        if code != 0:
            raise RuntimeError(out.strip() or "dpkg-query")
        return [line.split("\t")[0] for line in out.splitlines()
                if "\t" in line and line.split("\t")[1].startswith("ii")]  # fmt: skip

    async def plan(self, keep: Set[str]) -> Dict[str, Any]:
        code, out = await self._run(["apt-get", "-s", "autoremove", "--purge"])
        if code != 0:
            return {"status": "failed", "error": out.strip()[-2000:]}
        remove, kept = build_plan(
            simulated_removals(out), await self._installed(), keep
        )
        if remove:
            check = await self._simulate([p["name"] for p in remove])
            if check.get("error"):
                return {"status": "refused", "error": check["error"],
                        "packages": remove, "kept": kept}  # fmt: skip
        return {"status": "planned", "packages": remove, "kept": kept}

    async def _simulate(self, names: List[str]) -> Dict[str, Any]:
        """apt's own answer to removing exactly ``names``: refused when it
        would take anything else, or anything of a protected kernel."""
        code, out = await self._run(["apt-get", "-s", "remove", "--purge"] + names)
        if code != 0:
            return {"error": out.strip()[-2000:]}
        extra = [n for n in simulated_removals(out) if n not in set(names)]
        if extra:
            return {"error": _("apt would also remove: %s") % ", ".join(extra[:20])}
        return {}

    async def apply(
        self, keep: Set[str], approved: List[str], approve_plan: bool = False
    ) -> Dict[str, Any]:
        """Remove ``approved`` -- or, after an automatic update run
        (``approve_plan``), this fresh plan -- and nothing else."""
        fresh = await self.plan(keep)
        if fresh["status"] != "planned":
            return fresh
        planned = {p["name"]: p for p in fresh["packages"]}
        names = list(planned) if approve_plan else [n for n in approved if n in planned]
        if not names:
            return {"status": "done", "packages": [], "kept": fresh["kept"]}
        check = await self._simulate(names)
        if check.get("error"):
            return {"status": "refused", "error": check["error"],
                    "packages": [planned[n] for n in names], "kept": fresh["kept"]}  # fmt: skip
        code, out = await self._run(
            ["sudo", "apt-get", "remove", "--purge", "-y"] + names
        )
        result = {"packages": [planned[n] for n in names], "kept": fresh["kept"]}
        if code != 0:
            return dict(result, status="failed", error=out.strip()[-2000:])
        problems = boot_path_problems(keep)
        if problems:
            return dict(result, status="boot_path_broken", error=", ".join(problems))
        return dict(result, status="done")

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        reason = _unsupported_text()
        if reason:
            return {"status": "unsupported", "error": reason}
        keep = protected_abis(parameters.get("protected_releases") or [])
        try:
            if parameters.get("mode") == "apply":
                approved = [str(n) for n in parameters.get("approved") or []]
                return await self.apply(
                    keep, approved, bool(parameters.get("approve_plan"))
                )
            return await self.plan(keep)
        except Exception as error:  # pylint: disable=broad-except
            logger.exception("package cleanup failed")
            return {"status": "failed", "error": str(error)[:2000]}

    async def _report(self, parameters: Dict[str, Any]) -> None:
        result = await self.execute(parameters)
        payload = dict(result, run_id=parameters.get("run_id"),
                       mode=parameters.get("mode") or "plan",
                       running_kernel=kernel_state.running_release())  # fmt: skip
        approval = self.agent.registration_manager.get_host_approval_from_db()
        if approval:
            payload["host_id"] = str(approval.host_id)
        message = self.agent.create_message("package_cleanup_result", payload)
        if not await self.agent.send_message(message):
            logger.warning("Could not queue the package cleanup result")

    async def package_cleanup(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Start a plan or an apply; the result follows as its own message."""
        if not parameters.get("run_id"):
            return {"success": False, "error": _("run_id is required")}
        task = asyncio.ensure_future(self._report(parameters))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return {"success": True, "started": True}
