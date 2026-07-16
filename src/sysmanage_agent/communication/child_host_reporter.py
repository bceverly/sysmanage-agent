# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Periodic agent-driven child host listing reporter (post-cutover home).

Drop-in replacement for ``communication/child_host_collector.ChildHostCollector``
that does not depend on the legacy ``operations/child_host_*`` cluster.

Responsibilities (mirroring the legacy collector's public surface):

* :meth:`send_child_hosts_update` — runs the same hypervisor-listing
  shell that the engine's ``build_list_child_hosts_plan`` emits, parses
  the section-delimited stdout, enriches bhyve rows from
  ``/vm/metadata/<name>.json``, and ships a ``child_host_list_update``
  message to the server.

* :meth:`child_host_heartbeat` — periodic 60 s loop calling
  :meth:`send_child_hosts_update`.  On Windows hosts it also drives
  the WSL keep-alive lifecycle (``~/.wslconfig`` + per-distro
  ``sleep infinity`` Popen) via :class:`WslKeepalive`.

Switching from the legacy collector is a one-line import change in
``data_collector.py``:

    # before:
    from src.sysmanage_agent.communication.child_host_collector import ChildHostCollector
    self.child_host_collector = ChildHostCollector(agent_instance)

    # after:
    from src.sysmanage_agent.communication.child_host_reporter import ChildHostReporter
    self.child_host_collector = ChildHostReporter(agent_instance)

The legacy collector and this reporter MUST NOT both be wired in
concurrently — they each ship periodic ``child_host_list_update``
messages and would generate duplicates.

The hypervisor-listing shell is duplicated from the engine here so the
reporter doesn't need the engine ``.so`` to be loadable on the agent
side (which would be odd — the engine is server-side Pro+ binary, not
agent-side).  When the engine adds new sections in the future, mirror
the change here.
"""

import asyncio
import json
import logging
import platform
import subprocess  # nosec B404 # required for hypervisor list shell
from typing import Any, Dict, List, TYPE_CHECKING

from src.i18n import _
from src.sysmanage_agent.wsl.keepalive import WslKeepalive, is_windows

if TYPE_CHECKING:
    from main import SysManageAgent  # noqa: F401


# Same shell as virtualization_engine container_engine.build_list_child_hosts_plan.
# Kept duplicated rather than imported from the engine because the engine is a
# server-side Pro+ binary and we don't want the agent to depend on it being
# loadable agent-side.  Update both when adding new sections.
_LISTING_SHELL = (
    "set +e\n"
    "echo '===LXD==='\n"
    "command -v lxc >/dev/null 2>&1 && lxc list --format json 2>/dev/null || echo '[]'\n"
    "echo '===KVM==='\n"
    "command -v virsh >/dev/null 2>&1 && sudo virsh list --all 2>/dev/null || true\n"
    "echo '===BHYVE==='\n"
    "command -v vm >/dev/null 2>&1 && sudo vm list 2>/dev/null || true\n"
    "echo '===BHYVE_META==='\n"
    "if [ -d /vm/metadata ]; then\n"
    "  for f in /vm/metadata/*.json; do\n"
    '    [ -f "$f" ] || continue\n'
    '    cat "$f"\n'
    "    echo\n"
    "  done\n"
    "fi\n"
    "echo '===VMM==='\n"
    "command -v vmctl >/dev/null 2>&1 && sudo vmctl status 2>/dev/null || true\n"
    "echo '===WSL==='\n"
    "command -v wsl >/dev/null 2>&1 && wsl --list --verbose 2>/dev/null || true\n"
    "exit 0\n"
)


def _split_section_blocks(stdout: str) -> Dict[str, str]:
    """Split sectioned listing-shell stdout into ``{section_name: block_text}``."""
    blocks: Dict[str, str] = {}
    current: str = ""
    buf: List[str] = []
    for raw in stdout.splitlines():
        if raw.startswith("===") and raw.rstrip().endswith("==="):
            if current:
                blocks[current] = "\n".join(buf)
            current = raw.strip("=").strip().lower()
            buf = []
            continue
        if current:
            buf.append(raw)
    if current:
        blocks[current] = "\n".join(buf)
    return blocks


def _normalize_status(state: str) -> str:
    """Map raw hypervisor state strings to the canonical sysmanage status set."""
    canonical = (state or "").strip().lower()
    if canonical in ("running", "up"):
        return "running"
    if canonical in ("stopped", "shut", "off", "halted"):
        return "stopped"
    return canonical or "unknown"


def _parse_lxd(text: str) -> List[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    out: List[Dict[str, Any]] = []
    for item in data:
        name = item.get("name") or ""
        if not name:
            continue
        out.append(
            {
                "child_name": name,
                "child_type": "lxd",
                "status": _normalize_status(item.get("status") or ""),
            }
        )
    return out


def _parse_kvm(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_header = False
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        if not seen_header:
            if stripped.lstrip().startswith("Id"):
                seen_header = True
            continue
        if stripped.lstrip().startswith("---"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        # virsh list --all: "Id   Name   State"
        # State may be one or two tokens (e.g. "shut off").
        name = parts[1]
        state = " ".join(parts[2:])
        out.append(
            {
                "child_name": name,
                "child_type": "kvm",
                "status": _normalize_status(state),
            }
        )
    return out


def _parse_bhyve(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_header = False
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        if not seen_header:
            if stripped.lstrip().startswith("NAME"):
                seen_header = True
            continue
        parts = stripped.split()
        if not parts:
            continue
        state = parts[-1] if parts else ""
        if state.startswith("(") and len(parts) >= 2:
            state = parts[-2]
        out.append(
            {
                "child_name": parts[0],
                "child_type": "bhyve",
                "status": _normalize_status(state),
            }
        )
    return out


def _iter_top_level_json_objects(text: str):
    """Yield each top-level ``{...}`` document substring from concatenated JSON.

    Walks ``text`` character-by-character tracking brace depth; emits the
    buffered substring each time depth returns to zero.  Used by
    :func:`_parse_bhyve_meta` to split the ``===BHYVE_META===`` block
    (which is one JSON object per ``/vm/metadata/<name>.json`` file
    concatenated together with newlines) into individually-parseable
    documents.
    """
    buf = ""
    depth = 0
    for char in text:
        if char == "{":
            if depth == 0:
                buf = ""
            depth += 1
        if depth > 0:
            buf += char
        if char == "}":
            depth -= 1
            if depth == 0 and buf.strip():
                yield buf
                buf = ""


def _parse_bhyve_meta(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse the ``===BHYVE_META===`` block: concatenated JSON objects."""
    if not text or not text.strip():
        return {}
    metas: Dict[str, Dict[str, Any]] = {}
    for doc in _iter_top_level_json_objects(text):
        try:
            obj = json.loads(doc)
        except (TypeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        name = obj.get("vm_name") or ""
        if name:
            metas[name] = obj
    return metas


def _parse_vmm(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_header = False
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        if not seen_header:
            if stripped.lstrip().startswith("ID"):
                seen_header = True
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        out.append(
            {
                "child_name": parts[-1],
                "child_type": "vmm",
                "status": "running",
            }
        )
    return out


def _parse_wsl(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_header = False
    for line in text.splitlines():
        stripped = line.strip("﻿").rstrip()
        if not stripped.strip():
            continue
        if not seen_header:
            if "NAME" in stripped and "STATE" in stripped:
                seen_header = True
            continue
        if stripped.lstrip().startswith("*"):
            stripped = stripped.lstrip().lstrip("*").lstrip()
        parts = stripped.split()
        if len(parts) < 2:
            continue
        out.append(
            {
                "child_name": parts[0],
                "child_type": "wsl",
                "status": _normalize_status(parts[1]),
            }
        )
    return out


def _parse_listing_stdout(stdout: str) -> List[Dict[str, Any]]:
    """Parse the listing shell's section-delimited stdout into child host rows.

    Mirrors the OSS-side ``proplus_dispatch._parse_list_child_hosts_stdout``
    parser, including the bhyve metadata enrichment that lifts hostname
    / vm_ip / distribution out of ``/vm/metadata/<name>.json`` and
    attaches them to the bhyve listing rows.
    """
    blocks = _split_section_blocks(stdout)
    children: List[Dict[str, Any]] = []
    children.extend(_parse_lxd(blocks.get("lxd", "")))
    children.extend(_parse_kvm(blocks.get("kvm", "")))
    bhyve_children = _parse_bhyve(blocks.get("bhyve", ""))
    bhyve_metas = _parse_bhyve_meta(blocks.get("bhyve_meta", ""))
    for child in bhyve_children:
        meta = bhyve_metas.get(child["child_name"])
        if meta:
            if meta.get("hostname"):
                child["hostname"] = meta["hostname"]
            if meta.get("vm_ip"):
                child["vm_ip"] = meta["vm_ip"]
            if meta.get("distribution"):
                child["distribution"] = {"distribution_name": meta["distribution"]}
    children.extend(bhyve_children)
    children.extend(_parse_vmm(blocks.get("vmm", "")))
    children.extend(_parse_wsl(blocks.get("wsl", "")))
    return children


class ChildHostReporter:
    """Periodic agent-driven child host listing reporter.

    Same constructor signature as the legacy ``ChildHostCollector`` so
    a swap in ``data_collector.py`` is one-line.  The agent reference
    is held only so we can call ``self.agent.create_message`` /
    ``self.agent.send_message`` and read host_id from the registration
    manager.
    """

    def __init__(self, agent_instance: "SysManageAgent"):
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)
        self._wsl_keepalive = WslKeepalive(self.logger)

    # ------------------------------------------------------------------
    # Listing shell + send
    # ------------------------------------------------------------------

    def _run_listing_shell(self) -> str:
        """Run the listing shell and return its stdout (or empty string on failure)."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sh", "-c", _LISTING_SHELL],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return result.stdout or ""
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.debug("Listing shell failed: %s", exc)
            return ""

    async def send_child_hosts_update(self) -> None:
        """Run the listing shell and ship a ``child_host_list_update`` to the server."""
        os_type = platform.system().lower()
        if os_type not in ("windows", "linux", "openbsd", "freebsd"):
            return
        try:
            stdout = self._run_listing_shell()
            child_hosts = _parse_listing_stdout(stdout)

            child_hosts_info: Dict[str, Any] = {
                "success": True,
                "child_hosts": child_hosts,
                "count": len(child_hosts),
                "hostname": self.agent.registration.get_system_info()["hostname"],
            }
            host_approval = self.agent.registration_manager.get_host_approval_from_db()
            if host_approval:
                child_hosts_info["host_id"] = str(host_approval.host_id)

            message = self.agent.create_message(
                "child_host_list_update", child_hosts_info
            )
            self.logger.debug(
                "AGENT_DEBUG: Sending child hosts message: %s", message["message_id"]
            )
            success = await self.agent.send_message(message)
            if success:
                self.logger.debug(
                    "AGENT_DEBUG: Child hosts data sent successfully (%d hosts)",
                    len(child_hosts),
                )
            else:
                self.logger.warning(_("Failed to send child hosts data"))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self.logger.error(_("Error collecting/sending child hosts data: %s"), exc)

    # ------------------------------------------------------------------
    # Periodic loop + Windows-specific keep-alive integration
    # ------------------------------------------------------------------

    async def child_host_heartbeat(self) -> None:
        """60 s loop: keep WSL alive on Windows, then ship a listing update."""
        self.logger.debug("Child host heartbeat started")

        if is_windows():
            if self._wsl_keepalive.ensure_wslconfig():
                self._wsl_keepalive.restart_wsl()
            self.logger.info(_("Starting WSL keep-alive processes"))
            self._wsl_keepalive.ensure_keepalive_processes()

        heartbeat_interval = 60
        try:
            while self.agent.running:
                try:
                    await asyncio.sleep(heartbeat_interval)
                    if is_windows():
                        self._wsl_keepalive.ensure_keepalive_processes()
                    await self.send_child_hosts_update()
                    self.logger.debug("AGENT_DEBUG: Child host heartbeat completed")
                except asyncio.CancelledError:
                    self.logger.debug("Child host heartbeat cancelled")
                    raise
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    self.logger.error(_("Child host heartbeat error: %s"), exc)
                    continue
        finally:
            if is_windows():
                self.logger.info(_("Stopping WSL keep-alive processes"))
            self._wsl_keepalive.stop_all_keepalive_processes()
