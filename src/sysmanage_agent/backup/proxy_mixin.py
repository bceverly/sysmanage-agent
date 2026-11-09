# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""restate-proxy on both sides of a policy (server ROADMAP 25.5).

A mixin for :class:`BackupOperations`; see ``proxy_access`` for what is sent
and why.  The backed-up host makes its tokens and reports their hashes; the
storage host writes and removes the grants that name them, and audits the
proxy.  Nothing here ever logs or reports a token.
"""

import json
import os
import shutil
from typing import Any, Dict, List, Optional

from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import restate_contract as contract

PROXY_BINARIES = (
    "/usr/local/sbin/restate-proxy",
    "/usr/local/bin/restate-proxy",
    "/usr/sbin/restate-proxy",
    "/usr/bin/restate-proxy",
)


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def _read_bytes(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def proxy_binary() -> Optional[str]:
    found = shutil.which("restate-proxy")
    return found or next((p for p in PROXY_BINARIES if os.path.exists(p)), None)


class BackupProxyMixin:
    """The proxy's tokens, grants and audit, for BackupOperations."""

    async def _apply_proxy(
        self, policy: Dict[str, Any], features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Make this side's proxy files match the policy; what the configure
        reply (and the policy's saved state) says of them."""
        if policy["role"] == "host":
            return await self._apply_host_proxy(policy, features)
        if policy["role"] == "storage" and policy.get("proxy") is not None:
            return await self._apply_grants(policy)
        return {}

    async def _apply_host_proxy(
        self, policy: Dict[str, Any], features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Tokens of this host's own for the proxy: made once, kept root's
        alone, reported only as hashes.  Removed when the target is on NFS."""
        policy_id = policy["policy_id"]
        proxy = policy.get("proxy")
        if not proxy or not contract.reads_remote(features):
            for path in (access.token_path(policy_id), access.ca_path(policy_id),
                         access.token_path(policy_id, previous=True)):  # fmt: skip
                if os.path.exists(path):
                    await self._remove_root_file(path)
            return {}
        known = (self._load("policies.json").get(policy_id) or {}).get(
            "proxy_tokens"
        ) or {}
        tokens: Dict[str, str] = {}
        for key, previous in (("current", False), ("previous", True)):
            path = access.token_path(policy_id, previous)
            if previous and not proxy.get("previous_url"):
                if os.path.exists(path):
                    await self._remove_root_file(path)
                continue
            if known.get(key) and os.path.exists(path):
                tokens[key] = known[key]
                continue
            token = access.new_token()
            await self._install_root_file(token, path, mode="600")
            tokens[key] = access.token_sha256(token)
        if proxy.get("ca"):
            await self._install_root_file(proxy["ca"], access.ca_path(policy_id))
        elif os.path.exists(access.ca_path(policy_id)):
            await self._remove_root_file(access.ca_path(policy_id))
        return {"proxy_tokens": tokens}

    async def _apply_grants(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Write this host's grants; remove the ones this agent wrote for the
        target whose client the target no longer has."""
        proxy = policy["proxy"]
        written = []
        for grant in proxy["grants"]:
            text = access.render_grant(
                access.grant_repository(policy, grant), grant, proxy["target_id"]
            )
            path = access.grant_path(grant["client"])
            if _read_text(path) != text:
                await self._install_root_file(text, path)
            written.append(grant["client"])
        removed = []
        for path in access.stale_grants(
            proxy["target_id"], proxy["clients"], os.listdir, _read_text
        ):
            await self._remove_root_file(path)
            removed.append(os.path.basename(path)[: -len(".conf")])
        return {"proxy_grants": {"written": written, "removed": removed}}

    async def _proxy_audit(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The proxy as this host's clients need it: running, its certificate
        good, and each of this host's grants read as the proxy reads it."""
        proxy = policy.get("proxy") or {}
        if not proxy.get("enabled") or not proxy.get("grants"):
            return []
        binary = proxy_binary()
        if binary is None:
            return [{"code": "proxy_running", "level": "error",
                     "params": {"problem": "not_installed"}}]  # fmt: skip
        code, _out, _err = await self._run(["pgrep", "-x", "restate-proxy"])
        findings = [{"code": "proxy_running", "level": "ok" if code == 0 else "error",
                     "params": {} if code == 0 else {"problem": "stopped"}}]  # fmt: skip
        findings.append(access.certificate_finding(_read_bytes(access.PROXY_CERT)))
        code, out, _err = await self._run(
            [binary, "--check-grants", access.GRANTS_DIR, "--json"]
        )
        try:
            checked = json.loads(out) if code in (0, 2) and out else None
        except ValueError:
            checked = None
        findings += access.grant_findings(
            proxy["grants"], checked if isinstance(checked, dict) else None
        )
        return findings
