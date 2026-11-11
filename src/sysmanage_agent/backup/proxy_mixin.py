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
import platform
import shutil
from typing import Any, Dict, List, Optional

from src.sysmanage_agent.backup import host_mount
from src.sysmanage_agent.backup import proxy_access as access
from src.sysmanage_agent.backup import proxy_service as service
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
        return {
            "proxy_grants": {"written": written, "removed": removed},
            **await self._apply_proxy_service(policy),
        }

    # --- the proxy as a service (backup/proxy_service.py) -----------------

    async def _apply_proxy_service(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Run restate-proxy as the repositories' account, with its
        certificate; what the configure reply says of it (``proxy_csr`` when
        a certificate is wanted)."""
        proxy = policy["proxy"]
        account = policy.get("service_account") or "restate"
        if not proxy["enabled"]:
            await self._stop_proxy_service(account)
            return {}
        if proxy_binary() is None:
            return {"proxy_service": "not_installed"}
        await self._run_proxy_as(account)
        out: Dict[str, Any] = {}
        changed = False
        if proxy.get("cert"):
            changed, csr = await self._apply_proxy_cert(proxy["cert"], account)
            if csr:
                out["proxy_csr"] = csr
        if os.path.exists(access.PROXY_CERT) and os.path.exists(access.PROXY_KEY):
            await self._start_proxy_service(restart=changed)
            out["proxy_service"] = "started"
        return out

    async def _apply_proxy_cert(self, cert: Dict[str, Any], account: str):
        """Install the certificate the server signed for this host's pending
        key, or ask for one; ``(installed something, request or None)``."""
        pending_path = service.pending_path(self._backup_dir())
        pending = service.load_key(_read_text(pending_path))
        pem = cert["pem"]
        if pem and pending is not None and service.same_key(pending, pem):
            await self._install_root_file(
                service.key_pem(pending), access.PROXY_KEY, mode="600"
            )
            await self._run(self._privileged(
                ["chown", f"{account}:{account}", access.PROXY_KEY]))  # fmt: skip
            await self._install_root_file(pem, access.PROXY_CERT)
            os.unlink(pending_path)
            return True, None
        installed = _read_text(access.PROXY_CERT)
        if not cert["renew"] and (not pem or installed == pem):
            return False, None
        # Wanted: a new one, or the server holds one this host has no key
        # for (it is issued again for the key this host does hold).
        if pending is None:
            self._ensure_dirs()
            pending = service.new_key()
            service.write_private(pending_path, service.key_pem(pending))
        return False, service.csr_pem(pending, cert["name"])

    def _proxy_systemd(self) -> bool:
        return platform.system() == "Linux" and host_mount.systemd_running()

    async def _run_proxy_as(self, account: str) -> None:
        if self._proxy_systemd():
            text = service.drop_in(account)
            if _read_text(service.DROP_IN) != text:
                await self._install_root_file(text, service.DROP_IN)
                await self._run(self._privileged(["systemctl", "daemon-reload"]))
        elif platform.system() == "FreeBSD":
            await self._run(
                self._privileged(["sysrc", *service.freebsd_settings(account)])
            )

    async def _start_proxy_service(self, restart: bool) -> None:
        if self._proxy_systemd():
            await self._run(self._privileged(["systemctl", "enable", service.UNIT]))
            action = "restart" if restart else "start"
            await self._run(self._privileged(["systemctl", action, service.UNIT]))
        elif platform.system() == "FreeBSD":
            await self._run(self._privileged(["sysrc", "restate_proxy_enable=YES"]))
            action = "restart" if restart else "start"
            await self._run(
                self._privileged(["service", service.FREEBSD_SERVICE, action])
            )

    async def _stop_proxy_service(self, account: str) -> None:
        """Back on NFS: stop and disable the service this agent turned on --
        never one an operator runs by hand (no drop-in, no knob of ours)."""
        if self._proxy_systemd():
            if not os.path.exists(service.DROP_IN):
                return
            await self._run(self._privileged(["systemctl", "disable", service.UNIT]))
            await self._run(self._privileged(["systemctl", "stop", service.UNIT]))
            await self._remove_root_file(service.DROP_IN)
            await self._run(self._privileged(["systemctl", "daemon-reload"]))
        elif platform.system() == "FreeBSD":
            code, out, _err = await self._run(["sysrc", "-n", "restate_proxy_user"])
            if code != 0 or out.strip() != account:
                return
            await self._run(
                self._privileged(["service", service.FREEBSD_SERVICE, "stop"])
            )
            await self._run(self._privileged(["sysrc", "restate_proxy_enable=NO"]))

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
