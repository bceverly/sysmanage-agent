# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Decryption keys for ONE restate job (Pro+ backup_engine, 24.6 S4).

A restore, listing or what-changed of an encrypted repository arrives with
``needs_key: true`` and no key: commands travel through the server's
database-backed queue, so the key never goes there.  The agent fetches the
run's keys over HTTPS with its own credentials (``POST /api/agent/backup-key``,
the poll's connection token and host token; the server hands them out once
per run), and restate reads them with ``decrypt_with``:

* each key is written to a private file on tmpfs (``/dev/shm``), installed
  root-owned 0600 under ``KEY_DIR`` (``/run``, tmpfs) and the staged copy
  removed at once -- the key never touches a disk;
* restate's checks pass: a regular file, root's, readable by no one else, in
  a root-owned directory writable by no one else;
* the files are removed when the run ends -- and at agent start, any a crash
  left behind (``stale``).

Nothing here logs a key; messages name the run at most.
"""

import os
import posixpath
import re
import tempfile
from typing import Any, Dict, Iterable, List, Optional

from src.i18n import _

KEY_DIR = "/run/sysmanage-agent/backup-keys"
# tmpfs, so the key never reaches a disk: stage() makes a 0600 file there
# with mkstemp (O_EXCL, random name), so no other user can plant the path.
_STAGE_DIRS = ("/dev/shm", "/run/shm")  # NOSONAR  # nosec B108
_KEY_NAME = re.compile(r"^[0-9a-f-]{36}-\d{1,2}\.key$")
# The armor header's marker, without the dashes that make a secret scanner
# take this check for a key.
_ARMORED = "BEGIN PGP PRIVATE KEY BLOCK"
MAX_KEYS = 16


class KeyFetchError(Exception):
    """The run's keys could not be had; the message says why (never a key)."""


def key_path(run_id: str, index: int) -> str:
    return posixpath.join(KEY_DIR, f"{run_id}-{index}.key")


def check_keys(answer: Any) -> List[str]:
    """The server's ``{"keys": [...]}``: armored OpenPGP secret keys only."""
    keys = answer.get("keys") if isinstance(answer, dict) else None
    if not isinstance(keys, list) or not keys or len(keys) > MAX_KEYS:
        raise KeyFetchError(_("The server sent no usable keys"))
    if not all(isinstance(k, str) and _ARMORED in k for k in keys):
        raise KeyFetchError(_("The server sent something that is not a secret key"))
    return keys


def stage(content: str, dirs: Iterable[str] = _STAGE_DIRS) -> str:
    """A private (0600) file on tmpfs holding ``content``; its path."""
    where = next((d for d in dirs if os.path.isdir(d)), None)
    if where is None:
        raise KeyFetchError(_("No tmpfs to stage the key on"))
    handle, path = tempfile.mkstemp(dir=where, prefix=".sysmanage-key-")
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(content)
    return path


def install_argv(staged: str, dest: str) -> List[str]:
    """Root-owned 0600; ``-D`` makes the directory root's 0755 if missing."""
    return ["install", "-D", "-m", "600", "-o", "0", "-g", "0", "--", staged, dest]


def remove_argv(paths: List[str]) -> List[str]:
    return ["rm", "-f", "--"] + list(paths)


def stale(names: Iterable[str], keep: Iterable[str]) -> List[str]:
    """Key files in KEY_DIR that no running job owns (a crash left them)."""
    kept = set(keep)
    return [
        key_path_of(name)
        for name in names
        if _KEY_NAME.match(name) and key_path_of(name) not in kept
    ]


def key_path_of(name: str) -> str:
    return posixpath.join(KEY_DIR, name)


async def fetch(agent: Any, run_id: str, session_factory=None) -> List[str]:
    """The run's keys from the server, over HTTPS (never the queue)."""
    # pylint: disable=import-outside-toplevel
    import aiohttp

    from src.sysmanage_agent.core.server_endpoint import ServerEndpoint

    endpoint = ServerEndpoint(agent.config)
    approval = agent.registration_manager.get_host_approval_from_db()
    host_id = str(getattr(approval, "host_id", "") or "")
    if not host_id:
        raise KeyFetchError(_("This host is not approved yet"))
    token = await agent.get_auth_token()
    host_token = await agent.get_stored_host_token()
    factory = session_factory or (
        lambda: aiohttp.ClientSession(**endpoint.session_kwargs())
    )
    async with factory() as session, session.post(
        endpoint.rest_url("/api/agent/backup-key"),
        json={"host_id": host_id, "run_id": run_id},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Host-Token": host_token or "",
        },
        proxy=endpoint.proxy(),
    ) as response:
        if response.status != 200:
            detail = await _detail(response)
            raise KeyFetchError(
                _(
                    "The server did not release the backup key: HTTP %(status)s, %(detail)s"
                )
                % {"status": response.status, "detail": detail}
            )
        return check_keys(await response.json())


async def _detail(response) -> str:
    try:
        body: Optional[Dict[str, Any]] = await response.json()
    except Exception:  # pylint: disable=broad-except
        return _("no reason given")
    detail = body.get("detail") if isinstance(body, dict) else None
    return str(detail)[:200] if detail else "no reason given"


async def install(keys: List[str], run_id: str, run, privileged) -> List[str]:
    """Install ``keys`` for ``run_id``; their paths.  ``run`` / ``privileged``
    are the agent's own subprocess helpers.  A failure removes what was
    installed and raises KeyFetchError."""
    paths: List[str] = []
    try:
        for index, key in enumerate(keys):
            staged = stage(key)
            try:
                dest = key_path(run_id, index)
                code, _out, err = await run(privileged(install_argv(staged, dest)))
            finally:
                os.unlink(staged)
            if code != 0:
                raise KeyFetchError(
                    _("Could not install the backup key: %s") % (err or code)
                )
            paths.append(dest)
    except BaseException:
        await remove(paths, run, privileged)
        raise
    return paths


async def remove(paths: List[str], run, privileged) -> None:
    """Remove key files; never raises (a stale one is swept at start)."""
    if not paths:
        return
    try:
        await run(privileged(remove_argv(paths)))
    except Exception:  # pylint: disable=broad-except
        pass


async def sweep(inflight: Dict[str, Any], run, privileged, listdir=os.listdir) -> None:
    """At agent start: remove key files no running job owns."""
    try:
        names = listdir(KEY_DIR)
    except OSError:
        return
    owned = [p for record in inflight.values() if isinstance(record, dict)
             for p in record.get("key_files") or []]  # fmt: skip
    await remove(stale(names, owned), run, privileged)


async def for_run(
    agent, features, run_id: str, params: Dict[str, Any], run, privileged
):
    """The key files a run needs (``needs_key``: an encrypted repository),
    fetched for this run only; [] when it needs none."""
    # pylint: disable=import-outside-toplevel,too-many-arguments,too-many-positional-arguments
    from src.sysmanage_agent.backup import restate_contract as contract
    from src.sysmanage_agent.backup.job_validation import PolicyError

    if not params.get("needs_key"):
        return []
    if not contract.supports(features, "decrypt_with"):
        raise PolicyError(
            _("This restate cannot decrypt an encrypted repository; upgrade restate.")
        )
    return await install(await fetch(agent, run_id), run_id, run, privileged)


def refusal_code(error: Exception) -> str:
    """The agent's refusal reason for a job that could not be set up."""
    if isinstance(error, KeyFetchError):
        return "key_unavailable"
    return "install_failed" if isinstance(error, OSError) else "invalid_request"
