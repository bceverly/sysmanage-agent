# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The detached off-site run (server ROADMAP 27.3)::

    python -m src.sysmanage_agent.offsite_cloud.runner RUN_DIR ZFS_PATH

The agent starts it in a session of its own, so it outlives an agent
restart (the agent's unit stops only its main process), writes the
credentials and the key to its standard input as one JSON line and closes
it.  The run holds ``RUN_DIR/run.lock`` for as long as it lives, reads
``job.json``, and leaves ``result.json`` for the agent to report.
"""

import datetime
import json
import os
import sys
from typing import Any, Dict, Optional, TextIO

from src.sysmanage_agent.offsite_cloud import crypto
from src.sysmanage_agent.offsite_cloud import job as jobs
from src.sysmanage_agent.offsite_cloud import runfiles
from src.sysmanage_agent.offsite_cloud import s3
from src.sysmanage_agent.offsite_cloud.restore import Restore
from src.sysmanage_agent.offsite_cloud.upload import Upload, Zfs, decode_key

CHECK_DAYS = 1


def read_secrets(stream: TextIO) -> Dict[str, Any]:
    line = stream.readline(65536)
    try:
        secrets = json.loads(line)
    except ValueError as error:
        raise ValueError("no credentials on standard input") from error
    if (
        not isinstance(secrets, dict)
        or not secrets.get("access_key")
        or not secrets.get("secret_key")
    ):
        raise ValueError("no credentials on standard input")
    secrets["key_bytes"] = decode_key(str(secrets.get("key") or ""))
    return secrets


def client_for(job: Dict[str, Any], secrets: Dict[str, Any]) -> s3.Client:
    return s3.Client(
        job["bucket"], job["region"], secrets["access_key"], secrets["secret_key"],
        endpoint=job.get("endpoint"), session_token=secrets.get("session_token") or None,
    )  # fmt: skip


def check(job: Dict[str, Any], key: bytes, client: s3.Client) -> Dict[str, Any]:
    """Prove the credentials can upload (a small encrypted canary that S3
    keeps a day) and say whether the bucket has Object Lock on."""
    from src.sysmanage_agent.offsite_cloud.upload import (
        object_key,
    )  # pylint: disable=import-outside-toplevel

    now = datetime.datetime.now(datetime.timezone.utc)
    blob = crypto.seal_bytes(key, job["run_id"], 0, now.isoformat().encode("utf-8"))
    canary = object_key(job["prefix"], f"d{CHECK_DAYS}", "check", job["copy_id"])
    lock = client.object_lock()
    client.put_bytes(
        canary, blob, now + datetime.timedelta(days=CHECK_DAYS) if lock else None
    )
    return {"run_id": job["run_id"], "copy_id": job["copy_id"], "status": "ok",
            "object_lock": lock, "key_id": crypto.key_id(key), "canary": canary,
            "finished_at": now.isoformat()}  # fmt: skip


def run(directory: str, zfs_path: str, stdin: TextIO) -> Dict[str, Any]:
    raw = runfiles.read_json(os.path.join(directory, runfiles.JOB))
    if raw is None:
        raise ValueError("no job file")
    job = jobs.validate(raw)
    secrets = read_secrets(stdin)
    client = client_for(job, secrets)
    zfs = Zfs(zfs_path, sudo=not (hasattr(os, "geteuid") and os.geteuid() == 0))
    if job["action"] == jobs.UPLOAD:
        return Upload(job, secrets["key_bytes"], directory, zfs, client).run()
    if job["action"] == jobs.RESTORE:
        return Restore(job, secrets["key_bytes"], directory, zfs, client).run()
    return check(job, secrets["key_bytes"], client)


def main(argv: Optional[list] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or not os.path.isabs(argv[0]):
        print("usage: runner RUN_DIR ZFS_PATH", file=sys.stderr)
        return 2
    directory = argv[0]
    lock = runfiles.take_lock(directory)
    if lock is None:
        print("another off-site run holds this copy", file=sys.stderr)
        return 3
    try:
        try:
            result = run(directory, argv[1], sys.stdin)
        except (ValueError, jobs.JobError, OSError, s3.S3Error) as error:
            raw = runfiles.read_json(os.path.join(directory, runfiles.JOB)) or {}
            result = {"run_id": raw.get("run_id"), "copy_id": raw.get("copy_id"),
                      "status": "failed", "errors": [str(error)]}  # fmt: skip
        runfiles.write_json(os.path.join(directory, runfiles.RESULT), result)
        print(
            f"off-site run {result.get('run_id')}: {result.get('status')}", flush=True
        )
    finally:
        lock.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
