# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The way back from the off-site copy (server ROADMAP 27.3) -- Community.

Works with no license and after a lapse ("never hold safety hostage").
Deep Archive takes 12 to 48 hours to thaw, so one detached run does both
steps and survives the wait:

1. THAW: ask S3 to restore every part of the chain -- a full and the
   incrementals after it, in order -- for ``thaw_days``, then look again
   every ``poll_seconds`` until all of them are readable (an object in
   S3 Standard is readable at once).
2. RECEIVE: per stream, in order, each part is downloaded to a spool file,
   checked against the manifest's size and SHA-256, decrypted (which also
   proves it is that stream's part at that place) and written to
   ``zfs receive -u <dataset>``.  The full makes the dataset -- one that
   does not exist yet, never over a live one -- and each incremental adds
   its snapshot.

The restored dataset holds the repository as it was; restate restores from
it like from any other repository.
"""

import datetime
import hashlib
import os
import time
from typing import Any, Callable, Dict, List

from src.sysmanage_agent.offsite_cloud import crypto
from src.sysmanage_agent.offsite_cloud import datasets as ds
from src.sysmanage_agent.offsite_cloud import runfiles
from src.sysmanage_agent.offsite_cloud import s3
from src.sysmanage_agent.offsite_cloud.upload import Zfs, ZfsError

OK, FAILED, INTERRUPTED = "ok", "failed", "interrupted"
POLL_SECONDS = 15 * 60
MAX_WAIT = datetime.timedelta(days=4)


class RestoreError(RuntimeError):
    """The chain cannot be restored as asked."""


def check_chain(streams: List[Dict[str, Any]]) -> None:
    """A full first, then incrementals each on the snapshot before it."""
    if not streams:
        raise RestoreError("nothing to restore")
    if streams[0].get("kind") != "full":
        raise RestoreError("a restore starts from a full copy")
    for before, after in zip(streams, streams[1:]):
        if after.get("kind") != "incremental" or after.get(
            "base_snapshot"
        ) != before.get("snapshot"):
            raise RestoreError("the incrementals do not follow on from each other")
    for stream in streams:
        ds.valid_snapshot(stream.get("snapshot"))
        if not stream.get("parts"):
            raise RestoreError("a stream with no parts")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Restore:  # pylint: disable=too-many-instance-attributes
    """One thaw-and-receive run."""

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __init__(
        self, job: Dict[str, Any], key: bytes, directory: str, zfs: Zfs,
        client: s3.Client, now: Callable[[], datetime.datetime] = _now,
        sleep: Callable[[float], None] = time.sleep,
    ):  # fmt: skip
        self.job = job
        self.key = key
        self.dir = directory
        self.zfs = zfs
        self.client = client
        self.now = now
        self.sleep = sleep
        self.streams = job["streams"]
        self.target = ds.valid_dataset(job["target_dataset"])
        self.received = 0

    def _status(self, phase: str, **extra: Any) -> None:
        runfiles.write_json(os.path.join(self.dir, runfiles.STATUS), dict(
            extra, run_id=self.job["run_id"], phase=phase, bytes_received=self.received,
            updated_at=self.now().isoformat(),
        ))  # fmt: skip

    def _parts(self) -> List[Dict[str, Any]]:
        return [p for s in self.streams for p in s["parts"]]

    def thaw(self) -> None:
        days = int(self.job.get("thaw_days") or 7)
        tier = self.job.get("tier") or "Bulk"
        parts = self._parts()
        for part in parts:
            if s3.restore_state(self.client.head(part["key"])) == "archived":
                self.client.restore(part["key"], days, tier)
        started = self.now()
        while True:
            states = [s3.restore_state(self.client.head(p["key"])) for p in parts]
            if "missing" in states:
                raise RestoreError("a part of the copy is not in the bucket")
            ready = states.count("ready")
            self._status("thawing", parts_ready=ready, parts_total=len(parts))
            if ready == len(parts):
                return
            if self.now() - started > MAX_WAIT:
                raise RestoreError("the thaw did not finish in four days")
            self.sleep(int(self.job.get("poll_seconds") or POLL_SECONDS))

    def _exists(self) -> bool:
        found = ds.filesystems(self.zfs.run(ds.list_filesystems(), privileged=False))
        return self.target in found

    def _receive_stream(self, stream: Dict[str, Any], spool: str) -> None:
        proc = self.zfs.stream_in(ds.receive(self.target))
        failure = None
        try:
            for part in sorted(stream["parts"], key=lambda p: p["index"]):
                self._fetch(part, spool)
                with open(spool, "rb") as handle:
                    self.received += crypto.decrypt_object(
                        handle.read, proc.stdin.write, self.key, stream["stream_id"],
                        part["index"],
                    )  # fmt: skip
                runfiles.remove(spool)
                self._status(
                    "receiving", snapshot=stream["snapshot"], part=part["index"]
                )
        except BaseException as error:  # stop zfs receive, which then discards
            failure = error
            raise
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass
            err = proc.stderr.read().decode("utf-8", "replace").strip()
            code = proc.wait()
            if failure is None and code != 0:
                raise ZfsError(f"zfs receive: {err or code}")

    def _fetch(self, part: Dict[str, Any], spool: str) -> None:
        digest = hashlib.sha256()
        with open(spool, "wb") as out:
            os.chmod(spool, 0o600)

            def sink(block: bytes) -> None:
                digest.update(block)
                out.write(block)

            self.client.get_to(part["key"], sink)
        if (
            os.path.getsize(spool) != int(part["bytes"])
            or digest.hexdigest() != part["sha256"]
        ):
            raise crypto.DecryptError(f"part {part['index']} is not what was uploaded")

    def run(self) -> Dict[str, Any]:
        try:
            check_chain(self.streams)
            if self._exists():
                raise RestoreError(
                    f"{self.target} already exists; restore into a new dataset"
                )
            self.thaw()
            spool = os.path.join(
                runfiles.ensure(os.path.join(self.dir, runfiles.SPOOL)), "part"
            )
            for stream in self.streams:
                self._receive_stream(stream, spool)
        except s3.S3Error as error:
            return self._result(INTERRUPTED if error.transient else FAILED, str(error))
        except (
            RestoreError,
            ZfsError,
            ds.DatasetError,
            crypto.DecryptError,
            OSError,
        ) as error:
            return self._result(FAILED, str(error))
        return self._result(OK)

    def _result(self, status: str, error: str = "") -> Dict[str, Any]:
        return {
            "run_id": self.job["run_id"], "copy_id": self.job["copy_id"], "status": status,
            "target_dataset": self.target, "bytes_received": self.received,
            "snapshot": self.streams[-1]["snapshot"] if self.streams else None,
            "errors": [error] if error else [], "finished_at": self.now().isoformat(),
        }  # fmt: skip
