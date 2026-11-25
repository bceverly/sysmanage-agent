# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""One off-site upload, run detached on the storage host (server ROADMAP 27.3).

1. Take one snapshot of every chosen dataset at once (``zfs snapshot`` with
   them all: one consistent moment), named for the copy alone.
2. Per dataset: ``zfs send`` -- incremental from the base the server named
   when that snapshot is still here, else a full -- cut into parts of
   ``part_bytes``, each encrypted (``crypto``) into a spool file and uploaded
   with its storage class and Object Lock retention.  The parts done are
   written to ``state.json`` as they land.
3. Its manifest -- what the stream is, what it builds on, every part's key,
   size and SHA-256 -- encrypted to S3 Standard.
4. The dataset's older copy snapshots go, keeping the new one and its base.

An interrupted run (the network, the agent's host restarting, a cap that
would not let it finish) RESUMES: the next run finds ``state.json``, sends
the same snapshot again and skips the parts already in the bucket --
checking that what it skips is byte-for-byte what it uploaded -- instead of
starting over.  A ``zfs send`` that fails drops that stream (its parts
expire with the bucket's lifecycle rule) and the dataset is tried again by
the next run.
"""

import base64
import datetime
import hashlib
import json
import os
import subprocess  # nosec B404 - fixed zfs argv, no shell
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.sysmanage_agent.offsite_cloud import bandwidth
from src.sysmanage_agent.offsite_cloud import crypto
from src.sysmanage_agent.offsite_cloud import datasets as ds
from src.sysmanage_agent.offsite_cloud import runfiles
from src.sysmanage_agent.offsite_cloud import s3

FORMAT = "sysmanage-offsite-manifest"
OK, PARTIAL, FAILED, INTERRUPTED = "ok", "partial", "failed", "interrupted"


class ZfsError(RuntimeError):
    """A zfs command that failed."""


class Zfs:
    """zfs through ``sudo -n`` (the agent's account), or directly as root."""

    def __init__(self, path: str = "zfs", sudo: bool = True):
        self.path = path
        self.sudo = sudo

    def _argv(self, argv: List[str]) -> List[str]:
        argv = [self.path] + list(argv[1:])
        return (["sudo", "-n"] + argv) if self.sudo else argv

    def run(self, argv: List[str], privileged: bool = True) -> str:
        full = self._argv(argv) if privileged else [self.path] + list(argv[1:])
        done = subprocess.run(  # nosec B603 - argv from datasets.py
            full, capture_output=True, text=True, check=False, cwd="/", timeout=600
        )
        if done.returncode != 0:
            raise ZfsError(
                f"{' '.join(argv[:2])}: {(done.stderr or '').strip() or done.returncode}"
            )
        return done.stdout or ""

    def stream(self, argv: List[str]) -> subprocess.Popen:
        return subprocess.Popen(  # nosec B603 - argv from datasets.py
            self._argv(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/"
        )

    def stream_in(self, argv: List[str]) -> subprocess.Popen:
        """A command that reads a stream (``zfs receive``)."""
        return subprocess.Popen(  # nosec B603 - argv from datasets.py
            self._argv(argv), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, cwd="/",
        )  # fmt: skip


def object_key(*parts: str) -> str:
    return "/".join(p.strip("/") for p in parts if p and p.strip("/"))


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Upload:  # pylint: disable=too-many-instance-attributes
    """One run of the copy for one storage host."""

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __init__(
        self, job: Dict[str, Any], key: bytes, directory: str, zfs: Zfs,
        client: s3.Client, now: Callable[[], datetime.datetime] = _now,
        throttle: Optional[bandwidth.Throttle] = None,
    ):  # fmt: skip
        self.job = job
        self.key = key
        self.dir = directory
        self.zfs = zfs
        self.client = client
        self.now = now
        self.throttle = throttle or bandwidth.Throttle(
            bandwidth.validate(job.get("bandwidth"))
        )
        self.state: Dict[str, Any] = {}
        self.uploaded = 0
        self.errors: List[str] = []
        self.streams: List[Dict[str, Any]] = []

    # --- state ---------------------------------------------------------------------

    def _save(self) -> None:
        runfiles.write_json(os.path.join(self.dir, runfiles.STATE), self.state)

    def _status(self, **extra: Any) -> None:
        done = sum(1 for d in self.state.get("datasets", {}).values() if d.get("done"))
        runfiles.write_json(os.path.join(self.dir, runfiles.STATUS), dict(
            extra, run_id=self.job["run_id"], snapshot=self.state.get("snapshot"),
            datasets_done=done, datasets_total=len(self.state.get("datasets", {})),
            bytes_uploaded=self.uploaded, updated_at=self.now().isoformat(),
        ))  # fmt: skip

    def _resumable(
        self, previous: Optional[Dict[str, Any]], found: Dict[str, str]
    ) -> bool:
        if not previous or previous.get("copy_id") != self.job["copy_id"]:
            return False
        try:
            ds.valid_snapshot(previous.get("snapshot"))
        except ds.DatasetError:
            return False
        pending = [
            n for n, d in (previous.get("datasets") or {}).items() if not d.get("done")
        ]
        return bool(pending) and all(n in found for n in pending)

    def _begin(self) -> None:
        found = ds.filesystems(self.zfs.run(ds.list_filesystems(), privileged=False))
        previous = runfiles.read_json(os.path.join(self.dir, runfiles.STATE))
        if self._resumable(previous, found):
            self.state = previous
            self.state["resumed_by"] = self.job["run_id"]
            self._save()
            return
        root = ds.storage_dataset(found, self.job["storage_path"])
        chosen = ds.chosen(found, root, self.job.get("exclude") or [],
                           self.job.get("include") or [])  # fmt: skip
        if not chosen:
            raise ZfsError("no ZFS dataset to copy at the storage path")
        snapshot = ds.snapshot_name(self.now())
        self.zfs.run(ds.take_snapshots(chosen, snapshot))
        bases = self.job.get("bases") or {}
        entries: Dict[str, Any] = {}
        for name in chosen:
            base = bases.get(name)
            have = ds.offsite_snapshots(
                self.zfs.run(ds.list_snapshots(name), privileged=False), name
            )
            entries[name] = {"base": base if base in have and base != snapshot else None,
                             "done": False}  # fmt: skip
        self.state = {"copy_id": self.job["copy_id"], "run_id": self.job["run_id"],
                      "snapshot": snapshot, "datasets": entries}  # fmt: skip
        self._save()

    # --- one dataset -------------------------------------------------------------

    def _days(self, kind: str) -> int:
        retention = self.job["retention"]
        return int(
            retention["full_days"] if kind == "full" else retention["incremental_days"]
        )

    def _retain_until(self, days: int) -> Optional[datetime.datetime]:
        return (
            self.now() + datetime.timedelta(days=days)
            if self.job.get("object_lock")
            else None
        )

    def _stream_entry(self, name: str) -> Dict[str, Any]:
        entry = self.state["datasets"][name]
        if not entry.get("stream_id"):
            entry["stream_id"] = str(uuid.uuid4())
            entry["kind"] = "incremental" if entry.get("base") else "full"
            entry["parts"] = []
            entry["started_at"] = self.now().isoformat()
            self._save()
        return entry

    def _skip_done(self, source: crypto.ChunkSource, entry: Dict[str, Any]) -> None:
        """Read past the parts already uploaded, proving they are the same."""
        for part in entry["parts"]:
            digest = hashlib.sha256()
            target = source.consumed + int(part["plain_bytes"])
            while source.consumed < target and not source.exhausted:
                chunk, _ends = source.take()
                digest.update(chunk)
            if digest.hexdigest() != part["plain_sha256"]:
                raise ZfsError("the stream differs from the one being resumed")

    def _send_parts(self, name: str, entry: Dict[str, Any], proc) -> None:
        source = crypto.ChunkSource(proc.stdout.read)
        if entry["parts"]:
            self._skip_done(source, entry)
        days = self._days(entry["kind"])
        spool = runfiles.ensure(os.path.join(self.dir, runfiles.SPOOL))
        while not entry.get("sent"):
            if entry["parts"] and source.exhausted:
                break
            self._one_part(name, entry, source, days, os.path.join(spool, "part"))
            entry["sent"] = source.exhausted
            self._save()
        entry["stream_bytes"] = source.consumed

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _one_part(self, name: str, entry: Dict[str, Any], source: crypto.ChunkSource,
                  days: int, spool: str) -> None:  # fmt: skip
        index = len(entry["parts"])
        before = hashlib.sha256()
        start = source.consumed
        wrapped = _HashingSource(source, before)
        with open(spool, "wb") as out:
            os.chmod(spool, 0o600)
            plain, size, digest = crypto.encrypt_part(
                wrapped,
                out,
                self.key,
                entry["stream_id"],
                index,
                int(self.job["part_bytes"]),
            )
        key = object_key(
            self.job.get("prefix", ""), f"d{days}", entry["stream_id"], f"{index:06d}"
        )
        self.client.put_file(
            key, spool, size, digest, self.job.get("storage_class") or "DEEP_ARCHIVE",
            self._retain_until(days),
            wrap=lambda handle: bandwidth.ThrottledReader(handle, self.throttle),
        )  # fmt: skip
        runfiles.remove(spool)
        self.uploaded += size
        entry["parts"].append({"index": index, "key": key, "bytes": size, "sha256": digest,
                               "plain_bytes": plain, "plain_sha256": before.hexdigest(),
                               "offset": start})  # fmt: skip
        self._status(dataset=name, part=index)

    def _manifest(self, name: str, entry: Dict[str, Any]) -> Dict[str, Any]:
        days = self._days(entry["kind"])
        manifest = {
            "format": FORMAT, "version": 1, "copy_id": self.job["copy_id"],
            "run_id": self.job["run_id"], "stream_id": entry["stream_id"],
            "dataset": name, "snapshot": self.state["snapshot"],
            "base_snapshot": entry.get("base"), "kind": entry["kind"],
            "created_at": entry["started_at"], "finished_at": self.now().isoformat(),
            "key_id": crypto.key_id(self.key), "retention_days": days,
            "storage_class": self.job.get("storage_class") or "DEEP_ARCHIVE",
            "stream_bytes": entry.get("stream_bytes", 0),
            "parts": [{k: p[k] for k in ("index", "key", "bytes", "sha256", "plain_bytes")}
                      for p in entry["parts"]],
        }  # fmt: skip
        blob = crypto.seal_bytes(self.key, entry["stream_id"], crypto.MANIFEST_PART,
                                 json.dumps(manifest, sort_keys=True).encode("utf-8"))  # fmt: skip
        key = object_key(self.job.get("prefix", ""), f"m{days}", self.job["copy_id"],
                         self.state["snapshot"], entry["stream_id"])  # fmt: skip
        self.client.put_bytes(key, blob, self._retain_until(days))
        return dict(manifest, manifest_key=key)

    def _dataset(self, name: str) -> None:
        entry = self._stream_entry(name)
        if not entry.get("sent"):
            proc = self.zfs.stream(
                ds.send(name, self.state["snapshot"], entry.get("base"))
            )
            try:
                self._send_parts(name, entry, proc)
            finally:
                proc.stdout.close()
                err = proc.stderr.read().decode("utf-8", "replace").strip()
                code = proc.wait()
            if code != 0:
                self._drop_stream(entry)
                raise ZfsError(f"zfs send {name}: {err or code}")
        manifest = self._manifest(name, entry)
        entry["done"] = True
        entry["manifest"] = manifest
        self._save()
        self.streams.append(manifest)
        self._prune(name, entry.get("base"))

    def _drop_stream(self, entry: Dict[str, Any]) -> None:
        for field in (
            "stream_id",
            "kind",
            "parts",
            "sent",
            "started_at",
            "stream_bytes",
        ):
            entry.pop(field, None)
        self._save()

    def _prune(self, name: str, base: Optional[str]) -> None:
        try:
            have = ds.offsite_snapshots(
                self.zfs.run(ds.list_snapshots(name), privileged=False), name
            )
            for old in ds.to_remove(have, (self.state["snapshot"], base)):
                self.zfs.run(ds.destroy(name, old))
        except ZfsError as error:  # the copy is good; the next run tries again
            self.errors.append(f"{name}: {error}")

    # --- the run -------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        try:
            self._begin()
        except (
            ZfsError,
            ds.DatasetError,
            OSError,
            subprocess.SubprocessError,
        ) as error:
            return self._result(FAILED, [str(error)])
        status = OK
        for name, entry in sorted(self.state["datasets"].items()):
            if entry.get("done"):
                if "manifest" in entry:
                    self.streams.append(entry["manifest"])
                continue
            self._status(dataset=name, part=None)
            try:
                self._dataset(name)
            except s3.S3Error as error:
                # the bucket is unreachable or refuses: stop, keep the progress
                self.errors.append(f"{name}: {error}")
                return self._result(INTERRUPTED if error.transient else FAILED)
            except (ZfsError, ds.DatasetError, crypto.DecryptError, OSError) as error:
                self.errors.append(f"{name}: {error}")
                status = PARTIAL
        return self._result(status)

    def _result(
        self, status: str, errors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        if status in (OK, PARTIAL):
            runfiles.remove(os.path.join(self.dir, runfiles.STATE))
        result = {
            "run_id": self.job["run_id"], "copy_id": self.job["copy_id"], "status": status,
            "snapshot": self.state.get("snapshot"), "streams": self.streams,
            "bytes_uploaded": self.uploaded, "errors": (errors or []) + self.errors,
            "key_id": crypto.key_id(self.key), "finished_at": self.now().isoformat(),
            "failed_datasets": sorted(
                n for n, d in self.state.get("datasets", {}).items() if not d.get("done")
            ),
        }  # fmt: skip
        return result


class _HashingSource:  # pylint: disable=too-few-public-methods
    """A ChunkSource that also hashes what one part takes."""

    def __init__(self, source: crypto.ChunkSource, digest):
        self._source = source
        self._digest = digest
        self.chunk_size = source.chunk_size

    def take(self) -> Tuple[bytes, bool]:
        chunk, ends = self._source.take()
        self._digest.update(chunk)
        return chunk, ends


def decode_key(text: str) -> bytes:
    key = base64.b64decode(text, validate=True)
    if len(key) != crypto.KEY_BYTES:
        raise ValueError("the off-site key must be 32 bytes")
    return key
