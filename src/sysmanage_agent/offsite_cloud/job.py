# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""What the server may ask of an off-site run, checked (server ROADMAP 27.3).

The agent checks every field before it writes the job file, and the
detached run checks it again before it acts.  Nothing in a job is a secret:
the credentials and the key come over HTTPS, for the run alone.
"""

import posixpath
import re
import urllib.parse
import uuid
from typing import Any, Dict, List

from src.sysmanage_agent.offsite_cloud import bandwidth
from src.sysmanage_agent.offsite_cloud import datasets as ds

UPLOAD, RESTORE, CHECK = "upload", "restore", "check"
ACTIONS = (UPLOAD, RESTORE, CHECK)
STORAGE_CLASSES = ("STANDARD", "STANDARD_IA", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE")
TIERS = ("Bulk", "Standard")
MIB = 1 << 20
DEFAULT_PART = 256 * MIB
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_REGION = re.compile(r"[a-z0-9-]{1,32}")
_PREFIX = re.compile(r"[A-Za-z0-9_.()!*'/-]{0,200}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class JobError(ValueError):
    """A job the agent refuses; ``reason`` is its code."""

    reason = "invalid_request"


def _uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError as error:
        raise JobError(f"{field} is not an id") from error


def _int(value: Any, field: str, low: int, high: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not low <= value <= high
    ):
        raise JobError(f"{field} must be a whole number from {low} to {high}")
    return value


def _endpoint(value: Any) -> Any:
    if value in (None, ""):
        return None
    parts = urllib.parse.urlsplit(str(value))
    if (parts.scheme not in ("https", "http") or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment):  # fmt: skip
        raise JobError("the endpoint must be a plain http(s) address")
    return str(value).rstrip("/")


def _prefix(value: Any) -> str:
    text = str(value or "").strip("/")
    if not _PREFIX.fullmatch(text) or ".." in text.split("/") or "//" in text:
        raise JobError("the prefix may hold letters, digits and - _ . / only")
    return text


def _dataset_list(value: Any, field: str) -> List[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > 1000:
        raise JobError(f"{field} must be a list of datasets")
    try:
        return [ds.valid_dataset(v) for v in value]
    except ds.DatasetError as error:
        raise JobError(str(error)) from error


def _bases(value: Any) -> Dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, dict) or len(value) > 5000:
        raise JobError("bases must map datasets to snapshots")
    try:
        return {ds.valid_dataset(k): ds.valid_snapshot(v) for k, v in value.items()}
    except ds.DatasetError as error:
        raise JobError(str(error)) from error


def _common(params: Dict[str, Any]) -> Dict[str, Any]:
    action = params.get("action")
    if action not in ACTIONS:
        raise JobError("unknown off-site action")
    bucket = str(params.get("bucket") or "")
    if not _BUCKET.fullmatch(bucket) or ".." in bucket:
        raise JobError("not an S3 bucket name")
    region = str(params.get("region") or "us-east-1")
    if not _REGION.fullmatch(region):
        raise JobError("not an AWS region")
    return {
        "action": action, "run_id": _uuid(params.get("run_id"), "run_id"),
        "copy_id": _uuid(params.get("copy_id"), "copy_id"), "bucket": bucket,
        "region": region, "endpoint": _endpoint(params.get("endpoint")),
        "prefix": _prefix(params.get("prefix")),
    }  # fmt: skip


def _upload(params: Dict[str, Any], job: Dict[str, Any]) -> None:
    path = params.get("storage_path")
    if not isinstance(path, str) or not posixpath.isabs(path) or "\0" in path:
        raise JobError("the storage path must be absolute")
    storage_class = params.get("storage_class") or "DEEP_ARCHIVE"
    if storage_class not in STORAGE_CLASSES:
        raise JobError("unknown storage class")
    retention = params.get("retention") or {}
    if not isinstance(retention, dict):
        raise JobError("retention must be an object")
    part = params.get("part_bytes") or DEFAULT_PART
    _int(part, "part_bytes", 16 * MIB, 4096 * MIB)
    if part % MIB:
        raise JobError("part_bytes must be whole MiB")
    try:
        schedule = bandwidth.validate(params.get("bandwidth"))
    except bandwidth.ScheduleError as error:
        raise JobError(str(error)) from error
    job.update({
        "storage_path": posixpath.normpath(path), "storage_class": storage_class,
        "object_lock": bool(params.get("object_lock", True)),
        "retention": {
            "full_days": _int(retention.get("full_days"), "full_days", 1, 36500),
            "incremental_days": _int(retention.get("incremental_days"),
                                     "incremental_days", 1, 36500),
        },
        "exclude": _dataset_list(params.get("exclude"), "exclude"),
        "include": _dataset_list(params.get("include"), "include"),
        "bases": _bases(params.get("bases")), "part_bytes": part,
        "bandwidth": params.get("bandwidth") or None,
    })  # fmt: skip
    job["_schedule"] = schedule


def _part(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise JobError("a part is not an object")
    key = str(value.get("key") or "")
    if not key or len(key) > 1024 or key.startswith("/"):
        raise JobError("a part has no key")
    sha = str(value.get("sha256") or "")
    if not _HEX64.fullmatch(sha):
        raise JobError("a part has no SHA-256")
    return {"key": key, "sha256": sha, "index": _int(value.get("index"), "index", 0, 10**7),
            "bytes": _int(value.get("bytes"), "bytes", 1, 1 << 40)}  # fmt: skip


def _stream(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise JobError("a stream is not an object")
    try:
        snapshot = ds.valid_snapshot(value.get("snapshot"))
        base = value.get("base_snapshot")
        base = ds.valid_snapshot(base) if base else None
    except ds.DatasetError as error:
        raise JobError(str(error)) from error
    parts = value.get("parts")
    if not isinstance(parts, list) or not parts or len(parts) > 100000:
        raise JobError("a stream has no parts")
    kind = value.get("kind")
    if kind not in ("full", "incremental"):
        raise JobError("a stream is a full or an incremental")
    return {"stream_id": _uuid(value.get("stream_id"), "stream_id"), "kind": kind,
            "snapshot": snapshot, "base_snapshot": base,
            "parts": [_part(p) for p in parts]}  # fmt: skip


def _restore(params: Dict[str, Any], job: Dict[str, Any]) -> None:
    streams = params.get("streams")
    if not isinstance(streams, list) or not streams or len(streams) > 1000:
        raise JobError("a restore needs its chain of streams")
    tier = params.get("tier") or "Bulk"
    if tier not in TIERS:
        raise JobError("the thaw tier is Bulk or Standard")
    try:
        target = ds.valid_dataset(params.get("target_dataset"))
    except ds.DatasetError as error:
        raise JobError(str(error)) from error
    job.update({
        "streams": [_stream(s) for s in streams], "target_dataset": target, "tier": tier,
        "thaw_days": _int(params.get("thaw_days") or 7, "thaw_days", 1, 30),
        "poll_seconds": _int(params.get("poll_seconds") or 900, "poll_seconds", 60, 3600),
    })  # fmt: skip


def validate(params: Dict[str, Any]) -> Dict[str, Any]:
    """The job, checked and normalized; JobError when it is not acceptable."""
    if not isinstance(params, dict):
        raise JobError("the job is not an object")
    job = _common(params)
    if job["action"] == UPLOAD:
        _upload(params, job)
    elif job["action"] == RESTORE:
        _restore(params, job)
    job.pop("_schedule", None)
    return job
