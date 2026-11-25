# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""An off-site upload and its restore, end to end against fakes (27.3).

What must hold:
  * one snapshot of every chosen dataset, each sent on its own: a full where
    there is no base here, else an incremental from it; parts and a
    manifest in the bucket, encrypted, with their retention;
  * an interrupted upload RESUMES from the parts already in the bucket,
    and refuses to if the stream it would skip is not the same;
  * a failed ``zfs send`` drops that stream only;
  * only the copy's older snapshots are destroyed, keeping the new and base;
  * the restore thaws everything, waits, then receives the chain in order
    into a NEW dataset and gets the bytes back exactly.
"""

# pylint: disable=protected-access,redefined-outer-name
import datetime
import hashlib
import io
import json
import os
import uuid

import pytest

from src.sysmanage_agent.offsite_cloud import crypto
from src.sysmanage_agent.offsite_cloud import job as jobs
from src.sysmanage_agent.offsite_cloud import runfiles
from src.sysmanage_agent.offsite_cloud import s3
from src.sysmanage_agent.offsite_cloud.restore import Restore, RestoreError, check_chain
from src.sysmanage_agent.offsite_cloud.upload import Upload, ZfsError

KEY = bytes(range(32))
MIB = 1 << 20
WEB = "/srv/backups/web-1a2b3c4d"
NOW = datetime.datetime(2026, 11, 25, 2, 0, tzinfo=datetime.timezone.utc)


def stream_bytes(dataset, snapshot, base):
    seed = hashlib.sha256(f"{dataset}|{snapshot}|{base}".encode()).digest()
    return (seed * ((40 * MIB) // 32 + 1))[: 40 * MIB + 123]


class FakeProc:
    def __init__(self, data=b"", code=0, err=b""):
        self.stdout = io.BytesIO(data)
        self.stderr = io.BytesIO(err)
        self.stdin = io.BytesIO()
        self.stdin.close = lambda: None
        self._code = code

    def wait(self):
        return self._code


class FakeZfs:
    def __init__(self):
        self.filesystems = {"tank": "/tank", "tank/backups": "/srv/backups",
                            "tank/backups/web-1a2b3c4d": "/srv/backups/web-1a2b3c4d"}  # fmt: skip
        self.snapshots = {}
        self.commands = []
        self.fail_send = set()
        self.received = {}

    def run(self, argv, privileged=True):
        self.commands.append((list(argv), privileged))
        if argv[:2] == ["zfs", "list"] and "filesystem" in argv:
            return "".join(f"{k}\t{v}\n" for k, v in self.filesystems.items())
        if argv[:2] == ["zfs", "list"]:
            name = argv[-1]
            return "".join(
                f"{name}@{s}\n" for s in sorted(self.snapshots.get(name, ()))
            )
        if argv[:2] == ["zfs", "snapshot"]:
            for target in argv[2:]:
                name, snap = target.split("@")
                self.snapshots.setdefault(name, set()).add(snap)
            return ""
        if argv[:2] == ["zfs", "destroy"]:
            name, snap = argv[2].split("@")
            self.snapshots[name].discard(snap)
            return ""
        raise AssertionError(argv)

    def stream(self, argv):
        self.commands.append((list(argv), True))
        target = argv[-1]
        name, snap = target.split("@")
        base = argv[3].split("@")[1] if "-i" in argv else None
        if name in self.fail_send:
            return FakeProc(
                stream_bytes(name, snap, base)[: 5 * MIB], 1, b"broken pipe"
            )
        return FakeProc(stream_bytes(name, snap, base))

    def stream_in(self, argv):
        self.commands.append((list(argv), True))
        proc = FakeProc()
        self.received.setdefault(argv[-1], []).append(proc.stdin)
        return proc


class FakeS3:
    def __init__(self, fail_after=None):
        self.objects = {}
        self.fail_after = fail_after
        self.restores = []

    def put_file(self, key, path, size, sha256_hex, storage_class="DEEP_ARCHIVE",
                 retain_until=None, wrap=None):  # fmt: skip
        if self.fail_after is not None and len(self.objects) >= self.fail_after:
            raise s3.S3Error(0, "ConnectionError", "network down")
        with open(path, "rb") as handle:
            data = (wrap(handle) if wrap else handle).read()
        assert len(data) == size and hashlib.sha256(data).hexdigest() == sha256_hex
        self.objects[key] = {
            "data": data,
            "class": storage_class,
            "until": retain_until,
        }

    def put_bytes(self, key, data, retain_until=None):
        self.objects[key] = {"data": data, "class": "STANDARD", "until": retain_until}

    def head(self, key):
        obj = self.objects.get(key)
        if obj is None:
            return None
        headers = {}
        if obj["class"] == "DEEP_ARCHIVE":
            headers["x-amz-storage-class"] = "DEEP_ARCHIVE"
            if obj.get("thawed") is not None:
                state = "false" if obj["thawed"] else "true"
                headers["x-amz-restore"] = f'ongoing-request="{state}"'
        return headers

    def restore(self, key, days, tier="Bulk"):
        self.restores.append((key, days, tier))
        self.objects[key]["thawed"] = False
        return "started"

    def get_to(self, key, sink):
        sink(self.objects[key]["data"])


def _job(tmp_path, **over):
    job = jobs.validate(dict({
        "action": "upload", "run_id": str(uuid.uuid4()),
        "copy_id": "11111111-2222-3333-4444-555555555555", "bucket": "acme-offsite",
        "region": "us-east-2", "prefix": "nas", "storage_path": "/srv/backups",
        "retention": {"full_days": 241, "incremental_days": 210}, "part_bytes": 16 * MIB,
    }, **over))  # fmt: skip
    return job


def _upload(tmp_path, zfs, client, now=NOW, **over):
    directory = runfiles.ensure(str(tmp_path / "copy"))
    return Upload(
        _job(tmp_path, **over), KEY, directory, zfs, client, now=lambda: now
    ).run()


def test_a_first_upload_sends_every_dataset_full_with_a_manifest(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    result = _upload(tmp_path, zfs, client)
    assert result["status"] == "ok", result
    snap = "sysmanage-offsite-20261125T020000Z"
    assert result["snapshot"] == snap
    # one atomic snapshot of both datasets at and under the storage path, not tank
    assert (["zfs", "snapshot", f"tank/backups@{snap}",
             f"tank/backups/web-1a2b3c4d@{snap}"], True) in zfs.commands  # fmt: skip
    assert [s["dataset"] for s in result["streams"]] == [
        "tank/backups",
        "tank/backups/web-1a2b3c4d",
    ]
    stream = result["streams"][1]
    assert stream["kind"] == "full" and stream["base_snapshot"] is None
    assert [p["index"] for p in stream["parts"]] == [0, 1, 2]  # 40 MiB in 16 MiB parts
    for part in stream["parts"]:
        obj = client.objects[part["key"]]
        assert part["key"].startswith(f"nas/d241/{stream['stream_id']}/")
        assert obj["class"] == "DEEP_ARCHIVE"
        assert obj["until"] == NOW + datetime.timedelta(days=241)
        assert b"web-1a2b3c4d" not in obj["data"]
    manifest = client.objects[stream["manifest_key"]]
    assert stream["manifest_key"].startswith(
        "nas/m241/11111111-2222-3333-4444-555555555555/"
    )
    assert manifest["class"] == "STANDARD"
    opened = json.loads(crypto.open_bytes(KEY, manifest["data"], stream["stream_id"],
                                          crypto.MANIFEST_PART))  # fmt: skip
    assert opened["parts"] == stream["parts"] and opened["key_id"] == crypto.key_id(KEY)
    # all the parts decrypt back into the stream
    data = b"".join(crypto.open_bytes(KEY, client.objects[p["key"]]["data"], stream["stream_id"],
                                      p["index"]) for p in stream["parts"])  # fmt: skip
    assert data == stream_bytes("tank/backups/web-1a2b3c4d", snap, None)
    assert not os.path.exists(tmp_path / "copy" / runfiles.STATE)


def test_the_next_upload_is_incremental_where_the_base_is_still_here(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    first = _upload(tmp_path, zfs, client)
    base = first["snapshot"]
    zfs.filesystems["tank/backups/new-9a8b7c6d"] = "/srv/backups/new-9a8b7c6d"
    later = NOW + datetime.timedelta(days=1)
    second = _upload(tmp_path, zfs, client, now=later,
                     bases={"tank/backups": base, "tank/backups/web-1a2b3c4d": base,
                            "tank/backups/new-9a8b7c6d": base})  # fmt: skip
    kinds = {s["dataset"]: (s["kind"], s["base_snapshot"]) for s in second["streams"]}
    assert kinds == {"tank/backups": ("incremental", base),
                     "tank/backups/web-1a2b3c4d": ("incremental", base),
                     "tank/backups/new-9a8b7c6d": ("full", None)}  # fmt: skip
    assert second["streams"][0]["parts"][0]["key"].startswith("nas/d210/")
    # a third run keeps the newest and its base, and destroys the oldest
    third = _upload(tmp_path, zfs, client, now=later + datetime.timedelta(days=1),
                    bases={"tank/backups": second["snapshot"]})  # fmt: skip
    assert zfs.snapshots["tank/backups"] == {second["snapshot"], third["snapshot"]}


def test_an_interrupted_upload_resumes_from_the_parts_in_the_bucket(tmp_path):
    zfs, client = FakeZfs(), FakeS3(fail_after=1)
    first = _upload(tmp_path, zfs, client, storage_path=WEB)
    assert first["status"] == "interrupted"
    assert len(client.objects) == 1
    state = runfiles.read_json(str(tmp_path / "copy" / runfiles.STATE))
    entry = state["datasets"]["tank/backups/web-1a2b3c4d"]
    assert len(entry["parts"]) == 1
    client.fail_after = None
    later = NOW + datetime.timedelta(hours=8)
    second = _upload(tmp_path, zfs, client, now=later, storage_path=WEB)
    assert second["status"] == "ok" and second["snapshot"] == first["snapshot"]
    stream = second["streams"][0]
    assert stream["stream_id"] == entry["stream_id"] and len(stream["parts"]) == 3
    data = b"".join(crypto.open_bytes(KEY, client.objects[p["key"]]["data"], stream["stream_id"],
                                      p["index"]) for p in stream["parts"])  # fmt: skip
    assert data == stream_bytes("tank/backups/web-1a2b3c4d", first["snapshot"], None)
    # only one snapshot was taken across both runs
    assert sum(1 for c, _p in zfs.commands if c[:2] == ["zfs", "snapshot"]) == 1


def test_a_resume_whose_stream_changed_starts_that_stream_again(tmp_path):
    zfs, client = FakeZfs(), FakeS3(fail_after=1)
    _upload(tmp_path, zfs, client, storage_path=WEB)
    client.fail_after = None
    path = str(tmp_path / "copy" / runfiles.STATE)
    state = runfiles.read_json(path)
    state["datasets"]["tank/backups/web-1a2b3c4d"]["parts"][0]["plain_sha256"] = (
        "0" * 64
    )
    runfiles.write_json(path, state)
    result = _upload(tmp_path, zfs, client, storage_path=WEB)
    assert result["status"] == "partial"
    assert "differs" in result["errors"][0]


def test_a_failed_send_drops_that_stream_only(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    zfs.fail_send = {"tank/backups"}
    result = _upload(tmp_path, zfs, client)
    assert result["status"] == "partial"
    assert [s["dataset"] for s in result["streams"]] == ["tank/backups/web-1a2b3c4d"]
    assert result["failed_datasets"] == ["tank/backups"]
    assert "broken pipe" in result["errors"][0]


def test_without_object_lock_nothing_is_retained(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    _upload(tmp_path, zfs, client, object_lock=False)
    assert all(obj["until"] is None for obj in client.objects.values())


def test_nothing_to_copy_fails_plainly(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    result = _upload(tmp_path, zfs, client, storage_path="/elsewhere")
    assert result["status"] == "failed" and "no ZFS dataset" in result["errors"][0]


# --- restore --------------------------------------------------------------------------


def _restore_job(streams, target="tank/restored"):
    return jobs.validate({
        "action": "restore", "run_id": str(uuid.uuid4()),
        "copy_id": "11111111-2222-3333-4444-555555555555", "bucket": "acme-offsite",
        "region": "us-east-2", "prefix": "nas", "streams": streams,
        "target_dataset": target, "poll_seconds": 60,
    })  # fmt: skip


def test_a_restore_thaws_waits_and_receives_the_chain_in_order(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    first = _upload(tmp_path, zfs, client, storage_path=WEB)
    second = _upload(tmp_path, zfs, client, now=NOW + datetime.timedelta(days=1),
                     storage_path=WEB,
                     bases={"tank/backups/web-1a2b3c4d": first["snapshot"]})  # fmt: skip
    chain = [first["streams"][0], second["streams"][0]]
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        for obj in client.objects.values():  # S3 finishes the thaw
            if obj.get("thawed") is False:
                obj["thawed"] = True

    directory = runfiles.ensure(str(tmp_path / "restore"))
    result = Restore(_restore_job(chain), KEY, directory, zfs, client,
                     now=lambda: NOW, sleep=sleep).run()  # fmt: skip
    assert result["status"] == "ok", result
    assert len(client.restores) == 6 and waits == [60]
    received = zfs.received["tank/restored"]
    assert received[0].getvalue() == stream_bytes(
        "tank/backups/web-1a2b3c4d", first["snapshot"], None
    )
    assert received[1].getvalue() == stream_bytes(
        "tank/backups/web-1a2b3c4d", second["snapshot"], first["snapshot"]
    )


def test_a_restore_never_writes_over_an_existing_dataset(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    first = _upload(tmp_path, zfs, client, storage_path=WEB)
    directory = runfiles.ensure(str(tmp_path / "restore"))
    result = Restore(_restore_job(first["streams"], "tank/backups"), KEY, directory, zfs,
                     client).run()  # fmt: skip
    assert result["status"] == "failed" and "already exists" in result["errors"][0]


def test_a_part_changed_in_the_bucket_is_refused(tmp_path):
    zfs, client = FakeZfs(), FakeS3()
    first = _upload(tmp_path, zfs, client, storage_path=WEB, storage_class="STANDARD")
    part = first["streams"][0]["parts"][1]
    data = bytearray(client.objects[part["key"]]["data"])
    data[-1] ^= 1
    client.objects[part["key"]]["data"] = bytes(data)
    directory = runfiles.ensure(str(tmp_path / "restore"))
    result = Restore(_restore_job(first["streams"]), KEY, directory, zfs, client).run()
    assert (
        result["status"] == "failed" and "not what was uploaded" in result["errors"][0]
    )


def test_a_chain_must_start_with_a_full_and_follow_on():
    full = {
        "kind": "full",
        "snapshot": "sysmanage-offsite-20261101T000000Z",
        "parts": [1],
    }
    inc = {"kind": "incremental", "snapshot": "sysmanage-offsite-20261102T000000Z",
           "base_snapshot": "sysmanage-offsite-20261101T000000Z", "parts": [1]}  # fmt: skip
    check_chain([full, inc])
    with pytest.raises(RestoreError):
        check_chain([inc])
    with pytest.raises(RestoreError):
        check_chain(
            [full, dict(inc, base_snapshot="sysmanage-offsite-20261030T000000Z")]
        )


def test_zfs_errors_name_the_command_only():
    error = ZfsError("zfs send: dataset does not exist")
    assert "send" in str(error)
