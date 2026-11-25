# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The off-site cloud copy's building blocks (server ROADMAP 27.3).

What must hold:
  * an object decrypts only with its key, as its own stream and part, whole:
    altered, cut short, extended, reordered or swapped objects are refused;
  * the S3 signature is AWS's (the published example) and the secret never
    shows in an error;
  * the bandwidth cap follows the local clock, past midnight too;
  * only the copy's own snapshots are ever destroyed, and a job's names are
    checked before anything runs.
"""

# pylint: disable=protected-access
import datetime
import io
import uuid

import pytest

from src.sysmanage_agent.offsite_cloud import bandwidth
from src.sysmanage_agent.offsite_cloud import crypto
from src.sysmanage_agent.offsite_cloud import datasets as ds
from src.sysmanage_agent.offsite_cloud import job as jobs
from src.sysmanage_agent.offsite_cloud import s3

KEY = bytes(range(32))
STREAM = str(uuid.UUID(int=7))


def _seal(data: bytes, part: int = 0, limit: int = 1 << 30, key: bytes = KEY) -> bytes:
    out = io.BytesIO()
    source = crypto.ChunkSource(
        io.BytesIO(data).read, chunk_size=1 << crypto.CHUNK_LOG2
    )
    crypto.encrypt_part(source, out, key, STREAM, part, limit)
    return out.getvalue()


def _open(blob: bytes, **kwargs) -> bytes:
    out = io.BytesIO()
    crypto.decrypt_object(io.BytesIO(blob).read, out.write, KEY, **kwargs)
    return out.getvalue()


@pytest.mark.parametrize(
    "size", [0, 1, (1 << 20) - 1, 1 << 20, (1 << 20) + 5, 3 * (1 << 20)]
)
def test_round_trip_at_every_boundary(size):
    data = bytes((i * 7) % 251 for i in range(size))
    assert _open(_seal(data), stream_id=STREAM, part_index=0) == data


def test_the_key_id_names_the_key_without_revealing_it():
    kid = crypto.key_id(KEY)
    assert len(kid) == 16 and kid != KEY.hex()[:16]
    assert crypto.key_id(crypto.new_key()) != kid
    blob = _seal(b"x")
    assert crypto.Header(blob[: crypto.HEADER_BYTES]).key_id == kid


@pytest.mark.parametrize(
    "mangle",
    [
        lambda b: b[:-1],  # cut short
        lambda b: b + b"\0" * 20,  # extended
        lambda b: b[:100] + bytes([b[100] ^ 1]) + b[101:],  # one bit
        lambda b: b[: crypto.HEADER_BYTES],  # header only
        lambda b: b[: crypto.HEADER_BYTES + (1 << 20) + 16],  # last chunk dropped
    ],
)
def test_altered_objects_are_refused(mangle):
    blob = _seal(b"a" * ((1 << 20) + 10))
    with pytest.raises(crypto.DecryptError):
        _open(mangle(blob))


def test_chunks_cannot_be_reordered():
    blob = _seal(b"a" * (1 << 20) + b"b" * (1 << 20) + b"c")
    head = crypto.HEADER_BYTES
    size = (1 << 20) + 16
    first, second = blob[head : head + size], blob[head + size : head + 2 * size]
    swapped = blob[:head] + second + first + blob[head + 2 * size :]
    with pytest.raises(crypto.DecryptError):
        _open(swapped)


def test_another_key_stream_or_part_is_refused():
    blob = _seal(b"secret", part=3)
    with pytest.raises(crypto.DecryptError, match="needs the key"):
        crypto.decrypt_object(io.BytesIO(blob).read, lambda b: None, crypto.new_key())
    with pytest.raises(crypto.DecryptError, match="another stream"):
        _open(blob, stream_id=str(uuid.uuid4()))
    with pytest.raises(crypto.DecryptError, match="another part"):
        _open(blob, part_index=2)
    assert _open(blob, part_index=3) == b"secret"


def test_a_header_rewritten_to_another_part_fails():
    blob = bytearray(_seal(b"secret", part=3))
    blob[36:40] = (2).to_bytes(4, "big")  # the part index, authenticated
    with pytest.raises(crypto.DecryptError):
        _open(bytes(blob), part_index=2)


def test_a_stream_splits_into_parts_that_join_back():
    data = bytes(range(256)) * 20000  # ~5 MiB
    source = crypto.ChunkSource(io.BytesIO(data).read)
    parts = []
    while not parts or not source.exhausted:
        out = io.BytesIO()
        plain, size, digest = crypto.encrypt_part(
            source, out, KEY, STREAM, len(parts), 2 << 20
        )
        assert size == len(out.getvalue()) and plain <= 2 << 20
        assert digest == __import__("hashlib").sha256(out.getvalue()).hexdigest()
        parts.append(out.getvalue())
    assert len(parts) == 3
    joined = b"".join(_open(p, part_index=i) for i, p in enumerate(parts))
    assert joined == data


def test_two_objects_never_share_a_salt():
    one, two = _seal(b"same"), _seal(b"same")
    assert one[40:72] != two[40:72] and one != two


def test_manifests_round_trip_in_memory():
    blob = crypto.seal_bytes(KEY, STREAM, crypto.MANIFEST_PART, b'{"a": 1}')
    assert crypto.open_bytes(KEY, blob, STREAM, crypto.MANIFEST_PART) == b'{"a": 1}'


# --- S3 -------------------------------------------------------------------------


def test_the_signature_matches_awss_published_example():
    # AWS SigV4 documentation, "GET Object" example (examplebucket, test.txt).
    client = s3.Client("examplebucket", "us-east-1", "AKIAIOSFODNN7EXAMPLE",
                       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")  # fmt: skip
    client.host = "examplebucket.s3.amazonaws.com"  # the example's global endpoint
    headers = client._headers(
        "GET", "/test.txt", {}, {"range": "bytes=0-9"}, s3.EMPTY_SHA256,
        now=datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc),
    )  # fmt: skip
    assert headers["authorization"].endswith(
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )
    assert (
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"
        in headers["authorization"]
    )


def test_addressing_follows_the_bucket_and_endpoint():
    assert (
        s3.Client("b-1", "eu-west-2", "a", "s").host == "b-1.s3.eu-west-2.amazonaws.com"
    )
    dotted = s3.Client("my.bucket", "eu-west-2", "a", "s")
    assert (
        dotted.host == "s3.eu-west-2.amazonaws.com"
        and dotted._path("k") == "/my.bucket/k"
    )
    local = s3.Client("b-1", "us-east-1", "a", "s", endpoint="http://127.0.0.1:9000")
    assert (local.scheme, local.host, local._path("x y/z")) == ("http", "127.0.0.1:9000",
                                                                 "/b-1/x%20y/z")  # fmt: skip


def test_errors_never_carry_the_secret():
    error = s3._error_of(
        403, b"<Error><Code>AccessDenied</Code><Message>no</Message></Error>"
    )
    assert (error.status, error.code, error.transient) == (403, "AccessDenied", False)
    assert s3._error_of(503, b"<Error><Code>SlowDown</Code></Error>").transient
    assert "wJalr" not in str(error)


@pytest.mark.parametrize(
    "headers,state",
    [
        (None, "missing"),
        ({}, "ready"),
        ({"x-amz-storage-class": "DEEP_ARCHIVE"}, "archived"),
        ({"x-amz-storage-class": "DEEP_ARCHIVE", "x-amz-restore": 'ongoing-request="true"'},
         "thawing"),
        ({"x-amz-storage-class": "DEEP_ARCHIVE",
          "x-amz-restore": 'ongoing-request="false", expiry-date="x"'}, "ready"),
    ],
)  # fmt: skip
def test_restore_state_from_head(headers, state):
    assert s3.restore_state(headers) == state


def test_transient_failures_are_retried_then_raised():
    client = s3.Client("b-1", "us-east-1", "a", "s")
    client.sleep = lambda _s: None
    answers = [(503, {}, b"<Error><Code>SlowDown</Code></Error>"), (200, {}, b"ok")]
    client._once = lambda *a, **k: answers.pop(0)
    assert client.request("GET", "k")[2] == b"ok"
    client._once = lambda *a, **k: (
        403,
        {},
        b"<Error><Code>AccessDenied</Code></Error>",
    )
    with pytest.raises(s3.S3Error, match="AccessDenied"):
        client.request("GET", "k")


# --- bandwidth ------------------------------------------------------------------------


BUSINESS = {"rules": [{"days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00",
                       "kbps": 8000}], "default_kbps": 0}  # fmt: skip


@pytest.mark.parametrize(
    "moment,cap",
    [
        (datetime.datetime(2026, 11, 23, 9, 0), 1_000_000),  # Monday morning
        (datetime.datetime(2026, 11, 23, 18, 0), 0),  # Monday at six
        (datetime.datetime(2026, 11, 28, 12, 0), 0),  # Saturday
    ],
)
def test_the_cap_follows_the_clock(moment, cap):
    assert bandwidth.cap_at(bandwidth.validate(BUSINESS), moment) == cap


def test_a_rule_past_midnight_covers_the_next_morning():
    night = bandwidth.validate({"rules": [{"days": [4], "start": "22:00", "end": "02:00",
                                           "kbps": 800}]})  # fmt: skip
    assert (
        bandwidth.cap_at(night, datetime.datetime(2026, 11, 27, 23, 0)) == 100_000
    )  # Fri
    assert (
        bandwidth.cap_at(night, datetime.datetime(2026, 11, 28, 1, 0)) == 100_000
    )  # Sat am
    assert bandwidth.cap_at(night, datetime.datetime(2026, 11, 28, 23, 0)) == 0


@pytest.mark.parametrize(
    "bad",
    [{"rules": [{"days": [7], "start": "08:00", "end": "09:00", "kbps": 1}]},
     {"rules": [{"days": [1], "start": "8", "end": "09:00", "kbps": 1}]},
     {"rules": [{"days": [1], "start": "08:00", "end": "09:00", "kbps": -1}]},
     {"default_kbps": True}],
)  # fmt: skip
def test_bad_schedules_are_refused(bad):
    with pytest.raises(bandwidth.ScheduleError):
        bandwidth.validate(bad)


def test_the_throttle_holds_the_rate():
    clock = [0.0]
    throttle = bandwidth.Throttle(
        bandwidth.validate({"default_kbps": 80}),  # 10,000 bytes a second
        clock=lambda: clock[0], now=datetime.datetime.now,
        sleep=lambda s: clock.__setitem__(0, clock[0] + s),
    )  # fmt: skip
    throttle.consume(50_000)
    assert 4.5 <= clock[0] <= 5.5


# --- datasets and jobs --------------------------------------------------------------


LISTING = "tank\t/tank\ntank/backups\t/srv/backups\ntank/backups/web-1a2b3c4d\t/srv/backups/web-1a2b3c4d\ntank/backups/db-5e6f7a8b\t/srv/backups/db-5e6f7a8b\ntank/gdr\t/tank/gdr\n"


def test_the_datasets_under_the_storage_path_are_chosen():
    found = ds.filesystems(LISTING)
    root = ds.storage_dataset(found, "/srv/backups/")
    assert root == "tank/backups"
    assert ds.chosen(found, root, [], []) == [
        "tank/backups",
        "tank/backups/db-5e6f7a8b",
        "tank/backups/web-1a2b3c4d",
    ]
    assert ds.chosen(
        found, root, ["tank/backups/db-5e6f7a8b"], ["tank/gdr", "tank/nope"]
    ) == ["tank/backups", "tank/backups/web-1a2b3c4d", "tank/gdr"]


def test_only_the_copys_own_snapshots_are_listed_and_removed():
    listing = ("tank/b@autosnap_2026-11-01\ntank/b@sysmanage-1b4e28ba-2fa1-11d2-883f-0016d3cca427\n"
               "tank/b@sysmanage-offsite-20261101T020000Z\ntank/b@sysmanage-offsite-20261102T020000Z\n"
               "tank/b@sysmanage-offsite-20261103T020000Z\n")  # fmt: skip
    have = ds.offsite_snapshots(listing, "tank/b")
    assert have == ["sysmanage-offsite-20261101T020000Z", "sysmanage-offsite-20261102T020000Z",
                    "sysmanage-offsite-20261103T020000Z"]  # fmt: skip
    assert ds.to_remove(have, ("sysmanage-offsite-20261103T020000Z",
                               "sysmanage-offsite-20261102T020000Z")) == [
        "sysmanage-offsite-20261101T020000Z"]  # fmt: skip
    with pytest.raises(ds.DatasetError):
        ds.destroy("tank/b", "autosnap_2026-11-01")
    with pytest.raises(ds.DatasetError):
        ds.send("tank/b; rm -rf /", "sysmanage-offsite-20261103T020000Z")


def test_the_commands_are_exact():
    snap = "sysmanage-offsite-20261103T020000Z"
    base = "sysmanage-offsite-20261102T020000Z"
    assert ds.take_snapshots(["a/b", "a/c"], snap) == [
        "zfs",
        "snapshot",
        f"a/b@{snap}",
        f"a/c@{snap}",
    ]
    assert ds.send("a/b", snap, base) == [
        "zfs",
        "send",
        "-i",
        f"a/b@{base}",
        f"a/b@{snap}",
    ]
    assert ds.receive("a/r") == ["zfs", "receive", "-u", "a/r"]


def _upload_job(**over):
    job = {"action": "upload", "run_id": str(uuid.uuid4()), "copy_id": str(uuid.uuid4()),
           "bucket": "acme-offsite", "region": "us-east-2", "prefix": "nas/",
           "storage_path": "/srv/backups",
           "retention": {"full_days": 241, "incremental_days": 210}}  # fmt: skip
    job.update(over)
    return job


def test_a_good_upload_job_is_normalized():
    job = jobs.validate(_upload_job())
    assert job["prefix"] == "nas" and job["storage_class"] == "DEEP_ARCHIVE"
    assert job["object_lock"] is True and job["part_bytes"] == 256 << 20
    assert job["endpoint"] is None


@pytest.mark.parametrize(
    "over",
    [{"bucket": "Bad_Bucket"}, {"action": "delete"}, {"prefix": "../x"},
     {"endpoint": "https://user:pw@s3.example"}, {"storage_class": "ONEZONE"},
     {"retention": {"full_days": 0, "incremental_days": 1}}, {"part_bytes": 1 << 20},
     {"storage_path": "relative"}, {"exclude": ["tank/x y"]},
     {"bases": {"tank/b": "autosnap"}}, {"run_id": "nope"}],
)  # fmt: skip
def test_bad_jobs_are_refused(over):
    with pytest.raises(jobs.JobError):
        jobs.validate(_upload_job(**over))


def test_a_restore_job_needs_a_chain_and_a_dataset():
    part = {"key": "nas/d241/x/000000", "sha256": "a" * 64, "index": 0, "bytes": 10}
    stream = {"stream_id": str(uuid.uuid4()), "kind": "full",
              "snapshot": "sysmanage-offsite-20261103T020000Z", "parts": [part]}  # fmt: skip
    base = {
        k: v for k, v in _upload_job().items() if k not in ("storage_path", "retention")
    }
    job = jobs.validate(dict(base, action="restore", streams=[stream],
                             target_dataset="tank/restored"))  # fmt: skip
    assert job["tier"] == "Bulk" and job["thaw_days"] == 7
    with pytest.raises(jobs.JobError):
        jobs.validate(
            dict(base, action="restore", streams=[stream], target_dataset="/x")
        )
    with pytest.raises(jobs.JobError):
        jobs.validate(dict(base, action="restore", streams=[], target_dataset="tank/r"))
