# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The off-site copy's encryption: AES-256 only (server ROADMAP 27.3).

Nothing leaves the site unencrypted, and nothing in this layer can be broken
by a quantum computer: there is no RSA or elliptic-curve key wrapping, only
AES-256-GCM under a 32-byte key that the operator holds (OpenBAO, and the
break-glass export).  Grover's algorithm leaves AES-256 at 128-bit strength.

Every object (a part of a ``zfs send`` stream, or a manifest) is one
"SMOC1" stream::

    header  "SMOC" | version 1 | flags 0 | log2(chunk size) | 0
            | key id (8) | stream id (16) | part index (4, big-endian)
            | salt (32)                                      = 68 bytes
    chunks  AES-256-GCM(plaintext chunk) + 16-byte tag, each chunk_size
            bytes of plaintext except the last

* The object's own key is HKDF-SHA256(master key, salt, info) with a random
  32-byte salt per object, so no two objects share a key and nonces can be
  counters.
* Chunk ``i``'s nonce is seven zero bytes, ``i`` (4 bytes) and a final flag:
  1 on the last chunk only (the STREAM construction).  Cutting an object
  short, or dropping, repeating or reordering chunks, fails to decrypt.
* The header is every chunk's associated data, so the stream id and part
  index are authenticated: a part cannot be passed off as another one.
* The key id (HMAC-SHA256 of a fixed label under the key, 8 bytes) says
  which key an object needs, without revealing it.
"""

import hashlib
import hmac
import os
import struct
import uuid
from typing import BinaryIO, Callable, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SMOC"
VERSION = 1
KEY_BYTES = 32
SALT_BYTES = 32
TAG_BYTES = 16
CHUNK_LOG2 = 20  # 1 MiB of plaintext per chunk
HEADER = struct.Struct(">4sBBBB8s16sI32s")
HEADER_BYTES = HEADER.size
MANIFEST_PART = 0xFFFFFFFF
MAX_CHUNKS = 0xFFFFFFFF
_KEY_ID_LABEL = b"sysmanage-offsite-key-id"
_INFO = b"sysmanage-offsite-v1"


class DecryptError(ValueError):
    """An object that is not ours, needs another key, or was altered."""


def new_key() -> bytes:
    """A fresh 32-byte AES-256 key."""
    return os.urandom(KEY_BYTES)


def key_id(key: bytes) -> str:
    """The 16-hex-digit name of ``key``; reveals nothing about it."""
    _check_key(key)
    return hmac.new(key, _KEY_ID_LABEL, hashlib.sha256).hexdigest()[:16]


def _check_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise ValueError("the off-site key must be 32 bytes")


def _object_key(key: bytes, salt: bytes, kid: bytes) -> AESGCM:
    derived = HKDF(
        algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=_INFO + kid
    ).derive(bytes(key))
    return AESGCM(derived)


def _nonce(index: int, last: bool) -> bytes:
    # A counter nonce is safe here: each object has its own key, derived from
    # a random 32-byte salt, so no (key, nonce) pair ever repeats.
    flag = b"\1" if last else b"\0"
    return b"\0" * 7 + struct.pack(">I", index) + flag  # nosemgrep


class Header:  # pylint: disable=too-few-public-methods
    """A parsed SMOC1 header."""

    def __init__(self, raw: bytes):
        if len(raw) != HEADER_BYTES:
            raise DecryptError("not an off-site copy object (too short)")
        magic, version, _flags, log2, _zero, kid, stream, part, salt = HEADER.unpack(
            raw
        )
        if magic != MAGIC:
            raise DecryptError("not an off-site copy object")
        if version != VERSION:
            raise DecryptError(f"unknown off-site copy format version {version}")
        if not 12 <= log2 <= 26:
            raise DecryptError("bad chunk size in the object header")
        self.raw = raw
        self.key_id = kid.hex()
        self.stream_id = str(uuid.UUID(bytes=stream))
        self.part_index = part
        self.salt = salt
        self.chunk_size = 1 << log2


def header_bytes(key: bytes, stream_id: str, part_index: int, salt: bytes) -> bytes:
    return HEADER.pack(
        MAGIC, VERSION, 0, CHUNK_LOG2, 0, bytes.fromhex(key_id(key)),
        uuid.UUID(str(stream_id)).bytes, part_index, salt,
    )  # fmt: skip


class Encryptor:
    """Seal one object's chunks in order; ``header`` goes first."""

    def __init__(
        self, key: bytes, stream_id: str, part_index: int, salt: Optional[bytes] = None
    ):
        _check_key(key)
        self.salt = salt if salt is not None else os.urandom(SALT_BYTES)
        self.header = header_bytes(key, stream_id, part_index, self.salt)
        self._aead = _object_key(key, self.salt, self.header[8:16])
        self._index = 0
        self._done = False

    def seal(self, chunk: bytes, last: bool) -> bytes:
        if self._done:
            raise ValueError("this object is already finished")
        if len(chunk) > (1 << CHUNK_LOG2):
            raise ValueError("chunk larger than the chunk size")
        if self._index > MAX_CHUNKS:
            raise ValueError("too many chunks in one object")
        out = self._aead.encrypt(_nonce(self._index, last), bytes(chunk), self.header)
        self._index += 1
        self._done = last
        return out


class ChunkSource:
    """Plaintext chunks from a pipe, with one chunk of look-ahead, so the
    last chunk of the stream is known when it is sealed."""

    def __init__(self, read: Callable[[int], bytes], chunk_size: int = 1 << CHUNK_LOG2):
        self._read = read
        self.chunk_size = chunk_size
        self._next = self._fill()
        self.consumed = 0
        self.sha256 = hashlib.sha256()

    def _fill(self) -> bytes:
        parts = []
        wanted = self.chunk_size
        while wanted:
            data = self._read(wanted)
            if not data:
                break
            parts.append(data)
            wanted -= len(data)
        return b"".join(parts)

    @property
    def exhausted(self) -> bool:
        return not self._next

    def take(self) -> Tuple[bytes, bool]:
        """``(chunk, stream_ends_after_it)``."""
        chunk = self._next
        self._next = self._fill() if len(chunk) == self.chunk_size else b""
        self.consumed += len(chunk)
        self.sha256.update(chunk)
        return chunk, not self._next


def encrypt_part(
    source: ChunkSource,
    out: BinaryIO,
    key: bytes,
    stream_id: str,
    part_index: int,
    limit: int,
) -> Tuple[int, int, str]:
    """Seal up to ``limit`` plaintext bytes (whole chunks) of ``source`` into
    ``out`` as one object; ``(plaintext bytes, object bytes, object sha256)``.

    The object's last chunk is the stream's last chunk or the one that
    reaches ``limit``.  An empty stream still makes one (empty) object.
    """
    if limit < source.chunk_size:
        raise ValueError("a part must hold at least one chunk")
    sealer = Encryptor(key, stream_id, part_index)
    digest = hashlib.sha256(sealer.header)
    out.write(sealer.header)
    plain = 0
    written = len(sealer.header)
    while True:
        chunk, ends = source.take()
        plain += len(chunk)
        last = ends or plain + source.chunk_size > limit
        sealed = sealer.seal(chunk, last)
        out.write(sealed)
        digest.update(sealed)
        written += len(sealed)
        if last:
            return plain, written, digest.hexdigest()


def decrypt_object(
    read: Callable[[int], bytes],
    write: Callable[[bytes], object],
    key: bytes,
    stream_id: Optional[str] = None,
    part_index: Optional[int] = None,
) -> int:
    """Decrypt one object from ``read`` into ``write``; the plaintext bytes.

    Refuses (DecryptError) an object for another key, stream or part, an
    altered one, and one cut short -- nothing after the final chunk either.
    """
    _check_key(key)
    head = Header(_read_exactly(read, HEADER_BYTES))
    if head.key_id != key_id(key):
        raise DecryptError(f"this object needs the key {head.key_id}")
    if stream_id is not None and head.stream_id != str(uuid.UUID(str(stream_id))):
        raise DecryptError("this object belongs to another stream")
    if part_index is not None and head.part_index != part_index:
        raise DecryptError("this object is another part of its stream")
    aead = _object_key(key, head.salt, bytes.fromhex(head.key_id))
    size = head.chunk_size + TAG_BYTES
    index = total = 0
    current = _read_exactly(read, size, allow_short=True)
    while True:
        following = _read_exactly(read, size, allow_short=True) if current else b""
        last = not following
        try:
            plain = aead.decrypt(_nonce(index, last), current, head.raw)
        except InvalidTag as error:
            raise DecryptError(
                "the object was altered, cut short or needs another key"
            ) from error
        write(plain)
        total += len(plain)
        if last:
            return total
        index += 1
        current = following


def _read_exactly(
    read: Callable[[int], bytes], size: int, allow_short: bool = False
) -> bytes:
    parts = []
    wanted = size
    while wanted:
        data = read(wanted)
        if not data:
            break
        parts.append(data)
        wanted -= len(data)
    got = b"".join(parts)
    if len(got) != size and not allow_short:
        raise DecryptError("the object is cut short")
    return got


def seal_bytes(key: bytes, stream_id: str, part_index: int, data: bytes) -> bytes:
    """A whole small object (a manifest) in memory."""
    import io  # pylint: disable=import-outside-toplevel

    out = io.BytesIO()
    source = ChunkSource(io.BytesIO(data).read)
    limit = max(len(data), 1) + source.chunk_size
    encrypt_part(source, out, key, stream_id, part_index, limit)
    return out.getvalue()


def open_bytes(key: bytes, blob: bytes, stream_id: Optional[str] = None,
               part_index: Optional[int] = None) -> bytes:  # fmt: skip
    import io  # pylint: disable=import-outside-toplevel

    out = io.BytesIO()
    decrypt_object(io.BytesIO(blob).read, out.write, key, stream_id, part_index)
    return out.getvalue()
