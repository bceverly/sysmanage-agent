# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Certificate storage for agent mutual TLS and server pinning (ROADMAP 25.10).

Holds, in one directory:

* ``client.key`` -- the host's EC P-256 private key.  Generated on this host
  and never sent anywhere; created 0600 (the mode is set when the file is
  created, not afterwards, so there is no moment it is readable by others).
* ``client.crt`` -- the certificate the server issued for that key (0644).
* ``ca.crt`` -- the SysManage CA that issued it (0644).  ADDED to the trust
  used for the server, never a replacement for the system store.
* ``server_pins.json`` -- the pinned server identity (0644), see
  ``server_pinning``.

Every write goes to a temporary file in the same directory and is then moved
into place with ``os.replace``, so a reader sees the old file or the new one,
never half of either.  A renewal keeps the previous key and certificate until
the new pair is complete on disk.
"""

import functools
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from src.i18n import _

# Renew this long before the certificate expires (the server's renew_after is
# the same: not_after - 30 days).
RENEW_BEFORE = timedelta(days=30)
# How many server SPKI pins are kept: the current one plus the previous two,
# enough to ride out a certificate change in either direction.
MAX_PINS = 3
PINS_VERSION = 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

KEY_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0600
PUBLIC_MODE = (
    stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH  # NOSONAR - 0644
)


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 -- the form every pin is written in."""
    return hashlib.sha256(data).hexdigest()


def _stage(path: Path, data: bytes, mode: int) -> Path:
    """Write ``data`` to a fresh temporary file beside ``path``; return it.

    ``os.open`` with the mode creates the file with it, so a private key is
    never readable by anyone else even for an instant.  The explicit chmod
    after it only undoes a umask that narrowed a public file.
    """
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    handle = os.open(str(tmp), flags, mode)
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        if os.name != "nt":
            os.chmod(tmp, mode)
    except BaseException:
        _discard(tmp)
        raise
    return tmp


def _discard(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    """Replace ``path`` with ``data`` in one step (temp file + os.replace)."""
    tmp = _stage(path, data, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        _discard(tmp)
        raise


class CertificateStore:
    """Manages certificate storage and validation for agent authentication."""

    def __init__(self, config_dir: Optional[str] = None):
        """Initialize certificate store with config directory."""
        # Set platform-specific default path if none provided
        if config_dir is None:
            if os.name == "nt":  # Windows
                config_dir = r"C:\ProgramData\SysManage"
            else:  # Unix-like (Linux, macOS, BSD)
                config_dir = "/etc/sysmanage-agent"

        # Use a safe default path for testing only if using the default production path
        default_paths = ["/etc/sysmanage-agent", r"C:\ProgramData\SysManage"]
        if "PYTEST_CURRENT_TEST" in os.environ and config_dir in default_paths:
            config_dir = tempfile.mkdtemp(prefix="sysmanage_agent_test_certs_")

        self.config_dir = Path(config_dir)

        # Try to create the system directory, fall back to local directory if permission denied
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            # Set directory permissions (Unix only)
            # Skip chmod if we don't have permission (e.g., snap common directory owned by root)
            if os.name != "nt":
                try:
                    os.chmod(
                        self.config_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
                    )
                except OSError:
                    # Directory exists but we can't chmod it - that's okay if we can write to it
                    pass
        except OSError:
            # Fall back to local directory in the same location as the running script
            script_dir = Path(sys.argv[0]).parent.resolve()
            fallback_dir = script_dir / ".sysmanage-agent"

            print(
                _(
                    "⚠️  Cannot access {config_dir}, falling back to {fallback_dir}"
                ).format(config_dir=config_dir, fallback_dir=fallback_dir)
            )
            self.config_dir = fallback_dir
            self.config_dir.mkdir(parents=True, exist_ok=True)
            # Set directory permissions (Unix only)
            if os.name != "nt":
                os.chmod(self.config_dir, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        # Certificate file paths
        self.client_cert_path = self.config_dir / "client.crt"
        self.client_key_path = self.config_dir / "client.key"
        self.ca_cert_path = self.config_dir / "ca.crt"
        self.pins_path = self.config_dir / "server_pins.json"

    # -- the host's own certificate -------------------------------------

    def store_issued(self, certificate_pem: str, key_pem: bytes, ca_pem: str) -> None:
        """Store a newly issued certificate, its key and the issuing CA.

        All three are written to temporary files first; only when every one
        is complete are they moved into place, key and certificate back to
        back.  Until then the previous pair stays in use untouched.
        """
        staged = [
            (_stage(self.client_key_path, key_pem, KEY_MODE), self.client_key_path),
            (
                _stage(
                    self.client_cert_path, certificate_pem.encode("ascii"), PUBLIC_MODE
                ),
                self.client_cert_path,
            ),
            (
                _stage(self.ca_cert_path, ca_pem.encode("ascii"), PUBLIC_MODE),
                self.ca_cert_path,
            ),
        ]
        try:
            for tmp, final in staged:
                os.replace(tmp, final)
        finally:
            for tmp, _final in staged:
                if tmp.exists():
                    _discard(tmp)

    def load_client_certificate(self) -> Optional[x509.Certificate]:
        """The stored client certificate, or None if absent or unreadable."""
        try:
            return x509.load_pem_x509_certificate(self.client_cert_path.read_bytes())
        except (OSError, ValueError):
            return None

    def _key_matches(self, cert: x509.Certificate) -> bool:
        """Whether client.key is the private half of ``cert``."""
        try:
            key = serialization.load_pem_private_key(
                self.client_key_path.read_bytes(), password=None
            )
        except (OSError, ValueError, TypeError):
            return False
        spki = (
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return key.public_key().public_bytes(*spki) == cert.public_key().public_bytes(
            *spki
        )

    def certificate_state(
        self, now: Optional[datetime] = None
    ) -> Tuple[str, Optional[datetime]]:
        """``("none" | "expired" | "valid", not_after)`` for the stored pair.

        "none" also covers a certificate without its matching key: such a
        pair cannot be presented, and the cure is the same -- a new one.
        """
        cert = self.load_client_certificate()
        if cert is None or not self._key_matches(cert):
            return "none", None
        now = now or datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        if not cert.not_valid_before_utc <= now < not_after:
            return "expired", not_after
        return "valid", not_after

    def presentable_paths(
        self, now: Optional[datetime] = None
    ) -> Optional[Tuple[str, str]]:
        """``(cert, key)`` paths when the pair may be presented, else None.

        An expired certificate is never presented.
        """
        state, _not_after = self.certificate_state(now)
        if state != "valid":
            return None
        return str(self.client_cert_path), str(self.client_key_path)

    def needs_renewal(self, now: Optional[datetime] = None) -> bool:
        """No certificate, an expired one, or inside the 30-day renewal window."""
        now = now or datetime.now(timezone.utc)
        state, not_after = self.certificate_state(now)
        if state != "valid" or not_after is None:
            return True
        return now >= not_after - RENEW_BEFORE

    def ca_certificate_der(self) -> Optional[bytes]:
        """The stored SysManage CA in DER form, or None."""
        try:
            ca = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        except (OSError, ValueError):
            return None
        return ca.public_bytes(serialization.Encoding.DER)

    def load_certificates(self) -> Optional[Tuple[str, str, str]]:
        """
        Load stored certificates.

        Returns:
            Tuple of (client_cert_path, client_key_path, ca_cert_path) or None
        """
        if not all(
            [
                self.client_cert_path.exists(),
                self.client_key_path.exists(),
                self.ca_cert_path.exists(),
            ]
        ):
            return None

        return (
            str(self.client_cert_path),
            str(self.client_key_path),
            str(self.ca_cert_path),
        )

    def is_certificate_valid(self) -> bool:
        """Check if stored client certificate is still valid."""
        cert = self.load_client_certificate()
        if cert is None:
            return False
        now = datetime.now(timezone.utc)
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

    def has_certificates(self) -> bool:
        """Whether an unexpired certificate and its key are stored."""
        return self.presentable_paths() is not None

    # -- server pins ------------------------------------------------------

    def load_pins(self) -> Optional[Dict[str, Any]]:
        """The pins file, or None when there is none or it is not usable.

        An unusable file is treated as absent: the agent pins afresh on its
        next successful connection, exactly as after a deliberate reset.
        """
        try:
            data = json.loads(self.pins_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("v") != PINS_VERSION:
            return None
        ca_sha256 = data.get("ca_sha256")
        spkis = data.get("spki_sha256")
        if not isinstance(ca_sha256, str) or not _HEX64.match(ca_sha256):
            return None
        if not isinstance(spkis, list) or not spkis:
            return None
        if not all(isinstance(s, str) and _HEX64.match(s) for s in spkis):
            return None
        return {"v": PINS_VERSION, "ca_sha256": ca_sha256, "spki_sha256": spkis}

    def save_pins(self, ca_sha256: str, spki_sha256: List[str]) -> None:
        """Write the pins, newest SPKI first, keeping at most MAX_PINS."""
        kept: List[str] = []
        for spki in spki_sha256:
            spki = spki.lower()
            if spki not in kept:
                kept.append(spki)
        document = {
            "v": PINS_VERSION,
            "ca_sha256": ca_sha256.lower(),
            "spki_sha256": kept[:MAX_PINS],
        }
        write_atomic(
            self.pins_path,
            (json.dumps(document, indent=2) + "\n").encode("utf-8"),
            PUBLIC_MODE,
        )

    def add_pin(self, spki_sha256: str) -> None:
        """Trust one more server SPKI under the already pinned CA."""
        pins = self.load_pins()
        if pins is None:
            raise ValueError("no pins to add to")
        self.save_pins(pins["ca_sha256"], [spki_sha256] + pins["spki_sha256"])

    def clear_pins(self) -> bool:
        """Remove the pins file.  True if there was one."""
        if not self.pins_path.exists():
            return False
        self.pins_path.unlink()
        return True

    def clear_certificates(self) -> None:
        """Remove the certificate, key, CA and pins."""
        for path in [
            self.client_cert_path,
            self.client_key_path,
            self.ca_cert_path,
            self.pins_path,
        ]:
            if path.exists():
                path.unlink()


@functools.lru_cache(maxsize=4)
def _store_for(config_dir: Optional[str]) -> CertificateStore:
    return CertificateStore(config_dir=config_dir)


def default_store() -> CertificateStore:
    """The agent's one certificate store.

    ``SYSMANAGE_CONFIG_DIR`` (snap confinement) chooses the directory, as it
    always has.  Cached so the agent, its REST calls and its WebSocket all see
    the same files through the same object.
    """
    return _store_for(os.environ.get("SYSMANAGE_CONFIG_DIR"))
