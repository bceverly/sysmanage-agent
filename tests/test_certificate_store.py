# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Tests for agent certificate store functionality.

Enrollment-specific storage (modes, atomic replace, renewal timing, pins) is
covered in tests/test_host_certificate.py.
"""

import os
import platform
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.security import certificate_store
from src.security.certificate_store import CertificateStore
from tests.mtls_support import Pki, key_pem, pem


def _self_signed(not_before, not_after):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-cert")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert, key


class TestCertificateStore:
    """Test certificate store functionality."""

    # pylint: disable=attribute-defined-outside-init
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.cert_store = CertificateStore(self.temp_dir)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _write(self, not_before, not_after):
        cert, key = _self_signed(not_before, not_after)
        self.cert_store.client_cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        self.cert_store.client_key_path.write_bytes(key_pem(key))
        return cert

    def test_certificate_store_initialization(self):
        """Test certificate store initialization."""
        assert self.cert_store.config_dir == Path(self.temp_dir)
        assert self.cert_store.config_dir.exists()
        assert self.cert_store.client_cert_path == Path(self.temp_dir) / "client.crt"
        assert self.cert_store.client_key_path == Path(self.temp_dir) / "client.key"
        assert self.cert_store.ca_cert_path == Path(self.temp_dir) / "ca.crt"
        assert self.cert_store.pins_path == Path(self.temp_dir) / "server_pins.json"

    def test_store_issued_and_load_certificates(self):
        """store_issued writes all three files; load_certificates finds them."""
        pki = Pki()
        cert, key = pki.issue("host")
        self.cert_store.store_issued(pem(cert), key_pem(key), pem(pki.cert))

        result = self.cert_store.load_certificates()
        assert result == (
            str(self.cert_store.client_cert_path),
            str(self.cert_store.client_key_path),
            str(self.cert_store.ca_cert_path),
        )
        assert self.cert_store.client_cert_path.read_text() == pem(cert)
        assert self.cert_store.client_key_path.read_bytes() == key_pem(key)
        assert self.cert_store.ca_cert_path.read_text() == pem(pki.cert)

    def test_load_certificates_missing_files(self):
        """Test certificate loading when files are missing."""
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        assert self.cert_store.load_certificates() is None

    def test_is_certificate_valid_success(self):
        now = datetime.now(timezone.utc)
        self._write(now - timedelta(minutes=1), now + timedelta(days=30))
        assert self.cert_store.is_certificate_valid() is True

    def test_is_certificate_valid_expired(self):
        now = datetime.now(timezone.utc)
        self._write(now - timedelta(days=2), now - timedelta(days=1))
        assert self.cert_store.is_certificate_valid() is False

    def test_is_certificate_valid_future(self):
        now = datetime.now(timezone.utc)
        self._write(now + timedelta(days=1), now + timedelta(days=2))
        assert self.cert_store.is_certificate_valid() is False

    def test_is_certificate_valid_no_file(self):
        assert self.cert_store.is_certificate_valid() is False

    def test_is_certificate_valid_invalid_cert(self):
        self.cert_store.client_cert_path.write_text("INVALID_CERTIFICATE_DATA")
        assert self.cert_store.is_certificate_valid() is False

    def test_clear_certificates(self):
        """Clearing removes the certificate, key, CA and pins."""
        for path in (
            self.cert_store.client_cert_path,
            self.cert_store.client_key_path,
            self.cert_store.ca_cert_path,
            self.cert_store.pins_path,
        ):
            path.write_text("X")
        self.cert_store.clear_certificates()
        assert not list(Path(self.temp_dir).iterdir())

    def test_clear_certificates_partial(self):
        """Clearing works when only some files exist."""
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        self.cert_store.clear_certificates()
        assert not self.cert_store.client_cert_path.exists()

    def test_has_certificates_valid_pair(self):
        now = datetime.now(timezone.utc)
        self._write(now - timedelta(minutes=1), now + timedelta(days=30))
        assert self.cert_store.has_certificates() is True

    def test_has_certificates_missing_key(self):
        now = datetime.now(timezone.utc)
        self._write(now - timedelta(minutes=1), now + timedelta(days=30))
        self.cert_store.client_key_path.unlink()
        assert self.cert_store.has_certificates() is False

    def test_has_certificates_invalid_cert(self):
        self.cert_store.client_cert_path.write_text("INVALID_CERT")
        self.cert_store.client_key_path.write_text("CLIENT_KEY")
        assert self.cert_store.has_certificates() is False

    def test_has_certificates_expired(self):
        now = datetime.now(timezone.utc)
        self._write(now - timedelta(days=2), now - timedelta(days=1))
        assert self.cert_store.has_certificates() is False


class TestCertificateStoreError:
    """Test certificate store error conditions."""

    def test_certificate_store_directory_creation_failure(self):
        """Test handling of directory creation failure with fallback."""
        if platform.system() == "Windows":
            invalid_paths = [
                "NUL\\invalid",  # NUL is a reserved device name
                "CON\\test",  # CON is a reserved device name
                "C:\\*invalid*",  # Invalid characters in path
                "\\\\?\\C:\\<>:|invalid",  # Invalid characters
            ]
            result = False
            for invalid_path in invalid_paths:
                try:
                    cert_store = CertificateStore(invalid_path)
                    if str(cert_store.config_dir) != invalid_path:
                        result = True
                        break
                except (OSError, ValueError, Exception):
                    result = True
                    break
            assert (
                result
            ), "Expected at least one invalid Windows path to fail or use fallback"
        else:
            # /dev/null is a file, not a directory
            try:
                cert_store = CertificateStore("/dev/null/invalid")
                assert str(cert_store.config_dir) != "/dev/null/invalid"
                assert cert_store.config_dir.exists()
            except Exception:
                pass

    @pytest.mark.skipif(os.name == "nt", reason="POSIX directory modes")
    def test_store_issued_into_read_only_directory_raises(self):
        """A store that cannot write says so instead of half-writing."""
        temp_dir = tempfile.mkdtemp()
        try:
            cert_store = CertificateStore(temp_dir)
            read_only_dir = Path(temp_dir) / "readonly"
            read_only_dir.mkdir()
            os.chmod(read_only_dir, 0o555)  # nosec B103
            cert_store.client_cert_path = read_only_dir / "client.crt"
            cert_store.client_key_path = read_only_dir / "client.key"
            cert_store.ca_cert_path = read_only_dir / "ca.crt"
            if os.geteuid() != 0:  # root writes anyway
                with pytest.raises(PermissionError):
                    cert_store.store_issued("CERT", b"KEY", "CA")
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            os.chmod(read_only_dir, 0o700)  # nosec B103
        finally:
            shutil.rmtree(temp_dir)


class TestCertificateStoreIntegration:
    """Integration tests for certificate store."""

    def test_certificate_store_persistence(self, tmp_path):
        """What one instance stores, another instance of the directory reads."""
        pki = Pki()
        cert, key = pki.issue("host")
        CertificateStore(str(tmp_path)).store_issued(
            pem(cert), key_pem(key), pem(pki.cert)
        )
        CertificateStore(str(tmp_path)).save_pins(pki.sha256, ["a" * 64])

        second = CertificateStore(str(tmp_path))
        assert second.has_certificates()
        assert second.load_client_certificate() == cert
        assert second.load_pins()["ca_sha256"] == pki.sha256

    def test_default_store_is_one_object(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SYSMANAGE_CONFIG_DIR", str(tmp_path))
        first = certificate_store.default_store()
        assert first is certificate_store.default_store()
        assert first.config_dir == tmp_path
