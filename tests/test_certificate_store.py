"""
Tests for agent certificate store functionality.
"""

import os
import tempfile
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from security.certificate_store import CertificateStore


class TestCertificateStore:  # pylint: disable=too-many-public-methods
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

    def test_certificate_store_initialization(self):
        """Test certificate store initialization."""
        assert self.cert_store.config_dir == Path(self.temp_dir)
        assert self.cert_store.config_dir.exists()

        # Check file paths are set correctly
        assert self.cert_store.client_cert_path == Path(self.temp_dir) / "client.crt"
        assert self.cert_store.client_key_path == Path(self.temp_dir) / "client.key"
        assert self.cert_store.ca_cert_path == Path(self.temp_dir) / "ca.crt"
        assert (
            self.cert_store.server_fingerprint_path
            == Path(self.temp_dir) / "server.fingerprint"
        )

    def test_store_certificates(self):
        """Test storing certificate data."""
        cert_data = {
            "certificate": "-----BEGIN CERTIFICATE-----\nCLIENT_CERT_DATA\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY_DATA\n-----END PRIVATE KEY-----",
            "ca_certificate": "-----BEGIN CERTIFICATE-----\nCA_CERT_DATA\n-----END CERTIFICATE-----",
            "server_fingerprint": "ABCD1234567890ABCD1234567890ABCD1234567890ABCD1234567890ABCD1234",
        }

        self.cert_store.store_certificates(cert_data)

        # Check all files were created
        assert self.cert_store.client_cert_path.exists()
        assert self.cert_store.client_key_path.exists()
        assert self.cert_store.ca_cert_path.exists()
        assert self.cert_store.server_fingerprint_path.exists()

        # Check file contents
        assert self.cert_store.client_cert_path.read_text() == cert_data["certificate"]
        assert self.cert_store.client_key_path.read_text() == cert_data["private_key"]
        assert self.cert_store.ca_cert_path.read_text() == cert_data["ca_certificate"]
        assert (
            self.cert_store.server_fingerprint_path.read_text()
            == cert_data["server_fingerprint"]
        )

    def test_store_certificates_file_permissions(self):
        """Test that stored certificates have correct file permissions."""
        cert_data = {
            "certificate": "CLIENT_CERT",
            "private_key": "PRIVATE_KEY",
            "ca_certificate": "CA_CERT",
            "server_fingerprint": "FINGERPRINT",
        }

        self.cert_store.store_certificates(cert_data)

        # Client private key should be 0600 (owner read/write only)
        key_perms = oct(self.cert_store.client_key_path.stat().st_mode)[-3:]
        assert key_perms == "600"

        # Other files should be 0644 (world readable)
        cert_perms = oct(self.cert_store.client_cert_path.stat().st_mode)[-3:]
        assert cert_perms == "644"

        ca_perms = oct(self.cert_store.ca_cert_path.stat().st_mode)[-3:]
        assert ca_perms == "644"

        fingerprint_perms = oct(self.cert_store.server_fingerprint_path.stat().st_mode)[
            -3:
        ]
        assert fingerprint_perms == "644"

    def test_load_certificates_success(self):
        """Test successful certificate loading."""
        # Create test certificate files
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        self.cert_store.client_key_path.write_text("CLIENT_KEY")
        self.cert_store.ca_cert_path.write_text("CA_CERT")

        result = self.cert_store.load_certificates()

        assert result is not None
        assert len(result) == 3
        assert result[0] == str(self.cert_store.client_cert_path)
        assert result[1] == str(self.cert_store.client_key_path)
        assert result[2] == str(self.cert_store.ca_cert_path)

    def test_load_certificates_missing_files(self):
        """Test certificate loading when files are missing."""
        # Only create some files
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        # Missing client key and CA cert

        result = self.cert_store.load_certificates()
        assert result is None

    def test_get_server_fingerprint_success(self):
        """Test successful server fingerprint retrieval."""
        fingerprint = "ABCD1234567890ABCD1234567890ABCD1234567890ABCD1234567890ABCD1234"
        self.cert_store.server_fingerprint_path.write_text(fingerprint)

        result = self.cert_store.get_server_fingerprint()
        assert result == fingerprint

    def test_get_server_fingerprint_missing(self):
        """Test server fingerprint retrieval when file missing."""
        result = self.cert_store.get_server_fingerprint()
        assert result is None

    def test_validate_server_certificate_success(self):
        """Test successful server certificate validation."""
        # Create a test certificate DER data
        test_cert_der = b"test_certificate_data"
        expected_fingerprint = hashlib.sha256(test_cert_der).hexdigest().upper()

        # Store the fingerprint
        self.cert_store.server_fingerprint_path.write_text(expected_fingerprint)

        result = self.cert_store.validate_server_certificate(test_cert_der)
        assert result is True

    def test_validate_server_certificate_mismatch(self):
        """Test server certificate validation with fingerprint mismatch."""
        # Store a different fingerprint
        self.cert_store.server_fingerprint_path.write_text("DIFFERENT_FINGERPRINT")

        test_cert_der = b"test_certificate_data"
        result = self.cert_store.validate_server_certificate(test_cert_der)
        assert result is False

    def test_validate_server_certificate_no_stored_fingerprint(self):
        """Test server certificate validation when no fingerprint stored."""
        test_cert_der = b"test_certificate_data"
        result = self.cert_store.validate_server_certificate(test_cert_der)
        assert result is False

    def create_test_certificate(self, valid_days=365):
        """Helper method to create a test certificate."""
        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create certificate
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test-cert")]
        )

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=valid_days))
            .sign(private_key, hashes.SHA256())
        )

        return cert

    def test_is_certificate_valid_success(self):
        """Test certificate validity check for valid certificate."""
        # Create valid certificate
        cert = self.create_test_certificate(valid_days=30)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Store certificate
        self.cert_store.client_cert_path.write_bytes(cert_pem)

        result = self.cert_store.is_certificate_valid()
        assert result is True

    def test_is_certificate_valid_expired(self):
        """Test certificate validity check for expired certificate."""
        # Create expired certificate - use past valid dates
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test-cert")]
        )

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))  # Valid 2 days ago
            .not_valid_after(now - timedelta(days=1))  # Expired 1 day ago
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Store certificate
        self.cert_store.client_cert_path.write_bytes(cert_pem)

        result = self.cert_store.is_certificate_valid()
        assert result is False

    def test_is_certificate_valid_not_yet_valid(self):
        """Test certificate validity check for not-yet-valid certificate."""
        # Create certificate that's valid starting tomorrow
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test-cert")]
        )

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=1))  # Valid starting tomorrow
            .not_valid_after(now + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self.cert_store.client_cert_path.write_bytes(cert_pem)

        result = self.cert_store.is_certificate_valid()
        assert result is False

    def test_is_certificate_valid_missing_file(self):
        """Test certificate validity check when certificate file missing."""
        result = self.cert_store.is_certificate_valid()
        assert result is False

    def test_is_certificate_valid_invalid_format(self):
        """Test certificate validity check with invalid certificate format."""
        # Store invalid certificate data
        self.cert_store.client_cert_path.write_text("INVALID_CERTIFICATE_DATA")

        result = self.cert_store.is_certificate_valid()
        assert result is False

    def test_clear_certificates(self):
        """Test clearing all stored certificates."""
        # Create test files
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        self.cert_store.client_key_path.write_text("CLIENT_KEY")
        self.cert_store.ca_cert_path.write_text("CA_CERT")
        self.cert_store.server_fingerprint_path.write_text("FINGERPRINT")

        # Verify files exist
        assert self.cert_store.client_cert_path.exists()
        assert self.cert_store.client_key_path.exists()
        assert self.cert_store.ca_cert_path.exists()
        assert self.cert_store.server_fingerprint_path.exists()

        # Clear certificates
        self.cert_store.clear_certificates()

        # Verify files are gone
        assert not self.cert_store.client_cert_path.exists()
        assert not self.cert_store.client_key_path.exists()
        assert not self.cert_store.ca_cert_path.exists()
        assert not self.cert_store.server_fingerprint_path.exists()

    def test_clear_certificates_partial_files(self):
        """Test clearing certificates when only some files exist."""
        # Only create some files
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        self.cert_store.server_fingerprint_path.write_text("FINGERPRINT")

        # Should not raise error when clearing
        self.cert_store.clear_certificates()

        # Should have removed existing files
        assert not self.cert_store.client_cert_path.exists()
        assert not self.cert_store.server_fingerprint_path.exists()

    def test_has_certificates_success(self):
        """Test has_certificates when all certificates are valid."""
        # Create valid certificate
        cert = self.create_test_certificate(valid_days=30)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Store all required files
        self.cert_store.client_cert_path.write_bytes(cert_pem)
        self.cert_store.client_key_path.write_text("CLIENT_KEY")
        self.cert_store.ca_cert_path.write_text("CA_CERT")
        self.cert_store.server_fingerprint_path.write_text("FINGERPRINT")

        result = self.cert_store.has_certificates()
        assert result is True

    def test_has_certificates_missing_files(self):
        """Test has_certificates when files are missing."""
        # Only create some files
        self.cert_store.client_cert_path.write_text("CLIENT_CERT")
        # Missing other files

        result = self.cert_store.has_certificates()
        assert result is False

    def test_has_certificates_invalid_cert(self):
        """Test has_certificates when certificate is invalid."""
        # Store invalid certificate
        self.cert_store.client_cert_path.write_text("INVALID_CERT")
        self.cert_store.client_key_path.write_text("CLIENT_KEY")
        self.cert_store.ca_cert_path.write_text("CA_CERT")
        self.cert_store.server_fingerprint_path.write_text("FINGERPRINT")

        result = self.cert_store.has_certificates()
        assert result is False

    def test_has_certificates_no_fingerprint(self):
        """Test has_certificates when server fingerprint is missing."""
        # Create valid certificate but no fingerprint
        cert = self.create_test_certificate(valid_days=30)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        self.cert_store.client_cert_path.write_bytes(cert_pem)
        self.cert_store.client_key_path.write_text("CLIENT_KEY")
        self.cert_store.ca_cert_path.write_text("CA_CERT")
        # No fingerprint file

        result = self.cert_store.has_certificates()
        assert result is False


class TestCertificateStoreError:
    """Test certificate store error conditions."""

    def test_certificate_store_directory_creation_failure(self):
        """Test handling of directory creation failure."""
        # Try to create certificate store in invalid location
        with pytest.raises(Exception):
            CertificateStore("/dev/null/invalid")

    def test_certificate_store_permission_errors(self):
        """Test handling of permission errors during file operations."""
        temp_dir = tempfile.mkdtemp()
        try:
            cert_store = CertificateStore(temp_dir)

            # Create read-only directory to simulate permission error
            read_only_dir = Path(temp_dir) / "readonly"
            read_only_dir.mkdir()
            os.chmod(read_only_dir, 0o555)  # Read and execute only

            cert_data = {
                "certificate": "CERT",
                "private_key": "KEY",
                "ca_certificate": "CA",
                "server_fingerprint": "FINGERPRINT",
            }

            # Override paths to point to read-only directory
            cert_store.client_cert_path = read_only_dir / "client.crt"
            cert_store.client_key_path = read_only_dir / "client.key"
            cert_store.ca_cert_path = read_only_dir / "ca.crt"
            cert_store.server_fingerprint_path = read_only_dir / "server.fingerprint"

            # Should raise PermissionError
            with pytest.raises(PermissionError):
                cert_store.store_certificates(cert_data)

        finally:
            # Clean up - restore permissions first
            read_only_dir = Path(temp_dir) / "readonly"
            if read_only_dir.exists():
                os.chmod(read_only_dir, 0o755)
            shutil.rmtree(temp_dir)


class TestCertificateStoreIntegration:
    """Integration tests for certificate store."""

    # pylint: disable=attribute-defined-outside-init
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.cert_store = CertificateStore(self.temp_dir)

    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_complete_certificate_workflow(self):
        """Test complete certificate storage and validation workflow."""
        # 1. Store certificates
        cert_data = {
            "certificate": "-----BEGIN CERTIFICATE-----\nCLIENT_CERT_DATA\n-----END CERTIFICATE-----",
            "private_key": "-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY_DATA\n-----END PRIVATE KEY-----",
            "ca_certificate": "-----BEGIN CERTIFICATE-----\nCA_CERT_DATA\n-----END CERTIFICATE-----",
            "server_fingerprint": "ABCD1234567890ABCD1234567890ABCD1234567890ABCD1234567890ABCD1234",
        }

        self.cert_store.store_certificates(cert_data)

        # 2. Verify certificates can be loaded
        cert_paths = self.cert_store.load_certificates()
        assert cert_paths is not None
        assert len(cert_paths) == 3

        # 3. Verify server fingerprint retrieval
        fingerprint = self.cert_store.get_server_fingerprint()
        assert fingerprint == cert_data["server_fingerprint"]

        # 4. Test server certificate validation
        test_cert_der = b"test_certificate_data"
        expected_fingerprint = hashlib.sha256(test_cert_der).hexdigest().upper()

        # Update fingerprint to match test data
        self.cert_store.server_fingerprint_path.write_text(expected_fingerprint)
        result = self.cert_store.validate_server_certificate(test_cert_der)
        assert result is True

        # 5. Clear all certificates
        self.cert_store.clear_certificates()

        # 6. Verify everything is cleaned up
        assert not self.cert_store.has_certificates()
        assert self.cert_store.load_certificates() is None
        assert self.cert_store.get_server_fingerprint() is None

    def test_certificate_store_persistence(self):
        """Test that certificate store persists across instances."""
        # Create first certificate store instance
        cert_store1 = CertificateStore(self.temp_dir)

        cert_data = {
            "certificate": "PERSISTENT_CERT",
            "private_key": "PERSISTENT_KEY",
            "ca_certificate": "PERSISTENT_CA",
            "server_fingerprint": "PERSISTENT_FINGERPRINT",
        }

        cert_store1.store_certificates(cert_data)

        # Create second certificate store instance
        cert_store2 = CertificateStore(self.temp_dir)

        # Verify data persists
        assert cert_store2.load_certificates() is not None
        assert cert_store2.get_server_fingerprint() == "PERSISTENT_FINGERPRINT"

        # Verify file contents are correct
        assert cert_store2.client_cert_path.read_text() == "PERSISTENT_CERT"
        assert cert_store2.ca_cert_path.read_text() == "PERSISTENT_CA"
