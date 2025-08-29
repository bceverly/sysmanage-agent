"""
Certificate storage and validation for agent mTLS authentication.

This module handles storing, loading, and validating certificates
for secure communication with the SysManage server.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class CertificateStore:
    """Manages certificate storage and validation for agent authentication."""

    def __init__(self, config_dir: str = "/etc/sysmanage-agent"):
        """Initialize certificate store with config directory."""
        # Use a safe default path for testing only if using the default production path
        import os

        if "PYTEST_CURRENT_TEST" in os.environ and config_dir == "/etc/sysmanage-agent":
            import tempfile

            config_dir = tempfile.mkdtemp(prefix="sysmanage_agent_test_certs_")

        self.config_dir = Path(config_dir)

        # Try to create the system directory, fall back to local directory if permission denied
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.config_dir, 0o700)
        except PermissionError:
            # Fall back to local directory in the same location as the running script
            import sys

            script_dir = Path(sys.argv[0]).parent.resolve()
            fallback_dir = script_dir / ".sysmanage-agent"

            print(f"⚠️  Cannot access {config_dir}, falling back to {fallback_dir}")
            self.config_dir = fallback_dir
            self.config_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.config_dir, 0o700)

        # Certificate file paths
        self.client_cert_path = self.config_dir / "client.crt"
        self.client_key_path = self.config_dir / "client.key"
        self.ca_cert_path = self.config_dir / "ca.crt"
        self.server_fingerprint_path = self.config_dir / "server.fingerprint"

    def store_certificates(self, cert_data: Dict[str, str]) -> None:
        """
        Store certificate data from server response.

        Args:
            cert_data: Dictionary containing certificate, private_key,
                      ca_certificate, and server_fingerprint
        """
        # Store client certificate
        with open(self.client_cert_path, "w") as f:
            f.write(cert_data["certificate"])
        os.chmod(self.client_cert_path, 0o644)

        # Store client private key with restrictive permissions
        with open(self.client_key_path, "w") as f:
            f.write(cert_data["private_key"])
        os.chmod(self.client_key_path, 0o600)

        # Store CA certificate
        with open(self.ca_cert_path, "w") as f:
            f.write(cert_data["ca_certificate"])
        os.chmod(self.ca_cert_path, 0o644)

        # Store server fingerprint
        with open(self.server_fingerprint_path, "w") as f:
            f.write(cert_data["server_fingerprint"])
        os.chmod(self.server_fingerprint_path, 0o644)

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

    def get_server_fingerprint(self) -> Optional[str]:
        """Get stored server certificate fingerprint."""
        if not self.server_fingerprint_path.exists():
            return None

        with open(self.server_fingerprint_path, "r") as f:
            return f.read().strip()

    def validate_server_certificate(self, cert_der: bytes) -> bool:
        """
        Validate server certificate against stored fingerprint.

        Args:
            cert_der: Server certificate in DER format

        Returns:
            True if certificate matches stored fingerprint
        """
        stored_fingerprint = self.get_server_fingerprint()
        if not stored_fingerprint:
            return False

        # Calculate fingerprint of provided certificate
        fingerprint = hashlib.sha256(cert_der).hexdigest().upper()

        return fingerprint == stored_fingerprint

    def is_certificate_valid(self) -> bool:
        """Check if stored client certificate is still valid."""
        if not self.client_cert_path.exists():
            return False

        try:
            with open(self.client_cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())

            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)

            # Check if certificate is within validity period
            return now >= cert.not_valid_before_utc and now <= cert.not_valid_after_utc

        except Exception:
            return False

    def clear_certificates(self) -> None:
        """Clear all stored certificates and fingerprints."""
        for path in [
            self.client_cert_path,
            self.client_key_path,
            self.ca_cert_path,
            self.server_fingerprint_path,
        ]:
            if path.exists():
                path.unlink()

    def has_certificates(self) -> bool:
        """Check if certificates are stored and valid."""
        return (
            self.load_certificates() is not None
            and self.is_certificate_valid()
            and self.get_server_fingerprint() is not None
        )
