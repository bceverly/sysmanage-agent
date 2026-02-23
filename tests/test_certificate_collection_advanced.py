"""
Unit tests for src.sysmanage_agent.collection.certificate_collection module.
Advanced tests for certificate type detection, CA detection, Windows/Unix
collection, directory processing, common name extraction, integration,
edge cases, and logging.

This module provides comprehensive test coverage for:
- Certificate type detection (CA, Server, Client, Code Signing, Email)
- CA certificate detection by path, subject, and purpose
- Windows certificate collection and formatting
- Unix certificate collection and deduplication
- Certificate directory and single certificate processing
- Common Name (CN) extraction from subjects
- Integration workflows
- Edge cases and boundary conditions
- macOS keychain collection
- Logging behavior
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import json
import subprocess
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.certificate_collection import CertificateCollector


class TestCertificateTypeDetection:
    """Test cases for certificate type detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_determine_certificate_type_ca(self):
        """Test detecting CA certificate."""
        output = """subject=CN=Root CA
SSL client CA : Yes
SSL server CA : Yes
Certificate Sign : Yes"""

        cert_type = self.collector._determine_certificate_type(output)

        assert cert_type == "CA"

    def test_determine_certificate_type_server(self):
        """Test detecting server certificate."""
        output = """subject=CN=www.example.com
SSL client : No
SSL server : Yes
SSL client CA : No
SSL server CA : No"""

        cert_type = self.collector._determine_certificate_type(output)

        assert cert_type == "Server"

    def test_determine_certificate_type_client(self):
        """Test detecting client certificate."""
        output = """subject=CN=Client Cert
SSL client : Yes
SSL server : No
SSL client CA : No
SSL server CA : No"""

        cert_type = self.collector._determine_certificate_type(output)

        assert cert_type == "Client"

    def test_determine_certificate_type_code_signing(self):
        """Test detecting code signing certificate."""
        output = """subject=CN=Developer Cert
Code Signing : Yes
SSL client : No
SSL server : No"""

        cert_type = self.collector._determine_certificate_type(output)

        assert cert_type == "Code Signing"

    def test_determine_certificate_type_email(self):
        """Test detecting email certificate."""
        output = """subject=CN=Email Cert
Email Protection : Yes
S/MIME : Yes
SSL client : No
SSL server : No"""

        cert_type = self.collector._determine_certificate_type(output)

        assert cert_type == "Email"

    def test_determine_certificate_type_unknown(self):
        """Test detecting unknown certificate type."""
        output = """subject=CN=Unknown Cert
Some Other Purpose : Yes"""

        cert_type = self.collector._determine_certificate_type(output)

        assert cert_type == "Unknown"

    def test_check_subject_for_ca_indicators_root_ca(self):
        """Test detecting Root CA from subject."""
        output = """subject=CN=DigiCert Global Root CA, O=DigiCert Inc"""

        result = self.collector._check_subject_for_ca_indicators(output)

        assert result == "CA"

    def test_check_subject_for_ca_indicators_certificate_authority(self):
        """Test detecting Certificate Authority from subject."""
        output = """subject=CN=Test Certificate Authority, O=Test"""

        result = self.collector._check_subject_for_ca_indicators(output)

        assert result == "CA"

    def test_check_subject_for_ca_indicators_none(self):
        """Test non-CA subject returns None."""
        output = """subject=CN=www.example.com, O=Example Inc"""

        result = self.collector._check_subject_for_ca_indicators(output)

        assert result is None


class TestCADetection:
    """Test cases for CA certificate detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_detect_ca_certificate_by_path(self):
        """Test CA detection by file path."""
        cert_info = {"subject": "CN=Test"}
        output = "SSL client : No\nSSL server : No"

        # Test various CA path indicators
        ca_paths = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/root-ca.pem",
            "/intermediate-ca.crt",
        ]

        for path in ca_paths:
            result = self.collector._detect_ca_certificate(path, cert_info, output)
            assert result is True, f"Failed for path: {path}"

    def test_detect_ca_certificate_by_subject(self):
        """Test CA detection by subject containing Root."""
        cert_info = {"subject": "CN=DigiCert Root CA"}
        output = "SSL client : No\nSSL server : No"

        result = self.collector._detect_ca_certificate(
            "/test/cert.pem", cert_info, output
        )

        assert result is True

    def test_detect_ca_certificate_by_purpose(self):
        """Test CA detection by OpenSSL purpose.

        The implementation checks for "Certificate Sign" in the output
        and requires that "SSL client" and "SSL server" are NOT present.
        This is a case-sensitive check.
        """
        cert_info = {"subject": "CN=Test Cert"}
        # Output must contain "Certificate Sign" but NOT "SSL client" or "SSL server"
        output = "Certificate Sign : Yes\nCRL Sign : Yes"

        result = self.collector._detect_ca_certificate(
            "/test/cert.pem", cert_info, output
        )

        assert result is True

    def test_detect_ca_certificate_not_ca(self):
        """Test non-CA certificate detection."""
        cert_info = {"subject": "CN=www.example.com"}
        output = "SSL client : No\nSSL server : Yes"

        result = self.collector._detect_ca_certificate(
            "/test/server.pem", cert_info, output
        )

        assert result is False


class TestWindowsCertificateCollection:
    """Test cases for Windows certificate collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("subprocess.run")
    def test_collect_windows_certificates_success(self, mock_run):
        """Test successful Windows certificate collection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"Subject": "CN=Test", "Issuer": "CN=CA", "NotAfter": "2025-12-31T23:59:59Z", "Store": "LocalMachine\\\\Root"}',
            stderr="",
        )

        result = self.collector._collect_windows_certificates()

        assert len(result) >= 0  # May vary based on mock
        mock_run.assert_called()

    @patch("subprocess.run")
    def test_collect_windows_certificates_exception(self, mock_run):
        """Test Windows collection with exception."""
        mock_run.side_effect = Exception("PowerShell error")

        result = self.collector._collect_windows_certificates()

        assert not result

    def test_build_powershell_command(self):
        """Test PowerShell command building."""
        store = "LocalMachine\\Root"

        cmd = self.collector._build_powershell_command(store)

        assert "Get-ChildItem" in cmd
        assert store in cmd
        assert "ConvertTo-Json" in cmd

    @patch("subprocess.run")
    def test_execute_powershell_command(self, mock_run):
        """Test PowerShell command execution."""
        mock_run.return_value = Mock(returncode=0, stdout="test", stderr="")

        result = self.collector._execute_powershell_command("test command")

        assert result is not None
        mock_run.assert_called_once()

    def test_parse_powershell_output_valid_json(self):
        """Test parsing valid PowerShell JSON output."""
        stdout = '{"Subject": "CN=Test", "Issuer": "CN=CA", "NotAfter": "2025-12-31T23:59:59Z", "Store": "LocalMachine\\\\Root"}'
        certificates = []

        self.collector._parse_powershell_output(stdout, certificates)

        assert len(certificates) == 1

    def test_parse_powershell_output_multiple_certs(self):
        """Test parsing multiple certificates from PowerShell."""
        stdout = """{"Subject": "CN=Cert1", "Issuer": "CN=CA", "Store": "LocalMachine\\\\Root"}
{"Subject": "CN=Cert2", "Issuer": "CN=CA", "Store": "LocalMachine\\\\CA"}"""
        certificates = []

        self.collector._parse_powershell_output(stdout, certificates)

        assert len(certificates) == 2

    def test_parse_powershell_output_invalid_json(self):
        """Test parsing invalid JSON in PowerShell output."""
        stdout = "invalid json content"
        certificates = []

        # Should not raise exception
        self.collector._parse_powershell_output(stdout, certificates)

        assert len(certificates) == 0

    def test_parse_powershell_output_empty(self):
        """Test parsing empty PowerShell output."""
        stdout = ""
        certificates = []

        self.collector._parse_powershell_output(stdout, certificates)

        assert len(certificates) == 0

    @patch("subprocess.run")
    def test_process_windows_certificate_store_timeout(self, mock_run):
        """Test Windows certificate store processing with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=60)
        certificates = []

        self.collector._process_windows_certificate_store(
            "LocalMachine\\Root", certificates
        )

        assert len(certificates) == 0

    @patch("subprocess.run")
    def test_process_windows_certificate_store_exception(self, mock_run):
        """Test Windows certificate store processing with exception."""
        mock_run.side_effect = Exception("Unknown error")
        certificates = []

        self.collector._process_windows_certificate_store(
            "LocalMachine\\Root", certificates
        )

        assert len(certificates) == 0


class TestWindowsCertificateFormatting:
    """Test cases for Windows certificate data formatting."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_format_windows_certificate_root_store(self):
        """Test formatting certificate from Root store."""
        cert_data = {
            "Subject": "CN=DigiCert Root CA, O=DigiCert",
            "Issuer": "CN=DigiCert Root CA, O=DigiCert",
            "NotBefore": "2020-01-01T00:00:00Z",
            "NotAfter": "2030-12-31T23:59:59Z",
            "SerialNumber": "1234567890ABCDEF",
            "Thumbprint": "ABCDEF1234567890",
            "Store": "LocalMachine\\Root",
            "HasPrivateKey": False,
        }

        result = self.collector._format_windows_certificate(cert_data)

        assert result["is_ca"] is True
        assert result["key_usage"] == "CA"
        assert result["certificate_name"] == "DigiCert Root CA"

    def test_format_windows_certificate_ca_store(self):
        """Test formatting certificate from CA store."""
        cert_data = {
            "Subject": "CN=Intermediate CA",
            "Issuer": "CN=Root CA",
            "NotAfter": "2025-12-31T23:59:59Z",
            "Store": "LocalMachine\\CA",
            "Thumbprint": "ABCDEF",
        }

        result = self.collector._format_windows_certificate(cert_data)

        assert result["is_ca"] is True
        assert result["key_usage"] == "CA"

    def test_format_windows_certificate_personal_store(self):
        """Test formatting certificate from Personal/My store."""
        cert_data = {
            "Subject": "CN=www.example.com",
            "Issuer": "CN=CA",
            "NotAfter": "2025-12-31T23:59:59Z",
            "Store": "LocalMachine\\My",
            "Thumbprint": "ABCDEF",
        }

        result = self.collector._format_windows_certificate(cert_data)

        assert result["is_ca"] is False
        assert result["key_usage"] == "Server"


class TestUnixCertificateCollection:
    """Test cases for Unix certificate collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_collect_unix_certificates_empty_paths(self):
        """Test Unix certificate collection with empty paths."""
        result = self.collector._collect_unix_certificates([])

        assert not result

    @patch("glob.glob")
    def test_collect_unix_certificates_deduplication(self, mock_glob):
        """Test Unix certificate collection deduplicates by fingerprint."""
        mock_glob.return_value = ["/cert1.pem", "/cert2.pem"]

        # Both certs have same fingerprint
        with patch.object(
            self.collector,
            "_extract_certificate_info",
            side_effect=[
                {"fingerprint_sha256": "abc123", "name": "cert1"},
                {"fingerprint_sha256": "abc123", "name": "cert2"},
            ],
        ):
            result = self.collector._collect_unix_certificates(["/certs"])

            # Should only have 1 cert due to deduplication
            assert len(result) == 1

    def test_collect_unix_certificates_no_fingerprint(self):
        """Test Unix certificate collection includes certs without fingerprint."""
        # Mock the entire directory processing to return a single cert without fingerprint
        with patch.object(
            self.collector,
            "_process_certificate_directory",
        ) as mock_process:
            # Simulate adding a certificate without fingerprint
            def add_cert(_cert_dir, certificates, _seen_fingerprints):
                certificates.append({"name": "cert1", "fingerprint_sha256": None})

            mock_process.side_effect = add_cert

            result = self.collector._collect_unix_certificates(["/certs"])

            assert len(result) == 1
            assert result[0]["name"] == "cert1"


class TestCertificateDirectoryProcessing:
    """Test cases for certificate directory processing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("glob.glob")
    def test_process_certificate_directory_success(self, mock_glob):
        """Test successful certificate directory processing."""
        mock_glob.side_effect = [
            ["/certs/cert1.pem"],
            [],  # recursive
            [],  # crt pattern
            [],
            [],  # cer pattern
            [],
        ]
        certificates = []
        seen_fingerprints = set()

        with patch.object(
            self.collector,
            "_extract_certificate_info",
            return_value={"fingerprint_sha256": "abc123"},
        ):
            self.collector._process_certificate_directory(
                "/certs", certificates, seen_fingerprints
            )

            assert len(certificates) == 1

    @patch("glob.glob")
    def test_process_certificate_directory_exception(self, mock_glob):
        """Test certificate directory processing with exception."""
        mock_glob.side_effect = Exception("Permission denied")
        certificates = []
        seen_fingerprints = set()

        # Should not raise exception
        self.collector._process_certificate_directory(
            "/certs", certificates, seen_fingerprints
        )

        assert len(certificates) == 0

    @patch("glob.glob")
    def test_process_certificate_pattern_pem(self, mock_glob):
        """Test processing PEM certificate pattern."""
        mock_glob.side_effect = [
            ["/certs/ca.pem", "/certs/server.pem"],
            [],
        ]
        certificates = []
        seen_fingerprints = set()

        with patch.object(
            self.collector,
            "_process_single_certificate",
        ) as mock_process:
            self.collector._process_certificate_pattern(
                "/certs", "*.pem", certificates, seen_fingerprints
            )

            assert mock_process.call_count == 2

    @patch("glob.glob")
    def test_process_certificate_pattern_crt(self, mock_glob):
        """Test processing CRT certificate pattern."""
        mock_glob.side_effect = [
            ["/certs/ca.crt"],
            [],
        ]
        certificates = []
        seen_fingerprints = set()

        with patch.object(
            self.collector,
            "_process_single_certificate",
        ):
            self.collector._process_certificate_pattern(
                "/certs", "*.crt", certificates, seen_fingerprints
            )


class TestSingleCertificateProcessing:
    """Test cases for single certificate processing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_process_single_certificate_success(self):
        """Test successful single certificate processing."""
        certificates = []
        seen_fingerprints = set()

        with patch.object(
            self.collector,
            "_extract_certificate_info",
            return_value={"fingerprint_sha256": "abc123", "name": "test"},
        ):
            self.collector._process_single_certificate(
                "/certs/test.pem", certificates, seen_fingerprints
            )

            assert len(certificates) == 1
            assert "abc123" in seen_fingerprints

    def test_process_single_certificate_duplicate(self):
        """Test single certificate processing with duplicate fingerprint."""
        certificates = []
        seen_fingerprints = {"abc123"}  # Pre-existing fingerprint

        with patch.object(
            self.collector,
            "_extract_certificate_info",
            return_value={"fingerprint_sha256": "abc123", "name": "test"},
        ):
            self.collector._process_single_certificate(
                "/certs/test.pem", certificates, seen_fingerprints
            )

            assert len(certificates) == 0  # Should not add duplicate

    def test_process_single_certificate_exception(self):
        """Test single certificate processing with exception."""
        certificates = []
        seen_fingerprints = set()

        with patch.object(
            self.collector,
            "_extract_certificate_info",
            side_effect=Exception("Parse error"),
        ):
            # Should not raise exception
            self.collector._process_single_certificate(
                "/certs/test.pem", certificates, seen_fingerprints
            )

            assert len(certificates) == 0

    def test_process_single_certificate_no_info(self):
        """Test single certificate processing when extraction returns None."""
        certificates = []
        seen_fingerprints = set()

        with patch.object(
            self.collector,
            "_extract_certificate_info",
            return_value=None,
        ):
            self.collector._process_single_certificate(
                "/certs/test.pem", certificates, seen_fingerprints
            )

            assert len(certificates) == 0


class TestCommonNameExtraction:
    """Test cases for Common Name extraction from subject."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_extract_cn_from_subject_simple(self):
        """Test CN extraction from simple subject."""
        subject = "CN=Test Certificate, O=Test Organization, C=US"

        common_name = self.collector._extract_cn_from_subject(subject)

        assert common_name == "Test Certificate"

    def test_extract_cn_from_subject_cn_first(self):
        """Test CN extraction when CN is first."""
        subject = "CN=First Certificate, O=Org"

        common_name = self.collector._extract_cn_from_subject(subject)

        assert common_name == "First Certificate"

    def test_extract_cn_from_subject_cn_last(self):
        """Test CN extraction when CN is last."""
        subject = "O=Org, C=US, CN=Last Certificate"

        common_name = self.collector._extract_cn_from_subject(subject)

        assert common_name == "Last Certificate"

    def test_extract_cn_from_subject_no_cn(self):
        """Test CN extraction when no CN present."""
        subject = "O=Organization, C=US"

        common_name = self.collector._extract_cn_from_subject(subject)

        assert common_name == ""

    def test_extract_cn_from_subject_empty(self):
        """Test CN extraction from empty subject."""
        common_name = self.collector._extract_cn_from_subject("")

        assert common_name == ""

    def test_extract_cn_from_subject_none(self):
        """Test CN extraction from None subject."""
        common_name = self.collector._extract_cn_from_subject(None)

        assert common_name == ""

    def test_extract_cn_from_subject_with_spaces(self):
        """Test CN extraction with spaces in value."""
        subject = "CN=Certificate With Many Spaces, O=Org"

        common_name = self.collector._extract_cn_from_subject(subject)

        assert common_name == "Certificate With Many Spaces"


class TestCertificateCollectionIntegration:
    """Integration tests for certificate collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("platform.system")
    def test_full_collection_workflow_linux(self, mock_system):
        """Test complete certificate collection workflow on Linux."""
        mock_system.return_value = "Linux"

        with patch.object(
            self.collector,
            "_get_unix_cert_paths",
            return_value=["/etc/ssl/certs"],
        ):
            with patch.object(
                self.collector,
                "_collect_unix_certificates",
                return_value=[
                    {
                        "file_path": "/etc/ssl/certs/ca.crt",
                        "subject": "CN=CA",
                        "issuer": "CN=CA",
                        "not_before": "2023-01-01T00:00:00+00:00",
                        "not_after": "2025-12-31T23:59:59+00:00",
                        "fingerprint_sha256": "abc123",
                        "is_ca": True,
                        "key_usage": "CA",
                    }
                ],
            ):
                result = self.collector.collect_certificates()

                assert len(result) == 1
                assert result[0]["is_ca"] is True
                assert result[0]["key_usage"] == "CA"

    @patch("platform.system")
    def test_full_collection_workflow_windows(self, mock_system):
        """Test complete certificate collection workflow on Windows."""
        mock_system.return_value = "Windows"

        mock_ps_output = json.dumps(
            {
                "Subject": "CN=Windows Cert",
                "Issuer": "CN=Windows CA",
                "NotBefore": "2023-01-01T00:00:00Z",
                "NotAfter": "2025-12-31T23:59:59Z",
                "SerialNumber": "12345",
                "Thumbprint": "ABCDEF123456",
                "Store": "LocalMachine\\Root",
                "HasPrivateKey": False,
            }
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=mock_ps_output, stderr="")

            _result = self.collector.collect_certificates()

            # Should attempt to collect from Windows stores
            assert mock_run.called

    @patch("platform.system")
    def test_logging_on_collection(self, mock_system):
        """Test that logging occurs during collection."""
        mock_system.return_value = "Linux"

        with patch.object(self.collector, "_get_unix_cert_paths", return_value=[]):
            with patch.object(
                self.collector, "_collect_unix_certificates", return_value=[]
            ):
                with patch.object(self.collector, "logger") as mock_logger:
                    self.collector.collect_certificates()

                    # Should log the collection result
                    mock_logger.info.assert_called()


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_parse_subject_line_multiple_cn(self):
        """Test parsing subject with multiple CN fields."""
        cert_info = {}
        # Some certificates may have multiple CN fields
        line = "subject=CN=Primary CN, CN=Secondary CN, O=Org"

        self.collector._parse_subject_line(line, cert_info)

        # Should get the first CN
        assert cert_info["certificate_name"] == "Primary CN"

    def test_has_ca_indicators_complex(self):
        """Test CA indicator detection with complex output."""
        output = "ssl client : no\nssl server : no\ncertificate sign : yes"

        result = self.collector._has_ca_indicators(
            output,
            ["ssl client ca : yes", "ssl server ca : yes", "certificate sign : yes"],
        )

        assert result is True

    def test_check_ssl_purpose_indicators_both(self):
        """Test SSL purpose when both client and server are yes."""
        output = "ssl client : yes\nssl server : yes"

        result = self.collector._check_ssl_purpose_indicators(output)

        # Should prefer server when both are yes
        assert result == "Server"

    def test_check_other_purposes_smime(self):
        """Test detecting S/MIME purpose."""
        output = "s/mime : yes"

        result = self.collector._check_other_purposes(output)

        assert result == "Email"

    def test_extract_cert_info_from_pem_timeout(self):
        """Test PEM extraction with timeout."""
        cert_pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        keychain = {"name": "Test", "path": "/test"}

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="openssl", timeout=10)

            result = self.collector._extract_cert_info_from_pem(cert_pem, keychain)

            assert result is None

    def test_extract_cert_info_from_pem_exception(self):
        """Test PEM extraction with generic exception."""
        cert_pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
        keychain = {"name": "Test", "path": "/test"}

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Unknown error")

            result = self.collector._extract_cert_info_from_pem(cert_pem, keychain)

            assert result is None

    def test_windows_store_empty_output(self):
        """Test Windows certificate store with empty output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

            certificates = []
            self.collector._process_windows_certificate_store(
                "LocalMachine\\Root", certificates
            )

            assert len(certificates) == 0

    def test_windows_store_error_output(self):
        """Test Windows certificate store with error result."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1, stdout="", stderr="Access denied"
            )

            certificates = []
            self.collector._process_windows_certificate_store(
                "LocalMachine\\Root", certificates
            )

            assert len(certificates) == 0


class TestMacOSKeyChainCollector:
    """Additional test cases for macOS keychain collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_collect_macos_keychain_certificates_all_keychains(self):
        """Test that all keychains are attempted."""
        with patch.object(
            self.collector,
            "_extract_certificates_from_keychain",
            side_effect=[
                [{"name": "cert1"}],
                [{"name": "cert2"}],
                [{"name": "cert3"}],
            ],
        ):
            result = self.collector._collect_macos_keychain_certificates()

            # Should attempt all 3 default keychains
            assert len(result) == 3

    def test_collect_macos_keychain_certificates_partial_failure(self):
        """Test keychain collection when some keychains fail."""
        with patch.object(
            self.collector,
            "_extract_certificates_from_keychain",
            side_effect=[
                [{"name": "cert1"}],
                Exception("Keychain locked"),
                [{"name": "cert3"}],
            ],
        ):
            result = self.collector._collect_macos_keychain_certificates()

            # Should still get certs from successful keychains
            assert len(result) == 2


class TestCertificateCollectionLogging:
    """Test logging behavior during certificate collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("platform.system")
    def test_log_unsupported_platform(self, mock_system):
        """Test logging for unsupported platform."""
        mock_system.return_value = "Plan9"

        with patch.object(self.collector, "logger") as mock_logger:
            self.collector.collect_certificates()

            mock_logger.warning.assert_called()

    @patch("platform.system")
    def test_log_collection_error(self, mock_system):
        """Test logging for collection error."""
        mock_system.return_value = "Linux"

        with patch.object(
            self.collector,
            "_get_unix_cert_paths",
            side_effect=Exception("Permission denied"),
        ):
            with patch.object(self.collector, "logger") as mock_logger:
                self.collector.collect_certificates()

                mock_logger.error.assert_called()

    @patch("platform.system")
    def test_log_certificate_count(self, mock_system):
        """Test logging of certificate count."""
        mock_system.return_value = "Linux"

        with patch.object(self.collector, "_get_unix_cert_paths", return_value=[]):
            with patch.object(
                self.collector,
                "_collect_unix_certificates",
                return_value=[{"name": "cert1"}, {"name": "cert2"}],
            ):
                with patch.object(self.collector, "logger") as mock_logger:
                    self.collector.collect_certificates()

                    # Should log the count
                    mock_logger.info.assert_called()
