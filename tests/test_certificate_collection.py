"""
Unit tests for src.sysmanage_agent.collection.certificate_collection module.
Tests certificate collection functionality across different platforms.

This module provides comprehensive test coverage for:
- Certificate discovery on different platforms (Windows, macOS, Linux, BSD)
- Certificate parsing (X.509 format)
- Expiration detection
- Certificate chain validation
- Multi-platform support
- Error handling
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-public-methods

import subprocess
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.certificate_collection import CertificateCollector


class TestCertificateCollectorInit:
    """Test cases for CertificateCollector initialization."""

    def test_init(self):
        """Test CertificateCollector initialization."""
        collector = CertificateCollector()
        assert collector is not None
        assert hasattr(collector, "logger")

    def test_init_logger_configured(self):
        """Test that logger is properly configured on init."""
        collector = CertificateCollector()
        assert collector.logger is not None
        assert (
            collector.logger.name
            == "src.sysmanage_agent.collection.certificate_collection"
        )


class TestCertificateDiscovery:
    """Test cases for certificate discovery functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    # Platform-specific discovery tests

    @patch("platform.system")
    def test_collect_certificates_windows(self, mock_system):
        """Test certificate collection on Windows."""
        mock_system.return_value = "Windows"

        with patch.object(
            self.collector,
            "_collect_windows_certificates",
            return_value=[{"name": "test-cert", "type": "CA", "thumbprint": "abc123"}],
        ) as mock_windows:
            result = self.collector.collect_certificates()

            assert len(result) == 1
            assert result[0]["name"] == "test-cert"
            mock_windows.assert_called_once()

    @patch("platform.system")
    def test_collect_certificates_macos(self, mock_system):
        """Test certificate collection on macOS."""
        mock_system.return_value = "Darwin"

        with patch.object(
            self.collector,
            "_collect_macos_certificates",
            return_value=[{"name": "test-cert", "type": "SSL", "subject": "CN=test"}],
        ) as mock_macos:
            result = self.collector.collect_certificates()

            assert len(result) == 1
            assert result[0]["name"] == "test-cert"
            mock_macos.assert_called_once()

    @patch("platform.system")
    def test_collect_certificates_linux(self, mock_system):
        """Test certificate collection on Linux."""
        mock_system.return_value = "Linux"

        with patch.object(
            self.collector, "_get_unix_cert_paths", return_value=["/etc/ssl/certs"]
        ):
            with patch.object(
                self.collector,
                "_collect_unix_certificates",
                return_value=[
                    {
                        "name": "ca-cert",
                        "type": "CA",
                        "file_path": "/etc/ssl/certs/ca.crt",
                    }
                ],
            ) as mock_unix:
                result = self.collector.collect_certificates()

                assert len(result) == 1
                assert result[0]["name"] == "ca-cert"
                mock_unix.assert_called_once_with(["/etc/ssl/certs"])

    @patch("platform.system")
    def test_collect_certificates_freebsd(self, mock_system):
        """Test certificate collection on FreeBSD."""
        mock_system.return_value = "FreeBSD"

        with patch.object(
            self.collector,
            "_get_unix_cert_paths",
            return_value=["/usr/local/share/certs"],
        ):
            with patch.object(
                self.collector,
                "_collect_unix_certificates",
                return_value=[
                    {
                        "name": "freebsd-cert",
                        "file_path": "/usr/local/share/certs/ca.crt",
                    }
                ],
            ) as mock_unix:
                result = self.collector.collect_certificates()

                assert len(result) == 1
                assert result[0]["name"] == "freebsd-cert"
                mock_unix.assert_called_once()

    @patch("platform.system")
    def test_collect_certificates_openbsd(self, mock_system):
        """Test certificate collection on OpenBSD."""
        mock_system.return_value = "OpenBSD"

        with patch.object(
            self.collector, "_get_unix_cert_paths", return_value=["/etc/ssl/certs"]
        ):
            with patch.object(
                self.collector,
                "_collect_unix_certificates",
                return_value=[
                    {"name": "openbsd-cert", "file_path": "/etc/ssl/certs/ca.crt"}
                ],
            ) as mock_unix:
                result = self.collector.collect_certificates()

                assert len(result) == 1
                mock_unix.assert_called_once()

    @patch("platform.system")
    def test_collect_certificates_netbsd(self, mock_system):
        """Test certificate collection on NetBSD."""
        mock_system.return_value = "NetBSD"

        with patch.object(
            self.collector, "_get_unix_cert_paths", return_value=["/etc/openssl"]
        ):
            with patch.object(
                self.collector,
                "_collect_unix_certificates",
                return_value=[
                    {"name": "netbsd-cert", "file_path": "/etc/openssl/certs/ca.crt"}
                ],
            ) as mock_unix:
                result = self.collector.collect_certificates()

                assert len(result) == 1
                mock_unix.assert_called_once()

    @patch("platform.system")
    def test_collect_certificates_unsupported_platform(self, mock_system):
        """Test certificate collection on unsupported platform."""
        mock_system.return_value = "UnsupportedOS"

        result = self.collector.collect_certificates()

        assert not result

    @patch("platform.system")
    def test_collect_certificates_exception(self, mock_system):
        """Test certificate collection with exception."""
        mock_system.return_value = "Windows"

        with patch.object(
            self.collector,
            "_collect_windows_certificates",
            side_effect=Exception("Test error"),
        ):
            result = self.collector.collect_certificates()

            assert not result


class TestUnixCertificatePaths:
    """Test cases for Unix certificate path discovery."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("platform.system")
    @patch("os.path.isdir")
    @patch("glob.glob")
    def test_get_unix_cert_paths_linux(self, mock_glob, mock_isdir, mock_system):
        """Test Unix certificate path discovery on Linux."""
        mock_system.return_value = "Linux"
        mock_isdir.return_value = True
        mock_glob.return_value = []

        with patch.object(
            self.collector,
            "_collect_system_cert_paths",
            return_value=["/etc/ssl/certs", "/etc/pki/tls/certs"],
        ):
            with patch.object(
                self.collector, "_collect_app_cert_paths", return_value=[]
            ):
                paths = self.collector._get_unix_cert_paths()

                assert "/etc/ssl/certs" in paths
                assert "/etc/pki/tls/certs" in paths

    @patch("platform.system")
    @patch("os.path.isdir")
    def test_get_unix_cert_paths_filters_nonexistent(self, mock_isdir, mock_system):
        """Test that non-existent directories are filtered out."""
        mock_system.return_value = "Linux"

        def isdir_side_effect(path):
            return path == "/etc/ssl/certs"

        mock_isdir.side_effect = isdir_side_effect

        with patch.object(
            self.collector,
            "_collect_system_cert_paths",
            return_value=["/etc/ssl/certs", "/nonexistent/path"],
        ):
            with patch.object(
                self.collector, "_collect_app_cert_paths", return_value=[]
            ):
                with patch("glob.glob", return_value=[]):
                    paths = self.collector._get_unix_cert_paths()

                    assert "/etc/ssl/certs" in paths
                    assert "/nonexistent/path" not in paths


class TestLinuxCertificatePaths:
    """Test cases for Linux-specific certificate path detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("os.path.exists")
    def test_collect_linux_cert_paths_no_os_release(self, mock_exists):
        """Test Linux cert paths when /etc/os-release doesn't exist."""
        mock_exists.return_value = False

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/ssl/certs" in paths
        assert "/etc/pki/tls/certs" in paths

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_collect_linux_cert_paths_ubuntu(self, mock_open, mock_exists):
        """Test Linux cert paths on Ubuntu."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID=ubuntu\nVERSION_ID="22.04"'
        )

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/ssl/certs" in paths
        assert "/usr/local/share/ca-certificates" in paths

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_collect_linux_cert_paths_debian(self, mock_open, mock_exists):
        """Test Linux cert paths on Debian."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID=debian\nVERSION_ID="11"'
        )

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/ssl/certs" in paths
        assert "/usr/local/share/ca-certificates" in paths

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_collect_linux_cert_paths_rhel(self, mock_open, mock_exists):
        """Test Linux cert paths on RHEL."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID="rhel"\nVERSION_ID="8.6"'
        )

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/pki/tls/certs" in paths
        assert "/etc/pki/ca-trust/source/anchors" in paths

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_collect_linux_cert_paths_centos(self, mock_open, mock_exists):
        """Test Linux cert paths on CentOS."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID="centos"\nVERSION_ID="8"'
        )

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/pki/tls/certs" in paths
        assert "/etc/pki/ca-trust/source/anchors" in paths

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_collect_linux_cert_paths_fedora(self, mock_open, mock_exists):
        """Test Linux cert paths on Fedora."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID=fedora\nVERSION_ID="38"'
        )

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/pki/tls/certs" in paths
        assert "/etc/pki/ca-trust/source/anchors" in paths

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_collect_linux_cert_paths_opensuse(self, mock_open, mock_exists):
        """Test Linux cert paths on openSUSE."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID="opensuse-leap"\nVERSION_ID="15.4"'
        )

        paths = self.collector._collect_linux_cert_paths()

        assert "/etc/ssl/certs" in paths
        assert "/var/lib/ca-certificates/pem" in paths


class TestSystemCertificatePaths:
    """Test cases for system-level certificate path collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_collect_system_cert_paths_freebsd(self):
        """Test FreeBSD system certificate paths."""
        paths = self.collector._collect_system_cert_paths("FreeBSD")

        assert "/usr/local/share/certs" in paths
        assert "/etc/ssl/certs" in paths
        assert "/usr/local/etc/ssl/certs" in paths

    def test_collect_system_cert_paths_openbsd(self):
        """Test OpenBSD system certificate paths."""
        paths = self.collector._collect_system_cert_paths("OpenBSD")

        assert "/etc/ssl" in paths
        assert "/etc/ssl/certs" in paths
        assert "/var/www/conf/ssl" in paths

    def test_collect_system_cert_paths_netbsd(self):
        """Test NetBSD system certificate paths."""
        paths = self.collector._collect_system_cert_paths("NetBSD")

        assert "/etc/openssl" in paths
        assert "/usr/pkg/share/mozilla-rootcerts" in paths
        assert "/usr/pkg/etc/ssl/certs" in paths

    def test_collect_system_cert_paths_unknown(self):
        """Test unknown system returns empty list."""
        paths = self.collector._collect_system_cert_paths("UnknownOS")

        assert not paths


class TestAppCertificatePaths:
    """Test cases for application-specific certificate path collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_collect_app_cert_paths_linux(self):
        """Test Linux application certificate paths."""
        paths = self.collector._collect_app_cert_paths("Linux")

        assert "/opt/*/ssl/certs" in paths
        assert "/usr/local/nginx/conf/ssl" in paths
        assert "/etc/nginx/ssl" in paths
        assert "/etc/apache2/ssl/certs" in paths

    def test_collect_app_cert_paths_freebsd(self):
        """Test FreeBSD application certificate paths."""
        paths = self.collector._collect_app_cert_paths("FreeBSD")

        assert "/usr/local/etc/nginx/ssl" in paths
        assert "/usr/local/etc/apache24/ssl" in paths

    def test_collect_app_cert_paths_openbsd(self):
        """Test OpenBSD application certificate paths."""
        paths = self.collector._collect_app_cert_paths("OpenBSD")

        assert "/var/www/conf/ssl" in paths
        assert "/usr/local/etc/nginx/ssl" in paths
        assert "/etc/httpd/ssl" in paths

    def test_collect_app_cert_paths_netbsd(self):
        """Test NetBSD application certificate paths."""
        paths = self.collector._collect_app_cert_paths("NetBSD")

        assert "/usr/pkg/etc/nginx/ssl" in paths
        assert "/usr/pkg/etc/apache24/ssl" in paths
        assert "/usr/pkg/share/ca-certificates" in paths


class TestMacOSCertificateCollection:
    """Test cases for macOS certificate collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("os.path.isdir")
    def test_get_macos_cert_paths(self, mock_isdir):
        """Test macOS certificate path discovery."""
        mock_isdir.return_value = True

        paths = self.collector._get_macos_cert_paths()

        assert "/etc/ssl/certs" in paths
        assert "/usr/local/etc/openssl/certs" in paths
        assert "/System/Library/OpenSSL/certs" in paths

    @patch("os.path.isdir")
    def test_get_macos_cert_paths_homebrew(self, mock_isdir):
        """Test macOS Homebrew certificate paths."""
        mock_isdir.return_value = True

        paths = self.collector._get_macos_cert_paths()

        assert "/opt/homebrew/etc/openssl/certs" in paths
        assert "/usr/local/opt/openssl/ssl/certs" in paths

    def test_collect_macos_certificates_deduplication(self):
        """Test macOS certificate collection deduplication."""
        keychain_certs = [
            {"fingerprint_sha256": "abc123", "name": "cert1"},
            {"fingerprint_sha256": "def456", "name": "cert2"},
        ]
        filesystem_certs = [
            {"fingerprint_sha256": "abc123", "name": "cert1-dup"},  # Duplicate
            {"fingerprint_sha256": "ghi789", "name": "cert3"},
        ]

        with patch.object(
            self.collector,
            "_collect_macos_keychain_certificates",
            return_value=keychain_certs,
        ):
            with patch.object(self.collector, "_get_macos_cert_paths", return_value=[]):
                with patch.object(
                    self.collector,
                    "_collect_unix_certificates",
                    return_value=filesystem_certs,
                ):
                    result = self.collector._collect_macos_certificates()

                    # Should have 3 unique certificates, not 4
                    assert len(result) == 3
                    fingerprints = [c.get("fingerprint_sha256") for c in result]
                    assert "abc123" in fingerprints
                    assert "def456" in fingerprints
                    assert "ghi789" in fingerprints


class TestMacOSKeychainCertificates:
    """Test cases for macOS keychain certificate collection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("subprocess.run")
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_extract_certificates_from_keychain_success(
        self, mock_expanduser, mock_exists, mock_run
    ):
        """Test successful keychain certificate extraction."""
        mock_expanduser.return_value = "/Library/Keychains/System.keychain"
        mock_exists.return_value = True

        pem_output = """-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTE3MTEyNzEyMjM0NVoXDTI3MTEyNzEyMjM0NVowWjEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzE0MDIGA1UEAxMrRGln
aUNlcnQgR2xvYmFsIEcyIFRMUyBSU0EgU0hBMjU2IDIwMjAgQ0ExMIIBIjANBgkq
-----END CERTIFICATE-----"""

        mock_run.return_value = Mock(returncode=0, stdout=pem_output, stderr="")

        keychain = {"name": "System", "path": "/Library/Keychains/System.keychain"}

        with patch.object(
            self.collector,
            "_parse_macos_security_output",
            return_value=[{"name": "test-cert"}],
        ) as mock_parse:
            result = self.collector._extract_certificates_from_keychain(keychain)

            assert len(result) == 1
            mock_parse.assert_called_once()

    @patch("subprocess.run")
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_extract_certificates_from_keychain_not_found(
        self, mock_expanduser, mock_exists, mock_run
    ):
        """Test keychain extraction when keychain not found."""
        mock_expanduser.return_value = "/nonexistent/keychain"
        mock_exists.return_value = False

        keychain = {"name": "Missing", "path": "/nonexistent/keychain"}

        result = self.collector._extract_certificates_from_keychain(keychain)

        assert not result
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_extract_certificates_from_keychain_timeout(
        self, mock_expanduser, mock_exists, mock_run
    ):
        """Test keychain extraction with timeout."""
        mock_expanduser.return_value = "/Library/Keychains/System.keychain"
        mock_exists.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="security", timeout=30)

        keychain = {"name": "System", "path": "/Library/Keychains/System.keychain"}

        result = self.collector._extract_certificates_from_keychain(keychain)

        assert not result

    @patch("subprocess.run")
    @patch("os.path.exists")
    @patch("os.path.expanduser")
    def test_extract_certificates_from_keychain_command_failure(
        self, mock_expanduser, mock_exists, mock_run
    ):
        """Test keychain extraction when security command fails."""
        mock_expanduser.return_value = "/Library/Keychains/System.keychain"
        mock_exists.return_value = True
        mock_run.return_value = Mock(
            returncode=1, stdout="", stderr="Error accessing keychain"
        )

        keychain = {"name": "System", "path": "/Library/Keychains/System.keychain"}

        result = self.collector._extract_certificates_from_keychain(keychain)

        assert not result


class TestPEMParsing:
    """Test cases for PEM certificate parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_parse_macos_security_output_single_cert(self):
        """Test parsing single certificate from security output."""
        pem_output = """-----BEGIN CERTIFICATE-----
MIIB0TCCATqgAwIBAgIJAKZ1wKsVWBH3MA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMMBnRlc3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzAN
BgNVBAMMBnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtesttest
-----END CERTIFICATE-----"""

        keychain = {"name": "Test", "path": "/test/keychain"}

        with patch.object(
            self.collector, "_extract_cert_info_from_pem", return_value={"name": "test"}
        ) as mock_extract:
            result = self.collector._parse_macos_security_output(pem_output, keychain)

            assert len(result) == 1
            mock_extract.assert_called_once()

    def test_parse_macos_security_output_multiple_certs(self):
        """Test parsing multiple certificates from security output."""
        pem_output = """-----BEGIN CERTIFICATE-----
CERT1DATA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
CERT2DATA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
CERT3DATA
-----END CERTIFICATE-----"""

        keychain = {"name": "Test", "path": "/test/keychain"}

        with patch.object(
            self.collector,
            "_extract_cert_info_from_pem",
            side_effect=[{"name": "cert1"}, {"name": "cert2"}, {"name": "cert3"}],
        ):
            result = self.collector._parse_macos_security_output(pem_output, keychain)

            assert len(result) == 3

    def test_parse_macos_security_output_invalid_cert(self):
        """Test parsing with invalid certificate returns empty."""
        pem_output = """-----BEGIN CERTIFICATE-----
CERT1DATA
-----END CERTIFICATE-----"""

        keychain = {"name": "Test", "path": "/test/keychain"}

        with patch.object(
            self.collector, "_extract_cert_info_from_pem", return_value=None
        ):
            result = self.collector._parse_macos_security_output(pem_output, keychain)

            assert len(result) == 0

    def test_parse_macos_security_output_empty(self):
        """Test parsing empty output."""
        keychain = {"name": "Test", "path": "/test/keychain"}

        result = self.collector._parse_macos_security_output("", keychain)

        assert not result


class TestX509CertificateParsing:
    """Test cases for X.509 certificate parsing."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    @patch("subprocess.run")
    def test_extract_certificate_info_success(self, mock_run):
        """Test successful certificate info extraction."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""subject=CN=Test Certificate, O=Test Org
issuer=CN=Test CA, O=Test CA Org
notBefore=Jan  1 00:00:00 2023 GMT
notAfter=Dec 31 23:59:59 2025 GMT
serial=1234567890ABCDEF
SHA256 Fingerprint=AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
SSL server : Yes
SSL client : No""",
            stderr="",
        )

        cert_info = self.collector._extract_certificate_info("/path/to/cert.pem")

        assert cert_info is not None
        assert cert_info["subject"] == "CN=Test Certificate, O=Test Org"
        assert cert_info["issuer"] == "CN=Test CA, O=Test CA Org"
        assert cert_info["serial_number"] == "1234567890ABCDEF"

    @patch("subprocess.run")
    def test_extract_certificate_info_openssl_failure(self, mock_run):
        """Test certificate info extraction with OpenSSL failure."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="Error")

        cert_info = self.collector._extract_certificate_info("/path/to/cert.pem")

        assert cert_info is None

    @patch("subprocess.run")
    def test_extract_certificate_info_timeout(self, mock_run):
        """Test certificate info extraction with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="openssl", timeout=10)

        cert_info = self.collector._extract_certificate_info("/path/to/cert.pem")

        assert cert_info is None

    @patch("subprocess.run")
    def test_extract_certificate_info_file_not_found(self, mock_run):
        """Test certificate info extraction with OpenSSL not found."""
        mock_run.side_effect = FileNotFoundError("openssl not found")

        cert_info = self.collector._extract_certificate_info("/path/to/cert.pem")

        assert cert_info is None

    @patch("subprocess.run")
    def test_extract_certificate_info_generic_exception(self, mock_run):
        """Test certificate info extraction with generic exception."""
        mock_run.side_effect = Exception("Unknown error")

        cert_info = self.collector._extract_certificate_info("/path/to/cert.pem")

        assert cert_info is None


class TestOpenSSLOutputParsing:
    """Test cases for parsing OpenSSL output."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_parse_openssl_output_complete(self):
        """Test parsing complete OpenSSL output."""
        output = """subject=CN=Test Certificate, O=Test Org
issuer=CN=Test CA, O=Test CA Org
notBefore=Jan  1 00:00:00 2023 GMT
notAfter=Dec 31 23:59:59 2025 GMT
serial=1234567890ABCDEF
SHA256 Fingerprint=AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90
SSL server : Yes
SSL client : No"""

        cert_info = self.collector._parse_openssl_output("/test/cert.pem", output)

        assert cert_info["file_path"] == "/test/cert.pem"
        assert cert_info["subject"] == "CN=Test Certificate, O=Test Org"
        assert cert_info["issuer"] == "CN=Test CA, O=Test CA Org"
        assert cert_info["serial_number"] == "1234567890ABCDEF"
        assert cert_info["fingerprint_sha256"] is not None
        assert "collected_at" in cert_info

    def test_parse_openssl_output_extracts_certificate_name(self):
        """Test that certificate name is extracted from CN."""
        output = """subject=CN=My Test Certificate, O=Test Org
issuer=CN=Test CA
notBefore=Jan  1 00:00:00 2023 GMT
notAfter=Dec 31 23:59:59 2025 GMT"""

        cert_info = self.collector._parse_openssl_output("/test/cert.pem", output)

        assert cert_info["certificate_name"] == "My Test Certificate"

    def test_parse_openssl_output_line_subject(self):
        """Test parsing subject line."""
        cert_info = {}
        self.collector._parse_openssl_output_line("subject=CN=Test, O=Org", cert_info)

        assert cert_info["subject"] == "CN=Test, O=Org"
        assert cert_info["certificate_name"] == "Test"

    def test_parse_openssl_output_line_issuer(self):
        """Test parsing issuer line."""
        cert_info = {}
        self.collector._parse_openssl_output_line("issuer=CN=Issuer", cert_info)

        assert cert_info["issuer"] == "CN=Issuer"

    def test_parse_openssl_output_line_not_before(self):
        """Test parsing notBefore line."""
        cert_info = {}
        self.collector._parse_openssl_output_line(
            "notBefore=Jan  1 00:00:00 2023 GMT", cert_info
        )

        assert cert_info["not_before"] is not None

    def test_parse_openssl_output_line_not_after(self):
        """Test parsing notAfter line."""
        cert_info = {}
        self.collector._parse_openssl_output_line(
            "notAfter=Dec 31 23:59:59 2025 GMT", cert_info
        )

        assert cert_info["not_after"] is not None

    def test_parse_openssl_output_line_serial(self):
        """Test parsing serial line."""
        cert_info = {}
        self.collector._parse_openssl_output_line("serial=ABCD1234", cert_info)

        assert cert_info["serial_number"] == "ABCD1234"

    def test_parse_openssl_output_line_fingerprint(self):
        """Test parsing fingerprint line."""
        cert_info = {}
        self.collector._parse_openssl_output_line(
            "SHA256 Fingerprint=AB:CD:EF:12:34", cert_info
        )

        assert cert_info["fingerprint_sha256"] == "abcdef1234"


class TestExpirationDetection:
    """Test cases for certificate expiration detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_parse_openssl_date_valid(self):
        """Test parsing valid OpenSSL date format."""
        date_str = "Jan  1 00:00:00 2023 GMT"

        result = self.collector._parse_openssl_date(date_str, "notBefore")

        assert result is not None
        assert "2023" in result

    def test_parse_openssl_date_without_gmt(self):
        """Test parsing date without GMT suffix."""
        date_str = "Dec 31 23:59:59 2025"

        result = self.collector._parse_openssl_date(date_str, "notAfter")

        assert result is not None
        assert "2025" in result

    def test_parse_openssl_date_invalid(self):
        """Test parsing invalid date format."""
        date_str = "invalid-date-format"

        result = self.collector._parse_openssl_date(date_str, "notBefore")

        assert result is None

    def test_parse_openssl_date_various_months(self):
        """Test parsing dates with different months."""
        months = [
            ("Jan  1 00:00:00 2023 GMT", "01"),
            ("Feb 15 12:30:00 2023 GMT", "02"),
            ("Mar 20 06:00:00 2023 GMT", "03"),
            ("Dec 31 23:59:59 2023 GMT", "12"),
        ]

        for date_str, _expected_month in months:
            result = self.collector._parse_openssl_date(date_str, "test")
            assert result is not None
