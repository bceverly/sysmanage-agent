"""
Unit tests for src.sysmanage_agent.collection.certificate_collection module.
Tests certificate collection functionality across different platforms.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from unittest.mock import patch

from src.sysmanage_agent.collection.certificate_collection import CertificateCollector


class TestCertificateCollector:
    """Test cases for CertificateCollector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.collector = CertificateCollector()

    def test_init(self):
        """Test CertificateCollector initialization."""
        assert self.collector is not None
        assert hasattr(self.collector, "logger")

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
    def test_collect_certificates_unsupported_platform(self, mock_system):
        """Test certificate collection on unsupported platform."""
        mock_system.return_value = "UnsupportedOS"

        result = self.collector.collect_certificates()

        assert not result

    @patch("platform.system")
    def test_collect_certificates_exception(self, mock_system):
        """Test certificate collection with exception."""
        mock_system.return_value = "Linux"

        with patch.object(
            self.collector, "_get_unix_cert_paths", side_effect=Exception("Test error")
        ):
            result = self.collector.collect_certificates()

            assert not result
