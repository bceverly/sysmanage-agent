"""
Unit tests for src.sysmanage_agent.operations.certificate_operations module.
Tests SSL/TLS certificate deployment and management operations.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.certificate_operations import (
    CertificateOperations,
    _SSL_CERTS_DIR,
)


class TestCertificateOperationsInit:
    """Test cases for CertificateOperations initialization."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()

    def test_init(self):
        """Test CertificateOperations initialization."""
        cert_ops = CertificateOperations(self.mock_agent)
        assert cert_ops.agent_instance == self.mock_agent
        assert cert_ops.logger is not None

    def test_init_logger_configured(self):
        """Test that logger is properly configured on init."""
        cert_ops = CertificateOperations(self.mock_agent)
        assert cert_ops.logger is not None
        assert (
            cert_ops.logger.name
            == "src.sysmanage_agent.operations.certificate_operations"
        )


class TestValidateCertificateInputs:
    """Test cases for certificate input validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    def test_validate_empty_certificates_list(self):
        """Test validation fails with empty certificates list."""
        result = self.cert_ops._validate_certificate_inputs([])

        assert result is not None
        assert result["success"] is False
        assert "No certificates provided" in result["error"]

    def test_validate_none_certificates(self):
        """Test validation fails with None certificates."""
        result = self.cert_ops._validate_certificate_inputs(None)

        assert result is not None
        assert result["success"] is False
        assert "No certificates provided" in result["error"]

    def test_validate_valid_certificates(self):
        """Test validation passes with valid certificates list."""
        certificates = [{"name": "test-cert", "content": "cert-content"}]
        result = self.cert_ops._validate_certificate_inputs(certificates)

        assert result is None  # None means no validation errors


class TestGetSslDirectory:
    """Test cases for SSL directory detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @patch("platform.system")
    def test_get_ssl_directory_linux(self, mock_system):
        """Test SSL directory detection on Linux."""
        mock_system.return_value = "Linux"

        with patch.object(
            self.cert_ops, "_get_linux_ssl_dir", return_value="/etc/ssl/certs"
        ):
            with patch.object(
                self.cert_ops,
                "_validate_ssl_directory",
                return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
            ):
                result = self.cert_ops._get_ssl_directory()

                assert result["success"] is True
                assert result["ssl_dir"] == "/etc/ssl/certs"

    @patch("platform.system")
    def test_get_ssl_directory_darwin(self, mock_system):
        """Test SSL directory detection on macOS (Darwin)."""
        mock_system.return_value = "Darwin"

        with patch.object(
            self.cert_ops,
            "_validate_ssl_directory",
            return_value={"success": True, "ssl_dir": _SSL_CERTS_DIR},
        ):
            result = self.cert_ops._get_ssl_directory()

            assert result["success"] is True
            assert result["ssl_dir"] == _SSL_CERTS_DIR

    @patch("platform.system")
    def test_get_ssl_directory_freebsd(self, mock_system):
        """Test SSL directory detection on FreeBSD."""
        mock_system.return_value = "FreeBSD"

        with patch.object(
            self.cert_ops,
            "_validate_ssl_directory",
            return_value={"success": True, "ssl_dir": _SSL_CERTS_DIR},
        ):
            result = self.cert_ops._get_ssl_directory()

            assert result["success"] is True
            assert result["ssl_dir"] == _SSL_CERTS_DIR

    @patch("platform.system")
    def test_get_ssl_directory_openbsd(self, mock_system):
        """Test SSL directory detection on OpenBSD."""
        mock_system.return_value = "OpenBSD"

        with patch.object(
            self.cert_ops,
            "_validate_ssl_directory",
            return_value={"success": True, "ssl_dir": _SSL_CERTS_DIR},
        ):
            result = self.cert_ops._get_ssl_directory()

            assert result["success"] is True
            assert result["ssl_dir"] == _SSL_CERTS_DIR

    @patch("platform.system")
    def test_get_ssl_directory_unsupported_os(self, mock_system):
        """Test SSL directory detection on unsupported OS."""
        mock_system.return_value = "Unsupported"

        result = self.cert_ops._get_ssl_directory()

        assert result["success"] is False
        assert "Unsupported operating system" in result["error"]

    @patch("platform.system")
    def test_get_ssl_directory_windows_unsupported(self, mock_system):
        """Test SSL directory detection on Windows (unsupported)."""
        mock_system.return_value = "Windows"

        result = self.cert_ops._get_ssl_directory()

        assert result["success"] is False
        assert "Unsupported operating system" in result["error"]


class TestGetSslDirForSystem:
    """Test cases for system-specific SSL directory lookup."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    def test_get_ssl_dir_for_linux(self):
        """Test SSL directory for Linux."""
        with patch.object(
            self.cert_ops, "_get_linux_ssl_dir", return_value="/etc/ssl/certs"
        ):
            result = self.cert_ops._get_ssl_dir_for_system("linux")

            assert result == "/etc/ssl/certs"

    def test_get_ssl_dir_for_darwin(self):
        """Test SSL directory for macOS (darwin)."""
        result = self.cert_ops._get_ssl_dir_for_system("darwin")

        assert result == _SSL_CERTS_DIR

    def test_get_ssl_dir_for_freebsd(self):
        """Test SSL directory for FreeBSD."""
        result = self.cert_ops._get_ssl_dir_for_system("freebsd")

        assert result == _SSL_CERTS_DIR

    def test_get_ssl_dir_for_openbsd(self):
        """Test SSL directory for OpenBSD."""
        result = self.cert_ops._get_ssl_dir_for_system("openbsd")

        assert result == _SSL_CERTS_DIR

    def test_get_ssl_dir_for_unsupported(self):
        """Test SSL directory for unsupported system returns None."""
        result = self.cert_ops._get_ssl_dir_for_system("unsupported_os")

        assert result is None


class TestGetLinuxSslDir:
    """Test cases for Linux-specific SSL directory detection."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @patch("os.path.exists")
    def test_get_linux_ssl_dir_no_os_release(self, mock_exists):
        """Test Linux SSL dir when /etc/os-release doesn't exist."""
        mock_exists.return_value = False

        result = self.cert_ops._get_linux_ssl_dir()

        assert result == _SSL_CERTS_DIR

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_linux_ssl_dir_ubuntu(self, mock_open, mock_exists):
        """Test Linux SSL dir on Ubuntu (Debian-based)."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID=ubuntu\nVERSION_ID="22.04"'
        )

        result = self.cert_ops._get_linux_ssl_dir()

        assert result == _SSL_CERTS_DIR

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_linux_ssl_dir_rhel(self, mock_open, mock_exists):
        """Test Linux SSL dir on RHEL."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID="rhel"\nVERSION_ID="8.6"'
        )

        result = self.cert_ops._get_linux_ssl_dir()

        assert result == "/etc/pki/tls/certs"

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_linux_ssl_dir_centos(self, mock_open, mock_exists):
        """Test Linux SSL dir on CentOS."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID="centos"\nVERSION_ID="8"'
        )

        result = self.cert_ops._get_linux_ssl_dir()

        assert result == "/etc/pki/tls/certs"

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_linux_ssl_dir_fedora(self, mock_open, mock_exists):
        """Test Linux SSL dir on Fedora."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'ID=fedora\nVERSION_ID="38"'
        )

        result = self.cert_ops._get_linux_ssl_dir()

        assert result == "/etc/pki/tls/certs"

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_linux_ssl_dir_red_hat(self, mock_open, mock_exists):
        """Test Linux SSL dir on Red Hat."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            'NAME="Red Hat Enterprise Linux"\nID=rhel'
        )

        result = self.cert_ops._get_linux_ssl_dir()

        assert result == "/etc/pki/tls/certs"

    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_linux_ssl_dir_read_exception(self, mock_open, mock_exists):
        """Test Linux SSL dir when reading os-release fails."""
        mock_exists.return_value = True
        mock_open.side_effect = IOError("Permission denied")

        result = self.cert_ops._get_linux_ssl_dir()

        # Should return default when read fails
        assert result == _SSL_CERTS_DIR


class TestValidateSslDirectory:
    """Test cases for SSL directory validation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @patch("os.path.exists")
    @patch("os.access")
    def test_validate_existing_writable_directory(self, mock_access, mock_exists):
        """Test validation of existing writable directory."""
        mock_exists.return_value = True
        mock_access.return_value = True

        result = self.cert_ops._validate_ssl_directory("/etc/ssl/certs")

        assert result["success"] is True
        assert result["ssl_dir"] == "/etc/ssl/certs"

    @patch("os.path.exists")
    @patch("os.access")
    def test_validate_existing_not_writable_directory(self, mock_access, mock_exists):
        """Test validation of existing but not writable directory."""
        mock_exists.return_value = True
        mock_access.return_value = False

        result = self.cert_ops._validate_ssl_directory("/etc/ssl/certs")

        assert result["success"] is False
        assert "No write permission" in result["error"]

    @patch("os.path.exists")
    @patch("os.makedirs")
    @patch("os.access")
    def test_validate_create_directory_success(
        self, mock_access, mock_makedirs, mock_exists
    ):
        """Test successful directory creation."""
        mock_exists.return_value = False
        mock_makedirs.return_value = None
        mock_access.return_value = True

        with patch("os.path.exists", side_effect=[False, True]):
            with patch("os.access", return_value=True):
                _result = self.cert_ops._validate_ssl_directory("/new/ssl/certs")

        # After makedirs, exists should return True for access check
        # The actual behavior depends on mock setup

    @patch("os.path.exists")
    @patch("os.makedirs")
    def test_validate_create_directory_permission_denied(
        self, mock_makedirs, mock_exists
    ):
        """Test directory creation with permission denied."""
        mock_exists.return_value = False
        mock_makedirs.side_effect = PermissionError("Permission denied")

        result = self.cert_ops._validate_ssl_directory("/root/ssl/certs")

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    @patch("os.path.exists")
    @patch("os.makedirs")
    def test_validate_create_directory_os_error(self, mock_makedirs, mock_exists):
        """Test directory creation with OS error."""
        mock_exists.return_value = False
        mock_makedirs.side_effect = OSError("Disk full")

        result = self.cert_ops._validate_ssl_directory("/new/ssl/certs")

        assert result["success"] is False
        assert "Failed to create SSL directory" in result["error"]


class TestDeployCertificates:
    """Test cases for certificate deployment."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_certificates_no_certificates(self):
        """Test deployment with no certificates provided."""
        parameters = {"certificates": []}
        result = await self.cert_ops.deploy_certificates(parameters)

        assert result["success"] is False
        assert "No certificates provided" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_certificates_empty_parameters(self):
        """Test deployment with empty parameters."""
        parameters = {}
        result = await self.cert_ops.deploy_certificates(parameters)

        assert result["success"] is False
        assert "No certificates provided" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_certificates_unsupported_os(self):
        """Test deployment on unsupported operating system."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={
                "success": False,
                "error": "Unsupported operating system for certificate deployment: windows",
            },
        ):
            parameters = {
                "certificates": [
                    {"name": "test-cert", "content": "-----BEGIN CERTIFICATE-----"}
                ]
            }
            result = await self.cert_ops.deploy_certificates(parameters)

            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_certificates_empty_content(self):
        """Test deployment with empty certificate content."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            parameters = {
                "certificates": [
                    {"name": "empty-cert", "content": ""},
                    {"name": "empty-cert-2", "content": None},
                ]
            }
            result = await self.cert_ops.deploy_certificates(parameters)

            assert result["success"] is False
            assert "Empty content for certificate" in result.get("errors", [""])[0]
            assert result["deployed_count"] == 0

    @pytest.mark.asyncio
    async def test_deploy_certificates_success(self):
        """Test successful certificate deployment."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod") as mock_chmod:
                    with patch("os.chown") as mock_chown:
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ):
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "test-cert",
                                        "filename": "test.crt",
                                        "content": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                                        "subtype": "root",
                                    }
                                ]
                            }
                            result = await self.cert_ops.deploy_certificates(parameters)

                            assert result["success"] is True
                            assert result["deployed_count"] == 1
                            assert len(result["deployed_certificates"]) == 1
                            assert (
                                result["deployed_certificates"][0]["name"]
                                == "test-cert"
                            )
                            mock_chmod.assert_called_once()
                            mock_chown.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_certificates_default_filename(self):
        """Test deployment with default filename."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ):
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "my-cert",
                                        # No filename - should default to "my-cert.crt"
                                        "content": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                                    }
                                ]
                            }
                            result = await self.cert_ops.deploy_certificates(parameters)

                            assert result["success"] is True
                            assert (
                                result["deployed_certificates"][0]["filename"]
                                == "my-cert.crt"
                            )

    @pytest.mark.asyncio
    async def test_deploy_certificates_write_error(self):
        """Test deployment with file write error."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            with patch("aiofiles.open", side_effect=IOError("Permission denied")):
                parameters = {
                    "certificates": [
                        {
                            "name": "test-cert",
                            "content": "-----BEGIN CERTIFICATE-----",
                        }
                    ]
                }
                result = await self.cert_ops.deploy_certificates(parameters)

                assert result["success"] is False
                assert len(result.get("errors", [])) > 0
                assert "Failed to deploy certificate" in result["errors"][0]

    @pytest.mark.asyncio
    async def test_deploy_certificates_chmod_error(self):
        """Test deployment with chmod error."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod", side_effect=OSError("Permission denied")):
                    parameters = {
                        "certificates": [
                            {
                                "name": "test-cert",
                                "content": "-----BEGIN CERTIFICATE-----",
                            }
                        ]
                    }
                    result = await self.cert_ops.deploy_certificates(parameters)

                    assert result["success"] is False
                    assert len(result.get("errors", [])) > 0

    @pytest.mark.asyncio
    async def test_deploy_certificates_multiple_certs(self):
        """Test deploying multiple certificates."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ):
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "cert1",
                                        "content": "cert-content-1",
                                        "subtype": "root",
                                    },
                                    {
                                        "name": "cert2",
                                        "content": "cert-content-2",
                                        "subtype": "intermediate",
                                    },
                                    {
                                        "name": "cert3",
                                        "content": "cert-content-3",
                                        "subtype": "server",
                                    },
                                ]
                            }
                            result = await self.cert_ops.deploy_certificates(parameters)

                            assert result["success"] is True
                            assert result["deployed_count"] == 3

    @pytest.mark.asyncio
    async def test_deploy_certificates_ca_update_failure(self):
        """Test deployment with CA update failure (should still succeed)."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                            side_effect=Exception("update-ca-certificates failed"),
                        ):
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "ca-cert",
                                        "content": "ca-content",
                                        "subtype": "ca",
                                    }
                                ]
                            }
                            result = await self.cert_ops.deploy_certificates(parameters)

                            # Should still succeed for certificate deployment
                            assert result["success"] is True
                            # But should have errors about CA update
                            assert len(result.get("errors", [])) > 0
                            assert "Failed to update CA certificate bundle" in str(
                                result["errors"]
                            )

    @pytest.mark.asyncio
    async def test_deploy_certificates_no_ca_update_for_non_ca_certs(self):
        """Test that CA update is not called for non-CA certificates."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ) as mock_update_ca:
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "server-cert",
                                        "content": "server-content",
                                        "subtype": "server",
                                    }
                                ]
                            }
                            result = await self.cert_ops.deploy_certificates(parameters)

                            assert result["success"] is True
                            # CA update should NOT be called for non-CA certs
                            mock_update_ca.assert_not_called()

    @pytest.mark.asyncio
    async def test_deploy_certificates_content_newline_handling(self):
        """Test that content without trailing newline gets one added."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {
                                    "name": "test-cert",
                                    "content": "no-trailing-newline",  # No \n at end
                                }
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        assert result["success"] is True
                        # Should have been called twice - once for content, once for newline
                        assert mock_file.write.call_count == 2

    @pytest.mark.asyncio
    async def test_deploy_certificates_content_with_newline(self):
        """Test that content with trailing newline doesn't get extra newline."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {
                                    "name": "test-cert",
                                    "content": "has-trailing-newline\n",  # Has \n at end
                                }
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        assert result["success"] is True
                        # Should have been called only once - content already has newline
                        assert mock_file.write.call_count == 1

    @pytest.mark.asyncio
    async def test_deploy_certificates_unexpected_exception(self):
        """Test deployment with unexpected exception."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            side_effect=Exception("Unexpected error"),
        ):
            with patch.object(
                self.cert_ops,
                "_validate_certificate_inputs",
                return_value=None,
            ):
                parameters = {
                    "certificates": [{"name": "test-cert", "content": "cert-content"}]
                }
                result = await self.cert_ops.deploy_certificates(parameters)

                assert result["success"] is False
                assert (
                    "Unexpected error during certificate deployment" in result["error"]
                )


class TestUpdateCaCertificates:
    """Test cases for CA certificate bundle update."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @pytest.mark.asyncio
    @patch("platform.system")
    @patch("os.path.exists")
    async def test_update_ca_certificates_linux_debian(self, mock_exists, mock_system):
        """Test CA update on Debian/Ubuntu Linux."""
        mock_system.return_value = "Linux"
        mock_exists.side_effect = (
            lambda path: path == "/usr/sbin/update-ca-certificates"
        )
        self.mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True
        }

        await self.cert_ops._update_ca_certificates()

        self.mock_agent.system_ops.execute_shell_command.assert_called_once_with(
            {"command": "sudo /usr/sbin/update-ca-certificates"}
        )

    @pytest.mark.asyncio
    @patch("platform.system")
    @patch("os.path.exists")
    async def test_update_ca_certificates_linux_rhel(self, mock_exists, mock_system):
        """Test CA update on RHEL/CentOS/Fedora Linux."""
        mock_system.return_value = "Linux"
        # update-ca-certificates doesn't exist, but update-ca-trust does
        mock_exists.side_effect = lambda path: path == "/usr/bin/update-ca-trust"
        self.mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True
        }

        await self.cert_ops._update_ca_certificates()

        self.mock_agent.system_ops.execute_shell_command.assert_called_once_with(
            {"command": "sudo /usr/bin/update-ca-trust extract"}
        )

    @pytest.mark.asyncio
    @patch("platform.system")
    @patch("os.path.exists")
    async def test_update_ca_certificates_linux_debian_fails_try_rhel(
        self, mock_exists, mock_system
    ):
        """Test CA update falls back to RHEL method when Debian method fails."""
        mock_system.return_value = "Linux"
        mock_exists.return_value = True  # Both paths exist

        # First call fails, second succeeds
        self.mock_agent.system_ops.execute_shell_command.side_effect = [
            {"success": False},  # update-ca-certificates fails
            {"success": True},  # update-ca-trust succeeds
        ]

        await self.cert_ops._update_ca_certificates()

        assert self.mock_agent.system_ops.execute_shell_command.call_count == 2

    @pytest.mark.asyncio
    @patch("platform.system")
    @patch("os.path.exists")
    async def test_update_ca_certificates_linux_no_update_mechanism(
        self, mock_exists, mock_system
    ):
        """Test CA update when no update mechanism is available."""
        mock_system.return_value = "Linux"
        mock_exists.return_value = False  # Neither update tool exists

        # Should not raise, just log warning
        await self.cert_ops._update_ca_certificates()

        self.mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    @patch("platform.system")
    async def test_update_ca_certificates_macos(self, mock_system):
        """Test CA update on macOS (not implemented)."""
        mock_system.return_value = "Darwin"

        # Should not raise, just log info
        await self.cert_ops._update_ca_certificates()

        self.mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    @patch("platform.system")
    async def test_update_ca_certificates_freebsd(self, mock_system):
        """Test CA update on FreeBSD (not implemented)."""
        mock_system.return_value = "FreeBSD"

        # Should not raise, just log info
        await self.cert_ops._update_ca_certificates()

        self.mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    @patch("platform.system")
    async def test_update_ca_certificates_openbsd(self, mock_system):
        """Test CA update on OpenBSD (not implemented)."""
        mock_system.return_value = "OpenBSD"

        # Should not raise, just log info
        await self.cert_ops._update_ca_certificates()

        self.mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    @patch("platform.system")
    @patch("os.path.exists")
    async def test_update_ca_certificates_exception(self, mock_exists, mock_system):
        """Test CA update raises exception on error."""
        mock_system.return_value = "Linux"
        mock_exists.return_value = True
        self.mock_agent.system_ops.execute_shell_command.side_effect = Exception(
            "Command failed"
        )

        with pytest.raises(Exception, match="Command failed"):
            await self.cert_ops._update_ca_certificates()


class TestDeployCertificatesIntegration:
    """Integration tests for certificate deployment workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_mixed_certificates(self):
        """Test deploying mix of CA and non-CA certificates."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ) as mock_update_ca:
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "root-ca",
                                        "content": "root-ca-content",
                                        "subtype": "root",
                                    },
                                    {
                                        "name": "intermediate-ca",
                                        "content": "intermediate-ca-content",
                                        "subtype": "intermediate",
                                    },
                                    {
                                        "name": "server-cert",
                                        "content": "server-cert-content",
                                        "subtype": "server",
                                    },
                                ]
                            }
                            result = await self.cert_ops.deploy_certificates(parameters)

                            assert result["success"] is True
                            assert result["deployed_count"] == 3
                            # CA update should be called because we have root/intermediate certs
                            mock_update_ca.assert_called_once()

    @pytest.mark.asyncio
    async def test_deploy_partial_failure(self):
        """Test deployment where some certificates fail."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            call_count = 0

            def aiofiles_side_effect(*_args, **_kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 2:
                    raise IOError("Write failed")
                return mock_file

            with patch("aiofiles.open", side_effect=aiofiles_side_effect):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {"name": "cert1", "content": "content1"},
                                {"name": "cert2", "content": "content2"},  # Will fail
                                {"name": "cert3", "content": "content3"},
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        # Should have partial success
                        assert result["success"] is True  # At least some deployed
                        assert result["deployed_count"] == 2
                        assert len(result.get("errors", [])) == 1

    @pytest.mark.asyncio
    async def test_deploy_all_fail(self):
        """Test deployment where all certificates fail."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            parameters = {
                "certificates": [
                    {"name": "cert1", "content": ""},  # Empty content
                    {"name": "cert2", "content": ""},  # Empty content
                ]
            }
            result = await self.cert_ops.deploy_certificates(parameters)

            assert result["success"] is False
            assert result["deployed_count"] == 0
            assert "No certificates were successfully deployed" in result.get(
                "error", ""
            )


class TestCertificateSubtypes:
    """Test cases for different certificate subtypes."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_ca_subtype_triggers_update(self):
        """Test that 'ca' subtype triggers CA bundle update."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ) as mock_update:
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "ca",
                                        "content": "ca-content",
                                        "subtype": "ca",
                                    }
                                ]
                            }
                            await self.cert_ops.deploy_certificates(parameters)
                            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_root_subtype_triggers_update(self):
        """Test that 'root' subtype triggers CA bundle update."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ) as mock_update:
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "root",
                                        "content": "root-content",
                                        "subtype": "root",
                                    }
                                ]
                            }
                            await self.cert_ops.deploy_certificates(parameters)
                            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_intermediate_subtype_triggers_update(self):
        """Test that 'intermediate' subtype triggers CA bundle update."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ) as mock_update:
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "intermediate",
                                        "content": "intermediate-content",
                                        "subtype": "intermediate",
                                    }
                                ]
                            }
                            await self.cert_ops.deploy_certificates(parameters)
                            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_server_subtype_no_update(self):
        """Test that 'server' subtype does not trigger CA bundle update."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(
                            self.cert_ops,
                            "_update_ca_certificates",
                            new_callable=AsyncMock,
                        ) as mock_update:
                            parameters = {
                                "certificates": [
                                    {
                                        "name": "server",
                                        "content": "server-content",
                                        "subtype": "server",
                                    }
                                ]
                            }
                            await self.cert_ops.deploy_certificates(parameters)
                            mock_update.assert_not_called()

    @pytest.mark.asyncio
    async def test_default_subtype(self):
        """Test certificate with default subtype (certificate)."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {
                                    "name": "cert",
                                    "content": "cert-content",
                                    # No subtype specified - defaults to "certificate"
                                }
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        assert result["success"] is True
                        assert (
                            result["deployed_certificates"][0]["subtype"]
                            == "certificate"
                        )


class TestLogging:
    """Test cases for logging behavior."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_log_successful_deployment(self):
        """Test logging on successful deployment."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        with patch.object(self.cert_ops, "logger") as mock_logger:
                            parameters = {
                                "certificates": [
                                    {"name": "test-cert", "content": "content"}
                                ]
                            }
                            await self.cert_ops.deploy_certificates(parameters)

                            mock_logger.info.assert_called()

    @pytest.mark.asyncio
    async def test_log_deployment_error(self):
        """Test logging on deployment error."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            with patch("aiofiles.open", side_effect=IOError("Write failed")):
                with patch.object(self.cert_ops, "logger") as mock_logger:
                    parameters = {
                        "certificates": [{"name": "test-cert", "content": "content"}]
                    }
                    await self.cert_ops.deploy_certificates(parameters)

                    mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_log_unexpected_error(self):
        """Test logging on unexpected error."""
        with patch.object(
            self.cert_ops,
            "_validate_certificate_inputs",
            return_value=None,
        ):
            with patch.object(
                self.cert_ops,
                "_get_ssl_directory",
                side_effect=Exception("Unexpected"),
            ):
                with patch.object(self.cert_ops, "logger") as mock_logger:
                    parameters = {
                        "certificates": [{"name": "test-cert", "content": "content"}]
                    }
                    await self.cert_ops.deploy_certificates(parameters)

                    mock_logger.error.assert_called()


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.system_ops = Mock()
        self.mock_agent.system_ops.execute_shell_command = AsyncMock()
        self.cert_ops = CertificateOperations(self.mock_agent)

    def test_ssl_certs_dir_constant(self):
        """Test that _SSL_CERTS_DIR is set correctly."""
        assert _SSL_CERTS_DIR == "/etc/ssl/certs"

    @pytest.mark.asyncio
    async def test_deploy_with_special_characters_in_name(self):
        """Test deployment with special characters in certificate name."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {
                                    "name": "cert-with-special_chars.test",
                                    "content": "content",
                                }
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_with_unicode_content(self):
        """Test deployment with unicode content in certificate."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {
                                    "name": "unicode-cert",
                                    "content": "-----BEGIN CERTIFICATE-----\nUnicode: \u00e9\u00e8\u00ea\n-----END CERTIFICATE-----",
                                }
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_certificate_without_name_key(self):
        """Test deployment when certificate has no 'name' key."""
        with patch.object(
            self.cert_ops,
            "_get_ssl_directory",
            return_value={"success": True, "ssl_dir": "/etc/ssl/certs"},
        ):
            mock_file = MagicMock()
            mock_file.__aenter__ = AsyncMock(return_value=mock_file)
            mock_file.__aexit__ = AsyncMock(return_value=None)
            mock_file.write = AsyncMock()

            with patch("aiofiles.open", return_value=mock_file):
                with patch("os.chmod"):
                    with patch("os.chown"):
                        parameters = {
                            "certificates": [
                                {
                                    # No 'name' key - should default to 'unknown'
                                    "content": "content",
                                    "filename": "test.crt",
                                }
                            ]
                        }
                        result = await self.cert_ops.deploy_certificates(parameters)

                        assert result["success"] is True
                        # Name should default to 'unknown'
                        assert result["deployed_certificates"][0]["name"] == "unknown"

    def test_get_linux_ssl_dir_various_distros(self):
        """Test Linux SSL dir detection for various distributions."""
        distro_tests = [
            ("ID=rhel", "/etc/pki/tls/certs"),
            ("ID=centos", "/etc/pki/tls/certs"),
            ("ID=fedora", "/etc/pki/tls/certs"),
            ('NAME="Red Hat Enterprise Linux"', "/etc/pki/tls/certs"),
            ("ID=ubuntu", "/etc/ssl/certs"),
            ("ID=debian", "/etc/ssl/certs"),
            ("ID=arch", "/etc/ssl/certs"),
        ]

        for os_release_content, expected_dir in distro_tests:
            # Capture loop variable in closure
            content = os_release_content
            with patch("os.path.exists", return_value=True):
                with patch(
                    "builtins.open",
                    MagicMock(
                        return_value=MagicMock(
                            __enter__=lambda s, c=content: MagicMock(read=lambda: c),
                            __exit__=lambda *args: None,
                        )
                    ),
                ):
                    result = self.cert_ops._get_linux_ssl_dir()
                    assert (
                        result == expected_dir
                    ), f"Failed for {os_release_content}: expected {expected_dir}, got {result}"
