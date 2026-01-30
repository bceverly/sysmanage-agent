"""
Certificate operations module for SysManage agent.
Handles SSL/TLS certificate deployment and management.
"""

from __future__ import annotations

import logging
import os
import platform
from typing import Any, Dict

import aiofiles

# Default SSL certificate directory
_SSL_CERTS_DIR = "/etc/ssl/certs"


class CertificateOperations:
    """Handles certificate-related operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize certificate operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def deploy_certificates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSL certificates to the appropriate system directory."""
        certificates = parameters.get("certificates", [])

        # Validate inputs
        validation_error = self._validate_certificate_inputs(certificates)
        if validation_error:
            return validation_error

        try:
            # Determine the SSL certificate directory based on OS
            ssl_dir_result = self._get_ssl_directory()
            if not ssl_dir_result["success"]:
                return ssl_dir_result

            ssl_dir = ssl_dir_result["ssl_dir"]
            deployed_certificates = []
            errors = []

            for certificate in certificates:
                cert_name = certificate.get("name", "unknown")
                filename = certificate.get("filename", f"{cert_name}.crt")
                content = certificate.get("content", "")
                subtype = certificate.get("subtype", "certificate")

                if not content:
                    errors.append(f"Empty content for certificate '{cert_name}'")
                    continue

                try:
                    # Full path for the certificate file
                    cert_file_path = os.path.join(ssl_dir, filename)

                    # Write the certificate file
                    async with aiofiles.open(
                        cert_file_path, "w", encoding="utf-8"
                    ) as file_handle:
                        await file_handle.write(content)
                        # Ensure content ends with newline
                        if not content.endswith("\n"):
                            await file_handle.write("\n")

                    # Set appropriate permissions for certificates (644 - readable by all)
                    os.chmod(cert_file_path, 0o644)  # NOSONAR

                    # Set root ownership (certificates should be owned by root)
                    os.chown(cert_file_path, 0, 0)

                    deployed_certificates.append(
                        {
                            "name": cert_name,
                            "filename": filename,
                            "path": cert_file_path,
                            "subtype": subtype,
                        }
                    )

                    self.logger.info(
                        "Successfully deployed certificate '%s' to %s",
                        cert_name,
                        cert_file_path,
                    )

                except (OSError, IOError) as error:
                    error_msg = (
                        f"Failed to deploy certificate '{cert_name}': {str(error)}"
                    )
                    errors.append(error_msg)
                    self.logger.error(error_msg)

            # Update certificate bundle if we deployed CA certificates
            ca_certificates = [
                c
                for c in deployed_certificates
                if c.get("subtype") in ["root", "intermediate", "ca"]
            ]
            if ca_certificates:
                try:
                    await self._update_ca_certificates()
                    self.logger.info("Updated CA certificate bundle")
                except Exception as error:
                    error_msg = f"Failed to update CA certificate bundle: {str(error)}"
                    errors.append(error_msg)
                    self.logger.warning(error_msg)

            # Prepare result
            result = {
                "success": len(deployed_certificates) > 0,
                "deployed_certificates": deployed_certificates,
                "deployed_count": len(deployed_certificates),
                "ssl_directory": ssl_dir,
            }

            if errors:
                result["errors"] = errors
                result["error_count"] = len(errors)

            if len(deployed_certificates) == 0:
                result["error"] = "No certificates were successfully deployed"

            return result

        except Exception as error:
            self.logger.error(
                "Unexpected error during certificate deployment: %s", str(error)
            )
            return {
                "success": False,
                "error": f"Unexpected error during certificate deployment: {str(error)}",
            }

    def _validate_certificate_inputs(self, certificates: list) -> Dict[str, Any] | None:
        """Validate certificate deployment inputs."""
        if not certificates:
            return {"success": False, "error": "No certificates provided"}

        return None  # No validation errors

    def _get_ssl_directory(self) -> Dict[str, Any]:
        """Get the appropriate SSL certificate directory for the current OS."""
        system = platform.system().lower()

        ssl_dir = self._get_ssl_dir_for_system(system)
        if ssl_dir is None:
            return {
                "success": False,
                "error": f"Unsupported operating system for certificate deployment: {system}",
            }

        return self._validate_ssl_directory(ssl_dir)

    def _get_ssl_dir_for_system(self, system: str) -> str | None:
        """
        Get the SSL directory path for the given system.

        Returns:
            SSL directory path, or None if system is unsupported.
        """
        if system == "linux":
            return self._get_linux_ssl_dir()

        if system in ["darwin", "freebsd", "openbsd"]:
            return _SSL_CERTS_DIR

        return None

    def _get_linux_ssl_dir(self) -> str:
        """Detect the appropriate SSL directory for Linux distributions."""
        if not os.path.exists("/etc/os-release"):
            return _SSL_CERTS_DIR

        try:
            with open("/etc/os-release", "r", encoding="utf-8") as file_handle:
                os_release = file_handle.read().lower()
        except Exception:  # pylint: disable=broad-exception-caught
            return _SSL_CERTS_DIR

        if any(
            distro in os_release for distro in ["rhel", "centos", "fedora", "red hat"]
        ):
            return "/etc/pki/tls/certs"

        return _SSL_CERTS_DIR

    def _validate_ssl_directory(self, ssl_dir: str) -> Dict[str, Any]:
        """Validate that the SSL directory exists and is writable."""
        if not os.path.exists(ssl_dir):
            try:
                os.makedirs(ssl_dir, mode=0o755, exist_ok=True)
            except PermissionError:
                return {
                    "success": False,
                    "error": f"Permission denied creating SSL directory: {ssl_dir}",
                }
            except OSError as error:
                return {
                    "success": False,
                    "error": f"Failed to create SSL directory: {str(error)}",
                }

        if not os.access(ssl_dir, os.W_OK):
            return {
                "success": False,
                "error": f"No write permission to SSL directory: {ssl_dir}",
            }

        return {"success": True, "ssl_dir": ssl_dir}

    async def _update_ca_certificates(self):
        """Update the CA certificate bundle after deploying new CA certificates."""
        system = platform.system().lower()

        try:
            if system == "linux":
                # Try update-ca-certificates for Debian/Ubuntu systems
                if os.path.exists("/usr/sbin/update-ca-certificates"):
                    result = await self.agent_instance.system_ops.execute_shell_command(
                        {"command": "sudo /usr/sbin/update-ca-certificates"}
                    )
                    if result["success"]:
                        return

                # Try update-ca-trust for RHEL/CentOS/Fedora systems
                if os.path.exists("/usr/bin/update-ca-trust"):
                    result = await self.agent_instance.system_ops.execute_shell_command(
                        {"command": "sudo /usr/bin/update-ca-trust extract"}
                    )
                    if result["success"]:
                        return

            elif system == "darwin":  # macOS
                # For macOS, we would need to use the Security framework
                # This is a simplified approach - in practice you might want to use keychain
                self.logger.info("macOS certificate bundle update not implemented")
                return

            elif system in ["freebsd", "openbsd"]:
                # BSD systems might have their own certificate management
                self.logger.info("BSD certificate bundle update not implemented")
                return

            # If we get here, no update mechanism was found
            self.logger.warning(
                "No CA certificate update mechanism found for this system"
            )

        except Exception as error:
            self.logger.error("Error updating CA certificate bundle: %s", str(error))
            raise
