"""
SSL Certificate collection module for SysManage Agent.
Handles platform-specific SSL certificate discovery and information gathering.
"""

import glob
import json
import logging
import os
import platform
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.i18n import _

logger = logging.getLogger(__name__)


class CertificateCollector:
    """Collects SSL certificate information across different platforms."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def collect_certificates(self) -> List[Dict[str, Any]]:
        """Collect SSL certificate information from the system."""
        system = platform.system()
        certificates = []

        try:
            if system == "Windows":
                certificates = self._collect_windows_certificates()
            elif system == "Darwin":  # macOS
                certificates = self._collect_unix_certificates(
                    self._get_macos_cert_paths()
                )
            elif system in ["Linux", "FreeBSD", "OpenBSD"]:
                certificates = self._collect_unix_certificates(
                    self._get_unix_cert_paths()
                )
            else:
                self.logger.warning(
                    _("Unsupported platform for certificate collection: %s"), system
                )

            self.logger.info(_("Collected %d certificates"), len(certificates))
            return certificates

        except Exception as e:
            self.logger.error(_("Error collecting certificates: %s"), e)
            return []

    def _get_unix_cert_paths(self) -> List[str]:
        """Get certificate directory paths for Unix/Linux systems."""
        system = platform.system()
        paths = []

        if system == "Linux":
            # Detect distribution-specific paths
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    os_release = f.read()

                if "ubuntu" in os_release.lower() or "debian" in os_release.lower():
                    paths = ["/etc/ssl/certs", "/usr/local/share/ca-certificates"]
                elif any(
                    distro in os_release.lower()
                    for distro in ["rhel", "centos", "fedora", "red hat"]
                ):
                    paths = ["/etc/pki/tls/certs", "/etc/pki/ca-trust/source/anchors"]
                elif "opensuse" in os_release.lower():
                    paths = ["/etc/ssl/certs", "/var/lib/ca-certificates/pem"]
                else:
                    # Default Linux paths
                    paths = ["/etc/ssl/certs", "/etc/pki/tls/certs"]
            else:
                # Fallback for systems without os-release
                paths = ["/etc/ssl/certs", "/etc/pki/tls/certs"]

        elif system == "FreeBSD":
            paths = [
                "/usr/local/share/certs",
                "/etc/ssl/certs",
                "/usr/local/etc/ssl/certs",
                "/usr/local/etc/pki/tls/certs",
                "/etc/pki/tls/certs",
            ]
        elif system == "OpenBSD":
            paths = [
                "/etc/ssl",  # Include the main SSL directory for cert.pem
                "/etc/ssl/certs",
                "/var/www/conf/ssl",
                "/usr/local/etc/ssl/certs",
                "/usr/local/share/certs",
                "/etc/ssl/private",  # Private keys directory
            ]

        # Add common application-specific directories
        app_paths = [
            "/opt/*/ssl/certs",
            "/usr/local/nginx/conf/ssl",
            "/etc/nginx/ssl",
            "/etc/apache2/ssl/certs",
            "/etc/httpd/ssl/certs",
        ]

        # Add FreeBSD-specific application directories
        if system == "FreeBSD":
            freebsd_app_paths = [
                "/usr/local/etc/nginx/ssl",
                "/usr/local/etc/apache24/ssl",
                "/usr/local/etc/ssl/certs",
                "/usr/local/share/ca-certificates",
            ]
            app_paths.extend(freebsd_app_paths)

        # Add OpenBSD-specific application directories
        elif system == "OpenBSD":
            openbsd_app_paths = [
                "/var/www/conf/ssl",
                "/usr/local/etc/nginx/ssl",
                "/usr/local/share/ca-certificates",
                "/usr/local/etc/apache2/ssl",
                "/etc/httpd/ssl",
            ]
            app_paths.extend(openbsd_app_paths)

        for app_path in app_paths:
            paths.extend(glob.glob(app_path))

        return [p for p in paths if os.path.isdir(p)]

    def _get_macos_cert_paths(self) -> List[str]:
        """Get certificate directory paths for macOS."""
        paths = [
            "/etc/ssl/certs",
            "/usr/local/etc/openssl/certs",
            "/System/Library/OpenSSL/certs",
        ]

        # Add Homebrew OpenSSL paths if they exist
        homebrew_paths = [
            "/opt/homebrew/etc/openssl/certs",
            "/usr/local/opt/openssl/ssl/certs",
        ]

        return [p for p in (paths + homebrew_paths) if os.path.isdir(p)]

    def _collect_unix_certificates(self, cert_paths: List[str]) -> List[Dict[str, Any]]:
        """Collect certificates from Unix/Linux filesystem paths."""
        certificates = []
        seen_fingerprints = set()  # Track unique certificates by fingerprint

        for cert_dir in cert_paths:
            self._process_certificate_directory(
                cert_dir, certificates, seen_fingerprints
            )

        return certificates

    def _process_certificate_directory(
        self, cert_dir: str, certificates: List[Dict[str, Any]], seen_fingerprints: set
    ) -> None:
        """Process a single certificate directory."""
        try:
            self.logger.debug(_("Scanning certificate directory: %s"), cert_dir)
            cert_patterns = ["*.pem", "*.crt", "*.cer"]

            for pattern in cert_patterns:
                self._process_certificate_pattern(
                    cert_dir, pattern, certificates, seen_fingerprints
                )

        except Exception as e:
            self.logger.warning(
                _("Failed to scan certificate directory %s: %s"), cert_dir, e
            )

    def _process_certificate_pattern(
        self,
        cert_dir: str,
        pattern: str,
        certificates: List[Dict[str, Any]],
        seen_fingerprints: set,
    ) -> None:
        """Process certificate files matching a specific pattern."""
        # Check for files in the directory itself
        cert_files = glob.glob(os.path.join(cert_dir, pattern))
        # Also check subdirectories recursively
        cert_files.extend(
            glob.glob(os.path.join(cert_dir, "**", pattern), recursive=True)
        )

        for cert_file in cert_files:
            self._process_single_certificate(cert_file, certificates, seen_fingerprints)

    def _process_single_certificate(
        self, cert_file: str, certificates: List[Dict[str, Any]], seen_fingerprints: set
    ) -> None:
        """Process a single certificate file."""
        try:
            cert_info = self._extract_certificate_info(cert_file)
            if cert_info:
                fingerprint = cert_info.get("fingerprint_sha256")
                if fingerprint and fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(fingerprint)
                    certificates.append(cert_info)
                elif not fingerprint:
                    # If no fingerprint, include it anyway
                    certificates.append(cert_info)

        except Exception as e:
            self.logger.debug(_("Failed to process certificate %s: %s"), cert_file, e)

    def _collect_windows_certificates(self) -> List[Dict[str, Any]]:
        """Collect certificates from Windows Certificate Store."""
        certificates = []

        try:
            # Comprehensive list of Windows certificate stores
            # Ordered by importance - start with stores most likely to contain certificates
            stores = [
                "LocalMachine\\Root",  # Trusted Root Certification Authorities (usually has many certs)
                "LocalMachine\\CA",  # Intermediate Certification Authorities
                "CurrentUser\\My",  # Current User Personal certificates
                "LocalMachine\\My",  # Local Machine Personal certificates
                "LocalMachine\\AuthRoot",  # Third-party root CAs
                "LocalMachine\\TrustedPeople",  # Trusted People
                "LocalMachine\\TrustedPublisher",  # Trusted Publishers
                "CurrentUser\\Root",  # Current User Root certificates
                "CurrentUser\\CA",  # Current User Intermediate CAs
                "LocalMachine\\WebHosting",  # Web hosting certificates (if available)
                "CurrentUser\\TrustedPeople",  # Current User Trusted People
            ]

            for store in stores:
                self._process_windows_certificate_store(store, certificates)

            self.logger.info(
                _("Windows certificate collection completed: %d certificates found"),
                len(certificates),
            )

        except Exception as e:
            self.logger.error(_("Error collecting Windows certificates: %s"), e)

        return certificates

    def _process_windows_certificate_store(
        self, store: str, certificates: List[Dict[str, Any]]
    ) -> None:
        """Process certificates from a specific Windows certificate store."""
        try:
            ps_command = self._build_powershell_command(store)
            result = self._execute_powershell_command(ps_command)

            if result and result.returncode == 0:
                if result.stdout.strip():
                    cert_count_before = len(certificates)
                    self._parse_powershell_output(result.stdout, certificates)
                    cert_count_after = len(certificates)
                    added_certs = cert_count_after - cert_count_before
                    if added_certs > 0:
                        self.logger.debug(
                            _("Found %d certificates in store %s"), added_certs, store
                        )
                    else:
                        self.logger.debug(
                            _("No valid certificates found in store %s"), store
                        )
                else:
                    self.logger.debug(_("Certificate store %s is empty"), store)
            else:
                error_msg = (
                    result.stderr.strip()
                    if result and result.stderr
                    else "Unknown error"
                )
                self.logger.debug(
                    _("Failed to query certificate store %s: %s"), store, error_msg
                )

        except subprocess.TimeoutExpired:
            self.logger.warning(
                _("Timeout querying Windows certificate store: %s"), store
            )
        except Exception as e:
            self.logger.warning(
                _("Failed to query Windows certificate store %s: %s"), store, e
            )

    def _build_powershell_command(self, store: str) -> str:
        """Build PowerShell command for querying certificate store."""
        return f"""
        Get-ChildItem -Path "Cert:\\{store}" | ForEach-Object {{
            $cert = $_
            $json = @{{
                Subject = $cert.Subject
                Issuer = $cert.Issuer
                NotBefore = $cert.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssZ')
                NotAfter = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssZ')
                SerialNumber = $cert.SerialNumber
                Thumbprint = $cert.Thumbprint
                Store = "{store}"
                HasPrivateKey = $cert.HasPrivateKey
            }} | ConvertTo-Json -Compress
            Write-Output $json
        }}
        """

    def _execute_powershell_command(self, ps_command: str):
        """Execute PowerShell command and return result."""
        return subprocess.run(  # nosec B602 B603 B607
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def _parse_powershell_output(
        self, stdout: str, certificates: List[Dict[str, Any]]
    ) -> None:
        """Parse PowerShell output and extract certificate information."""
        lines = stdout.strip().split("\n")
        for line in lines:
            line = line.strip()
            if line:
                try:
                    cert_data = json.loads(line)
                    cert_info = self._format_windows_certificate(cert_data)
                    if cert_info:
                        certificates.append(cert_info)
                except json.JSONDecodeError:
                    self.logger.debug(
                        _("Failed to parse certificate JSON: %s"), line[:100]
                    )
                    continue
                except Exception as e:
                    self.logger.debug(
                        _("Error processing certificate data: %s"), str(e)
                    )
                    continue

    def _extract_certificate_info(self, cert_file: str) -> Optional[Dict[str, Any]]:
        """Extract certificate information using OpenSSL."""
        try:
            # Use openssl command (OpenBSD also uses openssl command despite having LibreSSL)
            openssl_cmd = "openssl"

            # Extract certificate information including key usage and purpose
            cmd = [
                openssl_cmd,
                "x509",
                "-in",
                cert_file,
                "-noout",
                "-subject",
                "-issuer",
                "-startdate",
                "-enddate",
                "-serial",
                "-fingerprint",
                "-sha256",
                "-purpose",
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, check=False
            )  # nosec B602 B603

            if result.returncode != 0:
                self.logger.debug(
                    _("OpenSSL failed for %s: %s"), cert_file, result.stderr
                )
                return None

            return self._parse_openssl_output(cert_file, result.stdout)

        except subprocess.TimeoutExpired:
            self.logger.warning(
                _("Timeout extracting certificate info from: %s"), cert_file
            )
            return None
        except FileNotFoundError:
            self.logger.warning(
                _("OpenSSL/LibreSSL not found, skipping certificate: %s"), cert_file
            )
            return None
        except Exception as e:
            self.logger.debug(
                _("Error extracting certificate info from %s: %s"), cert_file, e
            )
            return None

    def _parse_openssl_output(self, cert_file: str, output: str) -> Dict[str, Any]:
        """Parse OpenSSL output into structured certificate information."""
        cert_info = {
            "file_path": cert_file,
            "certificate_name": None,
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "serial_number": None,
            "fingerprint_sha256": None,
            "is_ca": False,
            "key_usage": None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

        for line in output.strip().split("\n"):
            line = line.strip()

            if line.startswith("subject="):
                cert_info["subject"] = line[8:].strip()
                # Extract common name for certificate_name
                cn_match = [
                    part for part in cert_info["subject"].split(",") if "CN=" in part
                ]
                if cn_match:
                    cert_info["certificate_name"] = cn_match[0].split("CN=")[1].strip()

            elif line.startswith("issuer="):
                cert_info["issuer"] = line[7:].strip()

            elif line.startswith("notBefore="):
                try:
                    date_str = line[10:].strip()
                    # Remove timezone suffix (GMT) as strptime has issues with %Z
                    if date_str.endswith(" GMT"):
                        date_str = date_str[:-4]
                    # Convert OpenSSL date format to ISO format
                    dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                    cert_info["not_before"] = dt.replace(
                        tzinfo=timezone.utc
                    ).isoformat()
                except ValueError as e:
                    self.logger.debug(
                        _("Failed to parse notBefore date '%s': %s"), date_str, e
                    )

            elif line.startswith("notAfter="):
                try:
                    date_str = line[9:].strip()
                    # Remove timezone suffix (GMT) as strptime has issues with %Z
                    if date_str.endswith(" GMT"):
                        date_str = date_str[:-4]
                    # Convert OpenSSL date format to ISO format
                    dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                    cert_info["not_after"] = dt.replace(tzinfo=timezone.utc).isoformat()
                except ValueError as e:
                    self.logger.debug(
                        _("Failed to parse notAfter date '%s': %s"), date_str, e
                    )

            elif line.startswith("serial="):
                cert_info["serial_number"] = line[7:].strip()

            elif line.startswith("SHA256 Fingerprint="):
                cert_info["fingerprint_sha256"] = (
                    line[19:].strip().replace(":", "").lower()
                )

        # Parse purpose information to determine certificate type
        cert_info["key_usage"] = self._determine_certificate_type(output)

        # Determine if it's a CA certificate based on path, subject, or purpose
        cert_path_lower = cert_file.lower()
        is_ca_path = any(
            ca_indicator in cert_path_lower
            for ca_indicator in ["ca", "root", "intermediate"]
        )
        is_ca_subject = cert_info.get("subject", "").find(
            "CA:TRUE"
        ) != -1 or "Root" in cert_info.get("subject", "")
        is_ca_purpose = (
            "Certificate Sign" in output
            and "SSL client" not in output
            and "SSL server" not in output
        )
        cert_info["is_ca"] = is_ca_path or is_ca_subject or is_ca_purpose

        return cert_info

    def _determine_certificate_type(self, openssl_output: str) -> str:
        """
        Determine certificate type based on OpenSSL purpose output.
        Returns 'CA', 'Server', 'Client', or 'Unknown'.
        """
        output_lower = openssl_output.lower()

        # Check for CA certificate indicators - enhanced detection
        ca_indicators = [
            "ssl client ca : yes",
            "ssl server ca : yes",
            "certificate sign : yes",
        ]

        # Check certificate name/subject for CA indicators first
        cert_type = self._check_subject_for_ca_indicators(openssl_output)
        if cert_type:
            return cert_type

        # Check OpenSSL purpose output for CA indicators - prioritize CA indicators
        if self._has_ca_indicators(output_lower, ca_indicators):
            return "CA"

        # Check for server/client certificate types
        cert_type = self._check_ssl_purpose_indicators(output_lower)
        if cert_type:
            return cert_type

        # Check for other purposes
        cert_type = self._check_other_purposes(output_lower)
        if cert_type:
            return cert_type

        return "Unknown"

    def _check_subject_for_ca_indicators(self, openssl_output: str) -> Optional[str]:
        """Check certificate subject for CA indicators."""
        subject_ca_indicators = [
            "root ca",
            "root certification authority",
            "certificate authority",
            "global root ca",
        ]
        for line in openssl_output.split("\n"):
            if line.strip().startswith("subject="):
                subject_lower = line.lower()
                if any(
                    indicator in subject_lower for indicator in subject_ca_indicators
                ):
                    return "CA"
        return None

    def _has_ca_indicators(self, output_lower: str, ca_indicators: List[str]) -> bool:
        """Check if output has CA indicators."""
        has_basic_ca = any(indicator in output_lower for indicator in ca_indicators)
        has_cert_sign = (
            "certificate sign" in output_lower
            and "ssl client : no" in output_lower
            and "ssl server : no" in output_lower
        )
        has_explicit_ca = (
            "ssl client ca : yes" in output_lower
            or "ssl server ca : yes" in output_lower
        )
        return has_basic_ca or has_cert_sign or has_explicit_ca

    def _check_ssl_purpose_indicators(self, output_lower: str) -> Optional[str]:
        """Check for SSL server/client certificate indicators."""
        # Check for server certificate indicators (only if not already identified as CA)
        if (
            "ssl server : yes" in output_lower
            and "ssl server ca : yes" not in output_lower
        ):
            return "Server"

        # Check for client certificate indicators
        if "ssl client : yes" in output_lower and "ssl server : no" in output_lower:
            return "Client"

        # If both SSL client and server are yes, prefer server
        if "ssl client : yes" in output_lower and "ssl server : yes" in output_lower:
            return "Server"

        return None

    def _check_other_purposes(self, output_lower: str) -> Optional[str]:
        """Check for other certificate purposes."""
        if "code signing" in output_lower:
            return "Code Signing"
        if "email protection" in output_lower or "s/mime" in output_lower:
            return "Email"
        return None

    def _format_windows_certificate(self, cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format Windows certificate data into our standard format."""
        return {
            "file_path": f"Windows Certificate Store: {cert_data.get('Store', '')}",
            "certificate_name": self._extract_cn_from_subject(
                cert_data.get("Subject", "")
            ),
            "subject": cert_data.get("Subject"),
            "issuer": cert_data.get("Issuer"),
            "not_before": cert_data.get("NotBefore"),
            "not_after": cert_data.get("NotAfter"),
            "serial_number": cert_data.get("SerialNumber"),
            "fingerprint_sha256": cert_data.get("Thumbprint", "").lower(),
            "is_ca": "Root" in cert_data.get("Store", "")
            or "CA" in cert_data.get("Store", ""),
            "key_usage": (
                "CA"
                if (
                    "Root" in cert_data.get("Store", "")
                    or "CA" in cert_data.get("Store", "")
                )
                else "Server"
            ),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    def _extract_cn_from_subject(self, subject: str) -> str:
        """Extract Common Name from certificate subject."""
        if not subject:
            return ""

        # Parse subject string to extract CN
        for part in subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                return part[3:].strip()
        return ""
