"""
WSL-specific child host operations.
"""

import asyncio
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, List

from src.i18n import _

from .child_host_wsl_control import WslControlOperations
from .child_host_wsl_setup import WslSetupOperations


class WslOperations:
    """WSL-specific operations for child host management."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize WSL operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks

        # Initialize sub-modules with shared decode function
        self._control_ops = WslControlOperations(logger, self._decode_wsl_output)
        self._setup_ops = WslSetupOperations(logger, self._decode_wsl_output)

    def _get_creationflags(self) -> int:
        """Get subprocess creation flags for Windows."""
        return (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

    def _validate_wsl_inputs(
        self, distribution: str, hostname: str, username: str, password_hash: str
    ) -> Dict[str, Any]:
        """Validate required inputs for WSL instance creation."""
        if not distribution:
            return {"success": False, "error": _("Distribution is required")}
        if not hostname:
            return {"success": False, "error": _("Hostname is required")}
        if not username:
            return {"success": False, "error": _("Username is required")}
        if not password_hash:
            return {"success": False, "error": _("Password hash is required")}
        return {"success": True}

    async def _check_and_enable_wsl(self) -> Dict[str, Any]:
        """Check WSL status and enable if needed."""
        wsl_check = self.virtualization_checks.check_wsl_support()
        if not wsl_check.get("available"):
            return {
                "success": False,
                "error": _("WSL is not available on this system"),
            }

        if wsl_check.get("needs_enable"):
            enable_result = await self.enable_wsl_internal()
            if not enable_result.get("success"):
                return enable_result
            if enable_result.get("reboot_required"):
                return {
                    "success": False,
                    "error": _("WSL has been enabled but a reboot is required"),
                    "reboot_required": True,
                }

        return {"success": True}

    async def _configure_wslconfig(self) -> None:
        """Configure .wslconfig and restart WSL if needed."""
        wslconfig_result = self._setup_ops.configure_wslconfig()
        if wslconfig_result.get("success"):
            self.logger.info(
                "Configured .wslconfig for %d user profile(s)",
                wslconfig_result.get("profiles_configured", 0),
            )
            if not wslconfig_result.get("already_configured"):
                await self._restart_wsl_for_config()
        else:
            self.logger.warning(
                "Could not configure .wslconfig: %s",
                wslconfig_result.get("error", "Unknown error"),
            )

    async def _restart_wsl_for_config(self) -> None:
        """Restart WSL to apply new .wslconfig settings."""
        self.logger.info("Restarting WSL to apply new .wslconfig settings...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--shutdown",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)
            self.logger.info("WSL restarted successfully")
        except asyncio.TimeoutError:
            self.logger.warning("WSL shutdown timed out, continuing anyway")
        except Exception as shutdown_error:
            self.logger.warning("Could not restart WSL: %s", shutdown_error)

    async def _setup_wsl_user_and_systemd(
        self,
        actual_wsl_name: str,
        exe_name: str,
        username: str,
        password_hash: str,
        fqdn_hostname: str,
    ) -> Dict[str, Any]:
        """Set up user, systemd, and hostname in WSL instance."""
        # Configure default user as root temporarily
        await self._send_progress(
            "configuring_root", _("Configuring temporary root access...")
        )
        config_result = await self._setup_ops.configure_default_user(
            actual_wsl_name, exe_name, "root"
        )
        if not config_result.get("success"):
            return config_result

        # Create the requested user
        await self._send_progress("creating_user", _("Creating user %s...") % username)
        user_result = await self._setup_ops.create_user(
            actual_wsl_name, username, password_hash
        )
        if not user_result.get("success"):
            return user_result

        # Enable systemd
        await self._send_progress("enabling_systemd", _("Enabling systemd..."))
        systemd_result = await self._setup_ops.enable_systemd(actual_wsl_name)
        if not systemd_result.get("success"):
            return systemd_result

        # Set hostname (use FQDN)
        await self._send_progress(
            "setting_hostname", _("Setting hostname to %s...") % fqdn_hostname
        )
        hostname_result = await self._setup_ops.set_hostname(
            actual_wsl_name, fqdn_hostname
        )
        if not hostname_result.get("success"):
            self.logger.warning(
                "Hostname configuration failed: %s", hostname_result.get("error")
            )

        # Set default user to created user
        await self._send_progress("setting_default_user", _("Setting default user..."))
        default_user_result = await self._setup_ops.configure_default_user(
            actual_wsl_name, exe_name, username
        )
        if not default_user_result.get("success"):
            return default_user_result

        return {"success": True}

    async def _install_and_configure_agent(
        self,
        actual_wsl_name: str,
        agent_install_commands: List[str],
        server_url: str,
        hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str,
    ) -> None:
        """Install and configure sysmanage-agent in WSL instance."""
        if agent_install_commands:
            await self._send_progress(
                "installing_agent", _("Installing sysmanage-agent...")
            )
            agent_result = await self._setup_ops.install_agent(
                actual_wsl_name, agent_install_commands
            )
            if not agent_result.get("success"):
                self.logger.warning(
                    "Agent installation failed: %s", agent_result.get("error")
                )

        if server_url:
            await self._send_progress(
                "configuring_agent", _("Configuring sysmanage-agent...")
            )
            config_agent_result = await self._setup_ops.configure_agent(
                actual_wsl_name,
                server_url,
                hostname,
                server_port,
                use_https,
                auto_approve_token,
            )
            if not config_agent_result.get("success"):
                self.logger.warning(
                    "Agent configuration failed: %s",
                    config_agent_result.get("error"),
                )

        await self._send_progress("starting_agent", _("Starting agent service..."))
        start_result = await self._setup_ops.start_agent_service(actual_wsl_name)
        if not start_result.get("success"):
            self.logger.warning(
                "Agent service start failed: %s", start_result.get("error")
            )

    async def create_wsl_instance(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        distribution: str,
        hostname: str,
        username: str,
        password_hash: str,
        server_url: str,
        agent_install_commands: List[str],
        listing_helper,
        server_port: int = 8443,
        use_https: bool = True,
        auto_approve_token: str = None,
    ) -> Dict[str, Any]:
        """
        Create a new WSL instance with the full installation flow.

        Args:
            distribution: WSL distribution identifier (e.g., 'Ubuntu-24.04')
            hostname: Hostname for the WSL instance
            username: Non-root username to create
            password_hash: Pre-hashed password (bcrypt) for the user
            server_url: URL for the sysmanage server
            agent_install_commands: Commands to install the agent
            listing_helper: ChildHostListing instance for checking existing instances
            server_port: Port for the sysmanage server (default 8443)
            use_https: Whether to use HTTPS for server connection (default True)

        Returns:
            Dict with success status and details
        """
        try:
            # Validate inputs
            validation = self._validate_wsl_inputs(
                distribution, hostname, username, password_hash
            )
            if not validation.get("success"):
                return validation

            # Derive FQDN hostname
            fqdn_hostname = self._setup_ops.get_fqdn_hostname(hostname, server_url)
            if fqdn_hostname != hostname:
                self.logger.info(
                    "Using FQDN hostname '%s' (user provided '%s')",
                    fqdn_hostname,
                    hostname,
                )

            # Check and enable WSL
            await self._send_progress("checking_wsl", _("Checking WSL status..."))
            wsl_result = await self._check_and_enable_wsl()
            if not wsl_result.get("success"):
                return wsl_result

            # Configure .wslconfig
            await self._send_progress(
                "configuring_wsl", _("Configuring WSL settings...")
            )
            await self._configure_wslconfig()

            # Check if distribution already exists
            await self._send_progress(
                "checking_existing", _("Checking for existing installation...")
            )
            if self._check_distribution_exists(distribution, listing_helper):
                return {
                    "success": False,
                    "error": _("Distribution '%s' is already installed") % distribution,
                }

            # Install the distribution
            await self._send_progress(
                "installing_distribution",
                _("Installing distribution %s...") % distribution,
            )
            install_result = await self._install_distribution(distribution)
            if not install_result.get("success"):
                return install_result

            actual_wsl_name = install_result.get("actual_name", distribution)
            if actual_wsl_name != distribution:
                self.logger.info(
                    "Using actual WSL name '%s' (requested '%s')",
                    actual_wsl_name,
                    distribution,
                )

            exe_name = self._setup_ops.get_executable_name(actual_wsl_name)

            # Set up user and systemd
            setup_result = await self._setup_wsl_user_and_systemd(
                actual_wsl_name, exe_name, username, password_hash, fqdn_hostname
            )
            if not setup_result.get("success"):
                return setup_result

            # Restart WSL to apply systemd
            await self._send_progress(
                "restarting_wsl", _("Restarting WSL to apply changes...")
            )
            restart_result = await self._setup_ops.restart_instance(actual_wsl_name)
            if not restart_result.get("success"):
                return restart_result

            # Install and configure agent
            await self._install_and_configure_agent(
                actual_wsl_name,
                agent_install_commands,
                server_url,
                hostname,
                server_port,
                use_https,
                auto_approve_token,
            )

            await self._send_progress("complete", _("Installation complete"))

            return {
                "success": True,
                "child_name": actual_wsl_name,
                "child_type": "wsl",
                "hostname": fqdn_hostname,
                "username": username,
                "message": _("WSL instance '%s' created successfully")
                % actual_wsl_name,
            }

        except Exception as error:
            self.logger.error(_("Error creating WSL instance: %s"), error)
            return {"success": False, "error": str(error)}

    async def _send_progress(self, step: str, message: str):
        """Send a progress update to the server."""
        try:
            if hasattr(self.agent, "send_message"):
                progress_message = self.agent.create_message(
                    "child_host_creation_progress",
                    {
                        "step": step,
                        "message": message,
                    },
                )
                await self.agent.send_message(progress_message)
        except Exception as error:
            self.logger.debug("Failed to send progress update: %s", error)

    def _decode_wsl_output(self, stdout: bytes, stderr: bytes) -> str:
        """
        Decode WSL command output which may be UTF-16LE encoded.

        wsl.exe outputs UTF-16LE on Windows, but subprocess with text=True
        expects UTF-8, resulting in garbled or empty output.

        Args:
            stdout: Raw stdout bytes
            stderr: Raw stderr bytes

        Returns:
            Combined decoded output as a string
        """
        combined = stdout + stderr
        if not combined:
            return ""

        # Try UTF-16LE first (what wsl.exe actually outputs)
        try:
            # Remove BOM if present
            if combined.startswith(b"\xff\xfe"):
                combined = combined[2:]
            decoded = combined.decode("utf-16-le")
            # Filter out null characters that may appear
            decoded = decoded.replace("\x00", "")
            if decoded.strip():
                return decoded
        except (UnicodeDecodeError, LookupError):
            pass

        # Fall back to UTF-8
        try:
            return combined.decode("utf-8")
        except UnicodeDecodeError:
            pass

        # Last resort: latin-1 (never fails)
        return combined.decode("latin-1")

    async def enable_wsl_internal(self) -> Dict[str, Any]:
        """
        Enable WSL on the system using wsl --install.

        Returns:
            Dict with success status and whether reboot is required
        """
        try:
            self.logger.info("Attempting to enable WSL")

            # Use wsl --install which enables all required features
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--install",
                "--no-distribution",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=300
                )  # 5 minutes timeout
            except asyncio.TimeoutError:
                proc.kill()
                return {"success": False, "error": _("WSL installation timed out")}

            # Decode the UTF-16LE output from wsl.exe
            output = self._decode_wsl_output(stdout, stderr).lower()

            # Check for reboot required error code
            if proc.returncode == 3010:
                self.logger.info("WSL install requires reboot (exit code 3010)")
                return {"success": True, "reboot_required": True}

            # Check output for reboot indicators
            if "reboot" in output or "restart" in output:
                self.logger.info("WSL install requires reboot (found in output)")
                return {"success": True, "reboot_required": True}

            if proc.returncode != 0:
                error_msg = output or "Unknown error"
                self.logger.error("WSL install failed: %s", error_msg)
                return {"success": False, "error": error_msg}

            # The install command returned 0, but we need to verify WSL actually works
            # wsl --install can return 0 even when Virtual Machine Platform isn't enabled
            self.logger.info("WSL install command completed, verifying status...")

            status_proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                status_stdout, status_stderr = await asyncio.wait_for(
                    status_proc.communicate(), timeout=30
                )
            except asyncio.TimeoutError:
                status_proc.kill()
                return {"success": False, "error": _("WSL status check timed out")}

            # Decode the UTF-16LE output from wsl.exe
            status_output = self._decode_wsl_output(
                status_stdout, status_stderr
            ).lower()
            self.logger.debug("WSL status output: %s", status_output[:500])

            # Check for indicators that WSL isn't fully enabled
            return self._check_wsl_status_output(
                status_output, status_stdout, status_stderr
            )

        except Exception as error:
            return {"success": False, "error": str(error)}

    def _check_wsl_status_output(
        self, status_output: str, status_stdout: bytes, status_stderr: bytes
    ) -> Dict[str, Any]:
        """Check WSL status output for enablement issues."""
        if "please enable" in status_output or "not supported" in status_output:
            self.logger.warning(
                "WSL install completed but additional setup required: %s",
                status_stdout or status_stderr,
            )

            # Check if it's an actual BIOS virtualization issue
            if "bios" in status_output and "virtualization" in status_output:
                return {
                    "success": False,
                    "error": _(
                        "WSL requires virtualization to be enabled in BIOS/UEFI. "
                        "Please enable virtualization in your system's BIOS settings "
                        "and restart the computer."
                    ),
                    "requires_bios_change": True,
                }

            return {"success": True, "reboot_required": True}

        self.logger.info("WSL enabled and verified successfully")
        return {"success": True, "reboot_required": False}

    def _check_distribution_exists(self, distribution: str, listing_helper) -> bool:
        """
        Check if a WSL distribution is already installed.

        Args:
            distribution: Distribution name to check
            listing_helper: ChildHostListing instance

        Returns:
            True if distribution exists, False otherwise
        """
        try:
            instances = listing_helper.list_wsl_instances()
            for instance in instances:
                if instance.get("child_name", "").lower() == distribution.lower():
                    return True
            return False
        except Exception:
            return False

    async def _install_distribution(self, distribution: str) -> Dict[str, Any]:
        """
        Install a WSL distribution non-interactively.

        Args:
            distribution: Distribution identifier (e.g., 'Ubuntu-24.04')

        Returns:
            Dict with success status and actual_name (the WSL internal name)
        """
        try:
            self.logger.info("Installing WSL distribution: %s", distribution)

            # Use --no-launch to prevent interactive first run
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--install",
                "-d",
                distribution,
                "--no-launch",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=1800
                )  # 30 minutes timeout for large distributions
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "success": False,
                    "error": _("Distribution installation timed out"),
                }

            # Decode the UTF-16LE output from wsl.exe
            output = self._decode_wsl_output(stdout, stderr)

            if proc.returncode == 0:
                self.logger.info("Distribution %s installed successfully", distribution)
                # Detect the actual WSL name (may differ from install name)
                actual_name = self._detect_actual_wsl_name(distribution)
                return {"success": True, "actual_name": actual_name}

            error_msg = output or "Installation failed"
            self.logger.error("Distribution installation failed: %s", error_msg)
            return {"success": False, "error": error_msg}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def _detect_actual_wsl_name(self, requested_distribution: str) -> str:
        """
        Detect the actual WSL distribution name after installation.

        WSL may use different internal names than the install identifier.
        For example, 'Fedora' becomes 'FedoraLinux-43'.

        Args:
            requested_distribution: The distribution name we requested to install

        Returns:
            The actual WSL distribution name, or the requested name if detection fails
        """
        try:
            # Get the list of installed distributions
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-l", "-v"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=self._get_creationflags(),
            )

            output = self._decode_wsl_output(result.stdout, result.stderr)
            if not output:
                return requested_distribution

            return self._parse_wsl_list_output(output, requested_distribution)

        except Exception as error:
            self.logger.warning(
                "Error detecting actual WSL name: %s, using requested name: %s",
                error,
                requested_distribution,
            )
            return requested_distribution

    def _parse_wsl_list_output(self, output: str, requested_distribution: str) -> str:
        """Parse wsl -l -v output to find matching distribution name."""
        lines = output.strip().split("\n")
        if len(lines) < 2:
            return requested_distribution

        requested_lower = requested_distribution.lower()
        for line in lines[1:]:
            distro_name = self._extract_distro_name_from_line(line)
            if not distro_name:
                continue

            match_result = self._check_distro_name_match(
                distro_name, requested_lower, requested_distribution
            )
            if match_result:
                return match_result

        self.logger.warning(
            "Could not detect actual WSL name for %s, using requested name",
            requested_distribution,
        )
        return requested_distribution

    def _extract_distro_name_from_line(self, line: str) -> str:
        """Extract distribution name from a wsl -l -v output line."""
        line = line.strip()
        if not line:
            return ""

        # Remove asterisk for default
        if line.startswith("*"):
            line = line[1:].strip()

        # Parse the name (first column)
        parts = line.split()
        return parts[0] if parts else ""

    def _check_distro_name_match(
        self, distro_name: str, requested_lower: str, requested_distribution: str
    ) -> str:
        """Check if distribution name matches the requested distribution."""
        distro_lower = distro_name.lower()

        # Check for exact match first
        if distro_lower == requested_lower:
            return distro_name

        # Check for partial match (e.g., "Fedora" in "FedoraLinux-43")
        # or base name match (e.g., "fedora" in "fedoralinux-43")
        is_partial_match = requested_lower in distro_lower
        is_base_match = distro_lower.startswith(requested_lower.replace("-", ""))
        if is_partial_match or is_base_match:
            self.logger.info(
                "WSL distribution name mapping: %s -> %s",
                requested_distribution,
                distro_name,
            )
            return distro_name

        return ""

    async def enable_wsl(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enable WSL on a Windows system.

        This is called when the user clicks "Enable WSL" in the UI.

        Args:
            _parameters: Optional parameters (unused)

        Returns:
            Dict with success status and whether reboot is required
        """
        self.logger.info(_("Enabling WSL on this system"))

        result = await self.enable_wsl_internal()

        if result.get("success") and result.get("reboot_required"):
            # Notify server that reboot is required
            try:
                if hasattr(self.agent, "send_message"):
                    reboot_message = self.agent.create_message(
                        "reboot_status_update",
                        {
                            "reboot_required": True,
                            "reboot_required_reason": "WSL feature enablement pending",
                        },
                    )
                    await self.agent.send_message(reboot_message)
            except Exception as error:
                self.logger.warning("Failed to send reboot status update: %s", error)

        return result

    # Delegate control operations to sub-module
    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Start a stopped WSL instance."""
        return await self._control_ops.start_child_host(parameters)

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Stop a running WSL instance."""
        return await self._control_ops.stop_child_host(parameters)

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a WSL instance (stop then start)."""
        return await self._control_ops.restart_child_host(parameters)

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete (unregister) a WSL instance."""
        return await self._control_ops.delete_child_host(parameters)
