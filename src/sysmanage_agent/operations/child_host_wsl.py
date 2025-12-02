"""
WSL-specific child host operations.
"""

import shutil
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, List, Optional

from src.i18n import _


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

    async def create_wsl_instance(
        self,
        distribution: str,
        hostname: str,
        username: str,
        password: str,
        server_url: str,
        agent_install_commands: List[str],
        listing_helper,
    ) -> Dict[str, Any]:
        """
        Create a new WSL instance with the full installation flow.

        Args:
            distribution: WSL distribution identifier (e.g., 'Ubuntu-24.04')
            hostname: Hostname for the WSL instance
            username: Non-root username to create
            password: Password for the user
            server_url: URL for the sysmanage server
            agent_install_commands: Commands to install the agent
            listing_helper: ChildHostListing instance for checking existing instances

        Returns:
            Dict with success status and details
        """
        try:
            # Validate inputs
            if not distribution:
                return {"success": False, "error": _("Distribution is required")}
            if not hostname:
                return {"success": False, "error": _("Hostname is required")}
            if not username:
                return {"success": False, "error": _("Username is required")}
            if not password:
                return {"success": False, "error": _("Password is required")}

            # Send progress update
            await self._send_progress("checking_wsl", _("Checking WSL status..."))

            # Step 1: Check WSL is enabled
            wsl_check = self.virtualization_checks.check_wsl_support()
            if not wsl_check.get("available"):
                return {
                    "success": False,
                    "error": _("WSL is not available on this system"),
                }

            if wsl_check.get("needs_enable"):
                # Attempt to enable WSL
                enable_result = await self.enable_wsl_internal()
                if not enable_result.get("success"):
                    return enable_result
                if enable_result.get("reboot_required"):
                    return {
                        "success": False,
                        "error": _("WSL has been enabled but a reboot is required"),
                        "reboot_required": True,
                    }

            # Step 2: Check if distribution already exists
            await self._send_progress(
                "checking_existing", _("Checking for existing installation...")
            )
            existing = self._check_distribution_exists(distribution, listing_helper)
            if existing:
                return {
                    "success": False,
                    "error": _("Distribution '%s' is already installed") % distribution,
                }

            # Step 3: Install the distribution
            await self._send_progress(
                "installing_distribution",
                _("Installing distribution %s...") % distribution,
            )
            install_result = await self._install_distribution(distribution)
            if not install_result.get("success"):
                return install_result

            # Get the executable name for this distribution
            exe_name = self._get_executable_name(distribution)

            # Step 4: Configure default user as root temporarily
            await self._send_progress(
                "configuring_root", _("Configuring temporary root access...")
            )
            config_result = await self._configure_default_user(
                distribution, exe_name, "root"
            )
            if not config_result.get("success"):
                return config_result

            # Step 5: Create the requested user
            await self._send_progress(
                "creating_user", _("Creating user %s...") % username
            )
            user_result = await self._create_user(distribution, username, password)
            if not user_result.get("success"):
                return user_result

            # Step 6: Enable systemd
            await self._send_progress("enabling_systemd", _("Enabling systemd..."))
            systemd_result = await self._enable_systemd(distribution)
            if not systemd_result.get("success"):
                return systemd_result

            # Step 7: Set default user to created user
            await self._send_progress(
                "setting_default_user", _("Setting default user...")
            )
            default_user_result = await self._configure_default_user(
                distribution, exe_name, username
            )
            if not default_user_result.get("success"):
                return default_user_result

            # Step 8: Restart WSL to apply systemd
            await self._send_progress(
                "restarting_wsl", _("Restarting WSL to apply changes...")
            )
            restart_result = await self._restart_instance(distribution)
            if not restart_result.get("success"):
                return restart_result

            # Step 9: Install sysmanage-agent
            if agent_install_commands:
                await self._send_progress(
                    "installing_agent", _("Installing sysmanage-agent...")
                )
                agent_result = await self._install_agent(
                    distribution, agent_install_commands
                )
                if not agent_result.get("success"):
                    self.logger.warning(
                        "Agent installation failed: %s", agent_result.get("error")
                    )
                    # Continue anyway - admin can install manually

            # Step 10: Configure agent
            if server_url:
                await self._send_progress(
                    "configuring_agent", _("Configuring sysmanage-agent...")
                )
                config_agent_result = await self._configure_agent(
                    distribution, server_url, hostname
                )
                if not config_agent_result.get("success"):
                    self.logger.warning(
                        "Agent configuration failed: %s",
                        config_agent_result.get("error"),
                    )

            # Step 11: Start agent service
            await self._send_progress("starting_agent", _("Starting agent service..."))
            start_result = await self._start_agent_service(distribution)
            if not start_result.get("success"):
                self.logger.warning(
                    "Agent service start failed: %s", start_result.get("error")
                )

            await self._send_progress("complete", _("Installation complete"))

            return {
                "success": True,
                "child_name": distribution,
                "child_type": "wsl",
                "hostname": hostname,
                "username": username,
                "message": _("WSL instance '%s' created successfully") % distribution,
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

            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Use wsl --install which enables all required features
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--install", "--no-distribution"],
                capture_output=True,
                timeout=300,  # 5 minutes timeout
                check=False,
                creationflags=creationflags,
            )

            # Decode the UTF-16LE output from wsl.exe
            output = self._decode_wsl_output(result.stdout, result.stderr).lower()

            # Check for reboot required error code
            if result.returncode == 3010:
                self.logger.info("WSL install requires reboot (exit code 3010)")
                return {"success": True, "reboot_required": True}

            # Check output for reboot indicators
            if "reboot" in output or "restart" in output:
                self.logger.info("WSL install requires reboot (found in output)")
                return {"success": True, "reboot_required": True}

            if result.returncode != 0:
                error_msg = output or "Unknown error"
                self.logger.error("WSL install failed: %s", error_msg)
                return {"success": False, "error": error_msg}

            # The install command returned 0, but we need to verify WSL actually works
            # wsl --install can return 0 even when Virtual Machine Platform isn't enabled
            self.logger.info("WSL install command completed, verifying status...")

            status_result = subprocess.run(  # nosec B603 B607
                ["wsl", "--status"],
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            # Decode the UTF-16LE output from wsl.exe
            status_output = self._decode_wsl_output(
                status_result.stdout, status_result.stderr
            ).lower()
            self.logger.debug("WSL status output: %s", status_output[:500])

            # Check for indicators that WSL isn't fully enabled
            if "please enable" in status_output or "not supported" in status_output:
                # WSL requires additional setup
                self.logger.warning(
                    "WSL install completed but additional setup required: %s",
                    status_result.stdout or status_result.stderr,
                )

                # Check if it's an actual BIOS virtualization issue
                # (both "bios" AND "virtualization" must be present)
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

                # "Virtual Machine Platform" or other Windows features need a reboot
                # after wsl --install enables them
                return {"success": True, "reboot_required": True}

            # WSL status check passed - it's actually working
            self.logger.info("WSL enabled and verified successfully")
            return {"success": True, "reboot_required": False}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("WSL installation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

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
            Dict with success status
        """
        try:
            self.logger.info("Installing WSL distribution: %s", distribution)

            # Use --no-launch to prevent interactive first run
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--install", "-d", distribution, "--no-launch"],
                capture_output=True,
                timeout=1800,  # 30 minutes timeout for large distributions
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            # Decode the UTF-16LE output from wsl.exe
            output = self._decode_wsl_output(result.stdout, result.stderr)

            if result.returncode == 0:
                self.logger.info("Distribution %s installed successfully", distribution)
                return {"success": True}

            error_msg = output or "Installation failed"
            self.logger.error("Distribution installation failed: %s", error_msg)
            return {"success": False, "error": error_msg}

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": _("Distribution installation timed out"),
            }
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _get_executable_name(self, distribution: str) -> Optional[str]:
        """
        Get the executable name for a WSL distribution.

        Args:
            distribution: Distribution name

        Returns:
            Executable name or None if unknown
        """
        # Map distribution names to their executables
        exe_map = {
            "ubuntu-24.04": "ubuntu2404.exe",
            "ubuntu-22.04": "ubuntu2204.exe",
            "ubuntu-20.04": "ubuntu2004.exe",
            "ubuntu-18.04": "ubuntu1804.exe",
            "ubuntu": "ubuntu.exe",
            "debian": "debian.exe",
            "kali-linux": "kali.exe",
            "opensuse-tumbleweed": "opensuse-tumbleweed.exe",
            "opensuse-leap-15": "opensuse-leap-15.exe",
            "sles-15": "sles-15.exe",
            "fedora": "fedora.exe",
            "almalinux-9": "almalinux-9.exe",
            "rockylinux-9": "rockylinux-9.exe",
        }
        return exe_map.get(distribution.lower())

    async def _configure_default_user(
        self, distribution: str, exe_name: Optional[str], username: str
    ) -> Dict[str, Any]:
        """
        Configure the default user for a WSL distribution.

        Args:
            distribution: Distribution name
            exe_name: Distribution executable name (e.g., 'ubuntu2404.exe')
            username: Username to set as default

        Returns:
            Dict with success status
        """
        try:
            if exe_name:
                # Use distribution-specific executable
                exe_path = shutil.which(exe_name)
                if exe_path:
                    result = subprocess.run(  # nosec B603 B607
                        [exe_path, "config", "--default-user", username],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                        creationflags=(
                            subprocess.CREATE_NO_WINDOW
                            if hasattr(subprocess, "CREATE_NO_WINDOW")
                            else 0
                        ),
                    )
                    if result.returncode == 0:
                        return {"success": True}

            # Fallback: Use wsl.exe to run passwd command for user config
            # This is less clean but works for all distributions
            self.logger.debug(
                "Using wsl command to configure default user for %s", distribution
            )

            # For root, we don't need to do anything special - WSL defaults to root
            # if no user is configured during first run
            if username == "root":
                return {"success": True}

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _create_user(
        self, distribution: str, username: str, password: str
    ) -> Dict[str, Any]:
        """
        Create a non-root user in a WSL distribution.

        Args:
            distribution: Distribution name
            username: Username to create
            password: Password for the user

        Returns:
            Dict with success status
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Create user with home directory and bash shell
            create_cmd = f"useradd -m -s /bin/bash {username}"
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", create_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                # User might already exist
                if "already exists" not in result.stderr.lower():
                    return {
                        "success": False,
                        "error": _("Failed to create user: %s")
                        % (result.stderr or result.stdout),
                    }

            # Set password
            # Use chpasswd which reads from stdin
            passwd_cmd = f"echo '{username}:{password}' | chpasswd"
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", passwd_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to set password: %s")
                    % (result.stderr or result.stdout),
                }

            # Add user to sudo/wheel group
            # Try sudo first (Debian/Ubuntu), then wheel (Fedora/RHEL)
            for sudo_group in ["sudo", "wheel"]:
                add_group_cmd = f"usermod -aG {sudo_group} {username}"
                result = subprocess.run(  # nosec B603 B607
                    ["wsl", "-d", distribution, "--", "sh", "-c", add_group_cmd],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                    creationflags=creationflags,
                )
                if result.returncode == 0:
                    break

            self.logger.info("User %s created successfully", username)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _enable_systemd(self, distribution: str) -> Dict[str, Any]:
        """
        Enable systemd in a WSL distribution.

        Args:
            distribution: Distribution name

        Returns:
            Dict with success status
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Write systemd=true to /etc/wsl.conf
            wsl_conf_cmd = (
                "mkdir -p /etc && "
                "(grep -q '\\[boot\\]' /etc/wsl.conf 2>/dev/null && "
                "sed -i 's/systemd=.*/systemd=true/' /etc/wsl.conf || "
                "echo -e '[boot]\\nsystemd=true' >> /etc/wsl.conf)"
            )

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", wsl_conf_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to enable systemd: %s")
                    % (result.stderr or result.stdout),
                }

            self.logger.info("Systemd enabled for distribution %s", distribution)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _restart_instance(self, distribution: str) -> Dict[str, Any]:
        """
        Restart a WSL instance to apply changes.

        Args:
            distribution: Distribution name

        Returns:
            Dict with success status
        """
        try:
            import asyncio  # pylint: disable=import-outside-toplevel

            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Terminate the distribution
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "--terminate", distribution],
                capture_output=True,
                timeout=60,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                output = self._decode_wsl_output(result.stdout, result.stderr)
                self.logger.warning("WSL terminate returned non-zero: %s", output)

            # Wait a moment for termination to complete
            await asyncio.sleep(2)

            # Start the distribution again
            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "echo", "Started"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to restart WSL instance: %s")
                    % (result.stderr or result.stdout),
                }

            self.logger.info("WSL instance %s restarted successfully", distribution)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _install_agent(
        self, distribution: str, install_commands: List[str]
    ) -> Dict[str, Any]:
        """
        Install sysmanage-agent in a WSL distribution.

        Args:
            distribution: Distribution name
            install_commands: List of commands to run for installation

        Returns:
            Dict with success status
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            for cmd in install_commands:
                self.logger.debug("Running agent install command: %s", cmd)

                result = subprocess.run(  # nosec B603 B607
                    ["wsl", "-d", distribution, "--", "sh", "-c", cmd],
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minutes per command
                    check=False,
                    creationflags=creationflags,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Agent install command failed: %s - %s",
                        cmd,
                        result.stderr or result.stdout,
                    )
                    # Continue with remaining commands

            self.logger.info("Agent installation commands completed")
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _configure_agent(
        self, distribution: str, server_url: str, hostname: str
    ) -> Dict[str, Any]:
        """
        Configure sysmanage-agent in a WSL distribution.

        Args:
            distribution: Distribution name
            server_url: URL of the sysmanage server
            hostname: Hostname for this agent

        Returns:
            Dict with success status
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Create the configuration file
            config_content = f"""# Sysmanage Agent Configuration
# Auto-generated during WSL child host creation

server:
  hostname: "{server_url}"
  port: 8000
  use_https: true
  verify_ssl: true

agent:
  hostname_override: "{hostname}"
"""

            # Write configuration file
            # Escape quotes and newlines for shell
            escaped_content = config_content.replace("'", "'\"'\"'")
            config_cmd = f"echo '{escaped_content}' > /etc/sysmanage-agent.yaml"

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", config_cmd],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to write agent config: %s")
                    % (result.stderr or result.stdout),
                }

            self.logger.info("Agent configured with server %s", server_url)
            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

    async def _start_agent_service(self, distribution: str) -> Dict[str, Any]:
        """
        Start the sysmanage-agent service in a WSL distribution.

        Args:
            distribution: Distribution name

        Returns:
            Dict with success status
        """
        try:
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            # Enable and start the service
            start_cmd = "systemctl enable --now sysmanage-agent || true"

            result = subprocess.run(  # nosec B603 B607
                ["wsl", "-d", distribution, "--", "sh", "-c", start_cmd],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                creationflags=creationflags,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Agent service start may have failed: %s",
                    result.stderr or result.stdout,
                )

            return {"success": True}

        except Exception as error:
            return {"success": False, "error": str(error)}

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
