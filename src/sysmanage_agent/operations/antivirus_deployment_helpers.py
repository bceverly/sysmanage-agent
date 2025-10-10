"""
Helper functions for ClamAV deployment across different platforms.

This module contains platform-specific deployment logic extracted from
the massive deploy_antivirus() function to reduce complexity.
"""

import asyncio
import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def _get_brew_user():
    """Get the user that owns the Homebrew installation."""
    import pwd  # pylint: disable=import-outside-toplevel

    # Check both possible Homebrew locations
    brew_dirs = ["/opt/homebrew", "/usr/local/Homebrew"]
    for brew_dir in brew_dirs:
        if os.path.exists(brew_dir):
            try:
                stat_info = os.stat(brew_dir)
                return pwd.getpwuid(stat_info.st_uid).pw_name
            except (OSError, KeyError):
                continue

    # Fallback to SUDO_USER if available
    return os.environ.get("SUDO_USER")


async def configure_config_file(sample_path: str, target_path: str, sed_patterns: list):
    """Configure a ClamAV config file from sample using sed."""
    if not os.path.exists(sample_path):
        return

    logger.info("Creating %s from sample", target_path)
    process = await asyncio.create_subprocess_exec(
        "cp",
        sample_path,
        target_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.communicate()

    # Apply sed patterns
    for pattern_data in sed_patterns:
        if isinstance(pattern_data, tuple):
            pattern, extra_arg = pattern_data
        else:
            pattern, extra_arg = pattern_data, ""

        args = ["sed", "-i"]
        if extra_arg:
            args.append(extra_arg)
        args.extend(["-e", pattern, target_path])

        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    logger.info("%s configured", target_path)


async def wait_for_virus_database(db_paths: list, timeout: int = 30):
    """Wait for virus database to be downloaded."""
    logger.info("Waiting for virus database download")
    database_ready = False
    for _ in range(timeout):
        if any(os.path.exists(path) for path in db_paths):
            logger.info("Virus database downloaded successfully")
            database_ready = True
            break
        await asyncio.sleep(1)

    if not database_ready:
        logger.warning(
            "Virus database not downloaded after %d seconds, proceeding anyway", timeout
        )


async def deploy_clamav_macos(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on macOS via Homebrew."""
    logger.info("Detected macOS system, installing ClamAV via Homebrew")

    # Install ClamAV via Homebrew
    logger.info("Installing clamav")
    result = update_detector.install_package("clamav", "auto")
    logger.info("clamav installation result: %s", result)

    # Determine the correct config path based on architecture
    is_arm = os.path.exists("/opt/homebrew")
    config_base = "/opt/homebrew/etc/clamav" if is_arm else "/usr/local/etc/clamav"
    log_dir = "/opt/homebrew/var/log/clamav" if is_arm else "/usr/local/var/log/clamav"
    db_dir = "/opt/homebrew/var/lib/clamav" if is_arm else "/usr/local/var/lib/clamav"

    logger.info("Configuring ClamAV on macOS")

    # Create directories
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(db_dir, exist_ok=True)

    # Configure freshclam.conf
    await configure_config_file(
        f"{config_base}/freshclam.conf.sample",
        f"{config_base}/freshclam.conf",
        [("s/^Example/#Example/", "")],
    )

    # Configure clamd.conf
    clamd_conf = f"{config_base}/clamd.conf"
    clamd_sample = f"{config_base}/clamd.conf.sample"
    if os.path.exists(clamd_sample):
        logger.info("Creating clamd.conf from sample")
        process = await asyncio.create_subprocess_exec(
            "cp",
            clamd_sample,
            clamd_conf,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Apply multiple sed commands
        sed_commands = [
            "s/^Example/#Example/",
            f"s|^#LogFile.*|LogFile {log_dir}/clamd.log|",
            f"s|^#PidFile.*|PidFile {log_dir}/clamd.pid|",
            f"s|^#DatabaseDirectory.*|DatabaseDirectory {db_dir}|",
            f"s|^#LocalSocket.*|LocalSocket {log_dir}/clamd.sock|",
        ]

        for sed_cmd in sed_commands:
            process = await asyncio.create_subprocess_exec(
                "sed",
                "-i",
                "",
                "-e",
                sed_cmd,
                clamd_conf,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

        logger.info("clamd.conf configured")

    # Update virus definitions
    logger.info("Updating virus definitions with freshclam")
    freshclam_cmd = (
        "/opt/homebrew/bin/freshclam" if is_arm else "/usr/local/bin/freshclam"
    )

    brew_user = _get_brew_user() if os.geteuid() == 0 else None

    if brew_user:
        logger.info("Running freshclam as user: %s", brew_user)
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "-u",
            brew_user,
            freshclam_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    else:
        process = await asyncio.create_subprocess_exec(
            freshclam_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("Virus definitions updated successfully")
    else:
        logger.warning(
            "Failed to update virus definitions: %s",
            stderr.decode() if stderr else "unknown error",
        )

    # Start service
    logger.info("Starting ClamAV service via brew services")
    brew_cmd = "/opt/homebrew/bin/brew" if is_arm else "/usr/local/bin/brew"

    process = await asyncio.create_subprocess_exec(
        "sudo",
        brew_cmd,
        "services",
        "start",
        "clamav",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("ClamAV service started successfully")
    else:
        logger.warning(
            "Failed to start ClamAV service: %s",
            stderr.decode() if stderr else "unknown error",
        )

    await asyncio.sleep(2)
    return True, None, None, "ClamAV installed successfully on macOS"


async def deploy_clamav_netbsd(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on NetBSD."""
    logger.info("Detected NetBSD system, installing ClamAV package")

    result = update_detector.install_package("clamav", "auto")
    logger.info("clamav installation result: %s", result)

    logger.info("Configuring ClamAV on NetBSD")

    # Configure freshclam.conf
    await configure_config_file(
        "/usr/pkg/etc/freshclam.conf.sample",
        "/usr/pkg/etc/freshclam.conf",
        [("s/^Example/#Example/", "")],
    )

    # Configure clamd.conf
    await configure_config_file(
        "/usr/pkg/etc/clamd.conf.sample",
        "/usr/pkg/etc/clamd.conf",
        [("s/^Example/#Example/", ""), ("s/^#LocalSocket /LocalSocket /", "")],
    )

    # Copy rc.d scripts
    logger.info("Copying rc.d scripts to /etc/rc.d/")
    for script in ["clamd", "freshclamd"]:
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "cp",
            f"/usr/pkg/share/examples/rc.d/{script}",
            "/etc/rc.d/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    # Enable services in rc.conf
    logger.info("Enabling ClamAV services in rc.conf")
    for service in ["freshclamd", "clamd"]:
        process = await asyncio.create_subprocess_exec(
            "sh",
            "-c",
            f"grep -q '^{service}=' /etc/rc.conf 2>/dev/null || echo '{service}=YES' | sudo tee -a /etc/rc.conf > /dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    # Start freshclamd first
    logger.info("Starting freshclamd service")
    process = await asyncio.create_subprocess_exec(
        "sudo",
        "service",
        "freshclamd",
        "start",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("freshclamd service started successfully")
    else:
        logger.warning(
            "Failed to start freshclamd: %s",
            stderr.decode() if stderr else "unknown error",
        )

    # Wait for database
    await wait_for_virus_database(["/var/clamav/main.cvd", "/var/clamav/main.cld"])

    # Start clamd
    logger.info("Starting clamd service")
    process = await asyncio.create_subprocess_exec(
        "sudo",
        "service",
        "clamd",
        "start",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("clamd service started successfully")
    else:
        logger.warning(
            "Failed to start clamd: %s",
            stderr.decode() if stderr else "unknown error",
        )

    await asyncio.sleep(2)
    return True, None, None, "ClamAV installed successfully on NetBSD"


async def deploy_clamav_freebsd(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on FreeBSD."""
    logger.info("Detected FreeBSD system, installing ClamAV package")

    result = update_detector.install_package("clamav", "auto")
    logger.info("clamav installation result: %s", result)

    logger.info("Configuring ClamAV on FreeBSD")

    # Configure freshclam.conf
    await configure_config_file(
        "/usr/local/etc/freshclam.conf.sample",
        "/usr/local/etc/freshclam.conf",
        [("s/^Example/#Example/", "")],
    )

    # Configure clamd.conf
    await configure_config_file(
        "/usr/local/etc/clamd.conf.sample",
        "/usr/local/etc/clamd.conf",
        [("s/^Example/#Example/", ""), ("s/^#LocalSocket /LocalSocket /", "")],
    )

    # Enable services
    logger.info("Enabling ClamAV services in rc.conf")
    for service in ["clamav_freshclam_enable=YES", "clamav_clamd_enable=YES"]:
        process = await asyncio.create_subprocess_exec(
            "sysrc",
            service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

    # Start freshclam first
    logger.info("Starting clamav_freshclam service")
    process = await asyncio.create_subprocess_exec(
        "service",
        "clamav_freshclam",
        "start",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("clamav_freshclam service started successfully")
    else:
        logger.warning(
            "Failed to start clamav_freshclam: %s",
            stderr.decode() if stderr else "unknown error",
        )

    # Wait for database
    await wait_for_virus_database(
        ["/var/db/clamav/main.cvd", "/var/db/clamav/main.cld"]
    )

    # Start clamd
    logger.info("Starting clamav_clamd service")
    process = await asyncio.create_subprocess_exec(
        "service",
        "clamav_clamd",
        "start",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("clamav_clamd service started successfully")
    else:
        logger.warning(
            "Failed to start clamav_clamd: %s",
            stderr.decode() if stderr else "unknown error",
        )

    await asyncio.sleep(2)
    return True, None, None, "ClamAV installed successfully on FreeBSD"


async def deploy_clamav_openbsd(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on OpenBSD."""
    logger.info("Detected OpenBSD system, installing ClamAV package")

    result = update_detector.install_package("clamav", "auto")
    logger.info("clamav installation result: %s", result)

    logger.info("Configuring ClamAV on OpenBSD")

    # Configure freshclam.conf
    await configure_config_file(
        "/usr/local/share/examples/clamav/freshclam.conf.sample",
        "/etc/freshclam.conf",
        [("s/^Example/#Example/",)],
    )

    # Configure clamd.conf
    clamd_sample = "/usr/local/share/examples/clamav/clamd.conf.sample"
    clamd_conf = "/etc/clamd.conf"
    if os.path.exists(clamd_sample):
        logger.info("Creating clamd.conf from sample")
        process = await asyncio.create_subprocess_exec(
            "cp",
            clamd_sample,
            clamd_conf,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Multiple sed edits
        process = await asyncio.create_subprocess_exec(
            "sed",
            "-i",
            "-e",
            "s/^Example/#Example/",
            "-e",
            "s/^#LocalSocket /LocalSocket /",
            "-e",
            "s|/run/clamav/|/var/run/clamav/|g",
            clamd_conf,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        logger.info("clamd.conf configured")

    # Create runtime directory
    logger.info("Creating runtime directories for ClamAV")
    clamav_run_dir = "/var/run/clamav"
    if not os.path.exists(clamav_run_dir):
        process = await asyncio.create_subprocess_exec(
            "mkdir",
            "-p",
            clamav_run_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        process = await asyncio.create_subprocess_exec(
            "chown",
            "_clamav:_clamav",
            clamav_run_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()
        logger.info("Created and configured /var/run/clamav directory")

    # Enable and start freshclam
    logger.info("Enabling and starting freshclam service")
    process = await asyncio.create_subprocess_exec(
        "rcctl",
        "enable",
        "freshclam",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.communicate()

    process = await asyncio.create_subprocess_exec(
        "rcctl",
        "start",
        "freshclam",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("freshclam service enabled and started successfully")
    else:
        logger.warning(
            "Failed to start freshclam: %s",
            stderr.decode() if stderr else "unknown error",
        )

    # Wait for database
    await wait_for_virus_database(
        ["/var/db/clamav/main.cvd", "/var/db/clamav/main.cld"]
    )

    # Enable and start clamd
    logger.info("Enabling and starting clamd service")
    process = await asyncio.create_subprocess_exec(
        "rcctl",
        "enable",
        "clamd",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.communicate()

    process = await asyncio.create_subprocess_exec(
        "rcctl",
        "start",
        "clamd",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("clamd service enabled and started successfully")
    else:
        logger.warning(
            "Failed to start clamd: %s",
            stderr.decode() if stderr else "unknown error",
        )

    await asyncio.sleep(2)
    return True, None, None, "ClamAV installed successfully on OpenBSD"


async def deploy_clamav_opensuse(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on openSUSE."""
    logger.info("Detected openSUSE system, installing ClamAV packages")

    packages = ["clamav", "clamav_freshclam", "clamav-daemon"]
    for pkg in packages:
        logger.info("Installing %s", pkg)
        result = update_detector.install_package(pkg, "auto")
        logger.info("%s installation result: %s", pkg, result)

    # Enable and start freshclam
    logger.info("Enabling and starting freshclam service")
    process = await asyncio.create_subprocess_exec(
        "systemctl",
        "enable",
        "--now",
        "freshclam.service",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("freshclam service enabled and started successfully")
    else:
        logger.warning(
            "Failed to enable/start freshclam: %s",
            stderr.decode() if stderr else "unknown error",
        )

    # Enable and start clamd
    service_name = "clamd.service"
    logger.info("Enabling and starting service: %s", service_name)
    process = await asyncio.create_subprocess_exec(
        "systemctl",
        "enable",
        "--now",
        service_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    if process.returncode == 0:
        logger.info("Service %s enabled and started successfully", service_name)
        await asyncio.sleep(2)
    else:
        logger.warning(
            "Failed to enable/start service %s: %s",
            service_name,
            stderr.decode() if stderr else "unknown error",
        )

    return True, None, None, "ClamAV installed successfully on openSUSE"


async def deploy_clamav_rhel(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on RHEL/CentOS."""
    logger.info(
        "Detected RHEL/CentOS system, enabling EPEL and installing ClamAV packages"
    )

    # Enable EPEL
    epel_result = update_detector.install_package("epel-release", "auto")
    logger.info("EPEL installation result: %s", epel_result)

    # Install ClamAV packages
    packages = ["clamav", "clamd", "clamav-update"]
    for pkg in packages:
        logger.info("Installing %s", pkg)
        result = update_detector.install_package(pkg, "auto")
        logger.info("%s installation result: %s", pkg, result)

    # Update virus definitions
    logger.info("Updating virus definitions with freshclam")
    process = await asyncio.create_subprocess_exec(
        "freshclam",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        logger.info("Virus definitions updated successfully")
    else:
        logger.warning(
            "Failed to update virus definitions: %s",
            stderr.decode() if stderr else "unknown error",
        )

    # Configure clamd@scan
    config_file = "/etc/clamd.d/scan.conf"
    logger.info("Configuring %s", config_file)

    with open(config_file, "r", encoding="utf-8") as file_handle:
        config_content = file_handle.read()

    config_content = config_content.replace("#Example", "# Example").replace(
        "#LocalSocket /run/clamd.scan/clamd.sock",
        "LocalSocket /run/clamd.scan/clamd.sock",
    )

    with open(config_file, "w", encoding="utf-8") as file_handle:
        file_handle.write(config_content)

    logger.info("Configuration updated successfully")

    # Enable and start service
    service_name = "clamd@scan"
    logger.info("Enabling and starting service: %s", service_name)
    process = await asyncio.create_subprocess_exec(
        "systemctl",
        "enable",
        "--now",
        service_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()

    if process.returncode == 0:
        logger.info("Service %s enabled and started successfully", service_name)
        await asyncio.sleep(2)
    else:
        logger.warning(
            "Failed to enable/start service %s: %s",
            service_name,
            stderr.decode() if stderr else "unknown error",
        )

    return True, None, None, "ClamAV installed successfully on RHEL/CentOS"


async def deploy_clamav_windows(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on Windows via Chocolatey."""
    logger.info("Detected Windows system, installing ClamAV via Chocolatey")

    # Use clamwin package which includes ClamAV engine for Windows
    package_to_install = "clamwin"

    logger.info("Installing %s", package_to_install)
    result = update_detector.install_package(package_to_install, "auto")
    logger.info("%s installation result: %s", package_to_install, result)

    # Determine success based on result
    success = isinstance(result, dict) and result.get("success", False)
    error_message = result.get("error") if isinstance(result, dict) else None

    if not success:
        return False, error_message or "Installation failed", None, str(result)

    logger.info("Configuring ClamAV on Windows")

    # Common installation paths
    common_paths = [
        "C:\\Program Files\\ClamWin\\bin",
        "C:\\Program Files (x86)\\ClamWin\\bin",
        "C:\\Program Files\\ClamAV",
        "C:\\Program Files (x86)\\ClamAV",
        "C:\\ProgramData\\chocolatey\\lib\\clamwin\\tools\\bin",
        "C:\\ProgramData\\chocolatey\\lib\\clamav\\tools",
    ]

    clamav_path = None
    for path in common_paths:
        if os.path.exists(path):
            clamav_path = path
            break

    if not clamav_path:
        logger.warning("Could not locate ClamAV installation directory")
        return (
            False,
            "Installation directory not found",
            None,
            "ClamAV installation directory not found",
        )

    # Update virus definitions
    freshclam_exe = os.path.join(clamav_path, "freshclam.exe")
    if not os.path.exists(freshclam_exe):
        logger.warning("freshclam.exe not found at %s", freshclam_exe)
    else:
        logger.info("Updating virus definitions with freshclam")
        try:
            process = await asyncio.create_subprocess_exec(
                freshclam_exe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()
            if process.returncode == 0:
                logger.info("Virus definitions updated successfully")
            else:
                logger.warning(
                    "Failed to update virus definitions: %s",
                    stderr.decode() if stderr else "unknown error",
                )
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.warning("Error running freshclam: %s", error)

    await asyncio.sleep(2)
    return True, None, None, "ClamAV installed successfully on Windows"


async def deploy_clamav_debian(
    update_detector,
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Deploy ClamAV on Debian/Ubuntu."""
    result = update_detector.install_package("clamav", "auto")

    # Determine success based on result
    success = True
    error_message = None
    installed_version = None

    if isinstance(result, dict):
        success = result.get("success", True)
        error_message = result.get("error")
        installed_version = result.get("version")
    elif isinstance(result, str):
        if "error" in result.lower() or "failed" in result.lower():
            success = False
            error_message = result

    # Enable and start service
    if success:
        logger.info(
            "Antivirus package clamav installed successfully, enabling and starting service"
        )
        try:
            service_name = "clamav_freshclam"
            logger.info("Enabling and starting service: %s", service_name)
            process = await asyncio.create_subprocess_exec(
                "systemctl",
                "enable",
                "--now",
                service_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("Service %s enabled and started successfully", service_name)
                await asyncio.sleep(2)
            else:
                logger.warning(
                    "Failed to enable/start service %s: %s",
                    service_name,
                    stderr.decode() if stderr else "unknown error",
                )
        except Exception as service_error:  # pylint: disable=broad-exception-caught
            logger.warning("Failed to enable service: %s", str(service_error))

    return success, error_message, installed_version, result
