"""
Diagnostic collection functionality for the SysManage agent.

This module handles the collection of various system diagnostics including
system logs, configuration files, network information, process information,
disk usage, environment variables, agent logs, and error logs.
"""

import platform
from datetime import datetime, timezone
from typing import Dict, Any

import aiofiles

from src.i18n import _


class DiagnosticCollector:
    """Handles collection of system diagnostics."""

    def __init__(self, agent_instance):
        """Initialize the DiagnosticCollector with a reference to the agent.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
        """
        self.agent = agent_instance
        self.logger = agent_instance.logger
        self.system_ops = agent_instance.system_ops
        self.registration = agent_instance.registration

    async def collect_diagnostics(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Collect system diagnostics and send to server."""
        try:
            collection_id = parameters.get("collection_id")
            collection_types = parameters.get("collection_types", [])

            self.logger.info(
                _("Starting diagnostics collection for ID: %s"), collection_id
            )
            self.logger.info(_("Collection types requested: %s"), collection_types)

            # Dictionary to store collected data
            system_info = self.registration.get_system_info()
            diagnostic_data = {
                "collection_id": collection_id,
                "success": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": system_info["hostname"],
            }

            # Collect all requested diagnostic types
            await self._collect_all_diagnostic_types(collection_types, diagnostic_data)

            # Calculate and add statistics
            collection_size, files_collected = self._calculate_collection_statistics(
                diagnostic_data
            )
            diagnostic_data["collection_size_bytes"] = collection_size
            diagnostic_data["files_collected"] = files_collected

            # Send diagnostic data to server
            await self._send_diagnostic_result(diagnostic_data)

            self.logger.info(
                _("Diagnostics collection completed for ID: %s"), collection_id
            )

            return {
                "success": True,
                "collection_id": collection_id,
                "message": "Diagnostics collected and sent to server",
            }

        except Exception as error:
            self.logger.error(_("Failed to collect diagnostics: %s"), error)

            # Send error result to server if we have collection_id
            if parameters.get("collection_id"):
                await self._send_diagnostic_error(parameters["collection_id"], error)

            return {"success": False, "error": str(error)}

    async def _collect_single_diagnostic_type(
        self, collection_type: str, diagnostic_data: Dict[str, Any]
    ) -> None:
        """Collect a single diagnostic type and add it to diagnostic_data.

        Args:
            collection_type: The type of diagnostic to collect
            diagnostic_data: Dictionary to store the collected data
        """
        if collection_type == "system_logs":
            self.logger.info("Collecting system logs...")
            diagnostic_data["system_logs"] = await self._collect_system_logs()
        elif collection_type == "configuration_files":
            self.logger.info("Collecting configuration files...")
            diagnostic_data["configuration_files"] = (
                await self._collect_configuration_files()
            )
        elif collection_type == "network_info":
            self.logger.info("Collecting network information...")
            diagnostic_data["network_info"] = await self._collect_network_info()
        elif collection_type == "process_info":
            self.logger.info("Collecting process information...")
            diagnostic_data["process_info"] = await self._collect_process_info()
        elif collection_type == "disk_usage":
            self.logger.info("Collecting disk usage information...")
            diagnostic_data["disk_usage"] = await self._collect_disk_usage()
        elif collection_type == "environment_variables":
            self.logger.info("Collecting environment variables...")
            diagnostic_data["environment_variables"] = (
                await self._collect_environment_variables()
            )
        elif collection_type == "agent_logs":
            self.logger.info("Collecting agent logs...")
            diagnostic_data["agent_logs"] = await self._collect_agent_logs()
        elif collection_type == "error_logs":
            self.logger.info("Collecting error logs...")
            diagnostic_data["error_logs"] = await self._collect_error_logs()
        else:
            self.logger.warning(_("Unknown collection type: %s"), collection_type)

    async def _collect_all_diagnostic_types(
        self, collection_types: list, diagnostic_data: Dict[str, Any]
    ) -> None:
        """Collect all requested diagnostic types.

        Args:
            collection_types: List of diagnostic types to collect
            diagnostic_data: Dictionary to store the collected data
        """
        for i, collection_type in enumerate(collection_types, 1):
            try:
                self.logger.info(
                    _("Starting collection %d/%d: %s"),
                    i,
                    len(collection_types),
                    collection_type,
                )
                start_time = datetime.now(timezone.utc)

                await self._collect_single_diagnostic_type(
                    collection_type, diagnostic_data
                )

                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.logger.info(
                    _("Completed collection of %s in %.2f seconds"),
                    collection_type,
                    elapsed,
                )

            except Exception as error:
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.logger.error(
                    _("Failed to collect %s after %.2f seconds: %s"),
                    collection_type,
                    elapsed,
                    error,
                )
                # Continue collecting other types even if one fails

    def _calculate_collection_statistics(
        self, diagnostic_data: Dict[str, Any]
    ) -> tuple:
        """Calculate statistics about the collected diagnostic data.

        Args:
            diagnostic_data: Dictionary containing collected diagnostic data

        Returns:
            Tuple of (collection_size, files_collected)
        """
        self.logger.info("Calculating collection statistics...")
        collection_size = 0
        files_collected = 0

        for key, value in diagnostic_data.items():
            if isinstance(value, (dict, list)) and key != "collection_id":
                collection_size += len(str(value))
                if isinstance(value, dict) and "files" in value:
                    files_collected += len(value.get("files", []))
                elif isinstance(value, list):
                    files_collected += len(value)

        self.logger.info(
            "Collection statistics: %d bytes, %d files/entries collected",
            collection_size,
            files_collected,
        )

        return collection_size, files_collected

    async def _send_diagnostic_result(self, diagnostic_data: Dict[str, Any]) -> None:
        """Send diagnostic data to the server.

        Args:
            diagnostic_data: Dictionary containing collected diagnostic data
        """
        self.logger.info("Preparing to send diagnostic data to server...")
        send_start_time = datetime.now(timezone.utc)

        diagnostic_message = self.agent.create_message(
            "diagnostic_collection_result", diagnostic_data
        )

        self.logger.info(
            "Sending diagnostic message (ID: %s)...",
            diagnostic_message.get("message_id"),
        )
        await self.agent.send_message(diagnostic_message)

        send_elapsed = (datetime.now(timezone.utc) - send_start_time).total_seconds()
        self.logger.info("Diagnostic message sent in %.2f seconds", send_elapsed)

    async def _send_diagnostic_error(
        self, collection_id: str, error: Exception
    ) -> None:
        """Send diagnostic collection error to the server.

        Args:
            collection_id: The collection ID
            error: The exception that occurred
        """
        system_info = self.registration.get_system_info()
        error_data = {
            "collection_id": collection_id,
            "success": False,
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": system_info["hostname"],
        }
        try:
            error_message = self.agent.create_message(
                "diagnostic_collection_result", error_data
            )
            await self.agent.send_message(error_message)
        except Exception as send_error:
            self.logger.error(_("Failed to send error message: %s"), send_error)

    async def _collect_windows_event_log(
        self, log_name: str, max_events: int, log_key: str
    ) -> Dict[str, str]:
        """Collect a single Windows Event Log.

        Args:
            log_name: The Windows Event Log name (e.g. System, Application, Security)
            max_events: Maximum number of events to retrieve
            log_key: The key to use in the returned dictionary

        Returns:
            Dict with the log_key mapped to the collected log content
        """
        result_data = {}
        self.logger.info("Collecting Windows %s Event Log...", log_name)
        start_time = datetime.now(timezone.utc)

        if log_name == "Security":
            command = (
                'powershell -Command "try { Get-WinEvent -LogName Security '
                f"-MaxEvents {max_events} | Select-Object TimeCreated, "
                "LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json "
                "} catch { 'Security logs not accessible - admin privileges required' }\""
            )
        else:
            command = (
                f'powershell -Command "Get-WinEvent -LogName {log_name} '
                f"-MaxEvents {max_events} | Select-Object TimeCreated, "
                'LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json"'
            )

        result = await self.system_ops.execute_shell_command({"command": command})
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        if result.get("success"):
            result_data[log_key] = result.get("result", {}).get("stdout", "")
            self.logger.info(
                "Windows %s Event Log collected in %.2f seconds", log_name, elapsed
            )
        else:
            self.logger.warning(
                "Windows %s Event Log collection failed after %.2f seconds",
                log_name,
                elapsed,
            )

        return result_data

    async def _collect_unix_system_logs(self) -> Dict[str, str]:
        """Collect system logs on Linux/Unix systems.

        Returns:
            Dict with collected log entries
        """
        system_logs = {}

        result = await self.system_ops.execute_shell_command(
            {"command": "journalctl --since '1 hour ago' --no-pager -n 100"}
        )
        if result.get("success"):
            system_logs["journalctl_recent"] = result.get("result", {}).get(
                "stdout", ""
            )

        result = await self.system_ops.execute_shell_command(
            {"command": "dmesg | tail -n 50"}
        )
        if result.get("success"):
            system_logs["dmesg_recent"] = result.get("result", {}).get("stdout", "")

        result = await self.system_ops.execute_shell_command(
            {
                "command": "tail -n 50 /var/log/auth.log 2>/dev/null || tail -n 50 /var/log/secure 2>/dev/null || echo 'Auth logs not accessible'"
            }
        )
        if result.get("success"):
            system_logs["auth_log"] = result.get("result", {}).get("stdout", "")

        return system_logs

    async def _collect_system_logs(self) -> Dict[str, Any]:
        """Collect system log information."""
        try:
            system_logs = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                self.logger.info(
                    "Collecting Windows System Event Log (this may take 10-30 seconds)..."
                )
                system_logs.update(
                    await self._collect_windows_event_log(
                        "System", 100, "windows_system_log"
                    )
                )
                system_logs.update(
                    await self._collect_windows_event_log(
                        "Application", 50, "windows_application_log"
                    )
                )
                self.logger.info(
                    "Collecting Windows Security Event Log (may require admin privileges)..."
                )
                system_logs.update(
                    await self._collect_windows_event_log(
                        "Security", 50, "windows_security_log"
                    )
                )
            else:
                system_logs = await self._collect_unix_system_logs()

            return system_logs

        except Exception as error:
            self.logger.error(_("Error collecting system logs: %s"), error)
            return {"error": str(error)}

    async def _collect_configuration_files(self) -> Dict[str, Any]:
        """Collect relevant configuration files."""
        try:
            config_files = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get Windows network configuration
                result = await self.system_ops.execute_shell_command(
                    {"command": "ipconfig /all"}
                )
                if result.get("success"):
                    config_files["network_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Windows services configuration (key system services)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, Status, StartType | ConvertTo-Json\""
                    }
                )
                if result.get("success"):
                    config_files["services_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Windows firewall configuration
                result = await self.system_ops.execute_shell_command(
                    {"command": "netsh advfirewall show allprofiles"}
                )
                if result.get("success"):
                    config_files["firewall_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

            else:
                # Linux/Unix systems
                # Get network configuration
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "cat /etc/network/interfaces 2>/dev/null || cat /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null || echo 'Network config not found'"
                    }
                )
                if result.get("success"):
                    config_files["network_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get SSH configuration
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "cat /etc/ssh/sshd_config 2>/dev/null || echo 'SSH config not accessible'"
                    }
                )
                if result.get("success"):
                    config_files["ssh_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

            # Get agent configuration (our own config) - works on both platforms
            try:
                async with aiofiles.open(
                    "config.yaml", "r", encoding="utf-8"
                ) as file_handle:
                    config_files["agent_config"] = await file_handle.read()
            except Exception:
                config_files["agent_config"] = "Agent config not readable"

            return config_files

        except Exception as error:
            self.logger.error(_("Error collecting configuration files: %s"), error)
            return {"error": str(error)}

    async def _collect_windows_network_command(
        self, command: str, key: str, label: str
    ) -> Dict[str, str]:
        """Collect a single Windows network diagnostic command.

        Args:
            command: The shell command to execute
            key: The key to use in the returned dictionary
            label: Human-readable label for logging

        Returns:
            Dict with the key mapped to the collected output
        """
        result_data = {}
        self.logger.info("Collecting %s...", label)
        start_time = datetime.now(timezone.utc)
        result = await self.system_ops.execute_shell_command({"command": command})
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        if result.get("success"):
            result_data[key] = result.get("result", {}).get("stdout", "")
            self.logger.info("%s collected in %.2f seconds", label, elapsed)
        else:
            self.logger.warning(
                "%s collection failed after %.2f seconds", label, elapsed
            )

        return result_data

    async def _collect_windows_dns_config(self) -> Dict[str, str]:
        """Collect Windows DNS configuration with fallback.

        Returns:
            Dict with dns_config key mapped to collected DNS output
        """
        result_data = await self._collect_windows_network_command(
            "ipconfig /displaydns",
            "dns_config",
            "DNS configuration (ipconfig /displaydns)",
        )

        if "dns_config" not in result_data:
            self.logger.info("Trying alternative DNS configuration method...")
            result_data = await self._collect_windows_network_command(
                'powershell -Command "Get-DnsClientServerAddress | ConvertTo-Json"',
                "dns_config",
                "DNS configuration (alternative)",
            )

        if "dns_config" not in result_data:
            result_data["dns_config"] = "DNS configuration not available"

        return result_data

    async def _collect_windows_network_info(self) -> Dict[str, str]:
        """Collect network information on Windows systems.

        Returns:
            Dict with collected network information
        """
        network_info = {}
        network_info.update(
            await self._collect_windows_network_command(
                "ipconfig /all", "interfaces", "network interfaces (ipconfig /all)"
            )
        )
        network_info.update(
            await self._collect_windows_network_command(
                "route print", "routes", "routing table (route print)"
            )
        )
        network_info.update(
            await self._collect_windows_network_command(
                "netstat -an", "connections", "network connections (netstat -an)"
            )
        )
        network_info.update(await self._collect_windows_dns_config())
        return network_info

    async def _collect_unix_network_info(self) -> Dict[str, str]:
        """Collect network information on Linux/Unix systems.

        Returns:
            Dict with collected network information
        """
        network_info = {}

        commands = [
            ("ip addr show", "interfaces"),
            ("ip route show", "routes"),
            ("ss -tulpn", "connections"),
            (
                "cat /etc/resolv.conf 2>/dev/null || echo 'DNS config not accessible'",
                "dns_config",
            ),
        ]

        for command, key in commands:
            result = await self.system_ops.execute_shell_command({"command": command})
            if result.get("success"):
                network_info[key] = result.get("result", {}).get("stdout", "")

        return network_info

    async def _collect_network_info(self) -> Dict[str, Any]:
        """Collect network information."""
        try:
            current_platform = platform.system()

            if current_platform == "Windows":
                network_info = await self._collect_windows_network_info()
            else:
                network_info = await self._collect_unix_network_info()

            return network_info

        except Exception as error:
            self.logger.error(_("Error collecting network info: %s"), error)
            return {"error": str(error)}

    async def _collect_process_info(self) -> Dict[str, Any]:
        """Collect process information."""
        try:
            process_info = {}

            # Get process list
            result = await self.system_ops.execute_shell_command(
                {"command": "ps aux --sort=-%cpu | head -n 20"}
            )
            if result.get("success"):
                process_info["top_processes_cpu"] = result.get("result", {}).get(
                    "stdout", ""
                )

            # Get memory usage
            result = await self.system_ops.execute_shell_command(
                {"command": "ps aux --sort=-%mem | head -n 20"}
            )
            if result.get("success"):
                process_info["top_processes_memory"] = result.get("result", {}).get(
                    "stdout", ""
                )

            # Get system load
            result = await self.system_ops.execute_shell_command({"command": "uptime"})
            if result.get("success"):
                process_info["system_load"] = result.get("result", {}).get("stdout", "")

            # Get memory info
            result = await self.system_ops.execute_shell_command({"command": "free -h"})
            if result.get("success"):
                process_info["memory_info"] = result.get("result", {}).get("stdout", "")

            return process_info

        except Exception as error:
            self.logger.error(_("Error collecting process info: %s"), error)
            return {"error": str(error)}

    async def _collect_windows_disk_usage(self) -> Dict[str, str]:
        """Collect disk usage information on Windows systems.

        Returns:
            Dict with collected disk usage data
        """
        disk_info = {}
        disk_commands = [
            (
                "powershell -Command \"Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, @{Name='UsedSpace';Expression={$_.Size - $_.FreeSpace}} | ConvertTo-Json\"",
                "filesystem_usage",
                "Windows filesystem usage",
            ),
            (
                "powershell -Command \"Get-Counter -Counter '\\LogicalDisk(*)\\% Disk Time' -MaxSamples 1 | ConvertTo-Json\"",
                "io_stats",
                "Windows disk performance counters",
            ),
            (
                "powershell -Command \"Get-ChildItem -Path C:\\ -Directory | Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | Select-Object @{Name='Path';Expression={$_.PSPath}}, @{Name='Size';Expression={$_.Sum}} | Sort-Object Size -Descending | Select-Object -First 10 | ConvertTo-Json\"",
                "largest_directories",
                "largest directories (this may take 30+ seconds)",
            ),
        ]

        for command, key, label in disk_commands:
            self.logger.info("Collecting %s...", label)
            start_time = datetime.now(timezone.utc)
            result = await self.system_ops.execute_shell_command({"command": command})
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

            if result.get("success"):
                disk_info[key] = result.get("result", {}).get("stdout", "")
                self.logger.info("%s collected in %.2f seconds", label, elapsed)
            else:
                self.logger.warning(
                    "%s collection failed after %.2f seconds", label, elapsed
                )

        return disk_info

    async def _collect_unix_disk_usage(self) -> Dict[str, str]:
        """Collect disk usage information on Linux/Unix systems.

        Returns:
            Dict with collected disk usage data
        """
        disk_info = {}
        commands = [
            ("df -h", "filesystem_usage"),
            ("iostat -x 1 1 2>/dev/null || echo 'iostat not available'", "io_stats"),
            (
                "du -h /var /tmp /home 2>/dev/null | sort -hr | head -n 10 || echo 'Disk usage analysis not available'",
                "largest_directories",
            ),
        ]

        for command, key in commands:
            result = await self.system_ops.execute_shell_command({"command": command})
            if result.get("success"):
                disk_info[key] = result.get("result", {}).get("stdout", "")

        return disk_info

    async def _collect_disk_usage(self) -> Dict[str, Any]:
        """Collect disk usage information."""
        try:
            current_platform = platform.system()

            if current_platform == "Windows":
                disk_info = await self._collect_windows_disk_usage()
            else:
                disk_info = await self._collect_unix_disk_usage()

            return disk_info

        except Exception as error:
            self.logger.error(_("Error collecting disk usage: %s"), error)
            return {"error": str(error)}

    async def _collect_environment_variables(self) -> Dict[str, Any]:
        """Collect environment variables (filtered for security)."""
        try:
            env_vars = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get safe environment variables (exclude sensitive ones)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-ChildItem Env: | Where-Object {$_.Name -match '^(PATH|HOME|USERNAME|COMPUTERNAME|PROCESSOR_|OS|TEMP|TMP)$'} | Sort-Object Name | ConvertTo-Json\""
                    }
                )
                if result.get("success"):
                    env_vars["safe_env_vars"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Python path if available
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "python -c \"import sys; print('\\n'.join(sys.path))\" 2>NUL || echo Python path not available"
                    }
                )
                if result.get("success"):
                    env_vars["python_path"] = result.get("result", {}).get("stdout", "")

            else:
                # Linux/Unix systems
                # Get safe environment variables (exclude sensitive ones)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "env | grep -E '^(PATH|HOME|USER|SHELL|LANG|LC_|TZ|TERM)=' | sort"
                    }
                )
                if result.get("success"):
                    env_vars["safe_env_vars"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get Python path if available
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "python3 -c 'import sys; print(\"\\n\".join(sys.path))' 2>/dev/null || echo 'Python path not available'"
                    }
                )
                if result.get("success"):
                    env_vars["python_path"] = result.get("result", {}).get("stdout", "")

            return env_vars

        except Exception as error:
            self.logger.error(_("Error collecting environment variables: %s"), error)
            return {"error": str(error)}

    async def _collect_agent_logs(self) -> Dict[str, Any]:
        """Collect agent log information."""
        try:
            agent_logs = {}

            # Get recent agent logs
            try:
                async with aiofiles.open(
                    "logs/agent.log", "r", encoding="utf-8"
                ) as file_handle:
                    # Get last 100 lines
                    lines = await file_handle.readlines()
                    agent_logs["recent_logs"] = "".join(lines[-100:])
            except Exception:
                agent_logs["recent_logs"] = "Agent logs not accessible"

            # Get agent status
            agent_logs["agent_status"] = {
                "running": self.agent.running,
                "connected": self.agent.connected,
                "reconnect_attempts": getattr(self.agent, "reconnect_attempts", 0),
                "last_ping": getattr(self.agent, "last_ping", None),
                "uptime": datetime.now(timezone.utc).isoformat(),
            }

            return agent_logs

        except Exception as error:
            self.logger.error(_("Error collecting agent logs: %s"), error)
            return {"error": str(error)}

    async def _collect_error_logs(self) -> Dict[str, Any]:
        """Collect error logs from various sources."""
        try:
            error_logs = {}

            # Get system error logs
            result = await self.system_ops.execute_shell_command(
                {"command": "journalctl -p err --since '1 hour ago' --no-pager -n 50"}
            )
            if result.get("success"):
                error_logs["system_errors"] = result.get("result", {}).get("stdout", "")

            # Get kernel errors
            result = await self.system_ops.execute_shell_command(
                {"command": "dmesg | grep -i error | tail -n 20"}
            )
            if result.get("success"):
                error_logs["kernel_errors"] = result.get("result", {}).get("stdout", "")

            # Get agent error logs
            try:
                async with aiofiles.open(
                    "logs/agent.log", "r", encoding="utf-8"
                ) as file_handle:
                    lines = await file_handle.readlines()
                    error_lines = [line for line in lines if "ERROR" in line.upper()]
                    error_logs["agent_errors"] = "".join(error_lines[-50:])
            except Exception:
                error_logs["agent_errors"] = "Agent error logs not accessible"

            return error_logs

        except Exception as error:
            self.logger.error(_("Error collecting error logs: %s"), error)
            return {"error": str(error)}
