"""
Diagnostic collection functionality for the SysManage agent.

This module handles the collection of various system diagnostics including
system logs, configuration files, network information, process information,
disk usage, environment variables, agent logs, and error logs.
"""

import platform
from datetime import datetime, timezone
from typing import Dict, Any

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

    async def _collect_system_logs(self) -> Dict[str, Any]:
        """Collect system log information."""
        try:
            system_logs = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get Windows Event Log entries
                self.logger.info(
                    "Collecting Windows System Event Log (this may take 10-30 seconds)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": 'powershell -Command "Get-WinEvent -LogName System -MaxEvents 100 | Select-Object TimeCreated, LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json"'
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    system_logs["windows_system_log"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Windows System Event Log collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Windows System Event Log collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get Application Event Log entries
                self.logger.info("Collecting Windows Application Event Log...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": 'powershell -Command "Get-WinEvent -LogName Application -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json"'
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    system_logs["windows_application_log"] = result.get(
                        "result", {}
                    ).get("stdout", "")
                    self.logger.info(
                        "Windows Application Event Log collected in %.2f seconds",
                        elapsed,
                    )
                else:
                    self.logger.warning(
                        "Windows Application Event Log collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get Security Event Log entries (may require admin privileges)
                self.logger.info(
                    "Collecting Windows Security Event Log (may require admin privileges)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"try { Get-WinEvent -LogName Security -MaxEvents 50 | Select-Object TimeCreated, LevelDisplayName, Id, TaskDisplayName, Message | ConvertTo-Json } catch { 'Security logs not accessible - admin privileges required' }\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    system_logs["windows_security_log"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Windows Security Event Log collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Windows Security Event Log collection failed after %.2f seconds",
                        elapsed,
                    )

            else:
                # Linux/Unix systems
                # Try to get recent system log entries
                result = await self.system_ops.execute_shell_command(
                    {"command": "journalctl --since '1 hour ago' --no-pager -n 100"}
                )
                if result.get("success"):
                    system_logs["journalctl_recent"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get kernel messages
                result = await self.system_ops.execute_shell_command(
                    {"command": "dmesg | tail -n 50"}
                )
                if result.get("success"):
                    system_logs["dmesg_recent"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get auth log if available
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "tail -n 50 /var/log/auth.log 2>/dev/null || tail -n 50 /var/log/secure 2>/dev/null || echo 'Auth logs not accessible'"
                    }
                )
                if result.get("success"):
                    system_logs["auth_log"] = result.get("result", {}).get("stdout", "")

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
                with open("config.yaml", "r", encoding="utf-8") as file_handle:
                    config_files["agent_config"] = file_handle.read()
            except Exception:
                config_files["agent_config"] = "Agent config not readable"

            return config_files

        except Exception as error:
            self.logger.error(_("Error collecting configuration files: %s"), error)
            return {"error": str(error)}

    async def _collect_network_info(
        self,
    ) -> Dict[str, Any]:  # pylint: disable=too-many-branches,too-many-statements
        """Collect network information."""
        try:
            network_info = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get network interfaces
                self.logger.info("Collecting network interfaces (ipconfig /all)...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "ipconfig /all"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["interfaces"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Network interfaces collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Network interfaces collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get routing table
                self.logger.info("Collecting routing table (route print)...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "route print"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["routes"] = result.get("result", {}).get("stdout", "")
                    self.logger.info("Routing table collected in %.2f seconds", elapsed)
                else:
                    self.logger.warning(
                        "Routing table collection failed after %.2f seconds", elapsed
                    )

                # Get network connections
                self.logger.info("Collecting network connections (netstat -an)...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "netstat -an"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["connections"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Network connections collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Network connections collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get DNS configuration (using safer command)
                self.logger.info(
                    "Collecting DNS configuration (ipconfig /displaydns)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {"command": "ipconfig /displaydns"}
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    network_info["dns_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "DNS configuration collected in %.2f seconds", elapsed
                    )
                else:
                    # Fallback to getting DNS servers from network adapters
                    self.logger.info("Trying alternative DNS configuration method...")
                    start_time = datetime.now(timezone.utc)
                    result = await self.system_ops.execute_shell_command(
                        {
                            "command": 'powershell -Command "Get-DnsClientServerAddress | ConvertTo-Json"'
                        }
                    )
                    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                    if result.get("success"):
                        network_info["dns_config"] = result.get("result", {}).get(
                            "stdout", ""
                        )
                        self.logger.info(
                            "DNS configuration (alternative) collected in %.2f seconds",
                            elapsed,
                        )
                    else:
                        self.logger.warning(
                            "DNS configuration collection failed after %.2f seconds",
                            elapsed,
                        )
                        network_info["dns_config"] = "DNS configuration not available"

            else:
                # Linux/Unix systems
                # Get network interfaces
                result = await self.system_ops.execute_shell_command(
                    {"command": "ip addr show"}
                )
                if result.get("success"):
                    network_info["interfaces"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get routing table
                result = await self.system_ops.execute_shell_command(
                    {"command": "ip route show"}
                )
                if result.get("success"):
                    network_info["routes"] = result.get("result", {}).get("stdout", "")

                # Get network connections
                result = await self.system_ops.execute_shell_command(
                    {"command": "ss -tulpn"}
                )
                if result.get("success"):
                    network_info["connections"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get DNS configuration
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "cat /etc/resolv.conf 2>/dev/null || echo 'DNS config not accessible'"
                    }
                )
                if result.get("success"):
                    network_info["dns_config"] = result.get("result", {}).get(
                        "stdout", ""
                    )

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

    async def _collect_disk_usage(self) -> Dict[str, Any]:
        """Collect disk usage information."""
        try:
            disk_info = {}
            current_platform = platform.system()

            if current_platform == "Windows":
                # Get filesystem usage
                self.logger.info("Collecting Windows filesystem usage...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, @{Name='UsedSpace';Expression={$_.Size - $_.FreeSpace}} | ConvertTo-Json\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    disk_info["filesystem_usage"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Windows filesystem usage collected in %.2f seconds", elapsed
                    )
                else:
                    self.logger.warning(
                        "Windows filesystem usage collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get disk performance counters
                self.logger.info("Collecting Windows disk performance counters...")
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-Counter -Counter '\\LogicalDisk(*)\\% Disk Time' -MaxSamples 1 | ConvertTo-Json\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    disk_info["io_stats"] = result.get("result", {}).get("stdout", "")
                    self.logger.info(
                        "Windows disk performance counters collected in %.2f seconds",
                        elapsed,
                    )
                else:
                    self.logger.warning(
                        "Windows disk performance counters collection failed after %.2f seconds",
                        elapsed,
                    )

                # Get largest directories using PowerShell (this can be very slow)
                self.logger.info(
                    "Collecting largest directories (this may take 30+ seconds)..."
                )
                start_time = datetime.now(timezone.utc)
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "powershell -Command \"Get-ChildItem -Path C:\\ -Directory | Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | Select-Object @{Name='Path';Expression={$_.PSPath}}, @{Name='Size';Expression={$_.Sum}} | Sort-Object Size -Descending | Select-Object -First 10 | ConvertTo-Json\""
                    }
                )
                elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
                if result.get("success"):
                    disk_info["largest_directories"] = result.get("result", {}).get(
                        "stdout", ""
                    )
                    self.logger.info(
                        "Largest directories analysis completed in %.2f seconds",
                        elapsed,
                    )
                else:
                    self.logger.warning(
                        "Largest directories analysis failed after %.2f seconds",
                        elapsed,
                    )

            else:
                # Linux/Unix systems
                # Get filesystem usage
                result = await self.system_ops.execute_shell_command(
                    {"command": "df -h"}
                )
                if result.get("success"):
                    disk_info["filesystem_usage"] = result.get("result", {}).get(
                        "stdout", ""
                    )

                # Get disk I/O stats
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "iostat -x 1 1 2>/dev/null || echo 'iostat not available'"
                    }
                )
                if result.get("success"):
                    disk_info["io_stats"] = result.get("result", {}).get("stdout", "")

                # Get largest files/directories
                result = await self.system_ops.execute_shell_command(
                    {
                        "command": "du -h /var /tmp /home 2>/dev/null | sort -hr | head -n 10 || echo 'Disk usage analysis not available'"
                    }
                )
                if result.get("success"):
                    disk_info["largest_directories"] = result.get("result", {}).get(
                        "stdout", ""
                    )

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
                with open("logs/agent.log", "r", encoding="utf-8") as file_handle:
                    # Get last 100 lines
                    lines = file_handle.readlines()
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
                with open("logs/agent.log", "r", encoding="utf-8") as file_handle:
                    lines = file_handle.readlines()
                    error_lines = [line for line in lines if "ERROR" in line.upper()]
                    error_logs["agent_errors"] = "".join(error_lines[-50:])
            except Exception:
                error_logs["agent_errors"] = "Agent error logs not accessible"

            return error_logs

        except Exception as error:
            self.logger.error(_("Error collecting error logs: %s"), error)
            return {"error": str(error)}
