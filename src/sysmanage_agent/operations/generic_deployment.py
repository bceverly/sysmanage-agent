"""
Generic deployment operations module for SysManage agent.
Handles generic file deployment and command sequence execution,
enabling server-side orchestration without agent domain knowledge.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from typing import Any, Dict

import aiofiles


class GenericDeployment:
    """Handles generic file deployment and command sequence execution."""

    def __init__(self, agent_instance):
        """Initialize generic deployment with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

    # ================================================================
    # deploy_files handler
    # ================================================================

    async def deploy_files(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deploy files to the filesystem atomically.

        Parameters:
            files: list of dicts with keys:
                - path: absolute destination path
                - content: file content as string
                - permissions: octal string e.g. "0644" (optional, default "0644")
                - owner_uid: numeric UID (optional, default 0)
                - owner_gid: numeric GID (optional, default 0)

        Returns:
            {success, deployed_files[], errors[]}
        """
        files = parameters.get("files", [])
        if not files:
            return {"success": False, "error": "No files provided"}

        deployed_files = []
        errors = []

        for file_spec in files:
            path = file_spec.get("path")
            content = file_spec.get("content")

            if not path:
                errors.append("File entry missing 'path'")
                continue
            if content is None:
                errors.append(f"File entry missing 'content' for path '{path}'")
                continue

            try:
                result = await self._deploy_single_file(file_spec)
                if result["success"]:
                    deployed_files.append(result)
                else:
                    errors.append(result.get("error", f"Failed to deploy {path}"))
            except Exception as exc:
                error_msg = f"Error deploying '{path}': {exc}"
                self.logger.error(error_msg)
                errors.append(error_msg)

        return {
            "success": len(deployed_files) > 0,
            "deployed_files": deployed_files,
            "deployed_count": len(deployed_files),
            "errors": errors if errors else [],
            "error_count": len(errors),
        }

    async def _deploy_single_file(self, file_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy a single file atomically using temp file + rename."""
        path = file_spec["path"]
        content = file_spec["content"]
        permissions = file_spec.get("permissions", "0644")
        owner_uid = file_spec.get("owner_uid", 0)
        owner_gid = file_spec.get("owner_gid", 0)

        # Parse octal permissions string
        try:
            mode = int(permissions, 8)
        except (ValueError, TypeError):
            mode = 0o644

        # Ensure parent directory exists
        parent_dir = os.path.dirname(path)
        if parent_dir:
            os.makedirs(parent_dir, mode=0o755, exist_ok=True)

        # Write atomically: temp file in same directory, then rename
        try:
            file_descriptor, tmp_path = tempfile.mkstemp(
                dir=parent_dir, prefix=".sysmanage_deploy_"
            )
            try:
                async with aiofiles.open(
                    file_descriptor, "w", encoding="utf-8", closefd=True
                ) as temp_file:
                    await temp_file.write(content)
                    if content and not content.endswith("\n"):
                        await temp_file.write("\n")

                os.chmod(tmp_path, mode)
                os.chown(tmp_path, owner_uid, owner_gid)
                os.rename(tmp_path, path)
            except Exception:
                # Clean up temp file on failure
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            self.logger.info("Deployed file: %s", path)
            return {
                "success": True,
                "path": path,
                "permissions": permissions,
                "owner_uid": owner_uid,
                "owner_gid": owner_gid,
            }

        except PermissionError as exc:
            return {
                "success": False,
                "error": f"Permission denied writing '{path}': {exc}",
            }
        except OSError as exc:
            return {
                "success": False,
                "error": f"OS error writing '{path}': {exc}",
            }

    # ================================================================
    # execute_command_sequence handler
    # ================================================================

    async def execute_command_sequence(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a sequence of steps in order, stopping on failure.

        Parameters:
            steps: list of step dicts, each with:
                - type: "shell" | "deploy_file" | "wait_condition"
                - For "shell": command, timeout (optional, default 300)
                - For "deploy_file": path, content, permissions (optional)
                - For "wait_condition": command, match, timeout, interval
                - description: human-readable step description (optional)
            progress_message_type: message type for progress updates (optional)
            child_host_id: UUID for progress messages (optional)

        Returns:
            {success, completed_steps, total_steps, results[], errors[]}
        """
        steps = parameters.get("steps", [])
        if not steps:
            return {"success": False, "error": "No steps provided"}

        progress_type = parameters.get(
            "progress_message_type", "command_sequence_progress"
        )
        child_host_id = parameters.get("child_host_id")

        results = []
        errors = []
        completed = 0

        for i, step in enumerate(steps):
            step_type = step.get("type", "shell")
            description = step.get("description", f"Step {i + 1}")

            # Send progress update
            await self._send_progress(
                progress_type,
                {
                    "step": i + 1,
                    "total_steps": len(steps),
                    "description": description,
                    "status": "running",
                    "child_host_id": child_host_id,
                },
            )

            try:
                if step_type == "shell":
                    result = await self._execute_shell_step(step)
                elif step_type == "deploy_file":
                    result = await self._execute_deploy_file_step(step)
                elif step_type == "wait_condition":
                    result = await self._execute_wait_condition_step(step)
                else:
                    result = {
                        "success": False,
                        "error": f"Unknown step type: {step_type}",
                    }

                results.append(
                    {
                        "step": i + 1,
                        "type": step_type,
                        "description": description,
                        "success": result.get("success", False),
                        "output": result.get("output", ""),
                    }
                )

                if result.get("success"):
                    completed += 1
                else:
                    error_msg = result.get(
                        "error", f"Step {i + 1} failed: {description}"
                    )
                    errors.append(error_msg)
                    self.logger.error(
                        "Command sequence step %d/%d failed: %s - %s",
                        i + 1,
                        len(steps),
                        description,
                        error_msg,
                    )
                    # Stop on failure
                    break

            except Exception as exc:
                error_msg = f"Step {i + 1} exception: {exc}"
                errors.append(error_msg)
                results.append(
                    {
                        "step": i + 1,
                        "type": step_type,
                        "description": description,
                        "success": False,
                        "output": str(exc),
                    }
                )
                self.logger.error(error_msg)
                break

        # Send final progress
        final_status = "completed" if completed == len(steps) else "failed"
        await self._send_progress(
            progress_type,
            {
                "step": completed,
                "total_steps": len(steps),
                "description": "Sequence " + final_status,
                "status": final_status,
                "child_host_id": child_host_id,
            },
        )

        return {
            "success": completed == len(steps),
            "completed_steps": completed,
            "total_steps": len(steps),
            "results": results,
            "errors": errors if errors else [],
        }

    async def _execute_shell_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command step."""
        command = step.get("command", "")
        timeout = step.get("timeout", 300)

        if not command:
            return {"success": False, "error": "Empty shell command"}

        result = await self.agent.execute_shell_command(
            {"command": command, "timeout": timeout}
        )

        success = result.get("success", False)
        output = result.get("result", {})
        if isinstance(output, dict):
            output = output.get("stdout", "") or output.get("output", "")

        return {
            "success": success,
            "output": output,
            "error": result.get("error") if not success else None,
        }

    async def _execute_deploy_file_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a file deployment step."""
        result = await self._deploy_single_file(
            {
                "path": step.get("path", ""),
                "content": step.get("content", ""),
                "permissions": step.get("permissions", "0644"),
                "owner_uid": step.get("owner_uid", 0),
                "owner_gid": step.get("owner_gid", 0),
            }
        )
        return result

    async def _execute_wait_condition_step(
        self, step: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a wait condition step, polling until match or timeout."""
        command = step.get("command", "")
        match_str = step.get("match", "")
        timeout = step.get("timeout", 120)
        interval = step.get("interval", 5)

        if not command:
            return {"success": False, "error": "Empty wait_condition command"}

        elapsed = 0
        last_output = ""
        while elapsed < timeout:
            result = await self.agent.execute_shell_command(
                {"command": command, "timeout": 30}
            )
            output = result.get("result", {})
            if isinstance(output, dict):
                output = output.get("stdout", "") or output.get("output", "")
            last_output = str(output)

            if match_str in last_output:
                return {"success": True, "output": last_output}

            await asyncio.sleep(interval)
            elapsed += interval

        return {
            "success": False,
            "error": (
                f"Wait condition timed out after {timeout}s. "
                f"Expected '{match_str}' in output. Last output: {last_output[:200]}"
            ),
            "output": last_output,
        }

    async def _send_progress(self, message_type: str, data: Dict[str, Any]) -> None:
        """Send a progress message to the server."""
        try:
            message = self.agent.create_message(message_type, data)
            await self.agent.send_message(message)
        except Exception as exc:
            self.logger.warning("Failed to send progress message: %s", exc)
