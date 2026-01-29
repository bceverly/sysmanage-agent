"""
SSH key operations module for SysManage agent.
Handles SSH key deployment and management operations.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Tuple

import aiofiles


class SSHKeyOperations:
    """Handles SSH key operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize SSH key operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def _write_key_file(
        self,
        key_file_path: str,
        content: str,
        subtype: str,
        user_uid: int,
        user_gid: int,
    ) -> None:
        """Write SSH key content to file with proper permissions."""
        async with aiofiles.open(key_file_path, "w", encoding="utf-8") as file_handle:
            await file_handle.write(content)
            if not content.endswith("\n"):
                await file_handle.write("\n")

        # Set permissions based on key type
        permissions = 0o644 if subtype == "public" else 0o600
        os.chmod(key_file_path, permissions)
        os.chown(key_file_path, user_uid, user_gid)

    async def _deploy_single_key(
        self, ssh_key: Dict[str, Any], ssh_dir: str, user_uid: int, user_gid: int
    ) -> Tuple[Dict[str, Any] | None, str | None]:
        """
        Deploy a single SSH key.

        Returns:
            Tuple of (deployed_key_info, error_message)
            - If successful: (key_info_dict, None)
            - If failed: (None, error_message)
        """
        key_name = ssh_key.get("name", "unknown")
        filename = ssh_key.get("filename", "ssh_key")
        content = ssh_key.get("content", "")
        subtype = ssh_key.get("subtype", "private")

        if not content:
            return None, f"Empty content for key '{key_name}'"

        try:
            key_file_path = os.path.join(ssh_dir, filename)
            await self._write_key_file(
                key_file_path, content, subtype, user_uid, user_gid
            )

            self.logger.info(
                "Successfully deployed SSH key '%s' to %s", key_name, key_file_path
            )

            return {
                "name": key_name,
                "filename": filename,
                "path": key_file_path,
                "subtype": subtype,
            }, None

        except (OSError, IOError) as error:
            error_msg = f"Failed to deploy key '{key_name}': {str(error)}"
            self.logger.error(error_msg)
            return None, error_msg

    async def _update_authorized_keys(
        self,
        public_keys: List[Dict[str, Any]],
        ssh_dir: str,
        user_uid: int,
        user_gid: int,
        username: str,
    ) -> str | None:
        """Update authorized_keys file with public keys. Returns error message or None."""
        authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

        try:
            # Read existing authorized_keys
            existing_keys = []
            if os.path.exists(authorized_keys_path):
                async with aiofiles.open(
                    authorized_keys_path, "r", encoding="utf-8"
                ) as file_handle:
                    content = await file_handle.read()
                    existing_keys = content.splitlines()

            # Append new public keys
            async with aiofiles.open(
                authorized_keys_path, "a", encoding="utf-8"
            ) as file_handle:
                for pub_key in public_keys:
                    async with aiofiles.open(
                        pub_key["path"], "r", encoding="utf-8"
                    ) as key_file:
                        key_content = (await key_file.read()).strip()
                        if key_content not in existing_keys:
                            await file_handle.write(key_content + "\n")

            os.chmod(authorized_keys_path, 0o600)
            os.chown(authorized_keys_path, user_uid, user_gid)
            self.logger.info("Updated authorized_keys for user '%s'", username)
            return None

        except (OSError, IOError) as error:
            error_msg = f"Failed to update authorized_keys: {str(error)}"
            self.logger.error(error_msg)
            return error_msg

    def _build_deployment_result(
        self,
        deployed_keys: List[Dict[str, Any]],
        errors: List[str],
        username: str,
        ssh_dir: str,
    ) -> Dict[str, Any]:
        """Build the final deployment result dictionary."""
        result = {
            "success": len(deployed_keys) > 0,
            "deployed_keys": deployed_keys,
            "deployed_count": len(deployed_keys),
            "username": username,
            "ssh_directory": ssh_dir,
        }

        if errors:
            result["errors"] = errors
            result["error_count"] = len(errors)

        if not deployed_keys:
            result["error"] = "No SSH keys were successfully deployed"

        return result

    async def deploy_ssh_keys(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSH keys to a user's .ssh directory with proper permissions."""
        username = parameters.get("username")
        ssh_keys = parameters.get("ssh_keys", [])

        validation_error = self._validate_ssh_key_inputs(username, ssh_keys)
        if validation_error:
            return validation_error

        try:
            setup_result = self._setup_ssh_environment(username)
            if not setup_result["success"]:
                return setup_result

            ssh_dir = setup_result["ssh_dir"]
            user_uid = setup_result["user_uid"]
            user_gid = setup_result["user_gid"]

            deployed_keys = []
            errors = []

            # Deploy each key
            for ssh_key in ssh_keys:
                key_info, error = await self._deploy_single_key(
                    ssh_key, ssh_dir, user_uid, user_gid
                )
                if key_info:
                    deployed_keys.append(key_info)
                if error:
                    errors.append(error)

            # Update authorized_keys for public keys
            public_keys = [k for k in deployed_keys if k.get("subtype") == "public"]
            if public_keys:
                auth_error = await self._update_authorized_keys(
                    public_keys, ssh_dir, user_uid, user_gid, username
                )
                if auth_error:
                    errors.append(auth_error)

            return self._build_deployment_result(
                deployed_keys, errors, username, ssh_dir
            )

        except Exception as error:
            self.logger.error(
                "Unexpected error during SSH key deployment: %s", str(error)
            )
            return {
                "success": False,
                "error": f"Unexpected error during SSH key deployment: {str(error)}",
            }

    def _validate_ssh_key_inputs(
        self, username: str, ssh_keys: list
    ) -> Dict[str, Any] | None:
        """Validate SSH key deployment inputs."""
        if not username:
            return {"success": False, "error": "Username is required"}

        if not ssh_keys:
            return {"success": False, "error": "No SSH keys provided"}

        return None  # No validation errors

    def _setup_ssh_environment(self, username: str) -> Dict[str, Any]:
        """Setup SSH environment for a user."""
        import pwd  # pylint: disable=import-outside-toplevel,import-error

        try:
            user_info = pwd.getpwnam(username)
            home_dir = user_info.pw_dir
            user_uid = user_info.pw_uid
            user_gid = user_info.pw_gid
        except KeyError:
            return {"success": False, "error": f"User '{username}' not found"}

        # Create .ssh directory if it doesn't exist
        ssh_dir = os.path.join(home_dir, ".ssh")

        try:
            # Create directory with proper permissions (700)
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            # Ensure ownership is correct
            os.chown(ssh_dir, user_uid, user_gid)
        except PermissionError:
            return {
                "success": False,
                "error": f"Permission denied creating/accessing {ssh_dir}",
            }
        except OSError as error:
            return {
                "success": False,
                "error": f"Failed to create .ssh directory: {str(error)}",
            }

        return {
            "success": True,
            "ssh_dir": ssh_dir,
            "user_uid": user_uid,
            "user_gid": user_gid,
        }
