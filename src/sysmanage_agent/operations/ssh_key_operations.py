"""
SSH key operations module for SysManage agent.
Handles SSH key deployment and management operations.
"""

import logging
import os
from typing import Any, Dict


class SSHKeyOperations:
    """Handles SSH key operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize SSH key operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def deploy_ssh_keys(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSH keys to a user's .ssh directory with proper permissions."""
        username = parameters.get("username")
        ssh_keys = parameters.get("ssh_keys", [])

        # Validate inputs
        validation_error = self._validate_ssh_key_inputs(username, ssh_keys)
        if validation_error:
            return validation_error

        try:
            # Get user info and setup SSH directory
            setup_result = self._setup_ssh_environment(username)
            if not setup_result["success"]:
                return setup_result

            ssh_dir = setup_result["ssh_dir"]
            user_uid = setup_result["user_uid"]
            user_gid = setup_result["user_gid"]

            deployed_keys = []
            errors = []

            for ssh_key in ssh_keys:
                key_name = ssh_key.get("name", "unknown")
                filename = ssh_key.get("filename", "ssh_key")
                content = ssh_key.get("content", "")
                subtype = ssh_key.get("subtype", "private")

                if not content:
                    errors.append(f"Empty content for key '{key_name}'")
                    continue

                try:
                    # Full path for the key file
                    key_file_path = os.path.join(ssh_dir, filename)

                    # Write the key file
                    with open(key_file_path, "w", encoding="utf-8") as file_handle:
                        file_handle.write(content)
                        # Ensure content ends with newline
                        if not content.endswith("\n"):
                            file_handle.write("\n")

                    # Set appropriate permissions based on key type
                    if subtype == "public":
                        # Public keys: readable by owner and group (644)
                        os.chmod(key_file_path, 0o644)
                    else:
                        # Private keys and others: readable by owner only (600)
                        os.chmod(key_file_path, 0o600)

                    # Set correct ownership
                    os.chown(key_file_path, user_uid, user_gid)

                    deployed_keys.append(
                        {
                            "name": key_name,
                            "filename": filename,
                            "path": key_file_path,
                            "subtype": subtype,
                        }
                    )

                    self.logger.info(
                        "Successfully deployed SSH key '%s' to %s",
                        key_name,
                        key_file_path,
                    )

                except (OSError, IOError) as error:
                    error_msg = f"Failed to deploy key '{key_name}': {str(error)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)

            # Handle authorized_keys for public keys
            public_keys = [k for k in deployed_keys if k.get("subtype") == "public"]
            if public_keys:
                try:
                    authorized_keys_path = os.path.join(ssh_dir, "authorized_keys")

                    # Read existing authorized_keys if it exists
                    existing_keys = []
                    if os.path.exists(authorized_keys_path):
                        with open(
                            authorized_keys_path, "r", encoding="utf-8"
                        ) as file_handle:
                            existing_keys = file_handle.read().splitlines()

                    # Append new public keys to authorized_keys
                    with open(
                        authorized_keys_path, "a", encoding="utf-8"
                    ) as file_handle:
                        for pub_key in public_keys:
                            pub_key_path = pub_key["path"]
                            with open(pub_key_path, "r", encoding="utf-8") as key_file:
                                key_content = key_file.read().strip()
                                if key_content not in existing_keys:
                                    file_handle.write(key_content + "\n")

                    # Set proper permissions for authorized_keys
                    os.chmod(authorized_keys_path, 0o600)
                    os.chown(authorized_keys_path, user_uid, user_gid)

                    self.logger.info("Updated authorized_keys for user '%s'", username)

                except (OSError, IOError) as error:
                    error_msg = f"Failed to update authorized_keys: {str(error)}"
                    errors.append(error_msg)
                    self.logger.error(error_msg)

            # Prepare result
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

            if len(deployed_keys) == 0:
                result["error"] = "No SSH keys were successfully deployed"

            return result

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
