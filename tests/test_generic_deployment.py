"""
Unit tests for src.sysmanage_agent.operations.generic_deployment module.
Tests for the GenericDeployment.deploy_files() handler.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,redefined-outer-name

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.generic_deployment import GenericDeployment

_MOD = "src.sysmanage_agent.operations.generic_deployment"


@pytest.fixture
def file_deploy_mocks():
    """Provide consolidated mocks for file deployment tests."""
    with (
        patch(f"{_MOD}.tempfile.mkstemp") as mkstemp,
        patch(f"{_MOD}.os.unlink") as _unlink,
        patch(f"{_MOD}.os.path.exists", return_value=False) as _exists,
        patch(f"{_MOD}.os.makedirs") as makedirs,
        patch(f"{_MOD}.os.chown") as chown,
        patch(f"{_MOD}.os.chmod") as chmod,
        patch(f"{_MOD}.os.rename") as rename,
        patch(f"{_MOD}.aiofiles.open") as aiofiles_open,
    ):
        mock_file = AsyncMock()
        aiofiles_open.return_value.__aenter__.return_value = mock_file
        yield {
            "mkstemp": mkstemp,
            "makedirs": makedirs,
            "chown": chown,
            "chmod": chmod,
            "rename": rename,
            "aiofiles_open": aiofiles_open,
            "mock_file": mock_file,
        }


class TestDeployFiles:
    """Test cases for GenericDeployment.deploy_files() method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.deployment = GenericDeployment(self.mock_agent)

    @pytest.mark.asyncio
    async def test_deploy_files_success(self, file_deploy_mocks):
        """Deploy 2 files successfully, verify both are deployed."""
        file_deploy_mocks["mkstemp"].side_effect = [
            (10, "/etc/.sysmanage_deploy_abc"),
            (11, "/opt/.sysmanage_deploy_def"),
        ]

        parameters = {
            "files": [
                {
                    "path": "/etc/myapp.conf",
                    "content": "key=value",
                    "permissions": "0644",
                    "owner_uid": 0,
                    "owner_gid": 0,
                },
                {
                    "path": "/opt/myapp/config.yaml",
                    "content": "setting: true",
                    "permissions": "0644",
                    "owner_uid": 0,
                    "owner_gid": 0,
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert result["success"] is True
        assert result["deployed_count"] == 2
        assert len(result["deployed_files"]) == 2
        assert len(result["errors"]) == 0

    @pytest.mark.asyncio
    async def test_deploy_files_empty_list(self):
        """Pass empty files list, expect success False."""
        result = await self.deployment.deploy_files({"files": []})

        assert result["success"] is False
        assert "No files provided" in result.get("error", "")

    @pytest.mark.asyncio
    async def test_deploy_files_missing_path(self):
        """File entry missing 'path', expect error in errors list."""
        parameters = {
            "files": [
                {"content": "some content", "permissions": "0644"},
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert any("missing 'path'" in err for err in result["errors"])

    @pytest.mark.asyncio
    async def test_deploy_files_missing_content(self):
        """File entry missing 'content', expect error in errors list."""
        parameters = {
            "files": [
                {"path": "/etc/myapp.conf", "permissions": "0644"},
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert any("missing 'content'" in err for err in result["errors"])

    @pytest.mark.asyncio
    async def test_deploy_files_permission_error(self, file_deploy_mocks):
        """Mock os.rename to raise PermissionError, expect error."""
        file_deploy_mocks["mkstemp"].return_value = (10, "/etc/.sysmanage_deploy_abc")
        file_deploy_mocks["rename"].side_effect = PermissionError("Permission denied")

        parameters = {
            "files": [
                {
                    "path": "/etc/myapp.conf",
                    "content": "key=value",
                    "permissions": "0644",
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert result["success"] is False
        assert result["error_count"] > 0

    @pytest.mark.asyncio
    async def test_deploy_files_partial_success(self, file_deploy_mocks):
        """2 files: first succeeds, second fails with permission error."""
        file_deploy_mocks["mkstemp"].side_effect = [
            (10, "/etc/.sysmanage_deploy_abc"),
            (11, "/opt/.sysmanage_deploy_def"),
        ]

        # First rename succeeds, second raises PermissionError
        file_deploy_mocks["rename"].side_effect = [
            None,
            PermissionError("Permission denied"),
        ]

        parameters = {
            "files": [
                {
                    "path": "/etc/myapp.conf",
                    "content": "key=value",
                    "permissions": "0644",
                },
                {
                    "path": "/opt/protected.conf",
                    "content": "secret=value",
                    "permissions": "0600",
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        # First file succeeded so overall success is True, but there are errors
        assert result["success"] is True
        assert result["deployed_count"] == 1
        assert result["error_count"] == 1

    @pytest.mark.asyncio
    async def test_deploy_files_sets_permissions(self, file_deploy_mocks):
        """Verify os.chmod called with correct octal mode from '0600' string."""
        file_deploy_mocks["mkstemp"].return_value = (10, "/etc/.sysmanage_deploy_abc")

        parameters = {
            "files": [
                {
                    "path": "/etc/secret.conf",
                    "content": "secret=value",
                    "permissions": "0600",
                    "owner_uid": 0,
                    "owner_gid": 0,
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert result["success"] is True
        file_deploy_mocks["chmod"].assert_called_once_with(
            "/etc/.sysmanage_deploy_abc", 0o600
        )

    @pytest.mark.asyncio
    async def test_deploy_files_sets_ownership(self, file_deploy_mocks):
        """Verify os.chown called with correct uid/gid."""
        file_deploy_mocks["mkstemp"].return_value = (
            10,
            "/var/lib/.sysmanage_deploy_abc",
        )

        parameters = {
            "files": [
                {
                    "path": "/var/lib/myapp/data.conf",
                    "content": "data=here",
                    "permissions": "0644",
                    "owner_uid": 1000,
                    "owner_gid": 1000,
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert result["success"] is True
        file_deploy_mocks["chown"].assert_called_once_with(
            "/var/lib/.sysmanage_deploy_abc", 1000, 1000
        )

    @pytest.mark.asyncio
    async def test_deploy_files_creates_parent_dir(self, file_deploy_mocks):
        """Verify os.makedirs called for parent directory."""
        file_deploy_mocks["mkstemp"].return_value = (
            10,
            "/opt/newapp/.sysmanage_deploy_abc",
        )

        parameters = {
            "files": [
                {
                    "path": "/opt/newapp/config.yaml",
                    "content": "enabled: true",
                    "permissions": "0644",
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert result["success"] is True
        file_deploy_mocks["makedirs"].assert_called_once_with(
            "/opt/newapp", mode=0o755, exist_ok=True
        )

    @pytest.mark.asyncio
    async def test_deploy_files_atomic_write(self, file_deploy_mocks):
        """Verify tempfile.mkstemp and os.rename are used for atomic write."""
        file_deploy_mocks["mkstemp"].return_value = (10, "/etc/.sysmanage_deploy_abc")

        parameters = {
            "files": [
                {
                    "path": "/etc/myapp.conf",
                    "content": "key=value",
                    "permissions": "0644",
                },
            ]
        }

        result = await self.deployment.deploy_files(parameters)

        assert result["success"] is True
        # Verify atomic write pattern: mkstemp creates temp, rename moves it
        file_deploy_mocks["mkstemp"].assert_called_once_with(
            dir="/etc", prefix=".sysmanage_deploy_"
        )
        file_deploy_mocks["rename"].assert_called_once_with(
            "/etc/.sysmanage_deploy_abc", "/etc/myapp.conf"
        )
