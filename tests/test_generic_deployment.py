"""
Unit tests for src.sysmanage_agent.operations.generic_deployment module.
Tests for the GenericDeployment.deploy_files() handler.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,redefined-outer-name

import hashlib
import os as _real_os
import tempfile as _real_tempfile
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.generic_deployment import GenericDeployment

_MOD = "src.sysmanage_agent.operations.generic_deployment"

# Used by Section 8.6 SHA-256 / backup-rollback tests below. Tests there use
# real temp files (no mocking of chown/chmod/rename) to exercise the real
# atomic-write + rollback paths. We force owner to the current user so chown
# doesn't require root.
_CURRENT_UID = _real_os.getuid()
_CURRENT_GID = _real_os.getgid()


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


# ============================================================================
# SHA-256 verification (Section 8.6 — file integrity)
# ============================================================================


def _sha256(s: str) -> str:
    """SHA-256 hex digest of a string, encoded as UTF-8."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class TestSha256Verification:
    """Tests for the optional expected_sha256 field on deploy_files."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.deployment = GenericDeployment(self.mock_agent)

    @pytest.mark.asyncio
    async def test_pre_write_hash_mismatch_refuses_deployment(self):
        """If expected_sha256 doesn't match the supplied content, refuse."""
        # Use a real temp directory so we can verify nothing was written
        with _real_tempfile.TemporaryDirectory() as tmpdir:
            target = _real_os.path.join(tmpdir, "myapp.conf")
            params = {
                "files": [
                    {
                        "path": target,
                        "content": "the actual content",
                        "expected_sha256": "0" * 64,  # deliberately wrong
                    }
                ]
            }
            result = await self.deployment.deploy_files(params)

        assert result["success"] is False
        assert result["error_count"] == 1
        assert "Pre-write SHA-256 mismatch" in result["errors"][0]
        # Crucially: the file must NOT exist
        assert not _real_os.path.exists(target)

    @pytest.mark.asyncio
    async def test_pre_write_hash_match_proceeds_to_write(self):
        """When expected_sha256 matches, the file gets written normally."""
        with _real_tempfile.TemporaryDirectory() as tmpdir:
            target = _real_os.path.join(tmpdir, "myapp.conf")
            # Use content with explicit trailing newline so what we hash is
            # exactly what gets written (the deploy code auto-appends one if
            # missing, which would otherwise diverge our test hash).
            content = "good content\n"
            params = {
                "files": [
                    {
                        "path": target,
                        "content": content,
                        "expected_sha256": _sha256(content),
                        "owner_uid": _CURRENT_UID,
                        "owner_gid": _CURRENT_GID,
                    }
                ]
            }
            result = await self.deployment.deploy_files(params)

        assert result["success"] is True
        assert result["deployed_count"] == 1
        assert result["deployed_files"][0]["verified_sha256"] == _sha256(content)

    @pytest.mark.asyncio
    async def test_post_write_hash_mismatch_rolls_back_with_backup(self):
        """If on-disk hash differs from expected after write, restore from backup."""
        with _real_tempfile.TemporaryDirectory() as tmpdir:
            target = _real_os.path.join(tmpdir, "myapp.conf")
            # Pre-existing file with known content
            with open(target, "w", encoding="utf-8") as fobj:
                fobj.write("ORIGINAL")

            # Trick: pass content whose pre-write hash matches expected, but
            # patch _sha256_of_file to return a different hash to simulate
            # a post-write corruption (truncation, encoding bug, etc.).
            # Trailing newline is explicit so the auto-append doesn't change
            # the hash we're verifying.
            content = "new content\n"
            with patch.object(
                self.deployment,
                "_sha256_of_file",
                return_value="ff" * 32,  # not the real hash
            ):
                params = {
                    "files": [
                        {
                            "path": target,
                            "content": content,
                            "expected_sha256": _sha256(content),
                            "backup": True,
                            "owner_uid": _CURRENT_UID,
                            "owner_gid": _CURRENT_GID,
                        }
                    ]
                }
                result = await self.deployment.deploy_files(params)

                # Asserts must run BEFORE the TemporaryDirectory exits or the
                # files we're checking will already be gone.
                assert result["success"] is False
                assert "Post-write SHA-256 mismatch" in result["errors"][0]
                assert "Restored from backup" in result["errors"][0]
                with open(target, "r", encoding="utf-8") as fobj:
                    assert fobj.read() == "ORIGINAL"

    @pytest.mark.asyncio
    async def test_post_write_hash_mismatch_no_backup_leaves_failed_file(self):
        """No backup requested means we report failure but don't rollback."""
        with _real_tempfile.TemporaryDirectory() as tmpdir:
            target = _real_os.path.join(tmpdir, "myapp.conf")
            content = "new content\n"
            with patch.object(
                self.deployment,
                "_sha256_of_file",
                return_value="ff" * 32,
            ):
                params = {
                    "files": [
                        {
                            "path": target,
                            "content": content,
                            "expected_sha256": _sha256(content),
                            # backup intentionally omitted
                            "owner_uid": _CURRENT_UID,
                            "owner_gid": _CURRENT_GID,
                        }
                    ]
                }
                result = await self.deployment.deploy_files(params)

        assert result["success"] is False
        assert "No backup available" in result["errors"][0]


# ============================================================================
# Backup/rollback (Section 8.6 — rollback support)
# ============================================================================


class TestBackupAndRollback:
    """Tests for the optional backup field on deploy_files."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.deployment = GenericDeployment(self.mock_agent)

    @pytest.mark.asyncio
    async def test_backup_created_when_target_exists(self):
        """A .sysmanage.bak copy is left next to the new file on success."""
        with _real_tempfile.TemporaryDirectory() as tmpdir:
            target = _real_os.path.join(tmpdir, "myapp.conf")
            with open(target, "w", encoding="utf-8") as fobj:
                fobj.write("OLD")

            params = {
                "files": [
                    {
                        "path": target,
                        "content": "NEW",
                        "backup": True,
                        "owner_uid": _CURRENT_UID,
                        "owner_gid": _CURRENT_GID,
                    }
                ]
            }
            result = await self.deployment.deploy_files(params)

            # Asserts must run BEFORE TemporaryDirectory exits.
            assert result["success"] is True
            backup = target + ".sysmanage.bak"
            assert _real_os.path.exists(backup)
            with open(backup, "r", encoding="utf-8") as fobj:
                assert fobj.read() == "OLD"

    @pytest.mark.asyncio
    async def test_no_backup_when_target_does_not_exist(self):
        """First-time deploy needs no backup; the result reflects that."""
        with _real_tempfile.TemporaryDirectory() as tmpdir:
            target = _real_os.path.join(tmpdir, "myapp.conf")
            params = {
                "files": [
                    {
                        "path": target,
                        "content": "NEW",
                        "backup": True,
                        "owner_uid": _CURRENT_UID,
                        "owner_gid": _CURRENT_GID,
                    }
                ]
            }
            result = await self.deployment.deploy_files(params)

        assert result["success"] is True
        assert result["deployed_files"][0]["backup_path"] is None


class TestApplyDeploymentPlan:
    """Tests for GenericDeployment.apply_deployment_plan() handler."""

    def setup_method(self):
        """Set up a deployment with a mocked agent."""
        self.mock_agent = Mock()
        self.mock_agent.send_message = AsyncMock()
        self.mock_agent.create_message = Mock(return_value={"type": "test"})
        self.mock_agent.install_package = AsyncMock(return_value={"success": True})
        self.mock_agent.uninstall_packages = AsyncMock(return_value={"success": True})
        self.mock_agent.message_processor = Mock()
        self.mock_agent.message_processor._handle_service_control = AsyncMock(
            return_value={"success": True}
        )
        self.deployment = GenericDeployment(self.mock_agent)

    @pytest.mark.asyncio
    async def test_empty_plan_succeeds(self):
        """An empty plan is a no-op success."""
        result = await self.deployment.apply_deployment_plan({"plan": {}})
        assert result["success"] is True
        assert result["failed_step"] is None
        assert result["errors"] == []

    @pytest.mark.asyncio
    async def test_plan_runs_packages_then_files_then_commands_then_services(self):
        """Steps execute in canonical order; on success, all branches are populated."""
        plan = {
            "packages": ["clamav"],
            "files": [{"path": "/tmp/a", "content": "x"}],
            "commands": [{"argv": ["/bin/true"]}],
            "service_actions": [{"service": "clamav", "action": "start"}],
        }
        # Stub deploy_files to succeed without touching disk.
        self.deployment.deploy_files = AsyncMock(
            return_value={
                "success": True,
                "deployed_files": [{"path": "/tmp/a"}],
                "errors": [],
            }
        )
        result = await self.deployment.apply_deployment_plan({"plan": plan})

        assert result["success"] is True
        assert "packages" in result["results"]
        assert "files" in result["results"]
        assert "commands" in result["results"]
        assert "service_actions" in result["results"]

    @pytest.mark.asyncio
    async def test_plan_packages_can_be_dicts_with_manager_hint(self):
        """Package entries may be {manager, name} for platforms with multiple managers."""
        plan = {"packages": [{"manager": "pkg", "name": "clamav"}]}
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["success"] is True
        # install_package was called with the right manager hint.
        call_args = self.mock_agent.install_package.call_args[0][0]
        assert call_args["package_name"] == "clamav"
        assert call_args["package_manager"] == "pkg"

    @pytest.mark.asyncio
    async def test_plan_command_failure_aborts_when_not_ignore_errors(self):
        """A failing command with ignore_errors=False stops the plan."""
        plan = {
            "commands": [
                {"argv": ["/bin/false"], "ignore_errors": False},
                {"argv": ["/bin/true"]},
            ],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["success"] is False
        assert result["failed_step"] == "commands"
        # Only the first command should have run.
        assert len(result["results"]["commands"]) == 1

    @pytest.mark.asyncio
    async def test_plan_command_failure_ignored_when_ignore_errors(self):
        """A failing command with ignore_errors=True does NOT abort the plan."""
        plan = {
            "commands": [
                {"argv": ["/bin/false"], "ignore_errors": True},
                {"argv": ["/bin/true"]},
            ],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["success"] is True
        assert result["failed_step"] is None
        # Both commands should have run.
        assert len(result["results"]["commands"]) == 2

    @pytest.mark.asyncio
    async def test_plan_command_timeout_kills_process(self):
        """A command exceeding its timeout is killed and reported as failure."""
        plan = {
            "commands": [
                {"argv": ["/bin/sleep", "5"], "timeout": 1, "ignore_errors": True},
            ],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        # ignore_errors -> the plan still succeeds, but the command result
        # records the timeout.
        assert result["results"]["commands"][0]["success"] is False
        assert "timeout" in result["results"]["commands"][0].get("error", "")

    @pytest.mark.asyncio
    async def test_plan_command_filenotfound_is_a_failure(self):
        """A command pointing at a missing binary returns a clean failure."""
        plan = {
            "commands": [
                {"argv": ["/no/such/bin"], "ignore_errors": True},
            ],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["results"]["commands"][0]["success"] is False

    @pytest.mark.asyncio
    async def test_plan_service_actions_grouped_by_action(self):
        """Multiple services with the same action are grouped into one call."""
        plan = {
            "service_actions": [
                {"service": "clamd", "action": "start"},
                {"service": "freshclam", "action": "start"},
                {"service": "clamd", "action": "enable"},
            ],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["success"] is True
        # Two distinct actions emitted: enable (first) then start.
        actions_used = [r["action"] for r in result["results"]["service_actions"]]
        assert actions_used == ["enable", "start"]

    @pytest.mark.asyncio
    async def test_plan_service_action_failure_aborts(self):
        """A failed service_control returns failed_step='service_actions'."""
        self.mock_agent.message_processor._handle_service_control = AsyncMock(
            return_value={"success": False, "error": "unit not found"}
        )
        plan = {
            "service_actions": [{"service": "clamd", "action": "start"}],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["success"] is False
        assert result["failed_step"] == "service_actions"

    @pytest.mark.asyncio
    async def test_plan_packages_to_remove_runs_last(self):
        """packages_to_remove fires after services have been stopped."""
        plan = {
            "service_actions": [{"service": "clamd", "action": "stop"}],
            "packages_to_remove": ["clamav"],
        }
        result = await self.deployment.apply_deployment_plan({"plan": plan})
        assert result["success"] is True
        assert "packages_to_remove" in result["results"]
        # uninstall_packages called.
        assert self.mock_agent.uninstall_packages.called

    @pytest.mark.asyncio
    async def test_plan_can_be_passed_inline_or_under_plan_key(self):
        """parameters['plan'] and parameters itself both work as the plan dict."""
        # Inline (no "plan" wrapper)
        result_inline = await self.deployment.apply_deployment_plan(
            {"commands": [{"argv": ["/bin/true"]}]}
        )
        # Wrapped
        result_wrapped = await self.deployment.apply_deployment_plan(
            {"plan": {"commands": [{"argv": ["/bin/true"]}]}}
        )
        assert result_inline["success"] is True
        assert result_wrapped["success"] is True
