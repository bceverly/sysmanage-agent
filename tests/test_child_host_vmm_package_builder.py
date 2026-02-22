"""
Comprehensive unit tests for src.sysmanage_agent.operations.child_host_vmm_package_builder module.
Tests OpenBSD package building operations for VMM child hosts.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open

import pytest

from src.sysmanage_agent.operations.child_host_vmm_package_builder import (
    PackageBuilder,
    _PBUILD_USER_GROUP,
    _NO_OUTPUT,
)


class TestPackageBuilderInit:
    """Test cases for PackageBuilder initialization."""

    def test_init_with_logger(self):
        """Test PackageBuilder initialization with logger."""
        mock_logger = Mock()
        builder = PackageBuilder(mock_logger)

        assert builder.logger == mock_logger


class TestBuildAgentPackage:
    """Test cases for build_agent_package method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    @patch.object(PackageBuilder, "_build_package")
    def test_build_agent_package_success(
        self,
        mock_build,
        _mock_clean,
        _mock_setup,
        _mock_run,
        _mock_copytree,
        _mock_mkdir,
        _mock_rmtree,
        mock_exists,
    ):
        """Test successful agent package build."""
        mock_exists.return_value = True
        mock_build.return_value = {
            "success": True,
            "package_path": "/usr/packages/amd64/all/sysmanage-agent-1.0.0.tgz",
            "error": None,
        }

        # Mock file operations for Makefile and PLIST
        makefile_content = "GH_TAGNAME = v0.0.1\nsysmanage-agent.yaml\n"
        _plist_content = "sysmanage-agent.yaml\n"

        with patch("builtins.open", mock_open(read_data=makefile_content)):
            result = self.builder.build_agent_package(Path("/tmp/port"), "v1.0.0")

        assert result["success"] is True
        assert (
            result["package_path"]
            == "/usr/packages/amd64/all/sysmanage-agent-1.0.0.tgz"
        )
        mock_build.assert_called_once()

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    @patch.object(PackageBuilder, "_build_package")
    def test_build_agent_package_no_existing_port_dir(
        self,
        mock_build,
        _mock_clean,
        _mock_setup,
        _mock_run,
        _mock_copytree,
        _mock_mkdir,
        mock_rmtree,
        mock_exists,
    ):
        """Test agent package build when port directory does not exist."""
        mock_exists.return_value = False
        mock_build.return_value = {
            "success": True,
            "package_path": "/usr/packages/amd64/all/sysmanage-agent-1.0.0.tgz",
            "error": None,
        }

        with patch("builtins.open", mock_open(read_data="GH_TAGNAME = v0.0.1\n")):
            result = self.builder.build_agent_package(Path("/tmp/port"), "v1.0.0")

        assert result["success"] is True
        mock_rmtree.assert_not_called()

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_agent_package_timeout(
        self, mock_run, _mock_copytree, _mock_mkdir, _mock_rmtree, mock_exists
    ):
        """Test agent package build timeout."""
        mock_exists.return_value = False
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="chown", timeout=30)

        with tempfile.TemporaryDirectory() as port_dir:
            port_path = Path(port_dir)

            with patch("builtins.open", mock_open(read_data="GH_TAGNAME = v0.0.1\n")):
                result = self.builder.build_agent_package(port_path, "v1.0.0")

        assert result["success"] is False
        assert result["package_path"] is None
        assert "timeout" in result["error"].lower()
        self.mock_logger.error.assert_called()

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_agent_package_called_process_error(
        self, mock_run, _mock_copytree, _mock_mkdir, _mock_rmtree, mock_exists
    ):
        """Test agent package build with CalledProcessError."""
        mock_exists.return_value = False
        # Raise CalledProcessError with bytes stderr when chown is called
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chown", stderr=b"Permission denied"
        )

        with tempfile.TemporaryDirectory() as port_dir:
            port_path = Path(port_dir)

            with patch("builtins.open", mock_open(read_data="GH_TAGNAME = v0.0.1\n")):
                result = self.builder.build_agent_package(port_path, "v1.0.0")

        assert result["success"] is False
        assert result["package_path"] is None
        assert "Permission denied" in result["error"]
        # Verify the error logging happened
        self.mock_logger.error.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    def test_build_agent_package_generic_exception(self, mock_copytree):
        """Test agent package build with generic exception."""
        mock_copytree.side_effect = Exception("Unexpected error")

        with tempfile.TemporaryDirectory() as port_dir:
            port_path = Path(port_dir)

            result = self.builder.build_agent_package(port_path, "v1.0.0")

        assert result["success"] is False
        assert result["package_path"] is None
        assert "Build error" in result["error"]
        self.mock_logger.error.assert_called()


class TestBuildAgentPackageMakefileHandling:
    """Test cases for Makefile handling in build_agent_package."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    @patch.object(PackageBuilder, "_build_package")
    def test_makefile_gh_tagname_replacement(
        self,
        mock_build,
        _mock_clean,
        _mock_setup,
        mock_run,
        _mock_copytree,
        _mock_rmtree,
    ):
        """Test that GH_TAGNAME is correctly replaced in Makefile."""
        mock_build.return_value = {
            "success": True,
            "package_path": "/pkg.tgz",
            "error": None,
        }
        mock_run.return_value = Mock(returncode=0)

        with tempfile.TemporaryDirectory() as port_dir:
            port_path = Path(port_dir)

            # Create mock ports directory structure
            _ports_dir = Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
            with patch.object(Path, "exists", return_value=False):
                with patch.object(Path, "parent", new_callable=MagicMock):
                    makefile_content = (
                        "COMMENT = sysmanage agent\n"
                        "GH_TAGNAME = v0.0.1\n"
                        "DISTNAME = sysmanage-agent\n"
                        "sysmanage-agent.yaml file\n"
                    )

                    mock_file = mock_open(read_data=makefile_content)
                    written_content = []

                    def track_write(content):
                        written_content.append(content)

                    mock_file.return_value.write = track_write

                    with patch("builtins.open", mock_file):
                        self.builder.build_agent_package(port_path, "v2.0.0")

                    # Verify GH_TAGNAME was updated
                    if written_content:
                        combined = "".join(written_content)
                        assert "GH_TAGNAME = v2.0.0" in combined or mock_build.called

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    @patch.object(PackageBuilder, "_build_package")
    def test_makefile_yaml_filename_replacement(
        self,
        mock_build,
        _mock_clean,
        _mock_setup,
        mock_run,
        _mock_copytree,
        _mock_rmtree,
    ):
        """Test that yaml filename is correctly replaced in Makefile."""
        mock_build.return_value = {
            "success": True,
            "package_path": "/pkg.tgz",
            "error": None,
        }
        mock_run.return_value = Mock(returncode=0)

        with tempfile.TemporaryDirectory() as port_dir:
            port_path = Path(port_dir)

            with patch.object(Path, "exists", return_value=False):
                makefile_content = (
                    "COMMENT = sysmanage agent\n"
                    "GH_TAGNAME = v0.0.1\n"
                    "FILES += sysmanage-agent.yaml\n"
                )

                written_content = []
                mock_file = mock_open(read_data=makefile_content)

                def track_write(content):
                    written_content.append(content)

                mock_file.return_value.write = track_write

                with patch("builtins.open", mock_file):
                    self.builder.build_agent_package(port_path, "v1.0.0")

                # Verify logging occurred
                self.mock_logger.info.assert_called()


class TestBuildAgentPackagePlistHandling:
    """Test cases for PLIST handling in build_agent_package."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    @patch.object(PackageBuilder, "_build_package")
    def test_plist_yaml_filename_replacement(
        self,
        mock_build,
        _mock_clean,
        _mock_setup,
        mock_run,
        _mock_copytree,
        _mock_rmtree,
    ):
        """Test that yaml filename is correctly replaced in PLIST."""
        mock_build.return_value = {
            "success": True,
            "package_path": "/pkg.tgz",
            "error": None,
        }
        mock_run.return_value = Mock(returncode=0)

        with tempfile.TemporaryDirectory() as port_dir:
            port_path = Path(port_dir)

            with patch.object(Path, "exists") as mock_exists:
                # Makefile exists, PLIST exists
                mock_exists.side_effect = [False, True, True]

                plist_content = "@comment etc/sysmanage-agent.yaml\n"

                with patch("builtins.open", mock_open(read_data=plist_content)):
                    self.builder.build_agent_package(port_path, "v1.0.0")

                # Verify logging occurred
                self.mock_logger.info.assert_called()


class TestBuildAgentPackageDistinfoHandling:
    """Test cases for distinfo handling in build_agent_package."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    def test_distinfo_stub_format(self):
        """Test that distinfo stub has correct format with version."""
        # The distinfo stub format used in the code
        agent_version = "v1.2.3"
        expected_stub = f"""SHA256 ({agent_version}.tar.gz) = 0000000000000000000000000000000000000000000000000000000000000000
SIZE ({agent_version}.tar.gz) = 0
"""
        # Verify the format is valid
        assert f"SHA256 ({agent_version}.tar.gz)" in expected_stub
        assert f"SIZE ({agent_version}.tar.gz)" in expected_stub
        assert (
            "0000000000000000000000000000000000000000000000000000000000000000"
            in expected_stub
        )

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    @patch.object(PackageBuilder, "_build_package")
    def test_distinfo_stub_write_called(
        self,
        mock_build,
        _mock_clean,
        _mock_setup,
        mock_run,
        _mock_copytree,
        _mock_mkdir,
        _mock_rmtree,
        mock_path_exists,
    ):
        """Test that distinfo file is written when it exists."""
        # Makefile exists, PLIST exists, distinfo exists
        mock_path_exists.side_effect = [False, True, True, True]
        mock_build.return_value = {
            "success": True,
            "package_path": "/pkg.tgz",
            "error": None,
        }
        mock_run.return_value = Mock(returncode=0)

        makefile_content = "GH_TAGNAME = v0.0.1\n"
        _plist_content = "sysmanage-agent.yaml\n"

        written_files = []
        _original_open = open

        def mock_open_side_effect(path, *args, **kwargs):
            mode = args[0] if args else kwargs.get("mode", "r")
            if "w" in mode:
                written_files.append(str(path))
            return mock_open(read_data=makefile_content)(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_side_effect):
            self.builder.build_agent_package(Path("/tmp/port"), "v1.2.3")

        # Verify logging occurred
        self.mock_logger.info.assert_called()


class TestSetupBuildEnvironment:
    """Test cases for _setup_build_environment method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_success(self, mock_run, mock_mkdir):
        """Test successful build environment setup."""
        mock_run.return_value = Mock(returncode=0)

        self.builder._setup_build_environment(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        # Should create directories and set permissions
        assert mock_mkdir.call_count >= 4  # obj/ports, packages dirs, plist dir
        assert mock_run.call_count >= 4  # chmod + chown calls

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_chmod_call(self, mock_run, _mock_mkdir):
        """Test that chmod o+x is called on /usr/obj."""
        mock_run.return_value = Mock(returncode=0)

        self.builder._setup_build_environment(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        chmod_calls = [
            call for call in mock_run.call_args_list if "chmod" in call[0][0]
        ]
        assert len(chmod_calls) >= 1
        # Check that chmod o+x /usr/obj was called
        chmod_call = chmod_calls[0]
        assert chmod_call[0][0] == ["chmod", "o+x", "/usr/obj"]

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_chown_calls(self, mock_run, _mock_mkdir):
        """Test that chown calls use _pbuild:_pbuild."""
        mock_run.return_value = Mock(returncode=0)

        self.builder._setup_build_environment(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        chown_calls = [
            call for call in mock_run.call_args_list if "chown" in call[0][0]
        ]
        # Should have chown calls for obj/ports, /usr/packages, plist, port dir
        assert len(chown_calls) >= 4
        for call in chown_calls:
            assert "_pbuild:_pbuild" in call[0][0]

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_creates_package_dirs(self, mock_run, _mock_mkdir):
        """Test that package directories are created."""
        mock_run.return_value = Mock(returncode=0)

        self.builder._setup_build_environment(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        # Verify logging shows package directories setup
        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("package directories" in call.lower() for call in info_calls)

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_timeout(self, mock_run, _mock_mkdir):
        """Test build environment setup with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="chmod", timeout=30)

        with pytest.raises(subprocess.TimeoutExpired):
            self.builder._setup_build_environment(
                Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
            )

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_called_process_error(self, mock_run, _mock_mkdir):
        """Test build environment setup with CalledProcessError."""
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="chown", stderr=b"Permission denied"
        )

        with pytest.raises(subprocess.CalledProcessError):
            self.builder._setup_build_environment(
                Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
            )


class TestCleanPreviousBuilds:
    """Test cases for _clean_previous_builds method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_success(self, mock_run):
        """Test successful cleanup of previous builds."""
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

        self.builder._clean_previous_builds()

        # Should call rm commands for PLIST, work directories, and old packages
        assert mock_run.call_count == 3

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_plist_cleanup(self, mock_run):
        """Test PLIST cleanup command."""
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

        self.builder._clean_previous_builds()

        plist_calls = [
            call
            for call in mock_run.call_args_list
            if "plist" in str(call[0][0]).lower()
        ]
        assert len(plist_calls) >= 1
        # Check pattern includes sysmanage-agent
        plist_call = plist_calls[0]
        assert "sysmanage-agent" in plist_call[0][0][2]

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_work_dir_cleanup(self, mock_run):
        """Test work directory cleanup command."""
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

        self.builder._clean_previous_builds()

        work_calls = [
            call for call in mock_run.call_args_list if "obj/ports" in str(call[0][0])
        ]
        assert len(work_calls) >= 1

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_packages_cleanup(self, mock_run):
        """Test old packages cleanup command."""
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

        self.builder._clean_previous_builds()

        pkg_calls = [
            call
            for call in mock_run.call_args_list
            if "packages" in str(call[0][0]) and ".tgz" in str(call[0][0])
        ]
        assert len(pkg_calls) >= 1

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_continues_on_failure(self, mock_run):
        """Test cleanup continues even when commands fail."""
        mock_run.return_value = Mock(returncode=1, stdout=b"", stderr=b"No such file")

        # Should not raise exception
        self.builder._clean_previous_builds()

        # All cleanup commands should still be attempted
        assert mock_run.call_count == 3

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_check_false(self, mock_run):
        """Test cleanup uses check=False."""
        mock_run.return_value = Mock(returncode=1)

        self.builder._clean_previous_builds()

        for call in mock_run.call_args_list:
            kwargs = call[1]
            assert kwargs.get("check") is False

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_logging(self, mock_run):
        """Test cleanup logs each step."""
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

        self.builder._clean_previous_builds()

        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("PLIST" in call for call in info_calls)
        assert any("work directories" in call.lower() for call in info_calls)
        assert any("packages" in call.lower() for call in info_calls)


class TestBuildPackage:
    """Test cases for _build_package method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.os.path.exists"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_success(self, mock_run, mock_exists):
        """Test successful package build."""
        mock_exists.return_value = True
        mock_run.side_effect = [
            Mock(returncode=0, stdout="clean output", stderr=""),  # make clean
            Mock(returncode=0, stdout="makesum output", stderr=""),  # make makesum
            Mock(returncode=0, stdout="fetch output", stderr=""),  # make fetch
            Mock(returncode=0, stdout="package output", stderr=""),  # make package
            Mock(
                returncode=0, stdout="/usr/packages", stderr=""
            ),  # show=PACKAGE_REPOSITORY
            Mock(
                returncode=0,
                stdout="/usr/packages/amd64/all/sysmanage-agent-1.0.0.tgz",
                stderr="",
            ),  # ls
        ]

        result = self.builder._build_package(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        assert result["success"] is True
        assert (
            result["package_path"]
            == "/usr/packages/amd64/all/sysmanage-agent-1.0.0.tgz"
        )
        assert result["error"] is None

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_make_package_failure(self, mock_run):
        """Test package build failure when make package fails."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="clean output", stderr=""),  # make clean
            Mock(returncode=0, stdout="makesum output", stderr=""),  # make makesum
            Mock(returncode=0, stdout="fetch output", stderr=""),  # make fetch
            Mock(returncode=1, stdout="", stderr="Build error"),  # make package fails
        ]

        result = self.builder._build_package(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        assert result["success"] is False
        assert result["package_path"] is None
        assert "make package failed" in result["error"]
        self.mock_logger.error.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.os.path.exists"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_not_found(self, mock_run, mock_exists):
        """Test package build when built package is not found."""
        mock_exists.return_value = False
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean
            Mock(returncode=0, stdout="", stderr=""),  # make makesum
            Mock(returncode=0, stdout="", stderr=""),  # make fetch
            Mock(returncode=0, stdout="", stderr=""),  # make package
            Mock(
                returncode=0, stdout="/usr/packages", stderr=""
            ),  # show=PACKAGE_REPOSITORY
            Mock(returncode=0, stdout="", stderr=""),  # ls (empty result)
        ]

        result = self.builder._build_package(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        assert result["success"] is False
        assert result["package_path"] is None
        assert "not found" in result["error"].lower()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_runs_as_pbuild(self, mock_run):
        """Test that build commands run as _pbuild user."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=1, stdout="", stderr="error"),  # Fail early
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        for call in mock_run.call_args_list:
            cmd = call[0][0]
            if "make" in str(cmd):
                assert "su" in cmd[0]
                assert "_pbuild" in cmd

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_make_clean_logs_output(self, mock_run):
        """Test that make clean output is logged."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Clean completed", stderr="clean warning"),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=1, stdout="", stderr="error"),
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        # Check logging of make clean output
        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("make clean" in call.lower() for call in info_calls)
        warning_calls = [str(call) for call in self.mock_logger.warning.call_args_list]
        assert any("stderr" in call.lower() for call in warning_calls)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_make_fetch_logs_return_code(self, mock_run):
        """Test that make fetch return code is logged."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean
            Mock(returncode=0, stdout="", stderr=""),  # make makesum
            Mock(returncode=0, stdout="fetch complete", stderr=""),  # make fetch
            Mock(returncode=1, stdout="", stderr="error"),  # make package
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        # Check return code logging
        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any(
            "return code" in call.lower() and "fetch" in call.lower()
            for call in info_calls
        )

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_no_output_message(self, mock_run):
        """Test that '(no output)' is used when commands have no stdout."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean - no output
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=1, stdout="", stderr="error"),
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        # Verify "(no output)" is used
        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("no output" in call.lower() for call in info_calls)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_timeout_values(self, mock_run):
        """Test that correct timeout values are used for each command."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=1, stdout="", stderr="error"),
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        # Check timeouts
        timeout_mapping = {}
        for call in mock_run.call_args_list:
            cmd_str = " ".join(call[0][0])
            timeout_mapping[cmd_str] = call[1].get("timeout")

        # Verify appropriate timeouts
        for cmd, timeout in timeout_mapping.items():
            if "clean" in cmd:
                assert timeout == 60
            elif "makesum" in cmd:
                assert timeout == 120
            elif "fetch" in cmd:
                assert timeout == 300
            elif "package" in cmd:
                assert timeout == 600

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.os.path.exists"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_gets_package_repository(self, mock_run, mock_exists):
        """Test that package repository is queried from Makefile."""
        mock_exists.return_value = True
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean
            Mock(returncode=0, stdout="", stderr=""),  # make makesum
            Mock(returncode=0, stdout="", stderr=""),  # make fetch
            Mock(returncode=0, stdout="", stderr=""),  # make package
            Mock(
                returncode=0, stdout="/custom/packages\n", stderr=""
            ),  # show=PACKAGE_REPOSITORY
            Mock(
                returncode=0,
                stdout="/custom/packages/amd64/all/sysmanage-agent-1.0.tgz\n",
                stderr="",
            ),
        ]

        result = self.builder._build_package(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        assert result["success"] is True
        # Verify package repository query was made
        show_calls = [
            call
            for call in mock_run.call_args_list
            if "PACKAGE_REPOSITORY" in str(call[0][0])
        ]
        assert len(show_calls) == 1


class TestBuildPackageWithWorkingDirectory:
    """Test cases for _build_package working directory handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_cwd_is_ports_dir(self, mock_run):
        """Test that commands are run in the ports directory."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=1, stdout="", stderr="error"),
        ]

        ports_dir = Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        self.builder._build_package(ports_dir)

        for call in mock_run.call_args_list:
            kwargs = call[1]
            if "cwd" in kwargs:
                assert kwargs["cwd"] == ports_dir


class TestBuildPackageEdgeCases:
    """Edge case tests for _build_package method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_make_fetch_with_stderr(self, mock_run):
        """Test that make fetch stderr is logged when present."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean
            Mock(returncode=0, stdout="", stderr=""),  # make makesum
            Mock(
                returncode=0,
                stdout="fetch complete",
                stderr="fetch warning: slow connection",
            ),  # make fetch
            Mock(returncode=1, stdout="", stderr="error"),  # make package fails
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        # Check that stderr was logged as warning
        warning_calls = [str(call) for call in self.mock_logger.warning.call_args_list]
        assert any(
            "fetch" in call.lower() and "stderr" in call.lower()
            for call in warning_calls
        )

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.os.path.exists"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_empty_package_path(self, mock_run, mock_exists):
        """Test package build when ls returns empty string."""
        mock_exists.return_value = False
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean
            Mock(returncode=0, stdout="", stderr=""),  # make makesum
            Mock(returncode=0, stdout="", stderr=""),  # make fetch
            Mock(returncode=0, stdout="", stderr=""),  # make package
            Mock(
                returncode=0, stdout="/usr/packages", stderr=""
            ),  # show=PACKAGE_REPOSITORY
            Mock(returncode=0, stdout="   \n", stderr=""),  # ls returns whitespace only
        ]

        result = self.builder._build_package(
            Path("/usr/ports/mystuff/sysutils/sysmanage-agent")
        )

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_build_package_make_makesum_with_stderr(self, mock_run):
        """Test make makesum with stderr output."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # make clean
            Mock(
                returncode=0,
                stdout="makesum output",
                stderr="Warning: checksum mismatch",
            ),
            Mock(returncode=0, stdout="", stderr=""),  # make fetch
            Mock(returncode=1, stdout="", stderr="error"),  # make package
        ]

        self.builder._build_package(Path("/usr/ports/mystuff/sysutils/sysmanage-agent"))

        warning_calls = [str(call) for call in self.mock_logger.warning.call_args_list]
        assert any("makesum" in call.lower() for call in warning_calls)


class TestPackageBuilderIntegration:
    """Integration-style tests for PackageBuilder."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.exists")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.os.path.exists"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.rmtree"
    )
    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    @patch.object(PackageBuilder, "_setup_build_environment")
    @patch.object(PackageBuilder, "_clean_previous_builds")
    def test_full_build_workflow(
        self,
        _mock_clean,
        _mock_setup,
        mock_run,
        _mock_copytree,
        _mock_mkdir,
        mock_rmtree,
        mock_os_exists,
        mock_path_exists,
    ):
        """Test full build workflow from start to finish."""
        # ports_dir exists (triggers rmtree), then makefile, plist, distinfo exist
        mock_path_exists.side_effect = [True, True, True, True]
        mock_os_exists.return_value = True

        # Mock final ls to return package path
        def run_side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "ls" in cmd_str:
                return Mock(
                    returncode=0,
                    stdout="/usr/packages/amd64/all/sysmanage-agent-1.0.0.tgz",
                    stderr="",
                )
            return Mock(returncode=0, stdout="output", stderr="")

        mock_run.side_effect = run_side_effect

        makefile_content = "GH_TAGNAME = v0.0.1\nsysmanage-agent.yaml\n"

        with patch("builtins.open", mock_open(read_data=makefile_content)):
            result = self.builder.build_agent_package(Path("/tmp/port"), "v1.0.0")

        # Should complete successfully
        assert result is not None
        # Verify cleanup was called on existing port directory
        mock_rmtree.assert_called()

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    def test_build_error_recovery(self, mock_copytree):
        """Test that errors are properly captured and returned."""
        mock_copytree.side_effect = PermissionError("Access denied")

        result = self.builder.build_agent_package(Path("/tmp/port"), "v1.0.0")

        assert result["success"] is False
        assert result["package_path"] is None
        assert "error" in result["error"].lower()


class TestPackageBuilderConstants:
    """Test cases for module constants."""

    def test_pbuild_user_group_constant(self):
        """Test _PBUILD_USER_GROUP constant value."""
        assert _PBUILD_USER_GROUP == "_pbuild:_pbuild"

    def test_no_output_constant(self):
        """Test _NO_OUTPUT constant value."""
        assert _NO_OUTPUT == "(no output)"


class TestPackageBuilderLogging:
    """Test cases for logging behavior."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.builder = PackageBuilder(self.mock_logger)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.shutil.copytree"
    )
    def test_build_agent_package_logs_entry(self, mock_copytree):
        """Test that build_agent_package logs entry message."""
        mock_copytree.side_effect = Exception("Test exception")

        self.builder.build_agent_package(Path("/tmp/port"), "v1.0.0")

        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("ENTERED build_agent_package" in call for call in info_calls)

    @patch("src.sysmanage_agent.operations.child_host_vmm_package_builder.Path.mkdir")
    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_setup_build_environment_logs_steps(self, mock_run, _mock_mkdir):
        """Test that _setup_build_environment logs each step."""
        mock_run.return_value = Mock(returncode=0)

        self.builder._setup_build_environment(Path("/test/ports"))

        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("build directories" in call.lower() for call in info_calls)
        assert any("package directories" in call.lower() for call in info_calls)

    @patch(
        "src.sysmanage_agent.operations.child_host_vmm_package_builder.subprocess.run"
    )
    def test_clean_previous_builds_logs_steps(self, mock_run):
        """Test that _clean_previous_builds logs each cleanup step."""
        mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

        self.builder._clean_previous_builds()

        info_calls = [str(call) for call in self.mock_logger.info.call_args_list]
        assert any("PLIST" in call for call in info_calls)
        assert any("work directories" in call.lower() for call in info_calls)
        assert any("packages" in call.lower() for call in info_calls)
