"""
Unit tests for child_host_config_generator module.

Tests the unified agent configuration generator for child host creation,
covering all OS-specific configurations and cloud-init generation.
"""

# pylint: disable=protected-access

from src.sysmanage_agent.operations.child_host_config_generator import (
    OS_DATABASE_PATHS,
    OS_LOG_PATHS,
    OS_SHELLS,
    gen_agent_config_shell_cmds,
    generate_agent_config,
    generate_cloudinit_userdata,
    get_database_path_for_os,
    get_log_path_for_os,
    get_shells_for_os,
)


class TestGetShellsForOS:
    """Test cases for get_shells_for_os function."""

    def test_ubuntu_shells(self):
        """Test shells for Ubuntu."""
        shells = get_shells_for_os("ubuntu")
        assert shells == ["sh", "bash", "dash"]

    def test_debian_shells(self):
        """Test shells for Debian."""
        shells = get_shells_for_os("debian")
        assert shells == ["sh", "bash", "dash"]

    def test_alpine_shells(self):
        """Test shells for Alpine Linux."""
        shells = get_shells_for_os("alpine")
        assert shells == ["sh", "ash", "bash"]

    def test_freebsd_shells(self):
        """Test shells for FreeBSD."""
        shells = get_shells_for_os("freebsd")
        assert shells == ["sh", "csh", "tcsh"]

    def test_openbsd_shells(self):
        """Test shells for OpenBSD."""
        shells = get_shells_for_os("openbsd")
        assert shells == ["sh", "ksh"]

    def test_netbsd_shells(self):
        """Test shells for NetBSD."""
        shells = get_shells_for_os("netbsd")
        assert shells == ["sh", "ksh"]

    def test_macos_shells(self):
        """Test shells for macOS."""
        shells = get_shells_for_os("macos")
        assert shells == ["sh", "bash", "zsh"]

    def test_windows_shells(self):
        """Test shells for Windows."""
        shells = get_shells_for_os("windows")
        assert shells == ["powershell", "cmd"]

    def test_linux_shells(self):
        """Test shells for generic Linux."""
        shells = get_shells_for_os("linux")
        assert shells == ["sh", "bash"]

    def test_unknown_os_falls_back_to_linux(self):
        """Test that unknown OS types fall back to Linux shells."""
        shells = get_shells_for_os("unknown_os")
        assert shells == OS_SHELLS["linux"]

    def test_case_insensitive_lookup(self):
        """Test that OS type lookup is case insensitive."""
        assert get_shells_for_os("Ubuntu") == get_shells_for_os("ubuntu")
        assert get_shells_for_os("FREEBSD") == get_shells_for_os("freebsd")
        assert get_shells_for_os("MacOS") == get_shells_for_os("macos")

    def test_empty_string_falls_back_to_linux(self):
        """Test that empty string falls back to Linux shells."""
        shells = get_shells_for_os("")
        assert shells == OS_SHELLS["linux"]


class TestGetDatabasePathForOS:
    """Test cases for get_database_path_for_os function."""

    def test_windows_database_path(self):
        """Test database path for Windows."""
        path = get_database_path_for_os("windows")
        assert path == "C:\\ProgramData\\SysManage\\agent.db"
        assert path == OS_DATABASE_PATHS["windows"]

    def test_linux_database_path(self):
        """Test database path for Linux."""
        path = get_database_path_for_os("linux")
        assert path == "/var/lib/sysmanage-agent/agent.db"
        assert path == OS_DATABASE_PATHS["default"]

    def test_ubuntu_database_path(self):
        """Test database path for Ubuntu uses Unix default."""
        path = get_database_path_for_os("ubuntu")
        assert path == OS_DATABASE_PATHS["default"]

    def test_freebsd_database_path(self):
        """Test database path for FreeBSD uses Unix default."""
        path = get_database_path_for_os("freebsd")
        assert path == OS_DATABASE_PATHS["default"]

    def test_macos_database_path(self):
        """Test database path for macOS uses Unix default."""
        path = get_database_path_for_os("macos")
        assert path == OS_DATABASE_PATHS["default"]

    def test_case_insensitive_windows(self):
        """Test that Windows lookup is case insensitive."""
        assert get_database_path_for_os("WINDOWS") == OS_DATABASE_PATHS["windows"]
        assert get_database_path_for_os("Windows") == OS_DATABASE_PATHS["windows"]

    def test_unknown_os_uses_default(self):
        """Test that unknown OS types use Unix default path."""
        path = get_database_path_for_os("unknown_os")
        assert path == OS_DATABASE_PATHS["default"]


class TestGetLogPathForOS:
    """Test cases for get_log_path_for_os function."""

    def test_windows_log_path(self):
        """Test log path for Windows."""
        path = get_log_path_for_os("windows")
        assert path == "C:\\ProgramData\\SysManage\\logs\\agent.log"
        assert path == OS_LOG_PATHS["windows"]

    def test_linux_log_path(self):
        """Test log path for Linux."""
        path = get_log_path_for_os("linux")
        assert path == "/var/log/sysmanage-agent/agent.log"
        assert path == OS_LOG_PATHS["default"]

    def test_ubuntu_log_path(self):
        """Test log path for Ubuntu uses Unix default."""
        path = get_log_path_for_os("ubuntu")
        assert path == OS_LOG_PATHS["default"]

    def test_freebsd_log_path(self):
        """Test log path for FreeBSD uses Unix default."""
        path = get_log_path_for_os("freebsd")
        assert path == OS_LOG_PATHS["default"]

    def test_macos_log_path(self):
        """Test log path for macOS uses Unix default."""
        path = get_log_path_for_os("macos")
        assert path == OS_LOG_PATHS["default"]

    def test_case_insensitive_windows(self):
        """Test that Windows lookup is case insensitive."""
        assert get_log_path_for_os("WINDOWS") == OS_LOG_PATHS["windows"]
        assert get_log_path_for_os("Windows") == OS_LOG_PATHS["windows"]

    def test_unknown_os_uses_default(self):
        """Test that unknown OS types use Unix default path."""
        path = get_log_path_for_os("unknown_os")
        assert path == OS_LOG_PATHS["default"]


class TestGenerateAgentConfig:
    """Test cases for generate_agent_config function."""

    def test_basic_config_generation(self):
        """Test basic configuration generation."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert 'hostname: "server.example.com"' in config
        assert "port: 8443" in config
        assert "use_https: true" in config

    def test_http_config_generation(self):
        """Test configuration with HTTP."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8080,
            use_https=False,
        )

        assert "use_https: false" in config
        assert "port: 8080" in config

    def test_config_with_auto_approve_token(self):
        """Test configuration with auto-approve token."""
        token = "550e8400-e29b-41d4-a716-446655440000"
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in config
        assert f'token: "{token}"' in config

    def test_config_without_auto_approve_token(self):
        """Test configuration without auto-approve token."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=None,
        )

        assert "auto_approve:" not in config

    def test_verify_ssl_true(self):
        """Test configuration with SSL verification enabled."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            verify_ssl=True,
        )

        assert "verify_ssl: true" in config

    def test_verify_ssl_false_default(self):
        """Test configuration with SSL verification disabled (default)."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "verify_ssl: false" in config

    def test_ubuntu_os_type(self):
        """Test configuration for Ubuntu."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="ubuntu",
        )

        assert "Ubuntu Linux" in config
        assert '- "sh"' in config
        assert '- "bash"' in config
        assert '- "dash"' in config
        assert "/var/lib/sysmanage-agent/agent.db" in config
        assert "/var/log/sysmanage-agent/agent.log" in config

    def test_debian_os_type(self):
        """Test configuration for Debian."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="debian",
        )

        assert "Debian Linux" in config
        assert '- "sh"' in config
        assert '- "bash"' in config
        assert '- "dash"' in config

    def test_alpine_os_type(self):
        """Test configuration for Alpine."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="alpine",
        )

        assert "Alpine Linux" in config
        assert '- "sh"' in config
        assert '- "ash"' in config
        assert '- "bash"' in config

    def test_freebsd_os_type(self):
        """Test configuration for FreeBSD."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="freebsd",
        )

        assert "FREEBSD" in config
        assert '- "sh"' in config
        assert '- "csh"' in config
        assert '- "tcsh"' in config

    def test_openbsd_os_type(self):
        """Test configuration for OpenBSD."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="openbsd",
        )

        assert "Openbsd" in config
        assert '- "sh"' in config
        assert '- "ksh"' in config

    def test_netbsd_os_type(self):
        """Test configuration for NetBSD."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="netbsd",
        )

        assert "Netbsd" in config
        assert '- "sh"' in config
        assert '- "ksh"' in config

    def test_macos_os_type(self):
        """Test configuration for macOS."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="macos",
        )

        assert "Macos" in config
        assert '- "sh"' in config
        assert '- "bash"' in config
        assert '- "zsh"' in config

    def test_windows_os_type(self):
        """Test configuration for Windows."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="windows",
        )

        assert "Windows" in config
        assert '- "powershell"' in config
        assert '- "cmd"' in config
        assert "C:\\ProgramData\\SysManage\\agent.db" in config
        assert "C:\\ProgramData\\SysManage\\logs\\agent.log" in config

    def test_default_linux_os_type(self):
        """Test configuration with default Linux OS type."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "Linux" in config
        assert '- "sh"' in config
        assert '- "bash"' in config

    def test_config_contains_standard_sections(self):
        """Test that config contains all standard sections."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "server:" in config
        assert "security:" in config
        assert "client:" in config
        assert "i18n:" in config
        assert "logging:" in config
        assert "websocket:" in config
        assert "database:" in config
        assert "script_execution:" in config

    def test_config_contains_client_settings(self):
        """Test that config contains client settings."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "registration_retry_interval: 30" in config
        assert "max_registration_retries: 10" in config
        assert "update_check_interval: 3600" in config

    def test_config_contains_websocket_settings(self):
        """Test that config contains websocket settings."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "auto_reconnect: true" in config
        assert "reconnect_interval: 5" in config
        assert "ping_interval: 60" in config

    def test_config_contains_script_execution_settings(self):
        """Test that config contains script execution settings."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "enabled: true" in config
        assert "timeout: 300" in config
        assert "max_concurrent: 3" in config
        assert "allowed_shells:" in config
        assert "user_restrictions:" in config
        assert "allow_user_switching: false" in config

    def test_config_contains_security_restrictions(self):
        """Test that config contains security restrictions."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        assert "restricted_paths:" in config
        assert '"/etc/passwd"' in config
        assert '"/etc/shadow"' in config
        assert '"/etc/ssh/"' in config
        assert '"*.key"' in config
        assert '"*.pem"' in config
        assert "audit_logging: true" in config
        assert "require_approval: false" in config

    def test_config_is_valid_yaml_structure(self):
        """Test that generated config has valid YAML-like structure."""
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="ubuntu",
            auto_approve_token="test-token",
            verify_ssl=True,
        )

        # Basic structural checks
        assert config.startswith("# sysmanage-agent configuration")
        lines = config.split("\n")
        assert len(lines) > 50  # Should have substantial content


class TestGenerateCloudinitUserdata:
    """Test cases for generate_cloudinit_userdata function."""

    def test_linux_userdata_basic(self):
        """Test basic Linux cloud-init userdata generation."""
        agent_config = "# test config"
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config=agent_config,
        )

        assert "#cloud-config" in userdata
        assert "hostname: testvm.example.com" in userdata
        assert "name: admin" in userdata
        assert "manage_etc_hosts: true" in userdata
        assert "chpasswd:" in userdata
        assert "shell: /bin/bash" in userdata

    def test_freebsd_userdata_basic(self):
        """Test basic FreeBSD cloud-init userdata generation."""
        agent_config = "# test config"
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$2b$bcrypt_hash",
            os_type="freebsd",
            agent_config=agent_config,
        )

        assert "#cloud-config" in userdata
        assert "hostname: testvm" in userdata  # short hostname
        assert "fqdn: testvm.example.com" in userdata
        assert "name: admin" in userdata
        assert "shell: /bin/sh" in userdata
        assert "groups: wheel" in userdata
        assert 'passwd: "$2b$bcrypt_hash"' in userdata
        assert "chpasswd:" not in userdata

    def test_linux_userdata_contains_agent_config(self):
        """Test Linux userdata contains agent configuration."""
        agent_config = """server:
  hostname: "server.example.com"
  port: 8443"""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config=agent_config,
        )

        assert "write_files:" in userdata
        assert "path: /etc/sysmanage-agent.yaml" in userdata
        assert "permissions: '0644'" in userdata
        assert "server.example.com" in userdata

    def test_freebsd_userdata_contains_agent_config(self):
        """Test FreeBSD userdata contains agent configuration."""
        agent_config = """server:
  hostname: "server.example.com"
  port: 8443"""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$2b$hash",
            os_type="freebsd",
            agent_config=agent_config,
        )

        assert "write_files:" in userdata
        assert "path: /etc/sysmanage-agent.yaml" in userdata
        assert "permissions: '0644'" in userdata
        assert "server.example.com" in userdata

    def test_userdata_with_auto_approve_token(self):
        """Test userdata includes auto-approve token file."""
        agent_config = "# test config"
        token = "550e8400-e29b-41d4-a716-446655440000"
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config=agent_config,
            auto_approve_token=token,
        )

        assert "path: /etc/sysmanage-agent/auto_approve_token" in userdata
        assert token in userdata
        assert "permissions: '0600'" in userdata

    def test_userdata_without_auto_approve_token(self):
        """Test userdata without auto-approve token."""
        agent_config = "# test config"
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config=agent_config,
            auto_approve_token=None,
        )

        assert "/etc/sysmanage-agent/auto_approve_token" not in userdata

    def test_linux_userdata_sudo_settings(self):
        """Test Linux userdata has proper sudo settings."""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config="# test",
        )

        assert "sudo: ALL=(ALL) NOPASSWD:ALL" in userdata
        assert "lock_passwd: false" in userdata

    def test_freebsd_userdata_sudo_settings(self):
        """Test FreeBSD userdata has proper sudo settings."""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$2b$hash",
            os_type="freebsd",
            agent_config="# test",
        )

        assert "sudo: ALL=(ALL) NOPASSWD:ALL" in userdata
        assert "lock_passwd: false" in userdata
        assert "disable_root: false" in userdata

    def test_linux_ssh_password_auth(self):
        """Test Linux userdata enables SSH password auth."""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config="# test",
        )

        assert "ssh_pwauth: true" in userdata

    def test_freebsd_ssh_password_auth(self):
        """Test FreeBSD userdata enables SSH password auth."""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$2b$hash",
            os_type="freebsd",
            agent_config="# test",
        )

        assert "ssh_pwauth: true" in userdata

    def test_freebsd_extracts_short_hostname(self):
        """Test FreeBSD correctly extracts short hostname from FQDN."""
        userdata = generate_cloudinit_userdata(
            hostname="myserver.subdomain.example.com",
            username="admin",
            password_hash="$2b$hash",
            os_type="freebsd",
            agent_config="# test",
        )

        assert "hostname: myserver" in userdata
        assert "fqdn: myserver.subdomain.example.com" in userdata

    def test_debian_uses_linux_format(self):
        """Test Debian uses Linux cloud-init format."""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="debian",
            agent_config="# test",
        )

        assert "chpasswd:" in userdata
        assert "shell: /bin/bash" in userdata
        assert "fqdn:" not in userdata  # Linux format doesn't separate fqdn

    def test_alpine_uses_linux_format(self):
        """Test Alpine uses Linux cloud-init format."""
        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="alpine",
            agent_config="# test",
        )

        assert "chpasswd:" in userdata
        assert "shell: /bin/bash" in userdata

    def test_config_indentation_preserved(self):
        """Test that multi-line config is properly indented."""
        agent_config = """server:
  hostname: "test"
  port: 8443
logging:
  level: INFO"""

        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config=agent_config,
        )

        # Config lines should be indented with 6 spaces
        assert "      server:" in userdata
        assert "        hostname:" in userdata

    def test_empty_config_lines_handled(self):
        """Test that empty lines in config are handled properly."""
        agent_config = """server:
  hostname: "test"

logging:
  level: INFO"""

        userdata = generate_cloudinit_userdata(
            hostname="testvm.example.com",
            username="admin",
            password_hash="$6$hash",
            os_type="ubuntu",
            agent_config=agent_config,
        )

        # Should not raise an error and should contain the config
        assert "server:" in userdata
        assert "logging:" in userdata


class TestGenAgentConfigShellCmds:
    """Test cases for gen_agent_config_shell_cmds function."""

    def test_basic_shell_commands_generation(self):
        """Test basic shell commands generation."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        # First line should create the file
        assert (
            'echo "# sysmanage-agent configuration" > /etc/sysmanage-agent/sysmanage-agent.yaml'
            in commands
        )
        # Subsequent lines should append
        assert '" >> /etc/sysmanage-agent/sysmanage-agent.yaml' in commands

    def test_custom_config_path(self):
        """Test shell commands with custom config path."""
        custom_path = "/custom/path/config.yaml"
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            config_path=custom_path,
        )

        assert f"> {custom_path}" in commands
        assert f">> {custom_path}" in commands

    def test_escapes_double_quotes(self):
        """Test that double quotes are properly escaped."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        # The hostname in the config should have escaped quotes
        assert 'hostname: \\"server.example.com\\"' in commands

    def test_escapes_backslashes_for_windows(self):
        """Test that backslashes are properly escaped for Windows paths."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="windows",
        )

        # Windows paths should have escaped backslashes
        assert "\\\\" in commands

    def test_contains_all_config_content(self):
        """Test that shell commands contain all config content."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="ubuntu",
        )

        # Should contain key configuration sections
        assert "server:" in commands
        assert "security:" in commands
        assert "websocket:" in commands
        assert "database:" in commands
        assert "script_execution:" in commands

    def test_with_auto_approve_token(self):
        """Test shell commands include auto-approve token."""
        token = "test-token-uuid"
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in commands
        assert token in commands

    def test_without_auto_approve_token(self):
        """Test shell commands without auto-approve token."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=None,
        )

        assert "auto_approve:" not in commands

    def test_verify_ssl_setting(self):
        """Test verify_ssl setting in shell commands."""
        commands_ssl_true = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            verify_ssl=True,
        )
        assert "verify_ssl: true" in commands_ssl_true

        commands_ssl_false = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            verify_ssl=False,
        )
        assert "verify_ssl: false" in commands_ssl_false

    def test_os_specific_shells_in_output(self):
        """Test OS-specific shells appear in shell commands."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="freebsd",
        )

        assert "csh" in commands
        assert "tcsh" in commands

    def test_all_lines_are_echo_commands(self):
        """Test that all lines are proper echo commands."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        lines = commands.split("\n")
        for line in lines:
            if line.strip():  # Skip empty lines
                assert line.startswith('echo "')

    def test_first_line_creates_file(self):
        """Test that first line creates file (uses >)."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        lines = commands.split("\n")
        first_line = lines[0]
        # First line should use > to create file
        assert " > " in first_line
        assert " >> " not in first_line

    def test_subsequent_lines_append(self):
        """Test that subsequent lines append (use >>)."""
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
        )

        lines = commands.split("\n")
        # All lines after the first should use >> to append
        for line in lines[1:]:
            if line.strip():
                assert " >> " in line
                assert line.count(" > ") == 0 or " >> " in line


class TestOSShellsConstant:
    """Test cases for OS_SHELLS constant."""

    def test_all_expected_os_types_present(self):
        """Test that all expected OS types are in OS_SHELLS."""
        expected_os_types = [
            "ubuntu",
            "debian",
            "alpine",
            "freebsd",
            "openbsd",
            "netbsd",
            "macos",
            "windows",
            "linux",
        ]
        for os_type in expected_os_types:
            assert os_type in OS_SHELLS, f"Missing OS type: {os_type}"

    def test_all_shell_lists_non_empty(self):
        """Test that all shell lists are non-empty."""
        for os_type, shells in OS_SHELLS.items():
            assert len(shells) > 0, f"Empty shell list for: {os_type}"

    def test_all_unix_have_sh(self):
        """Test that all Unix-like systems have 'sh' as a shell."""
        unix_types = [
            "ubuntu",
            "debian",
            "alpine",
            "freebsd",
            "openbsd",
            "netbsd",
            "macos",
            "linux",
        ]
        for os_type in unix_types:
            assert "sh" in OS_SHELLS[os_type], f"Missing 'sh' for: {os_type}"

    def test_windows_has_powershell(self):
        """Test that Windows has PowerShell."""
        assert "powershell" in OS_SHELLS["windows"]
        assert "cmd" in OS_SHELLS["windows"]


class TestOSDatabasePathsConstant:
    """Test cases for OS_DATABASE_PATHS constant."""

    def test_windows_path_present(self):
        """Test Windows database path is present."""
        assert "windows" in OS_DATABASE_PATHS
        assert "C:\\" in OS_DATABASE_PATHS["windows"]

    def test_default_path_present(self):
        """Test default Unix database path is present."""
        assert "default" in OS_DATABASE_PATHS
        assert OS_DATABASE_PATHS["default"].startswith("/var/lib/")


class TestOSLogPathsConstant:
    """Test cases for OS_LOG_PATHS constant."""

    def test_windows_path_present(self):
        """Test Windows log path is present."""
        assert "windows" in OS_LOG_PATHS
        assert "C:\\" in OS_LOG_PATHS["windows"]
        assert "log" in OS_LOG_PATHS["windows"].lower()

    def test_default_path_present(self):
        """Test default Unix log path is present."""
        assert "default" in OS_LOG_PATHS
        assert OS_LOG_PATHS["default"].startswith("/var/log/")


class TestIntegration:
    """Integration tests combining multiple functions."""

    def test_full_vm_provisioning_workflow_linux(self):
        """Test complete Linux VM provisioning workflow."""
        # Generate agent config
        agent_config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            os_type="ubuntu",
            auto_approve_token="test-token",
            verify_ssl=False,
        )

        # Generate cloud-init userdata
        userdata = generate_cloudinit_userdata(
            hostname="newvm.example.com",
            username="sysadmin",
            password_hash="$6$rounds=4096$salt$hash",
            os_type="ubuntu",
            agent_config=agent_config,
            auto_approve_token="test-token",
        )

        # Verify complete chain
        assert "sysmanage.example.com" in userdata
        assert "newvm.example.com" in userdata
        assert "sysadmin" in userdata
        assert "test-token" in userdata
        assert "/etc/sysmanage-agent.yaml" in userdata

    def test_full_vm_provisioning_workflow_freebsd(self):
        """Test complete FreeBSD VM provisioning workflow."""
        # Generate agent config
        agent_config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            os_type="freebsd",
            auto_approve_token="test-token",
            verify_ssl=False,
        )

        # Generate cloud-init userdata
        userdata = generate_cloudinit_userdata(
            hostname="bsdvm.example.com",
            username="admin",
            password_hash="$2b$12$bcrypt_hash",
            os_type="freebsd",
            agent_config=agent_config,
            auto_approve_token="test-token",
        )

        # Verify FreeBSD-specific content
        assert "hostname: bsdvm" in userdata
        assert "fqdn: bsdvm.example.com" in userdata
        assert "shell: /bin/sh" in userdata
        assert "csh" in agent_config or "tcsh" in agent_config

    def test_shell_commands_match_config(self):
        """Test that shell commands produce equivalent config content."""
        # Generate config directly
        config = generate_agent_config(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="alpine",
        )

        # Generate shell commands
        commands = gen_agent_config_shell_cmds(
            hostname="server.example.com",
            port=8443,
            use_https=True,
            os_type="alpine",
        )

        # Key content should appear in both (accounting for escaping)
        assert "Alpine Linux" in config
        assert "Alpine Linux" in commands
        assert "ash" in config
        assert "ash" in commands

    def test_all_os_types_generate_valid_config(self):
        """Test that all OS types can generate valid configurations."""
        os_types = list(OS_SHELLS.keys())

        for os_type in os_types:
            config = generate_agent_config(
                hostname="server.example.com",
                port=8443,
                use_https=True,
                os_type=os_type,
            )

            # Basic validity checks
            assert "server:" in config
            assert "hostname:" in config
            assert "allowed_shells:" in config
            assert len(config) > 100  # Should have substantial content
