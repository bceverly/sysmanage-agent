"""
Unit tests for VMM script generation modules.
Tests OpenBSD and Alpine Linux script and config generators.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from src.sysmanage_agent.operations.child_host_vmm_scripts import (
    generate_agent_config,
    generate_firsttime_script,
    generate_install_site_script,
)
from src.sysmanage_agent.operations.child_host_alpine_scripts import (
    generate_agent_config as alpine_generate_agent_config,
    generate_firstboot_script,
    generate_answer_file,
    generate_overlay_script,
)


class TestOpenBSDAgentConfig:
    """Test cases for OpenBSD agent config generation."""

    def test_generate_config_basic(self):
        """Test basic agent config generation."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert 'hostname: "sysmanage.example.com"' in config
        assert "port: 8443" in config
        assert "use_https: true" in config
        assert "verify_ssl: false" in config

    def test_generate_config_http(self):
        """Test agent config generation with HTTP."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8080, use_https=False
        )

        assert "use_https: false" in config
        assert "port: 8080" in config

    def test_generate_config_with_auto_approve_token(self):
        """Test agent config with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in config
        assert f'token: "{token}"' in config

    def test_generate_config_without_auto_approve_token(self):
        """Test agent config without auto-approve token."""
        config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=None,
        )

        assert "auto_approve:" not in config

    def test_generate_config_script_execution_settings(self):
        """Test that script execution settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "script_execution:" in config
        assert "enabled: true" in config
        assert "allowed_shells:" in config
        assert '- "sh"' in config
        assert '- "ksh"' in config

    def test_generate_config_security_settings(self):
        """Test that security settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "restricted_paths:" in config
        assert "/etc/passwd" in config
        assert "/etc/shadow" in config
        assert "audit_logging: true" in config

    def test_generate_config_logging_settings(self):
        """Test that logging settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "logging:" in config
        assert "/var/log/sysmanage-agent/agent.log" in config

    def test_generate_config_websocket_settings(self):
        """Test that websocket settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "websocket:" in config
        assert "auto_reconnect: true" in config


class TestOpenBSDFirstTimeScript:
    """Test cases for OpenBSD rc.firsttime script generation."""

    def test_generate_firsttime_script(self):
        """Test firsttime script generation."""
        script = generate_firsttime_script()

        assert script.startswith("#!/bin/sh")
        assert "First boot setup" in script

    def test_firsttime_script_package_installation(self):
        """Test that package installation is included."""
        script = generate_firsttime_script()

        assert "pkg_add" in script
        assert "PKG_PATH" in script
        assert "python" in script.lower()

    def test_firsttime_script_service_management(self):
        """Test that service management is included."""
        script = generate_firsttime_script()

        assert "rcctl enable sysmanage_agent" in script
        assert "rcctl start sysmanage_agent" in script

    def test_firsttime_script_logging(self):
        """Test that logging is configured."""
        script = generate_firsttime_script()

        assert "LOGFILE" in script
        assert "/var/log/firsttime.log" in script

    def test_firsttime_script_syspatch(self):
        """Test that syspatch is run."""
        script = generate_firsttime_script()

        assert "syspatch" in script

    def test_firsttime_script_shutdown(self):
        """Test that system shuts down after setup."""
        script = generate_firsttime_script()

        assert "shutdown -p now" in script


class TestOpenBSDInstallSiteScript:
    """Test cases for OpenBSD install.site script generation."""

    def test_generate_install_site_script(self):
        """Test install.site script generation."""
        script = generate_install_site_script()

        assert script.startswith("#!/bin/sh")
        assert "exit 0" in script

    def test_install_site_sets_installurl(self):
        """Test that installurl is set."""
        script = generate_install_site_script()

        assert "/etc/installurl" in script
        assert "cdn.openbsd.org" in script


class TestAlpineAgentConfig:
    """Test cases for Alpine Linux agent config generation."""

    def test_generate_config_basic(self):
        """Test basic agent config generation."""
        config = alpine_generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert 'hostname: "sysmanage.example.com"' in config
        assert "port: 8443" in config
        assert "use_https: true" in config

    def test_generate_config_with_auto_approve_token(self):
        """Test agent config with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        config = alpine_generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in config
        assert f'token: "{token}"' in config

    def test_alpine_specific_shells(self):
        """Test Alpine-specific allowed shells."""
        config = alpine_generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert '- "ash"' in config  # Alpine-specific shell


class TestAlpineFirstBootScript:
    """Test cases for Alpine Linux firstboot script generation."""

    def test_generate_firstboot_script(self):
        """Test firstboot script generation."""
        script = generate_firstboot_script()

        assert script.startswith("#!/bin/sh")
        assert "First boot setup" in script

    def test_firstboot_script_apk_operations(self):
        """Test that apk operations are included."""
        script = generate_firstboot_script()

        assert "apk update" in script
        assert "apk add" in script

    def test_firstboot_script_python_packages(self):
        """Test that Python packages are installed."""
        script = generate_firstboot_script()

        assert "python3" in script
        assert "py3-" in script

    def test_firstboot_script_openrc_service(self):
        """Test that OpenRC service is created."""
        script = generate_firstboot_script()

        assert "/etc/init.d/sysmanage_agent" in script
        assert "openrc-run" in script
        assert "rc-update add sysmanage_agent" in script
        assert "rc-service sysmanage_agent start" in script

    def test_firstboot_script_community_repo(self):
        """Test that community repo is enabled."""
        script = generate_firstboot_script()

        assert "community" in script
        assert "/etc/apk/repositories" in script

    def test_firstboot_script_logging(self):
        """Test that logging is configured."""
        script = generate_firstboot_script()

        assert "LOGFILE" in script
        assert "/var/log/sysmanage-firstboot.log" in script

    def test_firstboot_script_cleanup(self):
        """Test that script removes itself."""
        script = generate_firstboot_script()

        assert "rm -f /etc/local.d/sysmanage-firstboot.start" in script


class TestAlpineAnswerFile:
    """Test cases for Alpine Linux answer file generation."""

    def test_generate_answer_file_basic(self):
        """Test basic answer file generation."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "KEYMAPOPTS" in answer
        assert "vm01.example.com" in answer

    def test_answer_file_network_config(self):
        """Test network configuration in answer file."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "INTERFACESOPTS" in answer
        assert "192.168.1.100" in answer
        assert "192.168.1.1" in answer
        assert "255.255.255.0" in answer

    def test_answer_file_custom_disk(self):
        """Test custom disk configuration."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            disk="sda",
        )

        assert "DISKOPTS" in answer
        assert "/dev/sda" in answer

    def test_answer_file_default_disk(self):
        """Test default disk (vda for virtio)."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "/dev/vda" in answer

    def test_answer_file_custom_timezone(self):
        """Test custom timezone configuration."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            timezone="America/New_York",
        )

        assert "TIMEZONEOPTS" in answer
        assert "America/New_York" in answer

    def test_answer_file_user_settings(self):
        """Test user settings in answer file."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="testadmin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "USEROPTS" in answer
        assert "testadmin" in answer
        assert "wheel" in answer  # Admin group

    def test_answer_file_ssh_settings(self):
        """Test SSH settings in answer file."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "SSHDOPTS" in answer
        assert "openssh" in answer

    def test_answer_file_ntp_settings(self):
        """Test NTP settings in answer file."""
        answer = generate_answer_file(
            hostname="vm01.example.com",
            username="admin",
            _user_password_hash="$6$...",
            _root_password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "NTPOPTS" in answer
        assert "chrony" in answer


class TestAlpineOverlayScript:
    """Test cases for Alpine overlay script generation."""

    def test_generate_overlay_script(self):
        """Test overlay script generation."""
        script = generate_overlay_script()

        assert script.startswith("#!/bin/sh")
        assert "overlay" in script.lower()

    def test_overlay_script_creates_tarball(self):
        """Test that overlay script creates tarball."""
        script = generate_overlay_script()

        assert "tar" in script
        assert ".apkovl.tar.gz" in script

    def test_overlay_script_copies_files(self):
        """Test that overlay script copies overlay files."""
        script = generate_overlay_script()

        assert "/media/cdrom/overlay" in script
        assert "cp -a" in script


class TestScriptContentSecurity:
    """Security tests for generated scripts."""

    def test_no_hardcoded_passwords_openbsd(self):
        """Test OpenBSD scripts don't have hardcoded passwords."""
        config = generate_agent_config(hostname="test.com", port=8443, use_https=True)
        firsttime = generate_firsttime_script()
        installsite = generate_install_site_script()

        for content in [config, firsttime, installsite]:
            assert (
                "password" not in content.lower() or "password_hash" in content.lower()
            )
            assert "secret" not in content.lower()

    def test_no_hardcoded_passwords_alpine(self):
        """Test Alpine scripts don't have hardcoded passwords."""
        config = alpine_generate_agent_config(
            hostname="test.com", port=8443, use_https=True
        )
        firstboot = generate_firstboot_script()
        overlay = generate_overlay_script()

        for content in [config, firstboot, overlay]:
            assert (
                "password" not in content.lower() or "password_hash" in content.lower()
            )
            assert "secret" not in content.lower()

    def test_proper_quoting_in_config(self):
        """Test proper quoting of values in config."""
        config = generate_agent_config(
            hostname="test.example.com", port=8443, use_https=True
        )

        # Hostname should be quoted
        assert 'hostname: "test.example.com"' in config

    def test_special_characters_in_hostname(self):
        """Test handling of special characters in hostname."""
        config = generate_agent_config(
            hostname="test-server_01.subdomain.example.com", port=8443, use_https=True
        )

        assert "test-server_01.subdomain.example.com" in config

    def test_auto_approve_token_format(self):
        """Test auto-approve token is properly formatted."""
        token = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        config = generate_agent_config(
            hostname="test.com", port=8443, use_https=True, auto_approve_token=token
        )

        assert f'token: "{token}"' in config


class TestScriptShellCompatibility:
    """Test shell compatibility of generated scripts."""

    def test_posix_compatible_firsttime(self):
        """Test that firsttime script uses POSIX-compatible syntax."""
        script = generate_firsttime_script()

        # Should not use bash-specific syntax
        assert "[[" not in script or script.count("[[") == 0
        # Should use POSIX test syntax
        assert "[ " in script or "test " in script

    def test_posix_compatible_firstboot(self):
        """Test that firstboot script uses POSIX-compatible syntax."""
        script = generate_firstboot_script()

        # Should not use bash-specific syntax
        assert "[[" not in script

    def test_scripts_have_proper_shebang(self):
        """Test that scripts have proper shebang."""
        scripts = [
            generate_firsttime_script(),
            generate_install_site_script(),
            generate_firstboot_script(),
            generate_overlay_script(),
        ]

        for script in scripts:
            assert script.startswith("#!/bin/sh") or script.startswith(
                "#!/sbin/openrc-run"
            )
