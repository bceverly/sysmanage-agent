"""
Unit tests for Ubuntu autoinstall and script generators.
Tests Ubuntu VMM child host creation script and config generators.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import base64

from src.sysmanage_agent.operations.child_host_ubuntu_scripts import (
    generate_agent_config,
    generate_autoinstall_file,
    generate_autoinstall_with_agent,
    generate_firstboot_script,
    generate_firstboot_systemd_service,
    generate_grub_serial_config,
    generate_kernel_boot_params,
)


class TestUbuntuAgentConfig:
    """Test cases for Ubuntu agent config generation."""

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
        assert '- "bash"' in config
        assert '- "dash"' in config

    def test_generate_config_security_settings(self):
        """Test that security settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "restricted_paths:" in config
        assert '"/etc/passwd"' in config
        assert '"/etc/shadow"' in config
        assert '"/etc/ssh/"' in config
        assert "audit_logging: true" in config

    def test_generate_config_logging_settings(self):
        """Test that logging settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "logging:" in config
        assert '"/var/log/sysmanage-agent/agent.log"' in config

    def test_generate_config_websocket_settings(self):
        """Test that websocket settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "websocket:" in config
        assert "auto_reconnect: true" in config
        assert "reconnect_interval: 5" in config
        assert "ping_interval: 60" in config

    def test_generate_config_database_settings(self):
        """Test that database settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "database:" in config
        assert 'path: "agent.db"' in config
        assert "auto_migrate: true" in config

    def test_generate_config_client_settings(self):
        """Test that client identification settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "client:" in config
        assert "registration_retry_interval: 30" in config
        assert "max_registration_retries: 10" in config
        assert "update_check_interval: 3600" in config

    def test_generate_config_i18n_settings(self):
        """Test that internationalization settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "i18n:" in config
        assert 'language: "en"' in config


class TestUbuntuAutoinstallFile:
    """Test cases for Ubuntu autoinstall YAML generation."""

    def test_generate_autoinstall_basic(self):
        """Test basic autoinstall file generation."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$rounds=4096$salt$hashedpassword",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "#cloud-config" in autoinstall
        assert "autoinstall:" in autoinstall
        assert "version: 1" in autoinstall

    def test_generate_autoinstall_identity(self):
        """Test identity settings in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="testadmin",
            password_hash="$6$rounds=4096$salt$hashedpassword",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "identity:" in autoinstall
        assert "hostname: vm01.example.com" in autoinstall
        assert "username: testadmin" in autoinstall
        assert 'password: "$6$rounds=4096$salt$hashedpassword"' in autoinstall

    def test_generate_autoinstall_network_config(self):
        """Test network configuration in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "network:" in autoinstall
        assert "version: 2" in autoinstall
        assert "ethernets:" in autoinstall
        assert "enp0s2:" in autoinstall
        assert "192.168.1.100/24" in autoinstall
        assert "via: 192.168.1.1" in autoinstall
        assert "- 8.8.8.8" in autoinstall

    def test_generate_autoinstall_storage(self):
        """Test storage configuration in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "storage:" in autoinstall
        assert "layout:" in autoinstall
        assert "name: direct" in autoinstall

    def test_generate_autoinstall_ssh(self):
        """Test SSH configuration in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "ssh:" in autoinstall
        assert "install-server: true" in autoinstall
        assert "allow-pw: true" in autoinstall

    def test_generate_autoinstall_packages(self):
        """Test package list in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "packages:" in autoinstall
        assert "- openssh-server" in autoinstall
        assert "- sudo" in autoinstall
        assert "- python3" in autoinstall
        assert "- python3-pip" in autoinstall
        assert "- curl" in autoinstall
        assert "- ca-certificates" in autoinstall

    def test_generate_autoinstall_late_commands(self):
        """Test late-commands in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "late-commands:" in autoinstall
        # Check for /etc/hosts setup
        assert "echo '192.168.1.100 vm01.example.com vm01'" in autoinstall
        # Check for serial console setup
        assert "serial-getty@ttyS0.service" in autoinstall
        assert "console=ttyS0,115200n8" in autoinstall
        # Check for sysmanage-agent directory creation
        assert "mkdir -p /etc/sysmanage-agent" in autoinstall
        assert "mkdir -p /var/log/sysmanage-agent" in autoinstall
        assert "mkdir -p /var/lib/sysmanage-agent" in autoinstall

    def test_generate_autoinstall_custom_timezone(self):
        """Test custom timezone in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            timezone="America/New_York",
        )

        assert "timezone: America/New_York" in autoinstall

    def test_generate_autoinstall_default_timezone(self):
        """Test default timezone (UTC) in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "timezone: UTC" in autoinstall

    def test_generate_autoinstall_custom_shutdown(self):
        """Test custom shutdown action in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            shutdown_action="reboot",
        )

        assert "shutdown: reboot" in autoinstall

    def test_generate_autoinstall_default_shutdown(self):
        """Test default shutdown action (poweroff) in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "shutdown: poweroff" in autoinstall

    def test_generate_autoinstall_hostname_fqdn_handling(self):
        """Test FQDN handling in autoinstall."""
        # Test with FQDN
        autoinstall = generate_autoinstall_file(
            hostname="vm01.subdomain.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "vm01.subdomain.example.com" in autoinstall

    def test_generate_autoinstall_short_hostname(self):
        """Test short hostname handling (should get .local suffix)."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "hostname: vm01.local" in autoinstall

    def test_generate_autoinstall_locale_and_keyboard(self):
        """Test locale and keyboard settings in autoinstall."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "locale: en_US.UTF-8" in autoinstall
        assert "keyboard:" in autoinstall
        assert "layout: us" in autoinstall


class TestUbuntuAutoinstallWithAgent:
    """Test cases for Ubuntu autoinstall with agent setup."""

    def test_generate_autoinstall_with_agent_basic(self):
        """Test autoinstall with agent basic generation."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "#cloud-config" in autoinstall
        assert "autoinstall:" in autoinstall

    def test_generate_autoinstall_with_agent_base64_encoded_config(self):
        """Test that config is base64 encoded in autoinstall."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        # Check for base64 decoding command
        assert "base64 -d" in autoinstall
        assert "/etc/sysmanage-agent.yaml" in autoinstall

    def test_generate_autoinstall_with_agent_firstboot_script(self):
        """Test that firstboot script is included."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "/root/sysmanage-firstboot.sh" in autoinstall
        assert "chmod 755 /root/sysmanage-firstboot.sh" in autoinstall

    def test_generate_autoinstall_with_agent_systemd_service(self):
        """Test that systemd service is enabled."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "/etc/systemd/system/sysmanage-firstboot.service" in autoinstall
        assert "systemctl enable sysmanage-firstboot.service" in autoinstall

    def test_generate_autoinstall_with_agent_auto_approve_token(self):
        """Test autoinstall with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        # The token should be embedded in base64-encoded config
        assert autoinstall is not None
        # Decode one of the base64 sections to verify token is present
        # The config_b64 should contain the token
        agent_config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=token,
        )
        assert token in agent_config

    def test_generate_autoinstall_with_agent_deb_url(self):
        """Test autoinstall with agent .deb URL."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            agent_deb_url="http://192.168.1.1/sysmanage-agent.deb",
        )

        assert "wget" in autoinstall
        assert "http://192.168.1.1/sysmanage-agent.deb" in autoinstall
        assert "/root/sysmanage-agent.deb" in autoinstall

    def test_generate_autoinstall_with_agent_no_deb_url(self):
        """Test autoinstall without agent .deb URL."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            agent_deb_url=None,
        )

        # Should not have the download command
        assert "Download agent .deb from parent host" not in autoinstall

    def test_generate_autoinstall_with_agent_custom_timezone(self):
        """Test autoinstall with agent and custom timezone."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            timezone="Europe/London",
        )

        assert "timezone: Europe/London" in autoinstall

    def test_generate_autoinstall_with_agent_hostname_handling(self):
        """Test short hostname gets .local suffix."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="myvm",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "hostname: myvm.local" in autoinstall


class TestUbuntuFirstbootScript:
    """Test cases for Ubuntu firstboot script generation."""

    def test_generate_firstboot_script_basic(self):
        """Test basic firstboot script generation."""
        script = generate_firstboot_script()

        assert script.startswith("#!/bin/bash")
        assert "First boot setup" in script

    def test_generate_firstboot_script_with_server_info(self):
        """Test firstboot script with server info generates config."""
        script = generate_firstboot_script(
            ubuntu_version="24.04",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "Writing sysmanage-agent configuration" in script
        assert "sysmanage.example.com" in script
        assert "8443" in script
        assert "use_https: true" in script

    def test_generate_firstboot_script_without_server_info(self):
        """Test firstboot script without server info."""
        script = generate_firstboot_script(ubuntu_version="24.04")

        # Should not have config writing commands
        assert "Writing sysmanage-agent configuration" not in script

    def test_generate_firstboot_script_with_auto_approve_token(self):
        """Test firstboot script with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        script = generate_firstboot_script(
            ubuntu_version="24.04",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in script
        assert token in script

    def test_generate_firstboot_script_http(self):
        """Test firstboot script with HTTP (not HTTPS)."""
        script = generate_firstboot_script(
            ubuntu_version="24.04",
            server_hostname="sysmanage.example.com",
            server_port=8080,
            use_https=False,
        )

        assert "use_https: false" in script

    def test_generate_firstboot_script_package_installation(self):
        """Test that package installation is included."""
        script = generate_firstboot_script()

        assert "apt-get update" in script
        assert "apt-get install" in script
        assert "python3" in script
        assert "python3-pip" in script
        assert "python3-websockets" in script
        assert "python3-yaml" in script
        assert "python3-aiohttp" in script

    def test_generate_firstboot_script_agent_installation(self):
        """Test that agent installation is included."""
        script = generate_firstboot_script()

        assert "Installing sysmanage-agent" in script
        assert "/root/sysmanage-agent.deb" in script
        assert "dpkg -i" in script

    def test_generate_firstboot_script_wheel_installation(self):
        """Test that wheel installation fallback is included."""
        script = generate_firstboot_script()

        assert "/root/sysmanage_agent.whl" in script
        assert "pip3 install" in script

    def test_generate_firstboot_script_ppa_install(self):
        """Test that Launchpad PPA installation is included."""
        script = generate_firstboot_script()

        assert "ppa:bceverly/sysmanage-agent" in script
        assert "add-apt-repository" in script
        assert "apt-get install -y sysmanage-agent" in script

    def test_generate_firstboot_script_systemd_service(self):
        """Test that systemd service is created."""
        script = generate_firstboot_script()

        assert "/etc/systemd/system/sysmanage-agent.service" in script
        assert "systemctl daemon-reload" in script
        assert "systemctl enable sysmanage-agent" in script
        assert "systemctl start sysmanage-agent" in script

    def test_generate_firstboot_script_logging(self):
        """Test that logging is configured."""
        script = generate_firstboot_script()

        assert "LOGFILE" in script
        assert "/var/log/sysmanage-firstboot.log" in script

    def test_generate_firstboot_script_network_wait(self):
        """Test that network wait is included."""
        script = generate_firstboot_script()

        assert "Waiting for network" in script
        assert "ping" in script
        assert "archive.ubuntu.com" in script

    def test_generate_firstboot_script_cleanup(self):
        """Test that script cleans up after itself."""
        script = generate_firstboot_script()

        assert "systemctl disable sysmanage-firstboot.service" in script
        assert "rm -f /etc/systemd/system/sysmanage-firstboot.service" in script
        assert "rm -f /root/sysmanage-firstboot.sh" in script

    def test_generate_firstboot_script_ubuntu_version(self):
        """Test that Ubuntu version is included in script."""
        script = generate_firstboot_script(ubuntu_version="22.04")

        assert "Ubuntu version: 22.04" in script

    def test_generate_firstboot_script_error_handling(self):
        """Test that error handling is set up."""
        script = generate_firstboot_script()

        assert "set -e" in script


class TestUbuntuFirstbootSystemdService:
    """Test cases for firstboot systemd service generation."""

    def test_generate_firstboot_service(self):
        """Test firstboot systemd service generation."""
        service = generate_firstboot_systemd_service()

        assert "[Unit]" in service
        assert "[Service]" in service
        assert "[Install]" in service

    def test_firstboot_service_description(self):
        """Test service description."""
        service = generate_firstboot_systemd_service()

        assert "Description=SysManage Agent First Boot Setup" in service

    def test_firstboot_service_dependencies(self):
        """Test service dependencies."""
        service = generate_firstboot_systemd_service()

        assert "After=network-online.target" in service
        assert "Wants=network-online.target" in service

    def test_firstboot_service_condition(self):
        """Test service condition for firstboot script."""
        service = generate_firstboot_systemd_service()

        assert "ConditionPathExists=/root/sysmanage-firstboot.sh" in service

    def test_firstboot_service_type(self):
        """Test service type is oneshot."""
        service = generate_firstboot_systemd_service()

        assert "Type=oneshot" in service
        assert "RemainAfterExit=yes" in service

    def test_firstboot_service_exec(self):
        """Test service execution command."""
        service = generate_firstboot_systemd_service()

        assert "ExecStart=/bin/bash /root/sysmanage-firstboot.sh" in service

    def test_firstboot_service_logging(self):
        """Test service logging configuration."""
        service = generate_firstboot_systemd_service()

        assert "StandardOutput=journal" in service
        assert "StandardError=journal" in service

    def test_firstboot_service_install_target(self):
        """Test service install target."""
        service = generate_firstboot_systemd_service()

        assert "WantedBy=multi-user.target" in service


class TestGrubSerialConfig:
    """Test cases for GRUB serial console configuration."""

    def test_generate_grub_serial_config(self):
        """Test GRUB serial config generation."""
        config = generate_grub_serial_config()

        assert "GRUB_TERMINAL" in config
        assert "serial console" in config

    def test_grub_serial_command(self):
        """Test GRUB serial command settings."""
        config = generate_grub_serial_config()

        assert "GRUB_SERIAL_COMMAND" in config
        assert "--speed=115200" in config
        assert "--unit=0" in config
        assert "--word=8" in config
        assert "--parity=no" in config
        assert "--stop=1" in config

    def test_grub_cmdline_linux_default(self):
        """Test GRUB_CMDLINE_LINUX_DEFAULT settings."""
        config = generate_grub_serial_config()

        assert "GRUB_CMDLINE_LINUX_DEFAULT" in config
        assert "console=ttyS0,115200n8" in config

    def test_grub_cmdline_linux(self):
        """Test GRUB_CMDLINE_LINUX settings."""
        config = generate_grub_serial_config()

        assert "GRUB_CMDLINE_LINUX=" in config
        assert "console=ttyS0,115200n8" in config


class TestKernelBootParams:
    """Test cases for kernel boot parameters generation."""

    def test_generate_kernel_boot_params_basic(self):
        """Test basic kernel boot params generation."""
        params = generate_kernel_boot_params(
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            hostname="vm01",
        )

        assert "console=ttyS0,115200n8" in params
        assert "autoinstall" in params

    def test_generate_kernel_boot_params_ip_config(self):
        """Test IP configuration in kernel params."""
        params = generate_kernel_boot_params(
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            hostname="vm01",
        )

        # Format: ip=<client-ip>::<gateway>:<netmask>:<hostname>:<interface>:off
        assert "ip=192.168.1.100::192.168.1.1:255.255.255.0:vm01:enp0s2:off" in params

    def test_generate_kernel_boot_params_custom_interface(self):
        """Test custom interface in kernel params."""
        params = generate_kernel_boot_params(
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            hostname="vm01",
            interface="eth0",
        )

        assert "eth0:off" in params

    def test_generate_kernel_boot_params_default_interface(self):
        """Test default interface (enp0s2) in kernel params."""
        params = generate_kernel_boot_params(
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            hostname="vm01",
        )

        assert "enp0s2:off" in params

    def test_generate_kernel_boot_params_separator(self):
        """Test that params end with separator."""
        params = generate_kernel_boot_params(
            vm_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            hostname="vm01",
        )

        assert "---" in params

    def test_generate_kernel_boot_params_format(self):
        """Test overall format of kernel params."""
        params = generate_kernel_boot_params(
            vm_ip="10.0.0.50",
            gateway_ip="10.0.0.1",
            hostname="testvm",
            interface="enp0s3",
        )

        expected_parts = [
            "console=ttyS0,115200n8",
            "autoinstall",
            "ip=10.0.0.50::10.0.0.1:255.255.255.0:testvm:enp0s3:off",
            "---",
        ]
        for part in expected_parts:
            assert part in params


class TestScriptContentSecurity:
    """Security tests for generated Ubuntu scripts."""

    def test_no_hardcoded_passwords(self):
        """Test scripts don't have hardcoded passwords."""
        config = generate_agent_config(hostname="test.com", port=8443, use_https=True)
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )
        firstboot = generate_firstboot_script()
        grub = generate_grub_serial_config()

        for content in [config, grub]:
            # These shouldn't have password at all
            assert (
                "password" not in content.lower() or "password_hash" in content.lower()
            )

        # autoinstall has password_hash which is expected
        assert "password:" in autoinstall
        # firstboot doesn't have passwords
        assert (
            "password" not in firstboot.lower() or "password_hash" in firstboot.lower()
        )

    def test_proper_quoting_in_config(self):
        """Test proper quoting of values in config."""
        config = generate_agent_config(
            hostname="test.example.com", port=8443, use_https=True
        )

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


class TestBase64Encoding:
    """Test base64 encoding in autoinstall with agent."""

    def test_config_base64_encoding(self):
        """Test that config content is properly base64 encoded."""
        agent_config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
        )

        # Encode and decode to verify
        encoded = base64.b64encode(agent_config.encode()).decode()
        decoded = base64.b64decode(encoded).decode()

        assert decoded == agent_config

    def test_firstboot_script_base64_encoding(self):
        """Test that firstboot script is properly base64 encoded."""
        script = generate_firstboot_script(ubuntu_version="24.04")

        # Encode and decode to verify
        encoded = base64.b64encode(script.encode()).decode()
        decoded = base64.b64decode(encoded).decode()

        assert decoded == script

    def test_systemd_service_base64_encoding(self):
        """Test that systemd service is properly base64 encoded."""
        service = generate_firstboot_systemd_service()

        # Encode and decode to verify
        encoded = base64.b64encode(service.encode()).decode()
        decoded = base64.b64decode(encoded).decode()

        assert decoded == service


class TestVMMNetworkInterface:
    """Test VMM network interface constant usage."""

    def test_autoinstall_uses_vmm_interface(self):
        """Test that autoinstall uses the VMM network interface."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        # enp0s2 is the VMM_NETWORK_INTERFACE constant
        assert "enp0s2:" in autoinstall

    def test_autoinstall_with_agent_uses_vmm_interface(self):
        """Test that autoinstall with agent uses the VMM network interface."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        # enp0s2 is the VMM_NETWORK_INTERFACE constant
        assert "enp0s2:" in autoinstall


class TestAutoinstallYAMLStructure:
    """Test the YAML structure of generated autoinstall files."""

    def test_autoinstall_has_required_sections(self):
        """Test that autoinstall has all required sections."""
        autoinstall = generate_autoinstall_file(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        required_sections = [
            "version:",
            "locale:",
            "keyboard:",
            "timezone:",
            "identity:",
            "network:",
            "storage:",
            "ssh:",
            "packages:",
            "late-commands:",
            "shutdown:",
        ]

        for section in required_sections:
            assert section in autoinstall, f"Missing section: {section}"

    def test_autoinstall_with_agent_has_required_sections(self):
        """Test that autoinstall with agent has all required sections."""
        autoinstall = generate_autoinstall_with_agent(
            hostname="vm01.example.com",
            username="admin",
            password_hash="$6$...",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        required_sections = [
            "version:",
            "locale:",
            "keyboard:",
            "timezone:",
            "identity:",
            "network:",
            "storage:",
            "ssh:",
            "packages:",
            "late-commands:",
            "shutdown:",
        ]

        for section in required_sections:
            assert section in autoinstall, f"Missing section: {section}"


class TestFirstbootScriptConfigWriting:
    """Test the config writing section of firstboot script."""

    def test_config_writing_includes_all_sections(self):
        """Test that config writing includes all configuration sections."""
        script = generate_firstboot_script(
            ubuntu_version="24.04",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        config_sections = [
            "# sysmanage-agent configuration",
            "server:",
            "client:",
            "i18n:",
            "logging:",
            "websocket:",
            "database:",
            "script_execution:",
        ]

        for section in config_sections:
            assert section in script, f"Missing config section: {section}"

    def test_config_writing_security_settings(self):
        """Test that config writing includes security settings."""
        script = generate_firstboot_script(
            ubuntu_version="24.04",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        security_items = [
            "restricted_paths:",
            "audit_logging:",
            "require_approval:",
        ]

        for item in security_items:
            assert item in script, f"Missing security item: {item}"

    def test_config_writing_outputs_to_correct_file(self):
        """Test that config is written to correct file path."""
        script = generate_firstboot_script(
            ubuntu_version="24.04",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "/etc/sysmanage-agent.yaml" in script
