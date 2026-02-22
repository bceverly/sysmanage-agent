"""
Unit tests for Debian preseed and script generators.

Tests the child_host_debian_scripts module which provides preseed templates
and configuration generators for automated Debian installation on OpenBSD VMM.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

from src.sysmanage_agent.operations.child_host_debian_scripts import (
    generate_agent_config,
    generate_preseed_file,
    generate_firstboot_script,
    generate_firstboot_systemd_service,
    generate_grub_serial_config,
)


class TestDebianAgentConfig:
    """Test cases for Debian agent config generation."""

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
        """Test agent config generation with HTTP (no HTTPS)."""
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
        assert "# Auto-approval token for automatic host approval" in config

    def test_generate_config_without_auto_approve_token(self):
        """Test agent config without auto-approve token."""
        config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            auto_approve_token=None,
        )

        assert "auto_approve:" not in config

    def test_generate_config_with_empty_auto_approve_token(self):
        """Test agent config with empty string auto-approve token."""
        config = generate_agent_config(
            hostname="sysmanage.example.com",
            port=8443,
            use_https=True,
            auto_approve_token="",
        )

        # Empty string is falsy, so no auto_approve section
        assert "auto_approve:" not in config

    def test_generate_config_script_execution_settings(self):
        """Test that script execution settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "script_execution:" in config
        assert "enabled: true" in config
        assert "timeout: 300" in config
        assert "max_concurrent: 3" in config
        assert "allowed_shells:" in config
        assert '- "sh"' in config
        assert '- "bash"' in config
        assert '- "dash"' in config

    def test_generate_config_security_settings(self):
        """Test that security settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "security:" in config
        assert "restricted_paths:" in config
        assert '"/etc/passwd"' in config
        assert '"/etc/shadow"' in config
        assert '"/etc/ssh/"' in config
        assert '"/home/*/.ssh/"' in config
        assert '"/root/.ssh/"' in config
        assert '"*.key"' in config
        assert '"*.pem"' in config
        assert "audit_logging: true" in config
        assert "require_approval: false" in config

    def test_generate_config_logging_settings(self):
        """Test that logging settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "logging:" in config
        assert '"/var/log/sysmanage-agent/agent.log"' in config
        assert 'level: "INFO|WARNING|ERROR|CRITICAL"' in config

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
        """Test that client settings are included."""
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

    def test_generate_config_user_restrictions(self):
        """Test that user restriction settings are included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "user_restrictions:" in config
        assert "allow_user_switching: false" in config
        assert "allowed_users: []" in config

    def test_generate_config_header_comment(self):
        """Test that header comment is included."""
        config = generate_agent_config(
            hostname="sysmanage.example.com", port=8443, use_https=True
        )

        assert "# sysmanage-agent configuration" in config
        assert "# Auto-generated by VMM autoinstall for Debian Linux" in config


class TestDebianPreseedFile:
    """Test cases for Debian preseed file generation."""

    def test_generate_preseed_basic(self):
        """Test basic preseed file generation."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "# Debian 12 (bookworm) Preseed File" in preseed
        assert "# Auto-generated by sysmanage VMM autoinstall" in preseed

    def test_preseed_localization(self):
        """Test localization settings in preseed."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i debian-installer/locale string en_US.UTF-8" in preseed
        assert "d-i keyboard-configuration/xkb-keymap select us" in preseed

    def test_preseed_network_static_config(self):
        """Test static network configuration in preseed."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i netcfg/disable_autoconfig boolean true" in preseed
        assert "d-i netcfg/get_ipaddress string 192.168.1.100" in preseed
        assert "d-i netcfg/get_netmask string 255.255.255.0" in preseed
        assert "d-i netcfg/get_gateway string 192.168.1.1" in preseed
        assert "d-i netcfg/confirm_static boolean true" in preseed

    def test_preseed_dns_defaults_to_gateway(self):
        """Test DNS defaults to gateway IP when not specified."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i netcfg/get_nameservers string 192.168.1.1" in preseed

    def test_preseed_custom_dns(self):
        """Test custom DNS server configuration."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            dns_server="8.8.8.8",
        )

        assert "d-i netcfg/get_nameservers string 8.8.8.8" in preseed

    def test_preseed_hostname_parsing_fqdn(self):
        """Test FQDN hostname parsing."""
        preseed = generate_preseed_file(
            hostname="vm01.subdomain.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i netcfg/get_hostname string vm01" in preseed
        assert "d-i netcfg/get_domain string subdomain.example.com" in preseed
        assert "d-i netcfg/hostname string vm01" in preseed

    def test_preseed_hostname_parsing_simple(self):
        """Test simple hostname (no domain) parsing."""
        preseed = generate_preseed_file(
            hostname="vm01",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i netcfg/get_hostname string vm01" in preseed
        assert "d-i netcfg/get_domain string local" in preseed

    def test_preseed_mirror_settings(self):
        """Test mirror settings in preseed."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i mirror/country string manual" in preseed
        assert "d-i mirror/http/hostname string deb.debian.org" in preseed
        assert "d-i mirror/http/directory string /debian" in preseed
        assert "d-i mirror/suite string bookworm" in preseed

    def test_preseed_custom_mirror(self):
        """Test custom mirror URL."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            mirror_url="mirror.local.net",
        )

        assert "d-i mirror/http/hostname string mirror.local.net" in preseed

    def test_preseed_root_password(self):
        """Test root password configuration in preseed."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i passwd/root-login boolean true" in preseed
        assert "d-i passwd/root-password-crypted password $6$root_hash" in preseed

    def test_preseed_user_account(self):
        """Test user account configuration in preseed."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="testadmin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i passwd/make-user boolean true" in preseed
        assert "d-i passwd/user-fullname string testadmin" in preseed
        assert "d-i passwd/username string testadmin" in preseed
        assert "d-i passwd/user-password-crypted password $6$user_hash" in preseed
        assert "d-i passwd/user-default-groups string sudo" in preseed

    def test_preseed_timezone_default(self):
        """Test default timezone (UTC)."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i clock-setup/utc boolean true" in preseed
        assert "d-i time/zone string UTC" in preseed
        assert "d-i clock-setup/ntp boolean true" in preseed

    def test_preseed_custom_timezone(self):
        """Test custom timezone configuration."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            timezone="America/New_York",
        )

        assert "d-i time/zone string America/New_York" in preseed

    def test_preseed_disk_partitioning_default(self):
        """Test default disk partitioning (vda for virtio)."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i partman-auto/disk string /dev/vda" in preseed
        assert "d-i partman-auto/method string regular" in preseed
        assert "d-i partman-auto/choose_recipe select atomic" in preseed
        assert "d-i grub-installer/bootdev string /dev/vda" in preseed

    def test_preseed_custom_disk(self):
        """Test custom disk configuration."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            disk="sda",
        )

        assert "d-i partman-auto/disk string /dev/sda" in preseed
        assert "d-i grub-installer/bootdev string /dev/sda" in preseed

    def test_preseed_partitioning_confirmation(self):
        """Test partitioning confirmation settings."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert (
            "d-i partman-partitioning/confirm_write_new_label boolean true" in preseed
        )
        assert "d-i partman/choose_partition select finish" in preseed
        assert "d-i partman/confirm boolean true" in preseed
        assert "d-i partman/confirm_nooverwrite boolean true" in preseed

    def test_preseed_apt_settings(self):
        """Test APT repository settings."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i apt-setup/non-free-firmware boolean true" in preseed
        assert "d-i apt-setup/non-free boolean false" in preseed
        assert "d-i apt-setup/contrib boolean false" in preseed
        assert "d-i apt-setup/disable-cdrom-entries boolean true" in preseed
        assert "d-i apt-setup/services-select multiselect security, updates" in preseed
        assert "d-i apt-setup/security_host string security.debian.org" in preseed

    def test_preseed_package_selection(self):
        """Test package selection in preseed."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "tasksel tasksel/first multiselect standard, ssh-server" in preseed
        assert "openssh-server" in preseed
        assert "sudo" in preseed
        assert "curl" in preseed
        assert "wget" in preseed
        assert "ca-certificates" in preseed
        assert "python3" in preseed
        assert "python3-pip" in preseed
        assert "python3-venv" in preseed
        assert "d-i pkgsel/upgrade select full-upgrade" in preseed
        assert "d-i pkgsel/update-policy select unattended-upgrades" in preseed

    def test_preseed_grub_settings(self):
        """Test GRUB bootloader settings."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i grub-installer/only_debian boolean true" in preseed
        assert "d-i grub-installer/with_other_os boolean false" in preseed
        # Serial console for OpenBSD VMM
        assert "console=ttyS0,115200n8" in preseed

    def test_preseed_finish_settings(self):
        """Test installation finish settings."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i debian-installer/exit/halt boolean true" in preseed
        assert "d-i debian-installer/exit/poweroff boolean true" in preseed

    def test_preseed_late_command(self):
        """Test late_command section for post-installation setup."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i preseed/late_command string" in preseed
        assert "mkdir -p /target/etc/sysmanage-agent" in preseed
        assert "mkdir -p /target/var/log/sysmanage-agent" in preseed
        assert "mkdir -p /target/var/lib/sysmanage-agent" in preseed
        assert 'echo "vm01" > /target/etc/hostname' in preseed
        assert 'echo "127.0.0.1 localhost" > /target/etc/hosts' in preseed
        assert (
            'echo "192.168.1.100 vm01.example.com vm01" >> /target/etc/hosts' in preseed
        )
        assert "in-target systemctl enable sysmanage-firstboot.service" in preseed
        assert "setsid sh -c" in preseed
        assert "poweroff -f" in preseed

    def test_preseed_debian_version(self):
        """Test custom Debian version."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
            debian_version="11",
            debian_codename="bullseye",
        )

        assert "# Debian 11 (bullseye) Preseed File" in preseed
        assert "d-i mirror/suite string bullseye" in preseed

    def test_preseed_popularity_contest_disabled(self):
        """Test popularity contest is disabled."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$user_hash",
            root_password_hash="$6$root_hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert (
            "popularity-contest popularity-contest/participate boolean false" in preseed
        )


class TestDebianFirstBootScript:
    """Test cases for Debian firstboot script generation."""

    def test_generate_firstboot_script_basic(self):
        """Test basic firstboot script generation."""
        script = generate_firstboot_script()

        assert script.startswith("#!/bin/bash")
        assert "First boot setup" in script

    def test_firstboot_script_logging(self):
        """Test logging configuration in firstboot script."""
        script = generate_firstboot_script()

        assert 'LOGFILE="/var/log/sysmanage-firstboot.log"' in script
        assert 'exec >>"$LOGFILE" 2>&1' in script
        assert "$(date)" in script

    def test_firstboot_script_network_wait(self):
        """Test network waiting logic."""
        script = generate_firstboot_script()

        assert "Waiting for network" in script
        assert "ping -c 1 deb.debian.org" in script
        assert "seq 1 30" in script
        assert "sleep 2" in script

    def test_firstboot_script_apt_update(self):
        """Test apt-get update."""
        script = generate_firstboot_script()

        assert "apt-get update" in script

    def test_firstboot_script_python_dependencies(self):
        """Test Python dependencies installation."""
        script = generate_firstboot_script()

        assert "DEBIAN_FRONTEND=noninteractive apt-get install -y" in script
        assert "python3" in script
        assert "python3-pip" in script
        assert "python3-venv" in script
        assert "python3-websockets" in script
        assert "python3-yaml" in script
        assert "python3-aiohttp" in script
        assert "python3-cryptography" in script
        assert "python3-sqlalchemy" in script
        assert "python3-alembic" in script
        assert "python3-bcrypt" in script
        assert "python3-pydantic" in script

    def test_firstboot_script_agent_installation_local_deb(self):
        """Test agent installation from local .deb package."""
        script = generate_firstboot_script()

        assert "if [ -f /root/sysmanage-agent.deb ]" in script
        assert "dpkg -i /root/sysmanage-agent.deb" in script
        assert "apt-get install -f -y" in script
        assert "rm -f /root/sysmanage-agent.deb" in script

    def test_firstboot_script_agent_installation_wheel(self):
        """Test agent installation from wheel package."""
        script = generate_firstboot_script()

        assert "if [ -f /root/sysmanage_agent.whl ]" in script
        assert (
            "pip3 install --break-system-packages /root/sysmanage_agent.whl" in script
        )
        assert "rm -f /root/sysmanage_agent.whl" in script

    def test_firstboot_script_agent_installation_github(self):
        """Test agent installation from GitHub."""
        script = generate_firstboot_script()

        assert "Installing from GitHub releases" in script
        assert "api.github.com/repos/bceverly/sysmanage-agent/releases/latest" in script
        assert "pip3 install --break-system-packages sysmanage-agent" in script

    def test_firstboot_script_systemd_service_creation(self):
        """Test systemd service creation."""
        script = generate_firstboot_script()

        assert "Creating systemd service" in script
        assert "/etc/systemd/system/sysmanage-agent.service" in script
        assert "[Unit]" in script
        assert "Description=SysManage Agent" in script
        assert "After=network-online.target" in script
        assert "[Service]" in script
        assert "Type=simple" in script
        assert "ExecStart=/usr/bin/python3 -m sysmanage_agent" in script
        assert "WorkingDirectory=/var/lib/sysmanage-agent" in script
        assert "Restart=always" in script
        assert "[Install]" in script
        assert "WantedBy=multi-user.target" in script

    def test_firstboot_script_service_enablement(self):
        """Test service enablement and start."""
        script = generate_firstboot_script()

        assert "systemctl daemon-reload" in script
        assert "systemctl enable sysmanage-agent" in script
        assert "systemctl start sysmanage-agent" in script
        assert "systemctl status sysmanage-agent --no-pager" in script

    def test_firstboot_script_cleanup(self):
        """Test firstboot service cleanup."""
        script = generate_firstboot_script()

        assert "systemctl disable sysmanage-firstboot.service" in script
        assert "rm -f /etc/systemd/system/sysmanage-firstboot.service" in script
        assert "Firstboot service disabled and cleaned up" in script

    def test_firstboot_script_debian_version(self):
        """Test custom Debian version in firstboot script."""
        script = generate_firstboot_script(debian_version="11")

        assert "Debian version: 11" in script

    def test_firstboot_script_with_server_config(self):
        """Test firstboot script with server configuration."""
        script = generate_firstboot_script(
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
        )

        assert "Writing sysmanage-agent configuration" in script
        assert "/etc/sysmanage-agent.yaml" in script
        assert 'hostname: "sysmanage.example.com"' in script
        assert "port: 8443" in script
        assert "use_https: true" in script

    def test_firstboot_script_with_server_config_http(self):
        """Test firstboot script with HTTP server configuration."""
        script = generate_firstboot_script(
            server_hostname="sysmanage.example.com",
            server_port=8080,
            use_https=False,
        )

        assert "use_https: false" in script
        assert "port: 8080" in script

    def test_firstboot_script_with_auto_approve_token(self):
        """Test firstboot script with auto-approve token."""
        token = "12345678-1234-1234-1234-123456789012"
        script = generate_firstboot_script(
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert "auto_approve:" in script
        assert f'token: "{token}"' in script

    def test_firstboot_script_without_auto_approve_token(self):
        """Test firstboot script without auto-approve token."""
        script = generate_firstboot_script(
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token=None,
        )

        # Config section should be present but no auto_approve
        assert "Writing sysmanage-agent configuration" in script
        # Check that auto_approve is not in the script
        assert "auto_approve:" not in script

    def test_firstboot_script_without_server_config(self):
        """Test firstboot script without server configuration."""
        script = generate_firstboot_script()

        # Should not have config writing commands
        assert "Writing sysmanage-agent configuration" not in script

    def test_firstboot_script_partial_server_config(self):
        """Test firstboot script with partial server config (only hostname)."""
        script = generate_firstboot_script(
            server_hostname="sysmanage.example.com",
            server_port=None,  # Missing port
            use_https=True,
        )

        # Should not write config if port is missing
        assert "Writing sysmanage-agent configuration" not in script

    def test_firstboot_script_set_e(self):
        """Test that script exits on error."""
        script = generate_firstboot_script()

        assert "set -e" in script


class TestDebianFirstBootSystemdService:
    """Test cases for Debian firstboot systemd service generation."""

    def test_generate_service_basic(self):
        """Test basic systemd service generation."""
        service = generate_firstboot_systemd_service()

        assert "[Unit]" in service
        assert "[Service]" in service
        assert "[Install]" in service

    def test_service_description(self):
        """Test service description."""
        service = generate_firstboot_systemd_service()

        assert "Description=SysManage Agent First Boot Setup" in service

    def test_service_dependencies(self):
        """Test service dependencies."""
        service = generate_firstboot_systemd_service()

        assert "After=network-online.target" in service
        assert "Wants=network-online.target" in service

    def test_service_condition_path(self):
        """Test condition path exists for firstboot script."""
        service = generate_firstboot_systemd_service()

        assert "ConditionPathExists=/root/sysmanage-firstboot.sh" in service

    def test_service_type_oneshot(self):
        """Test service type is oneshot."""
        service = generate_firstboot_systemd_service()

        assert "Type=oneshot" in service

    def test_service_exec_start(self):
        """Test ExecStart command."""
        service = generate_firstboot_systemd_service()

        assert "ExecStart=/bin/bash /root/sysmanage-firstboot.sh" in service

    def test_service_remain_after_exit(self):
        """Test RemainAfterExit setting."""
        service = generate_firstboot_systemd_service()

        assert "RemainAfterExit=yes" in service

    def test_service_output_to_journal(self):
        """Test output to journal."""
        service = generate_firstboot_systemd_service()

        assert "StandardOutput=journal" in service
        assert "StandardError=journal" in service

    def test_service_wanted_by_multiuser(self):
        """Test WantedBy multi-user.target."""
        service = generate_firstboot_systemd_service()

        assert "WantedBy=multi-user.target" in service


class TestDebianGrubSerialConfig:
    """Test cases for GRUB serial console configuration."""

    def test_generate_grub_config_basic(self):
        """Test basic GRUB config generation."""
        config = generate_grub_serial_config()

        assert "# Serial console configuration for OpenBSD VMM" in config

    def test_grub_terminal_setting(self):
        """Test GRUB_TERMINAL setting."""
        config = generate_grub_serial_config()

        assert 'GRUB_TERMINAL="serial console"' in config

    def test_grub_serial_command(self):
        """Test GRUB_SERIAL_COMMAND setting."""
        config = generate_grub_serial_config()

        assert (
            'GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"'
            in config
        )

    def test_grub_cmdline_default(self):
        """Test GRUB_CMDLINE_LINUX_DEFAULT setting."""
        config = generate_grub_serial_config()

        assert 'GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0,115200n8"' in config

    def test_grub_cmdline_linux(self):
        """Test GRUB_CMDLINE_LINUX setting."""
        config = generate_grub_serial_config()

        assert 'GRUB_CMDLINE_LINUX="console=ttyS0,115200n8"' in config


class TestScriptContentSecurity:
    """Security tests for generated scripts and configs."""

    def test_no_hardcoded_secrets_in_config(self):
        """Test config doesn't have hardcoded secrets."""
        config = generate_agent_config(hostname="test.com", port=8443, use_https=True)

        # Check for common secret patterns (passwords should only appear in hash form)
        assert "secret_key" not in config.lower()
        # password appears in context of restricted_paths, which is fine
        lines_with_password = [
            line
            for line in config.split("\n")
            if "password" in line.lower() and "passwd" not in line.lower()
        ]
        # No actual password values should be present
        assert len(lines_with_password) == 0

    def test_no_hardcoded_secrets_in_preseed(self):
        """Test preseed uses hashed passwords, not plain text."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$rounds=5000$test",
            root_password_hash="$6$rounds=5000$root",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        # Passwords in preseed should be hashed (start with $6$ for SHA-512)
        assert "$6$rounds=5000$test" in preseed
        assert "$6$rounds=5000$root" in preseed
        # Make sure we're using password-crypted, not plain password
        assert "password-crypted password" in preseed

    def test_no_hardcoded_secrets_in_firstboot(self):
        """Test firstboot script doesn't have hardcoded secrets."""
        script = generate_firstboot_script()

        # No hardcoded passwords
        assert "secret" not in script.lower() or "security:" in script.lower()

    def test_proper_quoting_hostname(self):
        """Test proper quoting of hostname in config."""
        config = generate_agent_config(
            hostname="test.example.com", port=8443, use_https=True
        )

        assert 'hostname: "test.example.com"' in config

    def test_special_characters_in_hostname(self):
        """Test handling of special characters in hostname."""
        config = generate_agent_config(
            hostname="test-server_01.subdomain.example.com",
            port=8443,
            use_https=True,
        )

        assert "test-server_01.subdomain.example.com" in config

    def test_auto_approve_token_properly_quoted(self):
        """Test auto-approve token is properly quoted."""
        token = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        config = generate_agent_config(
            hostname="test.com",
            port=8443,
            use_https=True,
            auto_approve_token=token,
        )

        assert f'token: "{token}"' in config


class TestScriptShellCompatibility:
    """Test shell compatibility of generated scripts."""

    def test_firstboot_has_bash_shebang(self):
        """Test firstboot script has bash shebang (uses bash features)."""
        script = generate_firstboot_script()

        assert script.startswith("#!/bin/bash")

    def test_systemd_service_is_valid_unit(self):
        """Test systemd service is a valid unit file format."""
        service = generate_firstboot_systemd_service()

        # Must have required sections
        assert "[Unit]" in service
        assert "[Service]" in service
        assert "[Install]" in service

        # Check section order (Unit should come before Service)
        unit_pos = service.index("[Unit]")
        service_pos = service.index("[Service]")
        install_pos = service.index("[Install]")

        assert unit_pos < service_pos
        assert service_pos < install_pos

    def test_preseed_has_valid_format(self):
        """Test preseed file has valid d-i format."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        # All d-i directives should follow the pattern
        lines = preseed.split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("d-i "):
                # Should have at least 3 parts: d-i key type value
                parts = stripped.split()
                assert len(parts) >= 3, f"Invalid d-i directive: {stripped}"

    def test_grub_config_has_valid_format(self):
        """Test GRUB config has valid shell variable format."""
        config = generate_grub_serial_config()

        lines = config.split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Should be VARIABLE="value" format
                assert "=" in stripped, f"Invalid GRUB config line: {stripped}"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_preseed_with_ipv6_addresses(self):
        """Test preseed generation still works with IPv4 (IPv6 not fully supported)."""
        # Currently the function uses IPv4 addresses
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="10.0.0.1",
            vm_ip="10.0.0.100",
        )

        assert "10.0.0.1" in preseed
        assert "10.0.0.100" in preseed

    def test_config_with_minimum_port(self):
        """Test config with minimum valid port number."""
        config = generate_agent_config(hostname="test.com", port=1, use_https=True)

        assert "port: 1" in config

    def test_config_with_maximum_port(self):
        """Test config with maximum valid port number."""
        config = generate_agent_config(hostname="test.com", port=65535, use_https=True)

        assert "port: 65535" in config

    def test_preseed_with_long_hostname(self):
        """Test preseed with long hostname."""
        long_hostname = "vm01." + "subdomain." * 10 + "example.com"
        preseed = generate_preseed_file(
            hostname=long_hostname,
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "vm01" in preseed  # Short hostname
        assert "subdomain." in preseed  # Domain part

    def test_preseed_with_numeric_username(self):
        """Test preseed with numeric username."""
        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin123",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )

        assert "d-i passwd/username string admin123" in preseed

    def test_firstboot_with_all_parameters(self):
        """Test firstboot script with all parameters specified."""
        script = generate_firstboot_script(
            debian_version="12",
            server_hostname="sysmanage.example.com",
            server_port=8443,
            use_https=True,
            auto_approve_token="test-token-uuid",
        )

        assert "Debian version: 12" in script
        assert "sysmanage.example.com" in script
        assert "8443" in script
        assert "use_https: true" in script
        assert "test-token-uuid" in script

    def test_config_returns_string(self):
        """Test that all generator functions return strings."""
        config = generate_agent_config(hostname="test.com", port=8443, use_https=True)
        assert isinstance(config, str)

        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )
        assert isinstance(preseed, str)

        firstboot = generate_firstboot_script()
        assert isinstance(firstboot, str)

        service = generate_firstboot_systemd_service()
        assert isinstance(service, str)

        grub = generate_grub_serial_config()
        assert isinstance(grub, str)

    def test_config_not_empty(self):
        """Test that all generator functions return non-empty strings."""
        config = generate_agent_config(hostname="test.com", port=8443, use_https=True)
        assert len(config) > 0

        preseed = generate_preseed_file(
            hostname="vm01.example.com",
            username="admin",
            user_password_hash="$6$hash",
            root_password_hash="$6$hash",
            gateway_ip="192.168.1.1",
            vm_ip="192.168.1.100",
        )
        assert len(preseed) > 0

        firstboot = generate_firstboot_script()
        assert len(firstboot) > 0

        service = generate_firstboot_systemd_service()
        assert len(service) > 0

        grub = generate_grub_serial_config()
        assert len(grub) > 0
