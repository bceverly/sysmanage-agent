# SysManage Agent - Privacy Policy

**Effective Date**: October 20, 2025
**Last Updated**: October 20, 2025

## Overview

This Privacy Policy describes how the SysManage Agent ("the Agent", "software") collects, uses, and protects information when you use our system monitoring and management software.

## SignPath Foundation Requirement

This privacy policy is required for SignPath Foundation code signing certification. It defines what user data is collected, how it is transmitted, and how it is used, in compliance with SignPath Foundation Terms of Use.

## Data Collection Summary

### What Data Does the Agent Collect?

The SysManage Agent is a **system monitoring and management tool** that collects the following types of information:

#### 1. System Information
- Operating system name and version
- System architecture (x64, ARM64)
- Hostname and computer name
- System uptime and boot time
- CPU, memory, and disk usage statistics
- Network interface information
- Installed software inventory
- Running processes and services

#### 2. Configuration Data
- Agent configuration settings
- Server connection details (hostname, port)
- Authentication credentials (stored locally, encrypted)
- Policy assignments and compliance status

#### 3. Operational Data
- Agent installation timestamp
- Agent version information
- Service status and health checks
- Error logs and diagnostic information
- Task execution results

### What Data Does the Agent NOT Collect?

The Agent does **NOT** collect:
- ❌ Personal files or documents
- ❌ Web browsing history
- ❌ Passwords or credentials (except agent's own authentication)
- ❌ Email content or communications
- ❌ Financial information
- ❌ Personal identifiable information (PII) beyond system/user names
- ❌ Biometric data
- ❌ Location data (beyond network information)

## Data Transmission

### Where is Data Sent?

All collected data is transmitted **exclusively** to:

1. **Your Self-Hosted SysManage Server**
   - You configure the server address during installation
   - Data is sent to YOUR infrastructure, not to any third-party service
   - Communication uses HTTPS (encrypted in transit)
   - Certificate-based authentication

### No Third-Party Data Sharing

**Important**: The SysManage Agent does NOT send any data to:
- ❌ External analytics services
- ❌ Telemetry services
- ❌ Advertising networks
- ❌ Third-party monitoring services
- ❌ The SysManage project developers
- ❌ Any other external parties

**All data remains within your infrastructure.**

## How Data is Used

### Primary Purpose

Data collected by the Agent is used exclusively for:

1. **System Monitoring**: Track system health, performance, and resource usage
2. **Configuration Management**: Deploy and enforce system configurations
3. **Software Management**: Inventory and manage installed software
4. **Compliance Reporting**: Verify system compliance with policies
5. **Security Management**: Monitor security status and vulnerabilities
6. **Administrative Tasks**: Execute system administration commands

### Data Retention

- **Local Storage**: Agent maintains a local SQLite database for operational data
- **Local Retention**: Configurable (default: 30 days)
- **Server Storage**: Determined by your SysManage Server configuration
- **No External Retention**: No data is retained by external parties

## Data Security

### Encryption

- **In Transit**: All communication between Agent and Server uses HTTPS/TLS
- **At Rest**: Local database can be encrypted (depends on OS file system encryption)
- **Authentication**: Certificate-based mutual TLS authentication

### Access Control

- **Agent Service**: Runs as SYSTEM (Windows) or root (Linux) with necessary privileges
- **Local Database**: Protected by OS file system permissions
- **Configuration**: Stored in protected system directories

### No Automatic Updates or Phone-Home

The Agent does NOT:
- ❌ Automatically phone home to check for updates
- ❌ Send usage statistics to developers
- ❌ Report crashes or errors externally
- ❌ Download content from external servers (except during initial installation)

## Your Rights and Control

### Data Access

You have complete control over all collected data:
- Access all data via your SysManage Server
- Export data in standard formats
- Delete data at any time

### Configuration Control

You can:
- Configure what data is collected
- Disable specific monitoring features
- Set data retention periods
- Remove the Agent at any time

### Uninstallation

To remove the Agent and all local data:

**Windows**:
```powershell
# Uninstall via Control Panel or:
$productCode = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq "SysManage Agent" }).IdentifyingNumber
Start-Process msiexec.exe -ArgumentList "/x $productCode /qn" -Wait -Verb RunAs

# Remove all data (optional):
Remove-Item -Path "C:\ProgramData\SysManage" -Recurse -Force
```

**Linux**:
```bash
# APT/Debian:
sudo apt remove --purge sysmanage-agent

# RPM/RHEL:
sudo dnf remove sysmanage-agent

# Remove all data (optional):
sudo rm -rf /var/lib/sysmanage-agent
sudo rm -rf /etc/sysmanage-agent
```

## Compliance

### GDPR Compliance (European Users)

If you operate in the European Union:
- You (the system administrator) are the **data controller**
- The SysManage Agent is a **data processing tool**
- You are responsible for GDPR compliance in your use of the Agent
- Ensure users are informed about monitoring per GDPR Article 13

### CCPA Compliance (California Users)

If you operate in California:
- You must inform employees about monitoring per CCPA requirements
- Users have rights to access and delete their data
- Data is not sold or shared with third parties

### Industry Standards

The Agent follows security best practices:
- HTTPS/TLS for all communications
- Certificate-based authentication
- Principle of least privilege
- Regular security updates

## Open Source Transparency

### Source Code Availability

The SysManage Agent is **open source** (MIT License):
- Full source code: https://github.com/bceverly/sysmanage-agent
- You can audit exactly what data is collected
- You can verify no hidden data collection
- You can modify the code for your needs

### Community Verification

The open source nature ensures:
- Independent security audits are possible
- Community review of data handling
- No hidden backdoors or data exfiltration
- Transparent security practices

## Children's Privacy

The SysManage Agent is enterprise/system administration software not directed at children under 13. We do not knowingly collect information from children.

## Changes to This Policy

We may update this privacy policy as the software evolves. Changes will be:
- Posted to the documentation site
- Announced in release notes
- Dated with "Last Updated" timestamp

## SignPath Foundation Compliance

### Data Collection Disclosure (SignPath Requirement)

**Does the software collect and automatically submit user data?**

**Answer**: YES, with important caveats:

1. **What is collected**: System monitoring data (see "System Information" section)
2. **Where it's sent**: Only to YOUR self-hosted SysManage Server (not to any third party)
3. **Purpose**: System monitoring and management
4. **User control**: Full control over server address, data collection, and retention

**Important**: This is fundamentally different from typical "phone home" scenarios because:
- YOU control the destination server
- Data stays within YOUR infrastructure
- No third-party data sharing occurs
- Completely transparent (open source)

## Contact Information

### For Privacy Questions

- **Project Repository**: https://github.com/bceverly/sysmanage-agent/issues
- **Documentation**: https://bceverly.github.io/sysmanage-docs/

### For Security Issues

- **Security Policy**: https://github.com/bceverly/sysmanage-agent/security/policy
- **Report Vulnerabilities**: Via GitHub Security Advisories

## Publication Locations

This privacy policy is published at:
- **Repository**: https://github.com/bceverly/sysmanage-agent/blob/main/PRIVACY.md
- **Documentation**: https://bceverly.github.io/sysmanage-docs/ (linked from all download pages)
