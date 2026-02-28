<div align="center">
  <img src="sysmanage-logo.svg" alt="SysManage" width="330"/>
</div>

# SysManage Agent

[![CI/CD Pipeline](https://github.com/bceverly/sysmanage-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/bceverly/sysmanage-agent/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Linting](https://img.shields.io/badge/pylint-10.00/10-brightgreen.svg)](https://github.com/PyCQA/pylint)
[![Security: bandit](https://img.shields.io/badge/bandit-passing-brightgreen.svg)](https://github.com/PyCQA/bandit) [![Security: semgrep](https://img.shields.io/badge/semgrep-scan-brightgreen.svg)](https://semgrep.dev/) [![Security: safety](https://img.shields.io/badge/safety-passing-brightgreen.svg)](https://pypi.org/project/safety/) [![Security: snyk](https://img.shields.io/badge/snyk-monitored-brightgreen.svg)](https://snyk.io/) [![Security: trufflehog](https://img.shields.io/badge/trufflehog-clean-brightgreen.svg)](https://github.com/trufflesecurity/trufflehog)
[![Test Coverage](https://img.shields.io/badge/test%20coverage-92%25-brightgreen.svg)]()
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=bugs)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent)

A lightweight, secure, cross-platform system monitoring agent that connects to SysManage Server via WebSocket for real-time remote management.

## 📚 Documentation

**Complete documentation is available at [sysmanage.org](https://sysmanage.org)**

### Quick Links
- **🚀 [Getting Started](https://sysmanage.org/docs/getting-started/)** - Quick start guide and tutorials
- **🛠️ [Installation Guide](https://sysmanage.org/docs/agent/installation.html)** - Cross-platform installation
- **⚙️ [Configuration](https://sysmanage.org/docs/agent/configuration.html)** - Auto-discovery and manual setup
- **🔐 [Security](https://sysmanage.org/docs/security/)** - Security features and mTLS setup
- **🔧 [Privileged Execution](https://sysmanage.org/docs/agent/privileged-execution.html)** - Running with elevated privileges

## Overview

SysManage Agent is a headless Python application designed to be installed on remote systems for centralized monitoring and management. It establishes a secure WebSocket connection to the SysManage Server and provides real-time system information, command execution capabilities, and health monitoring.

### Key Features

- 🔄 **Real-time Communication**: WebSocket-based connection for instant responsiveness
- 🖥️ **Cross-platform Support**: Linux, Windows, macOS, FreeBSD, OpenBSD
- 🔐 **Secure by Design**: Encrypted communication with mTLS validation, no inbound ports required
- 📊 **System Monitoring**: CPU, memory, disk, network metrics collection
- ⚡ **Command Execution**: Remote command execution with security controls
- 🔧 **Package Management**: Remote software installation, updates, and OS version upgrade detection
- 💓 **Health Monitoring**: Automatic heartbeat and status reporting
- 🌍 **Multi-language Support**: Native support for 14 languages
- 🏃‍♂️ **Lightweight**: Minimal resource footprint and dependencies
- 🔍 **Auto-Discovery**: Automatically discover and configure with SysManage servers on the network

### Supported Platforms

- 🐧 **Linux**: Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky, AlmaLinux, Oracle Linux
- 🪟 **Windows**: 10, 11, Server 2019/2022
- 🍎 **macOS**: Intel and Apple Silicon
- 🔒 **FreeBSD**: Latest stable versions
- 🛡️ **OpenBSD**: Latest stable versions

## Installation

### Package Repositories (Recommended)

#### Ubuntu/Debian - APT Repository

```bash
# Add the repository
echo "deb [trusted=yes] https://bceverly.github.io/sysmanage-docs/repo/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/sysmanage.list

# Update and install
sudo apt update
sudo apt install sysmanage-agent

# Configure
sudo nano /etc/sysmanage-agent.yaml
sudo systemctl restart sysmanage-agent
```

**Supported:** Ubuntu 22.04+, Debian 11+

#### RHEL/CentOS/Fedora/Rocky/AlmaLinux/Oracle Linux - YUM/DNF Repository

**EL9 (RHEL 9, Rocky 9, AlmaLinux 9, Oracle Linux 9, CentOS Stream 9):**
```bash
sudo tee /etc/yum.repos.d/sysmanage.repo << EOF
[sysmanage]
name=SysManage Agent Repository
baseurl=https://bceverly.github.io/sysmanage-docs/repo/rpm/el9/x86_64
enabled=1
gpgcheck=0
EOF

sudo dnf install sysmanage-agent
```

**EL8 (RHEL 8, Rocky 8, AlmaLinux 8, Oracle Linux 8):**
```bash
# Install Python 3.11 first
sudo dnf module install python311

sudo tee /etc/yum.repos.d/sysmanage.repo << EOF
[sysmanage]
name=SysManage Agent Repository
baseurl=https://bceverly.github.io/sysmanage-docs/repo/rpm/el8/x86_64
enabled=1
gpgcheck=0
EOF

sudo dnf install sysmanage-agent
```

**Fedora 38+:**
```bash
sudo tee /etc/yum.repos.d/sysmanage.repo << EOF
[sysmanage]
name=SysManage Agent Repository
baseurl=https://bceverly.github.io/sysmanage-docs/repo/rpm/fedora/39/x86_64
enabled=1
gpgcheck=0
EOF

sudo dnf install sysmanage-agent
```

### Direct Downloads

Download packages from [GitHub Releases](https://github.com/bceverly/sysmanage-agent/releases)

## Prerequisites

- **Python**: 3.9, 3.11, or 3.12 (Python 3.13 not yet supported)
- **Network**: Outbound HTTPS access to SysManage Server
- **Privileges**: Administrative rights for system management tasks (optional)

**📖 For detailed platform-specific installation instructions, visit [sysmanage.org/docs/agent/installation.html](https://sysmanage.org/docs/agent/installation.html)**

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/bceverly/sysmanage-agent.git
cd sysmanage-agent

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate
# Note: On BSD systems (FreeBSD, OpenBSD, NetBSD), use: . .venv/bin/activate
# Windows users: .venv\Scripts\activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Start the agent
gmake start                    # Standard agent
# gmake start-privileged       # Privileged agent (for package management)
```

## Configuration

### Auto-Discovery (Recommended)
SysManage Agent includes automatic server discovery that eliminates the need for manual configuration in most scenarios:

1. **No Configuration Required**: If no configuration file exists, the agent automatically attempts to discover SysManage servers on the network
2. **Network Scanning**: The agent sends UDP broadcast discovery requests and listens for server announcements
3. **Automatic Configuration**: Once a server is discovered, the agent writes a complete configuration file automatically
4. **Fallback**: If auto-discovery fails, manual configuration is still supported

### Manual Configuration (Alternative)
Create configuration file at:
- **Linux/macOS/BSD**: `/etc/sysmanage-agent.yaml`
- **Windows**: `C:\ProgramData\SysManage\sysmanage-agent.yaml`

**📖 For complete configuration options, visit [sysmanage.org/docs/agent/configuration.html](https://sysmanage.org/docs/agent/configuration.html)**

## Security

SysManage Agent implements multiple layers of security:

- **Communication Security**: TLS 1.2+ encryption for all server communication
- **Mutual TLS (mTLS)**: Certificate-based authentication after host approval
- **Agent Security**: Minimal privilege execution, input validation, safe command execution
- **Network Security**: No inbound ports required, outbound connections only
- **Certificate Management**: Automatic certificate retrieval and validation

**📖 For complete security documentation, visit [sysmanage.org/docs/security/](https://sysmanage.org/docs/security/)**

## Privileged Execution

The agent requires elevated privileges for certain system management operations, particularly package management. Cross-platform privileged runner scripts are included:

- **Unix-like systems**: `run-privileged.sh` - Works on macOS, Linux, and OpenBSD
- **Windows**: `run-privileged.cmd` and `run-privileged.ps1` - Batch and PowerShell scripts

**📖 For detailed privileged execution setup, visit [sysmanage.org/docs/agent/privileged-execution.html](https://sysmanage.org/docs/agent/privileged-execution.html)**

## Development

### Running Tests
```bash
# Run all tests with coverage
make test

# Direct pytest execution
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Run linting
make lint
```

### Code Quality Standards
- **Perfect 10.00/10 PyLint score**: Clean, maintainable code
- **Black formatting**: Consistent code style
- **Comprehensive security scanning**: Bandit, Semgrep, Safety, Snyk, TruffleHog
- **Cross-platform testing**: All major operating systems

## Internationalization

SysManage Agent supports 14 languages for logging and system messages:

| Language | Code | Status |
|----------|------|--------|
| English | `en` | ✅ Complete |
| Spanish | `es` | ✅ Complete |
| French | `fr` | ✅ Complete |
| German | `de` | ✅ Complete |
| Italian | `it` | ✅ Complete |
| Portuguese | `pt` | ✅ Complete |
| Dutch | `nl` | ✅ Complete |
| Japanese | `ja` | ✅ Complete |
| Simplified Chinese | `zh_CN` | ✅ Complete |
| Traditional Chinese | `zh_TW` | ✅ Complete |
| Korean | `ko` | ✅ Complete |
| Russian | `ru` | ✅ Complete |
| Arabic | `ar` | ✅ Complete |
| Hindi | `hi` | ✅ Complete |

## Project Structure

```
sysmanage-agent/
├── main.py                 # Agent entry point
├── config.py               # Configuration management
├── registration.py         # Server registration logic
├── websocket_client.py     # WebSocket communication
├── system_info.py          # System information collection
├── command_executor.py     # Command execution engine
├── tests/                  # Test suite
├── requirements.txt        # Python dependencies
└── run-privileged.sh       # Privileged execution script
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Ensure code quality (`make lint test`)
5. Submit a pull request

**📖 For detailed contribution guidelines, visit [sysmanage.org/docs/](https://sysmanage.org/docs/)**

## Related Projects

- **[SysManage Server](https://github.com/bceverly/sysmanage)** - Central management platform
- **[Documentation Site](https://github.com/bceverly/sysmanage-docs)** - Source for sysmanage.org documentation

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for details.

## Support

- **📖 Documentation**: [sysmanage.org](https://sysmanage.org)
- **🐛 Issues**: [GitHub Issues](https://github.com/bceverly/sysmanage-agent/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/bceverly/sysmanage-agent/discussions)
- **🖥️ Server Project**: [SysManage Server](https://github.com/bceverly/sysmanage)

