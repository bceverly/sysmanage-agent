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
[![Test Coverage](https://img.shields.io/badge/test%20coverage-87%25-green.svg)]()
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=bugs)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=bceverly_sysmanage-agent&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=bceverly_sysmanage-agent)

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
- 🖥️ **Cross-platform Support**: Linux, Windows, macOS, FreeBSD, OpenBSD, NetBSD
- 🔐 **Secure by Design**: Encrypted communication with mTLS validation, no inbound ports required
- 📊 **System Monitoring**: CPU, memory, disk, network metrics collection
- ⚡ **Command Execution**: Remote command execution with security controls
- 🔧 **Package Management**: Remote software installation, updates, and OS version upgrade detection
- ⚙️ **Configuration Management**: applies desired-state profiles locally -- pull-style, so no inbound ports and no SSH -- via `ansible-core` on POSIX or the vendored DSC v3 engine on Windows, reporting per-task changed/ok/failed back over the same connection
- 💓 **Health Monitoring**: Automatic heartbeat and status reporting
- 🌍 **Multi-language Support**: Native support for 14 languages
- 🏃‍♂️ **Lightweight**: Minimal resource footprint and dependencies
- 🔍 **Auto-Discovery**: Automatically discover and configure with SysManage servers on the network

### Supported Platforms

- 🐧 **Linux**: Ubuntu 22.04/24.04/26.04 LTS, Debian 12+, RHEL, Rocky Linux, AlmaLinux, Oracle Linux and CentOS Stream 9 and 10, Fedora, Amazon Linux 2023, openSUSE Tumbleweed, SLES 15, Arch Linux, Alpine Linux 3.21/3.22
- 🪟 **Windows**: x64 and ARM64
- 🍎 **macOS**: Intel and Apple Silicon
- 🔒 **FreeBSD**: amd64
- 🛡️ **OpenBSD**: 7.9 and 8.0
- 🚩 **NetBSD**

## Installation

Install the agent from a signed native package. The full per-platform
instructions are at
[sysmanage.org/docs/agent/installation.html](https://sysmanage.org/docs/agent/installation.html);
the common cases are below. SysManage does not publish container images.

### Ubuntu - Launchpad PPA (Recommended)

```bash
sudo add-apt-repository ppa:bceverly/sysmanage-agent
sudo apt update
sudo apt install sysmanage-agent
```

### Debian - SysManage APT Repository

```bash
# Install the archive signing key and check its fingerprint:
#   896E ED43 9F5E 9BB1 FCA6 69A5 E033 E691 377F 0AE3
sudo install -d -m 0755 /usr/share/keyrings
curl -fsSL https://repo.sysmanage.org/agent/sysmanage-archive-keyring.gpg \
  | sudo tee /usr/share/keyrings/sysmanage-archive-keyring.gpg > /dev/null
gpg --show-keys /usr/share/keyrings/sysmanage-archive-keyring.gpg

# Add the repository, verified against that key
echo "deb [signed-by=/usr/share/keyrings/sysmanage-archive-keyring.gpg] https://repo.sysmanage.org/agent/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/sysmanage-agent.list

sudo apt update
sudo apt install sysmanage-agent
```

### RHEL Family, Fedora, Amazon Linux - Fedora Copr

RHEL, Rocky Linux, AlmaLinux, Oracle Linux and CentOS Stream 9 and 10, Fedora
43 and Amazon Linux 2023 (x86_64 and aarch64). Release 8 of the RHEL family is
not supported: the agent needs Python 3.9 or newer.

```bash
sudo dnf install epel-release      # RHEL family only; skip on Fedora and Amazon Linux
sudo dnf copr enable bceverly/sysmanage-agent
sudo dnf install sysmanage-agent
```

EL9 hosts that cannot reach Copr can use the signed DNF repository on the mirror:

```bash
sudo tee /etc/yum.repos.d/sysmanage-agent.repo << 'EOF'
[sysmanage-agent]
name=SysManage Agent
baseurl=https://repo.sysmanage.org/agent/rpm/el9/$basearch
enabled=1
gpgcheck=1
gpgkey=https://repo.sysmanage.org/agent/rpm/RPM-GPG-KEY-sysmanage
EOF
sudo dnf install sysmanage-agent
```

### openSUSE Tumbleweed, SLES 15 - Signed RPM Repositories

```bash
sudo rpm --import https://repo.sysmanage.org/agent/rpm/RPM-GPG-KEY-sysmanage
sudo zypper addrepo https://repo.sysmanage.org/agent/rpm/opensuse-tumbleweed/x86_64 sysmanage-agent   # Tumbleweed
# sudo zypper addrepo https://repo.sysmanage.org/agent/rpm/sles/15/x86_64 sysmanage-agent            # SLES 15
sudo zypper refresh
sudo zypper install sysmanage-agent
```

### Other Platforms

- **Arch Linux**: `yay -S sysmanage-agent` (AUR)
- **macOS**: `brew install bceverly/tap/sysmanage-agent`
- **Windows**: `winget install --id sysmanage.sysmanage-agent --exact` (x64), or
  the `.exe` bundle for x64 and ARM64 from the mirror
- **Alpine Linux, FreeBSD, OpenBSD, NetBSD**: packages from
  `https://repo.sysmanage.org/agent/<platform>/`. These downloads are **not
  signed**; each has a `.sha256` next to it. Check it before installing, as the
  installation guide shows.

### Point the Agent at Your Server

Edit `/etc/sysmanage-agent.yaml` (`C:\ProgramData\SysManage\sysmanage-agent.yaml`
on Windows), set `server.url`, and restart the agent. The agent needs outbound
port 443 to the server and nothing else. Then approve the host on the server's
Hosts page.

```yaml
server:
  url: "https://sysmanage.example.com"
  verify_ssl: true
```

```bash
sudo systemctl restart sysmanage-agent
```

## Prerequisites

- **Packages**: nothing to install first; each package brings what the agent needs
- **Network**: Outbound HTTPS (port 443) to the SysManage server
- **Privileges**: root or administrator rights to install the package

## Building from Source (Development)

For working on the agent itself. You need Python 3.9 through 3.14 (tested
across the full range in CI; 3.9 retained for macOS system Python) with its
development headers, a C compiler, and `make` (`gmake` on the BSDs).

```bash
git clone https://github.com/bceverly/sysmanage-agent.git
cd sysmanage-agent
make install-dev
cp installer/ubuntu/sysmanage-agent.yaml.example sysmanage-agent.yaml   # then set server.url
make start                     # gmake on the BSDs
# make start-privileged        # Privileged agent (for package management)
```

A source checkout reads `sysmanage-agent.yaml` in the project directory when
`/etc/sysmanage-agent.yaml` does not exist.

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

### MITRE "Lucky 13" (Unforgivable Vulnerabilities)

We test explicitly for the thirteen weakness classes in Steve Christey's MITRE paper [Unforgivable Vulnerabilities](https://cwe.mitre.org/documents/unforgivable_vulns/unforgivable.pdf) (2007): flaws so well documented and so easy to find that shipping one is unforgivable. The agent runs as root / SYSTEM and acts on the server's commands, so the checks focus on what a privileged process must never do and on refusing hostile values in those commands:

| # | Class (CWE) | What this repository checks |
|---|---|---|
| 1 | Buffer overflow (120) | 100 KB strings, null and wrong-type fields in commands are answered with an error, never crash the agent; nested commands are depth-limited |
| 2 | XSS (79) | The agent produces no HTML at all |
| 3 | Directory traversal (23) | Package names cannot be `../..`, `/full/path` or `./local.deb`; hostnames are validated |
| 4 | Remote file inclusion (98) | No `eval`/`exec`/dynamic imports/pickle/unsafe YAML on received data |
| 5 | SQL injection (89) | No SQL built from strings; package names cannot smuggle options (`-o ...`) or shell metacharacters |
| 6 | World-writable files (276) | Code, installers and packaging never make a file world-writable; deployed files keep the mode the server asked for |
| 7 | Direct request (425) | Not applicable: the agent serves no requests (checked in the server) |
| 8 | `authenticated=1` (472) | Not applicable: the agent accepts no logins (checked in the server) |
| 9 | Home-grown crypto (327) | No weak or home-made crypto; no `random` where a secret is involved |
| 10 | Privilege escalation via Help (271) | The privileged agent never launches a browser, help viewer or shell UI |
| 11 | Symlink following (61) | No predictable `/tmp` names; a symlink planted at a deploy path is replaced, never followed |
| 12 | Hard-coded / default password (259) | No credential ships in any agent config or in the code |
| 13 | Integer overflow (190) | `0xffffffff`, `2**63` and negative values in names and file modes are refused |

Exceptions are recorded with their reasons in `tests/lucky13/`. Run the checks with `make test-lucky13` (also part of `make security` and `make test`); CI runs them as their own step on every push.

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

