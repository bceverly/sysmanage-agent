<div align="center">
  <img src="sysmanage-logo.svg" alt="SysManage" width="330"/>
</div>

# SysManage Agent

[![CI/CD Pipeline](https://github.com/bceverly/sysmanage-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/bceverly/sysmanage-agent/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Linting](https://img.shields.io/badge/linting-pylint-blue.svg)](https://github.com/PyCQA/pylint)

A lightweight, secure, cross-platform system monitoring agent that connects to SysManage Server via WebSocket for real-time remote management.

## Overview

SysManage Agent is a headless Python application designed to be installed on remote systems for centralized monitoring and management. It establishes a secure WebSocket connection to the SysManage Server and provides real-time system information, command execution capabilities, and health monitoring.

### Key Features

- 🔄 **Real-time Communication**: WebSocket-based connection for instant responsiveness
- 🖥️ **Cross-platform Support**: Linux, Windows, macOS, FreeBSD, OpenBSD
- 🔐 **Secure by Design**: Encrypted communication with HMAC validation, no inbound ports required
- 📊 **System Monitoring**: CPU, memory, disk, network metrics collection
- ⚡ **Command Execution**: Remote command execution with security controls
- 🔧 **Package Management**: Remote software installation and updates
- 💓 **Health Monitoring**: Automatic heartbeat and status reporting
- 🌍 **Multi-language Support**: Native support for 14 languages
- 🏃‍♂️ **Lightweight**: Minimal resource footprint and dependencies
- 🔍 **Auto-Discovery**: Automatically discover and configure with SysManage servers on the network
- ⚙️ **Remote Configuration**: Receive and apply configuration updates from the server

## Architecture

The agent operates as a persistent service that:
1. **Auto-discovers** SysManage servers on the network (if no configuration exists)
2. **Connects** to SysManage Server via secure WebSocket with authentication tokens
3. **Registers** itself with system information (hostname, IP, platform) and awaits administrator approval
4. **Monitors** system health and sends periodic heartbeat messages
5. **Listens** for commands and configuration updates from the server
6. **Executes** commands securely with validation and resource limits
7. **Reports** command results and system status back to server with message integrity validation

### Internationalization

The SysManage Agent supports multiple languages for logging and system messages. The following languages are natively supported:

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

The agent uses the language specified in the configuration file for log messages and system output. If no language is specified, it defaults to English.

## Prerequisites

### System Requirements
- **Python**: 3.11 or 3.12 (Note: Python 3.13 is NOT yet supported due to package compatibility)
- **OS**: Linux, Windows, macOS, FreeBSD, or OpenBSD
- **Network**: Outbound HTTPS access to SysManage Server
- **Privileges**: Administrative rights for system management tasks

### Platform-Specific Installation Instructions

#### Linux (Ubuntu/Debian)
```bash
# Update package manager
sudo apt update

# Install Python (3.11 or 3.12 ONLY - not 3.13)
# For Ubuntu 22.04 through 24.10:
sudo apt install python3.11 python3.11-venv python3.11-dev python3-pip

# For Ubuntu with Python 3.12 (if available):
# sudo add-apt-repository ppa:deadsnakes/ppa
# sudo apt update
# sudo apt install python3.12 python3.12-venv python3.12-dev python3-pip

# Install build tools for cryptography packages and SQLite
sudo apt install build-essential libffi-dev libssl-dev pkg-config sqlite3

# Install Rust (required for cryptography)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### Linux (Ubuntu 25.04 or newer) - Building Python 3.12 from Source

Ubuntu 25.04+ only ships with Python 3.13, which is not yet compatible with many packages. You must build Python 3.12 from source:

```bash
# Install build dependencies
sudo apt install build-essential libssl-dev zlib1g-dev libbz2-dev \
    libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev \
    libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev \
    python3-openssl git pkg-config

# Download and build Python 3.12
cd /tmp
wget https://www.python.org/ftp/python/3.12.7/Python-3.12.7.tgz
tar -xf Python-3.12.7.tgz
cd Python-3.12.7

# Configure and build (this may take 10-15 minutes)
./configure --enable-optimizations --with-ensurepip=install
make -j$(nproc)
sudo make altinstall

# Verify installation
python3.12 --version

# Return to your project directory
cd ~/dev/sysmanage-agent

# Create virtual environment with Python 3.12
python3.12 -m venv .venv
source .venv/bin/activate

# Upgrade pip to latest version
pip install --upgrade pip

# Install Rust (required for cryptography)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### Linux (CentOS/RHEL/Fedora)
```bash
# Install Python 3.9+ (use available version)
sudo dnf install python3 python3-devel python3-pip

# If python3.9 is available in your distribution, you can also try:
# sudo dnf install python3.9 python3.9-devel python3-pip

# Install build tools and SQLite
sudo dnf groupinstall "Development Tools"
sudo dnf install libffi-devel openssl-devel pkg-config sqlite

# Install Rust (required for cryptography)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### macOS
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.9+ (will install latest Python 3)
brew install python3

# Or install a specific version if needed:
# brew install python@3.9

# Install SQLite3 (for local database)
brew install sqlite3

# Install Rust (required for cryptography)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build tools are included with Xcode Command Line Tools
xcode-select --install
```

#### Windows
```powershell
# 1. Install Chocolatey package manager (required for build tools)
# Run PowerShell as Administrator and execute:
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install GNU Make using Chocolatey (required for build processes)
# Run from Administrative Command Prompt or PowerShell:
choco install make

# 3. Install Python 3.9+ from https://python.org/downloads/
# Make sure to check "Add Python to PATH" during installation
# SQLite3 is included with Python installations on Windows

# 4. Install Rust from https://rustup.rs/
# Download and run rustup-init.exe

# 5. Install Git for Windows (includes build tools)
# Download from https://git-scm.com/download/win

# 6. Install Windows Build Tools (if needed for native packages)
# Note: windows-build-tools package is deprecated and may not work
# Instead, install Visual Studio Build Tools from Microsoft:
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
```

#### FreeBSD
```bash
# Update package manager
sudo pkg update

# Install Python 3.9+ (use available version)
sudo pkg install python3 py3-pip

# Or install a specific version if available:
# sudo pkg install python39 py39-pip

# Install SQLite3 (for local database)
sudo pkg install sqlite3

# Install build tools and Rust
sudo pkg install rust gcc cmake make pkg-config

# Set up environment
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### OpenBSD
```bash
# Update package manager
doas pkg_add -u

# Install Python 3.9+ (use available version)
doas pkg_add python-3 py3-pip

# Or install a specific version if available:
# doas pkg_add python-3.9 py3-pip

# Install SQLite3 (for local database)
doas pkg_add sqlite3

# Install build tools and Rust (REQUIRED for cryptography packages)
doas pkg_add rust gcc cmake gmake pkgconf

# Set up environment
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
source ~/.profile
```

**Important for OpenBSD**: Rust is absolutely required for building cryptography packages. The agent uses certificate-based authentication which requires cryptography support for security.

### Dependencies
All dependencies are automatically installed via `requirements.txt`:

**Core Runtime Dependencies:**
- `websockets>=13.0` - WebSocket client communication
- `PyYAML>=6.0.2` - Configuration file parsing
- `aiohttp>=3.12.0` - Asynchronous HTTP client for registration
- `cryptography>=41.0.0` - Certificate validation and TLS support (requires Rust compiler)
- `SQLAlchemy>=2.0.0` - Database ORM for local data storage
- `alembic>=1.12.0` - Database migration management

**Development Dependencies:**
- `pytest>=7.0.0` - Testing framework
- `pytest-asyncio>=0.21.0` - Async test support
- `pytest-cov>=4.0.0` - Test coverage reporting
- `black>=23.0.0` - Code formatting
- `pylint>=3.0.0` - Code linting
- `isort>=5.12.0` - Import sorting
- `bandit>=1.7.0` - Security linting
- `safety>=2.3.0,<4.0.0` - Security vulnerability scanning
- `typer>=0.9.0,<0.18.0` - CLI interface support

**Note:** The standard library `asyncio` is used for asynchronous operations but doesn't need to be installed separately as it's part of Python 3.7+.

### Required Directories and Permissions

The SysManage agent requires certain directories to exist with proper permissions for normal operation:

#### Certificate Storage Directory
**Default locations**: 
- **Linux/macOS/BSD**: `/etc/sysmanage-agent/` (automatically created if it doesn't exist)
- **Windows**: `C:\ProgramData\SysManage\` (automatically created if it doesn't exist)

```bash
# Create certificate directory with proper permissions (Linux/macOS)
sudo mkdir -p /etc/sysmanage-agent
sudo chown sysmanage-agent:sysmanage-agent /etc/sysmanage-agent
sudo chmod 0700 /etc/sysmanage-agent
```

```powershell
# Create certificate directory (Windows)
mkdir "C:\ProgramData\SysManage"
icacls "C:\ProgramData\SysManage" /grant "sysmanage-agent:(OI)(CI)F" /T
```

**Required permissions**:
- **Directory**: `0700` (Linux/macOS) or restricted access (Windows) - owner full control only
- **Private keys**: `0600` (owner read/write only) - highly restricted
- **Certificates**: `0600` (owner read/write only) - restricted for security
- **Configuration files**: `0600` (owner read/write only) - protect sensitive settings

#### Configuration File Locations

**Linux/macOS/BSD**: `/etc/sysmanage-agent.yaml`
```bash
# Create configuration file with proper permissions
sudo touch /etc/sysmanage-agent.yaml
sudo chown sysmanage-agent:sysmanage-agent /etc/sysmanage-agent.yaml
sudo chmod 0600 /etc/sysmanage-agent.yaml
```

**Windows**: `C:\ProgramData\SysManage\sysmanage-agent.yaml`
```powershell
# Create configuration file with restricted permissions
New-Item -Path "C:\ProgramData\SysManage\sysmanage-agent.yaml" -ItemType File -Force
icacls "C:\ProgramData\SysManage\sysmanage-agent.yaml" /grant "sysmanage-agent:F" /inheritance:r
```

#### Log Directory
If using file-based logging, ensure the log directory is writable:

**Linux/macOS**:
```bash
# Create log directory
sudo mkdir -p /var/log/sysmanage-agent
sudo chown sysmanage-agent:sysmanage-agent /var/log/sysmanage-agent
sudo chmod 0755 /var/log/sysmanage-agent
```

**Windows**:
```powershell
# Create log directory
mkdir C:\logs\sysmanage-agent
icacls "C:\logs\sysmanage-agent" /grant "sysmanage-agent:(OI)(CI)F" /T
```

#### Service User Account
For production deployments, create a dedicated service user:

**Linux**:
```bash
# Create sysmanage-agent user and group
sudo useradd -r -s /bin/false -d /opt/sysmanage-agent -c "SysManage Agent" sysmanage-agent
```

**macOS**:
```bash
# Create sysmanage-agent user
sudo dscl . -create /Users/sysmanage-agent
sudo dscl . -create /Users/sysmanage-agent UserShell /usr/bin/false
sudo dscl . -create /Users/sysmanage-agent RealName "SysManage Agent"
```

**Windows**:
```powershell
# Create sysmanage-agent service account
New-LocalUser -Name "sysmanage-agent" -Description "SysManage Agent Service" -NoPassword
```

**Note**: During development and testing, the application automatically detects test environments and uses temporary directories to avoid permission issues.

## Installation

### Method 1: From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/bceverly/sysmanage-agent.git
cd sysmanage-agent

# Create virtual environment
python3 -m venv .venv  # Linux/macOS
# python -m venv .venv   # Windows

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS (On OpenBSD: . .venv/bin/activate)
# OR
.venv\Scripts\activate     # Windows

# Upgrade pip to latest version
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

#### OpenBSD-Specific Installation Notes

OpenBSD users should follow the platform-specific instructions above, which include installing Rust. The key steps are:

```bash
# Install all required packages including Rust
doas pkg_add python-3.9 py3-pip rust gcc cmake gmake pkgconf

# Set up Rust environment
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
source ~/.profile

# Then install Python dependencies
pip install -r requirements.txt

# Or run the agent using the run script which automatically detects Rust availability
./run.sh
```

**Important Security Note**: The agent requires cryptography support for secure certificate-based authentication. Rust is mandatory for building these security packages. The run script will automatically detect if Rust is available and use appropriate installation methods.

### Method 2: Direct Installation

```bash
# Install directly from GitHub
pip install git+https://github.com/bceverly/sysmanage-agent.git
```

## Configuration

### Auto-Discovery (Recommended for New Deployments)

SysManage Agent includes automatic server discovery that eliminates the need for manual configuration in most scenarios:

#### How Auto-Discovery Works

1. **No Configuration Required**: If no configuration file exists, the agent automatically attempts to discover SysManage servers on the network
2. **Network Scanning**: The agent:
   - Sends UDP broadcast discovery requests to port 31337 on common network ranges
   - Listens for server announcement broadcasts on port 31338
   - Evaluates discovered servers using a scoring system (SSL preference, local network preference)
3. **Automatic Configuration**: Once a server is discovered, the agent:
   - Receives default configuration parameters from the server
   - Writes a complete configuration file automatically
   - Starts normal operation using the discovered settings
4. **Fallback**: If auto-discovery fails, manual configuration is still supported

#### Required Network Ports

For auto-discovery to work, ensure the following ports are available:

**Agent Ports (Outbound)**:
- **UDP 31337** - Send discovery requests to servers
- **UDP 31338** - Listen for server announcements  
- **TCP 6443** (or server port) - HTTPS connections to discovered server

**Server Ports (Inbound)**:
- **UDP 31337** - Server discovery beacon service
- **TCP 6443** (or configured port) - HTTPS API and WebSocket connections

#### Discovery Process Flow

```
Auto-Discovery Process:
1. Agent starts → No config file found
2. Agent broadcasts: "Looking for SysManage server" → Port 31337
3. Server responds: "SysManage server available + configuration" → Agent  
4. Agent evaluates servers and selects the best one
5. Agent writes configuration file with discovered settings
6. Agent connects via WebSocket using auto-generated configuration
```

### 1. Manual Server Configuration (Alternative)

Create `/etc/sysmanage-agent.yaml` (Linux/macOS/BSD) or `C:\ProgramData\SysManage\sysmanage-agent.yaml` (Windows):

```yaml
# SysManage Server connection details
server:
  hostname: "sysmanage.example.com"  # SysManage Server hostname
  port: 6443                         # Server WebSocket port
  protocol: "wss"                    # Use "ws" for non-SSL, "wss" for SSL

# Agent identification
agent:
  name: "my-server-01"               # Optional: Custom agent name
  tags:                              # Optional: Custom tags for grouping
    - "production"
    - "web-server"
    - "datacenter-1"

# Security settings
security:
  verify_ssl: true                   # Set to false for self-signed certificates
  api_key: "your-api-key-here"       # Optional: API key for authentication

# Monitoring settings
monitoring:
  heartbeat_interval: 30             # Seconds between heartbeat messages
  metrics_interval: 60               # Seconds between metric collection
  command_timeout: 300               # Maximum command execution time (seconds)

# Logging
logging:
  level: "INFO"                      # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "/var/log/sysmanage-agent.log"  # Linux/macOS/BSD
  # file: "C:\ProgramData\SysManage\logs\sysmanage-agent.log"  # Windows

# Internationalization
i18n:
  language: "en"                     # Agent language: en, es, fr, de, it, pt, nl, ja, zh_CN, zh_TW, ko, ru, ar, hi
```

### 2. Environment Variables (Alternative)

Instead of YAML configuration, you can use environment variables:

```bash
export SYSMANAGE_SERVER_HOST="sysmanage.example.com"
export SYSMANAGE_SERVER_PORT="6443"
export SYSMANAGE_PROTOCOL="wss"
export SYSMANAGE_VERIFY_SSL="true"
export SYSMANAGE_API_KEY="your-api-key"
export SYSMANAGE_HEARTBEAT_INTERVAL="30"
```

## Usage

### Running the Agent

#### Development Mode
```bash
# Run with debug output
python main.py --debug

# Run with custom config file
python main.py --config /path/to/config.yaml

# Run with specific server
python main.py --server sysmanage.example.com --port 6443
```

#### Production Mode (Service)

##### Linux (systemd)
Create `/etc/systemd/system/sysmanage-agent.service`:

```ini
[Unit]
Description=SysManage Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/opt/sysmanage-agent/.venv/bin/python /opt/sysmanage-agent/main.py
Restart=always
RestartSec=10
User=sysmanage
Group=sysmanage
WorkingDirectory=/opt/sysmanage-agent

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start the service
sudo systemctl enable sysmanage-agent
sudo systemctl start sysmanage-agent

# Check status
sudo systemctl status sysmanage-agent

# View logs
sudo journalctl -u sysmanage-agent -f
```

##### Windows (Service)
```powershell
# Install as Windows service using NSSM or similar
# Or run as scheduled task at startup
```

##### macOS (launchd)
Create `/Library/LaunchDaemons/com.sysmanage.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sysmanage.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/sysmanage-agent/.venv/bin/python</string>
        <string>/opt/sysmanage-agent/main.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

### Command Line Options

```bash
python main.py [OPTIONS]

Options:
  --config PATH              Configuration file path
  --server TEXT              SysManage server hostname
  --port INTEGER             Server WebSocket port (default: 6443)
  --protocol [ws|wss]        Connection protocol (default: wss)
  --debug                    Enable debug logging
  --no-verify-ssl           Disable SSL certificate verification
  --daemon                   Run as daemon (Unix only)
  --help                     Show help message
```

## Privileged Execution

### Overview

The SysManage Agent requires elevated privileges for certain system management operations, particularly **package management** (installing, updating, and removing software packages). This section provides cross-platform solutions for running the agent with appropriate permissions.

### Why Privileged Access is Required

Package management operations require administrative privileges:
- **Linux**: `apt`, `yum`, `dnf`, `zypper`, `pacman` require `sudo`
- **macOS**: `brew` operations may require administrator access
- **OpenBSD**: `pkg_add`, `pkg_delete` require `doas` or `root`
- **Windows**: Package installers require administrator privileges

### Cross-Platform Privileged Runner

The included `run-privileged.sh` script provides a secure, cross-platform solution for running the agent with elevated privileges.

#### Features
- ✅ **Cross-platform**: Works on macOS (zsh), Linux (bash), and OpenBSD (ksh)
- 🔐 **Security-focused**: Uses appropriate privilege escalation for each platform
- 🛡️ **Environment preservation**: Maintains Python virtual environment paths
- 🔍 **Auto-detection**: Automatically detects platform and available tools
- ⚡ **Developer-friendly**: Easy to use during development and testing

#### Usage

```bash
# Basic usage - start agent with privileges
./run-privileged.sh

# Pass arguments to the agent
./run-privileged.sh --config custom.yaml
./run-privileged.sh --debug

# Show help for the runner script
./run-privileged.sh --help runner
```

#### Platform-Specific Behavior

| Platform | Privilege Tool | Command Used |
|----------|---------------|--------------|
| **macOS** | `sudo` | `sudo -E PATH="..." python main.py` |
| **Linux** | `sudo` | `sudo -E PATH="..." python main.py` |  
| **OpenBSD** | `doas` (preferred) | `doas env PATH="..." python main.py` |
| **OpenBSD** | `sudo` (fallback) | `sudo -E PATH="..." python main.py` |

#### Installation

The script is included in the repository. Simply make it executable:

```bash
chmod +x run-privileged.sh
```

### Alternative Approaches

#### Option 1: Manual sudo execution (Development)

```bash
# Linux/macOS - Run with preserved environment and PATH
sudo -E PATH=".venv/bin:$PATH" .venv/bin/python main.py

# Alternative approach
sudo -E .venv/bin/python main.py --disable-migrations  # If database migrations cause issues
```

#### Option 2: Passwordless sudo configuration (Advanced)

For development environments, configure passwordless sudo for package management:

**Create `/etc/sudoers.d/sysmanage-agent`:**
```bash
# Allow user to run package management without password
%sysmanage ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dnf, /usr/bin/yum, /usr/bin/zypper, /usr/bin/pacman
%sysmanage ALL=(ALL) NOPASSWD: /usr/local/bin/brew  # macOS
%sysmanage ALL=(ALL) NOPASSWD: /usr/sbin/pkg_add, /usr/sbin/pkg_delete  # OpenBSD
```

**Then run normally:**
```bash
python main.py
```

#### Option 3: Production systemd service (Linux)

For production deployments, run as a systemd service with root privileges:

**Create `/etc/systemd/system/sysmanage-agent.service`:**
```ini
[Unit]
Description=SysManage Agent - System Management and Monitoring
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/sysmanage-agent
ExecStart=/opt/sysmanage-agent/.venv/bin/python main.py
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/sysmanage-agent
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Security Considerations

#### Development vs Production

| Environment | Recommended Approach | Security Level |
|-------------|---------------------|----------------|
| **Development** | `run-privileged.sh` script | Medium - Temporary elevation |
| **Testing** | Manual sudo execution | Medium - Session-based |
| **Production** | SystemD service as root | High - Isolated service |

#### Best Practices

1. **Minimal Privileges**: Only run with elevated privileges when necessary
2. **Audit Logging**: Monitor all privileged operations through system logs
3. **Environment Isolation**: Use virtual environments to isolate dependencies
4. **Regular Updates**: Keep the agent updated for security patches
5. **Access Control**: Restrict who can execute privileged operations

#### Privilege Escalation Tools

- **Linux/macOS**: Uses `sudo` with environment preservation (`-E` flag)
- **OpenBSD**: Prefers `doas` (OpenBSD's recommended tool) with fallback to `sudo`
- **Windows**: Requires "Run as Administrator" (future implementation)

### Troubleshooting Privileged Execution

#### Common Issues

**1. "alembic not found" error:**
```bash
# The script preserves PATH to include virtual environment
# If this still occurs, check that .venv/bin exists:
ls -la .venv/bin/alembic
```

**2. Password prompts:**
```bash
# Check if passwordless sudo is configured:
sudo -n true && echo "Passwordless sudo works" || echo "Password required"
```

**3. Permission denied:**
```bash
# Ensure script is executable:
chmod +x run-privileged.sh

# Check sudo access:
sudo -l
```

**4. Platform detection issues:**
```bash
# Manually check platform detection:
uname  # Should show: Linux, Darwin, or OpenBSD
```

#### Debugging

Enable verbose output by adding debug flags:

```bash
# Run with debug output
./run-privileged.sh --debug

# Check script execution with shell tracing
sh -x ./run-privileged.sh
```

### Examples

#### Package Update Scenario

When the SysManage Server sends a package update command:

1. **Without privileges** (fails):
   ```bash
   python main.py
   # Package update fails: "apt requires sudo"
   ```

2. **With privileges** (succeeds):
   ```bash
   ./run-privileged.sh
   # Package update succeeds: "alsa-ucm-conf updated successfully"
   ```

#### Cross-Platform Testing

```bash
# macOS with Homebrew
./run-privileged.sh  # Uses: sudo -E ...

# Ubuntu with APT  
./run-privileged.sh  # Uses: sudo -E ...

# OpenBSD with pkg_add
./run-privileged.sh  # Uses: doas env ... (or sudo -E ...)
```

## Monitoring and Troubleshooting

### Health Checks

The agent provides several ways to monitor its health:

1. **Process Status**: Check if the agent process is running
2. **Log Files**: Monitor log files for errors and warnings
3. **Server Dashboard**: View agent status in SysManage web interface
4. **Local Status**: HTTP status endpoint (if enabled)

### Log Analysis

```bash
# View live logs
tail -f /var/log/sysmanage-agent.log

# Search for errors
grep ERROR /var/log/sysmanage-agent.log

# Check connection status
grep "Connected\|Disconnected" /var/log/sysmanage-agent.log
```

### Common Issues

#### Connection Problems
```bash
# Test server connectivity
telnet sysmanage.example.com 6443

# Check DNS resolution
nslookup sysmanage.example.com

# Verify SSL certificate
openssl s_client -connect sysmanage.example.com:6443
```

#### Permission Issues
```bash
# Check agent user permissions
sudo -u sysmanage python main.py --debug

# Verify file permissions
ls -la /etc/sysmanage-agent.yaml
ls -la /var/log/sysmanage-agent.log
```

#### Resource Usage
```bash
# Monitor CPU and memory usage
top -p $(pgrep -f "python.*main.py")

# Check disk space
df -h /var/log
```

## Security Considerations

### Network Security
- **Outbound Only**: Agent initiates all connections, no inbound ports required
- **TLS Encryption**: All communication encrypted via WSS (WebSocket Secure)
- **Certificate Validation**: Server SSL certificates validated by default
- **Firewall Friendly**: Only requires HTTPS outbound access

### System Security
- **Privilege Separation**: Run with minimal required privileges
- **Command Validation**: All incoming commands validated before execution
- **Resource Limits**: Built-in timeouts and resource constraints
- **Audit Logging**: All actions logged for security auditing

### Agent Approval Process

SysManage implements a manual approval system to ensure only authorized agents can connect:

- **Initial Registration**: When the agent first connects, it registers with the server but is placed in "pending" status
- **Connection Blocked**: Agents with "pending" or "rejected" status cannot establish WebSocket connections for monitoring
- **Administrator Approval Required**: A system administrator must manually approve each new agent through the SysManage web interface
- **Approval Workflow**: 
  1. Agent registers and shows up as "pending" in the server's Hosts page
  2. Administrator reviews and approves or rejects the agent
  3. Once approved, the agent can establish full WebSocket connectivity
- **Re-approval**: If an approved agent is deleted from the server and reconnects, it will require re-approval

**Important**: The agent will continue attempting to connect even while in pending status, but will only be able to complete the full connection process once approved by an administrator.

### Mutual TLS (mTLS) Security

SysManage Agent implements mutual TLS authentication to protect against DNS poisoning attacks and ensure secure server verification:

#### Security Features

1. **Server Certificate Validation**: Agents validate server certificates against stored fingerprints to prevent DNS poisoning and man-in-the-middle attacks
2. **Certificate Pinning**: During first connection, agents store server certificate fingerprints for future validation
3. **Client Certificate Authentication**: After approval, agents use unique client certificates to authenticate with the server
4. **Automatic Certificate Management**: Agents retrieve certificates from the server after host approval

#### How mTLS Works

1. **Initial Connection**: Agent connects using token-based authentication during registration
2. **Host Approval**: Administrator approves the host through SysManage web interface  
3. **Certificate Retrieval**: Agent automatically fetches client certificates after approval
4. **Secure Authentication**: All subsequent connections use mutual TLS with certificate validation

#### Certificate Storage

Client certificates are stored securely with restricted permissions:

**Linux/macOS/BSD**: `/etc/sysmanage-agent/`
```
/etc/sysmanage-agent/
├── client.crt          # Agent client certificate
├── client.key          # Agent private key (0600 permissions)
├── ca.crt              # CA certificate for server validation
└── server.fingerprint  # Server certificate fingerprint for pinning
```

**Windows**: `C:\ProgramData\SysManage\`
```
C:\ProgramData\SysManage\
├── client.crt          # Agent client certificate
├── client.key          # Agent private key (restricted permissions)
├── ca.crt              # CA certificate for server validation
└── server.fingerprint  # Server certificate fingerprint for pinning
```

#### Security Benefits

- **DNS Poisoning Protection**: Agents verify they're connecting to the legitimate server using certificate fingerprints
- **Identity Verification**: Server can cryptographically verify agent identity using client certificates
- **Man-in-the-Middle Protection**: Full TLS encryption with mutual certificate validation ensures secure communication
- **Replay Attack Prevention**: Each connection uses fresh TLS sessions with proper key exchange

#### Certificate Management

- **Automatic Retrieval**: Certificates are automatically retrieved after host approval
- **Validation**: Certificates are validated on each connection attempt
- **Renewal**: Certificates can be refreshed by re-fetching from the server
- **Revocation**: Certificates become invalid if host approval is revoked

#### Migration from Token-based Authentication

The agent supports both authentication methods:
- **Legacy Mode**: Uses token-based authentication when certificates are not available
- **Enhanced Security Mode**: Uses mutual TLS when certificates are present
- **Automatic Upgrade**: Seamlessly transitions to certificate-based authentication after host approval

### Best Practices
1. **Dedicated User**: Run agent as dedicated system user, not root
2. **File Permissions**: Protect configuration files (600 permissions)
3. **Log Rotation**: Configure log rotation to prevent disk filling
4. **Updates**: Keep agent updated with latest security patches
5. **Monitoring**: Monitor agent logs for suspicious activity

## Development

### Project Structure
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
└── README.md              # This file
```

### Running Tests

The project includes a Makefile that works on all platforms including Windows:

```bash
# Run all tests with coverage (cross-platform)
make test

# Clean test artifacts
make clean

# Setup development environment
make setup

# Run linting
make lint
```

#### Platform-Specific Test Commands

**Linux/macOS/BSD:**
```bash
# Using make (recommended)
make test

# Direct pytest execution
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Run specific test
python -m pytest tests/test_basic.py -v
```

**Windows:**
```powershell
# Using make (requires Make for Windows or use from Git Bash)
make test

# Direct pytest execution
python -m pytest tests\ -v

# Run with coverage
python -m pytest tests\ --cov=. --cov-report=html

# Run specific test
python -m pytest tests\test_basic.py -v
```

**Note for Windows Users:** 
- The Makefile automatically detects Windows and adjusts paths accordingly
- Some tests related to Unix file permissions are automatically skipped on Windows
- All core functionality tests run successfully on Windows

### Code Quality

```bash
# Run linting
python -m pylint *.py

# Security scan
python -m bandit -r .

# Format code
python -m black .
```

## Protocol Documentation

### WebSocket Message Format

All messages use JSON format with the following structure:

```json
{
  "message_id": "unique-identifier",
  "message_type": "system_info|command|heartbeat|error",
  "timestamp": "2024-01-01T00:00:00.000000Z",
  "data": {
    // Message-specific payload
  }
}
```

### Message Types

#### System Info
```json
{
  "message_type": "system_info",
  "data": {
    "hostname": "server01",
    "platform": "Linux",
    "architecture": "x86_64",
    "cpu_count": 4,
    "memory_total": 8589934592,
    "ipv4": "192.168.1.100",
    "ipv6": "2001:db8::1"
  }
}
```

#### Heartbeat
```json
{
  "message_type": "heartbeat",
  "data": {
    "agent_status": "healthy",
    "system_load": 0.25,
    "memory_usage": 45.2,
    "disk_usage": 78.9,
    "network_rx_bytes": 1024000,
    "network_tx_bytes": 2048000
  }
}
```

#### Command Execution
```json
{
  "message_type": "command",
  "data": {
    "command_id": "cmd-12345",
    "command_type": "execute_shell",
    "parameters": {
      "command": "df -h",
      "timeout": 30
    }
  }
}
```

## Changelog

### Version 1.0.0
- Initial release with WebSocket communication
- Cross-platform system information collection
- Basic command execution capabilities
- Configuration management
- Service integration

## Internationalization (i18n)

The SysManage Agent supports multiple languages for user-facing messages and logs:

### Supported Languages
- **English** (en) - Default
- **Spanish** (es) - Español
- **French** (fr) - Français
- **German** (de) - Deutsch
- **Italian** (it) - Italiano
- **Portuguese** (pt) - Português
- **Dutch** (nl) - Nederlands
- **Japanese** (ja) - 日本語
- **Simplified Chinese** (zh_CN) - 简体中文
- **Traditional Chinese** (zh_TW) - 繁體中文
- **Korean** (ko) - 한국어
- **Russian** (ru) - Русский
- **Arabic** (ar) - العربية
- **Hindi** (hi) - हिन्दी

### Translation Files Location

```
i18n/locales/
├── en/LC_MESSAGES/messages.po
├── es/LC_MESSAGES/messages.po
├── fr/LC_MESSAGES/messages.po
├── de/LC_MESSAGES/messages.po
├── it/LC_MESSAGES/messages.po
├── pt/LC_MESSAGES/messages.po
├── nl/LC_MESSAGES/messages.po
├── ja/LC_MESSAGES/messages.po
├── zh_CN/LC_MESSAGES/messages.po
├── zh_TW/LC_MESSAGES/messages.po
├── ko/LC_MESSAGES/messages.po
├── ru/LC_MESSAGES/messages.po
├── ar/LC_MESSAGES/messages.po
└── hi/LC_MESSAGES/messages.po
```

### Adding New Languages

1. **Create translation file**: Add new `.po` file in `i18n/locales/{language}/LC_MESSAGES/messages.po`
2. **Translate messages**: Update all `msgstr` entries with appropriate translations
3. **Compile translation**: Run `msgfmt messages.po -o messages.mo` in the LC_MESSAGES directory
4. **Set language**: Use `set_language('{language}')` in your agent configuration

### Using Translations in Code

```python
from i18n import _

# Simple message translation
logger.info(_("Starting SysManage Agent"))

# Message with parameters (handled by logging framework)
logger.info(_("Connected to server successfully"))
```

### Language Detection
The agent uses the system default language (English) but can be configured to use specific languages through the configuration system.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Ensure code quality (`make lint test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Create a Pull Request

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: https://github.com/bceverly/sysmanage-agent/wiki
- **Issues**: https://github.com/bceverly/sysmanage-agent/issues
- **Server Project**: https://github.com/bceverly/sysmanage
