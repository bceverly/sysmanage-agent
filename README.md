<div align="center">
  <img src="sysmanage-logo.svg" alt="SysManage" width="330"/>
</div>

# SysManage Agent

[![CI/CD Pipeline](https://github.com/bceverly/sysmanage-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/bceverly/sysmanage-agent/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-BSD%202--Clause-green.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Linting](https://img.shields.io/badge/linting-pylint-blue.svg)](https://github.com/PyCQA/pylint)

A lightweight, secure, cross-platform system monitoring agent that connects to SysManage Server via WebSocket for real-time remote management.

## Overview

SysManage Agent is a headless Python application designed to be installed on remote systems for centralized monitoring and management. It establishes a secure WebSocket connection to the SysManage Server and provides real-time system information, command execution capabilities, and health monitoring.

### Key Features

- 🔄 **Real-time Communication**: WebSocket-based connection for instant responsiveness
- 🖥️ **Cross-platform Support**: Linux, Windows, macOS, FreeBSD, OpenBSD
- 🔐 **Secure by Design**: Encrypted communication, no inbound ports required
- 📊 **System Monitoring**: CPU, memory, disk, network metrics collection
- ⚡ **Command Execution**: Remote command execution with security controls
- 🔧 **Package Management**: Remote software installation and updates
- 💓 **Health Monitoring**: Automatic heartbeat and status reporting
- 🌍 **Multi-language Support**: Native support for 11 languages
- 🏃‍♂️ **Lightweight**: Minimal resource footprint and dependencies

## Architecture

The agent operates as a persistent service that:
1. Connects to SysManage Server via secure WebSocket
2. Registers itself with system information (hostname, IP, platform)
3. Sends periodic heartbeat messages
4. Listens for commands and executes them securely
5. Reports command results and system status back to server

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
| Korean | `ko` | ✅ Complete |
| Russian | `ru` | ✅ Complete |

The agent uses the language specified in the configuration file for log messages and system output. If no language is specified, it defaults to English.

## Prerequisites

### System Requirements
- **Python**: 3.9 or higher
- **OS**: Linux, Windows, macOS, FreeBSD, or OpenBSD
- **Network**: Outbound HTTPS access to SysManage Server
- **Privileges**: Administrative rights for system management tasks

### Dependencies
All dependencies are automatically installed via `requirements.txt`:
- `websockets` - WebSocket client communication
- `requests` - HTTP client for registration
- `psutil` - System information gathering
- `pydantic` - Data validation and configuration
- `asyncio` - Asynchronous I/O operations

## Installation

### Method 1: From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/bceverly/sysmanage-agent.git
cd sysmanage-agent

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# OR
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Direct Installation

```bash
# Install directly from GitHub
pip install git+https://github.com/bceverly/sysmanage-agent.git
```

## Configuration

### 1. Server Configuration

Create `/etc/sysmanage-agent.yaml` (Linux/macOS) or `C:\sysmanage-agent.yaml` (Windows):

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
  file: "/var/log/sysmanage-agent.log"  # Linux/macOS
  # file: "C:\logs\sysmanage-agent.log"  # Windows

# Internationalization
i18n:
  language: "en"                     # Agent language: en, es, fr, de, it, pt, nl, ja, zh_CN, ko, ru
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

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Run specific test
python -m pytest tests/test_basic.py -v
```

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
- **French** (fr) - Français  
- **Japanese** (ja) - 日本語

### Translation Files Location

```
i18n/locales/
├── en/LC_MESSAGES/messages.po
├── fr/LC_MESSAGES/messages.po
└── ja/LC_MESSAGES/messages.po
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

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: https://github.com/bceverly/sysmanage-agent/wiki
- **Issues**: https://github.com/bceverly/sysmanage-agent/issues
- **Server Project**: https://github.com/bceverly/sysmanage
