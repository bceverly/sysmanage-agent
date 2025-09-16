# Security Policy

## Supported Versions

We provide security updates for the following versions of SysManage Agent:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### 🔒 For Security Issues (DO NOT create public issues)

1. **Email**: Send details to security@sysmanage.org
2. **Include**: 
   - Description of the vulnerability
   - Steps to reproduce  
   - Potential impact assessment
   - Agent version and operating system
   - Configuration details (sanitized)

3. **Response Time**: We will acknowledge receipt within 48 hours
4. **Updates**: You'll receive updates every 7 days until resolution

### 📋 For Non-Security Issues

For general bugs and feature requests, please use [GitHub Issues](https://github.com/YOUR_USERNAME/sysmanage-agent/issues).

## Security Measures

### Communication Security
- TLS 1.2+ encryption for all server communication
- WebSocket Secure (WSS) for real-time communication
- Certificate validation (configurable for development)
- Message integrity verification

### Agent Security
- Minimal privilege execution (no root required)
- Input validation for all server commands
- Safe command execution with timeout limits
- Secure configuration file handling
- No credential storage on disk

### System Integration
- Platform-appropriate security measures
- Safe subprocess execution
- Resource usage limits
- Process isolation where possible

## Security Scanning Infrastructure

SysManage Agent implements automated security scanning through CI/CD pipeline integration to proactively identify and prevent security vulnerabilities in the agent codebase:

### Continuous Security Monitoring

All security scans run automatically on:
- **Every push** to main and develop branches
- **Every pull request**
- **Weekly scheduled scans** (Sundays at 2 AM UTC)

### Python Security Tools

#### Static Code Analysis
- **[Bandit](https://bandit.readthedocs.io/)** - Detects common security issues in Python code
  - Scans for SQL injection, hardcoded passwords, insecure random generators
  - Identifies unsafe use of eval(), exec(), and shell commands
  - Checks for insecure network communication patterns
  - Validates subprocess and command execution security

- **[Semgrep](https://semgrep.dev/)** - Multi-language static analysis with OWASP Top 10 rules
  - Checks for security anti-patterns and vulnerabilities
  - Uses community rules + OWASP Top 10 rule sets
  - Generates SARIF reports for GitHub Security tab
  - Analyzes configuration handling and input validation

#### Dependency Vulnerability Scanning
- **[Safety](https://pypi.org/project/safety/)** - Scans Python dependencies for known vulnerabilities
  - Checks against Python security advisories database
  - Identifies vulnerable package versions in requirements.txt
  - Generates detailed vulnerability reports
  - Provides upgrade recommendations for secure versions

#### Secrets Detection
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** - Comprehensive secrets scanning
  - Scans entire git history for leaked credentials
  - Detects API keys, passwords, tokens, certificates
  - Verifies secrets against live services
  - Prevents accidental credential commits

### Agent-Specific Security Scanning

The agent's security scanning focuses on Python-specific vulnerabilities and agent-related security concerns:

#### Network Communication Security
- SSL/TLS configuration validation
- WebSocket connection security analysis
- Certificate handling verification
- Protocol downgrade attack prevention

#### Command Execution Security
- Input sanitization verification
- Command injection prevention
- Subprocess security validation
- Privilege escalation detection

#### Configuration Security
- Configuration file permission checks
- Sensitive data exposure detection
- Default credential identification
- Insecure configuration pattern detection

### Local Security Testing

Developers can run security scans locally before committing:

```bash
# Individual security tools
python -m bandit -r src/ -f screen                    # Python static analysis
pip freeze | safety check --stdin                     # Python dependency check
trufflehog git file://. --only-verified               # Secrets detection

# If using requirements files
safety check -r requirements.txt                      # Dependency vulnerability scan
bandit -r src/ -f json -o bandit-report.json         # Generate JSON report
```

### Security Workflow Integration

Security scanning is integrated with the agent's CI/CD pipeline:

- **GitHub Security Tab**: Centralized vulnerability management dashboard
- **SARIF Reports**: Standardized security report format for tool interoperability
- **Security Artifacts**: Downloadable detailed reports for each scan
- **Pull Request Integration**: Security checks block merging if critical issues found
- **Weekly Monitoring**: Scheduled scans catch newly disclosed vulnerabilities

### Security Badge Status

Our README displays real-time security status badges:

- ![Security: bandit](https://img.shields.io/badge/bandit-passing-brightgreen.svg) **Bandit**: Python static analysis status
- ![Security: semgrep](https://img.shields.io/badge/semgrep-scan-brightgreen.svg) **Semgrep**: Multi-language security analysis
- ![Security: safety](https://img.shields.io/badge/safety-passing-brightgreen.svg) **Safety**: Python dependency vulnerability status
- ![Security: snyk](https://img.shields.io/badge/snyk-monitored-brightgreen.svg) **Snyk**: Dependency monitoring status
- ![Security: trufflehog](https://img.shields.io/badge/trufflehog-clean-brightgreen.svg) **TruffleHog**: Repository secrets scan status

## Security Best Practices

### Installation
- Run agent with minimal required privileges
- Use dedicated service account where possible
- Enable firewall rules for outbound connections only
- Verify agent binary integrity before installation

### Configuration
- Use HTTPS/WSS in production environments
- Enable certificate validation
- Use strong server authentication
- Configure appropriate retry limits
- Set reasonable timeout values

### Monitoring
- Monitor agent logs for suspicious activity
- Set up log rotation and retention policies
- Monitor network connections
- Track resource usage patterns

### Maintenance
- Apply security updates promptly
- Monitor Dependabot security alerts
- Regular security configuration reviews
- Keep Python runtime updated

## Agent Security Model

### Threat Model
The SysManage Agent is designed to be secure against:
- Network-based attacks (encrypted communication)
- Command injection (input validation)
- Privilege escalation (minimal privileges)
- Configuration tampering (secure file handling)

### Trust Boundaries
- **Server Trust**: Agent trusts configured server certificate
- **Command Trust**: Commands from authenticated server are trusted
- **System Trust**: Agent operates within user privilege boundaries
- **Network Trust**: All communication encrypted and authenticated

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Initial Report**: Security researcher reports issue privately
2. **Acknowledgment**: We confirm receipt and begin investigation  
3. **Investigation**: We assess impact and develop fixes
4. **Fix Development**: Patches are developed and tested
5. **Coordinated Release**: Fix is released with security advisory
6. **Public Disclosure**: Details shared after fix is available

## Security Configuration

### Production Deployment
```yaml
server:
  hostname: "your-server.com"
  port: 6443
  use_https: true  # Always use HTTPS in production
  api_path: ""

client:
  # Reasonable retry limits
  registration_retry_interval: 30
  max_registration_retries: 10

logging:
  level: "INFO"  # Avoid DEBUG in production
  file: "/var/log/sysmanage-agent.log"

websocket:
  auto_reconnect: true
  reconnect_interval: 5
  ping_interval: 30
```

### Development Configuration
- Use localhost/development certificates
- Enable debug logging if needed
- Use shorter retry intervals for testing
- Disable certificate validation only for development

## Contact

- **Security Team**: security@sysmanage.org
- **General Contact**: contact@sysmanage.org
- **GitHub Issues**: https://github.com/YOUR_USERNAME/sysmanage-agent/issues