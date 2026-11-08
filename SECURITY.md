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
- Mutual TLS: once approved, the host presents its own client certificate on
  every TLS connection to the server (see below)
- Server pinning: once the host has a certificate, the server's TLS
  certificate must be one the agent has pinned (see below)
- Message integrity verification

### Mutual TLS and Server Pinning

Everything in this section applies only when the agent talks to the server
over HTTPS/WSS. Over plain HTTP (development) the agent requests no
certificate and pins nothing.

**The host certificate.** Once the host has a host id and host token and is
approved, the agent generates an EC P-256 private key on the host and sends
only a certificate signing request to `POST /api/agent/certificate`,
authenticated with its connection token and host token. The key never leaves
the host. The files live in the agent's certificate directory
(`/etc/sysmanage-agent`, `C:\ProgramData\SysManage` on Windows, or
`SYSMANAGE_CONFIG_DIR` when set):

| File | Contents | Mode |
|------|----------|------|
| `client.key` | the host's private key | 0600, set when the file is created |
| `client.crt` | the certificate the server issued (365 days) | 0644 |
| `ca.crt` | the SysManage CA that issued it | 0644 |
| `server_pins.json` | the pinned server identity | 0644 |

Every file is written to a temporary file and moved into place, so a crash
never leaves half a file, and the previous key and certificate stay in use
until the new pair is on disk. (On Windows the modes are not applied; the
directory's ACLs govern access.)

**When a certificate is requested.** At start-up and every 24 hours, and when
a connection is confirmed or the host is approved, the agent requests one if
it has none, if it has expired, or if it expires within 30 days. It also
requests one right after the server refuses the host with
`host_certificate_required` or `host_certificate_expired` (on the WebSocket or
in a REST 403), at most once every 5 minutes; after such a request succeeds on
a WebSocket connection, the agent reconnects so the new certificate is
presented. A refusal with `host_certificate_invalid` is logged as an error and
triggers no request.

**Presenting it.** Every TLS connection to the server, REST and WebSocket alike,
is built by one function and presents the certificate when an unexpired one
and its matching key are stored. An expired certificate is never presented;
the agent logs that once and requests a new one. The SysManage CA is *added*
to the trust used for the server; the system trust store is never replaced,
because the server's own TLS certificate is usually a public one.

**What is pinned.** `server_pins.json` holds the SHA-256 of the SysManage CA
(DER) and the SHA-256 of the SubjectPublicKeyInfo of the server's TLS
certificate, keeping the newest three. The first pin is made right after the
first certificate is issued (or, whenever a certificate exists but no pins
file does, on the next confirmed connection or 24-hour check): the agent
fetches `GET /api/agent/server-identity` and pins the CA it was just issued
plus the TLS certificate it observed on that connection, provided the signed
statement verifies (as below). From then on every TLS connection to the server
checks, immediately after the handshake and before any request is sent, that
the server's leaf certificate has a pinned SPKI. A mismatch refuses the
connection with an error naming the SPKI it saw.

**How a re-pin works.** The server's TLS certificate (often Let's Encrypt)
changes every few months with a new key, so a mismatch starts one background
re-pin attempt, at most once a minute. The agent fetches
`/api/agent/server-identity` over a normally verified connection without the
pin check, and accepts the new certificate only if all of these hold:

1. the response's CA is the pinned CA (same SHA-256);
2. the identity certificate was issued directly by that CA and is within its
   validity period;
3. the statement is signed by the identity certificate's key (RSA PKCS#1 v1.5
   or ECDSA, SHA-256);
4. the statement has not expired;
5. the statement lists the SPKI of the certificate observed on that same
   connection.

On success the new SPKI is added to the pins and the agent logs that the
changed certificate is now trusted. On failure the pins are unchanged and the
agent logs an error naming the likely cause: a proxy, or another server,
presenting a different certificate. A different CA is never accepted by a
re-pin.

**TLS-inspecting proxies.** Set `server.tls_inspection: true` in the agent
config only when a proxy that re-signs TLS sits between the host and the
server. Pinning is then turned off (logged once as a warning). The client
certificate is still offered, but such a proxy removes it, so the server must
accept that host without one: its tenant can run mutual TLS in `optional`
mode, not `enforced`. Point `server.ca_bundle` at the proxy's root
certificate as before; never use `verify_ssl: false` for this.

**Resetting deliberately.** When the server really was replaced, or its CA
really changed, remove the pins and restart the agent. Run the reset command
from the agent's install directory, as the user the agent runs as, with the
agent's own Python (for the Linux packages that is `.venv/bin/python` in
`/opt/sysmanage-agent`). It uses the same certificate directory as the agent,
including `SYSMANAGE_CONFIG_DIR` when that is set:

```bash
cd /opt/sysmanage-agent
sudo .venv/bin/python -m src.security.pin_reset                # remove server_pins.json
sudo .venv/bin/python -m src.security.pin_reset --certificate  # also remove client.crt, client.key and ca.crt
```

Deleting `server_pins.json` by hand does the same as the first form. The agent
pins again, as above, on its next confirmed connection; with `--certificate` it
first requests a new certificate once the host is approved.

### Agent Security
- Minimal privilege execution (no root required)
- Input validation for all server commands
- Safe command execution with timeout limits
- Secure configuration file handling
- Credentials on disk are limited to the host token (agent database) and the
  host's private key (`client.key`, 0600 on POSIX systems)

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
semgrep scan --config="p/security-audit" --config="p/python" --config="p/owasp-top-ten"  # Multi-language static analysis
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
- **Server Trust**: Agent verifies the server's TLS certificate against the
  system trust store (plus `ca_bundle` and the SysManage CA), and, once it
  holds a host certificate and `tls_inspection` is not set, also requires the
  certificate to be pinned or signed by the pinned server identity
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