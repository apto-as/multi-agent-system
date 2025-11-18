# Security Deployment Guide
## Trinitas Decision System - Production Security Configuration

**Version**: 2.3.0
**Date**: 2025-11-03
**Target Audience**: DevOps Engineers, System Administrators, Security Engineers
**Status**: Production-Ready

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Security Configuration](#security-configuration)
4. [Best Practices](#best-practices)
5. [Monitoring and Logging](#monitoring-and-logging)
6. [Troubleshooting](#troubleshooting)
7. [Incident Response](#incident-response)
8. [Compliance Checklist](#compliance-checklist)

---

## Prerequisites

### System Requirements

**Minimum Requirements**:
- Python 3.11+
- Claude Code CLI installed
- 2GB RAM
- 1GB disk space

**Recommended Requirements**:
- Python 3.11+ with latest security patches
- Claude Code CLI v1.5+
- 4GB RAM
- 5GB disk space (for logs and decision storage)

### Dependencies

**Core Dependencies**:
```bash
# Required packages (already in pyproject.toml)
httpx>=0.24.0      # Async HTTP client
pydantic>=2.0      # Data validation
```

**Security-Related Packages**:
```bash
# Automatically installed
unicodedata  # Unicode normalization (built-in)
ipaddress    # IP validation (built-in)
pathlib      # Path operations (built-in)
collections  # deque for rate limiting (built-in)
threading    # Thread-safe locks (built-in)
```

### Pre-Installation Security Checklist

- [ ] Operating system is fully patched
- [ ] Python is latest stable version (3.11+)
- [ ] File system supports POSIX permissions (chmod)
- [ ] User account has appropriate permissions (not root)
- [ ] Firewall is configured (if using TMWS)
- [ ] SELinux/AppArmor policies reviewed (if applicable)

---

## Installation

### Step 1: Clone Repository

```bash
# Clone Trinitas Agents
git clone https://github.com/apto-as/trinitas-agents.git
cd trinitas-agents

# Verify integrity (optional but recommended)
git verify-commit HEAD
```

### Step 2: Install Dependencies

```bash
# Install with all security features
pip install -e ".[all]"

# Or use uv (recommended for faster installation)
uv sync --all-extras
```

### Step 3: Deploy Security Hooks

```bash
# Run installer (deploys to ~/.claude/)
./install_trinitas_config.sh

# Verify installation
ls -la ~/.claude/hooks/core/
# Should show:
# - decision_check.py
# - decision_memory.py
# - rate_limiter.py
# - security_utils.py
```

### Step 4: Set Secure Permissions

```bash
# Restrict access to hooks directory
chmod 700 ~/.claude/hooks/core/

# Restrict individual files
chmod 600 ~/.claude/hooks/core/*.py

# Restrict decisions directory (if using fallback storage)
mkdir -p ~/.claude/decisions
chmod 700 ~/.claude/decisions
```

### Step 5: Configure Environment

```bash
# Create secure configuration file
touch ~/.claude/security.env
chmod 600 ~/.claude/security.env

# Add configuration (edit with your values)
cat > ~/.claude/security.env << 'EOF'
# TMWS Configuration (optional)
TMWS_URL=https://tmws.your-domain.com
TMWS_API_KEY=your-secure-api-key-here

# Rate Limiting
RATE_LIMIT_MAX_CALLS=100
RATE_LIMIT_WINDOW_SECONDS=60

# Fallback Directory
FALLBACK_DIR=~/.claude/decisions

# Logging Level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO
EOF
```

---

## Security Configuration

### Rate Limiter Configuration

**Default Settings** (recommended for production):

```python
# In decision_check.py
rate_limiter = ThreadSafeRateLimiter(
    max_calls=100,         # Maximum calls per window
    window_seconds=60,     # Time window in seconds
    burst_size=10         # Allow short bursts (future feature)
)
```

**Adjustment Guidelines**:

| Environment | max_calls | window_seconds | Rationale |
|-------------|-----------|----------------|-----------|
| Development | 200 | 60 | More lenient for testing |
| Staging | 100 | 60 | Match production |
| Production | 100 | 60 | DoS protection |
| High-Load Production | 200 | 120 | More capacity, longer window |

**To Customize**:

Edit `~/.claude/hooks/core/decision_check.py`:

```python
# Line ~30
self.rate_limiter = ThreadSafeRateLimiter(
    max_calls=int(os.getenv("RATE_LIMIT_MAX_CALLS", "100")),
    window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
)
```

### TMWS URL Configuration

**Production Deployment**:

```python
# In decision_memory.py
def __init__(self):
    # Load from environment (secure)
    tmws_url = os.getenv("TMWS_URL", "https://tmws.example.com")

    # Validate URL (SSRF protection)
    self.tmws_url = validate_tmws_url(tmws_url, allow_localhost=False)  # ← False in production
```

**Security Considerations**:

1. **Always use HTTPS** in production
2. **Disable localhost** in production (`allow_localhost=False`)
3. **Use environment variables** for URLs (not hardcoded)
4. **Whitelist specific domains** if possible

**Example Production Configuration**:

```bash
# ~/.claude/security.env
TMWS_URL=https://tmws.internal.company.com
ALLOW_LOCALHOST=false  # Explicit production mode
```

### Fallback Directory Configuration

**Default Location**: `~/.claude/decisions`

**Security Requirements**:

1. **Permissions**: `0o700` (owner only)
2. **Location**: User home directory (not /tmp or world-writable)
3. **Disk Space**: Monitor usage (auto-cleanup recommended)

**Setup Secure Fallback**:

```bash
# Create fallback directory
mkdir -p ~/.claude/decisions
chmod 700 ~/.claude/decisions

# Optional: Set up auto-cleanup (keep only last 30 days)
cat > ~/.claude/scripts/cleanup_decisions.sh << 'EOF'
#!/bin/bash
# Cleanup old decision files
find ~/.claude/decisions -name "*.json" -mtime +30 -delete
EOF

chmod 700 ~/.claude/scripts/cleanup_decisions.sh

# Add to crontab (daily cleanup at 3 AM)
(crontab -l 2>/dev/null; echo "0 3 * * * ~/.claude/scripts/cleanup_decisions.sh") | crontab -
```

### File Permissions Best Practices

**Recommended Permissions**:

| Path | Permission | Octal | Description |
|------|-----------|-------|-------------|
| `~/.claude/` | `drwx------` | `0o700` | User-only access |
| `~/.claude/hooks/core/` | `drwx------` | `0o700` | User-only access |
| `~/.claude/hooks/core/*.py` | `-rw-------` | `0o600` | User read/write only |
| `~/.claude/decisions/` | `drwx------` | `0o700` | User-only access |
| `~/.claude/decisions/*.json` | `-rw-------` | `0o600` | User read/write only |
| `~/.claude/security.env` | `-rw-------` | `0o600` | User read/write only |

**Verify Permissions**:

```bash
# Check all critical paths
ls -la ~/.claude/hooks/core/
ls -la ~/.claude/decisions/
ls -la ~/.claude/security.env

# Fix if needed
chmod 700 ~/.claude/hooks/core/
chmod 600 ~/.claude/hooks/core/*.py
chmod 700 ~/.claude/decisions/
chmod 600 ~/.claude/security.env
```

---

## Best Practices

### 1. Defense in Depth

Implement multiple security layers:

```bash
# Layer 1: OS-level security
- Enable SELinux/AppArmor
- Use least-privilege user account
- Enable firewall (ufw, iptables)

# Layer 2: Application security
- Rate limiting (100/60s)
- Input validation (all functions)
- Path traversal prevention

# Layer 3: Network security
- SSRF protection (IP range blocking)
- HTTPS enforcement
- Certificate validation

# Layer 4: Monitoring
- Log all security events
- Alert on rate limit violations
- Monitor file access patterns
```

### 2. Secure Configuration Management

**Secrets Management**:

```bash
# ❌ WRONG: Hardcoded secrets
TMWS_URL = "https://tmws.example.com?api_key=abc123"

# ✅ CORRECT: Environment variables
TMWS_URL = os.getenv("TMWS_URL")
TMWS_API_KEY = os.getenv("TMWS_API_KEY")

# ✅ BETTER: Use secret management tools
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault
```

### 3. Regular Security Audits

**Weekly Checks**:
- Review rate limiter logs for anomalies
- Check disk usage in fallback directory
- Verify file permissions haven't changed

**Monthly Checks**:
- Update dependencies (`pip list --outdated`)
- Review security logs for patterns
- Test incident response procedures

**Quarterly Checks**:
- Full security audit with penetration testing
- Review and update security policies
- Update threat model

### 4. Least Privilege Principle

**User Account**:
```bash
# Create dedicated user for Claude Code
sudo useradd -m -s /bin/bash claude-user
sudo usermod -L claude-user  # Lock password (no login)

# Set up SSH key authentication only
sudo mkdir /home/claude-user/.ssh
sudo cp authorized_keys /home/claude-user/.ssh/
sudo chown -R claude-user:claude-user /home/claude-user/.ssh
sudo chmod 700 /home/claude-user/.ssh
sudo chmod 600 /home/claude-user/.ssh/authorized_keys
```

**File System Isolation**:
```bash
# Use AppArmor profile (Ubuntu/Debian)
sudo cat > /etc/apparmor.d/claude-code << 'EOF'
#include <tunables/global>

/home/claude-user/.claude/hooks/core/decision_check.py {
  #include <abstractions/base>
  #include <abstractions/python>

  # Allow read/write to decisions directory
  /home/claude-user/.claude/decisions/** rw,

  # Deny network (except TMWS)
  deny network inet,
  allow network inet to tmws.your-domain.com,

  # Deny other file access
  deny /** w,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/claude-code
```

### 5. Secure Logging

**Log Sanitization**:

```python
# Always sanitize logs (implemented in all hooks)
from .security_utils import sanitize_log_message, redact_secrets

# Log user input
logger.info(f"Prompt: {sanitize_log_message(redact_secrets(prompt))}")

# Log errors
logger.error(f"Error: {sanitize_log_message(str(exception))}")
```

**Log Rotation**:

```bash
# Configure logrotate
sudo cat > /etc/logrotate.d/claude-code << 'EOF'
/home/claude-user/.claude/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 claude-user claude-user
    sharedscripts
    postrotate
        # Signal Claude Code to reopen log files (if needed)
    endscript
}
EOF
```

---

## Monitoring and Logging

### Security Event Logging

**Key Events to Log**:

1. **Rate Limit Violations**:
   ```python
   logger.warning(f"Rate limit exceeded: {operation_id}")
   ```

2. **Path Traversal Attempts**:
   ```python
   logger.error(f"Path traversal blocked: {decision_id}")
   ```

3. **SSRF Attempts**:
   ```python
   logger.error(f"SSRF blocked: {url}")
   ```

4. **Invalid Input**:
   ```python
   logger.warning(f"Invalid input sanitized: {input_type}")
   ```

### Monitoring with Prometheus (Optional)

**Export Metrics**:

```python
# Add to decision_check.py
from prometheus_client import Counter, Histogram

rate_limit_rejections = Counter(
    'trinitas_rate_limit_rejections_total',
    'Total rate limit rejections'
)

prompt_processing_duration = Histogram(
    'trinitas_prompt_processing_seconds',
    'Prompt processing duration'
)

# In process_hook()
with prompt_processing_duration.time():
    # Process prompt
    pass

# On rate limit
rate_limit_rejections.inc()
```

### Alerting Rules

**Recommended Alerts**:

1. **High Rate Limit Rejections**:
   - Threshold: >10 rejections/minute
   - Action: Alert security team, potential DoS attack

2. **Path Traversal Attempts**:
   - Threshold: Any occurrence
   - Action: Immediate investigation, potential compromise

3. **SSRF Attempts**:
   - Threshold: Any occurrence
   - Action: Immediate investigation, potential attack

4. **Disk Space**:
   - Threshold: >80% usage in fallback directory
   - Action: Cleanup old decisions, increase capacity

**Example Alert Configuration** (Prometheus Alertmanager):

```yaml
groups:
  - name: trinitas_security
    rules:
      - alert: HighRateLimitRejections
        expr: rate(trinitas_rate_limit_rejections_total[1m]) > 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High rate of rate limit rejections detected"

      - alert: PathTraversalAttempt
        expr: increase(trinitas_path_traversal_attempts_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Path traversal attempt detected"
```

---

## Troubleshooting

### Common Issues

#### Issue 1: Rate Limit Too Restrictive

**Symptoms**:
- Frequent "Rate limit exceeded" errors
- Users complaining about slow responses

**Diagnosis**:
```bash
# Check rate limiter stats
grep "Rate limit" ~/.claude/logs/decision_check.log

# Calculate rejection rate
total=$(grep "Rate limit" ~/.claude/logs/decision_check.log | wc -l)
rejected=$(grep "Rate limit exceeded" ~/.claude/logs/decision_check.log | wc -l)
echo "Rejection rate: $(($rejected * 100 / $total))%"
```

**Solution**:
```python
# Increase limits in decision_check.py
self.rate_limiter = ThreadSafeRateLimiter(
    max_calls=200,  # Increase from 100
    window_seconds=60
)
```

#### Issue 2: TMWS URL Validation Fails

**Symptoms**:
- "SSRFError: Private IP not allowed"
- Cannot connect to local TMWS instance

**Diagnosis**:
```bash
# Test URL validation
python3 << 'EOF'
from .claude.hooks.core.security_utils import validate_tmws_url
try:
    url = validate_tmws_url("http://192.168.1.100:8080", allow_localhost=True)
    print(f"Valid: {url}")
except Exception as e:
    print(f"Invalid: {e}")
EOF
```

**Solution**:
```python
# Enable localhost for development
self.tmws_url = validate_tmws_url(
    tmws_url,
    allow_localhost=True  # ← Enable for local testing
)
```

#### Issue 3: Path Traversal False Positives

**Symptoms**:
- Valid decision IDs rejected
- "Invalid decision ID" errors for legitimate IDs

**Diagnosis**:
```bash
# Test decision ID validation
python3 << 'EOF'
from .claude.hooks.core.security_utils import validate_decision_id
test_ids = ["decision-123", "2024-11-03_prompt", "user_123_decision"]
for test_id in test_ids:
    try:
        valid = validate_decision_id(test_id)
        print(f"✅ Valid: {valid}")
    except ValueError as e:
        print(f"❌ Invalid: {test_id} - {e}")
EOF
```

**Solution**:
- Ensure decision IDs only use alphanumeric, dash, underscore
- Avoid special characters (`;`, `&`, `|`, `$`, etc.)

#### Issue 4: Permission Denied Errors

**Symptoms**:
- "Permission denied" when writing decisions
- Hook execution fails

**Diagnosis**:
```bash
# Check permissions
ls -la ~/.claude/decisions/
ls -la ~/.claude/hooks/core/

# Check ownership
stat -c "%U:%G %a" ~/.claude/decisions/
```

**Solution**:
```bash
# Fix ownership
sudo chown -R $USER:$USER ~/.claude/

# Fix permissions
chmod 700 ~/.claude/decisions/
chmod 600 ~/.claude/hooks/core/*.py
```

---

## Incident Response

### Security Incident Playbook

#### Step 1: Detection

**Indicators of Compromise (IoCs)**:
- Unusual spike in rate limit rejections
- Path traversal attempts in logs
- SSRF attempts targeting internal resources
- Unexpected file modifications in `~/.claude/`

#### Step 2: Containment

**Immediate Actions**:

```bash
# 1. Disable hooks temporarily
mv ~/.claude/hooks/core/decision_check.py ~/.claude/hooks/core/decision_check.py.disabled

# 2. Review recent logs
tail -n 1000 ~/.claude/logs/decision_check.log > /tmp/incident_$(date +%Y%m%d_%H%M%S).log

# 3. Check file integrity
find ~/.claude/hooks/core/ -type f -mtime -1 -ls

# 4. Block suspicious IPs (if applicable)
sudo iptables -A INPUT -s <SUSPICIOUS_IP> -j DROP
```

#### Step 3: Investigation

**Collect Evidence**:

```bash
# Capture system state
ps aux | grep claude > /tmp/processes.txt
netstat -tulpn | grep claude > /tmp/network.txt
ls -laR ~/.claude/ > /tmp/file_listing.txt

# Analyze logs
grep -i "error\|warning\|traversal\|ssrf\|rate limit" ~/.claude/logs/*.log > /tmp/security_events.log

# Check for unauthorized changes
git -C ~/trinitas-agents status
git -C ~/trinitas-agents log --oneline -10
```

#### Step 4: Eradication

**Remove Threats**:

```bash
# 1. Restore from backup (if compromised)
rm -rf ~/.claude/hooks/core/
cp -r ~/backups/claude/hooks/core/ ~/.claude/hooks/core/

# 2. Update dependencies
pip install -U --upgrade-strategy eager trinitas-agents

# 3. Verify integrity
sha256sum ~/.claude/hooks/core/*.py
```

#### Step 5: Recovery

**Restore Services**:

```bash
# 1. Re-enable hooks
mv ~/.claude/hooks/core/decision_check.py.disabled ~/.claude/hooks/core/decision_check.py

# 2. Test functionality
python3 ~/.claude/hooks/core/decision_check.py << 'EOF'
{
  "prompt": "Test prompt after incident",
  "decision_id": "test-recovery-001"
}
EOF

# 3. Monitor closely for 24 hours
tail -f ~/.claude/logs/decision_check.log
```

#### Step 6: Post-Incident Review

**Document Lessons Learned**:

1. Root cause analysis
2. Timeline of events
3. Effectiveness of response
4. Recommendations for prevention
5. Update incident response plan

---

## Compliance Checklist

### Pre-Deployment Checklist

- [ ] All dependencies updated to latest secure versions
- [ ] Rate limiting configured (100 calls/60 seconds)
- [ ] TMWS URL validated (HTTPS, no localhost in production)
- [ ] Fallback directory permissions set (0o700)
- [ ] File permissions verified (0o600 for .py files)
- [ ] Environment variables configured securely
- [ ] Logging enabled and tested
- [ ] Monitoring alerts configured
- [ ] Incident response plan documented
- [ ] Team trained on security procedures

### Production Deployment Checklist

- [ ] Code deployed from verified git commit
- [ ] Integrity checks passed (sha256sum)
- [ ] Hooks installed in `~/.claude/hooks/core/`
- [ ] Security configuration verified (`security.env`)
- [ ] Permissions locked down (no world-readable files)
- [ ] Rate limiter tested under load
- [ ] SSRF protection verified (try private IPs)
- [ ] Path traversal protection verified (try ../)
- [ ] Logging working (check log files)
- [ ] Alerts firing correctly (test with anomalies)

### Post-Deployment Checklist

- [ ] Monitor logs for first 24 hours
- [ ] Verify no rate limit false positives
- [ ] Check disk usage in fallback directory
- [ ] Confirm no security events
- [ ] Test incident response procedures
- [ ] Document deployment date and version
- [ ] Update change log
- [ ] Notify team of successful deployment

### Ongoing Compliance (Monthly)

- [ ] Review security logs for anomalies
- [ ] Update dependencies (`pip list --outdated`)
- [ ] Rotate credentials (TMWS API keys)
- [ ] Test backup and restore procedures
- [ ] Review and update threat model
- [ ] Conduct security training
- [ ] Audit file permissions
- [ ] Review rate limit settings

---

## Additional Resources

### Documentation

- [Security Utils API Documentation](../api/security_utils.md)
- [Security Architecture Document](../architecture/security_architecture.md)
- [Phase 1.3 Security Verification Report](../phase1.3_security_verification_report.md)

### External References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE Top 25 (2023)](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Support

- **GitHub Issues**: https://github.com/apto-as/trinitas-agents/issues
- **Security Issues**: security@trinitas-ai.com (private disclosure)
- **Documentation**: https://github.com/apto-as/trinitas-agents/docs/

---

**Last Updated**: 2025-11-03
**Version**: 2.3.0
**Author**: Hestia (Security Guardian) + Muses (Knowledge Architect)
**Status**: Production-Ready
**Security Contact**: security@trinitas-ai.com
