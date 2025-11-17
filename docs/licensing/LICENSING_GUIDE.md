# TMWS Licensing Guide
## Complete Guide to License Tiers, Obtaining Keys, and Management

**Last Updated**: 2025-11-16
**TMWS Version**: v2.3.2+
**License System**: Phase 2E (Source Protection + Startup Gate)

---

## Overview

TMWS v2.3.2+ requires a valid license key to operate. This document explains the licensing system, available tiers, and how to obtain and manage your license.

### Why Licensing?

Starting with v2.3.2, TMWS uses license keys to:
- **Protect source code**: Bytecode distribution prevents casual code inspection
- **Control distribution**: Ensure only authorized users can run TMWS
- **Enable tiered features**: Different capabilities for FREE, STANDARD, ENTERPRISE
- **Support development**: Revenue from paid tiers funds ongoing development

---

## License Tiers

### FREE Tier

**Cost**: $0 (lifetime)
**Features**:
- 1 agent (single namespace)
- Community support (GitHub Discussions)
- Basic features: Memory, Tasks, Workflows, Learning
- No commercial use
- Source code inspection disabled (bytecode only)

**Obtain**: Contact your system administrator

**Ideal For**: Personal use, experimentation, learning

---

### STANDARD Tier

**Cost**: $49/month or $499/year (17% discount)
**Features**:
- 10 agents (multi-namespace)
- Email support (48-hour response time)
- Advanced features: Security audit logging, RBAC, Rate limiting
- Commercial use allowed
- Priority bug fixes

**Obtain**: Contact your system administrator

**Ideal For**: Small teams, startups, production deployments

---

### ENTERPRISE Tier

**Cost**: Custom pricing (contact administrator)
**Features**:
- Unlimited agents
- Priority support (24-hour SLA)
- Custom features and integrations
- On-premise deployment support
- Dedicated account manager
- White-label options

**Obtain**: Contact your system administrator for custom configuration

**Ideal For**: Large organizations, high-security deployments, custom requirements

---

## Obtaining a License Key

### FREE Tier Process

1. **Request**: Contact your system administrator
2. **Receive**: Administrator generates FREE license key using internal tools
3. **Activate**: Add license key to `.env` file as `TMWS_LICENSE_KEY`

**Time**: Depends on administrator availability

---

### STANDARD/ENTERPRISE Process

1. **Request**: Contact your system administrator
2. **Approval**: Administrator reviews request and tier requirements
3. **Receive**: Administrator generates license key for your tier
4. **Activate**: Add license key to `.env` file as `TMWS_LICENSE_KEY`

**Time**: Depends on approval process

---

## License Key Format

All TMWS license keys follow this format:

```
TMWS-{TIER}-{UUID}-{CHECKSUM}
```

**Example**:
```
TMWS-FREE-12345678-1234-5678-1234-567812345678-ABCD1234
```

**Components**:
- `TMWS`: Prefix (all TMWS keys)
- `{TIER}`: License tier (FREE, STANDARD, ENTERPRISE, UNLIMITED)
- `{UUID}`: Unique identifier (UUID v4)
- `{CHECKSUM}`: HMAC-SHA256 signature (prevents tampering)

---

## License Validation

### Startup Validation

TMWS validates your license **every time it starts**:

1. **Environment Variable**: Reads `TMWS_LICENSE_KEY`
2. **Format Check**: Verifies key format
3. **Signature Check**: Validates HMAC-SHA256 checksum
4. **Expiration Check**: Checks if license has expired
5. **Revocation Check**: Ensures license hasn't been revoked
6. **Tier Enforcement**: Enables/disables features based on tier

**Fail-Fast Behavior**: If validation fails, TMWS **exits immediately** with error code 1.

### Grace Period

**Expired licenses**: 7-day grace period
**Behavior during grace period**:
- ⚠️  Warning logs on startup
- ✅ TMWS operates normally
- 📧 Email reminder to renew
- 🔴 After 7 days: License invalid, TMWS won't start

**Strict Mode**: Set `TMWS_LICENSE_STRICT_MODE=true` to disable grace period

---

## License Management

### Viewing License Info

**Via MCP Tool**:
```python
from src.tools.license_tools import get_license_info

info = await get_license_info(license_key="TMWS-...")
print(info)
# Output:
# {
#   "tier": "FREE",
#   "expires_at": "2026-11-16T00:00:00Z",
#   "agents_limit": 1,
#   "created_at": "2025-11-16T12:00:00Z"
# }
```

**Via Docker Logs**:
```bash
docker logs tmws | grep "License validated"
# Output:
# ✅ License validated successfully
#    Tier: FREE
#    Expires: 2026-11-16T00:00:00Z
```

---

### Renewing Licenses

**STANDARD/ENTERPRISE** (automatic renewal):
- Billing cycle renews automatically (monthly/annual)
- License key remains unchanged
- Expiration date extends automatically

**FREE Tier** (manual renewal):
- FREE licenses expire after 1 year
- Contact your system administrator for renewal
- New license key issued (update `.env` file)

---

### Upgrading Tiers

**FREE → STANDARD**:
1. Contact your system administrator
2. Request STANDARD tier upgrade
3. Administrator reviews and approves request
4. Receive new STANDARD license key
5. Update `.env` file with new key
6. Restart TMWS

**STANDARD → ENTERPRISE**:
1. Contact your system administrator
2. Discuss requirements and custom configuration needs
3. Receive custom ENTERPRISE license key
4. Update `.env` file
5. Restart TMWS

---

### Revoking Licenses

**Revocation** (All Tiers):
- Contact your system administrator to revoke license
- License revoked immediately or after notice period

**FREE Tier**:
- Cannot be revoked (lifetime license)
- Can be replaced with new FREE license if lost

**Revoked licenses**:
- TMWS will not start
- Error message: "License has been revoked"
- Must obtain new license

---

## Security & Privacy

### License Key Security

**IMPORTANT**: Treat your license key like a password.

**Best Practices**:
- ✅ Store in `.env` file (gitignored)
- ✅ Use environment variables in production
- ✅ Never commit to Git repositories
- ✅ Rotate keys if compromised
- ❌ Never share license keys publicly
- ❌ Don't include in documentation/screenshots
- ❌ Don't log license keys (TMWS automatically redacts)

**Compromise Response**:
1. Report to your system administrator immediately
2. License will be revoked immediately
3. New license key issued by administrator

### Privacy

**License validation collects**:
- License key (hashed, not stored plaintext)
- Validation timestamp
- TMWS version
- Agent count

**NOT collected**:
- Source code or intellectual property
- Memory content or task data
- User personal information (beyond email for account)

**Data retention**: 90 days (for support and fraud prevention)

---

## Troubleshooting

### Error: "TMWS requires a valid license key to start"

**Cause**: `TMWS_LICENSE_KEY` environment variable not set

**Solution**:
```bash
# Check if variable is set
echo $TMWS_LICENSE_KEY

# If empty, set it
export TMWS_LICENSE_KEY="TMWS-FREE-your-key-here"

# For Docker
vim .env  # Add TMWS_LICENSE_KEY=...
docker-compose restart
```

---

### Error: "Invalid license key: Invalid format"

**Cause**: License key format is incorrect

**Solution**:
- Verify key starts with `TMWS-`
- Check for typos or truncation
- Ensure no extra spaces or newlines
- Copy-paste from email carefully

---

### Error: "Invalid license key: License has been revoked"

**Cause**: License was revoked (subscription canceled or security issue)

**Solution**:
1. Contact your system administrator
2. Request license renewal if subscription expired
3. Report issue if revocation was unexpected

---

### Error: "Invalid license key: Signature verification failed"

**Cause**: License key checksum is invalid (tampered or corrupted)

**Solution**:
- Request new license key from your system administrator
- Check for data corruption (file transfer, copy-paste errors)
- Verify no quote escaping issues in `.env` file

---

### Warning: "License expired X days ago. Grace period: Y days remaining"

**Cause**: License has expired but grace period is active

**Solution**:
- Contact your system administrator for license renewal
- Update `.env` file with new key
- Restart TMWS before grace period ends

---

## Support

- **Community (FREE)**: https://github.com/apto-as/tmws/discussions
- **Internal Support**: Contact your system administrator
- **Security Issues**: Report to your system administrator

---

## License Agreement

By using TMWS with a license key, you agree to your organization's internal software license agreement and terms of use.

**Key Terms**:
- FREE tier: Non-commercial use only
- STANDARD/ENTERPRISE: Commercial use allowed
- No redistribution of bytecode or license keys
- Source code inspection prohibited (bytecode protection)
- Compliance with export control regulations

---

**End of Licensing Guide**
