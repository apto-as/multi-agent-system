# TMWS Licensing FAQ
## Frequently Asked Questions

**Last Updated**: 2025-11-16
**TMWS Version**: v2.3.2+

---

## General Questions

### Q: Why does TMWS v2.3.2+ require a license key?

**A**: TMWS v2.3.2 introduces source code protection (bytecode distribution) and license-based distribution control. This:
- Prevents casual source code inspection (protecting intellectual property)
- Enables tiered pricing (FREE, STANDARD, ENTERPRISE)
- Funds ongoing development and support
- Ensures only authorized users can run TMWS

---

### Q: Can I still use TMWS for free?

**A**: Yes! The **FREE tier** is **lifetime free** with:
- 1 agent
- Community support
- Basic features (Memory, Tasks, Workflows, Learning)
- No credit card required

**Obtain FREE license**: https://trinitas.ai/licensing/free

---

### Q: What happens if I don't have a license key?

**A**: TMWS v2.3.2+ will **not start** without a valid license key. You'll see this error:

```
❌ TMWS requires a valid license key to start.

Please set the TMWS_LICENSE_KEY environment variable:
  export TMWS_LICENSE_KEY='your-license-key'
```

**Solution**: Obtain a FREE license (5 minutes, no cost)

---

### Q: Can I inspect the source code?

**A**: No. TMWS v2.3.2+ is distributed as **Python bytecode** (.pyc files) for source protection.

**Why**:
- Protects proprietary algorithms and business logic
- Prevents unauthorized code modifications
- Complies with licensing requirements

**Decompilation**: Technically possible (~70-80% success), but **prohibited** by license agreement.

---

## License Tiers

### Q: What are the differences between FREE, STANDARD, and ENTERPRISE?

| Feature | FREE | STANDARD | ENTERPRISE |
|---------|------|----------|------------|
| **Cost** | $0 | $49/mo | Custom |
| **Agents** | 1 | 10 | Unlimited |
| **Support** | Community | Email (48h) | Priority (24h SLA) |
| **Commercial Use** | ❌ | ✅ | ✅ |
| **Advanced Features** | ❌ | ✅ | ✅ |
| **Custom Integrations** | ❌ | ❌ | ✅ |
| **White-Label** | ❌ | ❌ | ✅ |

---

### Q: Can I upgrade from FREE to STANDARD?

**A**: Yes!

1. Visit: https://trinitas.ai/licensing/upgrade
2. Enter your current FREE license key
3. Complete payment
4. Receive new STANDARD license key
5. Update `.env` file and restart TMWS

**Data migration**: Automatic (all data preserved)

---

### Q: What is a "namespace" and why does it matter?

**A**: A **namespace** is a logical grouping of agents, memories, and tasks.

**Example**:
- FREE tier: 1 namespace = 1 agent (e.g., `personal-assistant`)
- STANDARD tier: 10 namespaces = 10 agents (e.g., `team-1`, `team-2`, ..., `team-10`)

**Why it matters**: Each namespace is isolated (security), and agent limits are enforced per namespace.

---

## License Keys

### Q: What does a TMWS license key look like?

**A**: All TMWS keys follow this format:

```
TMWS-{TIER}-{UUID}-{CHECKSUM}
```

**Example**:
```
TMWS-FREE-12345678-1234-5678-1234-567812345678-ABCD1234
```

**Parts**:
- `TMWS`: Prefix (all keys)
- `FREE/STANDARD/ENTERPRISE`: Tier
- `12345678-1234-5678-1234-567812345678`: Unique ID (UUID v4)
- `ABCD1234`: Checksum (HMAC-SHA256, tamper protection)

---

### Q: Where do I get a license key?

**A**:

- **FREE**: https://trinitas.ai/licensing/free (instant, email delivery)
- **STANDARD**: https://trinitas.ai/licensing/standard (purchase, immediate delivery)
- **ENTERPRISE**: Contact sales@trinitas.ai (custom negotiation)

---

### Q: How long is my license key valid?

**A**:

- **FREE**: 1 year (renewable for free)
- **STANDARD**: Monthly or annual subscription (auto-renewal)
- **ENTERPRISE**: Custom term (typically annual)

---

### Q: Can I share my license key?

**A**: **No**. License keys are **non-transferable** and tied to your account.

**Violations**:
- Public sharing → License revoked
- Multiple simultaneous uses → Detected and flagged
- Commercial redistribution → Legal action

**Exceptions**: ENTERPRISE tier can distribute to internal team members (within organization).

---

## Validation & Errors

### Q: How does TMWS validate my license?

**A**: At **every startup**, TMWS:

1. Reads `TMWS_LICENSE_KEY` environment variable
2. Checks key format (TMWS-{TIER}-{UUID}-{CHECKSUM})
3. Validates checksum (HMAC-SHA256 signature)
4. Checks expiration date
5. Checks revocation status (database lookup)
6. Enables/disables features based on tier

**Fail-fast**: If validation fails, TMWS exits with error code 1.

---

### Q: What is the "7-day grace period"?

**A**: If your license **expires**, TMWS allows a **7-day grace period** before blocking startup.

**During grace period**:
- ⚠️ Warning logs on every startup
- ✅ TMWS operates normally
- 📧 Email reminder to renew
- 🔴 After 7 days: License invalid, TMWS won't start

**Disable grace period**: Set `TMWS_LICENSE_STRICT_MODE=true` (production recommended)

---

### Q: Why is my license key "invalid"?

**Common reasons**:

1. **Typo**: Check for copy-paste errors (no extra spaces/newlines)
2. **Expired**: License expired and grace period ended
3. **Revoked**: Subscription canceled or security issue
4. **Tampered**: Checksum verification failed (corrupted key)

**Solution**: Request new key at https://trinitas.ai/licensing/reissue

---

### Q: Can TMWS work offline?

**A**: **No**. License validation requires **internet access** to check revocation status.

**Workaround** (ENTERPRISE only): Contact sales for air-gapped deployment support (on-premise license server).

---

## Renewal & Management

### Q: How do I renew my FREE license?

**A**:

1. Visit: https://trinitas.ai/licensing/renew
2. Enter expired license key
3. Click "Renew FREE License"
4. Receive new license key via email
5. Update `.env` file with new key
6. Restart TMWS

**Cost**: $0 (free renewal)

---

### Q: Do STANDARD/ENTERPRISE licenses auto-renew?

**A**: Yes, **automatic renewal** with active subscription.

**How it works**:
- License expiration extends automatically
- License key remains unchanged (no update needed)
- Billing occurs on renewal date
- Email notification 7 days before renewal

**Cancel subscription**: License expires after current billing period ends.

---

### Q: How do I cancel my STANDARD subscription?

**A**:

1. Visit: https://trinitas.ai/account/subscription
2. Click "Cancel Subscription"
3. Confirm cancellation
4. License remains valid until end of billing period
5. After period ends: License expires (7-day grace period applies)

**Refunds**: Pro-rated refunds for annual plans (within 30 days)

---

## Troubleshooting

### Q: Error: "TMWS requires a valid license key to start"

**A**: `TMWS_LICENSE_KEY` environment variable is not set.

**Solution**:
```bash
# Check if set
echo $TMWS_LICENSE_KEY

# If empty, set it
export TMWS_LICENSE_KEY="TMWS-FREE-your-key-here"

# For Docker
vim .env  # Add TMWS_LICENSE_KEY=...
docker-compose restart
```

---

### Q: Error: "Invalid license key: Invalid format"

**A**: License key format is incorrect.

**Checklist**:
- [ ] Key starts with `TMWS-`
- [ ] Four parts separated by `-` (e.g., TMWS-FREE-UUID-CHECKSUM)
- [ ] No extra spaces or newlines
- [ ] Copied from email correctly

**Solution**: Copy-paste key carefully from email, or request new key.

---

### Q: Error: "Invalid license key: License has been revoked"

**A**: License was revoked (subscription canceled or security issue).

**Solution**:
1. Check subscription status: https://trinitas.ai/account
2. Renew if expired
3. Contact support@trinitas.ai if unexpected

---

### Q: Warning: "License expired X days ago. Grace period: Y days remaining"

**A**: License expired, but 7-day grace period is active.

**Solution**: Renew license **before grace period ends** to avoid service interruption.

**Renew**: https://trinitas.ai/licensing/renew

---

## Security & Privacy

### Q: Is my license key stored securely?

**A**: Yes.

**TMWS security**:
- License keys **never logged** (automatically redacted)
- Stored in `.env` file (gitignored by default)
- Database stores **hashed key** (not plaintext)
- HMAC-SHA256 signature prevents tampering

**Best practices**:
- ✅ Use `.env` file (not environment vars in shell history)
- ✅ Never commit `.env` to Git
- ✅ Use secrets management in production (e.g., AWS Secrets Manager)

---

### Q: What data does license validation collect?

**A**:

**Collected**:
- License key (hashed)
- Validation timestamp
- TMWS version
- Agent count

**NOT collected**:
- Source code or intellectual property
- Memory content or task data
- User personal information (beyond email)

**Data retention**: 90 days (support and fraud prevention)

**Privacy policy**: https://trinitas.ai/legal/privacy-policy

---

### Q: Can I use TMWS for commercial purposes with a FREE license?

**A**: **No**. FREE tier is **non-commercial only**.

**Allowed**:
- Personal use
- Education
- Open-source projects (non-profit)

**NOT allowed**:
- SaaS products
- Commercial services
- Revenue-generating applications

**Solution**: Upgrade to STANDARD ($49/month) for commercial use.

---

## Enterprise Features

### Q: What additional features does ENTERPRISE include?

**A**:

**Unlimited agents**: No namespace limits
**Priority support**: 24-hour SLA (vs 48h for STANDARD)
**Custom integrations**: Tailored connectors and APIs
**On-premise deployment**: Air-gapped, self-hosted option
**White-label**: Remove Trinitas branding
**Dedicated account manager**: Personalized assistance
**SLA guarantees**: Uptime, performance, support response
**Custom contract terms**: Flexible billing, multi-year discounts

**Contact sales**: sales@trinitas.ai

---

### Q: Can ENTERPRISE users distribute TMWS to their customers?

**A**: **Yes**, with restrictions.

**Allowed** (within your organization):
- Internal teams
- Subsidiaries
- Contractors (under NDA)

**NOT allowed** (external distribution):
- Reselling TMWS as a product
- SaaS with TMWS as backend (white-label SaaS requires special agreement)
- Open-source redistribution (bytecode or source)

**White-label SaaS**: Contact sales for custom licensing.

---

## Support

### Q: What support is included with each tier?

| Tier | Support Channel | Response Time |
|------|----------------|---------------|
| **FREE** | GitHub Discussions (community) | Best-effort |
| **STANDARD** | Email (support@trinitas.ai) | 48 hours |
| **ENTERPRISE** | Email + Phone | 24 hours (SLA) |

---

### Q: How do I report a security issue?

**A**: Email **security@trinitas.ai** (not public GitHub issues).

**Response**: 24 hours for CRITICAL, 48 hours for HIGH

**Bug bounty**: Up to $5,000 for verified vulnerabilities (ENTERPRISE tier only)

---

### Q: Can I request custom features?

**A**:

- **FREE**: Submit feature request on GitHub Discussions (no guarantee)
- **STANDARD**: Email support@trinitas.ai (prioritized based on demand)
- **ENTERPRISE**: Custom features included (discuss with account manager)

---

## Still Have Questions?

- **Community**: https://github.com/apto-as/tmws/discussions
- **Email**: support@trinitas.ai
- **Sales**: sales@trinitas.ai
- **Security**: security@trinitas.ai

---

**End of FAQ**
