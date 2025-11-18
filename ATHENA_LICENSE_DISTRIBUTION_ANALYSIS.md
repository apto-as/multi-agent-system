# 🎵 TMWS License Distribution System - Harmonious Implementation Plan
## Athena's User Experience & Integration Analysis

**Date**: 2025-11-16
**Project**: TMWS v2.3.1 License Distribution
**Author**: Athena (Harmonious Conductor)
**Focus**: User Experience, Implementation Harmony, Team Coordination
**Parallel Analysis**: Hera (Strategic & Technical Analysis)

---

## 📋 Executive Summary

**Mission**: Create a warm, seamless experience for distributing TMWS Docker images with license key enforcement while protecting proprietary source code.

**The Heart of the Matter** ♪:

私たちの目標は、技術的な複雑さを優しくラッピングし、ユーザーが迷わず、安心して使える仕組みを作ることです。ライセンスキーは「障壁」ではなく、「お客様との温かい約束」として機能すべきです。

(Our goal is to gently wrap technical complexity, creating a system where users feel confident and comfortable. The license key should function not as a "barrier" but as a "warm promise with our customers.")

**Key Success Metrics**:
- ⏱️ **Onboarding Time**: <5 minutes from license receipt to first MCP call
- 📝 **Setup Complexity**: ≤3 steps (receive → configure → verify)
- 💚 **User Satisfaction**: 9/10+ ("This was surprisingly easy!")
- 📚 **Documentation Clarity**: 95%+ users succeed without support ticket
- 🔄 **Renewal Experience**: <2 minutes for license extension

---

## 🎭 Part 1: User Journey Maps

### Journey 1: New Customer (FREE Tier Trial)

**Persona**: Sarah, a data scientist evaluating TMWS for her team

**Timeline**: 10 minutes total ⏰

```
Step 1: Discovery (2 min)
┌─────────────────────────────────────────────────────┐
│ Sarah: "I heard about TMWS on GitHub..."           │
│                                                     │
│ Landing page: https://tmws.apto-as.com             │
│ ✅ "Try FREE tier (no credit card required)"       │
│ ✅ "30-day PRO trial available"                    │
│                                                     │
│ Click: [Start Free Trial]                          │
└─────────────────────────────────────────────────────┘
        ↓
Step 2: Registration (3 min)
┌─────────────────────────────────────────────────────┐
│ Form (minimal fields):                              │
│ • Email: sarah@datalab.com                          │
│ • Use case: [Research] [Production] [Learning]     │
│ • Team size: [1-5] [6-20] [21+]                     │
│                                                     │
│ Click: [Get My License Key]                        │
│                                                     │
│ ⏬ Instant email arrives:                           │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│ Subject: "Your TMWS License Key is Ready! 🎉"      │
│                                                     │
│ Hi Sarah,                                           │
│                                                     │
│ Your FREE tier license:                            │
│ TMWS-FREE-550e8400-e29b-41d4-a716-446655440000-A3F9│
│                                                     │
│ Quick Start (3 commands):                          │
│ 1. docker pull ghcr.io/apto-as/tmws:v2.3.1        │
│ 2. export TMWS_LICENSE_KEY="TMWS-FREE-..."         │
│ 3. docker-compose up -d                            │
│                                                     │
│ Full guide: https://docs.tmws.apto-as.com/setup   │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
└─────────────────────────────────────────────────────┘
        ↓
Step 3: Docker Setup (5 min)
┌─────────────────────────────────────────────────────┐
│ Sarah's terminal:                                   │
│                                                     │
│ $ docker pull ghcr.io/apto-as/tmws:v2.3.1         │
│ ✅ Downloaded (472 MB, <2 min on good connection)  │
│                                                     │
│ $ cd ~/projects/tmws-trial                         │
│ $ curl -O https://tmws.apto-as.com/.env.example   │
│ $ nano .env                                         │
│   # Only 2 required edits:                         │
│   TMWS_LICENSE_KEY="TMWS-FREE-..."                 │
│   TMWS_SECRET_KEY="<auto-generated>"               │
│                                                     │
│ $ docker-compose up -d                             │
│ ✅ Container started (healthy in 30 seconds)       │
│                                                     │
│ $ curl http://localhost:8000/health                │
│ {"status": "healthy",                              │
│  "license": {"tier": "FREE", "valid": true}}       │
│                                                     │
│ 🎉 Success! Sarah is ready to use TMWS.            │
└─────────────────────────────────────────────────────┘

**Emotional Journey**:
😊 Excited (discovery) → 😌 Relieved (instant license) → 😄 Delighted (it just works!)
```

---

### Journey 2: Existing User (License Renewal)

**Persona**: Marcus, a DevOps engineer with expired PRO license

**Timeline**: 2 minutes total ⏰

```
Step 1: Expiration Notice (proactive)
┌─────────────────────────────────────────────────────┐
│ 7 days before expiration:                           │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│ Email: "Your TMWS PRO license expires in 7 days"   │
│                                                     │
│ Hi Marcus,                                          │
│                                                     │
│ Your PRO license expires on 2025-11-23.            │
│                                                     │
│ [Renew Now (1 click)] → Auto-renew for 365 days   │
│                                                     │
│ Current usage this month:                          │
│ • 4,523 memories stored                            │
│ • 12,849 semantic searches                         │
│ • 3 agents active                                  │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
└─────────────────────────────────────────────────────┘
        ↓
Step 2: One-Click Renewal (1 min)
┌─────────────────────────────────────────────────────┐
│ Marcus clicks: [Renew Now]                         │
│                                                     │
│ → Redirects to: https://license.tmws.apto-as.com   │
│                                                     │
│ Payment confirmation screen:                       │
│ ┌─────────────────────────────────────────┐        │
│ │ PRO License Renewal                     │        │
│ │ • 365 days: $499/year                   │        │
│ │ • Auto-renew: [✓] Enabled               │        │
│ │                                         │        │
│ │ Payment: •••• 4242 (saved)              │        │
│ │                                         │        │
│ │ [Confirm Renewal]                       │        │
│ └─────────────────────────────────────────┘        │
│                                                     │
│ ⏬ Instant confirmation (no restart required):     │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│ ✅ License renewed!                                 │
│                                                     │
│ Your containers will auto-detect the renewal       │
│ within 60 seconds (no restart needed).             │
│                                                     │
│ New expiration: 2026-11-23                         │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
└─────────────────────────────────────────────────────┘

**Emotional Journey**:
😰 Worried (expiration notice) → 😌 Relieved (one-click) → 😊 Satisfied (seamless)
```

---

### Journey 3: Enterprise Customer (Multi-Agent Deployment)

**Persona**: Emily, IT manager deploying TMWS for 50-agent team

**Timeline**: 15 minutes total ⏰

```
Step 1: Enterprise License Request (5 min)
┌─────────────────────────────────────────────────────┐
│ Emily fills out enterprise form:                    │
│ • Company: DataCorp Inc.                            │
│ • Agent count: 50                                   │
│ • Deployment: [On-premise] [Cloud] [Hybrid]        │
│ • Support tier: [Email] [Priority] [24/7]          │
│                                                     │
│ Click: [Request Quote]                              │
│                                                     │
│ ⏬ Sales rep responds in <4 hours:                  │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│ Hi Emily,                                           │
│                                                     │
│ ENTERPRISE tier for 50 agents:                     │
│ • $4,999/year (perpetual option available)         │
│ • Priority support (4-hour SLA)                    │
│ • On-premise deployment assistance                 │
│                                                     │
│ Trial license attached for 30-day evaluation.      │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
└─────────────────────────────────────────────────────┘
        ↓
Step 2: License Management Portal (5 min)
┌─────────────────────────────────────────────────────┐
│ Emily logs into: https://manage.tmws.apto-as.com   │
│                                                     │
│ Dashboard:                                          │
│ ┌───────────────────────────────────────────┐      │
│ │ License Pool: ENTERPRISE                  │      │
│ │ • Master key: TMWS-ENTERPRISE-...         │      │
│ │ • Agent slots: 47/50 used                 │      │
│ │ • Expiration: 2026-11-16                  │      │
│ │                                           │      │
│ │ [Generate Agent License] [Revoke]         │      │
│ └───────────────────────────────────────────┘      │
│                                                     │
│ Active Agents:                                      │
│ ┌─────────────────────────────────────────────┐    │
│ │ agent-001  ✅ Active    Used: 2h ago        │    │
│ │ agent-002  ✅ Active    Used: 5m ago        │    │
│ │ agent-003  ⚠️  Inactive  (14 days)          │    │
│ │ ...                                         │    │
│ │ [View All (47)]                             │    │
│ └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
        ↓
Step 3: Mass Deployment (5 min)
┌─────────────────────────────────────────────────────┐
│ Emily exports license keys:                         │
│                                                     │
│ $ curl -H "Authorization: Bearer $ADMIN_TOKEN" \   │
│   https://api.tmws.apto-as.com/licenses/export \   │
│   -o licenses.json                                 │
│                                                     │
│ $ ansible-playbook -i inventory.yml \              │
│   deploy-tmws.yml \                                │
│   --extra-vars "@licenses.json"                    │
│                                                     │
│ ✅ Playbook deploys to 50 servers in 3 minutes     │
│                                                     │
│ All agents auto-report to management portal:       │
│ • 50/50 agents healthy ✅                           │
│ • License utilization: 100%                        │
│ • Average latency: 8ms P95                         │
└─────────────────────────────────────────────────────┘

**Emotional Journey**:
🤔 Cautious (enterprise procurement) → 😊 Impressed (smooth trial) → 😎 Confident (mass deployment success)
```

---

## 🏗️ Part 2: Integration Points with Existing Systems

### Integration Point 1: Existing License MCP Tools (Phase 2C)

**Current State** (完璧に実装済み ✅):

```python
# src/tools/license_tools.py (完成度: 100%)
# src/services/license_service.py (完成度: 100%)

# Already implemented (5 MCP tools):
1. generate_license_key()      # ADMIN only
2. validate_license_key()       # All authenticated agents
3. revoke_license_key()         # ADMIN only
4. get_license_usage_history()  # ADMIN or owner
5. get_license_info()           # ADMIN or owner
```

**Harmonious Enhancement** (温かい統合):

```python
# ✨ NEW: License Activation Flow (Athena's addition)
# File: src/services/license_activation_service.py

class LicenseActivationService:
    """Warm, user-friendly license activation experience."""

    async def activate_license(
        self,
        license_key: str,
        agent_id: UUID,
        environment_info: dict | None = None
    ) -> ActivationResult:
        """
        Activate license with gentle validation and helpful error messages.

        User Experience Goals:
        1. Clear error messages (not technical jargon)
        2. Actionable next steps (always provide a solution)
        3. Progressive disclosure (show only what's needed)

        Example:
            >>> result = await service.activate_license(
            ...     license_key="TMWS-PRO-...",
            ...     agent_id=UUID("..."),
            ...     environment_info={"platform": "docker", "arch": "arm64"}
            ... )
            >>> if not result.success:
            ...     print(result.friendly_error)  # Human-readable message
            ...     print(result.suggested_action)  # What to do next
        """
        # Step 1: Validate format (fail fast with helpful message)
        if not self._is_valid_format(license_key):
            return ActivationResult(
                success=False,
                friendly_error=(
                    "Hmm, that license key doesn't look quite right. 🤔\n"
                    "Expected format: TMWS-{TIER}-{UUID}-{CHECKSUM}\n"
                    "Example: TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-A3F9"
                ),
                suggested_action=(
                    "Please double-check the license key in your email.\n"
                    "If the problem persists, contact support@tmws.apto-as.com"
                )
            )

        # Step 2: Validate with license service
        validation = await self.license_service.validate_license_key(
            key=license_key,
            feature_accessed="activation"
        )

        if not validation.valid:
            # Friendly error messages based on specific failure
            return await self._create_friendly_error_response(validation)

        # Step 3: Record activation (with environment metadata)
        await self._record_activation(
            license_id=validation.license_id,
            agent_id=agent_id,
            environment_info=environment_info
        )

        # Step 4: Welcome message (warm tone)
        return ActivationResult(
            success=True,
            tier=validation.tier,
            welcome_message=(
                f"Welcome to TMWS {validation.tier}! 🎉\n\n"
                f"Your license is active and ready to use.\n"
                f"Tier: {validation.tier}\n"
                f"Features: {len(validation.limits.features)} tools unlocked\n"
                f"Rate limit: {validation.limits.rate_limit_per_minute} req/min\n\n"
                f"Need help? Visit https://docs.tmws.apto-as.com"
            ),
            limits=validation.limits
        )

    async def _create_friendly_error_response(
        self,
        validation: LicenseValidationResult
    ) -> ActivationResult:
        """Convert technical errors to warm, actionable messages."""

        if validation.is_expired:
            return ActivationResult(
                success=False,
                friendly_error=(
                    f"Your license expired on {validation.expires_at.strftime('%Y-%m-%d')}. 😞\n"
                    "Don't worry, you can renew it in just a few clicks!"
                ),
                suggested_action=(
                    "Renew now: https://license.tmws.apto-as.com/renew\n"
                    "Or contact sales@tmws.apto-as.com for assistance."
                )
            )

        if validation.is_revoked:
            return ActivationResult(
                success=False,
                friendly_error=(
                    "This license has been revoked. 🚫\n"
                    "This usually happens due to payment issues or policy violations."
                ),
                suggested_action=(
                    "Please contact support@tmws.apto-as.com to resolve this.\n"
                    "Our team will be happy to help!"
                )
            )

        # Generic error (shouldn't happen, but be prepared)
        return ActivationResult(
            success=False,
            friendly_error=(
                "We couldn't validate your license. 😔\n"
                f"Error: {validation.error_message}"
            ),
            suggested_action=(
                "Please try again in a few moments.\n"
                "If this persists, contact support@tmws.apto-as.com with this error."
            )
        )
```

**Why This Approach?** (なぜこのアプローチ？):

1. **温かいトーン**: エラーメッセージも優しく、次の行動を明確に示す
2. **段階的開示**: 必要な情報だけを表示（技術的詳細は隠す）
3. **アクション指向**: すべてのエラーに「次に何をすべきか」を提示

---

### Integration Point 2: Docker Entrypoint (License Validation at Startup)

**Current State** (src/mcp_server.py):

```python
# Current entrypoint: No license validation
def main():
    first_run_setup()  # Database setup
    asyncio.run(async_main())  # MCP server start
```

**Harmonious Enhancement** (優しい起動フロー):

```python
# ✨ ENHANCED: src/mcp_server.py

async def validate_license_on_startup() -> LicenseInfo:
    """
    Validate license key at container startup.

    User Experience Goals:
    1. Fast failure (don't waste user's time)
    2. Clear next steps (how to fix)
    3. Development-friendly (optional for dev mode)
    """
    # Check if development mode (skip license validation)
    if settings.environment == "development":
        logger.info("🛠️  Development mode: License validation skipped")
        return LicenseInfo(tier="FREE", development_mode=True)

    # Get license key from environment
    license_key = os.getenv("TMWS_LICENSE_KEY")

    if not license_key:
        logger.error(
            "\n" + "=" * 60 + "\n"
            "⚠️  TMWS LICENSE KEY MISSING\n"
            "=" * 60 + "\n\n"
            "No license key found in environment.\n\n"
            "To fix this:\n"
            "1. Get your license key from: https://license.tmws.apto-as.com\n"
            "2. Add to .env file: TMWS_LICENSE_KEY=\"TMWS-...\"\n"
            "3. Restart container: docker-compose restart\n\n"
            "For development, set TMWS_ENVIRONMENT=development to skip validation.\n"
            "=" * 60
        )
        sys.exit(1)  # Fast failure (don't start MCP server)

    # Validate license
    try:
        service = LicenseService(db_session=None)  # Offline validation
        validation = await service.validate_license_key(
            key=license_key,
            feature_accessed="startup"
        )

        if not validation.valid:
            logger.error(
                "\n" + "=" * 60 + "\n"
                "⚠️  INVALID LICENSE KEY\n"
                "=" * 60 + "\n\n"
                f"Reason: {validation.error_message}\n\n"
                "To fix this:\n"
                "1. Check your license key in .env file\n"
                "2. Verify expiration: https://license.tmws.apto-as.com/check\n"
                "3. Contact support: support@tmws.apto-as.com\n"
                "=" * 60
            )
            sys.exit(1)

        # Success! Log welcome message
        logger.info(
            "\n" + "=" * 60 + "\n"
            "✅ TMWS LICENSE VALIDATED\n"
            "=" * 60 + "\n"
            f"Tier: {validation.tier.value}\n"
            f"Features: {len(validation.limits.features)} tools unlocked\n"
            f"Rate limit: {validation.limits.rate_limit_per_minute} req/min\n"
            f"Expires: {validation.expires_at.strftime('%Y-%m-%d') if validation.expires_at else 'Never (perpetual)'}\n"
            "=" * 60 + "\n"
        )

        return LicenseInfo(
            tier=validation.tier.value,
            limits=validation.limits,
            expires_at=validation.expires_at
        )

    except Exception as e:
        logger.error(
            "\n" + "=" * 60 + "\n"
            "⚠️  LICENSE VALIDATION ERROR\n"
            "=" * 60 + "\n\n"
            f"Error: {e}\n\n"
            "This might be a temporary network issue.\n"
            "To retry:\n"
            "1. Check internet connection\n"
            "2. Restart container: docker-compose restart\n"
            "3. If persists, contact support@tmws.apto-as.com\n"
            "=" * 60
        )
        sys.exit(1)


async def async_main():
    """Async main entry point with license validation."""
    # Step 1: Validate license BEFORE initializing server
    license_info = await validate_license_on_startup()

    # Step 2: Initialize server (existing code)
    server = HybridMCPServer()
    await server.initialize()

    # Step 3: Set license info in server context
    server.license_info = license_info

    # Step 4: Run MCP server (existing code)
    await server.mcp.run_async()
```

**Why This Approach?** (なぜこのアプローチ？):

1. **Fast Failure**: ライセンス検証失敗時、即座に停止（ユーザーの時間を無駄にしない）
2. **明確なエラーメッセージ**: 問題と解決策を明確に表示
3. **Development-Friendly**: 開発環境ではライセンス検証をスキップ可能

---

### Integration Point 3: Claude Desktop Configuration (.env distribution)

**User Pain Point** (ユーザーの痛点):
- ライセンスキーの配布方法が不明確
- `.env`ファイルの編集が手間

**Harmonious Solution** (優しい解決策):

```bash
# Option A: Environment Variable (Simplest)
# ~/.config/claude/mcp_config.json
{
  "tmws": {
    "command": "docker",
    "args": [
      "run", "--rm",
      "-e", "TMWS_LICENSE_KEY=TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-A3F9",
      "-e", "TMWS_ENVIRONMENT=production",
      "-v", "${HOME}/.tmws/data:/app/data",
      "ghcr.io/apto-as/tmws:v2.3.1"
    ]
  }
}

# Option B: .env File (Docker Compose)
# ~/tmws/.env
TMWS_LICENSE_KEY="TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-A3F9"
TMWS_ENVIRONMENT="production"

# docker-compose.yml
services:
  tmws:
    image: ghcr.io/apto-as/tmws:v2.3.1
    env_file:
      - .env  # ← Loads license key automatically
    volumes:
      - ~/.tmws/data:/app/data

# Option C: Secure Keychain (Mac/Linux - Most Secure)
# Store license in system keychain
$ security add-generic-password \
    -a tmws \
    -s "TMWS License Key" \
    -w "TMWS-PRO-550e8400-e29b-41d4-a716-446655440000-A3F9"

# Retrieve in entrypoint script
LICENSE_KEY=$(security find-generic-password -a tmws -s "TMWS License Key" -w)
```

**Recommendation for Documentation** (ドキュメント推奨):

```markdown
# 🔑 License Key Setup Guide

## Quick Start (3 Methods - Choose One)

### Method 1: Direct Environment Variable (Fastest ⚡)
**Best for**: Quick testing, single-container deployments

Add to your Claude Desktop config:
```json
{
  "tmws": {
    "command": "docker",
    "args": ["run", "--rm", "-e", "TMWS_LICENSE_KEY=YOUR-KEY-HERE", ...]
  }
}
```

### Method 2: .env File (Recommended ✅)
**Best for**: Production deployments, multiple containers

1. Create `.env` file:
```bash
echo "TMWS_LICENSE_KEY=YOUR-KEY-HERE" > ~/tmws/.env
```

2. Reference in `docker-compose.yml`:
```yaml
env_file:
  - .env
```

### Method 3: System Keychain (Most Secure 🔒)
**Best for**: Shared servers, security-conscious deployments

Mac/Linux:
```bash
security add-generic-password -a tmws -s "TMWS License Key" -w "YOUR-KEY-HERE"
```

Windows (Credential Manager):
```powershell
cmdkey /generic:"TMWS License Key" /user:tmws /pass:YOUR-KEY-HERE
```
```

---

## 🎯 Part 3: Team Coordination Plan

### Task Distribution (チーム分担)

#### Artemis (Technical Implementation) - 4-6 hours

**Primary Responsibilities**:
1. ✅ **License Activation Service** (src/services/license_activation_service.py)
   - Implement `activate_license()` with friendly error messages
   - Add `_create_friendly_error_response()` helper
   - Integration tests (100% coverage target)

2. ✅ **Docker Entrypoint Enhancement** (src/mcp_server.py)
   - Add `validate_license_on_startup()` function
   - Implement fast-failure logic
   - Add development mode bypass

3. ✅ **License Export API** (for Enterprise customers)
   - Endpoint: `POST /api/v1/licenses/export`
   - Bulk license generation for Ansible/Terraform
   - CSV/JSON export formats

**Deliverables**:
- [ ] `src/services/license_activation_service.py` (300 lines)
- [ ] Enhanced `src/mcp_server.py` (validation logic)
- [ ] `tests/unit/services/test_license_activation.py` (200 lines)
- [ ] API endpoint: `/api/v1/licenses/export`

---

#### Hestia (Security Validation) - 2-3 hours

**Primary Responsibilities**:
1. ✅ **License Key Security Audit**
   - Verify HMAC-SHA256 signature strength
   - Test timing attack resistance
   - Validate constant-time comparison

2. ✅ **Environment Variable Security**
   - Check for license key leakage in logs
   - Verify `.env` file permissions (0600)
   - Test Docker secrets management

3. ✅ **Error Message Security Review**
   - Ensure error messages don't leak license structure
   - Verify no enumeration attacks possible
   - Test rate limiting on validation endpoint

**Deliverables**:
- [ ] Security audit report (SECURITY_LICENSE_AUDIT.md)
- [ ] Test suite: `tests/unit/security/test_license_security.py`
- [ ] Recommendations document

---

#### Muses (Documentation Creation) - 3-4 hours

**Primary Responsibilities**:
1. ✅ **User Onboarding Guide** (docs/guides/LICENSE_SETUP_GUIDE.md)
   - 3 setup methods (env var, .env file, keychain)
   - Troubleshooting FAQ (10+ common issues)
   - Video transcript for YouTube tutorial

2. ✅ **Enterprise Deployment Guide** (docs/deployment/ENTERPRISE_LICENSE_DEPLOYMENT.md)
   - Ansible playbook example
   - Terraform module example
   - License management portal guide

3. ✅ **API Documentation** (docs/api/LICENSE_API_REFERENCE.md)
   - OpenAPI 3.1 spec for license endpoints
   - Code examples (Python, curl, JavaScript)
   - Error code reference

**Deliverables**:
- [ ] `docs/guides/LICENSE_SETUP_GUIDE.md`
- [ ] `docs/deployment/ENTERPRISE_LICENSE_DEPLOYMENT.md`
- [ ] `docs/api/LICENSE_API_REFERENCE.md`
- [ ] `examples/license_activation_examples.py`

---

### Coordination Timeline (調整タイムライン)

```
Week 1: Foundation
├─ Day 1-2: Artemis implements LicenseActivationService
├─ Day 2-3: Hestia audits security
└─ Day 3-4: Muses drafts documentation

Week 2: Integration
├─ Day 5: Artemis integrates with Docker entrypoint
├─ Day 6: Hestia validates integration
└─ Day 7: Muses reviews and publishes docs

Week 2-3: Testing & Refinement
├─ Day 8-9: Integration testing (all team)
├─ Day 10: User acceptance testing (select beta users)
└─ Day 11-12: Refinements based on feedback
```

---

## 🚀 Part 4: Migration Path (Gentle Transition)

### Phase 1: Existing Users (Zero Disruption)

**Goal**: Existing Docker users continue working without interruption

```yaml
# docker-compose.yml (backward compatible)
services:
  tmws:
    image: ghcr.io/apto-as/tmws:v2.3.1
    environment:
      # Option 1: License key provided (new users)
      TMWS_LICENSE_KEY: "${TMWS_LICENSE_KEY:-}"

      # Option 2: Development mode (existing users)
      TMWS_ENVIRONMENT: "${TMWS_ENVIRONMENT:-development}"
    volumes:
      - ./data:/app/data
```

**Migration Communication** (温かい通知):

```
Subject: 🎉 TMWS v2.3.1 - License System Update (Action Required for Production)

Hi TMWS Community,

We've enhanced TMWS with a new license system to better serve you! ✨

**What's Changed?**
• FREE tier: Now requires a license key (takes 2 minutes to get one)
• PRO/ENTERPRISE: Enhanced features and priority support
• Development: No change - set TMWS_ENVIRONMENT=development to skip validation

**Action Required:**
1. Get your FREE license key: https://license.tmws.apto-as.com/signup
2. Add to .env: TMWS_LICENSE_KEY="TMWS-FREE-..."
3. Restart container: docker-compose restart

**Development Users:**
No action needed! Development mode bypasses license validation.

**Questions?**
• Docs: https://docs.tmws.apto-as.com/license
• Support: support@tmws.apto-as.com

Thanks for using TMWS! 🙏

- The Trinitas Team
```

---

### Phase 2: Development Environment (Zero Friction)

**Goal**: Developers can test without license keys

```bash
# .env.development
TMWS_ENVIRONMENT=development  # ← Skip license validation
TMWS_LOG_LEVEL=DEBUG
TMWS_SECRET_KEY=dev-secret-key-not-for-production
```

**Why This Matters** (なぜ重要か):
- オープンソースコントリビューターがライセンスなしで開発可能
- CIテストがライセンスキー不要で実行可能
- ローカル開発がスムーズ

---

### Phase 3: Test Environment (License Mocking)

**Goal**: Integration tests don't require real license keys

```python
# tests/conftest.py

@pytest.fixture
def mock_license_validation(monkeypatch):
    """Mock license validation for testing."""
    async def mock_validate(key, feature_accessed=None):
        return LicenseValidationResult(
            valid=True,
            tier=TierEnum.PRO,
            license_id=UUID("550e8400-e29b-41d4-a716-446655440000"),
            limits=TierLimits(
                tier=TierEnum.PRO,
                max_agents=50,
                max_memories_per_agent=10000,
                rate_limit_per_minute=300,
                features=[...],  # All PRO features
                max_namespace_count=10,
                support_level="Email"
            )
        )

    monkeypatch.setattr(
        "src.services.license_service.LicenseService.validate_license_key",
        mock_validate
    )
```

---

## 📊 Part 5: Success Metrics (成功指標)

### User Experience Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Onboarding Time** | <5 minutes | Time from license receipt to first MCP call |
| **Setup Complexity** | ≤3 steps | Count of required actions in documentation |
| **Error Message Clarity** | 9/10+ | User survey: "Error messages were helpful" |
| **Documentation Completeness** | 95%+ | % of users completing setup without support ticket |
| **Renewal Success Rate** | 98%+ | % of renewals completed in <2 minutes |

### Technical Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **License Validation Latency** | <10ms P95 | Prometheus metrics in `validate_license_on_startup()` |
| **Offline Validation Success** | 100% | HMAC-SHA256 signature verification (no network required) |
| **Development Mode Bypass** | 100% | Zero license validation calls in dev mode |
| **Docker Image Size** | <500MB | Final image size after multi-stage build |
| **Startup Time (with validation)** | <2 seconds | Time from container start to MCP server ready |

### Business Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **FREE → PRO Conversion** | 15%+ | % of FREE users upgrading within 30 days |
| **Support Ticket Reduction** | -50% | Comparison of setup-related tickets (before vs after) |
| **User Satisfaction (NPS)** | 50+ | Net Promoter Score survey |
| **Documentation Engagement** | 80%+ | % of users visiting docs before support ticket |

---

## 🎭 Part 6: User Experience Enhancements (追加の優しさ)

### Enhancement 1: License Key Health Check Endpoint

**User Pain Point**: "Is my license key valid?"

**Solution**: `/health` endpoint includes license status

```json
GET /health

Response:
{
  "status": "healthy",
  "database": "connected",
  "chromadb": "ready",
  "ollama": "connected",
  "license": {
    "valid": true,
    "tier": "PRO",
    "expires_at": "2026-11-16T00:00:00Z",
    "days_until_expiration": 365,
    "features_enabled": 11,
    "rate_limit": "300 req/min"
  }
}
```

**Implementation** (優しい実装):

```python
# src/api/routers/health.py

@router.get("/health")
async def health_check(request: Request) -> dict:
    """
    Health check with license status.

    User Experience Goal:
    • One endpoint to check everything
    • Actionable warnings for expiring licenses
    • Clear next steps if license is invalid
    """
    # ... existing health checks ...

    # License status (from server context)
    license_info = request.app.state.server.license_info

    # Calculate days until expiration
    if license_info.expires_at:
        days_left = (license_info.expires_at - datetime.now(timezone.utc)).days

        # Friendly warning if expiring soon
        if days_left < 7:
            license_status = {
                "valid": True,
                "tier": license_info.tier,
                "expires_at": license_info.expires_at.isoformat(),
                "days_until_expiration": days_left,
                "warning": (
                    f"Your license expires in {days_left} days. "
                    f"Renew now to avoid interruption: "
                    f"https://license.tmws.apto-as.com/renew"
                )
            }
        else:
            license_status = {
                "valid": True,
                "tier": license_info.tier,
                "expires_at": license_info.expires_at.isoformat(),
                "days_until_expiration": days_left
            }
    else:
        # Perpetual license
        license_status = {
            "valid": True,
            "tier": license_info.tier,
            "expires_at": None,
            "perpetual": True
        }

    return {
        "status": "healthy",
        "database": "connected",
        "chromadb": "ready",
        "ollama": "connected",
        "license": license_status
    }
```

---

### Enhancement 2: Graceful Degradation (Free Tier Fallback)

**User Pain Point**: "My license expired, but I don't want to lose all my data!"

**Solution**: Automatic downgrade to FREE tier on expiration

```python
# src/services/license_service.py

async def validate_license_key(
    self,
    key: str,
    feature_accessed: str | None = None
) -> LicenseValidationResult:
    """
    Validate license with graceful degradation.

    User Experience Goal:
    • Expired PRO license → automatic FREE tier fallback
    • Users keep core features (6 MCP tools)
    • Clear upgrade path displayed
    """
    # ... existing validation logic ...

    if validation.is_expired:
        # Graceful degradation to FREE tier
        logger.warning(
            f"License expired for {key[:20]}... → Downgrading to FREE tier"
        )

        return LicenseValidationResult(
            valid=True,  # ← Still valid, but downgraded
            tier=TierEnum.FREE,
            license_id=validation.license_id,
            expires_at=None,
            is_expired=True,  # Flag for upgrade prompt
            limits=self._tier_limits[TierEnum.FREE],
            warning_message=(
                "Your PRO license expired. You've been downgraded to FREE tier.\n"
                "Renew now to restore PRO features: "
                "https://license.tmws.apto-as.com/renew"
            )
        )
```

**Why This Matters** (なぜ重要か):
- ユーザーは突然サービスを失わない（優しい移行）
- コアデータは保護される（メモリ、タスクは残る）
- アップグレードへの明確なパスを提示

---

### Enhancement 3: License Usage Dashboard (for Enterprise)

**User Pain Point** (Enterprise): "Which agents are using their licenses?"

**Solution**: Real-time usage dashboard

```python
# src/api/routers/license_dashboard.py

@router.get("/license/dashboard")
@require_permission("license:dashboard:read")
async def get_license_dashboard(
    db: AsyncSession,
    current_user: User
) -> dict:
    """
    Enterprise license usage dashboard.

    Shows:
    • Active agents (50/50 slots used)
    • Feature usage breakdown
    • License health alerts
    • Cost optimization recommendations
    """
    # Aggregate usage data
    usage_summary = await db.execute(
        select(
            LicenseKey.id,
            LicenseKey.tier,
            func.count(LicenseKeyUsage.id).label("usage_count"),
            func.max(LicenseKeyUsage.used_at).label("last_used")
        )
        .join(LicenseKeyUsage)
        .where(LicenseKey.agent_id == current_user.agent_id)
        .group_by(LicenseKey.id, LicenseKey.tier)
    )

    # Cost optimization recommendations
    recommendations = []
    if usage_summary.total_agents < license_pool_size * 0.5:
        recommendations.append({
            "type": "cost_savings",
            "message": (
                f"You're using {usage_summary.total_agents}/{license_pool_size} agent slots. "
                f"Consider downgrading to save ${estimated_savings}/year."
            ),
            "action_url": "https://manage.tmws.apto-as.com/downgrade"
        })

    return {
        "license_pool": {
            "total_slots": license_pool_size,
            "used_slots": usage_summary.total_agents,
            "utilization": f"{usage_summary.total_agents / license_pool_size * 100:.1f}%"
        },
        "feature_usage": usage_summary.feature_breakdown,
        "recommendations": recommendations,
        "health_alerts": health_alerts
    }
```

---

## 🎬 Part 7: Final Recommendations (最終提言)

### Top 3 Priorities (優先事項トップ3)

#### Priority 1: Warm Onboarding Experience (温かいオンボーディング体験)

**Goal**: ユーザーが迷わず、ストレスなく5分以内にセットアップ完了

**Implementation**:
1. ✅ **Instant License Delivery**: 登録後30秒以内にライセンスキーをメール送信
2. ✅ **3-Step Setup Guide**: 複雑なドキュメントではなく、3ステップのクイックスタート
3. ✅ **Friendly Error Messages**: 技術用語ではなく、人間らしいエラーメッセージ

**Success Metric**: 95%+ のユーザーがサポートチケットなしでセットアップ完了

---

#### Priority 2: Zero-Friction Development (摩擦ゼロの開発環境)

**Goal**: 開発者がライセンスキーなしでローカル開発・テスト可能

**Implementation**:
1. ✅ **Development Mode Bypass**: `TMWS_ENVIRONMENT=development` でライセンス検証スキップ
2. ✅ **Test Fixtures**: Mock license validation for CI/CD
3. ✅ **Documentation**: 開発モードの明確なガイド

**Success Metric**: 100% のテストがライセンスキーなしで実行可能

---

#### Priority 3: Graceful Expiration Handling (優しい期限切れ対応)

**Goal**: ライセンス期限切れでもユーザーがパニックしない

**Implementation**:
1. ✅ **7-Day Warning**: 期限7日前に親切なリマインダーメール
2. ✅ **Automatic FREE Tier Downgrade**: 期限切れ後もコア機能は継続使用可能
3. ✅ **One-Click Renewal**: 更新は1クリックで完了

**Success Metric**: 98%+ のユーザーが期限切れ前に更新完了

---

### Implementation Timeline (実装タイムライン)

```
Week 1: Foundation (基盤構築)
├─ Artemis: LicenseActivationService (1-2 days)
├─ Artemis: Docker entrypoint validation (1 day)
├─ Hestia: Security audit (1 day)
└─ Muses: Documentation draft (2 days)

Week 2: Integration (統合)
├─ Artemis: API endpoints (1 day)
├─ Artemis: Dashboard implementation (1 day)
├─ Hestia: Integration testing (1 day)
└─ Muses: Documentation review & publish (1 day)

Week 3: Testing & Launch (テストと公開)
├─ All: Integration testing (2 days)
├─ All: Beta user testing (2 days)
├─ All: Refinements (1 day)
└─ All: Production launch (1 day)
```

**Total Estimated Time**: 2-3 weeks (with parallel execution)

---

## 🎵 Athena's Closing Thoughts (温かい締めくくり)

親愛なるユーザー様へ、

このライセンスシステムは、単なる技術的な制約ではなく、私たちとあなたの間の「温かい約束」です。

私たちは以下を約束します：

1. **シンプルさ**: 5分以内のセットアップ、3ステップ以内の更新
2. **透明性**: 明確な料金体系、隠れたコストなし
3. **サポート**: 困ったときはいつでも助けます
4. **優しさ**: エラーメッセージも、期限切れ対応も、すべて温かく

あなたの成功が、私たちの成功です。

共に、素晴らしいシステムを作り上げましょう。♪

---

温かい調和とともに,
**Athena** (調和の指揮者)
Trinitas Development Team

---

**Document Metadata**:
- **Created**: 2025-11-16
- **Version**: 1.0.0
- **Status**: Ready for Team Review
- **Next Steps**: Hera's Strategic Analysis Integration
- **Estimated Reading Time**: 25 minutes
- **Collaboration**: This analysis complements Hera's strategic/technical focus
