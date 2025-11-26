# Progressive Disclosure v2.0 - Technical Specification

**Author**: Artemis (Technical Perfectionist)
**Date**: 2025-11-24
**Version**: 2.0
**Status**: Design Document

---

## Executive Summary

Progressive Disclosure v2.0 introduces a **5-tier license system** with token-based budget enforcement and expiration management. This specification provides complete implementation details, token consumption analysis, and deployment procedures.

**Key Changes from v1.0**:
- 5 tiers (was 4): FREE, PRO, ENTERPRISE, ADMINISTRATOR
- Token budget: 1M/5M/unlimited/unlimited
- Expiration: Required for FREE/PRO/ENTERPRISE, optional for ADMINISTRATOR
- DoS protection: 1M req/min for ENTERPRISE, none for ADMINISTRATOR

---

## 1. Token Consumption Analysis

### 1.1 Embedding Model

**Model**: `zylonai/multilingual-e5-large`
**Dimensions**: 1024
**Size**: 4,096 bytes (1,024 tokens per embedding)

### 1.2 Operation Token Costs

| Operation | Content Tokens | Embedding Tokens | Metadata Tokens | **Total** |
|-----------|----------------|------------------|-----------------|-----------|
| `create_memory` (short, 200 chars) | 50 | 1,024 | 75 | **1,149** |
| `create_memory` (medium, 1000 chars) | 250 | 1,024 | 75 | **1,349** |
| `create_memory` (long, 5000 chars) | 1,250 | 1,024 | 75 | **2,349** |
| `search_memories` (query) | 12 | 1,024 | 25 | **1,061** |
| `search_memories` (results, 10 items) | 500 | 0 | 250 | **750** |
| `get_memory` | 125 | 0 | 75 | **200** |
| `create_pattern` | 200 | 1,024 | 100 | **1,324** |
| `propagate_pattern` | 75 | 0 | 50 | **125** |
| `create_task` | 100 | 0 | 75 | **175** |
| `execute_workflow` | 250 | 0 | 125 | **375** |

### 1.3 Hourly Usage Scenarios

#### Scenario 1: Active Development (FREE tier sufficient)
```
Operations (1 hour):
- create_memory (medium): 50 × 1,325 tokens = 66,250 tokens
- search_memories: 100 × 112 tokens = 11,200 tokens
- get_memory: 200 × 200 tokens = 40,000 tokens
- create_pattern: 10 × 1,300 tokens = 13,000 tokens

Total: 130,450 tokens (13.0% of FREE tier)
FREE tier remaining: 869,550 tokens
```

#### Scenario 2: Heavy Search (FREE tier sufficient)
```
Operations (1 hour):
- search_memories (query): 500 × 112 tokens = 56,000 tokens
- search_memories (results): 500 × 575 tokens = 287,500 tokens
- get_memory: 1,000 × 200 tokens = 200,000 tokens

Total: 543,500 tokens (54.4% of FREE tier)
FREE tier remaining: 456,500 tokens
```

#### Scenario 3: Bulk Ingestion (FREE tier sufficient)
```
Operations (1 hour):
- create_memory (medium): 600 × 1,325 tokens = 795,000 tokens
- create_pattern: 50 × 1,300 tokens = 65,000 tokens

Total: 860,000 tokens (86.0% of FREE tier)
FREE tier remaining: 140,000 tokens
```

### 1.4 Tier Capacity Summary

| Tier | Token Budget | Memory Creations/hr | Searches/hr | Reads/hr |
|------|--------------|---------------------|-------------|----------|
| FREE | 1,000,000 | ~750 (medium) | ~8,900 | ~5,000 |
| PRO | 5,000,000 | ~3,775 (medium) | ~44,600 | ~25,000 |
| ENTERPRISE | Unlimited | Unlimited | Unlimited | Unlimited |
| ADMINISTRATOR | Unlimited | Unlimited | Unlimited | Unlimited |

**Rate Limits** (DoS protection):
- FREE: 100 req/min (recommended)
- PRO: 500 req/min (recommended)
- ENTERPRISE: 1,000,000 req/min (hard limit)
- ADMINISTRATOR: None

---

## 2. 5-Tier License System Architecture

### 2.1 Tier Definitions

```python
from enum import Enum
from dataclasses import dataclass
from typing import Optional

class TierEnum(str, Enum):
    """License tier enumeration."""
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"
    ADMINISTRATOR = "ADMINISTRATOR"

@dataclass
class TierLimits:
    """License tier limits configuration."""
    tier: str
    max_tokens_per_hour: Optional[int]  # None = unlimited
    max_requests_per_minute: Optional[int]  # None = unlimited
    expiration_required: bool  # False = perpetual license

    # Features
    multi_agent_sharing: bool = True
    learning_patterns: bool = True
    workflow_execution: bool = True
    security_audit_logs: bool = True

    # Support
    support_level: str = "community"  # community, email, phone, dedicated
    sla_uptime: Optional[float] = None  # None, 99.9%, 99.99%
```

### 2.2 Tier Matrix

```python
TIER_MATRIX = {
    TierEnum.FREE: TierLimits(
        tier="FREE",
        max_tokens_per_hour=1_000_000,
        max_requests_per_minute=100,
        expiration_required=True,
        support_level="community",
        sla_uptime=None,
    ),
    TierEnum.PRO: TierLimits(
        tier="PRO",
        max_tokens_per_hour=5_000_000,
        max_requests_per_minute=500,
        expiration_required=True,
        support_level="email",
        sla_uptime=0.99,  # 99% uptime
    ),
    TierEnum.ENTERPRISE: TierLimits(
        tier="ENTERPRISE",
        max_tokens_per_hour=None,  # Unlimited
        max_requests_per_minute=1_000_000,  # DoS threshold
        expiration_required=True,
        support_level="phone",
        sla_uptime=0.999,  # 99.9% uptime
    ),
    TierEnum.ADMINISTRATOR: TierLimits(
        tier="ADMINISTRATOR",
        max_tokens_per_hour=None,  # Unlimited
        max_requests_per_minute=None,  # No limits
        expiration_required=False,  # Perpetual
        support_level="dedicated",
        sla_uptime=0.9999,  # 99.99% uptime
    ),
}
```

### 2.3 License Key Format

```
Format: TMWS-{TIER}-{UUID}-{EXPIRY}-{SIGNATURE}

Components:
- TMWS: Prefix (constant)
- TIER: FREE | PRO | ENTERPRISE | ADMINISTRATOR
- UUID: Unique identifier (8 chars, hex)
- EXPIRY: YYYYMMDD | PERPETUAL
- SIGNATURE: HMAC-SHA256 (8 chars, hex)

Examples:
TMWS-FREE-a1b2c3d4-20250124-1a2b3c4d
TMWS-PRO-e5f6g7h8-20250424-5e6f7g8h
TMWS-ENTERPRISE-i9j0k1l2-20260124-9i0j1k2l
TMWS-ADMINISTRATOR-m3n4o5p6-PERPETUAL-3m4n5o6p
```

### 2.4 License Generation Algorithm

```python
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta

def generate_license_key(
    tier: TierEnum,
    duration_months: Optional[int] = None,
    agent_id: str = None,
    secret_key: str = None,
) -> str:
    """Generate cryptographically secure license key.

    Args:
        tier: License tier
        duration_months: License duration (None = perpetual for ADMINISTRATOR)
        agent_id: Agent identifier for tracking
        secret_key: HMAC secret key

    Returns:
        License key string

    Example:
        >>> generate_license_key(TierEnum.PRO, duration_months=3, agent_id="my-agent")
        'TMWS-PRO-e5f6g7h8-20250424-5e6f7g8h'
    """
    # Generate unique ID
    uuid = secrets.token_hex(4)  # 8 chars

    # Calculate expiry
    if tier == TierEnum.ADMINISTRATOR and duration_months is None:
        expiry = "PERPETUAL"
    else:
        expiry_date = datetime.utcnow() + timedelta(days=30 * duration_months)
        expiry = expiry_date.strftime("%Y%m%d")

    # Generate signature
    message = f"{tier.value}-{uuid}-{expiry}-{agent_id}"
    signature = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()[:8]

    return f"TMWS-{tier.value}-{uuid}-{expiry}-{signature}"
```

---

## 3. Implementation Architecture

### 3.1 Core Components

```
src/security/
├── budget_validator.py (UPDATED - 5-tier support)
├── license_manager.py (NEW - License CRUD operations)
└── license_validator.py (NEW - Signature validation)

src/models/
├── license.py (NEW - License model)
└── agent.py (UPDATED - License FK, expiration column)

src/cli/
└── license.py (NEW - CLI management tools)

src/api/routers/
└── license.py (NEW - License API endpoints)

migrations/versions/
└── 20251124_v2_license_system.py (NEW - DB schema)
```

### 3.2 Database Schema

```sql
-- License tiers enum
CREATE TYPE license_tier AS ENUM (
    'FREE',
    'PRO',
    'ENTERPRISE',
    'ADMINISTRATOR'
);

-- License keys table
CREATE TABLE license_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_key VARCHAR(200) UNIQUE NOT NULL,
    tier license_tier NOT NULL,
    agent_id VARCHAR(255) REFERENCES agents(agent_id),

    -- Expiration
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NULL,  -- NULL = perpetual (ADMINISTRATOR only)

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    revoked_at TIMESTAMP NULL,
    revoked_reason TEXT NULL,

    -- Tracking
    last_validated_at TIMESTAMP NULL,
    validation_count INTEGER DEFAULT 0,

    -- Indexes
    INDEX idx_license_keys_agent (agent_id),
    INDEX idx_license_keys_tier (tier),
    INDEX idx_license_keys_expiry (expires_at) WHERE expires_at IS NOT NULL,
    INDEX idx_license_keys_active (is_active, expires_at)
);

-- Agent license relationship (update agents table)
ALTER TABLE agents
ADD COLUMN license_key_id UUID REFERENCES license_keys(id),
ADD COLUMN license_tier license_tier DEFAULT 'FREE',
ADD COLUMN license_expiration TIMESTAMP NULL;

-- Index for expiration checks
CREATE INDEX idx_agents_license_expiry
ON agents(license_expiration)
WHERE license_expiration IS NOT NULL;
```

### 3.3 Budget Validator (Updated)

```python
# src/security/budget_validator.py

from datetime import datetime, timedelta
from typing import Optional
from enum import Enum
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.license import License, TierEnum
from ..core.exceptions import LicenseExpiredError, BudgetExceededError

class BudgetCheckResult(str, Enum):
    """Budget check result."""
    APPROVED = "approved"
    EXCEEDED = "exceeded"
    RATE_LIMITED = "rate_limited"
    EXPIRED = "expired"

class CentralizedBudgetValidator:
    """Centralized token budget validation with 5-tier support.

    Features:
    - Token budget enforcement (FREE/PRO only)
    - Rate limiting (all tiers with different thresholds)
    - Expiration checking (FREE/PRO/ENTERPRISE)
    - ADMINISTRATOR exemption (no limits, perpetual)

    Performance: 5-8ms P95 (target: <15ms)
    """

    # Tier limits matrix
    _TIER_MATRIX = {
        TierEnum.FREE: {
            "max_tokens_per_hour": 1_000_000,
            "max_requests_per_minute": 100,
            "expiration_required": True,
        },
        TierEnum.PRO: {
            "max_tokens_per_hour": 5_000_000,
            "max_requests_per_minute": 500,
            "expiration_required": True,
        },
        TierEnum.ENTERPRISE: {
            "max_tokens_per_hour": None,  # Unlimited
            "max_requests_per_minute": 1_000_000,  # DoS threshold
            "expiration_required": True,
        },
        TierEnum.ADMINISTRATOR: {
            "max_tokens_per_hour": None,  # Unlimited
            "max_requests_per_minute": None,  # No limits
            "expiration_required": False,  # Perpetual
        },
    }

    async def check_budget(
        self,
        agent_id: str,
        operation_tokens: int,
        db: AsyncSession,
    ) -> BudgetCheckResult:
        """Check if agent has sufficient token budget.

        Logic:
        1. Fetch agent license from DB
        2. Check expiration (if required by tier)
        3. Check rate limit (if applicable)
        4. Check token budget (if applicable)
        5. Update usage counters

        Args:
            agent_id: Agent identifier
            operation_tokens: Tokens required for operation
            db: Database session

        Returns:
            BudgetCheckResult enum

        Raises:
            LicenseExpiredError: If license expired
            BudgetExceededError: If budget exceeded
        """
        # 1. Fetch license
        license = await self._get_agent_license(agent_id, db)

        # 2. Check expiration
        if self._TIER_MATRIX[license.tier]["expiration_required"]:
            if license.expires_at and datetime.utcnow() > license.expires_at:
                raise LicenseExpiredError(
                    f"License expired for agent {agent_id}",
                    details={"expires_at": license.expires_at.isoformat()},
                )

        # 3. ADMINISTRATOR exemption (skip all checks)
        if license.tier == TierEnum.ADMINISTRATOR:
            return BudgetCheckResult.APPROVED

        # 4. Check rate limit
        rate_limit = self._TIER_MATRIX[license.tier]["max_requests_per_minute"]
        current_rate = await self._get_current_request_rate(agent_id, db)

        if rate_limit and current_rate >= rate_limit:
            return BudgetCheckResult.RATE_LIMITED

        # 5. Check token budget (ENTERPRISE has no token limit)
        if license.tier == TierEnum.ENTERPRISE:
            await self._increment_usage(agent_id, operation_tokens, db)
            return BudgetCheckResult.APPROVED

        # 6. FREE/PRO: Check hourly token budget
        max_tokens = self._TIER_MATRIX[license.tier]["max_tokens_per_hour"]
        current_usage = await self._get_hourly_token_usage(agent_id, db)

        if current_usage + operation_tokens > max_tokens:
            raise BudgetExceededError(
                f"Token budget exceeded for agent {agent_id}",
                details={
                    "tier": license.tier,
                    "max_tokens": max_tokens,
                    "current_usage": current_usage,
                    "requested": operation_tokens,
                },
            )

        # 7. Approve and update
        await self._increment_usage(agent_id, operation_tokens, db)
        return BudgetCheckResult.APPROVED
```

---

## 4. CLI Management Tools

### 4.1 CLI Commands

```python
# src/cli/license.py

import click
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import async_session_maker
from ..services.license_service import LicenseService
from ..models.license import TierEnum

@click.group()
def license():
    """License management commands."""
    pass

@license.command()
@click.option("--tier", type=click.Choice(["FREE", "PRO", "ENTERPRISE", "ADMINISTRATOR"]), required=True)
@click.option("--duration", type=str, help="Duration: 1m, 3m, 6m, 12m (months)")
@click.option("--agent-id", type=str, required=True, help="Agent identifier")
@click.option("--output", type=str, default="license.key", help="Output file")
def create(tier: str, duration: str, agent_id: str, output: str):
    """Create new license key.

    Examples:
        tmws license create --tier PRO --duration 3m --agent-id my-agent
        tmws license create --tier ADMINISTRATOR --agent-id admin --output admin.key
    """
    async def _create():
        async with async_session_maker() as db:
            service = LicenseService(db)

            # Parse duration
            if tier == "ADMINISTRATOR" and not duration:
                months = None  # Perpetual
            elif duration:
                months = int(duration.rstrip('m'))
            else:
                raise click.BadParameter("Duration required for non-ADMINISTRATOR tiers")

            # Generate license
            license_key = await service.create_license(
                tier=TierEnum(tier),
                duration_months=months,
                agent_id=agent_id,
            )

            # Save to file
            with open(output, 'w') as f:
                f.write(license_key)

            click.echo(f"✅ License created: {license_key}")
            click.echo(f"   Saved to: {output}")

    import asyncio
    asyncio.run(_create())

@license.command()
@click.option("--tier", type=click.Choice(["FREE", "PRO", "ENTERPRISE", "ADMINISTRATOR"]))
@click.option("--status", type=click.Choice(["active", "expired", "revoked"]))
def list(tier: str, status: str):
    """List licenses with filters.

    Examples:
        tmws license list --tier ENTERPRISE --status active
        tmws license list --status expired
    """
    async def _list():
        async with async_session_maker() as db:
            service = LicenseService(db)
            licenses = await service.list_licenses(tier=tier, status=status)

            click.echo(f"Found {len(licenses)} licenses:")
            for lic in licenses:
                status_icon = "✅" if lic.is_active else "❌"
                expiry = lic.expires_at.strftime("%Y-%m-%d") if lic.expires_at else "PERPETUAL"
                click.echo(f"{status_icon} {lic.license_key} | {lic.tier} | Expires: {expiry}")

    import asyncio
    asyncio.run(_list())

@license.command()
@click.option("--expired", is_flag=True, help="Delete only expired licenses")
@click.confirmation_option(prompt="Are you sure you want to delete licenses?")
def cleanup(expired: bool):
    """Delete licenses (expired or all).

    Examples:
        tmws license cleanup --expired
    """
    async def _cleanup():
        async with async_session_maker() as db:
            service = LicenseService(db)
            count = await service.cleanup_licenses(expired_only=expired)
            click.echo(f"✅ Deleted {count} licenses")

    import asyncio
    asyncio.run(_cleanup())

@license.command()
@click.option("--license-key", type=str, required=True)
@click.option("--extend", type=str, required=True, help="Extension: 1m, 3m, 6m, 12m")
def renew(license_key: str, extend: str):
    """Renew/extend license expiration.

    Examples:
        tmws license renew --license-key TMWS-PRO-... --extend 6m
    """
    async def _renew():
        async with async_session_maker() as db:
            service = LicenseService(db)
            months = int(extend.rstrip('m'))

            new_expiry = await service.extend_license(license_key, months)
            click.echo(f"✅ License extended")
            click.echo(f"   New expiry: {new_expiry.strftime('%Y-%m-%d')}")

    import asyncio
    asyncio.run(_renew())

@license.command()
@click.option("--license-key", type=str, required=True)
def validate(license_key: str):
    """Validate license key signature and expiration.

    Examples:
        tmws license validate --license-key TMWS-PRO-...
    """
    async def _validate():
        async with async_session_maker() as db:
            service = LicenseService(db)
            result = await service.validate_license(license_key)

            if result["valid"]:
                click.echo(f"✅ License VALID")
                click.echo(f"   Tier: {result['tier']}")
                click.echo(f"   Expires: {result['expires_at'] or 'PERPETUAL'}")
            else:
                click.echo(f"❌ License INVALID: {result['reason']}")

    import asyncio
    asyncio.run(_validate())
```

---

## 5. Docker Deployment

### 5.1 Dockerfile Updates

```dockerfile
# Dockerfile (additions)

# Install CLI dependencies
RUN pip install click

# Create license storage directory
RUN mkdir -p /app/data/licenses

# Expose license management port (optional REST API)
EXPOSE 8001

# Volume for persistent license storage
VOLUME ["/app/data/licenses"]
```

### 5.2 docker-compose.yml Updates

```yaml
# docker-compose.yml

version: '3.8'

services:
  tmws:
    image: tmws:v2.4.0
    ports:
      - "8000:8000"  # Main API
      - "8001:8001"  # License API (optional)
    environment:
      - TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}
      - TMWS_LICENSE_STORAGE=/app/data/licenses
    volumes:
      - ./data:/app/data
      - ./data/licenses:/app/data/licenses  # Persistent license storage
    command: uvicorn src.main:app --host 0.0.0.0 --port 8000
```

### 5.3 Update Procedure

```bash
# 1. Backup current data
docker-compose exec tmws cp -r /app/data /app/data.backup

# 2. Pull new image
docker pull tmws:v2.4.0

# 3. Stop current container
docker-compose down

# 4. Run database migration
docker-compose run --rm tmws alembic upgrade head

# 5. Start new container
docker-compose up -d

# 6. Verify license system
docker-compose exec tmws tmws license list
```

---

## 6. Performance Analysis

### 6.1 Budget Validation Latency

**Current Design (4-tier)**: 5-8ms P95
**Updated Design (5-tier)**: 7-10ms P95 (target: <15ms)

**Breakdown**:
```
License fetch: 3ms (DB query)
Expiration check: 2ms (date comparison)
Rate limit check: 2ms (Redis/in-memory counter)
Token budget check: 2ms (Redis/in-memory counter)
Update counters: 1ms (Redis write)
---
Total: 10ms P95
```

### 6.2 DoS Protection Performance

**ENTERPRISE Tier** (1M req/min threshold):
```
Token budget check: SKIPPED (0ms saved)
Rate limit check: 2ms (in-memory counter)
---
Total: 5ms P95 (50% faster than FREE/PRO)
```

**ADMINISTRATOR Tier** (no limits):
```
All checks: SKIPPED
---
Total: 3ms P95 (license fetch only, 70% faster)
```

### 6.3 Scalability

**Target**:
- FREE tier: 100 concurrent agents
- PRO tier: 500 concurrent agents
- ENTERPRISE tier: 10,000 concurrent agents
- ADMINISTRATOR tier: Unlimited

**Bottleneck Analysis**:
- Database: SQLite WAL mode supports 1,000 concurrent reads
- Redis: In-memory counters support 100K+ req/sec
- License validation: Stateless (can scale horizontally)

---

## 7. Implementation Estimate

### 7.1 Files to Create/Modify

| File | Lines | Effort |
|------|-------|--------|
| `src/security/budget_validator.py` | 250 (modify) | 30 min |
| `src/models/license.py` | 100 (new) | 15 min |
| `src/services/license_service.py` | 300 (new) | 45 min |
| `src/cli/license.py` | 300 (new) | 45 min |
| `src/api/routers/license.py` | 200 (new) | 30 min |
| `migrations/versions/20251124_v2_license.py` | 100 (new) | 15 min |
| `tests/unit/security/test_budget_validation.py` | 600 (modify) | 60 min |
| `tests/unit/cli/test_license_cli.py` | 400 (new) | 45 min |
| `docs/admin/LICENSE_MANAGEMENT_GUIDE.md` | 2,000 words | 30 min |
| `docs/deployment/DOCKER_UPDATE_GUIDE.md` | 1,500 words | 20 min |

**Total Code**: ~2,250 lines
**Total Docs**: ~3,500 words
**Total Effort**: 5.5 hours

### 7.2 Implementation Timeline

```
Day 1 (4 hours):
├─ Core implementation (2.5h)
│  ├─ Budget validator update (30m)
│  ├─ License model (15m)
│  ├─ License service (45m)
│  └─ Database migration (15m)
├─ CLI tools (1h)
└─ API endpoints (30m)

Day 2 (1.5 hours):
├─ Testing (1h)
│  ├─ Budget validation tests (30m)
│  └─ CLI tests (30m)
└─ Documentation (30m)

---
Total: 5.5 hours (1.5 days)
```

---

## 8. Testing Strategy

### 8.1 Unit Tests

```python
# tests/unit/security/test_budget_validation_5tier.py

import pytest
from datetime import datetime, timedelta

from src.security.budget_validator import CentralizedBudgetValidator, BudgetCheckResult
from src.models.license import TierEnum

@pytest.mark.asyncio
async def test_free_tier_token_budget(db_session):
    """FREE tier: Enforce 1M tokens/hour budget."""
    validator = CentralizedBudgetValidator()

    # Create FREE license
    license = await create_test_license(
        tier=TierEnum.FREE,
        expires_at=datetime.utcnow() + timedelta(days=30),
    )

    # First 500K tokens: APPROVED
    result = await validator.check_budget("agent-1", 500_000, db_session)
    assert result == BudgetCheckResult.APPROVED

    # Next 400K tokens: APPROVED (total 900K)
    result = await validator.check_budget("agent-1", 400_000, db_session)
    assert result == BudgetCheckResult.APPROVED

    # Next 200K tokens: EXCEEDED (total would be 1.1M)
    with pytest.raises(BudgetExceededError):
        await validator.check_budget("agent-1", 200_000, db_session)

@pytest.mark.asyncio
async def test_enterprise_unlimited_tokens(db_session):
    """ENTERPRISE tier: No token budget, only rate limit."""
    validator = CentralizedBudgetValidator()

    license = await create_test_license(
        tier=TierEnum.ENTERPRISE,
        expires_at=datetime.utcnow() + timedelta(days=365),
    )

    # 10M tokens: APPROVED (no budget check)
    result = await validator.check_budget("agent-ent", 10_000_000, db_session)
    assert result == BudgetCheckResult.APPROVED

    # Rate limit: 1M req/min (DoS threshold)
    # Simulate 1M requests in 1 minute
    for _ in range(1_000_000):
        result = await validator.check_budget("agent-ent", 100, db_session)

    # 1,000,001st request: RATE_LIMITED
    result = await validator.check_budget("agent-ent", 100, db_session)
    assert result == BudgetCheckResult.RATE_LIMITED

@pytest.mark.asyncio
async def test_administrator_no_limits(db_session):
    """ADMINISTRATOR tier: No token budget, no rate limit, perpetual."""
    validator = CentralizedBudgetValidator()

    license = await create_test_license(
        tier=TierEnum.ADMINISTRATOR,
        expires_at=None,  # Perpetual
    )

    # 100M tokens: APPROVED (no checks)
    result = await validator.check_budget("agent-admin", 100_000_000, db_session)
    assert result == BudgetCheckResult.APPROVED

    # Simulate 10M requests: All APPROVED (no rate limit)
    for _ in range(10_000_000):
        result = await validator.check_budget("agent-admin", 1000, db_session)
        assert result == BudgetCheckResult.APPROVED

@pytest.mark.asyncio
async def test_expiration_check(db_session):
    """Expiration check for FREE/PRO/ENTERPRISE (not ADMINISTRATOR)."""
    validator = CentralizedBudgetValidator()

    # Expired PRO license
    license = await create_test_license(
        tier=TierEnum.PRO,
        expires_at=datetime.utcnow() - timedelta(days=1),  # Yesterday
    )

    # Any operation: EXPIRED error
    with pytest.raises(LicenseExpiredError):
        await validator.check_budget("agent-expired", 1000, db_session)

    # ADMINISTRATOR perpetual: Never expires
    admin_license = await create_test_license(
        tier=TierEnum.ADMINISTRATOR,
        expires_at=None,
    )

    result = await validator.check_budget("agent-admin", 1000, db_session)
    assert result == BudgetCheckResult.APPROVED  # No expiration check
```

### 8.2 Integration Tests

```python
# tests/integration/test_license_workflow.py

import pytest
from datetime import datetime, timedelta

@pytest.mark.asyncio
async def test_license_creation_to_validation_workflow(db_session):
    """End-to-end: Create → Validate → Use → Renew → Delete."""
    from src.services.license_service import LicenseService

    service = LicenseService(db_session)

    # 1. Create PRO license (3 months)
    license_key = await service.create_license(
        tier=TierEnum.PRO,
        duration_months=3,
        agent_id="test-agent",
    )

    # 2. Validate license
    result = await service.validate_license(license_key)
    assert result["valid"] == True
    assert result["tier"] == "PRO"

    # 3. Use license (token budget check)
    validator = CentralizedBudgetValidator()
    check = await validator.check_budget("test-agent", 1_000_000, db_session)
    assert check == BudgetCheckResult.APPROVED

    # 4. Renew license (extend 6 months)
    new_expiry = await service.extend_license(license_key, 6)
    assert new_expiry > datetime.utcnow() + timedelta(days=180)

    # 5. Cleanup (delete license)
    count = await service.cleanup_licenses(expired_only=False)
    assert count == 1
```

---

## 9. Migration Path

### 9.1 Existing Users (v2.3.0 → v2.4.0)

**Default Behavior**:
- All existing agents: Assigned FREE tier
- Expiration: 30 days from upgrade date
- Token budget: 1M tokens/hour

**Admin Actions Required**:
1. Identify paid users (manual review)
2. Generate PRO/ENTERPRISE licenses
3. Distribute licenses to users
4. Users activate licenses via CLI/API

### 9.2 Database Migration

```python
# migrations/versions/20251124_v2_license_migration.py

def upgrade():
    # 1. Create license_tier enum
    op.execute("""
        CREATE TYPE license_tier AS ENUM (
            'FREE', 'PRO', 'ENTERPRISE', 'ADMINISTRATOR'
        );
    """)

    # 2. Create license_keys table
    op.create_table(...)

    # 3. Add license columns to agents
    op.add_column('agents', sa.Column('license_key_id', UUID, nullable=True))
    op.add_column('agents', sa.Column('license_tier', license_tier, default='FREE'))
    op.add_column('agents', sa.Column('license_expiration', DateTime, nullable=True))

    # 4. Create default FREE licenses for existing agents
    op.execute("""
        INSERT INTO license_keys (license_key, tier, agent_id, expires_at)
        SELECT
            'TMWS-FREE-' || substring(md5(random()::text) from 1 for 8) || '-' ||
            to_char(NOW() + interval '30 days', 'YYYYMMDD') || '-' ||
            substring(md5(agent_id || secret_key) from 1 for 8),
            'FREE',
            agent_id,
            NOW() + interval '30 days'
        FROM agents;
    """)

    # 5. Link agents to licenses
    op.execute("""
        UPDATE agents a
        SET license_key_id = lk.id,
            license_tier = 'FREE',
            license_expiration = lk.expires_at
        FROM license_keys lk
        WHERE a.agent_id = lk.agent_id;
    """)
```

---

## 10. Monitoring & Alerts

### 10.1 Key Metrics

```python
# Prometheus metrics

from prometheus_client import Counter, Histogram, Gauge

# Budget checks
budget_checks_total = Counter(
    'tmws_budget_checks_total',
    'Total budget checks',
    ['tier', 'result']  # result: approved, exceeded, rate_limited, expired
)

budget_check_duration = Histogram(
    'tmws_budget_check_duration_seconds',
    'Budget check latency',
    ['tier']
)

# License usage
license_tokens_used = Counter(
    'tmws_license_tokens_used_total',
    'Total tokens consumed',
    ['tier', 'agent_id']
)

active_licenses = Gauge(
    'tmws_active_licenses',
    'Number of active licenses',
    ['tier']
)

expiring_licenses = Gauge(
    'tmws_expiring_licenses_7d',
    'Licenses expiring in next 7 days',
    ['tier']
)
```

### 10.2 Alert Rules

```yaml
# Prometheus alert rules

groups:
  - name: tmws_license_alerts
    rules:
      - alert: HighBudgetExceededRate
        expr: |
          rate(tmws_budget_checks_total{result="exceeded"}[5m]) > 10
        for: 5m
        annotations:
          summary: "High budget exceeded rate ({{ $value }}/sec)"

      - alert: LicenseExpiringIn7Days
        expr: tmws_expiring_licenses_7d > 10
        annotations:
          summary: "{{ $value }} licenses expiring in 7 days"

      - alert: UnusualTokenConsumption
        expr: |
          rate(tmws_license_tokens_used_total[1h]) > 10000000
        for: 10m
        annotations:
          summary: "Unusual token consumption ({{ $value }}/hour)"
```

---

## 11. Security Considerations

### 11.1 License Key Protection

**Storage**:
- Database: Hashed signature only (not reversible)
- Client: Full key in secure storage (e.g., env vars, secrets manager)

**Transmission**:
- HTTPS only (TLS 1.3+)
- No logging of full license keys

**Validation**:
- HMAC-SHA256 signature verification
- Expiration check on every request
- Rate limiting to prevent brute-force attacks

### 11.2 DoS Protection

**ENTERPRISE Tier**:
- Rate limit: 1M req/min (hard limit)
- Above threshold: 429 Too Many Requests
- Automatic cooldown: 60 seconds

**ADMINISTRATOR Tier**:
- No automatic rate limiting
- Manual intervention for abuse (revoke license)

---

## 12. FAQ

### Q1: What happens when FREE license expires?

**Answer**: All operations return `403 Forbidden` with error message:
```json
{
  "error": "LicenseExpiredError",
  "message": "License expired for agent test-agent",
  "details": {
    "expires_at": "2025-01-24T12:00:00Z",
    "tier": "FREE"
  },
  "action_required": "Renew license or upgrade to PRO/ENTERPRISE"
}
```

### Q2: Can ENTERPRISE users have perpetual licenses?

**Answer**: No, only ADMINISTRATOR tier supports perpetual licenses. ENTERPRISE requires annual renewal (12-month duration recommended).

### Q3: How to migrate from FREE to PRO?

**Answer**:
1. Generate new PRO license: `tmws license create --tier PRO --duration 12m --agent-id <agent_id>`
2. Activate new license: `tmws license activate <license_key>`
3. Old FREE license is automatically revoked

### Q4: What's the difference between ENTERPRISE and ADMINISTRATOR?

**Answer**:

| Feature | ENTERPRISE | ADMINISTRATOR |
|---------|------------|---------------|
| Token budget | Unlimited | Unlimited |
| Rate limit | 1M req/min (DoS) | None |
| Expiration | Required (annual) | Perpetual |
| Support | Phone (99.9% SLA) | Dedicated (99.99% SLA) |
| Use case | Production deployments | System admins, internal tools |

---

## 13. References

### External Documentation
- ChromaDB Performance: https://docs.trychroma.com/performance
- SQLite WAL Mode: https://www.sqlite.org/wal.html
- HMAC Security: https://tools.ietf.org/html/rfc2104

### Internal Documentation
- Budget Validator v1.0: `docs/architecture/BUDGET_VALIDATOR_SPEC.md`
- License Service API: `docs/api/LICENSE_SERVICE_API.md`
- CLI Reference: `docs/cli/LICENSE_COMMANDS.md`

---

**End of Technical Specification**

*This document provides complete implementation details for Progressive Disclosure v2.0 with 5-tier license system.*
