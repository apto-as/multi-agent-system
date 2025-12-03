# TMWS-Acontext Integration Architecture
## Harmonious Dual-Layer Design

**Author**: Athena (Harmonious Conductor)
**Date**: 2025-12-02
**Version**: 1.0.0
**Status**: Design Proposal

---

## 1. Integration Philosophy

**Core Principle**: *Cooperation over Replacement*

TMWS and Acontext are not competitors—they are complementary systems that can work in symbiosis:

- **TMWS**: Mature multi-agent coordination platform with enterprise security
- **Acontext**: Autonomous learning engine with zero-config SOP extraction

**Integration Goal**: Preserve TMWS strengths while adding Acontext's autonomous learning capabilities.

---

## 2. Dual-Layer Architecture

### 2.1 Layer 1: Request-Response (TMWS Core)

**Responsibility**: Immediate responses to MCP tool calls

```
┌─────────────────────────────────────────────────────────┐
│  MCP Client (Claude Desktop / OpenCode)                 │
│  ├─ 96 existing TMWS tools (unchanged)                  │
│  └─ 4 new acontext bridge tools                         │
└─────────────────────────────────────────────────────────┘
                          ↓ (synchronous)
┌─────────────────────────────────────────────────────────┐
│  TMWS FastAPI Backend (Python 3.11+)                    │
│  ├─ Primary: Return stored context (<20ms P95)          │
│  └─ Side-effect: Enqueue learning task → Layer 2        │
└─────────────────────────────────────────────────────────┘
```

**Characteristics**:
- Synchronous MCP response (<100ms total latency)
- No blocking on learning operations
- Graceful degradation if Layer 2 unavailable

### 2.2 Layer 2: Autonomous Learning (Acontext Engine)

**Responsibility**: Background learning and pattern discovery

```
┌─────────────────────────────────────────────────────────┐
│  Event Queue (Redis / In-Memory)                        │
│  ├─ Learning events from TMWS                           │
│  └─ Priority: LOW (non-blocking)                        │
└─────────────────────────────────────────────────────────┘
                          ↓ (asynchronous)
┌─────────────────────────────────────────────────────────┐
│  Acontext Learning Engine (Go 1.21+)                    │
│  ├─ SOP Extraction (automatic)                          │
│  ├─ Context Pattern Discovery                           │
│  ├─ Memory Graph Evolution                              │
│  └─ Write-back via TMWS REST API                        │
└─────────────────────────────────────────────────────────┘
                          ↓ (async write)
┌─────────────────────────────────────────────────────────┐
│  TMWS Database (SQLite + ChromaDB)                      │
│  ├─ New: acontext_patterns table                        │
│  ├─ New: acontext_sops table                            │
│  └─ Enhanced: memories (with auto-tags)                 │
└─────────────────────────────────────────────────────────┘
```

**Characteristics**:
- Non-blocking background processing
- Autonomous learning without user intervention
- Eventual consistency (write-back within seconds)

---

## 3. Technical Integration Patterns

### 3.1 Event-Driven Communication

**Python → Go (Event Emission)**:

```python
# src/services/acontext_bridge.py

from typing import Any
import asyncio
from redis.asyncio import Redis
import json

class AcontextBridge:
    """Non-blocking bridge to Acontext learning engine."""

    def __init__(self, redis: Redis):
        self.redis = redis
        self.channel = "tmws:acontext:events"

    async def emit_learning_event(
        self,
        event_type: str,
        agent_id: str,
        namespace: str,
        data: dict[str, Any]
    ) -> None:
        """
        Emit learning event without blocking MCP response.

        Args:
            event_type: "sop_candidate" | "context_pattern" | "memory_created"
            agent_id: Agent identifier
            namespace: Namespace for isolation
            data: Event-specific payload

        Performance: <1ms P95 (Redis PUBLISH)
        """
        event = {
            "type": event_type,
            "agent_id": agent_id,
            "namespace": namespace,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }

        try:
            # Fire-and-forget (non-blocking)
            await self.redis.publish(self.channel, json.dumps(event))
        except Exception as e:
            # Graceful degradation: log but don't block MCP
            logger.warning(f"Failed to emit acontext event: {e}")
```

**Go ← Python (Event Consumption)**:

```go
// internal/acontext/event_consumer.go

package acontext

import (
    "context"
    "encoding/json"
    "log"
    "github.com/redis/go-redis/v9"
)

type EventConsumer struct {
    redis    *redis.Client
    channel  string
    handlers map[string]EventHandler
}

type EventHandler func(ctx context.Context, event LearningEvent) error

func (ec *EventConsumer) Start(ctx context.Context) error {
    pubsub := ec.redis.Subscribe(ctx, ec.channel)
    defer pubsub.Close()

    for {
        select {
        case <-ctx.Done():
            return nil
        case msg := <-pubsub.Channel():
            // Non-blocking handler (goroutine per event)
            go ec.handleEvent(ctx, msg.Payload)
        }
    }
}

func (ec *EventConsumer) handleEvent(ctx context.Context, payload string) {
    var event LearningEvent
    if err := json.Unmarshal([]byte(payload), &event); err != nil {
        log.Printf("Failed to unmarshal event: %v", err)
        return
    }

    handler, ok := ec.handlers[event.Type]
    if !ok {
        log.Printf("No handler for event type: %s", event.Type)
        return
    }

    // Execute handler with timeout
    handlerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    if err := handler(handlerCtx, event); err != nil {
        log.Printf("Handler failed for %s: %v", event.Type, err)
    }
}
```

### 3.2 REST API Write-Back

**Go → Python (Learned Patterns)**:

```go
// internal/acontext/tmws_client.go

package acontext

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

type TMWSClient struct {
    baseURL    string
    httpClient *http.Client
    apiKey     string
}

// WriteSOPPattern writes discovered SOP back to TMWS
func (c *TMWSClient) WriteSOPPattern(ctx context.Context, pattern SOPPattern) error {
    endpoint := fmt.Sprintf("%s/api/v1/acontext/sops", c.baseURL)

    payload := map[string]interface{}{
        "namespace":   pattern.Namespace,
        "trigger":     pattern.Trigger,
        "steps":       pattern.Steps,
        "confidence":  pattern.Confidence,
        "occurrences": pattern.Occurrences,
        "metadata":    pattern.Metadata,
    }

    body, _ := json.Marshal(payload)
    req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("failed to write SOP: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated {
        return fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }

    return nil
}
```

**Python ← Go (REST Endpoint)**:

```python
# src/api/routers/acontext.py

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from src.services.acontext_service import AcontextService
from src.security.authorization import require_mcp_auth

router = APIRouter(prefix="/api/v1/acontext", tags=["acontext"])

class SOPPatternCreate(BaseModel):
    namespace: str = Field(..., min_length=1, max_length=255)
    trigger: str = Field(..., description="SOP trigger pattern")
    steps: list[str] = Field(..., min_items=1, description="SOP steps")
    confidence: float = Field(..., ge=0.0, le=1.0)
    occurrences: int = Field(..., ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

@router.post("/sops", status_code=201)
async def create_sop_pattern(
    pattern: SOPPatternCreate,
    agent_id: str = Depends(require_mcp_auth),
    service: AcontextService = Depends()
):
    """
    Store SOP pattern discovered by Acontext learning engine.

    Security:
    - REQ-1: MCP authentication required
    - REQ-2: Namespace isolation enforced
    - REQ-4: Rate limited (30 calls/min)
    """
    result = await service.store_sop_pattern(
        agent_id=agent_id,
        namespace=pattern.namespace,
        trigger=pattern.trigger,
        steps=pattern.steps,
        confidence=pattern.confidence,
        occurrences=pattern.occurrences,
        metadata=pattern.metadata
    )

    return {
        "success": True,
        "sop_id": result["sop_id"],
        "stored_at": result["stored_at"]
    }
```

### 3.3 Graceful Degradation

**Layer 2 Unavailable** (Acontext engine down):

```python
# src/services/acontext_bridge.py

async def emit_learning_event(self, event_type: str, ...) -> None:
    try:
        await self.redis.publish(self.channel, json.dumps(event))
    except redis.exceptions.ConnectionError:
        # Layer 2 unavailable - gracefully degrade
        logger.warning("Acontext engine unavailable, continuing without learning")
        # MCP response still succeeds
    except Exception as e:
        # Unexpected error - log but don't block
        logger.error(f"Acontext event emission failed: {e}", exc_info=True)
```

**Layer 1 Stress** (TMWS overloaded):

```go
// internal/acontext/event_consumer.go

func (ec *EventConsumer) handleEvent(ctx context.Context, payload string) {
    // Backpressure: If handler queue > 1000, drop event
    if len(ec.handlerQueue) > 1000 {
        log.Printf("Handler queue full, dropping event (backpressure)")
        metrics.IncrementDroppedEvents()
        return
    }

    // Process event...
}
```

---

## 4. Data Schema Changes

### 4.1 New Tables (Acontext-specific)

**Table: `acontext_sops`** (Standard Operating Procedures)

```sql
CREATE TABLE acontext_sops (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace VARCHAR(255) NOT NULL,
    agent_id VARCHAR(255) NOT NULL,

    -- SOP Definition
    trigger TEXT NOT NULL,  -- Pattern that triggers this SOP
    steps JSONB NOT NULL,   -- Array of steps
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    occurrences INTEGER NOT NULL DEFAULT 1,

    -- Lifecycle
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Indexes
    INDEX idx_acontext_sops_namespace (namespace),
    INDEX idx_acontext_sops_trigger (trigger),
    INDEX idx_acontext_sops_agent (agent_id),

    -- Constraints
    CONSTRAINT fk_acontext_sops_namespace
        FOREIGN KEY (namespace) REFERENCES namespaces(name) ON DELETE CASCADE
);
```

**Table: `acontext_patterns`** (Discovered Context Patterns)

```sql
CREATE TABLE acontext_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace VARCHAR(255) NOT NULL,

    -- Pattern Definition
    pattern_type VARCHAR(50) NOT NULL,  -- "context_injection", "proactive_search", etc.
    condition JSONB NOT NULL,           -- When to apply this pattern
    action JSONB NOT NULL,              -- What to do
    confidence FLOAT NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),

    -- Effectiveness Tracking
    applied_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    effectiveness FLOAT GENERATED ALWAYS AS (
        CASE WHEN applied_count > 0
        THEN success_count::FLOAT / applied_count
        ELSE 0.0 END
    ) STORED,

    -- Lifecycle
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_applied_at TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Indexes
    INDEX idx_acontext_patterns_namespace (namespace),
    INDEX idx_acontext_patterns_type (pattern_type),
    INDEX idx_acontext_patterns_effectiveness (effectiveness DESC),

    -- Constraints
    CONSTRAINT fk_acontext_patterns_namespace
        FOREIGN KEY (namespace) REFERENCES namespaces(name) ON DELETE CASCADE
);
```

### 4.2 Enhanced Existing Tables

**Table: `memories`** (Add auto-tagging support)

```sql
-- Add column for Acontext-discovered tags
ALTER TABLE memories
ADD COLUMN auto_tags JSONB DEFAULT '[]';

-- Index for auto-tag searches
CREATE INDEX idx_memories_auto_tags ON memories USING GIN (auto_tags);

-- Example auto_tags structure:
-- {
--   "acontext_version": "1.0.0",
--   "tags": ["api_integration", "authentication", "jwt"],
--   "confidence": 0.92,
--   "discovered_at": "2025-12-02T10:30:00Z"
-- }
```

---

## 5. New MCP Tools (4 Bridge Tools)

### 5.1 Tool: `acontext_get_sops`

**Purpose**: Retrieve SOPs for current context

```python
@tool(
    name="acontext_get_sops",
    description="Get Standard Operating Procedures discovered by Acontext for current task"
)
async def acontext_get_sops(
    trigger_pattern: str,
    namespace: str | None = None,
    min_confidence: float = 0.7,
    limit: int = 5
) -> list[dict[str, Any]]:
    """
    Retrieve relevant SOPs based on trigger pattern.

    Args:
        trigger_pattern: Current task description (used for matching)
        namespace: Filter by namespace (defaults to agent's namespace)
        min_confidence: Minimum confidence threshold (0.0-1.0)
        limit: Max SOPs to return

    Returns:
        List of matching SOPs with steps and metadata

    Example:
        # Get SOPs for JWT authentication implementation
        sops = await acontext_get_sops("implement JWT authentication")
        # Returns: [
        #   {
        #     "trigger": "JWT authentication",
        #     "steps": ["1. Install PyJWT", "2. Create token service", ...],
        #     "confidence": 0.95,
        #     "occurrences": 12
        #   }
        # ]
    """
    pass
```

### 5.2 Tool: `acontext_inject_context`

**Purpose**: Get proactive context injection for current task

```python
@tool(
    name="acontext_inject_context",
    description="Get proactive context recommendations from Acontext learning"
)
async def acontext_inject_context(
    current_task: str,
    recent_memories: list[str],
    namespace: str | None = None,
    top_k: int = 3
) -> dict[str, Any]:
    """
    Get proactive context injection based on learned patterns.

    Args:
        current_task: Current task description
        recent_memories: Recent conversation context
        namespace: Filter by namespace
        top_k: Number of context items to inject

    Returns:
        {
            "injected_context": [
                {"type": "related_memory", "content": "...", "relevance": 0.92},
                {"type": "sop", "content": "...", "relevance": 0.88},
                {"type": "pattern", "content": "...", "relevance": 0.85}
            ],
            "reasoning": "Based on similar tasks, these contexts are relevant..."
        }

    Example:
        # Get context for database migration task
        context = await acontext_inject_context(
            current_task="Create Alembic migration for new table",
            recent_memories=["Discussed PostgreSQL schema", "User requested audit log"]
        )
    """
    pass
```

### 5.3 Tool: `acontext_record_feedback`

**Purpose**: Record effectiveness of injected context

```python
@tool(
    name="acontext_record_feedback",
    description="Record whether Acontext context injection was helpful"
)
async def acontext_record_feedback(
    pattern_id: str,
    helpful: bool,
    feedback_notes: str | None = None
) -> dict[str, Any]:
    """
    Record feedback on context injection effectiveness.

    Args:
        pattern_id: UUID of applied pattern
        helpful: Whether the injected context was helpful
        feedback_notes: Optional notes on why/why not

    Returns:
        {
            "pattern_id": "...",
            "new_effectiveness": 0.87,
            "applied_count": 15,
            "success_count": 13
        }

    Example:
        # Record positive feedback
        await acontext_record_feedback(
            pattern_id="550e8400-e29b-41d4-a716-446655440000",
            helpful=True,
            feedback_notes="SOP saved 30 minutes of research"
        )
    """
    pass
```

### 5.4 Tool: `acontext_get_learning_status`

**Purpose**: Check Acontext learning engine status

```python
@tool(
    name="acontext_get_learning_status",
    description="Get status of Acontext learning engine and recent discoveries"
)
async def acontext_get_learning_status(
    namespace: str | None = None
) -> dict[str, Any]:
    """
    Get Acontext learning engine status and statistics.

    Args:
        namespace: Filter by namespace (defaults to agent's namespace)

    Returns:
        {
            "engine_status": "running" | "stopped" | "unavailable",
            "last_learning_run": "2025-12-02T10:00:00Z",
            "statistics": {
                "total_sops": 42,
                "total_patterns": 18,
                "avg_confidence": 0.87,
                "recent_discoveries": [
                    {"type": "sop", "trigger": "...", "discovered_at": "..."}
                ]
            }
        }

    Example:
        # Check learning status
        status = await acontext_get_learning_status()
        if status["engine_status"] == "unavailable":
            print("Acontext learning is currently unavailable (graceful degradation)")
    """
    pass
```

---

## 6. Performance Targets

### 6.1 Layer 1 (Request-Response)

| Operation | Target | Notes |
|-----------|--------|-------|
| MCP tool call | <100ms P95 | Existing TMWS target preserved |
| Event emission | <1ms P95 | Redis PUBLISH (fire-and-forget) |
| Graceful degradation | <5ms P95 | When Layer 2 unavailable |

### 6.2 Layer 2 (Autonomous Learning)

| Operation | Target | Notes |
|-----------|--------|-------|
| SOP extraction | <5s P95 | Background processing |
| Pattern discovery | <10s P95 | Background processing |
| Write-back to TMWS | <50ms P95 | REST API call |
| Event queue depth | <1000 | Backpressure threshold |

### 6.3 End-to-End Learning Latency

- **SOP Discovery**: Within 30 seconds of pattern occurrence
- **Context Injection**: Available within 1 minute of pattern storage
- **Effectiveness Feedback**: Reflected in confidence within 5 seconds

---

## 7. Security Integration

### 7.1 Namespace Isolation (P0-1 Compliance)

**All Acontext operations enforce namespace isolation**:

```python
# src/services/acontext_service.py

async def store_sop_pattern(
    self,
    agent_id: str,
    namespace: str,
    trigger: str,
    steps: list[str],
    confidence: float,
    occurrences: int,
    metadata: dict[str, Any]
) -> dict[str, Any]:
    """
    Store SOP pattern with P0-1 namespace verification.

    Security:
    - REQ-1: Agent authentication required
    - REQ-2: Namespace verified from database (never trust input)
    - REQ-4: Rate limited (30 calls/min)
    """
    # P0-1: Verify namespace from database
    async with self.db.begin():
        agent = await self.db.get(Agent, agent_id)
        if not agent:
            raise AgentNotFoundError(f"Agent {agent_id} not found")

        verified_namespace = agent.namespace

        # Namespace mismatch check
        if namespace != verified_namespace:
            await self.audit_logger.log_event(
                agent_id=agent_id,
                event_type="acontext_namespace_mismatch",
                severity="CRITICAL",
                message=f"Namespace mismatch: claimed={namespace}, verified={verified_namespace}"
            )
            raise NamespaceAccessDeniedError("Namespace mismatch")

        # Store SOP in verified namespace
        sop = AcontextSOP(
            namespace=verified_namespace,  # ✅ Verified
            agent_id=agent_id,
            trigger=trigger,
            steps=steps,
            confidence=confidence,
            occurrences=occurrences,
            metadata=metadata
        )

        self.db.add(sop)
        await self.db.commit()

        return {"sop_id": str(sop.id), "stored_at": sop.created_at.isoformat()}
```

### 7.2 Rate Limiting

**Acontext-specific rate limits** (separate from existing TMWS limits):

```python
# src/security/rate_limiter.py

ACONTEXT_RATE_LIMITS = {
    "production": {
        "acontext_sop_write": RateLimitConfig(
            max_requests=30,
            window_seconds=60,
            block_duration_seconds=60
        ),
        "acontext_pattern_write": RateLimitConfig(
            max_requests=30,
            window_seconds=60,
            block_duration_seconds=60
        ),
        "acontext_context_inject": RateLimitConfig(
            max_requests=60,
            window_seconds=60,
            block_duration_seconds=30
        ),
        "acontext_feedback": RateLimitConfig(
            max_requests=100,
            window_seconds=60,
            block_duration_seconds=30
        )
    },
    "development": {
        # More permissive for testing
        "acontext_sop_write": RateLimitConfig(max_requests=60, window_seconds=60),
        "acontext_pattern_write": RateLimitConfig(max_requests=60, window_seconds=60),
        "acontext_context_inject": RateLimitConfig(max_requests=120, window_seconds=60),
        "acontext_feedback": RateLimitConfig(max_requests=200, window_seconds=60)
    },
    "test": {
        # Bypassed for integration tests
        "acontext_sop_write": RateLimitConfig(max_requests=999999, window_seconds=1),
        "acontext_pattern_write": RateLimitConfig(max_requests=999999, window_seconds=1),
        "acontext_context_inject": RateLimitConfig(max_requests=999999, window_seconds=1),
        "acontext_feedback": RateLimitConfig(max_requests=999999, window_seconds=1)
    }
}
```

### 7.3 Audit Logging

**All Acontext operations logged**:

```python
# Automatic audit events
await self.audit_logger.log_event(
    agent_id=agent_id,
    event_type="acontext_sop_stored",
    severity="MEDIUM",
    namespace=namespace,
    message=f"SOP pattern stored: {trigger}",
    details={
        "sop_id": str(sop.id),
        "confidence": confidence,
        "occurrences": occurrences,
        "step_count": len(steps)
    }
)
```

---

## 8. Migration Strategy

### Phase 1: Foundation (Week 1-2)

**Goal**: Set up dual-layer infrastructure without disrupting TMWS

**Deliverables**:
1. Redis event queue setup
2. Acontext Go service skeleton
3. Database schema additions (acontext_sops, acontext_patterns)
4. Event emission in TMWS (no-op if Redis unavailable)

**Risk**: LOW (additive changes only, graceful degradation built-in)

**Testing**:
- Event emission works (Redis available)
- Graceful degradation works (Redis unavailable)
- Zero impact on existing TMWS performance

### Phase 2: Learning Engine (Week 3-4)

**Goal**: Implement Acontext learning logic

**Deliverables**:
1. Go event consumer (SOP extraction)
2. Pattern discovery algorithm
3. REST API write-back to TMWS
4. Confidence scoring mechanism

**Risk**: MEDIUM (new Go service, but isolated from TMWS core)

**Testing**:
- SOP extraction accuracy (manual validation)
- Pattern discovery correctness
- Write-back API security (P0-1 compliance)

### Phase 3: MCP Integration (Week 5-6)

**Goal**: Expose Acontext capabilities via MCP tools

**Deliverables**:
1. 4 new MCP tools (get_sops, inject_context, record_feedback, get_status)
2. Proactive context injection logic
3. Effectiveness tracking and feedback loop

**Risk**: MEDIUM (new user-facing features)

**Testing**:
- Integration tests for 4 MCP tools
- User acceptance testing (dogfooding with Trinitas agents)
- Performance validation (<100ms P95 for MCP calls)

### Phase 4: Optimization & Tuning (Week 7-8)

**Goal**: Production readiness and performance tuning

**Deliverables**:
1. Confidence threshold calibration
2. Backpressure tuning (event queue limits)
3. Monitoring and alerting setup
4. Documentation (user guide, API reference)

**Risk**: LOW (polish and optimization)

**Testing**:
- Load testing (1000 concurrent users)
- Chaos testing (Layer 2 failure scenarios)
- Performance regression suite

---

## 9. Success Metrics

### 9.1 Performance Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| MCP latency (Layer 1) | <100ms P95 | No regression from current TMWS |
| Event emission overhead | <1ms P95 | Redis PUBLISH latency |
| SOP discovery latency | <5s P95 | Background processing |
| Context injection accuracy | >80% helpful | User feedback |

### 9.2 Adoption Metrics

| Metric | Target | Timeline |
|--------|--------|----------|
| SOPs discovered | >50 | Month 1 |
| SOPs applied (user-initiated) | >100 | Month 2 |
| Context injections | >200 | Month 3 |
| Positive feedback rate | >75% | Month 3 |

### 9.3 Reliability Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| Layer 2 availability | >99% | Independent from Layer 1 |
| Graceful degradation success | 100% | Layer 1 works when Layer 2 down |
| Zero data loss | 100% | Event queue persistence |

---

## 10. Risk Analysis & Mitigation

### 10.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Redis SPOF | MEDIUM | HIGH | Use Redis Cluster or fallback to in-memory queue |
| Go-Python integration bugs | MEDIUM | MEDIUM | Extensive integration testing, contract tests |
| Layer 2 performance degradation | LOW | MEDIUM | Backpressure limits, resource monitoring |
| P0-1 compliance violation | LOW | CRITICAL | Security audit before each release |

### 10.2 Operational Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Learning engine produces low-quality SOPs | HIGH | LOW | Confidence thresholds, user feedback loop |
| Event queue overflow | MEDIUM | MEDIUM | Backpressure (drop events if queue >1000) |
| Increased infrastructure complexity | HIGH | MEDIUM | Comprehensive monitoring, runbooks |

---

## 11. Alternatives Considered

### 11.1 Option A: Replace TMWS with Acontext

**Pros**:
- Simpler architecture (single system)
- Full Acontext capabilities

**Cons**:
- ❌ Lose 96 mature MCP tools
- ❌ Lose P0-1 security model
- ❌ Lose 9 Trinitas agent personas
- ❌ High migration risk
- **Verdict**: REJECTED (too disruptive)

### 11.2 Option B: Fork Acontext into TMWS (monolith)

**Pros**:
- Single deployment unit
- No inter-process communication

**Cons**:
- ❌ Mix Python + Go in single process (complex)
- ❌ Tight coupling (hard to iterate independently)
- ❌ No graceful degradation (learning failures block MCP)
- **Verdict**: REJECTED (violates separation of concerns)

### 11.3 Option C: Dual-Layer (Proposed)

**Pros**:
- ✅ Preserve all TMWS strengths
- ✅ Add Acontext autonomy without disruption
- ✅ Graceful degradation (Layer 1 independent)
- ✅ Clear separation of concerns
- ✅ Iterative migration (low risk)

**Cons**:
- Increased infrastructure complexity (manageable)
- Two systems to maintain (but loosely coupled)

**Verdict**: ✅ **SELECTED** (optimal balance)

---

## 12. Open Questions

### 12.1 Technical Questions

1. **Event Queue Technology**:
   - Option A: Redis (proven, low latency)
   - Option B: RabbitMQ (more features, higher complexity)
   - Option C: In-memory queue (simple, but no persistence)
   - **Recommendation**: Start with Redis, fallback to in-memory if unavailable

2. **Go Service Deployment**:
   - Option A: Separate binary (systemd service)
   - Option B: Embedded in TMWS (cgo)
   - Option C: Docker Compose multi-container
   - **Recommendation**: Start with Option A (simplest), migrate to C for production

3. **SOP Confidence Calibration**:
   - How many occurrences before SOP confidence >0.7?
   - Should confidence decay over time if unused?
   - **Recommendation**: Start with 3+ occurrences, no decay (simpler)

### 12.2 Product Questions

1. **Proactive Context Injection UX**:
   - Should Acontext inject context automatically in MCP responses?
   - Or should user explicitly call `acontext_inject_context`?
   - **Recommendation**: Explicit call first (less intrusive), auto-inject in v2.0

2. **SOP Editing**:
   - Should users be able to manually edit discovered SOPs?
   - Or are SOPs read-only (learning-derived only)?
   - **Recommendation**: Read-only initially, add editing in v2.0 if needed

---

## 13. Conclusion

This Harmonious Integration design preserves TMWS's strengths while adding Acontext's autonomous learning capabilities through a **symbiotic dual-layer architecture**.

**Key Principles**:
1. **Non-blocking**: Layer 2 never blocks Layer 1 (MCP responses)
2. **Graceful Degradation**: TMWS works perfectly even if Acontext is unavailable
3. **Security-First**: All Acontext operations enforce P0-1 namespace isolation
4. **Iterative Migration**: 4-phase rollout minimizes risk

**Timeline**: 8 weeks (2 weeks per phase)

**Risk Level**: LOW-MEDIUM (managed through isolation and graceful degradation)

---

**Next Steps**:
1. Review this design with all Trinitas agents (Hera for strategy, Artemis for performance, Hestia for security)
2. Get user approval for dual-layer approach
3. Begin Phase 1 implementation (Redis + database schema)

---

*Designed with empathetic understanding of both systems' strengths.*
*Athena, Harmonious Conductor - 2025-12-02*
