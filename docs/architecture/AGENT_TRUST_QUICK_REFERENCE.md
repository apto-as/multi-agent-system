# Agent Trust & Verification System - Quick Reference
## One-Page Overview for Implementation

**Full Design**: [AGENT_TRUST_VERIFICATION_ARCHITECTURE.md](./AGENT_TRUST_VERIFICATION_ARCHITECTURE.md)

---

## Core Concept

**Track agent trustworthiness through verification of claims against actual measurements**

```
Claim → Measurement → Comparison → Evidence Storage → Trust Update → Peer Review (if <0.8)
```

---

## Data Storage (No New Tables)

### 1. Agent.metadata_json["trust_data"]
```python
{
    "score": 0.95,  # float, 0.0-1.0
    "last_updated": "2025-10-27T10:30:00Z",
    "verification_count": 42,
    "false_report_count": 1,
    "peer_review_required": False,
    "history": [...],  # Last 10 events
    "peer_reviews": [...]
}
```

### 2. Memory with tags (Evidence)
```python
tags = [
    "evidence:verification",
    "agent:hera",
    "incident:2025-10-24",
    "accuracy:0.0",
    "category:false_report"
]
access_level = AccessLevel.SYSTEM  # Immutable
```

### 3. LearningPattern (Incident Patterns)
```python
category = "false_report"
namespace = "system"
access_level = "public"
pattern_data = {
    "agent": "hera",
    "claim_type": "test_results",
    "prevention": [...]
}
```

---

## API Surface

### AgentService (3 new methods)
```python
# Get trust data (owner sees all, others see summary)
await agent_service.get_trust_data(agent_id) → dict

# Update trust score (SYSTEM only)
await agent_service.update_trust_score(
    agent_id, accuracy, evidence_id, reason
) → dict

# Record peer review
await agent_service.record_peer_review(
    agent_id, reviewer_agent_id, approved, comments
) → dict
```

### MemoryService (2 new methods)
```python
# Create immutable evidence (SYSTEM only)
await memory_service.create_evidence_memory(
    agent_id, claim, measurement, accuracy
) → Memory

# Search evidence (SYSTEM/admin only)
await memory_service.search_evidence(
    agent_id, incident_date, min_accuracy, limit
) → list[Memory]
```

### WorkflowService (1 new workflow)
```python
# Standard verification workflow
await workflow_service.execute_workflow(
    "verification_standard",
    input_data={
        "agent_id": "hera",
        "report_content": "{...}",
        "evidence_path": None
    }
)
```

### MCP Tools (3 new tools)
```python
verify_agent_report(agent_id, report_content, evidence_path)
get_agent_trust_score(agent_id)
request_peer_review(agent_id, reviewer_agent_id, reason)
```

---

## Trust Score Formula

```python
penalty = 0.5 * (1 - accuracy)
new_trust = old_trust * (1 - penalty)
new_trust = round(new_trust / 0.05) * 0.05  # Round to 0.05
new_trust = clamp(new_trust, 0.0, 1.0)

# Peer review threshold: < 0.8
if new_trust < 0.8:
    require_peer_review = True
```

**Examples**:
- Perfect (1.0): No change
- Good (0.8): 10% penalty
- Medium (0.5): 25% penalty
- Failure (0.0): 50% penalty

---

## Security Controls

| Threat | Mitigation |
|--------|------------|
| Trust score manipulation | SYSTEM-only API |
| Verification bypass | Mandatory workflow |
| False evidence | SYSTEM-only creation, immutable |
| Unauthorized reads | Permission-based access |

**Key Rule**: All trust-modifying operations require `agent_id="system"`

---

## Implementation Phases

| Phase | Duration | Risk | Key Deliverables |
|-------|----------|------|------------------|
| 1. Agent Trust Tracking | Week 1 | LOW | AgentService extensions |
| 2. Evidence Storage | Week 2 | LOW | MemoryService extensions |
| 3. Verification Workflow | Week 3 | MED | WorkflowService + workflow |
| 4. Learning Patterns | Week 4 | LOW | LearningService extensions |
| 5. MCP Tools | Week 5 | LOW | User-facing tools |
| 6. Docs & Training | Week 6 | LOW | Documentation |

**Total Timeline**: 6 weeks
**Total Risk**: LOW-MEDIUM (leverages existing infrastructure)

---

## Verification Workflow Steps

```
1. Extract Claims    → Parse report for measurable claims
2. Execute Measurement → Run actual tests (if no evidence)
3. Compare Results   → Calculate accuracy
4. Store Evidence    → Create SYSTEM memory
5. Update Trust      → Apply formula
6. Check Threshold   → Require peer review if <0.8
7. Learn Pattern     → Store if accuracy <0.5
```

**Duration**: 5-30 seconds (depends on measurement)

---

## Testing Coverage

- **Unit Tests**: Trust calculations, evidence creation, pattern storage
- **Integration Tests**: Full verification workflow, evidence search
- **Security Tests**: Authorization checks, immutability
- **Performance Tests**: Latency benchmarks (<20ms for reads)

**Target**: 90%+ coverage

---

## Performance Targets (P95)

| Operation | Target | Expected |
|-----------|--------|----------|
| get_trust_data() | <20ms | 5ms |
| update_trust_score() | <50ms | 15ms |
| create_evidence_memory() | <100ms | 30ms |
| verification_workflow | <30s | 5-30s |

---

## Quick Start for Developers

### 1. Read Full Design
```bash
docs/architecture/AGENT_TRUST_VERIFICATION_ARCHITECTURE.md
```

### 2. Start with Phase 1
```bash
# Implement AgentService extensions
src/services/agent_service.py

# Add tests
tests/unit/test_agent_trust.py
tests/security/test_trust_authorization.py
```

### 3. Test Trust Score Calculation
```python
@pytest.mark.parametrize("old_score,accuracy,expected", [
    (0.95, 1.0, 0.95),
    (0.95, 0.0, 0.48),
])
async def test_trust_score(old_score, accuracy, expected):
    # ...
```

---

## Key Files to Modify

```
src/services/agent_service.py      # Phase 1: Trust tracking
src/services/memory_service.py     # Phase 2: Evidence storage
src/services/workflow_service.py   # Phase 3: Verification workflow
src/services/learning_service.py   # Phase 4: Pattern learning
src/tools/trust_tools.py           # Phase 5: MCP tools (new file)
```

---

## Common Patterns

### Pattern 1: Check Trust Before Critical Operation
```python
trust_data = await agent_service.get_trust_data(agent_id)
if trust_data["score"] < 0.8:
    # Require peer review or reject
    raise TrustTooLowError(f"Agent {agent_id} requires peer review")
```

### Pattern 2: Verify Agent Report
```python
result = await verify_agent_report(
    agent_id="hera",
    report_content='{"tests_passed": 432}',
    evidence_path=None  # Auto-execute measurement
)
# → Trust score updated automatically
```

### Pattern 3: Search Historical Incidents
```python
evidence_list = await memory_service.search_evidence(
    agent_id="hera",
    min_accuracy=0.5,  # Only false reports
    limit=10
)
```

---

## FAQ

**Q: Can agents see other agents' trust scores?**
A: Only summary (score + peer_review_required). Full data requires ownership or SYSTEM access.

**Q: Can trust scores be manually edited?**
A: No. Only SYSTEM agent can update via `update_trust_score()` with evidence.

**Q: What happens if an agent bypasses verification?**
A: Impossible. All trust updates require evidence_id (immutable SYSTEM memory).

**Q: How do agents recover from low trust?**
A: Pass peer review (+0.2), then consistent accurate reports gradually restore trust.

**Q: Is this backward compatible?**
A: Yes. JSON extension to existing models, no migration required.

---

**Status**: Design Complete - Implementation Ready
**Next Step**: Artemis implements Phase 1 (Agent Trust Tracking)
**Review Required**: Hestia (Security), Eris (Resource Planning)

---

*For detailed design, see [AGENT_TRUST_VERIFICATION_ARCHITECTURE.md](./AGENT_TRUST_VERIFICATION_ARCHITECTURE.md)*
