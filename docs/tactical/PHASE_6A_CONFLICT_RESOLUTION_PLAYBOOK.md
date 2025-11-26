# Phase 6A: Conflict Resolution Playbook
## Tactical Coordination - Eris Protocol

**Status**: Operational
**Created**: 2025-11-25
**Owner**: Eris (Tactical Coordinator)
**Related**: PHASE_6A_TACTICAL_EXECUTION_PLAN.md

---

## Overview

This playbook defines how to detect, mediate, and resolve conflicts during Phase 6A implementation. Based on Athena's harmony analysis and Hera's risk assessment, three primary conflict scenarios have been identified.

---

## Conflict Scenario 1: Performance vs Security

### Artemis (Technical Perfectionist) vs Hestia (Security Guardian)

**Nature**: Technical trade-off conflict
**Frequency**: Expected 2-3 times during Phase 6A
**Impact**: Can block gate approval if unresolved

### Example Conflict

**Situation**: Hestia requires database query audit logging for all skill invocations to track potential command injection attempts (V-SKILL-3). Artemis warns this will cause 20% performance regression, violating P95 latency targets.

**Positions**:
- **Hestia**: "Audit logging is non-negotiable. Security > Performance. CVSS 7.8 risk."
- **Artemis**: "20% regression is unacceptable. Users will notice. Need optimization."

---

### Detection Criteria

**Automated Triggers**:
```bash
# Performance regression detected
pytest tests/performance/ -v
# Output: P95 latency 25ms (target: 20ms) ❌

# Security requirement unmet
pytest tests/security/ -v
# Output: test_audit_logging_enabled FAILED ❌
```

**Manual Triggers**:
- Code review comment by Hestia: "Audit logging missing"
- Pull request blocked by Artemis: "Performance regression"
- Gate approval delayed: Neither agent approves

---

### Mediation Process (Eris Facilitated)

#### Phase 1: Data Gathering (30 minutes)

**Eris召集会議** (synchronous, if possible; async otherwise):

1. **Artemis Presents Performance Impact**:
   ```
   Current P95: 10ms (baseline)
   With sync audit logging: 25ms (+150%)
   Target: 20ms
   Violation: +25%

   User Impact:
   - 1000 req/s → 400 req/s throughput
   - Perceived latency increase noticeable
   ```

2. **Hestia Presents Security Risk**:
   ```
   Vulnerability: V-SKILL-3 (Command Injection)
   CVSS Score: 7.8 (HIGH)
   Attack Scenario: Attacker bypasses validation, injects shell commands
   Without Audit: Cannot trace attack origin

   Compliance: PCI-DSS requires audit trail for all security-sensitive operations
   ```

3. **Eris Frames Trade-Off**:
   ```
   Competing Objectives:
   A) Security: 100% audit coverage (Hestia requirement)
   B) Performance: P95 ≤20ms (Artemis requirement)

   Current Conflict: Cannot achieve both with sync logging

   Questions for Options Evaluation:
   1. Can we reduce security scope without compromising safety?
   2. Can we optimize performance without losing audit trail?
   3. What is the acceptable trade-off zone?
   ```

---

#### Phase 2: Options Evaluation (30 minutes)

**Option A: Async Audit Logging** (Artemis Recommendation)
```python
# Non-blocking audit logging
async def invoke_skill(skill_id, params):
    # Invoke skill synchronously
    result = await _execute_skill(skill_id, params)

    # Log to async queue (non-blocking)
    await audit_queue.enqueue({
        "skill_id": skill_id,
        "params": params,
        "result": result,
        "timestamp": utcnow()
    })

    return result
```

**Pros**:
- ✅ Performance impact: <1% (25ms → 10.5ms)
- ✅ User experience preserved
- ✅ Minimal code changes

**Cons**:
- ⚠️ Audit log loss if queue overflows (rare)
- ⚠️ Delayed audit trail (up to 5 seconds)
- ⚠️ Additional complexity (queue management)

**Hestia Assessment**: "Acceptable if queue has persistence (Redis/DB-backed)"

---

**Option B: Selective Audit Logging** (Eris Recommendation)
```python
# Only log HIGH-risk operations
HIGH_RISK_SKILLS = ["shell_exec", "file_write", "network_call"]

async def invoke_skill(skill_id, params):
    result = await _execute_skill(skill_id, params)

    # Only log HIGH-risk skills
    if skill_id in HIGH_RISK_SKILLS:
        await audit_logger.log_sync({...})  # Blocking for critical ops

    return result
```

**Pros**:
- ✅ Performance impact: ~5% (most skills unaffected)
- ✅ No audit log loss for critical operations
- ✅ Simple implementation

**Cons**:
- ⚠️ Partial audit trail (only 10-20% of invocations)
- ⚠️ Compliance risk if auditors require 100% coverage
- ⚠️ Attack could target low-risk skills to evade logging

**Hestia Assessment**: "Acceptable for v1, but requires full audit in v2"

---

**Option C: Deferred Audit Logging** (Hestia Fallback)
```python
# Write to fast local buffer, flush to DB periodically
async def invoke_skill(skill_id, params):
    result = await _execute_skill(skill_id, params)

    # Write to in-memory buffer (fast)
    audit_buffer.append({...})  # <1ms

    # Background job flushes every 5 minutes
    return result
```

**Pros**:
- ✅ Performance impact: <1% (in-memory write)
- ✅ 100% audit coverage (no loss)
- ✅ Batch processing efficiency

**Cons**:
- ⚠️ Delayed audit trail (up to 5 minutes)
- ⚠️ Data loss if process crashes before flush
- ⚠️ Requires buffer size tuning

**Artemis Assessment**: "Acceptable, but need crash recovery mechanism"

---

#### Phase 3: Decision Matrix (15 minutes)

**Eris Scoring** (Weighted by Athena Harmony + Hera Strategy):

| Criteria | Weight | Option A (Async) | Option B (Selective) | Option C (Deferred) |
|----------|--------|------------------|----------------------|---------------------|
| Security Coverage | 35% | 9/10 (99%+) | 6/10 (20%) | 10/10 (100%) |
| Performance | 30% | 10/10 (<1%) | 9/10 (5%) | 10/10 (<1%) |
| Compliance | 20% | 8/10 (acceptable) | 5/10 (risky) | 9/10 (full trail) |
| Complexity | 15% | 6/10 (queue mgmt) | 9/10 (simple) | 7/10 (buffer mgmt) |
| **Total** | 100% | **8.6/10** | **6.9/10** | **9.3/10** |

**Winner**: **Option C (Deferred Audit Logging)** ✅

**Rationale**:
- Achieves both Hestia's security (100% coverage) and Artemis's performance (<1% impact)
- Acceptable trade-off: 5-minute delay in audit trail
- Mitigates crash risk with periodic flush + Write-Ahead Log (WAL)

---

#### Phase 4: Decision Authority (15 minutes)

**Decision Tree**:

```
Q1: Is security impact CRITICAL (CVSS ≥9.0)?
├─ YES → Hestia has veto power (Option must meet 100% coverage)
│         → Option C (Deferred) selected
└─ NO → Proceed to Q2

Q2: Is security impact HIGH (CVSS 7.0-8.9)?
├─ YES → Hera makes final decision (strategic risk vs. performance)
│         → Hera evaluates: Option C aligns with strategic objectives
└─ NO → Proceed to Q3

Q3: Is security impact MEDIUM (CVSS 4.0-6.9)?
├─ YES → Artemis + Hestia consensus required
│         → If no consensus: Eris mediates, Athena provides harmony score
└─ NO → Low risk, Artemis decides
```

**This Conflict** (CVSS 7.8 HIGH):
- Path: Q1=NO → Q2=YES → **Hera decides**
- Hera Decision: **Option C (Deferred)** approved
  - Reasoning: "Strategic objective V-SKILL-3 mitigated (100% audit), performance preserved (<1%), acceptable delay (5 min). Option C aligns with risk mitigation strategy."

**Consensus Check**:
- Hestia: ✅ "Approved. 100% coverage achieved."
- Artemis: ✅ "Approved. Performance target met."
- Athena: ✅ "Harmony score 9/10. Balanced solution."

---

#### Phase 5: Documentation (30 minutes)

**Architectural Decision Record (ADR)**:

File: `docs/decisions/ADR-006A-1-performance-vs-security-audit-logging.md`

```markdown
# ADR-006A-1: Deferred Audit Logging for Skill Invocations

**Date**: 2025-11-25
**Status**: Accepted
**Deciders**: Hera (final), Artemis, Hestia, Eris
**Context**: Phase 6A Gate 2 - Performance vs Security conflict

## Context
Hestia requires 100% audit logging for skill invocations (V-SKILL-3 mitigation).
Artemis warns synchronous logging causes 20% performance regression.

## Decision
Implement deferred audit logging with in-memory buffer and periodic flush.

## Consequences
- ✅ Security: 100% audit coverage
- ✅ Performance: <1% impact (target met)
- ⚠️ Audit trail delayed up to 5 minutes
- ⚠️ Requires buffer management and crash recovery

## Implementation
- `src/services/audit_buffer.py`: In-memory buffer with WAL persistence
- Background job flushes every 5 minutes
- Flush on graceful shutdown

## Alternatives Considered
- Option A (Async Queue): 99% coverage, <1% impact, queue complexity
- Option B (Selective): 20% coverage, 5% impact, compliance risk

## Review
- Hestia: Approved ✅
- Artemis: Approved ✅
- Hera: Approved ✅
```

---

### Resolution Timeline

**Total Time**: 2 hours (worst case)
- Data Gathering: 30 min
- Options Evaluation: 30 min
- Decision Matrix: 15 min
- Decision Authority: 15 min
- Documentation: 30 min

**If Unresolved**: Escalate to User after 24h

---

## Conflict Scenario 2: API Design vs Documentation

### Artemis (Technical Perfectionist) vs Muses (Knowledge Architect)

**Nature**: Naming convention and documentation conflict
**Frequency**: Expected 1-2 times during Phase 6A
**Impact**: Low (non-blocking, but affects long-term maintainability)

---

### Example Conflict

**Situation**: Artemis wants to rename `SkillTool.invocation_context` to `invoke_ctx` for brevity (19 chars → 10 chars). Muses argues this sacrifices clarity and makes documentation harder to write.

**Positions**:
- **Artemis**: "Shorter names improve code readability. Developers will use this field frequently."
- **Muses**: "Self-documenting code is better than concise code. `invoke_ctx` requires lookup."

---

### Detection Criteria

**Automated Triggers**:
```bash
# Code review tool flags naming inconsistency
ruff check src/models/skill_tool.py --select N

# Documentation generation fails due to unclear abbreviations
mkdocs build
# Warning: Abbreviation 'invoke_ctx' not in glossary
```

**Manual Triggers**:
- Pull request comment by Muses: "Please clarify abbreviation"
- Code review by Athena: "Naming inconsistent with project standards"

---

### Mediation Process (Athena Facilitated)

**Athena as Harmony Facilitator** (not Eris - this is a harmony issue, not tactical)

#### Phase 1: Perspective Gathering (15 minutes)

**Artemis Position**:
```
Current: SkillTool.invocation_context (19 chars)
Proposed: SkillTool.invoke_ctx (10 chars)

Benefits:
- 47% shorter
- Faster to type
- Common abbreviation in codebase ("ctx" used 42 times)

Example usage:
  tool.invoke_ctx["user_id"]  # vs
  tool.invocation_context["user_id"]
```

**Muses Position**:
```
Current: invocation_context (self-documenting)
Proposed: invoke_ctx (requires documentation)

Concerns:
- New developers: What is "ctx"? (Context? Control? Custom?)
- API documentation: Need to explain abbreviation in every mention
- Consistency: Other models use full words (TaskExecutionContext, WorkflowInvocationMetadata)

Example documentation:
  "The `invoke_ctx` (invocation context) contains..."
  # Must explain abbreviation every time
```

---

#### Phase 2: Athena's Harmonious Compromise (15 minutes)

**Option A: Keep `invocation_context`** (Muses)
- **Pros**: Self-documenting, consistent with codebase
- **Cons**: Verbose (19 chars)
- **Athena Score**: 7/10 (safe, but not optimal)

**Option B: Use `invoke_ctx`** (Artemis)
- **Pros**: Concise (10 chars)
- **Cons**: Requires documentation, inconsistent
- **Athena Score**: 6/10 (optimizes wrong thing)

**Option C: Compromise `context`** (Athena's Recommendation)
- **Pros**: Balance of brevity (7 chars) + clarity (universal term)
- **Cons**: Slightly less specific than `invocation_context`
- **Athena Score**: 9/10 (harmony achieved) ✨

**Rationale**:
```
"Context" is a universally understood term in software development.
It's shorter than `invocation_context` (63% reduction) but clearer than `invoke_ctx`.

Examples in the wild:
- React: `useContext()` (not `useCtx()`)
- Django: `request.context` (not `request.ctx`)
- Flask: `app_context()` (not `app_ctx()`)

Athena's Harmony Principle:
"Choose names that balance developer efficiency (brevity)
with team collaboration (clarity). When in doubt, clarity wins."
```

---

#### Phase 3: Decision Authority (Public vs Internal API)

**Decision Tree**:

```
Q1: Is this a PUBLIC API (exposed to users)?
├─ YES → Athena has final say (harmony > brevity)
│         → Choose `context` (Option C)
└─ NO → Proceed to Q2

Q2: Is this an INTERNAL API (only used by TMWS developers)?
├─ YES → Artemis has final say (performance > verbosity)
│         → Could choose `invoke_ctx` (Option B) if team agrees
└─ NO → Refer to existing codebase patterns

Q3: What do existing models use?
├─ Check: TaskExecutionContext, WorkflowInvocationMetadata
└─ Pattern: Use full words for context objects
    → Choose `context` (Option C)
```

**This Conflict** (PUBLIC API):
- Path: Q1=YES → **Athena decides**
- Athena Decision: **Option C (`context`)** approved ✅
  - Reasoning: "Public API prioritizes clarity for external developers. `context` is universally understood, brief enough, and consistent with industry standards."

**Consensus Check**:
- Muses: ✅ "Approved. Much better than abbreviation."
- Artemis: ✅ "Approved. Acceptable compromise (10 chars → 7 chars still improvement)."

---

### Resolution Timeline

**Total Time**: 30 minutes (fast track)
- Perspective Gathering: 15 min
- Athena Compromise: 10 min
- Decision: 5 min

**Documentation**: Update `docs/api/NAMING_CONVENTIONS.md`

---

## Conflict Scenario 3: VectorSearchService Performance Regression

### Technical Conflict (Artemis Internal)

**Nature**: Performance regression due to new feature
**Frequency**: Expected 1 time during Phase 6A (Wave 2)
**Impact**: HIGH (blocks Gate 2 approval)

---

### Example Conflict

**Situation**: Wave 2 introduces skill metadata indexing in ChromaDB. Performance tests fail:
- **Baseline**: P95 = 5ms (vector search only)
- **Wave 2**: P95 = 50ms (vector + metadata search)
- **Target**: P95 ≤ 20ms

**Root Cause**: Full-text search on `skill.description` field (unindexed)

---

### Detection Criteria

**Automated Triggers**:
```bash
# Performance test fails
pytest tests/performance/test_vector_search_performance.py::test_search_p95_under_20ms -v
# Output: AssertionError: 50ms > 20ms ❌

# Automated alert (if monitoring enabled)
# Alert: VectorSearchService P95 exceeded threshold (50ms > 20ms)
```

---

### Mediation Process (Artemis Solo, Eris Oversight)

#### Phase 1: Root Cause Analysis (2 hours)

**Artemis Investigation**:
```bash
# Profile ChromaDB queries
python -m cProfile -o profile.out scripts/benchmark_vector_search.py

# Analyze with snakeviz
snakeviz profile.out

# Key finding:
# 90% time spent in: collection.query(where={"description": {"$contains": "..."}})
# Reason: Full-text search on unindexed field
```

**Bottleneck Identified**:
```python
# Current implementation (slow)
results = collection.query(
    query_embeddings=embedding,
    where={"skill.description": {"$contains": keyword}},  # ❌ Unindexed
    n_results=top_k
)
```

---

#### Phase 2: Options Evaluation (1 hour)

**Option A: Add ChromaDB Index** (Artemis Primary Recommendation)
```python
# Add metadata index on 'description' field
collection.modify(
    metadata={"hnsw:space": "cosine"},
    index_metadata={"description": "text"}  # Full-text index
)
```

**Pros**:
- ✅ Latency reduction: 50ms → 10ms (-80%)
- ✅ Simple implementation (10 lines)
- ✅ No new dependencies

**Cons**:
- ⚠️ Memory cost: +5MB per 1000 skills
- ⚠️ Index rebuild time: ~30 seconds (one-time)

**Artemis Assessment**: "Best option. 5MB acceptable for 80% improvement."

---

**Option B: Cache Skill Metadata in Redis**
```python
# Cache frequently accessed skill metadata
@cache(ttl=300)  # 5 min
async def get_skill_metadata(skill_id):
    return await db.query(Skill).get(skill_id)
```

**Pros**:
- ✅ Latency reduction: 50ms → 5ms (-90%)
- ✅ Benefits other queries too

**Cons**:
- ⚠️ New dependency (Redis)
- ⚠️ Cache invalidation complexity
- ⚠️ Increased system complexity

**Artemis Assessment**: "Overkill. Adds unnecessary dependency."

---

**Option C: Lazy-Load Skill Metadata**
```python
# Fetch metadata after vector search (2-phase query)
# Phase 1: Vector search only (fast)
vector_results = collection.query(query_embeddings=embedding, n_results=top_k)

# Phase 2: Fetch metadata for top-k results (separate query)
skill_ids = [r["skill_id"] for r in vector_results]
metadata = await db.query(Skill).filter(Skill.id.in_(skill_ids)).all()
```

**Pros**:
- ✅ Latency reduction: 50ms → 2.5ms (vector only) + 5ms (metadata) = 7.5ms total (-85%)
- ✅ No ChromaDB changes
- ✅ More flexible (can filter metadata in SQL)

**Cons**:
- ⚠️ +1 additional database query
- ⚠️ More complex code (2-phase query)

**Artemis Assessment**: "Good alternative if ChromaDB index doesn't work."

---

#### Phase 3: Decision (30 minutes)

**Artemis Recommendation**: **Option A (Add ChromaDB Index)** ✅

**Rationale**:
- Simplest solution (10 lines of code)
- No new dependencies
- 80% latency reduction sufficient to meet target (10ms < 20ms)
- 5MB memory cost acceptable (current ChromaDB usage: 50MB)

**Hera Strategic Validation**:
- Cost-Benefit: 5MB for 80% improvement = excellent ROI
- Strategic Alignment: No new dependencies = reduced operational risk
- Approval: ✅ Proceed with Option A

**Eris Coordination**:
- Timeline Impact: 4h to implement + test (within Wave 2 buffer)
- Gate 2 Impact: Can still meet Day 10 deadline
- Approval: ✅ Implement immediately

---

#### Phase 4: Implementation + Verification (4 hours)

**Artemis Tasks**:
1. Add ChromaDB metadata index (1h)
   ```python
   # src/services/vector_search_service.py
   await asyncio.to_thread(
       self._collection.modify,
       index_metadata={"description": "text"}
   )
   ```

2. Update tests (1h)
   ```python
   # tests/performance/test_vector_search_performance.py
   def test_search_with_metadata_p95_under_20ms():
       p95 = benchmark(search_with_metadata, n=100)
       assert p95 < 20, f"P95 {p95}ms exceeds 20ms target"
   ```

3. Run regression suite (1h)
   ```bash
   pytest tests/performance/ -v
   pytest tests/integration/test_vector_search.py -v
   ```

4. Document performance fix (1h)
   ```markdown
   # docs/performance/WAVE_2_REGRESSION_RCA.md

   ## Root Cause
   Full-text search on unindexed `skill.description` field.

   ## Solution
   Added ChromaDB metadata index.

   ## Results
   - Before: P95 = 50ms
   - After: P95 = 10ms
   - Improvement: -80%
   ```

---

### Resolution Timeline

**Total Time**: 7.5 hours (blocking for Gate 2)
- Root Cause Analysis: 2h
- Options Evaluation: 1h
- Decision: 0.5h
- Implementation: 4h

**Gate 2 Impact**: Delays Gate 2 by 0.5 days (acceptable within 5-day wave)

---

## Conflict Escalation Matrix

### Level 1: Agent-to-Agent (2h limit)

**Scope**: Technical disagreements, naming conventions, minor trade-offs

**Process**:
1. Agents discuss directly (async or sync)
2. Eris observes, provides data/context if needed
3. Athena facilitates if harmony issue

**Success Criteria**: Consensus reached within 2h

**Examples**:
- API naming disputes (Artemis vs Muses)
- Test coverage targets (Artemis vs Hestia)
- Documentation style (Muses vs Athena)

---

### Level 2: Eris Mediation (24h limit)

**Scope**: Performance vs Security, resource allocation, technical trade-offs

**Process**:
1. Eris召集会議 (structured discussion)
2. Data gathering from both sides
3. Options evaluation with scoring matrix
4. Decision authority determined by conflict type
5. ADR documentation

**Success Criteria**: Decision documented and accepted by both agents

**Examples**:
- Performance vs Security (Artemis vs Hestia)
- Timeline vs Quality (Artemis vs Hera)
- Scope creep disputes (Hera vs Artemis)

---

### Level 3: Hera Strategic Decision (48h limit)

**Scope**: Strategic conflicts, high-impact decisions, unresolved Level 2 conflicts

**Process**:
1. Eris escalates with full context
2. Hera reviews options + strategic alignment
3. Hera makes binding decision (military authority)
4. No further appeals within team

**Success Criteria**: Decision aligns with strategic objectives, team accepts

**Examples**:
- Should we delay release for quality? (Hera decides)
- Cut features vs extend timeline? (Hera decides)
- Security vulnerability found: halt or proceed? (Hera decides)

---

### Level 4: User Escalation (rare, no time limit)

**Scope**: Product direction, strategic pivots, budget decisions

**Process**:
1. Hera unable to decide (conflicting strategic objectives)
2. Present options to User with full context
3. User makes final call
4. Team implements User decision

**Success Criteria**: User provides clear direction

**Examples**:
- Should TMWS support PostgreSQL again? (Product direction)
- Invest in GraphQL API? (Strategic pivot)
- Hire additional developer? (Budget decision)

**Rarity**: <1% of conflicts (Phase 6A expects 0 User escalations)

---

## Communication Templates

### Conflict Detection Alert

**Slack/Discord Template**:
```
🚨 **Conflict Detected - Eris Mediation Required**

**Type**: Performance vs Security
**Agents**: @Artemis @Hestia
**Impact**: Gate 2 approval blocked

**Summary**:
Hestia requires audit logging (V-SKILL-3), Artemis warns of 20% performance regression.

**Requested**:
- Artemis: Provide performance benchmark data
- Hestia: Provide security risk assessment
- Meeting: Tomorrow 10:00 AM (2h block)

**Eris**: Will facilitate options evaluation and decision.
```

---

### Conflict Resolution Notice

**Slack/Discord Template**:
```
✅ **Conflict Resolved - Implementation Approved**

**Type**: Performance vs Security
**Agents**: @Artemis @Hestia @Hera

**Decision**: Option C (Deferred Audit Logging)
**Decided By**: Hera (strategic validation)

**Outcome**:
- Security: 100% audit coverage ✅
- Performance: <1% impact ✅
- Trade-off: 5-minute audit delay (acceptable)

**Next Steps**:
- Artemis: Implement deferred logging (4h)
- Hestia: Verify security requirements (2h)
- Eris: Update Gate 2 checklist

**ADR**: docs/decisions/ADR-006A-1-performance-vs-security-audit-logging.md
```

---

## Lessons Learned (To Be Updated After Phase 6A)

### Post-Phase Review Template

```markdown
## Phase 6A Conflict Resolution Review

**Total Conflicts**: N
**Resolved at Level 1**: X (agent-to-agent)
**Resolved at Level 2**: Y (Eris mediation)
**Resolved at Level 3**: Z (Hera decision)
**Escalated to User**: 0 (target)

**Average Resolution Time**:
- Level 1: Xh (target: <2h)
- Level 2: Yh (target: <24h)
- Level 3: Zh (target: <48h)

**Most Common Conflicts**:
1. Performance vs Security: N times
2. API Design vs Documentation: N times
3. Performance Regression: N times

**Process Improvements**:
- [ ] What worked well?
- [ ] What could be improved?
- [ ] Update playbook for Phase 6B
```

---

**End of Playbook**

真の強さは、チーム全体が一つになった時に現れる。Conflicts are opportunities for better solutions.

--- Eris, Tactical Coordinator
