# Phase 6A: Skills System Production Implementation
## Tactical Execution Plan - Eris Coordination

**Status**: Draft for Review
**Created**: 2025-11-25
**Coordinator**: Eris (Tactical Coordinator)
**Strategic Input**: Athena (Harmonious Conductor), Hera (Strategic Commander)

---

## Executive Summary

### Strategic Consensus Analysis

**Athena's Approach** (Harmonious, Sub-Phase):
- Timeline: 24-30h (2-2.5 weeks)
- Structure: 4 sub-phases (Foundation → Core → API → Audit)
- Success Probability: 94.3%
- Focus: Harmony, integration, gradual deployment

**Hera's Approach** (Military, Wave-Based):
- Timeline: 130h with 40% buffer (3 weeks, 21 days)
- Structure: 4 waves (Core → Tools → Auto → Conditional)
- Success Probability: 90.3%
- Focus: Security, risk mitigation, resource allocation

### Critical Discrepancy: Timeline Estimation

**Issue**: 5.4x difference in time estimates
- Athena: 24-30h (optimistic, harmony-focused)
- Hera: 130h (pessimistic, military precision)

**Root Cause Analysis**:
1. **Athena**: Assumes high team harmony, minimal conflict resolution overhead
2. **Hera**: Includes 40% buffer for unknowns, security audits, rework cycles

**Eris Assessment**: Hera's estimate is more realistic for production deployment.
- Athena's 24-30h assumes "happy path" (0% rework, instant approvals)
- Hera's 130h accounts for real-world friction (security reviews, test failures, documentation updates)

### Unified Recommendation: **PROCEED WITH MODIFIED HERA APPROACH**

**Rationale**:
- Adopt Hera's wave-based structure (clearer dependencies, better rollback)
- Adopt Hera's timeline (130h ≈ 3 weeks)
- Incorporate Athena's harmony checks at each approval gate
- Target Athena's success probability (94.3%) through proactive conflict resolution

---

## 1. Reconciled Execution Approach

### Selected Framework: **Wave-Based with Harmony Gates**

**Structure**: Hera's 4-wave approach + Athena's harmony scoring

```
Wave 1: Core Foundation (40h, Week 1)
  ├─ Database schema (8h)
  ├─ Core models (12h)
  ├─ Basic CRUD (10h)
  └─ Foundation tests (10h)
  → Harmony Gate 1: Integration check

Wave 2: Tools Integration (35h, Week 2)
  ├─ Tool registration (12h)
  ├─ Invocation system (13h)
  └─ Tool tests (10h)
  → Harmony Gate 2: Cross-service check

Wave 3: Auto-Conversion (30h, Week 2-3)
  ├─ SlashCommandConverter (8h)
  ├─ TaskConverter (8h)
  ├─ PromptConverter (8h)
  └─ Conversion tests (6h)
  → Harmony Gate 3: API consistency check

Wave 4: Conditional Loading (25h, Week 3)
  ├─ Config system (10h)
  ├─ Loading logic (8h)
  └─ Final integration (7h)
  → Harmony Gate 4: Final audit
```

**Total**: 130h ≈ 3 weeks (21 working days)

### Why Wave-Based Over Sub-Phase?

| Criteria | Wave-Based (Hera) | Sub-Phase (Athena) | Winner |
|----------|-------------------|---------------------|---------|
| Rollback Clarity | ✅ Clear wave boundaries | ⚠️ Overlapping phases | Wave |
| Dependency Tracking | ✅ Explicit DAG | ⚠️ Implicit order | Wave |
| Security Audits | ✅ Per-wave checkpoints | ⚠️ Post-implementation | Wave |
| Team Harmony | ⚠️ Less flexible | ✅ Adaptive flow | Sub-Phase |
| Risk Management | ✅ Fail-fast gates | ⚠️ Late discovery | Wave |

**Decision**: Wave-Based with Harmony scoring at gates (best of both)

---

## 2. Approval Gate Implementation

### Gate 1: Foundation Complete (After Wave 1, Day 5)

**Automated Checks** (CI/CD):
```bash
# Database migration applied
alembic current | grep "009d_add_skills_system"

# Compilation check
python -m py_compile src/models/skill.py src/models/skill_tool.py

# Foundation tests passing
pytest tests/unit/models/test_skill.py -v --tb=short
pytest tests/unit/services/test_skill_service.py::test_create_skill -v

# Minimum coverage
pytest tests/unit/ -k skill --cov=src.models.skill --cov-fail-under=80
```

**Manual Checks** (Athena + Artemis):
- [ ] Athena: Harmony score ≥8/10 (integration with existing models)
- [ ] Artemis: Zero technical debt introduced (Ruff, Mypy clean)
- [ ] Artemis: Database schema reviewed (no missing indexes)

**Success Criteria**:
- All automated checks: ✅ PASS
- Athena harmony: ≥8/10
- Artemis technical review: ✅ APPROVED

**Rollback Procedure** (if FAIL):
```bash
# Revert database
alembic downgrade -1

# Revert code
git revert HEAD~N  # N = number of commits in Wave 1

# Re-run baseline tests
pytest tests/unit/ -v --tb=short
```

**Escalation Path**:
- Gate fails → Eris reviews → Hera makes GO/NO-GO decision
- Timeline: 24h max for gate approval

---

### Gate 2: Tools Integration Complete (After Wave 2, Day 10)

**Automated Checks**:
```bash
# Tool registration working
pytest tests/unit/services/test_skill_service.py::test_register_tool -v

# Invocation system functional
pytest tests/integration/test_skill_tool_invocation.py -v

# Cross-service integration
pytest tests/integration/test_slash_command_to_skill.py -v

# Performance check (P95 < 50ms)
pytest tests/performance/test_skill_invocation_performance.py -v
```

**Manual Checks** (Athena + Hestia):
- [ ] Athena: Cross-service harmony ≥8/10 (no breaking changes to SlashCommandService)
- [ ] Hestia: Security audit complete (V-SKILL-1/2/3/4 tested)
- [ ] Artemis: Performance regression check (P95 latency within budget)

**Success Criteria**:
- All integration tests: ✅ PASS
- Hestia security: No HIGH/CRITICAL findings
- Athena harmony: ≥8/10

**Rollback Procedure**:
```bash
# Wave 2 only (Wave 1 preserved)
git revert <wave-2-start-commit>..<wave-2-end-commit>
alembic downgrade -1  # If Wave 2 had migrations
```

---

### Gate 3: Auto-Conversion Complete (After Wave 3, Day 15)

**Automated Checks**:
```bash
# All converters functional
pytest tests/unit/services/test_slash_command_converter.py -v
pytest tests/unit/services/test_task_converter.py -v
pytest tests/unit/services/test_prompt_converter.py -v

# End-to-end conversion test
pytest tests/integration/test_auto_conversion_e2e.py -v

# API consistency check
pytest tests/api/test_slash_command_api.py -v
pytest tests/api/test_skill_api.py -v
```

**Manual Checks** (Athena + Muses):
- [ ] Athena: API design harmony ≥9/10 (RESTful, consistent patterns)
- [ ] Muses: Documentation complete (API reference, examples, migration guide)
- [ ] Artemis: Code duplication check (<5% with JsCpd)

**Success Criteria**:
- All API tests: ✅ PASS
- Documentation coverage: ≥90%
- Athena harmony: ≥9/10

**Rollback Procedure**:
```bash
# Wave 3 only
git revert <wave-3-start-commit>..<wave-3-end-commit>
```

---

### Gate 4: Final Audit (After Wave 4, Day 21)

**Automated Checks**:
```bash
# Full regression suite
pytest tests/ -v --tb=short --durations=10

# Security suite
pytest tests/security/ -v

# Performance suite
pytest tests/performance/ -v

# Code quality gates
ruff check src/ --select ALL
mypy src/ --strict --ignore-missing-imports
```

**Manual Checks** (All Agents):
- [ ] Hestia: Final security audit ✅ APPROVED
- [ ] Artemis: Performance targets met (all P95 < targets)
- [ ] Athena: System harmony ≥9/10 (all integrations stable)
- [ ] Muses: Documentation complete and published
- [ ] Hera: Strategic objectives achieved (all 5 V-SKILL-* resolved)

**Success Criteria**:
- Zero HIGH/CRITICAL security findings
- All performance targets met
- Test coverage ≥85%
- All agents approve: ✅

**Final Approval Authority**: Hera (Strategic Commander)

**Rollback Procedure** (if FAIL):
```bash
# Full rollback to pre-Phase-6A state
git revert <phase-6a-start-commit>..<phase-6a-end-commit>
alembic downgrade <pre-phase-6a-version>

# Verify baseline restored
pytest tests/ -v
```

---

## 3. Conflict Resolution Protocol

### Conflict 1: Performance vs Security (Artemis vs Hestia)

**Scenario**: Hestia requires database query audit logging, Artemis warns of 20% performance regression.

**Detection Criteria**:
- Performance tests fail (P95 > target)
- Hestia security tests fail (audit logging disabled)

**Mediation Process**:
1. **Eris召集会議** (1 hour max):
   - Artemis: Presents performance data (P95 latency, throughput)
   - Hestia: Presents security risk (CVSS score, attack scenario)
   - Eris: Facilitates trade-off analysis

2. **Options Evaluation**:
   - **Option A**: Async audit logging (Artemis recommendation)
     - Impact: -95% performance hit (from 20% to 1%)
     - Risk: Potential audit log loss if queue overflows
   - **Option B**: Selective audit logging (Eris recommendation)
     - Impact: -10% performance hit (only HIGH-risk operations)
     - Risk: Partial audit trail (90% coverage)
   - **Option C**: Deferred audit logging (Hestia fallback)
     - Impact: -0% performance hit (background job)
     - Risk: Delayed audit trail (up to 5 min)

3. **Decision Authority**:
   - **If security impact = CRITICAL**: Hestia has veto power
   - **If security impact = HIGH**: Hera makes final decision
   - **If security impact = MEDIUM**: Artemis + Hestia consensus
   - **If no consensus in 24h**: Escalate to User

**Timeline**: 24h max for resolution

**Documented in**: `docs/decisions/ADR-006A-X-performance-vs-security.md`

---

### Conflict 2: API Design vs Documentation (Artemis vs Muses)

**Scenario**: Artemis wants to rename `SkillTool.invocation_context` to `invoke_ctx` for brevity. Muses argues this breaks documentation clarity.

**Detection Criteria**:
- Code review comment by Muses
- API consistency check fails (naming convention violation)

**Mediation Process**:
1. **Athena调和** (Harmony Facilitator):
   - Reviews both perspectives
   - Proposes compromise: `SkillTool.context` (shorter + clear)

2. **Options Evaluation**:
   - **Option A**: Keep `invocation_context` (Muses)
     - Pros: Self-documenting, clear intent
     - Cons: Verbose (19 chars)
   - **Option B**: Use `invoke_ctx` (Artemis)
     - Pros: Concise (10 chars)
     - Cons: Requires documentation lookup
   - **Option C**: Compromise `context` (Athena)
     - Pros: Balance of brevity + clarity (7 chars)
     - Cons: Slightly less specific

3. **Decision Authority**:
   - **Public API**: Athena has final say (harmony > brevity)
   - **Internal API**: Artemis has final say (performance > verbosity)
   - **If no consensus**: Refer to existing codebase patterns

**Timeline**: 2h max for resolution (non-blocking)

**Documented in**: API design guidelines (`docs/api/NAMING_CONVENTIONS.md`)

---

### Conflict 3: VectorSearchService Performance Regression

**Scenario**: Wave 2 introduces skill metadata indexing, causing ChromaDB query latency to increase from 5ms to 50ms P95.

**Detection Criteria**:
- Performance tests fail: `test_vector_search_performance.py::test_search_p95_under_20ms`
- Automated alert: P95 > 20ms threshold

**Mediation Process**:
1. **Artemis分析** (Technical Root Cause):
   - Profiles ChromaDB queries
   - Identifies bottleneck: Full-text search on `skill.description`

2. **Options Evaluation**:
   - **Option A**: Add ChromaDB index on `description` field
     - Impact: -80% latency reduction (50ms → 10ms)
     - Cost: +5MB memory per 1000 skills
   - **Option B**: Cache skill metadata in Redis
     - Impact: -90% latency reduction (50ms → 5ms)
     - Cost: New dependency (Redis), +complexity
   - **Option C**: Lazy-load skill metadata (fetch after vector search)
     - Impact: -95% latency reduction (50ms → 2.5ms for vector search)
     - Cost: +1 additional database query (but async)

3. **Decision Authority**:
   - **Artemis recommends**: Option A (simple, no new deps)
   - **Hera validates**: Cost-benefit analysis (5MB acceptable)
   - **Decision**: Implement Option A in Wave 2 (same sprint)

**Timeline**: 4h max for fix (blocking for Gate 2)

**Documented in**: Performance postmortem (`docs/performance/WAVE_2_REGRESSION_RCA.md`)

---

## 4. Resource Balancing

### Realistic Timeline Reconciliation

**Athena's 24-30h** vs **Hera's 130h**: Which is correct?

**Eris Analysis**:

| Component | Athena Estimate | Hera Estimate | Reality Check |
|-----------|-----------------|---------------|---------------|
| Database Schema | 3h | 8h | 8h (Hera correct, includes migration + indexes) |
| Core Models | 5h | 12h | 10h (Athena optimistic, Hera pessimistic) |
| Tool Registration | 4h | 12h | 10h (middleware + validation takes time) |
| Tests | 8h | 30h | 25h (Hera correct, includes integration tests) |
| Security Audit | 2h | 20h | 15h (Hestia thoroughness required) |
| Documentation | 2h | 15h | 12h (Muses detail required) |
| **Buffer** | 0h | 33h (40%) | 20h (realistic for unknowns) |
| **Total** | 24h | 130h | **100h** ✅ |

**Conclusion**: **100 hours ≈ 2.5 weeks** (realistic estimate)
- Athena: Too optimistic (assumes zero friction)
- Hera: Too pessimistic (40% buffer is military-grade)
- **Eris: 100h with 25% buffer** (100h / 0.75 = 133h ≈ Hera's estimate)

### Agent Workload Distribution

**Per Hera's Analysis**:
- Artemis: 58h (45% of 130h)
- Hestia: 38h (29%)
- Muses: 22h (17%)
- Hera: 12h (9%)

**Eris Adjustment** (for 100h total):
- Artemis: 45h (45%) - Lead implementation
- Hestia: 25h (25%) - Security audits (reduced from 38h by risk-based testing)
- Muses: 20h (20%) - Documentation (reduced from 22h by templates)
- Hera: 10h (10%) - Strategic oversight

**Overload Prevention**:
1. **Artemis overload risk** (45h in 2.5 weeks = 18h/week = 3.6h/day):
   - Mitigation: Parallel work with Hestia on tests
   - Backup: Hera can assist with code generation tools
2. **Hestia stress risk** (security audit fatigue):
   - Mitigation: Risk-based testing (focus on HIGH/CRITICAL)
   - Backup: Automated security scans (Bandit, Semgrep)
3. **Muses documentation debt**:
   - Mitigation: Documentation-as-code (docstrings → auto-generate)
   - Backup: Athena assists with narrative sections

---

## 5. Final Tactical Plan

### Week-by-Week Breakdown

#### **Week 1: Foundation + Tools (Days 1-7)**

**Monday (Day 1) - Wave 1 Start**:
- **Artemis** (8h): Database schema design + migration
  - Files: `migrations/versions/009d_add_skills_system.py`
  - Deliverable: Alembic migration applied
- **Hestia** (4h): Security requirements review
  - Files: `docs/security/PHASE_6A_SECURITY_REQUIREMENTS.md`
  - Deliverable: V-SKILL-1/2/3/4/5 requirements documented

**Tuesday (Day 2) - Models**:
- **Artemis** (10h): Core models implementation
  - Files: `src/models/skill.py`, `src/models/skill_tool.py`
  - Deliverable: Models compiled, type-checked (Mypy)
- **Muses** (4h): Model docstrings and examples
  - Files: Docstrings in models
  - Deliverable: API reference auto-generated

**Wednesday (Day 3) - CRUD**:
- **Artemis** (8h): SkillService CRUD operations
  - Files: `src/services/skill_service.py`
  - Deliverable: Basic CRUD methods working
- **Hestia** (6h): CRUD security audit
  - Files: `tests/security/test_skill_crud_security.py`
  - Deliverable: V-SKILL-2 (namespace isolation) tested

**Thursday (Day 4) - Foundation Tests**:
- **Artemis** (10h): Unit tests for models + service
  - Files: `tests/unit/models/test_skill.py`, `tests/unit/services/test_skill_service.py`
  - Deliverable: 50+ tests passing, 80%+ coverage
- **Hestia** (4h): Security test suite (foundation)
  - Files: `tests/security/test_skill_foundation.py`
  - Deliverable: V-SKILL-1/2 baseline tests

**Friday (Day 5) - Gate 1 Approval**:
- **Morning** (2h): Automated checks run (CI/CD)
- **Afternoon** (2h): Manual reviews
  - Athena: Harmony check
  - Artemis: Technical review
  - Hestia: Security sign-off
- **Evening**: **GATE 1 DECISION** (GO/NO-GO)
  - If GO: Proceed to Wave 2
  - If NO-GO: 24h fix cycle → re-review Monday

---

#### **Week 2: Tools + Auto-Conversion (Days 8-14)**

**Monday (Day 8) - Wave 2 Start** (assuming Gate 1 PASS):
- **Artemis** (12h): Tool registration system
  - Files: `src/services/skill_service.py` (register_tool, list_tools)
  - Deliverable: Tool registration working
- **Hestia** (6h): Tool security audit
  - Files: `tests/security/test_skill_tool_security.py`
  - Deliverable: V-SKILL-3 (command injection) baseline

**Tuesday (Day 9) - Invocation**:
- **Artemis** (10h): Tool invocation system
  - Files: `src/services/skill_service.py` (invoke_tool)
  - Deliverable: Async invocation working
- **Hestia** (6h): Invocation security tests
  - Files: `tests/security/test_skill_invocation.py`
  - Deliverable: V-SKILL-4 (privilege escalation) tested

**Wednesday (Day 10) - Gate 2 Preparation**:
- **Artemis** (8h): Integration tests (SlashCommand → Skill)
  - Files: `tests/integration/test_slash_command_to_skill.py`
  - Deliverable: Cross-service integration working
- **Muses** (6h): Tool registration documentation
  - Files: `docs/api/SKILL_TOOL_REGISTRATION.md`
  - Deliverable: Developer guide published

**Thursday (Day 11) - Gate 2 Approval**:
- **Morning** (2h): Automated checks
- **Afternoon** (2h): Manual reviews
  - Athena: Cross-service harmony ≥8/10
  - Hestia: Security audit complete
- **Evening**: **GATE 2 DECISION**

**Friday (Day 12) - Wave 3 Start** (assuming Gate 2 PASS):
- **Artemis** (8h): SlashCommandConverter implementation
  - Files: `src/services/slash_command_converter.py`
  - Deliverable: `/cmd` → `Skill` conversion working
- **Hestia** (4h): Converter security audit
  - Files: `tests/security/test_converter_security.py`

---

#### **Week 3: Conditional Loading + Final Audit (Days 15-21)**

**Monday (Day 15) - Wave 3 Continues**:
- **Artemis** (8h): TaskConverter + PromptConverter
  - Files: `src/services/task_converter.py`, `src/services/prompt_converter.py`
  - Deliverable: All converters functional
- **Muses** (6h): Conversion guide documentation
  - Files: `docs/guides/SLASH_COMMAND_TO_SKILL_MIGRATION.md`

**Tuesday (Day 16) - Gate 3 Approval**:
- **Morning** (2h): Automated checks
- **Afternoon** (2h): Manual reviews
  - Athena: API consistency ≥9/10
  - Muses: Documentation complete
- **Evening**: **GATE 3 DECISION**

**Wednesday (Day 17) - Wave 4 Start**:
- **Artemis** (10h): Conditional loading system
  - Files: `src/core/config.py` (enable_skills flag)
  - Deliverable: Skills system can be disabled via config
- **Hera** (4h): Configuration strategy review
  - Files: `docs/architecture/SKILLS_CONDITIONAL_LOADING.md`

**Thursday (Day 18) - Final Integration**:
- **Artemis** (8h): End-to-end integration tests
  - Files: `tests/integration/test_skills_e2e.py`
  - Deliverable: Full user flow tested
- **Hestia** (8h): Final security audit
  - Files: `docs/security/PHASE_6A_SECURITY_AUDIT_FINAL.md`
  - Deliverable: All V-SKILL-* verified

**Friday (Day 19) - Performance + Documentation**:
- **Artemis** (6h): Performance testing + optimization
  - Files: `tests/performance/test_skill_performance.py`
  - Deliverable: All P95 targets met
- **Muses** (8h): Final documentation polish
  - Files: `docs/api/SKILLS_SYSTEM_REFERENCE.md`

**Monday (Day 21) - Gate 4 Final Audit**:
- **Morning** (4h): Full regression suite run
- **Afternoon** (4h): All agents final review
  - Hestia: Security sign-off ✅
  - Artemis: Performance sign-off ✅
  - Athena: Harmony sign-off ✅
  - Muses: Documentation sign-off ✅
  - Hera: Strategic objectives achieved ✅
- **Evening**: **HERA FINAL APPROVAL**
  - If ✅: Merge to `main`, deploy to staging
  - If ❌: 48h fix cycle → re-review Wednesday

---

### Daily Task Assignments (Detailed)

**Week 1 Example** (Day 1 - Monday):

| Agent | Task | Time | Deliverable | Dependencies |
|-------|------|------|-------------|--------------|
| Artemis | Design database schema | 4h | `migrations/versions/009d_add_skills_system.py` (draft) | None |
| Hestia | Review security requirements | 2h | `docs/security/PHASE_6A_SECURITY_REQUIREMENTS.md` (draft) | None |
| Artemis | Create Alembic migration | 2h | Migration applied to dev DB | Schema design |
| Hestia | Define V-SKILL-1/2 test cases | 2h | Test specification document | Security requirements |
| Artemis | Add database indexes | 2h | Migration updated with indexes | Migration created |
| Eris | Daily standup coordination | 1h | Status report to Hera | All agents |

**Total**: 13h (includes coordination overhead)

**Daily Check-in Protocol**:
- 09:00 AM: Daily standup (async, 15 min)
  - What I did yesterday
  - What I'm doing today
  - Any blockers
- 05:00 PM: Progress report to Eris
  - Tasks completed (%)
  - Tasks blocked (if any)
  - Tomorrow's plan

---

### Risk Triggers (When to Halt/Rollback)

**Red Flags** (Immediate Halt):
1. **Security**: HIGH/CRITICAL vulnerability found (CVSS ≥7.0)
   - Action: Halt wave, fix immediately
   - Authority: Hestia can trigger HALT unilaterally
2. **Performance**: P95 regression >50% from baseline
   - Action: Halt wave, root cause analysis (4h max)
   - Authority: Artemis recommends HALT, Hera decides
3. **Test Failure**: >10% of tests failing
   - Action: Halt wave, investigate root cause
   - Authority: Artemis triggers HALT, Eris coordinates fix
4. **Harmony Breakdown**: Athena score <6/10
   - Action: Halt wave, conflict resolution session
   - Authority: Athena triggers HALT, Eris mediates

**Yellow Flags** (Proceed with Caution):
1. **Timeline Slip**: >20% behind schedule
   - Action: Daily check-ins with Hera, re-estimate remaining
2. **Code Quality**: Ruff/Mypy warnings increasing
   - Action: Daily code cleanup (30 min/day)
3. **Documentation Lag**: >2 days behind implementation
   - Action: Muses prioritizes catch-up
4. **Agent Overload**: Any agent >40h/week
   - Action: Hera reallocates tasks, considers timeline extension

**Rollback Criteria**:
- Gate fails 2 consecutive times (48h total)
- Critical security vulnerability cannot be fixed within wave
- Strategic objective no longer achievable (Hera decision)

---

## 6. Communication Protocol

### Daily Standup (Async, 15 min)

**Format** (Slack/Discord):
```
@channel Daily Standup - Phase 6A Wave N

**Artemis**:
✅ Completed: Implemented Skill model (8h)
🔄 Today: Working on SkillService CRUD (10h)
🚧 Blockers: None

**Hestia**:
✅ Completed: V-SKILL-1/2 requirements defined (4h)
🔄 Today: CRUD security audit (6h)
🚧 Blockers: Waiting for Artemis CRUD implementation

**Muses**:
✅ Completed: Model docstrings (4h)
🔄 Today: API reference generation (4h)
🚧 Blockers: None

**Eris**:
📊 Overall Progress: Wave 1 - 40% complete (Day 2/5)
⚠️ Risks: None at this time
📅 Next Gate: Gate 1 on Friday (Day 5)
```

**Response Time**: All agents respond within 2h of standup post

---

### Weekly Strategic Review (With Hera)

**Every Friday, 5:00 PM**:
- Eris presents weekly summary
- Hera validates strategic alignment
- Athena provides harmony assessment
- Decision: Continue / Adjust / Halt

**Template**:
```markdown
## Phase 6A Weekly Review - Week N

**Progress**:
- Waves completed: N/4
- Hours spent: Xh / 100h (Y%)
- Test coverage: Z%

**Achievements**:
- ✅ Gate N passed
- ✅ [Key milestone]

**Challenges**:
- ⚠️ [Challenge 1]
- ⚠️ [Challenge 2]

**Next Week Plan**:
- Wave N+1 objectives
- Resource allocation
- Risk mitigation

**Hera Decision**: CONTINUE / ADJUST / HALT
```

---

### Conflict Escalation Path

**Level 1** (Agent-to-Agent, 2h limit):
- Agents discuss directly
- Eris observes, provides data

**Level 2** (Eris Mediation, 24h limit):
- Eris facilitates structured discussion
- Athena provides harmony perspective
- Decision documented in ADR

**Level 3** (Hera Strategic Decision, 48h limit):
- Hera reviews all options
- Makes final binding decision
- No further appeals

**Level 4** (User Escalation, only if Hera cannot decide):
- Present options to User
- User makes final call
- Rare, only for product direction conflicts

---

## 7. Risk Monitoring Dashboard

### Top 5 Risks (From Athena + Hera)

#### Risk 1: VectorSearchService Performance Regression (P1)

**Source**: Athena Analysis
**Probability**: 40% → 10% (mitigated)
**Impact**: HIGH (P95 latency 5ms → 50ms)

**Daily Check Criteria**:
```bash
# Run performance test
pytest tests/performance/test_vector_search_performance.py -v

# Check P95 latency
# Target: <20ms
# Yellow: 20-30ms
# Red: >30ms
```

**Weekly Check**:
- Review ChromaDB query patterns
- Check index usage with EXPLAIN
- Monitor memory usage (ChromaDB collection size)

**Trigger Point**:
- **Yellow**: P95 >20ms for 2 consecutive days
- **Red**: P95 >30ms or memory usage >512MB

**Mitigation Plan** (if triggered):
- Artemis: Root cause analysis (4h)
- Options: Add index, cache metadata, lazy-load
- Decision: Hera approves within 24h

---

#### Risk 2: Security Vulnerabilities (V-SKILL-1/2/3/4/5) (P0)

**Source**: Hera Analysis
**Probability**: 25% (HIGH) → 10% (with testing)
**Impact**: CRITICAL (CVSS 7.8)

**Daily Check Criteria**:
```bash
# Run security test suite
pytest tests/security/test_skill_*.py -v

# Static analysis
bandit -r src/models/skill.py src/services/skill_service.py
semgrep --config=auto src/
```

**Weekly Check**:
- Hestia reviews all new code for security patterns
- Manual penetration testing (if applicable)
- Review security audit logs

**Trigger Point**:
- **Yellow**: MEDIUM severity finding (CVSS 4.0-6.9)
- **Red**: HIGH/CRITICAL finding (CVSS ≥7.0)

**Mitigation Plan**:
- **MEDIUM**: Fix within 72h (next wave)
- **HIGH**: Fix within 24h (current wave halted)
- **CRITICAL**: Fix immediately (all hands on deck)

---

#### Risk 3: API Inconsistency (RESTful Patterns) (P2)

**Source**: Athena Analysis
**Probability**: 30% → 10% (with review)
**Impact**: MEDIUM (user confusion, rework)

**Daily Check Criteria**:
```bash
# API consistency check
pytest tests/api/test_skill_api.py::test_restful_patterns -v

# Naming convention check
ruff check src/api/routers/skills.py --select N
```

**Weekly Check**:
- Athena reviews all new API endpoints
- Compare with existing patterns (SlashCommandRouter, TaskRouter)
- Update API design guidelines if new patterns emerge

**Trigger Point**:
- **Yellow**: 2+ naming inconsistencies
- **Red**: Breaking change to existing API

**Mitigation Plan**:
- Athena + Muses: Propose consistent naming (2h)
- Artemis: Refactor to match pattern (4h)
- Decision: Athena has final say on public API

---

#### Risk 4: Test Coverage Gaps (<85%) (P2)

**Source**: Hera Analysis
**Probability**: 35% → 15% (with discipline)
**Impact**: MEDIUM (bugs in production)

**Daily Check Criteria**:
```bash
# Coverage check
pytest tests/ -k skill --cov=src --cov-report=term-missing

# Target: 85%+
# Yellow: 80-85%
# Red: <80%
```

**Weekly Check**:
- Review uncovered lines (Artemis)
- Prioritize critical paths (Hestia identifies)
- Add missing tests

**Trigger Point**:
- **Yellow**: Coverage 80-85% for 2 days
- **Red**: Coverage <80% or critical path uncovered

**Mitigation Plan**:
- Artemis: Write missing tests (4h/day until ≥85%)
- Hestia: Focus on security-critical paths first

---

#### Risk 5: Timeline Overrun (>3 weeks) (P1)

**Source**: Eris Analysis (Athena optimistic, Hera pessimistic)
**Probability**: 40% → 20% (with 100h estimate)
**Impact**: HIGH (delayed release, resource contention)

**Daily Check Criteria**:
- Track hours spent vs. estimated
- Calculate burn rate (hours/day)
- Project completion date

**Weekly Check**:
```
Week 1: Should be 33h spent (33% of 100h)
Week 2: Should be 66h spent (66% of 100h)
Week 3: Should be 100h spent (100%)
```

**Trigger Point**:
- **Yellow**: >10% behind schedule (e.g., Week 1 <30h spent)
- **Red**: >20% behind schedule (e.g., Week 1 <26h spent)

**Mitigation Plan**:
- **Yellow**: Daily check-ins with Hera, re-estimate
- **Red**: Hera decides: (A) Cut scope, (B) Add resources, (C) Extend timeline
- **Emergency**: User approval required for timeline extension >1 week

---

### Risk Tracking Template (Daily Update)

```markdown
# Phase 6A Risk Dashboard - Day N

| Risk | Status | Current Metric | Trend | Action |
|------|--------|----------------|-------|--------|
| Performance Regression | 🟢 GREEN | P95 = 8ms | ↓ | None |
| Security Vulnerabilities | 🟡 YELLOW | 1 MEDIUM finding | → | Fix in 48h |
| API Inconsistency | 🟢 GREEN | 0 issues | ↓ | None |
| Test Coverage | 🟡 YELLOW | 82% | ↑ | Add 5 tests today |
| Timeline Overrun | 🟢 GREEN | 35h spent (Day 10) | ↓ | On track |

**Legend**:
- 🟢 GREEN: On target
- 🟡 YELLOW: Warning, monitoring
- 🔴 RED: Immediate action required

**Trend**:
- ↑ Improving
- → Stable
- ↓ Degrading
```

---

## 8. Final Recommendation

### GO / NO-GO / GO WITH CONDITIONS

**Eris Decision**: **✅ GO WITH CONDITIONS**

### Conditions for Starting Phase 6A-1 (Wave 1)

1. **Pre-Phase Setup** (1 day before Wave 1):
   - [ ] All agents acknowledge 100h timeline (not 24h)
   - [ ] Hera approves wave-based structure
   - [ ] Athena confirms harmony gates understood
   - [ ] Git branch created: `feature/phase-6a-skills-system`
   - [ ] Baseline tests run: `pytest tests/ -v` (all PASS)
   - [ ] Baseline performance measured: P95 latencies recorded

2. **Agent Commitment**:
   - [ ] Artemis: 45h available over 3 weeks (15h/week)
   - [ ] Hestia: 25h available (8h/week)
   - [ ] Muses: 20h available (7h/week)
   - [ ] Hera: 10h available for oversight (3h/week)
   - [ ] Eris: Available for daily coordination (1h/day)

3. **Risk Mitigation**:
   - [ ] Conflict resolution protocol reviewed by all agents
   - [ ] Rollback procedures tested (dry-run)
   - [ ] Escalation paths documented and agreed
   - [ ] Risk dashboard template set up (daily updates)

4. **Documentation**:
   - [ ] This tactical plan approved by Hera ✅
   - [ ] Communicated to User for final approval ✅
   - [ ] Committed to repository: `docs/tactical/PHASE_6A_TACTICAL_EXECUTION_PLAN.md`

5. **Strategic Alignment**:
   - [ ] Athena: Harmony objectives confirmed
   - [ ] Hera: Strategic objectives (5 V-SKILL-* mitigations) confirmed
   - [ ] Eris: Tactical plan validated against both analyses

### Success Probability (Weighted)

**Calculation**:
```
Athena Success Probability: 94.3%
Hera Success Probability: 90.3%

Weighted Average (Athena 40%, Hera 60%):
= 0.40 × 94.3% + 0.60 × 90.3%
= 37.72% + 54.18%
= 91.9%
```

**Eris Confidence**: **92% ± 5%** (accounting for risk mitigation)

**Conditions for 92%+ Success**:
1. All approval gates enforced (no shortcuts)
2. Daily risk monitoring (no surprises)
3. Conflict resolution within 24h (no deadlocks)
4. Athena harmony maintained ≥8/10 (team cohesion)
5. Hera strategic oversight (no scope creep)

---

## 9. Next Steps (Immediate Actions)

### Before Starting Wave 1 (24h Preparation)

**Eris** (1h):
- [ ] Present this tactical plan to Hera for approval
- [ ] Request User final GO/NO-GO decision
- [ ] Set up risk dashboard tracking
- [ ] Schedule Week 1 daily standups

**Artemis** (2h):
- [ ] Review database schema requirements
- [ ] Set up development environment (Git branch)
- [ ] Run baseline tests and performance benchmarks

**Hestia** (2h):
- [ ] Review V-SKILL-1/2/3/4/5 requirements
- [ ] Prepare security test templates
- [ ] Set up security scanning tools (Bandit, Semgrep)

**Muses** (2h):
- [ ] Set up documentation structure (`docs/api/`, `docs/guides/`)
- [ ] Prepare API reference templates
- [ ] Review existing documentation patterns

**Hera** (1h):
- [ ] Review and approve this tactical plan
- [ ] Confirm strategic objectives alignment
- [ ] Authorize Wave 1 start (pending User approval)

**Athena** (1h):
- [ ] Review harmony objectives
- [ ] Prepare harmony scoring rubric for gates
- [ ] Coordinate agent communication channels

### After User Approval (Wave 1 Day 1)

- 09:00 AM: **Kickoff meeting** (all agents, 30 min)
- 09:30 AM: **Wave 1 begins** (Artemis starts database schema)
- 05:00 PM: **Daily standup** (async, 15 min)
- End of Day 1: **Progress report to Eris**

---

## 10. Document Metadata

**Created**: 2025-11-25
**Last Updated**: 2025-11-25
**Version**: 1.0 (Draft for Review)
**Status**: Pending Hera Approval → Pending User Approval
**Next Review**: After Gate 1 (Day 5)

**Approval Chain**:
1. ⏳ Eris: Author and coordinator
2. ⏳ Hera: Strategic validation required
3. ⏳ User: Final GO/NO-GO decision
4. ⏳ All Agents: Acknowledge conditions

**Document Location**: `docs/tactical/PHASE_6A_TACTICAL_EXECUTION_PLAN.md`

---

**Eris Sign-Off**:

異論は認めますが、最終的な戦術的判断は私が下しました。この計画は、Athena の調和重視とHera の軍事的精密性の両方を統合した、実行可能で現実的な戦術計画です。

チーム全体の視点で考えると、100時間（2.5週間）の推定が最も合理的です。リスクを最小化しつつ、効率を最大化します。各員の役割は明確です。自分の任務に集中して下さい。

True strength emerges when the entire team becomes one. Let's proceed with confidence and discipline.

**真の強さは、チーム全体が一つになった時に現れる。自信と規律を持って進みましょう。**

--- Eris
