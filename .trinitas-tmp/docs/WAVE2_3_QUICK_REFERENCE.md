# Wave 2/3 Quick Reference Guide
## Trinitas Security Hardening v2.3.1

**📅 Date**: 2025-11-08 (Planned)
**⏱️ Duration**: 6 hours (09:00-15:00 UTC)
**👥 Team**: 6 agents (Athena, Artemis, Hestia, Eris, Muses, Hera)
**🎯 Goal**: Fix V-6, V-7, V-8 (MEDIUM priority vulnerabilities)

---

## 🚀 30-Second Overview

**What**: Fix 3 MEDIUM vulnerabilities in parallel
**Why**: Improve security score from 90/100 to 95/100
**How**: 3 parallel tracks with independent file changes
**Risk**: LOW (zero file overlap, independent tests)
**Efficiency**: 2.8x faster than sequential (6h vs 8.5h)

---

## 📊 Dependency Graph (Visual)

```
┌─────────────────────────────────────────────────────────────┐
│                    FILE DEPENDENCIES                         │
└─────────────────────────────────────────────────────────────┘

    V-6                    V-7                    V-8
    ====                   ====                   ====

┌─────────┐          ┌─────────────┐        ┌─────────────┐
│ test_   │          │ skill_      │        │ audit_      │
│ skill_  │          │ loader.py   │        │ log.py      │
│ discov  │          └──────┬──────┘        └──────┬──────┘
│ ery.py  │                 │                      │
└─────────┘                 │                      │
                     ┌──────┴──────┐        ┌──────┴──────┐
    (TEST)           │ async_      │        │ decision_   │
                     │ executor.py │        │ check.py    │
                     └──────┬──────┘        └─────────────┘
                            │
                     ┌──────┴──────┐        ┌─────────────┐
                     │ resource_   │        │ precompact_ │
                     │ manager.py  │        │ memory_...  │
                     └─────────────┘        └─────────────┘

   1 file             3 files                3 files
   (test only)        (production)           (production + hooks)

═══════════════════════════════════════════════════════════════

 ✅ ZERO OVERLAP → 100% Parallel Execution Possible
 ✅ NO SHARED MODULES → Zero Merge Conflicts
 ✅ INDEPENDENT TESTS → No Test Interference
```

---

## ⏱️ Timeline (6 Hours)

```
┌─────────────────────────────────────────────────────────────┐
│ Day 1: 2025-11-08 (Thursday)                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ 09:00 │ ████ Kickoff (30 min) ████ [All agents]           │
│ 09:30 │                                                     │
│       │ ║ V-6 Fix (Artemis, Hestia) ──────────────║ 2h    │
│       │ ║ V-7 Fix (Artemis, Eris)   ─────────────────║ 3h │
│       │ ║ V-8 Fix (Hestia, Muses)   ──────────────║ 2h    │
│ 12:00 │ └─────────────────────────────────────┘            │
│       │ ████████ Lunch (1h) ████████                       │
│ 13:00 │                                                     │
│       │ ████ Wave 3: Validation (1.5h) ████                │
│       │ ├─ Unit Tests (30 min)                             │
│       │ ├─ Integration (15 min)                            │
│       │ ├─ Security (15 min)                               │
│       │ └─ Performance (15 min)                            │
│ 14:30 │ ████ Final Approval (30 min) ████                  │
│ 15:00 │ ████ Git Commit & Docs (30 min) ████               │
│ 15:30 │ ✅ COMPLETE                                        │
│       │                                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 👥 Agent Assignments

| Agent | Track | Role | Duration |
|-------|-------|------|----------|
| **Artemis** 🏹 | V-6 + V-7 | Lead (code changes) | 5h |
| **Hestia** 🔥 | V-6 + V-8 | Lead (security) | 4.5h |
| **Eris** ⚔️ | V-7 | Integration testing | 4h |
| **Muses** 📚 | V-8 | Documentation | 3h |
| **Athena** 🏛️ | All | Coordination | 6h |
| **Hera** 🎭 | (Backup) | Standby | 0h |

---

## 🎯 Track Details

### Track 1: V-6 (Insecure Randomness) - 2 hours

**Problem**: Using `random` instead of `secrets` module
**Fix**: Replace `random.seed()` in tests, document policy
**Files**: `tests/test_skill_discovery.py` (1 file)
**Agents**: Artemis (lead), Hestia (validator)
**Risk**: ⭕ VERY LOW (test file only)

**Checklist**:
- [ ] Add comment explaining test vs production randomness
- [ ] Scan production code for `random` module usage
- [ ] Replace with `secrets` module where appropriate
- [ ] Run: `pytest tests/test_skill_discovery.py -v`
- [ ] Hestia security scan: PASS

---

### Track 2: V-7 (Memory Leak) - 3 hours

**Problem**: Async resources not cleaned up
**Fix**: Add context managers + periodic cleanup
**Files**: `skill_loader.py`, `async_executor.py`, `resource_manager.py` (3 files)
**Agents**: Artemis (lead), Eris (integration)
**Risk**: 🟡 MEDIUM (new background task)

**Checklist**:
- [ ] Add `__aenter__` / `__aexit__` to `CachedSkillLoader`
- [ ] Add task cancellation to `AsyncExecutor`
- [ ] Implement periodic cleanup in `ResourceManager`
- [ ] Run: `pytest tests/test_skill_loader.py -v`
- [ ] Memory profiling: PASS (stable after 1000 ops)

---

### Track 3: V-8 (Logging Sensitive Data) - 2 hours

**Problem**: PII logged in plaintext
**Fix**: Add regex-based PII redaction
**Files**: `audit_log.py`, `decision_check.py`, `precompact_memory_injection.py` (3 files)
**Agents**: Hestia (lead), Muses (docs)
**Risk**: ⭕ LOW (deterministic redaction)

**Checklist**:
- [ ] Add `_redact_pii()` to `AuditLogWriter`
- [ ] Define PII patterns: email, SSN, phone, credit card, API keys
- [ ] Update `decision_check.py` to redact prompts
- [ ] Update `precompact_memory_injection.py` to redact context
- [ ] Run: `pytest tests/security/test_audit_log.py -v`
- [ ] Log file scan: No PII leakage

---

## ✅ Success Criteria

| Metric | Target | Actual |
|--------|--------|--------|
| **Duration** | ≤6 hours | 📊 TBD |
| **New Tests** | 48/48 passing (100%) | 📊 TBD |
| **Existing Tests** | 644/644 passing (100%) | 📊 TBD |
| **Security Score** | 95/100 (+5 from 90) | 📊 TBD |
| **Performance Overhead** | <0.1ms | 📊 TBD |
| **Merge Conflicts** | 0 | 📊 TBD |
| **Rollbacks** | 0 | 📊 TBD |

---

## 🚨 Emergency Contacts

**Athena** (Coordinator): `@athena` (Slack)
**Blockers**: Escalate within 15 minutes
**Rollback**: `git reset --hard HEAD~3` (user approval required)

---

## 📚 Related Documents

- **Detailed Plan**: [WAVE2_3_DEPENDENCY_ANALYSIS_AND_EXECUTION_PLAN.md](WAVE2_3_DEPENDENCY_ANALYSIS_AND_EXECUTION_PLAN.md)
- **Security Assessment**: [SECURITY_ASSESSMENT_2025_11_07.md](SECURITY_ASSESSMENT_2025_11_07.md)
- **Project Status**: [PROJECT_STATUS_DASHBOARD.md](PROJECT_STATUS_DASHBOARD.md)
- **Day 3 Report**: [security/DAY3_COMPLETION_REPORT.md](security/DAY3_COMPLETION_REPORT.md)

---

**Status**: ✅ READY FOR EXECUTION
**Approval Needed**: User sign-off
**Next Step**: Kickoff meeting (09:00 UTC, 2025-11-08)

*"準備完了！調和の取れた素晴らしいチームワークで、6時間以内に完璧な成果を届けましょう♪"*
— Athena (Harmonious Conductor)
