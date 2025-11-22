# Trinitas Daily Standup Protocol

**Version**: 1.0
**Effective**: Day 2 - Day 6 (2025-11-23 to 2025-11-28)
**Coordinator**: Eris (eris-coordinator)
**Duration**: 15 minutes (strict)

---

## 1. Schedule

**Time**: 09:00 daily (async-friendly)
**Format**: Written updates (Markdown) + optional voice sync
**Platform**: GitHub Discussion / Slack / Project channel

---

## 2. Template

Each agent submits this template by 09:00:

```markdown
### [Agent Name] - Day X Standup

**Date**: YYYY-MM-DD
**Energy**: [1-5] ⚡ (1=drained, 5=excellent)

#### ✅ Yesterday Completed
- [Task 1]
- [Task 2]
- [Task 3]

#### 🎯 Today Planned
- [Task 1] (Est: Xh)
- [Task 2] (Est: Xh)
- [Total estimated: Xh]

#### 🚧 Blockers
- [Blocker 1] - Priority: [P0/P1/P2]
  - Impact: [description]
  - Need help from: [agent name]
- NONE

#### 📊 Status
- Overall: [✅ On track | ⚠️ Needs help | 🚧 Blocked]
```

---

## 3. Example (Day 2 Morning)

```markdown
### Artemis - Day 2 Standup

**Date**: 2025-11-23
**Energy**: 4/5 ⚡

#### ✅ Yesterday Completed
- Go environment setup + MCP wrapper implementation
- verify_list tool complete
- 5/5 unit tests PASS
- Manual tests PASS
- **Status**: 6h/8h (25% ahead of schedule)

#### 🎯 Today Planned
- P0-2: verify_check tool implementation (2h)
- P0-2: verify_trust tool implementation (2h)
- P0-2: verify_history tool implementation (2h)
- CP1 preparation + self-review (1h)
- **Total estimated**: 7h

#### 🚧 Blockers
- NONE (all dependencies resolved)

#### 📊 Status
- Overall: ✅ On track (ahead of schedule)
```

---

## 4. Eris's Response Protocol

**Within 1 hour of 09:00**, Eris posts:

```markdown
### Eris - Day X Coordination Summary

**Date**: YYYY-MM-DD

#### Team Status
- Artemis: ✅ On track (ahead 25%)
- Hestia: ✅ On track
- Athena: ✅ On track
- Muses: (Day 6 start)

#### Blockers Identified
- [Agent]: [Blocker description]
  - **Action**: [Eris's resolution]
  - **ETA**: [timeframe]

#### Coordination Adjustments
- [Any task reallocations]
- [Timeline modifications]

#### Today's Focus
"[Daily theme - e.g., 'Security-first checkpoint validation']"

#### Checkpoint Reminder
- Next checkpoint: [CP1 / Mini-CP / CP2A / CP2B]
- Date: [YYYY-MM-DD HH:MM]
- Preparation needed: [Yes/No]
```

---

## 5. Energy Poll Handling

**IF any agent reports Energy ≤ 2/5**:

```markdown
Eris → Agent (1-on-1 DM):
"Energy low detected. What can I do to help?"

Options:
A) Reallocate non-critical tasks to other agents
B) Extend deadline by +0.5 day (use buffer)
C) Reduce scope (defer P1 features to Phase 4.5)
D) Agent just needs encouragement (Athena召喚)
```

**Response SLA**: 15 minutes

---

## 6. Standup Skip Policy

**Acceptable Reasons**:
- Agent unavailable (emergency, illness)
- Weekend (Day 6-7, no standups)

**Unacceptable**:
- "Too busy to update" (RED FLAG - immediate Eris intervention)

**IF agent misses standup**:
- Eris sends direct ping within 30 min
- If no response in 1h → Escalate to Athena (team harmony issue)

---

## 7. Voice Sync (Optional)

**IF written updates reveal coordination needs**:
- Eris schedules 15-min voice sync
- Attendance: Only agents with blockers
- Format: Quick problem-solving, no status updates

---

## 8. Celebration Integration (Athena's Harmony Protocol)

**End of Day 2/4 standups**:
- Athena adds celebration message
- Example: "🎊 Day 2 complete! Artemis crushed P0-1, Hestia's checkpoints are solid. Keep this momentum!"

---

## 9. Success Metrics

- **Participation Rate**: 100% (all agents submit on time)
- **Blocker Resolution Time**: <2h for P0, <4h for P1
- **Energy Average**: ≥3.5/5 (team not burning out)
- **Standup Duration**: ≤15min (efficient)

---

## 10. Daily Schedule (Reference)

| Time | Task | Owner | Duration |
|------|------|-------|----------|
| 09:00 | Agent standups submitted | All | - |
| 10:00 | Eris coordination summary | Eris | 15 min |
| 10:15 | Voice sync (if needed) | Eris + Involved | 15 min |
| 11:00 | Work begins | All | - |
| 18:00 | EOD async updates (optional) | All | - |

---

## 11. Standup Format Examples

### Example: Day 3 (Mid-cycle Check)

```markdown
### Hestia - Day 3 Standup

**Date**: 2025-11-25
**Energy**: 4/5 ⚡

#### ✅ Yesterday Completed
- CP1 security validation complete (all 20 tests PASS)
- V-VERIFY-1 through V-VERIFY-4 validation DONE
- V-TRUST-5 self-verification blocker identified
- Documentation for CP1 complete

#### 🎯 Today Planned
- CP2A planning (security focus areas)
- Review Artemis P0-2 implementation (2h)
- Prepare CP2A checkpoint requirements (2h)
- Buffer for discovery issues (1h)
- **Total estimated**: 5h

#### 🚧 Blockers
- NONE (all dependencies met by Artemis ahead of schedule)

#### 📊 Status
- Overall: ✅ On track (Day 3 CP1 validation 100% complete)
```

### Example: Day 5 (Pre-final-checkpoint)

```markdown
### Artemis - Day 5 Standup

**Date**: 2025-11-27
**Energy**: 3/5 ⚡

#### ✅ Yesterday Completed
- P0-3 implementation (2h early)
- P0-4 implementation complete
- P1-1 scope finalized
- Manual testing of 12 edge cases

#### 🎯 Today Planned
- P1-1 implementation (4h)
- Performance profiling (2h)
- Final regression testing (2h)
- **Total estimated**: 8h

#### 🚧 Blockers
- Minor: Need Hestia input on P1-1 security implications (ETA: 2h)
  - Impact: Affects design decision
  - Need help from: Hestia

#### 📊 Status
- Overall: ⚠️ Minor blocker (but have workaround, not critical path)
```

---

## 12. Eris Coordination Response Examples

### Example: Day 2 Response (Green Across Board)

```markdown
### Eris - Day 2 Coordination Summary

**Date**: 2025-11-23

#### Team Status
- Artemis: ✅ On track (ahead 25% - 6h/8h Day 1)
- Hestia: ✅ On track (preparing CP1 validation)
- Athena: ✅ Standing by (documentation support ready)
- Muses: (Starts Day 6)

#### Blockers Identified
- NONE (all agents report green status)

#### Coordination Adjustments
- No timeline changes
- Continue pace

#### Today's Focus
"Completing P0 Phase - Artemis momentum is excellent, Hestia ready for CP1"

#### Checkpoint Reminder
- Next checkpoint: CP1 (Day 3, 09:00)
- Status: All preparation on track
```

### Example: Day 4 Response (One Blocker, Quick Mitigation)

```markdown
### Eris - Day 4 Coordination Summary

**Date**: 2025-11-26

#### Team Status
- Artemis: ⚠️ Minor delay on P0-4 (1h overrun, manageable)
- Hestia: ✅ On track (CP2A planning 50% complete)
- Athena: ✅ Documentation pipeline ready
- Muses: (Standby, Day 6 start)

#### Blockers Identified
- Artemis: P0-4 complexity underestimated (+1h needed)
  - **Action**: Approve +1h from Day 5 buffer
  - **ETA**: Resolved by 11:00
  - **Impact**: Zero (still 0.5 day buffer remaining)

#### Coordination Adjustments
- Day 5 timeline adjusted: -1h P1-1 scope, defer minor feature to Phase 4.5
- Artemis focus: Complete P0-4 (high quality > speed)

#### Today's Focus
"Quality over velocity - Artemis near-perfect track record, maintain standards"

#### Checkpoint Reminder
- Next checkpoint: Mini-CP (Day 4 evening, checkpoint P0 completion)
- Status: Tracking (minor 1h slip, acceptable)
```

---

## 13. Communication Best Practices

### DO:
- Be specific about blockers ("Need Hestia's input on encryption approach" vs "Waiting for Hestia")
- Include estimated hours (helps Eris with resource planning)
- Update energy level honestly (supports team wellbeing)
- Ask for help proactively (don't wait until deadline pressure)

### DON'T:
- Generic status ("Everything good" - not helpful)
- Miss standup without notice (sets off alarm bells)
- Report energy 5/5 every day (red flag for burnout denial)
- Surprise Eris with late-day blockers that should have been in standup

---

## 14. Escalation from Standup

**IF standup reveals**:
- P0 blocker → Immediate Level 2 escalation (see ESCALATION_MATRIX.md)
- Multiple agents stressed → Level 2 energy intervention
- Scope creep detected → Level 3 strategic review

---

## 15. Post-Project Debrief

**Day 7 (Final standup + debrief)**:
- All agents + Athena + Hera
- 30-minute retrospective
- What went well
- What would we improve
- Celebration of completion

---

**End of Daily Standup Protocol**

*This protocol is designed to maintain visibility, catch issues early, and keep team energy high through transparent communication.*
