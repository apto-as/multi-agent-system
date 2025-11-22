# Day 2 Quick Start - Standup & Escalation

**Deployment Date**: 2025-11-23 (Day 2)
**First Standup**: 09:00 sharp
**Coordinator**: Eris (eris-coordinator)

---

## For Each Agent: Day 2 Standup

**Deadline**: 09:00 on 2025-11-23
**Format**: Copy template, fill in, submit to project channel

```markdown
### [Your Name] - Day 2 Standup

**Date**: 2025-11-23
**Energy**: [1-5] ⚡

#### ✅ Yesterday Completed
- Task 1
- Task 2
- Task 3

#### 🎯 Today Planned
- Task 1 (Est: Xh)
- Task 2 (Est: Xh)
- **Total estimated**: Xh

#### 🚧 Blockers
- NONE

#### 📊 Status
- Overall: ✅ On track
```

---

## For Eris: Day 2 Coordination

**Your Actions**:
1. **09:00 - 10:00**: Receive all agent standups
2. **10:00 - 10:15**: Write coordination summary
3. **10:15 onwards**: Monitor for issues

**Coordination Summary Template**:

```markdown
### Eris - Day 2 Coordination Summary

**Date**: 2025-11-23

#### Team Status
- Artemis: ✅ [status + note]
- Hestia: ✅ [status + note]
- Athena: ✅ [status + note]
- Muses: [status - starts Day 6]

#### Blockers Identified
- NONE expected

#### Today's Focus
"Completing P0-1 implementation, preparing for CP1"

#### Checkpoint Reminder
- Next: CP1 (Day 3, 09:00)
- Preparation: On track
```

---

## Priority Quick Reference

| When | Do This | SLA |
|------|---------|-----|
| Agent has quick question | Ask directly (Level 1) | 30 min |
| Question times out | Tell Eris | 1 hour |
| P0 issue (build broken, agent down) | Ping Eris immediately | 15 min |
| P1 issue (test fails, timeline risk) | Report in standup or DM Eris | 2 hours |
| P2 issue (documentation gap) | Report in standup | 8 hours |

---

## Escalation Cheat Sheet

**Level 1** (Agent ↔ Agent):
- Technical questions
- Collaboration
- Peer review
- **Timeout**: 30 min → escalate to Level 2

**Level 2** (All → Eris):
- Timeline risk
- Resource conflict
- P0 issues
- **Timeout**: 1 hour → escalate to Level 3

**Level 3** (Athena + Hera):
- Major scope changes
- Strategic decisions
- Level 2 unresolved
- **Timeout**: 2 hours → user escalation

**Emergency** (Immediate):
- Agent unavailable
- Security vulnerability
- Build broken
- **Response**: 15 min (Eris)

---

## Day 2 Expected Timeline

| Time | Who | What | Expected Result |
|------|-----|------|-----------------|
| 09:00 | All | Submit standup | All updates received |
| 10:00 | Eris | Coordination summary | Team aligned |
| 11:00 | All | Resume work | P0-1 implementation |
| 14:00 | Eris | Energy check | All energized ≥3/5 |
| 18:00 | All | EOD update (optional) | Progress visible |

---

## If Something Goes Wrong (Decision Tree)

```
Agent has a problem
    ↓
Can they solve it alone?
    ├─ YES → Do it
    └─ NO → Ask another agent
              ↓
          Agent B responds?
              ├─ YES in 30 min → Done ✅
              └─ NO → Tell Eris
                       ↓
                    Eris decides
                    (Level 2)
                       ↓
                    Continue work
```

---

## Communication Rules

- **Standup**: Be specific ("P0-2 needs 2h more" vs "Might need help")
- **Blockers**: Report immediately (don't wait for standup)
- **Energy**: Answer honestly (3/5 is OK, don't fake 5/5)
- **Status**: ✅ On track | ⚠️ Needs help | 🚧 Blocked (pick one)

---

## Eris's Day 2 Checklist

- [ ] 09:30 - All standups received (or first reminder sent)
- [ ] 10:00 - Coordination summary written and posted
- [ ] 10:30 - No blockers reported? Confirm all green
- [ ] 12:00 - Mid-day energy check: All agents ≥3/5?
- [ ] 17:00 - Any issues that need Level 2 escalation?
- [ ] 18:00 - Day 2 complete, prepare Day 3 preview

---

## Artifacts for Reference

- Full protocol: `docs/coordination/DAILY_STANDUP_PROTOCOL.md` (350 lines)
- Escalation matrix: `docs/coordination/ESCALATION_MATRIX.md` (600 lines)
- Overview: `docs/coordination/README.md` (242 lines)

---

## Troubleshooting

**Q: Agent misses standup?**
A: Eris sends DM by 10:00. If no response by 11:00 → escalate to Athena (harmony issue)

**Q: Blocker discovered at 14:00?**
A: Report immediately to Eris via DM. Don't wait for standup. Response SLA applies.

**Q: Energy reported as 2/5?**
A: Eris DMs immediately: "What can I do to help?" Offer to reallocate, extend, reduce scope.

**Q: Standup reveals two agents disagree?**
A: Eris facilitates 15-min discussion. If unresolved → Level 2 escalation.

**Q: Checkpoint at risk?**
A: Eris escalates immediately to Level 3 (Athena + Hera). Don't wait.

---

## Day 2 Success = ✅

- All 3 agents submit standups on time
- No P0 blockers
- Artemis P0-1 implementation on track
- Team energy ≥3.5/5
- Checkpoint prep on schedule
- Zero escalations needed (great sign!)

---

**Ready for Day 2 deployment at 09:00 on 2025-11-23**

*Eris's coordination protocols are live. Let's keep the momentum and maintain team alignment throughout the week.*
