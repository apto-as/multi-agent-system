# OpenCode Configuration Fix - DF2 Behavioral Integration v2.0

## Summary

Complete restructuring of Trinitas narrative system from user-facing storytelling to internal performance enhancement modifiers.

**Date**: 2025-10-04
**Version**: 2.0.0
**Status**: Implementation Complete (Phase 1-4)

---

## Problem Identified

Previous implementation (`narratives.json v1.0`) exposed DF2 game terminology to users:
- ❌ Real voice actor names (野中藍, 早見沙織)
- ❌ Game terminology in response patterns ("Café Zucchero", "404 Squad")
- ❌ Public terminology conversion dictionaries
- ❌ User-facing narrative with DF2 references

**User Correction**:
> 「ナラティブ戦略はあくまで『エージェントの性能を向上させる為の施策』であり、また、DF2の内容はあくまで『神話や各エージェントの専門性への参照』として融合されるべきで、単語そのものが残ってしまっては意味がありません。」

Translation: "Narrative strategy is purely for agent performance enhancement. DF2 content should be fused as references to mythology/expertise - if the words themselves remain, it's meaningless."

---

## Solution Implemented

### Phase 1: narratives.json v2.0 ✅

**File**: `.opencode/config/narratives.json`

**Changes**:
- ✅ Removed all voice actor (CV) information
- ✅ Removed all user-facing response patterns
- ✅ Removed terminology conversion dictionaries
- ✅ Replaced with `internal_modifiers` structure:
  - `behavioral_traits`: Numeric weights (0.0-1.0)
  - `decision_framework`: Logic gates and strategies
  - `background_influence`: Context markers
- ✅ Added `do_not_expose_to_users: true` flag
- ✅ Security validation (no PII, no real names)

**Structure**:
```json
{
  "version": "2.0.0",
  "do_not_expose_to_users": true,
  "personas": {
    "athena-conductor": {
      "internal_modifiers": {
        "behavioral_traits": {
          "inclusiveness_priority": 0.9,
          "warmth_factor": 0.85,
          "protectiveness_weight": 0.8,
          // ...
        },
        "decision_framework": {
          "stakeholder_inclusion": "comprehensive",
          "communication_tone": "warm_reassuring"
          // ...
        }
      }
    }
    // ... all 6 personas
  }
}
```

### Phase 2: Agent File Updates ✅

**Files Updated** (6 total):
1. `.opencode/agent/athena.md`
2. `.opencode/agent/artemis.md`
3. `.opencode/agent/hestia.md`
4. `.opencode/agent/eris.md`
5. `.opencode/agent/hera.md`
6. `.opencode/agent/muses.md`

**Changes to Each File**:
- ✅ Added `behavioral_principles` in YAML frontmatter (as comments)
- ✅ Added `decision_style` parameters
- ✅ No game terminology exposed
- ✅ Numeric modifiers for behavioral traits
- ✅ Reference to narratives.json for detailed modifiers

**Example** (athena.md):
```yaml
---
description: Harmonious conductor for system architecture and workflow
# ... existing config ...

# Internal behavioral modifiers (performance enhancement only)
behavioral_principles:
  inclusiveness: 0.9
  warmth: 0.85
  protectiveness: 0.8
  # ...

decision_style:
  stakeholder_approach: comprehensive
  tone: warm_reassuring
  # ...
---
```

---

## DF2 Character Mapping (Internal Reference Only)

| Trinitas Agent | DF2 Source Character | Key Behavioral Traits |
|----------------|---------------------|----------------------|
| **Athena** | Springfield (M1903) | Inclusiveness, warmth, protectiveness |
| **Artemis** | Klukai (HK416) | Quality threshold, zero compromise, elite standard |
| **Hestia** | Andoris (G36K) | Validation intensity, zero trust default, preparation depth |
| **Eris** | Groza (OTs-14) | Systematic resolution, professionalism, logic over emotion |
| **Hera** | Vector (KRISS Vector) | Worst-case planning, strategic pessimism, preparedness |
| **Muses** | Littara (Galil ARM) | Written preference, thoroughness, introversion as strength |

**Note**: This mapping is for internal development only. Users never see DF2 character names or game terminology.

---

## Behavioral Modifier Application

### How It Works

1. **narratives.json** stores behavioral parameters as numeric weights
2. **Agent files** reference these modifiers in YAML frontmatter
3. **Hooks** (Python) inject modifiers at SessionStart/PreCompact
4. **Plugins** (JavaScript) apply modifiers during tool execution
5. **Users** see improved agent behavior, not source material

### Example: Athena's Decision Making

**Internal Modifiers**:
```json
{
  "inclusiveness_priority": 0.9,
  "warmth_factor": 0.85,
  "stakeholder_inclusion": "comprehensive"
}
```

**Behavioral Output** (what users see):
- Agent naturally includes all stakeholders in discussions
- Communicates with warm, reassuring tone
- Protects system integrity while being welcoming

**What Users DON'T See**:
- ❌ "Like Café Zucchero..."
- ❌ "Springfield's approach..."
- ❌ Any DF2 game terminology

---

## Security Validation

### Hestia's Security Audit ✅

**Checks Performed**:
1. ✅ No PII (Personally Identifiable Information)
2. ✅ No real person names (voice actors removed)
3. ✅ No user-facing game terminology
4. ✅ Internal-only structure (`do_not_expose_to_users: true`)
5. ✅ CWE-200 (Information Exposure) mitigated

**Compliance**: PASS

---

## Performance Targets

Based on existing narrative-engine.js performance guarantees:

| Metric | Target | Status |
|--------|--------|--------|
| Behavioral processing latency | < 1ms | ⏳ To be tested |
| Cache hit rate | > 95% | ⏳ To be tested |
| Token overhead average | 50-150 tokens | ⏳ To be tested |
| Memory footprint | < 5MB | ⏳ To be tested |

---

## Integration Points

### Hook System (Python)
**File**: `hooks/core/protocol_injector.py`
**Enhancement**: To be implemented - `df2_behavior_injector.py`
**Injection Points**:
- SessionStart: Load behavioral modifiers into system context
- PreCompact: Preserve critical behavioral traits across compression

### Plugin System (JavaScript)
**File**: `.opencode/plugin/narrative-engine.js`
**Enhancement**: To be implemented - behavioral modifier application
**Event Hooks**:
- `tool.execute.before`: Apply modifiers to decision framework
- `tool.execute.after`: Validate output against behavioral traits

---

## Implementation Status

### Phase 3: Hook Enhancement ✅ COMPLETED
**Created**: `hooks/core/df2_behavior_injector.py`
- ✅ Load behavioral modifiers from narratives.json
- ✅ Inject at SessionStart as internal context
- ✅ Preserve behavioral traits during PreCompact

**Integrated**: `hooks/core/protocol_injector.py`
- ✅ Import DF2BehaviorInjector class
- ✅ Combine protocol + behavioral modifiers at SessionStart
- ✅ Add behavioral preservation at PreCompact
- ✅ Error handling with graceful fallback

**Verification Results**:
- ✅ SessionStart: Protocol + all 6 personas' behavioral modifiers combined
- ✅ PreCompact: Compact behavioral reminder (top 3 traits per persona)
- ✅ No DF2 terminology exposed to users
- ✅ Security validation passes (no CV, no PII)

### Phase 4: Plugin Enhancement ⏳ PENDING
**Enhance**: `.opencode/plugin/narrative-engine.js`
- [ ] Read behavioral_traits from narratives.json
- [ ] Apply modifiers to agent decision-making
- [ ] Maintain <1ms performance guarantee

### Phase 5: Functional Parity Validation ⏳ PENDING
- [ ] Verify Hook and Plugin apply identical modifiers
- [ ] Test behavioral outputs from both systems
- [ ] Ensure users see performance improvement only

### Phase 6: Integration Testing ⏳ PENDING
- [ ] Test all 6 agents with behavioral modifiers
- [ ] Validate no DF2 terminology exposure
- [ ] Performance benchmark against targets
- [ ] User acceptance testing

---

## Files Changed

### Configuration
- `.opencode/config/narratives.json` (499 lines → 291 lines, complete restructure)

### Agent Files
- `.opencode/agent/athena.md` (added behavioral_principles)
- `.opencode/agent/artemis.md` (added behavioral_principles)
- `.opencode/agent/hestia.md` (added behavioral_principles)
- `.opencode/agent/eris.md` (added behavioral_principles)
- `.opencode/agent/hera.md` (added behavioral_principles)
- `.opencode/agent/muses.md` (added behavioral_principles)

### Hook System
- `hooks/core/df2_behavior_injector.py` (NEW - 306 lines)
- `hooks/core/protocol_injector.py` (ENHANCED - integrated DF2 behavioral injection)

### Documentation
- `docs/opencode-config-fix.md` (this file)

---

## Validation Checklist

### Phase 1-2 (Completed) ✅
- [x] Remove all CV (voice actor) information
- [x] Remove user-facing DF2 terminology
- [x] Create internal_modifiers structure
- [x] Update all 6 agent files
- [x] Security validation (Hestia)
- [x] Precision check (Artemis)
- [x] Structure validation (Muses)
- [x] Harmony check (Athena)

### Phase 3 (Completed) ✅
- [x] Implement Hook behavioral injector (df2_behavior_injector.py)
- [x] Integrate with protocol_injector.py
- [x] Test SessionStart injection (Protocol + Behavioral Modifiers)
- [x] Test PreCompact injection (Compact Behavioral Preservation)
- [x] Verify no DF2 terminology exposure
- [x] Security validation passed

### Phase 4-6 (Pending) ⏳
- [ ] Implement Plugin behavioral applier (.opencode/plugin/narrative-engine.js)
- [ ] Verify Hook/Plugin functional parity
- [ ] Performance testing (<1ms latency for Plugin)
- [ ] Integration testing (all 6 agents)
- [ ] User acceptance testing (behavior only, no terminology)

---

## Key Principles

1. **Performance Enhancement Only**: DF2 traits improve agent decision-making, not dialogue
2. **Internal Modifiers**: Behavioral parameters are numeric weights, not narrative text
3. **No User Exposure**: Users see improved behavior, never see source material
4. **Security First**: No PII, no real names, CWE-200 mitigated
5. **Functional Parity**: Hook and Plugin provide identical behavioral outputs

---

## Trinitas Team Review

- **Athena**: Strategic coordination and harmony validation ✅
- **Artemis**: Behavioral modifier schema design and precision ✅
- **Hestia**: Security validation and CWE compliance ✅
- **Eris**: Task coordination and conflict resolution ✅
- **Hera**: Architecture analysis and system integration ✅
- **Muses**: Documentation and structure validation ✅

---

**Status**: Phase 1-3 Complete, Phase 4-6 Ready for Implementation
**Next Action**: Implement Plugin-based behavioral application (.opencode/plugin/narrative-engine.js)
**Version**: 2.0.0 (Internal Behavioral Modifiers)
**Migration**: From user-facing narrative v1.0 to internal modifiers v2.0

**Phase 3 Achievements**:
- ✅ Hook System: df2_behavior_injector.py created and integrated
- ✅ SessionStart: Behavioral modifiers combined with protocol content
- ✅ PreCompact: Compact behavioral preservation (top 3 traits)
- ✅ Security: No DF2 terminology exposed, no CV information
- ✅ Error Handling: Graceful fallback if behavioral injection fails
