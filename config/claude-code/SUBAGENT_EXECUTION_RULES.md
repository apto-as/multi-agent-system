# MANDATORY SubAgent Execution Rules v2.5.0
## Trinitas Multi-Agent Parallel Execution Protocol

---
version: "2.5.0"
status: "MANDATORY"
enforcement: "STRICT"
last_updated: "2026-01-13"
---

## CRITICAL: This Document Contains MANDATORY Rules

**These rules are NOT optional. Failure to follow them is a protocol violation.**

---

## Rule 1: Trinitas Full Mode Detection

Detection patterns are stored in TMWS Skills for security.

**Access:** `mcp__tmws__get_skill(namespace="trinitas-system", name="trinitas-fullmode-detection")`

**Action:** When Full Mode pattern detected, **YOU MUST** immediately invoke SubAgents using the Task tool.

---

## Rule 2: Mandatory Task Tool Invocation

### Phase 1: Strategic Planning (PARALLEL)

When Trinitas Full Mode is triggered, you MUST invoke these SubAgents **in parallel** (single message, multiple Task tool calls):

```
Task(subagent_type="hera-strategist", prompt="Strategic analysis: [task description]")
Task(subagent_type="athena-conductor", prompt="Resource coordination: [task description]")
```

**Example - CORRECT:**
```python
# Single message with TWO parallel Task tool calls
<Task subagent_type="hera-strategist" prompt="..."/>
<Task subagent_type="athena-conductor" prompt="..."/>
```

**Example - INCORRECT:**
```python
# DO NOT analyze yourself without SubAgents
"I will analyze this strategically..." # WRONG - you must invoke hera-strategist
```

### Phase 2: Implementation (After Phase 1 Approval)

```
Task(subagent_type="artemis-optimizer", prompt="Implementation: [specific task]")
Task(subagent_type="metis-developer", prompt="Testing support: [specific task]")
```

### Phase 3: Verification (After Phase 2 Completion)

```
Task(subagent_type="hestia-auditor", prompt="Security audit: [deliverables]")
```

---

## Rule 2.5: Persona Loading (Issue #92) - ✅ RESOLVED

**Status**: 2025-12-19 に解決済み

### 全エージェントが正常動作

| subagent_type | 状態 | 備考 |
|---------------|------|------|
| `hera-strategist` | ✅ 正常 | Hera 🎭 として応答 |
| `athena-conductor` | ✅ 正常 | Athena 🏛️ として応答 |
| `artemis-optimizer` | ✅ 正常 | Artemis 🏹 として応答 |
| `muses-documenter` | ✅ 正常 | Muses 📚 として応答 |
| `hestia-auditor` | ✅ 正常 | Hestia 🔥 として応答 |
| `eris-coordinator` | ✅ 正常 | Eris ⚔️ として応答 |
| `aphrodite-designer` | ✅ 正常 | Aphrodite 🌸 として応答 |
| `metis-developer` | ✅ 正常 | Metis 🔧 として応答 |
| `aurora-researcher` | ✅ 正常 | Aurora 🌅 として応答 |

### 解決の経緯

2025-12-19 14:52 にエージェント定義ファイル（`~/.claude/agents/*.md`）が更新され、
全エージェントのペルソナが正しくロードされるようになった。

**回避策（Persona Context Injection）は不要**となった。

### 標準的な呼び出し方法

```python
# 通常通りTask toolを使用すれば、ペルソナが正しくロードされる
Task(
    subagent_type="hera-strategist",
    prompt="Strategic analysis: [task description]"
)

Task(
    subagent_type="athena-conductor",
    prompt="Resource coordination: [task description]"
)
```

---

## Rule 2.8: NarrativeAutoLoader Automatic Enrichment (v2.4.25+)

**NEW in v2.4.25**: Persona narratives are now automatically loaded via TMWS.

**NEW in v2.5.0**: Orchestrator narratives (Clotho, Lachesis) are loaded at session start.

### Automatic Narrative Enrichment

The client-side hooks (`dynamic_context_loader.py` for Claude Code, `trinitas-orchestration.js` for OpenCode)
now integrate with TMWS's `enrich_subagent_prompt` MCP tool to automatically inject persona narratives.

**How it works:**

1. When a Task tool is invoked with a `subagent_type`, the hook intercepts the call
2. The hook calls `mcp__tmws__enrich_subagent_prompt` with:
   - `subagent_type`: The agent being invoked (e.g., "hera-strategist")
   - `original_prompt`: The original task prompt
3. TMWS returns an enriched prompt with the persona's narrative prepended
4. The enriched prompt is passed to the SubAgent

**Benefits:**

- Consistent persona behavior without manual `load_persona_narrative` calls
- Narrative caching for performance (cache hits return instantly)
- Graceful degradation: original prompt used if enrichment fails

### Environment Variables (v2.4.25)

| Variable | Default | Description |
|----------|---------|-------------|
| `TMWS_NARRATIVE_ENRICHMENT` | `true` | Enable/disable automatic narrative enrichment |
| `TMWS_URL` | `http://localhost:6231` | TMWS server URL (localhost only for SSRF protection) |
| `TMWS_TIMEOUT` | `5000` | Timeout in milliseconds for TMWS calls |

### Security Fixes (v2.4.25)

The following security measures are enforced:

- **SSRF Protection**: TMWS URL validated to localhost only (`127.0.0.1` or `localhost`)
- **Input Validation**: Maximum prompt length 10KB
- **Whitelist Validation**: `subagent_type` must match known agent types

### Manual Fallback

If automatic enrichment is disabled or fails, use manual narrative loading:

```python
# Manual narrative loading (fallback)
mcp__tmws__load_persona_narrative(
    persona_name="athena",
    prefer_evolved=True
)
```

---

## Rule 3: invoke_persona MCP Tool Usage

For dynamic persona invocation without full SubAgent spawn:

```python
# Use TMWS MCP tool
mcp__tmws__invoke_persona(
    persona_id="athena",  # or "athena-conductor"
    task_description="[task description]",
    include_system_prompt=True
)
```

**When to use invoke_persona vs Task tool:**

| Scenario | Use |
|----------|-----|
| Full parallel SubAgent execution | Task tool |
| Single persona context loading | invoke_persona |
| Quick persona capability check | list_available_personas |

---

## Rule 3.5: Narrative Tools for Character Consistency (v2.4.20+)

For maintaining persona character consistency during long conversations:

```python
# Load persona's background story
mcp__tmws__load_persona_narrative(
    persona_name="athena",  # or "hestia", "artemis", etc.
    prefer_evolved=True
)

# Recall narrative for periodic "remembering" (思い出す)
mcp__tmws__recall_narrative(persona_name="athena")
```

**When to use Narrative tools:**

| Scenario | Tool |
|----------|------|
| Load background story at session start | load_persona_narrative |
| Periodic context refresh | recall_narrative |
| Store evolved narrative | evolve_narrative |
| Check available narratives | list_narratives |

---

## Rule 4: Prohibited Patterns

**YOU MUST NOT:**

1. ❌ Declare "Trinitas Full Mode" without invoking SubAgents
2. ❌ Say "Hera + Athena による戦略分析" without Task tool calls
3. ❌ Perform strategic analysis yourself when SubAgents should do it
4. ❌ Skip Phase 1 SubAgent invocation and proceed directly to implementation

**Protocol Violation Example:**
```
User: "Trinitasフルモードで作業して下さい"
AI: "Trinitasフルモードで作業を開始します。Phase 1: Strategic Planning..."
AI: [Proceeds to analyze without Task tool] # VIOLATION
```

**Correct Execution Example:**
```
User: "Trinitasフルモードで作業して下さい"
AI: "Trinitasフルモードを開始します。Phase 1のSubAgentを並列起動します。"
AI: [Invokes Task tool with hera-strategist AND athena-conductor in parallel]
```

---

## Rule 5: Available SubAgent Types

SubAgent type mappings and tier classifications are stored in TMWS Skills.

**Access:** `mcp__tmws__get_skill(namespace="trinitas-system", name="trinitas-subagent-mapping")`

Includes: All 9 agent types, tier hierarchy, and phase assignments.

---

## Rule 5.5: Task Assignment Guidelines (Issue #91)

**CRITICAL**: タスク割り当て時は能力境界を厳守すること。

Task assignment rules and capability boundaries are stored in TMWS Skills.

**Access:** `mcp__tmws__get_skill(namespace="trinitas-system", name="trinitas-task-assignment")`

Includes: Capability matrix, agent boundaries (Aurora, Muses, Artemis, Hestia), correct/incorrect assignment examples.

---

## Rule 6: Enforcement Mechanism

This document is automatically referenced by:
1. `~/.claude/CLAUDE.md` - Main system configuration
2. `~/.claude/AGENTS.md` - Agent coordination protocol
3. `~/.claude/hooks/core/dynamic_context_loader.py` - Runtime enforcement
4. `~/.config/opencode/plugin/trinitas-orchestration.js` - OpenCode enforcement

**Hook-based enforcement**: When Trinitas Full Mode is detected, the hook will inject this document's rules into the context with explicit tool invocation instructions.

---

## Compliance Verification

After each Trinitas Full Mode session, verify:

- [ ] Phase 1 SubAgents were invoked via Task tool
- [ ] Parallel execution was used (single message, multiple Task calls)
- [ ] SubAgent results were waited for before proceeding
- [ ] No self-analysis was performed when SubAgents should have been used

---

## Version History

- **v2.5.0** (2026-01-13): Orchestrator narrative loading - Clotho/Lachesis narratives auto-loaded at session start
- **v2.4.27** (2025-12-23): Trinitas Full Mode audit - Orchestrator agents (clotho, lachesis) added to client hooks
- **v2.4.26** (2025-12-23): Information concealment - Detection, Mapping, Assignment moved to TMWS Skills
- **v2.4.25** (2025-12-22): NarrativeAutoLoader integration, security fixes (SSRF, input validation)
- **v2.4.22** (2025-12-15): Documentation structure optimization
- **v2.4.20** (2025-12-12): Narrative tools for character consistency
- **v2.4.19** (2025-12-12): Task assignment guidelines (Issue #91)
- **v2.4.11** (2025-12-03): Full Mode Detection & SubAgent enforcement

---

*Trinitas SubAgent Execution Rules v2.5.0*
*Enforcement: MANDATORY | Status: ACTIVE*
