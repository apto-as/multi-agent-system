# MANDATORY SubAgent Execution Rules v2.4.22
## Trinitas Multi-Agent Parallel Execution Protocol

---
version: "2.4.22"
status: "MANDATORY"
enforcement: "STRICT"
last_updated: "2025-12-13"
---

## CRITICAL: This Document Contains MANDATORY Rules

**These rules are NOT optional. Failure to follow them is a protocol violation.**

---

## Rule 1: Trinitas Full Mode Detection

When ANY of the following patterns are detected in user input:
- "Trinitasフルモード" (Japanese)
- "Trinitas Full Mode" (English)
- "フルモードで作業" (Japanese)
- "full mode execution" (English)
- "/trinitas analyze" with "--personas"

**YOU MUST** immediately invoke SubAgents using the Task tool.

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

The following `subagent_type` values are valid for the Task tool:

| subagent_type | Persona | Tier |
|---------------|---------|------|
| `hera-strategist` | Hera | STRATEGIC |
| `athena-conductor` | Athena | STRATEGIC |
| `artemis-optimizer` | Artemis | SPECIALIST |
| `hestia-auditor` | Hestia | SPECIALIST |
| `eris-coordinator` | Eris | SPECIALIST |
| `muses-documenter` | Muses | SPECIALIST |
| `aphrodite-designer` | Aphrodite | SUPPORT |
| `metis-developer` | Metis | SUPPORT |
| `aurora-researcher` | Aurora | SUPPORT |

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

*Trinitas SubAgent Execution Rules v2.4.22*
*Enforcement: MANDATORY | Status: ACTIVE*
