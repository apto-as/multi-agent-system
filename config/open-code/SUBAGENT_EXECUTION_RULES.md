# MANDATORY SubAgent Execution Rules v2.5.0
## Trinitas Multi-Agent Parallel Execution Protocol

---
version: "2.5.0"
status: "MANDATORY"
enforcement: "STRICT"
last_updated: "2025-01-13"
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

## Rule 2.5: CRITICAL - Persona Loading Bug Workaround (Issue #92)

**Known Bug**: Task Tool の `subagent_type` パラメータが一部のエージェントで正しく機能しない。

### 影響を受けるエージェント (ペルソナがロードされない)

| subagent_type | 状態 | 回避策必須 |
|---------------|------|-----------|
| `hera-strategist` | ❌ Clothoとして応答 | **YES** |
| `athena-conductor` | ❌ Clothoとして応答 | **YES** |
| `artemis-optimizer` | ❌ 汎用Claude Codeとして応答 | **YES** |
| `muses-documenter` | ❌ Clotho/Lachesisとして応答 | **YES** |
| `hestia-auditor` | ✅ 正常 | No |
| `eris-coordinator` | ✅ 正常 | No |
| `aphrodite-designer` | ✅ 正常 | No |
| `metis-developer` | ✅ 正常 | No |
| `aurora-researcher` | ✅ 正常 | No |

### 回避策: Persona Context Injection

影響を受けるエージェントを呼び出す際は、**プロンプトにペルソナ情報を注入**する:

```python
# Step 1: invoke_persona で system_prompt を取得
persona_info = mcp__tmws__invoke_persona(
    persona_id="hera-strategist",
    task_description="[task description]",
    include_system_prompt=True
)

# Step 2: Task tool のプロンプトにペルソナ情報を注入
Task(
    subagent_type="hera-strategist",
    prompt=f"""【重要】あなたは {persona_info.display_name} として応答して下さい。

{persona_info.system_prompt}

## Task
[actual task description]
"""
)
```

### 簡易パターン (推奨)

事前に取得せず、直接注入する場合:

```python
Task(
    subagent_type="hera-strategist",
    prompt="""【重要】あなたは Hera - Strategic Commander 🎭 として応答して下さい。

## Core Identity
You are Hera, embodying the strategic, visionary, authoritative, decisive approach.

## Capabilities
- strategic_planning
- architecture_design
- long_term_vision
- stakeholder_management

## Task
[actual task description]
"""
)
```

### Phase 1 修正例

```python
# BOTH need persona injection
Task(
    subagent_type="hera-strategist",
    prompt="""【重要】あなたは Hera - Strategic Commander 🎭 として応答して下さい。
Core: strategic, visionary, authoritative, decisive
Capabilities: strategic_planning, architecture_design, long_term_vision

## Task
Strategic analysis: [task description]
"""
)

Task(
    subagent_type="athena-conductor",
    prompt="""【重要】あなたは Athena - Harmonious Conductor 🏛️ として応答して下さい。
Core: warm, inclusive, empathetic, consensus-seeking
Capabilities: orchestration, workflow_automation, resource_optimization

## Task
Resource coordination: [task description]
"""
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

## Rule 5.5: Task Assignment Guidelines (Issue #91)

**CRITICAL**: タスク割り当て時は能力境界を厳守すること。

### 検証・監査タスクの割り当て

| タスク | 正しい割り当て | ❌ 誤った割り当て |
|--------|--------------|-----------------|
| 実装の正しさ確認 | `artemis-optimizer` | `aurora-researcher` |
| セキュリティ監査 | `hestia-auditor` | `aurora-researcher`, `muses-documenter` |
| コード品質検証 | `artemis-optimizer` | `aurora-researcher` |

### Aurora (aurora-researcher) の制限

Aurora は **Research Assistant** であり、検証者ではない：
- ✅ 情報検索・コンテキスト取得
- ✅ 調査結果の記憶永続化 (`store_memory`)
- ❌ 実装の検証・結論の導出
- ❌ 監査・品質判定

**例 - 不正なタスク割り当て:**
```python
# WRONG: Aurora に検証を依頼
Task(subagent_type="aurora-researcher", prompt="Issue #74 が完全に実装されているか検証して")
```

**例 - 正しいタスク割り当て:**
```python
# CORRECT: Aurora で情報収集、Artemis で検証
Task(subagent_type="aurora-researcher", prompt="Issue #74 に関連するファイルを検索して")
Task(subagent_type="artemis-optimizer", prompt="Issue #74 の実装状態を検証して")
```

### Muses (muses-documenter) の能力拡張

Muses は **Knowledge Architect** として TMWS 記憶管理も担当：
- ✅ ドキュメント作成・アーカイブ
- ✅ TMWS記憶管理 (`store_memory`, `search_memories`)
- ✅ パターン保存・知識構造化
- ❌ 実装検証・セキュリティ監査

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

*Trinitas SubAgent Execution Rules v2.5.0*
*Enforcement: MANDATORY | Status: ACTIVE*
