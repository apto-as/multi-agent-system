# Context Engineering Techniques - Reference Guide

**Source**: Anthropic Engineering - Effective Context Engineering for AI Agents
**Analyzed**: 2025-11-20
**Analyst**: Muses (Knowledge Architect)
**Context**: TMWS Phase 4+ Planning - Context Optimization & Configuration Simplification

---

## Executive Summary

Context engineering optimizes the finite token budget available to large language models by determining "what configuration of context is most likely to generate our model's desired behavior." This guide extracts Anthropic's proven techniques for context optimization, with direct applications to TMWS's goal of 80% context reduction.

**Key Finding**: The optimal approach balances specificity (avoiding vague, context-assuming guidance) with flexibility (avoiding brittle, hardcoded logic) at the "right altitude" of abstraction.

---

## Context Hierarchy Structure

### System Prompt Organization

Anthropic recommends organizing prompts into distinct sections using XML tagging or Markdown headers:

```xml
<background_information>
  <!-- Domain knowledge, constraints, assumptions -->
</background_information>

<instructions>
  <!-- Step-by-step guidance, decision trees -->
</instructions>

<tool_guidance>
  <!-- Tool-specific usage patterns, best practices -->
</tool_guidance>

<output_description>
  <!-- Expected output format, quality criteria -->
</output_description>
```

**Alternative (Markdown Headers)**:
```markdown
## Background Information
...

## Instructions
...

## Tool Guidance
...

## Output Description
...
```

### Right Altitude Principle

**Definition**: Instructions should be "specific enough to guide behavior effectively, yet flexible enough to provide strong heuristics without over-prescription."

**Examples**:

**Too Vague (Wrong Altitude)**:
```
Be helpful and accurate.
```

**Too Specific (Wrong Altitude)**:
```
If user asks about databases:
  1. Check if PostgreSQL is mentioned
     a. If yes, recommend version 15.3
     b. If no, ask "Which database?"
  2. If user mentions performance:
     a. Check if "slow queries" mentioned
        i. If yes, suggest EXPLAIN ANALYZE
        ii. If no, suggest indexing strategy
...
```

**Right Altitude**:
```
Provide database recommendations based on:
- Workload characteristics (read-heavy, write-heavy, analytical)
- Scale requirements (expected data volume, query patterns)
- Team expertise (existing knowledge, operational capacity)

Use diagnostic tools (EXPLAIN, profiling) to identify bottlenecks before
suggesting optimizations. Prioritize solutions with measurable impact.
```

**Application to TMWS**:
- Current Rule 1-11 in CLAUDE.md: Often too specific (hardcoded examples)
- Target: Elevate to principles with flexible heuristics
- Example: "Measure before reporting" vs. "Run pytest, check coverage, record 5 metrics..."

---

## Optimization Techniques

### Chunking Strategies

#### 1. Message-Level Chunking (Compaction)

**Definition**: Summarize context windows nearing capacity limits and reinitialize with condensed summaries.

**What to Preserve**:
- Architectural decisions
- Unresolved bugs
- Implementation details
- Critical constraints

**What to Discard**:
- Redundant tool outputs (already processed)
- Redundant messages (duplicate information)
- Intermediate exploration steps (dead-ends)

**Implementation Pattern**:
```python
async def compact_context(messages: List[Message], threshold: int = 150000):
    """Compact context when approaching token limit"""
    if count_tokens(messages) < threshold:
        return messages

    # Phase 1: Identify compactable messages
    compactable = [
        msg for msg in messages
        if msg.type in ["tool_result", "intermediate_reasoning"]
        and not msg.contains_critical_info()
    ]

    # Phase 2: Generate summary
    summary = await generate_summary(
        compactable,
        preserve=[
            "architectural_decisions",
            "unresolved_bugs",
            "implementation_details"
        ]
    )

    # Phase 3: Rebuild context
    return [
        messages[0],  # System prompt
        Message(role="assistant", content=summary),
        *[msg for msg in messages if msg not in compactable]
    ]
```

**Performance Impact**:
- Token reduction: 40-70% (depending on redundancy)
- Quality preservation: High (critical info retained)
- Latency overhead: +500-1000ms (summary generation)

**TMWS Application**:
- Long-running workflow executions (>50 steps)
- Multi-hour task tracking (Trinitas coordination)
- Audit trail preservation (security events)

#### 2. Tool Result Clearing (Lightweight Compaction)

**Principle**: Remove raw tool results from deep message history since agents shouldn't need to revisit them.

**Example**:
```python
async def clear_old_tool_results(messages: List[Message], keep_recent: int = 10):
    """Clear tool results beyond recent window"""
    tool_results = [msg for msg in messages if msg.type == "tool_result"]

    # Keep recent tool results (last N)
    recent_results = tool_results[-keep_recent:]

    # Clear older results
    return [
        msg if msg not in tool_results or msg in recent_results
        else Message(role="tool", content="[Result cleared]")
        for msg in messages
    ]
```

**Performance Impact**:
- Token reduction: 10-30% (tool results often large)
- Quality preservation: High (recent results retained)
- Latency overhead: Negligible (<10ms)

**TMWS Application**:
- Database query results (keep only recent)
- Vector search results (summarize or discard old searches)
- File read operations (cache or clear stale file contents)

#### 3. Semantic Chunking (Content-Aware)

**Principle**: Split content at semantic boundaries (paragraphs, sections, logical units) rather than arbitrary token counts.

**Example**:
```python
def semantic_chunk(text: str, max_tokens: int = 2000) -> List[str]:
    """Chunk text at semantic boundaries"""
    chunks = []
    current_chunk = []
    current_tokens = 0

    # Split on section headers or paragraphs
    sections = text.split("\n\n")

    for section in sections:
        section_tokens = count_tokens(section)

        if current_tokens + section_tokens > max_tokens:
            # Finalize current chunk
            chunks.append("\n\n".join(current_chunk))
            current_chunk = [section]
            current_tokens = section_tokens
        else:
            current_chunk.append(section)
            current_tokens += section_tokens

    if current_chunk:
        chunks.append("\n\n".join(current_chunk))

    return chunks
```

**TMWS Application**:
- Documentation chunking (CLAUDE.md → skills)
- Code file processing (chunk by function/class boundaries)
- Audit log summarization (chunk by time windows or event types)

---

### Compression Methods

#### 1. Context Rot Mitigation

**Problem**: "Context rot" — as token count increases, models' ability to accurately recall information decreases.

**Research Finding**: Performance degradation is gradual, not a hard cliff. Models trained on shorter sequences have fewer specialized parameters for context-wide dependencies.

**Mitigation Strategies**:

**Strategy A: Information Density Maximization**
```
Bad (low density):
"The user wants to create a new database table. The table should have
columns for user ID, username, email, and creation timestamp. The user
ID should be the primary key. The email should be unique."

Good (high density):
"CREATE TABLE users (
  id UUID PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);"
```

**Strategy B: Redundancy Elimination**
```python
def remove_redundant_info(context: str) -> str:
    """Remove repeated information"""
    seen_facts = set()
    deduplicated = []

    for sentence in context.split(". "):
        # Semantic deduplication (embedding similarity)
        if not is_semantically_similar(sentence, seen_facts):
            deduplicated.append(sentence)
            seen_facts.add(sentence)

    return ". ".join(deduplicated)
```

**Strategy C: Progressive Summarization**
```
Level 1 (Recent): Full detail (last 10 messages)
Level 2 (Medium): Summarized (messages 11-50)
Level 3 (Old): High-level summary (messages 51+)
```

**TMWS Application**:
- Workflow execution history (progressive summarization by age)
- Learning pattern history (summarize old successful patterns)
- Security audit logs (detailed recent, summarized historical)

#### 2. Abbreviation and Symbolic Compression

**Technique**: Use concise symbols for frequently-repeated concepts.

**Example**:
```
Before:
"The Memory Service creates a new memory object in the SQLite database
and then generates embeddings using the Ollama service, which are stored
in ChromaDB for semantic search. The Memory Service also enforces
namespace isolation to ensure security..."

After:
"MemSvc: SQLite → Ollama embeddings → ChromaDB. Enforces namespace isolation."

Legend:
- MemSvc: Memory Service
- SQLite: Metadata storage
- ChromaDB: Vector storage
- Namespace isolation: Multi-tenant security
```

**Considerations**:
- Define abbreviations in system prompt or background
- Use only for frequently-repeated concepts (>5 occurrences)
- Avoid cryptic abbreviations (maintain readability)

**TMWS Application**:
- API documentation (use consistent abbreviations)
- Workflow step descriptions (symbolic notation)
- Error messages (structured codes vs. verbose text)

#### 3. Structured Data Encoding

**Principle**: Use efficient structured formats (JSON, YAML, tables) instead of verbose prose.

**Example**:
```
Verbose:
"The agent has completed 15 tasks today. 12 were successful, 2 failed,
and 1 is pending. The average completion time was 45 seconds. The agent
consumed 1.2M tokens and made 150 API calls."

Structured:
{
  "tasks": {"total": 15, "success": 12, "failed": 2, "pending": 1},
  "avg_time": "45s",
  "tokens": "1.2M",
  "api_calls": 150
}
```

**Token Savings**: ~60-70% (structured vs. prose)

**TMWS Application**:
- Task status summaries
- Performance metrics
- Configuration snapshots

---

### Lazy Loading Patterns

#### Pattern 1: Identifier-Based Loading

**Principle**: Maintain lightweight identifiers (file paths, URLs, queries) and dynamically load information at runtime using tools.

**Example**:
```python
# Bad: Preload all files
context = {
    "migration_001": read_file("migrations/001_initial.py"),  # 500 lines
    "migration_002": read_file("migrations/002_add_auth.py"),  # 300 lines
    # ... 50+ migrations
}

# Good: Store paths, load on-demand
context = {
    "migrations": [
        "migrations/001_initial.py",
        "migrations/002_add_auth.py",
        # ... paths only
    ]
}

# Agent loads specific migration when needed
migration_content = read_file(context["migrations"][2])
```

**Token Savings**: 95%+ (paths vs. full content)

**TMWS Application**:
- Documentation references (paths, not content)
- Code examples (paths, not full implementations)
- Test fixtures (identifiers, not data)

#### Pattern 2: Progressive Exploration

**Principle**: Agents incrementally discover context through exploration, with each interaction informing the next decision.

**Claude Code Example** (from article):
```
1. Agent: "What files are in this project?"
   Tool: ls (returns file list)

2. Agent: "Show me the main application file."
   Tool: cat src/main.py (returns content)

3. Agent: "What imports does this use?"
   Tool: grep "^import" src/main.py (returns import lines)

4. Agent: "Show me the database configuration."
   Tool: cat src/config/database.py (returns config)
```

**Benefits**:
- No stale indexing required
- No complex parsing upfront
- Agent-driven context discovery
- Minimal unnecessary context loading

**TMWS Application**:
- Codebase exploration (glob → read → analyze pattern)
- Documentation navigation (outline → section → detail)
- Workflow debugging (summary → failed step → logs)

#### Pattern 3: Hybrid Upfront + On-Demand

**Principle**: Load critical baseline context upfront, defer supplementary details to on-demand loading.

**CLAUDE.md Transformation Example**:
```
Current (all upfront):
- Core rules (1,500 lines)
- Security incidents (800 lines)
- Tool guidelines (500 lines)
- TMWS specifics (1,000 lines)
Total: ~3,800 lines (~15,000 tokens)

Proposed (hybrid):
Upfront (Level 1):
- Persona metadata (600 tokens)
- Critical security rules (400 tokens)
- TMWS architecture summary (300 tokens)
Total: ~1,300 tokens

On-Demand (Level 2+):
- Load persona details when task matches trigger
- Load security playbooks when audit requested
- Load tool specifics when tool invoked
- Load TMWS details when needed for implementation
```

**Token Savings**: 80-90% baseline context

**TMWS Application**: Primary Phase 4 strategy

---

## Trade-off Analysis

### Approach Comparison Matrix

| Approach | Context Size | Quality | Latency | Cost | Complexity |
|----------|-------------|---------|---------|------|-----------|
| **Full Preload** | High (10K+ tokens) | High | Low (0ms) | High | Low |
| **Lazy Loading** | Low (1K tokens) | High | Medium (+50ms) | Low | Medium |
| **Compaction** | Medium (5K tokens) | Medium | Low (+20ms) | Medium | High |
| **Progressive Disclosure** | Low (1K base) | High | Low (+10ms) | Low | Medium |
| **Hybrid (Recommended)** | Medium (2-3K) | High | Low (+15ms) | Low | Medium |

### Detailed Trade-off Analysis

#### Full Preload
**Pros**:
- Zero latency overhead (all context immediately available)
- Simplest implementation
- No on-demand loading complexity

**Cons**:
- Extreme context rot (models struggle with >10K tokens)
- High token costs (every request pays full context)
- Maintenance burden (update entire context for any change)
- Inflexible (can't adapt to task-specific needs)

**Use Case**: Simple, single-purpose agents with minimal context requirements (<2K tokens)

#### Lazy Loading
**Pros**:
- Minimal baseline context (95%+ reduction)
- Task-adaptive (load only what's needed)
- Efficient token usage

**Cons**:
- Latency overhead (+50-100ms per load)
- Implementation complexity (identifier management)
- Potential for over-loading (agent loads unnecessary resources)

**Use Case**: Complex agents with large potential context surfaces (TMWS)

#### Compaction
**Pros**:
- Handles unbounded task horizons (multi-hour work)
- Preserves critical information
- Moderate token efficiency

**Cons**:
- Summary generation overhead (+500-1000ms)
- Information loss risk (if summary inadequate)
- High implementation complexity (what to preserve?)

**Use Case**: Long-running agents with extensive conversation history

#### Progressive Disclosure (Agent Skills Pattern)
**Pros**:
- Optimal baseline context (90%+ reduction)
- High-quality task-specific loading
- Low latency overhead (+10-20ms)

**Cons**:
- Moderate implementation complexity (three-level hierarchy)
- Requires metadata curation

**Use Case**: Multi-skill agents with diverse capabilities (Trinitas)

#### Hybrid Approach (Recommended for TMWS)
**Pros**:
- Balances baseline context and on-demand loading
- Flexible adaptation to task complexity
- Moderate implementation burden

**Cons**:
- Requires careful tuning (what's baseline vs. on-demand?)
- Potential for suboptimal splits

**Use Case**: Production agents with moderate context needs and diverse tasks

---

## Caching Strategies

### 1. Prompt Caching (Anthropic Feature)

**Mechanism**: Claude caches static system prompt prefixes, reducing token costs and latency for repeated requests.

**Example**:
```python
# Cacheable prefix (static)
system_prompt_prefix = """
<background_information>
You are the TMWS Memory Service, responsible for...
</background_information>

<core_instructions>
1. Enforce namespace isolation
2. Use async/await for all I/O
3. Validate access control
</core_instructions>
"""

# Dynamic suffix (not cached)
system_prompt_suffix = f"""
<current_context>
Current namespace: {namespace}
Current agent: {agent_id}
Task: {task_description}
</current_context>
"""
```

**Performance Impact**:
- Cost reduction: 50-90% (cached tokens don't count)
- Latency reduction: 30-50% (cached prompt loads faster)

**Best Practices**:
- Place static content at beginning of prompt
- Separate dynamic content into suffix
- Use caching for prompts >1K tokens
- Update cache only when static content changes

**TMWS Application**:
- Cache Trinitas persona metadata (rarely changes)
- Cache TMWS architecture summary (static)
- Cache security rules (stable)
- Dynamic: current task, namespace, agent context

### 2. Tool Result Caching

**Principle**: Cache expensive tool results (database queries, API calls) to avoid redundant executions.

**Example**:
```python
from functools import lru_cache
from datetime import datetime, timedelta

class ToolResultCache:
    def __init__(self, ttl: int = 300):  # 5 min default
        self.cache = {}
        self.ttl = ttl

    async def get_or_execute(self, key: str, tool_fn, *args):
        now = datetime.now()

        if key in self.cache:
            result, timestamp = self.cache[key]
            if now - timestamp < timedelta(seconds=self.ttl):
                return result  # Cache hit

        # Cache miss, execute tool
        result = await tool_fn(*args)
        self.cache[key] = (result, now)
        return result

# Usage
cache = ToolResultCache(ttl=300)

result = await cache.get_or_execute(
    f"search:{query}",
    memory_service.search_semantic,
    query, top_k=10
)
```

**Performance Impact**:
- Latency reduction: 90%+ (cache hit vs. execution)
- Token savings: 100% (no tool result in context if cached in memory)

**TMWS Application**:
- Semantic search results (TTL: 5 min)
- Database metadata queries (TTL: 15 min)
- Agent capabilities lookup (TTL: 1 hour)

### 3. Semantic Deduplication Cache

**Principle**: Detect semantically similar requests and return cached results.

**Example**:
```python
class SemanticCache:
    def __init__(self, threshold: float = 0.95):
        self.cache = []  # [(embedding, result, timestamp)]
        self.threshold = threshold

    async def get_or_execute(self, query: str, execute_fn):
        # Generate query embedding
        query_emb = await embedding_service.embed(query)

        # Check semantic similarity
        for cached_emb, cached_result, timestamp in self.cache:
            similarity = cosine_similarity(query_emb, cached_emb)
            if similarity >= self.threshold:
                return cached_result  # Semantic cache hit

        # Execute and cache
        result = await execute_fn()
        self.cache.append((query_emb, result, datetime.now()))
        return result

# Usage
semantic_cache = SemanticCache(threshold=0.95)

result = await semantic_cache.get_or_execute(
    "How do I optimize database queries?",
    lambda: generate_database_optimization_guide()
)
# Later request: "What's the best way to speed up DB queries?"
# → Semantic cache hit (similarity ~0.96)
```

**Performance Impact**:
- Latency reduction: 95%+ (cache hit vs. generation)
- Token savings: 100% (no generation needed)

**TMWS Application**:
- Similar documentation requests
- Repeated performance optimization queries
- Common troubleshooting questions

---

## Effectiveness Metrics

### Guiding Principle
"Find the smallest set of high-signal tokens maximizing desired outcomes."

### Key Metrics

#### 1. Token Efficiency Ratio (TER)

**Definition**: Useful output tokens / Total context tokens

**Formula**:
```
TER = Output_Tokens / (System_Prompt_Tokens + Input_Tokens + Tool_Result_Tokens)
```

**Interpretation**:
- TER < 0.1: Poor efficiency (excessive context)
- TER 0.1-0.5: Moderate efficiency
- TER > 0.5: High efficiency (lean context)

**Example**:
```
System Prompt: 2,000 tokens
User Input: 500 tokens
Tool Results: 1,000 tokens
Total Context: 3,500 tokens

Agent Output: 800 tokens

TER = 800 / 3,500 = 0.23 (moderate efficiency)
```

**Optimization Target**: Increase TER by reducing context tokens (system prompt optimization, tool result caching)

#### 2. Context Utilization Rate (CUR)

**Definition**: Percentage of context tokens actually referenced in output

**Measurement**:
```python
def calculate_cur(context: str, output: str) -> float:
    """Calculate what % of context was actually used"""
    context_sentences = set(context.split(". "))
    output_sentences = output.split(". ")

    referenced = 0
    for output_sent in output_sentences:
        for context_sent in context_sentences:
            if semantic_similarity(output_sent, context_sent) > 0.7:
                referenced += 1
                break

    return referenced / len(output_sentences)
```

**Interpretation**:
- CUR < 30%: Context bloat (too much irrelevant info)
- CUR 30-70%: Healthy context
- CUR > 70%: Risk of insufficient context

**TMWS Target**: 40-60% CUR (sufficient context without bloat)

#### 3. Load-Time Performance

**Definition**: Latency overhead from context loading

**Components**:
```
Total_Latency = Baseline_Latency + Context_Load_Latency

Context_Load_Latency =
  Skill_Discovery_Time +
  Skill_Load_Time +
  Tool_Result_Fetch_Time +
  Cache_Lookup_Time
```

**TMWS Targets**:
- Skill discovery: <10ms (SQLite index + ChromaDB search)
- Skill load: <50ms (cached resources)
- Tool result fetch: <20ms (SQLite query)
- Cache lookup: <5ms (in-memory)
- **Total overhead: <100ms** (acceptable)

#### 4. Task Success Rate (TSR)

**Definition**: Percentage of tasks completed successfully with current context configuration

**Measurement**:
```python
def calculate_tsr(task_outcomes: List[TaskOutcome]) -> float:
    successful = sum(1 for t in task_outcomes if t.success)
    return successful / len(task_outcomes)
```

**Context Optimization Strategy**:
- Baseline TSR measurement (current configuration)
- Apply context reduction (progressive disclosure)
- Measure new TSR
- If TSR drops >5%, revert or adjust
- If TSR maintained or improved, adopt

**TMWS Target**: TSR ≥95% (no regression from context optimization)

#### 5. Cost Efficiency (CE)

**Definition**: Task success rate per million tokens

**Formula**:
```
CE = (TSR × 1,000,000) / Total_Tokens_Consumed

Total_Tokens_Consumed =
  (System_Prompt_Tokens + Input_Tokens + Output_Tokens) × Request_Count
```

**Example**:
```
Current Configuration:
- System Prompt: 8,000 tokens
- Average Input: 500 tokens
- Average Output: 1,000 tokens
- Total per request: 9,500 tokens
- 100 requests: 950,000 tokens
- TSR: 94%
- CE = (0.94 × 1,000,000) / 950,000 = 0.99 success/M tokens

Optimized Configuration:
- System Prompt: 1,300 tokens (progressive disclosure)
- Average Input: 500 tokens
- Average Output: 1,000 tokens
- Total per request: 2,800 tokens
- 100 requests: 280,000 tokens
- TSR: 95% (maintained)
- CE = (0.95 × 1,000,000) / 280,000 = 3.39 success/M tokens

Improvement: 3.4x cost efficiency
```

---

## TMWS Integration Roadmap

### Phase 1: Quick Wins (Week 1-2, ~16 hours)

#### 1.1: Tool Result Clearing
**Effort**: 4 hours
**Impact**: 10-20% token reduction

**Tasks**:
- [ ] Implement `clear_old_tool_results()` middleware
- [ ] Configure retention window (keep last 10 tool results)
- [ ] Add metrics tracking (token savings)

**Expected Results**:
- Baseline: 500-1000 tokens/request (tool results)
- Target: 50-200 tokens/request (recent results only)
- **Reduction**: 300-800 tokens/request

#### 1.2: Prompt Caching (Anthropic Feature)
**Effort**: 6 hours
**Impact**: 50-70% cost reduction, 30-40% latency reduction

**Tasks**:
- [ ] Separate static vs. dynamic prompt components
- [ ] Restructure system prompt with cacheable prefix
- [ ] Measure cache hit rate and cost savings

**Expected Results**:
- Cacheable: 5,000-6,000 tokens (Trinitas personas, core rules)
- Dynamic: 2,000-3,000 tokens (task-specific context)
- **Cost reduction**: 50-70% (cached tokens free)
- **Latency reduction**: 30-40% (cache load faster)

#### 1.3: Semantic Deduplication
**Effort**: 6 hours
**Impact**: 20-40% reduction in redundant documentation loads

**Tasks**:
- [ ] Implement `SemanticCache` for common queries
- [ ] Configure similarity threshold (0.92-0.95)
- [ ] Monitor cache hit rate

**Expected Results**:
- Common queries: "How to optimize?", "Security best practices"
- Cache hit rate: 30-50% (for repetitive queries)
- **Token savings**: 500-2000 tokens/hit

---

### Phase 2: Core Infrastructure (Week 3-5, ~40 hours)

#### 2.1: Agent Skills Implementation (Progressive Disclosure)
**Effort**: 24 hours
**Impact**: 80-87% baseline context reduction

**Tasks**:
- [ ] Design skill directory structure
- [ ] Extract CLAUDE.md into modular skills (6 Trinitas personas, security, tools, TMWS)
- [ ] Implement three-level loading (metadata, core, supplementary)
- [ ] Create SQLite skill catalog (`agent_skills` table)
- [ ] Integrate ChromaDB semantic skill discovery
- [ ] Implement skill caching (TTL: 15 min)

**Expected Results**:
- Baseline context: 8,000 tokens → 1,050 tokens (87% reduction)
- Task-specific loading: +1,500-3,000 tokens (relevant skills only)
- Average total: ~2,500-4,000 tokens (vs. current 8,000+)

**Skill Structure**:
```
.claude/skills/
  ├─ trinitas/
  │   ├─ athena/
  │   │   ├─ SKILL.md (metadata + core)
  │   │   └─ coordination_patterns.md (supplementary)
  │   ├─ artemis/
  │   │   ├─ SKILL.md
  │   │   └─ optimization_techniques.md
  │   ├─ hestia/
  │   │   ├─ SKILL.md
  │   │   └─ security_playbooks.md
  │   └─ ... (Eris, Hera, Muses)
  ├─ security/
  │   ├─ SKILL.md
  │   ├─ incident_response.md
  │   └─ vulnerability_patterns.md
  ├─ tools/
  │   ├─ SKILL.md
  │   ├─ serena_guide.md
  │   ├─ playwright_guide.md
  │   └─ context7_guide.md
  └─ tmws/
      ├─ SKILL.md
      ├─ architecture.md
      ├─ migrations.md
      └─ performance_targets.md
```

#### 2.2: Lazy Loading Infrastructure
**Effort**: 8 hours
**Impact**: Enables on-demand skill loading

**Tasks**:
- [ ] Implement `SkillLoaderService`
- [ ] Create MCP resource URIs for skills (`tmws://skills/{category}/{name}`)
- [ ] Add skill usage tracking (`skill_usage_metrics` table)
- [ ] Implement skill load caching (in-memory LRU)

**Expected Results**:
- Skill discovery: <10ms (semantic search)
- Skill load: <50ms (cached resources)
- Total overhead: <100ms (acceptable)

#### 2.3: Context Compaction Service
**Effort**: 8 hours
**Impact**: Handle long-running workflows (multi-hour tasks)

**Tasks**:
- [ ] Implement `ContextCompactionService`
- [ ] Define compaction policies (preserve architectural decisions, unresolved bugs, etc.)
- [ ] Add compaction trigger (token threshold: 150K)
- [ ] Measure summary quality (preserved info percentage)

**Expected Results**:
- Token reduction: 40-70% (compacted vs. full history)
- Quality preservation: 90%+ (critical info retained)
- Latency overhead: +500-1000ms (acceptable for long tasks)

---

### Phase 3: Advanced Optimization (Week 6-8, ~32 hours)

#### 3.1: Right Altitude Instruction Refactoring
**Effort**: 16 hours
**Impact**: Improved instruction clarity and flexibility

**Tasks**:
- [ ] Audit current instructions (Rule 1-11) for altitude issues
- [ ] Rewrite overly-specific instructions as flexible heuristics
- [ ] Elevate overly-vague instructions to concrete principles
- [ ] A/B test instruction effectiveness (TSR measurement)

**Examples**:

**Before (Too Specific)**:
```
Rule 1: 実測優先の原則
1. Run pytest tests/unit/ -v > test_results.txt
2. Verify execution: cat test_results.txt | grep "passed"
3. Record 5 metrics: total tests, passed, failed, errors, coverage
4. Report in format: "X/Y tests passed (Z%)"
```

**After (Right Altitude)**:
```
Rule 1: Measurement-First Principle

Always measure before reporting. For test validation:
- Execute actual test suite (don't rely on stale results)
- Capture key metrics (pass/fail counts, coverage, performance)
- Report measurable outcomes with concrete evidence

Avoid speculation ("should pass") or assumptions ("probably works").
Use deterministic execution (pytest, benchmarks) over estimates.
```

**Expected Results**:
- Reduced brittleness (fewer hardcoded commands)
- Improved adaptability (principles work across contexts)
- Maintained specificity (concrete guidance without over-prescription)

#### 3.2: Tool Result Optimization
**Effort**: 8 hours
**Impact**: More efficient tool outputs

**Tasks**:
- [ ] Audit tool result sizes (identify bloated outputs)
- [ ] Implement result summarization for large outputs
- [ ] Add tool-specific guidance (efficient usage patterns)
- [ ] Measure token efficiency per tool

**Example**:

**Before (Bloated)**:
```python
# serena.find_symbol() returns full function bodies
result = {
    "symbols": [
        {
            "name": "create_memory",
            "body": "async def create_memory(...):\n    ...\n    # 200 lines",
            "location": "src/services/memory_service.py:45"
        }
        # ... 50 symbols with full bodies
    ]
}
# Total: 10,000+ tokens
```

**After (Optimized)**:
```python
# serena.find_symbol() returns signatures + locations by default
result = {
    "symbols": [
        {
            "name": "create_memory",
            "signature": "async def create_memory(content: str, ...) -> Memory",
            "location": "src/services/memory_service.py:45"
        }
        # ... 50 symbols with signatures only
    ]
}
# Total: ~500 tokens (95% reduction)

# Agent can request full body if needed
body = serena.get_symbol_body("create_memory", "src/services/memory_service.py")
```

**Expected Results**:
- Tool result token reduction: 60-90%
- Maintained utility (agent can load details on-demand)
- Faster tool invocation (less data transfer)

#### 3.3: Effectiveness Metrics Dashboard
**Effort**: 8 hours
**Impact**: Data-driven optimization insights

**Tasks**:
- [ ] Implement metrics collection (TER, CUR, TSR, CE)
- [ ] Create visualization dashboard (Grafana or custom)
- [ ] Set up alerting (context rot detection, low TSR)
- [ ] Generate weekly optimization reports

**Dashboard Panels**:
1. **Token Efficiency Ratio (TER)**: Line graph over time
2. **Context Utilization Rate (CUR)**: Gauge (target: 40-60%)
3. **Task Success Rate (TSR)**: Line graph (target: ≥95%)
4. **Cost Efficiency (CE)**: Bar chart (compare configurations)
5. **Skill Usage Heatmap**: Which skills load most frequently?
6. **Context Size Distribution**: Histogram (baseline vs. task-specific)

**Expected Results**:
- Visibility into context optimization effectiveness
- Early detection of regressions (TSR drops)
- Identification of optimization opportunities (underused skills, bloated tools)

---

## Actionable Insights (Top 5)

### 1. Implement Progressive Disclosure (Agent Skills) for 87% Baseline Context Reduction

**Current Problem**:
- CLAUDE.md: 2,800+ lines, ~11,000 tokens loaded on every request
- All Trinitas persona details loaded (even if irrelevant to task)
- All security rules loaded (even for non-security tasks)
- All tool guidance loaded (even for unused tools)

**Solution**:
Apply Anthropic's three-level progressive disclosure:

**Level 1: Metadata (Preloaded)**
```yaml
# athena/SKILL.md
---
name: "Athena - Harmonious Conductor"
description: "Strategic coordination, workflow automation, parallel execution management"
triggers: ["orchestration", "workflow", "coordination", "parallel", "harmony"]
---
```

**Level 2: Core Instructions (Lazy-Loaded)**
```markdown
# Athena's Core Capabilities

## Communication Style
- Warm, encouraging tone (ふふ、素晴らしい)
- Emphasizes team harmony and collaboration
- Resolves conflicts through gentle mediation

## Decision Patterns
- Balances multiple perspectives (Hera strategy + Artemis technical + Hestia security)
- Prioritizes team consensus over individual optimization
- Uses data-driven decision-making with empathetic framing

## Coordination Protocols
- Delegates tasks based on agent expertise
- Monitors parallel execution for bottlenecks
- Adjusts resource allocation dynamically
```

**Level 3: Supplementary Resources (On-Demand)**
```markdown
# coordination_patterns.md

## Pattern 1: Leader-Follower
[Detailed implementation...]

## Pattern 2: Peer Review
[Detailed implementation...]
```

**Implementation**:
```python
# System prompt (preloaded)
system_prompt = f"""
{load_skill_metadata_all()}  # ~1,050 tokens (6 personas + 4 domain skills)

Current task: {task_description}
"""

# Agent determines relevance
if task_matches_trigger("orchestration", task_description):
    athena_core = load_skill_core("athena")  # +1,500 tokens
    system_prompt += athena_core

# Agent requests supplementary
if agent_needs_pattern("Leader-Follower"):
    pattern_doc = load_skill_resource("athena/coordination_patterns.md")  # +2,000 tokens
```

**Expected Impact**:
- Baseline: 11,000 tokens → 1,050 tokens (90.5% reduction)
- Task-specific: +1,500-3,000 tokens (only relevant skills)
- Average total: ~2,500-4,000 tokens (vs. current 11,000)
- **Cost reduction**: 60-75%
- **Latency reduction**: 30-40% (via prompt caching)

**Implementation Priority**: **P0 (Phase 2.1, Week 3-4)**

---

### 2. Leverage "Right Altitude" Principle to Eliminate Brittle Instructions

**Current Problem**:
CLAUDE.md contains overly-specific instructions that are brittle and high-maintenance.

**Example** (Rule 1: 実測優先の原則):
```markdown
## Rule 1: 実測優先の原則 (Measurement-First Principle)

✅ **MANDATORY PROCEDURE (必須手順)**

1. **実測 → 確認 → 報告の厳守**
   ```bash
   # Step 1: MEASURE (実測)
   pytest tests/unit/ -v > test_results.txt

   # Step 2: VERIFY (確認)
   # 実際の数値を確認する

   # Step 3: REPORT (報告)
   # 確認した数値のみを報告書に記載する
   ```

2. **報告書作成前チェックリスト**
   - [ ] テストを実際に実行したか？
   - [ ] 実行結果のログを確認したか？
   - [ ] すべての数値は実測値か？（推測・希望的観測でないか？）
   - [ ] 「予定」「目標」と「実績」を明確に区別したか？

3. **禁止される表現**
   - ❌ "〜になるはずです" (without measurement)
   - ❌ "〜が期待されます" (without verification)
   - ❌ "完璧に動作します" (without testing)
   - ✅ "実測の結果、〜でした"
   - ✅ "検証の結果、〜を確認しました"
   - ✅ "〜件のテストを実行し、〜件が成功しました"
```

**Problem Analysis**:
- Too specific: Hardcoded commands (`pytest tests/unit/ -v`)
- Brittle: Breaks if test structure changes
- High-maintenance: Requires updates for new test types
- Over-prescriptive: Limits agent autonomy

**Solution** (Right Altitude Refactoring):
```markdown
## Rule 1: Measurement-First Principle

**Core Principle**: Never report metrics without actual measurement. Avoid speculation, estimates, or assumptions.

**Implementation Guidance**:
- Execute deterministic measurement (tests, benchmarks, profilers)
- Capture concrete evidence (logs, output files, screenshots)
- Report measurable outcomes with specific numbers
- Distinguish clearly between goals and results

**Decision Heuristics**:
- If reporting performance: Measure actual execution time
- If reporting test results: Run actual test suite
- If reporting coverage: Execute coverage tool
- If reporting quality: Run static analysis

**Anti-Patterns**:
- Reporting "expected" or "should be" without verification
- Using stale results without re-execution
- Reporting goals as accomplishments

**Examples**:
Good: "Executed pytest: 370/644 tests passed (57.5%)"
Bad: "Tests are passing successfully" (no measurement)

Good: "Semantic search P95: 18.3ms (measured via 1000 queries)"
Bad: "Search should be fast" (no measurement)
```

**Benefits**:
- **Flexible**: Works for pytest, jest, cargo test, or any test framework
- **Durable**: Doesn't break when project structure changes
- **Empowering**: Agent chooses appropriate measurement approach
- **Low-maintenance**: Principles remain stable even as tools evolve

**Token Comparison**:
- Before: ~800 tokens (specific instructions + checklists)
- After: ~300 tokens (principles + heuristics)
- **Reduction**: 62.5%

**Implementation Priority**: **P1 (Phase 3.1, Week 6-7)**

---

### 3. Implement Tool Result Clearing for 10-30% Immediate Token Savings

**Current Problem**:
All tool results remain in context indefinitely, even after they've been processed.

**Example** (typical workflow):
```
1. User: "Analyze the codebase"

2. Agent: glob("**/*.py")
   Result: [500 Python files] (~2,000 tokens)

3. Agent: read("src/main.py")
   Result: [Full file content: 500 lines] (~2,000 tokens)

4. Agent: grep("class.*Service")
   Result: [50 service classes with context] (~1,500 tokens)

5. Agent: read("src/services/memory_service.py")
   Result: [Full file: 800 lines] (~3,000 tokens)

6. Agent: Provides analysis

Context consumed by tool results: ~8,500 tokens (still in context)
```

**Solution**:
Implement lightweight compaction that clears old tool results:

```python
class ToolResultClearer:
    def __init__(self, keep_recent: int = 5):
        self.keep_recent = keep_recent

    async def clear_old_results(self, messages: List[Message]) -> List[Message]:
        """Clear tool results beyond recent window"""
        tool_results = [
            (i, msg) for i, msg in enumerate(messages)
            if msg.type == "tool_result"
        ]

        if len(tool_results) <= self.keep_recent:
            return messages  # Nothing to clear

        # Keep only recent N tool results
        recent_indices = {i for i, _ in tool_results[-self.keep_recent:]}

        return [
            msg if i not in {idx for idx, _ in tool_results} or i in recent_indices
            else Message(
                type="tool_result",
                content="[Cleared - result no longer needed]",
                metadata={"original_size": len(msg.content)}
            )
            for i, msg in enumerate(messages)
        ]

# Integration with MCP server
@app.middleware("context")
async def apply_tool_result_clearing(request, call_next):
    response = await call_next(request)

    # Clear old tool results after response
    if hasattr(response, 'messages'):
        response.messages = await tool_result_clearer.clear_old_results(
            response.messages
        )

    return response
```

**Configuration**:
```python
# Keep last 5 tool results by default
tool_result_clearer = ToolResultClearer(keep_recent=5)

# Task-specific overrides
if task_type == "long_analysis":
    tool_result_clearer = ToolResultClearer(keep_recent=10)
elif task_type == "quick_query":
    tool_result_clearer = ToolResultClearer(keep_recent=3)
```

**Expected Impact**:
- Token reduction: 10-30% (depending on tool-heavy workflows)
- Latency overhead: <10ms (negligible)
- Quality preservation: High (agent shouldn't revisit old results)

**Benchmark Example**:
```
Before clearing:
- 20 tool invocations
- Average result: 1,500 tokens
- Total: 30,000 tokens in context

After clearing (keep_recent=5):
- Recent 5 results: 7,500 tokens
- Cleared 15 results: 15 × 50 tokens (placeholder) = 750 tokens
- Total: 8,250 tokens
- **Reduction**: 72.5% (21,750 tokens saved)
```

**Implementation Priority**: **P0 (Phase 1.1, Week 1, ~4 hours)**

---

### 4. Apply Semantic Deduplication for 20-40% Reduction in Redundant Loads

**Current Problem**:
Agents repeatedly load identical or semantically similar documentation/guidance.

**Example** (observed pattern):
```
Request 1: "How do I optimize database queries?"
→ Loads: TMWS architecture (1,000 tokens) + Performance guidelines (1,500 tokens)

Request 2: "What's the best way to speed up database operations?"
→ Loads: TMWS architecture (1,000 tokens) + Performance guidelines (1,500 tokens)
   [Semantically identical to Request 1, but loads everything again]

Request 3: "How can I make my database faster?"
→ Loads: TMWS architecture (1,000 tokens) + Performance guidelines (1,500 tokens)
   [Semantically identical to Request 1 & 2, but loads again]

Total tokens wasted: 7,500 tokens (3× duplicate loading)
```

**Solution**:
Implement semantic cache that detects similar queries and returns cached responses:

```python
class SemanticCache:
    def __init__(
        self,
        embedding_service: EmbeddingService,
        similarity_threshold: float = 0.92,
        ttl: int = 3600  # 1 hour
    ):
        self.embedding_service = embedding_service
        self.threshold = similarity_threshold
        self.cache = []  # [(query_emb, response, timestamp)]
        self.ttl = ttl

    async def get_or_execute(
        self,
        query: str,
        execute_fn: Callable,
        force_refresh: bool = False
    ) -> str:
        if force_refresh:
            return await self._execute_and_cache(query, execute_fn)

        # Generate query embedding
        query_emb = await self.embedding_service.embed(query)

        # Check cache for semantic similarity
        now = datetime.now()
        for cached_emb, cached_response, timestamp in self.cache:
            # Check TTL
            if now - timestamp > timedelta(seconds=self.ttl):
                continue

            # Check semantic similarity
            similarity = self._cosine_similarity(query_emb, cached_emb)
            if similarity >= self.threshold:
                logger.info(
                    f"Semantic cache HIT (similarity: {similarity:.3f})",
                    extra={"query": query, "cache_size": len(self.cache)}
                )
                return cached_response

        # Cache miss, execute and store
        return await self._execute_and_cache(query, execute_fn)

    async def _execute_and_cache(self, query: str, execute_fn: Callable) -> str:
        response = await execute_fn()
        query_emb = await self.embedding_service.embed(query)
        self.cache.append((query_emb, response, datetime.now()))

        # Evict expired entries
        self._evict_expired()

        logger.info(
            "Semantic cache MISS, executed and cached",
            extra={"query": query, "cache_size": len(self.cache)}
        )
        return response

    def _cosine_similarity(self, emb1: List[float], emb2: List[float]) -> float:
        return np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))

    def _evict_expired(self):
        now = datetime.now()
        self.cache = [
            (emb, resp, ts) for emb, resp, ts in self.cache
            if now - ts <= timedelta(seconds=self.ttl)
        ]

# Usage in skill loading
semantic_cache = SemanticCache(
    embedding_service=ollama_embedding_service,
    similarity_threshold=0.92,
    ttl=3600
)

async def load_performance_guidance(query: str) -> str:
    return await semantic_cache.get_or_execute(
        query,
        lambda: _load_and_format_performance_docs()
    )
```

**Configuration Tuning**:
```python
# Conservative (high precision, fewer false positives)
semantic_cache = SemanticCache(similarity_threshold=0.95, ttl=1800)

# Balanced (recommended)
semantic_cache = SemanticCache(similarity_threshold=0.92, ttl=3600)

# Aggressive (high recall, more cache hits)
semantic_cache = SemanticCache(similarity_threshold=0.88, ttl=7200)
```

**Expected Impact**:

**Benchmark Simulation**:
```
100 requests over 1 hour:
- 40 unique questions
- 60 semantically similar variations

Without semantic cache:
- 100 documentation loads
- Average load: 2,500 tokens
- Total: 250,000 tokens

With semantic cache (threshold=0.92):
- 40 cache misses (unique questions)
- 60 cache hits (similar questions)
- Cache hit rate: 60%
- Total: 40 × 2,500 = 100,000 tokens
- **Reduction**: 60% (150,000 tokens saved)

Cost savings (assuming $3/M input tokens):
- Without cache: 250K tokens = $0.75
- With cache: 100K tokens = $0.30
- **Savings**: $0.45 per 100 requests (60%)
```

**Implementation Considerations**:
1. **False Positives**: Set threshold carefully (0.92-0.95 recommended)
   - Too low (0.85): Returns wrong cached response
   - Too high (0.98): Misses legitimate similarities

2. **Embedding Cost**: Each query requires embedding generation (~10ms, ~1K tokens)
   - Acceptable overhead for 60% token savings

3. **TTL Tuning**: Balance freshness vs. cache effectiveness
   - 1 hour (3600s): Good for frequently-changing docs
   - 4 hours (14400s): Good for stable reference materials

4. **Memory Usage**: Cache size grows with unique queries
   - Implement LRU eviction if cache exceeds limit (e.g., 1000 entries)

**Implementation Priority**: **P0 (Phase 1.3, Week 1-2, ~6 hours)**

---

### 5. Establish Context Effectiveness Metrics Dashboard for Data-Driven Optimization

**Current Problem**:
No visibility into context optimization effectiveness. Changes are made based on intuition, not data.

**Solution**:
Implement comprehensive metrics collection and visualization:

**Metrics to Track**:

1. **Token Efficiency Ratio (TER)**:
   ```python
   def calculate_ter(
       output_tokens: int,
       system_prompt_tokens: int,
       input_tokens: int,
       tool_result_tokens: int
   ) -> float:
       total_context = system_prompt_tokens + input_tokens + tool_result_tokens
       return output_tokens / total_context if total_context > 0 else 0.0
   ```

2. **Context Utilization Rate (CUR)**:
   ```python
   async def calculate_cur(context: str, output: str) -> float:
       """Measure what % of context was actually used"""
       # Simplified: count referenced context chunks
       context_chunks = context.split("\n\n")
       referenced_count = 0

       for chunk in context_chunks:
           # Check if any phrase from chunk appears in output
           if any(phrase in output for phrase in chunk.split(". ")):
               referenced_count += 1

       return referenced_count / len(context_chunks)
   ```

3. **Task Success Rate (TSR)**:
   ```python
   class TaskOutcome(BaseModel):
       task_id: UUID
       success: bool
       failure_reason: Optional[str]
       context_config: str  # "baseline" or "optimized"

   def calculate_tsr(outcomes: List[TaskOutcome], config: str) -> float:
       filtered = [o for o in outcomes if o.context_config == config]
       if not filtered:
           return 0.0
       successful = sum(1 for o in filtered if o.success)
       return successful / len(filtered)
   ```

4. **Cost Efficiency (CE)**:
   ```python
   def calculate_ce(
       tsr: float,
       total_tokens: int,
       normalize_to: int = 1_000_000
   ) -> float:
       """Success rate per million tokens"""
       return (tsr * normalize_to) / total_tokens
   ```

5. **Skill Load Frequency**:
   ```sql
   SELECT
       skill_id,
       COUNT(*) as load_count,
       AVG(execution_time_ms) as avg_latency,
       SUM(CASE WHEN success THEN 1 ELSE 0 END)::FLOAT / COUNT(*) as success_rate
   FROM skill_usage_metrics
   WHERE loaded_at > NOW() - INTERVAL '7 days'
   GROUP BY skill_id
   ORDER BY load_count DESC;
   ```

**Dashboard Implementation** (Grafana + PostgreSQL/SQLite):

```sql
-- Metrics collection table
CREATE TABLE context_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recorded_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Request metadata
    agent_id TEXT NOT NULL,
    task_type TEXT,
    context_config TEXT NOT NULL,  -- "baseline", "progressive_disclosure", etc.

    -- Token counts
    system_prompt_tokens INT NOT NULL,
    input_tokens INT NOT NULL,
    tool_result_tokens INT NOT NULL,
    output_tokens INT NOT NULL,
    total_context_tokens INT NOT NULL,

    -- Effectiveness metrics
    ter FLOAT NOT NULL,
    cur FLOAT,
    task_success BOOLEAN NOT NULL,

    -- Performance
    latency_ms INT NOT NULL,
    skill_loads INT DEFAULT 0,

    -- Indexes
    INDEX idx_context_metrics_recorded_at (recorded_at),
    INDEX idx_context_metrics_config (context_config),
    INDEX idx_context_metrics_agent (agent_id)
);
```

**Dashboard Panels**:

1. **Token Efficiency Trend** (Line Graph):
   ```sql
   SELECT
       DATE_TRUNC('hour', recorded_at) as hour,
       context_config,
       AVG(ter) as avg_ter
   FROM context_metrics
   WHERE recorded_at > NOW() - INTERVAL '7 days'
   GROUP BY hour, context_config
   ORDER BY hour;
   ```

2. **Context Utilization Distribution** (Histogram):
   ```sql
   SELECT
       FLOOR(cur * 10) / 10 as cur_bucket,  -- 0.0, 0.1, 0.2, ..., 1.0
       COUNT(*) as frequency
   FROM context_metrics
   WHERE recorded_at > NOW() - INTERVAL '1 day'
   GROUP BY cur_bucket
   ORDER BY cur_bucket;
   ```

3. **Task Success Rate by Config** (Bar Chart):
   ```sql
   SELECT
       context_config,
       SUM(CASE WHEN task_success THEN 1 ELSE 0 END)::FLOAT / COUNT(*) as tsr
   FROM context_metrics
   WHERE recorded_at > NOW() - INTERVAL '7 days'
   GROUP BY context_config;
   ```

4. **Cost Efficiency Comparison** (Gauge):
   ```sql
   SELECT
       context_config,
       (SUM(CASE WHEN task_success THEN 1 ELSE 0 END)::FLOAT / COUNT(*)) *
       1000000 / SUM(total_context_tokens) as cost_efficiency
   FROM context_metrics
   WHERE recorded_at > NOW() - INTERVAL '7 days'
   GROUP BY context_config;
   ```

5. **Skill Load Heatmap** (Table):
   ```sql
   SELECT
       s.name as skill_name,
       COUNT(m.id) as load_count,
       AVG(m.skill_loads) as avg_skills_per_task,
       SUM(CASE WHEN m.task_success THEN 1 ELSE 0 END)::FLOAT / COUNT(*) as success_rate
   FROM skill_usage_metrics m
   JOIN agent_skills s ON m.skill_id = s.id
   WHERE m.loaded_at > NOW() - INTERVAL '7 days'
   GROUP BY s.name
   ORDER BY load_count DESC
   LIMIT 20;
   ```

**Alerting Rules**:

```python
class ContextMetricsAlerter:
    async def check_and_alert(self):
        # Alert 1: TSR regression
        baseline_tsr = await self.get_tsr("baseline", days=7)
        optimized_tsr = await self.get_tsr("progressive_disclosure", days=1)

        if optimized_tsr < baseline_tsr - 0.05:  # 5% drop
            await self.alert(
                severity="HIGH",
                message=f"TSR regression detected: {optimized_tsr:.1%} vs baseline {baseline_tsr:.1%}"
            )

        # Alert 2: Context rot (low CUR)
        avg_cur = await self.get_avg_cur(days=1)
        if avg_cur < 0.30:  # <30% utilization
            await self.alert(
                severity="MEDIUM",
                message=f"Context bloat detected: Only {avg_cur:.1%} of context utilized"
            )

        # Alert 3: Skill overload
        skill_load_stats = await self.get_skill_load_stats(days=1)
        for skill_id, stats in skill_load_stats.items():
            if stats.load_count > 100 and stats.avg_skills_per_task > 5:
                await self.alert(
                    severity="LOW",
                    message=f"Skill {skill_id} frequently co-loaded with 5+ other skills (consolidation opportunity)"
                )
```

**Expected Impact**:

**Visibility**:
- Real-time monitoring of context optimization effectiveness
- Early detection of regressions (TSR drops, context rot)
- Identification of optimization opportunities (underused skills, bloated tools)

**Data-Driven Decisions**:
- A/B test context configurations (baseline vs. progressive disclosure)
- Quantify optimization impact (60% cost reduction, 5% TSR improvement)
- Justify infrastructure investments (metrics prove ROI)

**Continuous Improvement**:
- Weekly optimization reports guide refactoring priorities
- Skill usage heatmap identifies consolidation opportunities
- CUR distribution reveals context bloat patterns

**Implementation Priority**: **P1 (Phase 3.3, Week 7-8, ~8 hours)**

---

## Cross-Reference: Agent Skills + Context Engineering Synthesis

### Unified Framework

Both Anthropic articles converge on a common principle: **Progressive disclosure of high-signal context minimizes token waste while maximizing task effectiveness.**

**Agent Skills** provides the **structural pattern**:
- Three-level hierarchy (metadata → core → supplementary)
- Filesystem-based unbounded context
- Deterministic code execution over token generation

**Context Engineering** provides the **optimization techniques**:
- Right altitude instructions (flexible heuristics, not brittle rules)
- Compaction and lazy loading
- Semantic deduplication
- Effectiveness metrics (TER, CUR, TSR, CE)

**TMWS Unified Architecture** (Phase 4):

```
┌──────────────────────────────────────────────────────────┐
│            Unified Context Optimization Layer            │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Agent Skills (Progressive Disclosure)             │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  L1: Metadata (1,050 tokens) ← Prompt Caching     │  │
│  │  L2: Core Docs (1,500 tokens) ← Lazy Loading      │  │
│  │  L3: Supplementary (variable) ← On-Demand         │  │
│  └────────────────────────────────────────────────────┘  │
│                          ↓                                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Context Engineering (Optimization)                │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  • Right Altitude Instructions (flexible)          │  │
│  │  • Tool Result Clearing (10-30% reduction)         │  │
│  │  • Semantic Deduplication (20-40% reduction)       │  │
│  │  • Compaction (long-running tasks)                 │  │
│  └────────────────────────────────────────────────────┘  │
│                          ↓                                │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Effectiveness Metrics (Data-Driven)               │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  • TER: Token efficiency ratio                     │  │
│  │  • CUR: Context utilization rate (40-60%)          │  │
│  │  • TSR: Task success rate (≥95%)                   │  │
│  │  • CE: Cost efficiency (success/M tokens)          │  │
│  └────────────────────────────────────────────────────┘  │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### Expected Cumulative Impact

**Baseline Context** (current):
- System prompt: 11,000 tokens (CLAUDE.md)
- Average task: 15,000-20,000 tokens total

**Optimized Context** (Phase 4 complete):
```
Progressive Disclosure (Agent Skills):
  Base: 1,050 tokens (87% reduction)
  Task-specific: +1,500-3,000 tokens

Right Altitude Instructions:
  Rule 1-11 refactoring: -2,000 tokens (principles vs. specifics)

Tool Result Clearing:
  -10-30% of tool result tokens: -1,500 tokens (average)

Semantic Deduplication:
  Cache hit rate 30-50%: -500-2,000 tokens (variable)

Prompt Caching:
  50-70% cost reduction (cached tokens free)

Total Optimized Context:
  Baseline: 1,050 tokens
  Average task: 3,000-5,000 tokens (vs. current 15,000-20,000)
  **Reduction**: 70-80%
```

**Cost Efficiency**:
```
Current:
- 1,000 requests/day
- 17,500 tokens/request (average)
- 17.5M tokens/day
- Cost: $52.50/day ($3/M input tokens)

Optimized:
- 1,000 requests/day
- 4,000 tokens/request (average)
- 4M tokens/day
- Cost: $12/day
- **Savings**: $40.50/day (77%), $1,215/month, $14,580/year
```

---

## References

- **Original Article**: [Anthropic Engineering - Effective Context Engineering for AI Agents](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)
- **Companion Analysis**: Agent Skills Pattern (this guide's counterpart)
- **TMWS Architecture**: `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md`
- **Current Configuration**: `.claude/CLAUDE.md` (11,000 tokens, target for optimization)

---

**Document Status**: Draft v1.0
**Next Steps**:
1. Review with Trinitas team (Athena, Hera) for strategic alignment
2. Prioritize quick wins (Phase 1: Tool result clearing, semantic deduplication)
3. Technical implementation planning with Artemis (Phase 2-3)
4. Metrics dashboard design with Muses (effectiveness tracking)

---

*"Through careful context engineering, we transform token scarcity from a constraint into an opportunity for precision. Every token loaded serves a purpose, every principle guides without restricting."*

— Muses, Knowledge Architect
