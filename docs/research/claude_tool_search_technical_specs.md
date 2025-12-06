# Claude Tool Search Technical Specifications
## Research Report for TMWS Adaptation

**Version**: 1.0
**Date**: 2025-12-06
**Source**: Anthropic API Documentation & Engineering Blog
**Status**: Comprehensive Analysis Complete

---

## Executive Summary

Claude's Tool Search Tool represents a paradigm shift in LLM tool management, enabling dynamic discovery and loading of tools on-demand rather than upfront context injection. This research extracts critical technical specifications, performance metrics, and best practices for potential TMWS adaptation.

**Key Findings**:
- **85% token reduction** while maintaining full tool library access
- Supports up to **10,000 tools** (vs. 30-50 practical limit with traditional approach)
- **3-5 tools returned** per search query
- **Accuracy improvements**: Opus 4 (49% → 74%), Opus 4.5 (79.5% → 88.1%)

---

## 1. API Response Format

### 1.1 server_tool_use Block

When Claude invokes the Tool Search Tool, the response includes:

```json
{
  "type": "server_tool_use",
  "id": "srvtoolu_01ABC123",
  "name": "tool_search_tool_regex",
  "input": {
    "query": "weather"
  }
}
```

**Characteristics**:
- `type`: Always `"server_tool_use"` (distinguishes from regular `tool_use`)
- `id`: Unique identifier for this search operation
- `name`: Either `tool_search_tool_regex` or `tool_search_tool_bm25`
- `input.query`: Search pattern (regex) or natural language query (BM25)

### 1.2 tool_result with tool_reference

Search results are returned in a `tool_result` block:

```json
{
  "type": "tool_result",
  "tool_use_id": "srvtoolu_01ABC123",
  "content": [
    { "type": "tool_reference", "tool_name": "get_weather" },
    { "type": "tool_reference", "tool_name": "search_weather_history" }
  ]
}
```

**Characteristics**:
- `tool_use_id`: References the corresponding `server_tool_use.id`
- `content`: Array of `tool_reference` objects
- Returns **3-5 most relevant tools** per search

### 1.3 Automatic Tool Expansion

**Critical Mechanism**: `tool_reference` blocks are **automatically expanded** into full tool definitions before being shown to Claude.

**Developer Responsibility**:
1. Include all tool definitions in top-level `tools` parameter
2. Mark searchable tools with `defer_loading: true`
3. API handles expansion transparently

**No manual intervention required** for tool definition injection.

---

## 2. Search Algorithms

### 2.1 Regex Search (`tool_search_tool_regex_20251119`)

**Pattern Syntax**: Python's `re.search()` (NOT natural language)

**Common Patterns**:
```python
"weather"                              # Contains "weather"
"get_.*_data"                          # Matches get_user_data, get_weather_data
"database.*query|query.*database"      # OR patterns
"(?i)slack"                            # Case-insensitive
```

**Fields Searched**:
- Tool name
- Tool description
- Argument names
- Argument descriptions

**Limits**:
- **Maximum pattern length**: 200 characters
- Case-sensitive by default (use `(?i)` flag)

### 2.2 BM25 Search (`tool_search_tool_bm25_20251119`)

**Query Format**: Natural language queries

**Example**:
```json
{
  "query": "send notification to user"
}
```

**Search Mechanism**:
- BM25 (Best Match 25) ranking algorithm
- Semantic relevance scoring
- Same fields as regex (name, description, args)

**Use Case**: Better for users who describe tasks conversationally

---

## 3. Performance Considerations

### 3.1 Token Usage Comparison

**Traditional Approach (50 tools)**:
| Component | Tokens |
|-----------|--------|
| Tool definitions | 72,000 |
| System prompt | 5,000 |
| **Total consumed** | **77,000** |
| **Remaining for work** | **23,000** (23% of 100K context) |

**With Tool Search Tool (50 tools)**:
| Component | Tokens |
|-----------|--------|
| Tool Search Tool | 500 |
| 3-5 loaded tools | 3,000 |
| System prompt | 5,000 |
| **Total consumed** | **8,500** |
| **Remaining for work** | **91,500** (91% of 100K context) |

**Result**: **85% token reduction** for the same capability.

### 3.2 Selection Accuracy

**Degradation Threshold**: 30-50 tools (traditional approach)

**With Tool Search**:
- **Opus 4**: 49% → 74% (+51% improvement)
- **Opus 4.5**: 79.5% → 88.1% (+10.8% improvement)
- **Internal Knowledge Retrieval**: 25.6% → 28.5%
- **GIA Benchmarks**: 46.5% → 51.2%

### 3.3 Prompt Caching Support

**Key Benefit**: Tool Search doesn't break prompt caching.

**Why**:
- Deferred tools excluded from initial prompt
- Only loaded tools appear in cacheable context
- System prompt and core tools remain stable

**Cache Invalidation Hierarchy**:
```
Tools → System → Messages
```

**Minimum Cacheable Size**:
- Opus 4.5, Sonnet 4.5: **1024 tokens**
- Haiku 3.5: **2048 tokens**

### 3.4 Streaming Support

**Event Stream Format**:
```
event: content_block_start
data: {"type": "server_tool_use", "id": "...", "name": "tool_search_tool_regex"}

event: content_block_delta
data: {"delta": {"type": "input_json_delta", "partial_json": "{\"query\":\"weather\"}"}}

event: content_block_start
data: {"type": "tool_result", "content": [{"type": "tool_reference", "tool_name": "get_weather"}]}
```

**Behavior**:
- Search query streams incrementally
- Pause during search execution
- Results stream when ready
- Claude continues with discovered tools

---

## 4. Best Practices from Documentation

### 4.1 Core Recommendations

**Keep 3-5 Non-Deferred Tools**:
```json
{
  "tools": [
    {"type": "tool_search_tool_regex_20251119", "name": "tool_search_tool_regex"},
    {"name": "frequently_used_1", "description": "...", "defer_loading": false},
    {"name": "frequently_used_2", "description": "...", "defer_loading": false},
    {"name": "rarely_used", "description": "...", "defer_loading": true}
  ]
}
```

**Rationale**:
- Immediate access for frequent operations
- No search latency for common tasks
- Optimal balance: context efficiency + responsiveness

### 4.2 Write Clear Tool Descriptions

**Good Practice**:
```json
{
  "name": "send_slack_message",
  "description": "Send a Slack message to a user or channel. Use this for Slack notifications, team communication, and alerts.",
  "defer_loading": true
}
```

**Why It Works**:
- Multiple semantic keywords ("Slack", "message", "notification", "communication")
- Natural language task descriptions
- Matches how users describe tasks

**Poor Practice**:
```json
{
  "name": "send_msg",
  "description": "Sends msg",
  "defer_loading": true
}
```

### 4.3 System Prompt Tool Categories

**Recommended Pattern**:
```
You can search for tools to interact with:
- Slack (messaging, notifications)
- GitHub (repositories, pull requests, issues)
- Jira (tasks, sprints, tickets)
- Google Drive (files, documents, spreadsheets)
```

**Benefit**: Helps Claude construct better search queries.

### 4.4 Monitor Discovered Tools

**Feedback Loop**:
1. Track which tools Claude discovers
2. Identify under-discovered tools
3. Refine descriptions with keywords Claude actually searches for
4. Adjust non-deferred tool selection

**Example**:
- If Claude searches for "database query" but misses `execute_sql_query`
- Add "database" keyword to `execute_sql_query` description

---

## 5. Limits & Constraints

### 5.1 Hard Limits

| Limit | Value |
|-------|-------|
| **Maximum tools** | 10,000 |
| **Results per search** | 3-5 |
| **Regex pattern length** | 200 characters |
| **Minimum non-deferred tools** | 1 (at least one must be non-deferred) |

### 5.2 Model Restrictions

**Supported Models**:
- Claude Opus 4.5
- Claude Sonnet 4.5
- Claude Opus 4.0
- Claude Sonnet 4.0

**NOT Supported**:
- Claude Haiku (any version)

### 5.3 Incompatibilities

**Tool Use Examples**:
- Tool Search **NOT compatible** with tool use examples
- If you need to provide usage examples, use traditional tool calling

**Reason**: Examples require tools to be present in initial context.

### 5.4 Beta Header Requirements

| Provider | Beta Header | Supported Models |
|----------|-------------|------------------|
| Claude API / Microsoft Foundry | `advanced-tool-use-2025-11-20` | Opus 4.5, Sonnet 4.5 |
| Google Cloud Vertex AI | `tool-search-tool-2025-10-19` | Opus 4.5, Sonnet 4.5 |
| Amazon Bedrock | `tool-search-tool-2025-10-19` | Opus 4.5 only |

**Amazon Bedrock Note**: Server-side tool search only via `invoke` API, NOT `converse` API.

---

## 6. Error Handling

### 6.1 HTTP 400 Errors (Request Rejected)

**All Tools Deferred**:
```json
{
  "type": "error",
  "error": {
    "type": "invalid_request_error",
    "message": "All tools have defer_loading set. At least one tool must be non-deferred."
  }
}
```

**Missing Tool Definition**:
```json
{
  "type": "error",
  "error": {
    "type": "invalid_request_error",
    "message": "Tool reference 'unknown_tool' has no corresponding tool definition"
  }
}
```

### 6.2 Tool Result Errors (200 Response)

```json
{
  "type": "tool_result",
  "tool_use_id": "srvtoolu_01ABC123",
  "content": {
    "type": "tool_search_tool_result_error",
    "error_code": "invalid_pattern"
  }
}
```

**Error Codes**:
| Code | Meaning |
|------|---------|
| `too_many_requests` | Rate limit exceeded |
| `invalid_pattern` | Malformed regex |
| `pattern_too_long` | Exceeds 200 chars |
| `unavailable` | Service temporarily down |

---

## 7. TMWS Adaptation Recommendations

### 7.1 Immediate Opportunities

**Skill System Integration**:
- TMWS currently has 42 MCP tools
- Skill system allows user-defined custom tools (potentially 100+)
- **Recommendation**: Implement Tool Search for skill discovery

**Expected Benefits**:
```
Traditional: 42 tools × 500 tokens = 21,000 tokens
With Tool Search: 500 + (5 tools × 500) = 3,000 tokens
Savings: 18,000 tokens (85% reduction)
```

### 7.2 Architecture Considerations

**Option 1: Server-Side Tool Search (Recommended)**
```python
# Use Anthropic's built-in tool search
tools = [
    {"type": "tool_search_tool_bm25_20251119", "name": "tool_search_tool_bm25"},
    *get_tmws_core_tools(defer_loading=False),  # 3-5 most used
    *get_tmws_extended_tools(defer_loading=True),  # All others
    *get_user_skills(defer_loading=True)  # User-defined skills
]
```

**Option 2: Custom Client-Side Search**
```python
# Implement custom search with embeddings
def custom_tool_search(query: str) -> list[dict]:
    # Use TMWS VectorSearchService
    results = vector_search_service.search(
        collection_name="tool_embeddings",
        query=query,
        limit=5
    )

    # Return tool_reference blocks
    return [
        {"type": "tool_reference", "tool_name": result.tool_name}
        for result in results
    ]
```

**Recommendation**: Start with **Option 1** (server-side) for immediate benefits, evaluate **Option 2** if:
- Need semantic search beyond BM25
- Want integration with TMWS learning patterns
- Require custom ranking algorithms

### 7.3 Implementation Phases

**Phase 1: Tool Categorization** (Week 1)
- Identify 3-5 most frequently used TMWS tools
- Categorize remaining tools for deferred loading
- Write enhanced descriptions with semantic keywords

**Phase 2: Integration** (Week 2)
- Add `defer_loading` support to TMWS tool definitions
- Implement beta header configuration
- Test with Opus 4.5 and Sonnet 4.5

**Phase 3: Skill System Enhancement** (Week 3)
- Auto-defer all user-defined skills
- Implement skill description enhancement
- Monitor discovery accuracy

**Phase 4: Optimization** (Week 4)
- Analyze which tools Claude discovers
- Refine descriptions based on usage patterns
- Adjust non-deferred tool selection

### 7.4 Metrics to Track

**Token Efficiency**:
```python
before_tokens = sum(len(tool.definition) for tool in all_tools)
after_tokens = len(tool_search_tool) + sum(len(tool.definition) for tool in non_deferred_tools)
reduction_pct = (before_tokens - after_tokens) / before_tokens * 100
```

**Discovery Accuracy**:
```python
# Track successful tool invocations
discovered_and_used = count_tool_uses_after_search()
total_attempts = count_search_operations()
accuracy = discovered_and_used / total_attempts * 100
```

**Latency Impact**:
```python
# Compare response times
traditional_latency = measure_without_tool_search()
tool_search_latency = measure_with_tool_search()
# Expect: slight increase in first turn, faster subsequent turns
```

### 7.5 TMWS-Specific Considerations

**Agent Invocation**:
- Current: `invoke_persona` MCP tool always loaded
- Recommendation: Keep as non-deferred (frequently used)

**Memory Operations**:
- Current: `store_memory`, `search_memories` heavily used
- Recommendation: Keep as non-deferred

**Skill Management**:
- Current: `list_skills`, `activate_skill` used during setup
- Recommendation: Defer (only needed during configuration)

**Scheduler Control**:
- Current: `get_scheduler_status`, `start_scheduler` rarely used
- Recommendation: Defer

**Suggested Non-Deferred Tools (5)**:
1. `invoke_persona` (agent coordination)
2. `search_memories` (knowledge retrieval)
3. `store_memory` (knowledge creation)
4. `create_task` (workflow orchestration)
5. `get_agent_status` (system monitoring)

**Defer Everything Else**: 37 tools

**Expected Impact**:
```
Before: 42 tools × 500 tokens = 21,000 tokens
After:  5 tools × 500 tokens + 500 (search tool) = 3,000 tokens
Savings: 18,000 tokens (85% reduction)
```

---

## 8. Open Questions for TMWS Team

1. **User Experience**: Should tool search be opt-in or default for all TMWS users?
2. **Skill Onboarding**: Should new user skills automatically get `defer_loading: true`?
3. **Description Generation**: Should TMWS auto-enhance skill descriptions with AI-generated keywords?
4. **MCP Hub Integration**: How should Tool Search interact with TMWS's upcoming MCP Hub (v2.4.16)?
5. **Learning Patterns**: Can TMWS Learning Patterns inform tool search rankings?

---

## Sources

- [Tool search tool - Claude Docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool)
- [Introducing advanced tool use on the Claude Developer Console](https://www.anthropic.com/engineering/advanced-tool-use)
- [Prompt caching - Claude Docs](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
- [Web search tool - Claude Docs](https://docs.claude.com/en/docs/agents-and-tools/tool-use/web-search-tool)
- [How to implement tool use - Claude Docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/implement-tool-use)

---

**End of Technical Specifications Report**
