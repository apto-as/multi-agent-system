# Progressive Disclosure Strategy
## Context Window Management for 100+ MCP Servers

**Status**: Phase 2E-2 Design Document
**Created**: 2025-11-20
**Architect**: Artemis (Technical Perfectionist)

---

## Problem Statement

**Challenge**: 100+ MCP servers with full schemas would consume 95,000-140,000 tokens (exceeds Claude's context limit).

**Target**: Reduce to 8,000-12,000 tokens (92-94% reduction) while maintaining discoverability.

---

## Solution: 4-Tier Hierarchical Loading

### Tier System

| Tier | Description | Token Budget | Tools Loaded | Use Case |
|------|-------------|--------------|--------------|----------|
| **T0** | Hot List | 1,500-2,000 | Top 10-15 | Initial context, frequently used |
| **T1** | Category Overview | 3,000-4,000 | Category summaries | Browsing menu |
| **T2** | Tool Summaries | 6,000-8,000 | 30-50 tools (brief) | Filtering & selection |
| **T3** | Full Schema | 10,000-12,000 | 5-10 tools (detailed) | Actual invocation |

### Tier Definitions

#### T0: Hot List (Initial Context)

**What's Loaded**:
- Top 10-15 most popular tools
- 1-2 sentence description
- Basic parameters (no nested schemas)

**Token Budget**: 1,500-2,000 tokens

**Example**:
```json
{
  "tier": "hot",
  "tools": [
    {
      "tool": "serena::find_symbol",
      "server": "serena-mcp-server",
      "description": "Find code symbols (classes, functions) by name pattern",
      "params": ["name_path_pattern", "relative_path"],
      "avg_latency": "47ms",
      "success_rate": "98.7%"
    },
    {
      "tool": "playwright::browser_snapshot",
      "server": "playwright",
      "description": "Capture accessibility snapshot of web page",
      "params": [],
      "avg_latency": "120ms",
      "success_rate": "99.2%"
    }
    // ... 8 more
  ]
}
```

**SQL Query**:
```sql
SELECT
    tool_name,
    display_name,
    description,
    parameters_schema -> 'required' AS required_params,
    avg_latency_ms,
    success_count * 100.0 / NULLIF(total_invocations, 0) AS success_rate
FROM mcp_tools
WHERE tier = 'hot'
ORDER BY tier_score DESC
LIMIT 15;
```

---

#### T1: Category Overview (Menu Navigation)

**What's Loaded**:
- All category names + descriptions
- Tool counts per category
- No individual tool details

**Token Budget**: 3,000-4,000 tokens (incremental from T0)

**Example**:
```json
{
  "tier": "category_overview",
  "categories": [
    {
      "category": "code_analysis",
      "display_name": "Code Analysis & Refactoring",
      "description": "Static analysis, symbol search, dependency management",
      "tool_count": 12,
      "server_count": 4,
      "popular_tools": ["serena::find_symbol", "pylint::analyze"]
    },
    {
      "category": "web_automation",
      "display_name": "Web Automation & Scraping",
      "description": "Browser automation, HTTP clients, web scraping",
      "tool_count": 15,
      "server_count": 5,
      "popular_tools": ["playwright::browser_snapshot", "http-mcp::fetch"]
    }
    // ... 8 more categories
  ]
}
```

**SQL Query**:
```sql
SELECT
    c.category_name,
    c.display_name,
    c.description,
    COUNT(DISTINCT t.id) AS tool_count,
    COUNT(DISTINCT s.id) AS server_count,
    ARRAY_AGG(
        t.tool_name ORDER BY t.tier_score DESC LIMIT 2
    ) AS popular_tools
FROM mcp_categories c
JOIN mcp_tools t ON t.primary_category = c.category_name
JOIN mcp_servers s ON t.server_id = s.id
WHERE s.is_active = TRUE
GROUP BY c.category_name, c.display_name, c.description
ORDER BY c.sort_order;
```

---

#### T2: Tool Summaries (Filtered List)

**What's Loaded**:
- 30-50 tools matching user's filter/search
- Brief descriptions (1 sentence)
- Basic parameters (top-level only, no nested objects)

**Token Budget**: 6,000-8,000 tokens (incremental from T1)

**Example**:
```json
{
  "tier": "tool_summaries",
  "filter": "category=code_analysis",
  "tools": [
    {
      "tool": "serena::find_symbol",
      "server": "serena-mcp-server",
      "description": "Find code symbols by name pattern",
      "params": {
        "name_path_pattern": "string (required)",
        "relative_path": "string (optional)"
      },
      "returns": "list of symbols with locations",
      "avg_latency": "47ms"
    },
    {
      "tool": "serena::find_referencing_symbols",
      "server": "serena-mcp-server",
      "description": "Find all references to a symbol",
      "params": {
        "name_path": "string (required)",
        "relative_path": "string (required)"
      },
      "returns": "list of referencing symbols",
      "avg_latency": "89ms"
    }
    // ... 28 more tools in code_analysis category
  ]
}
```

**SQL Query**:
```sql
SELECT
    t.tool_name,
    s.server_name,
    t.description,
    t.parameters_schema,  -- Simplified in application layer
    t.avg_latency_ms
FROM mcp_tools t
JOIN mcp_servers s ON t.server_id = s.id
WHERE t.primary_category = 'code_analysis'
  AND s.is_active = TRUE
ORDER BY t.tier_score DESC
LIMIT 50;
```

**Token Optimization**:
```python
def simplify_params(full_schema: dict) -> dict:
    """Reduce parameter schema to top-level types only."""
    simplified = {}
    for param_name, param_spec in full_schema.get("properties", {}).items():
        param_type = param_spec.get("type", "unknown")
        is_required = param_name in full_schema.get("required", [])
        simplified[param_name] = f"{param_type} ({'required' if is_required else 'optional'})"
    return simplified
```

---

#### T3: Full Schema (Invocation Ready)

**What's Loaded**:
- 5-10 tools with complete schemas
- All nested objects, enums, examples
- Full parameter descriptions
- Return value specifications

**Token Budget**: 10,000-12,000 tokens (incremental from T2)

**Example**:
```json
{
  "tier": "full_schema",
  "tool": "serena::find_symbol",
  "server": "serena-mcp-server",
  "description": "Retrieves information on all symbols/code entities (classes, methods, etc.) based on the given name path pattern. The returned symbol information can be used for edits or further queries. Specify `depth > 0` to also retrieve children/descendants (e.g., methods of a class).",

  "parameters": {
    "type": "object",
    "properties": {
      "name_path_pattern": {
        "type": "string",
        "description": "The name path matching pattern. Can be a simple name (e.g., 'method'), a relative path like 'class/method', or an absolute name path '/class/method'. Append an index `[i]` to match a specific overload.",
        "examples": ["UserController", "MyClass/my_method", "/App/Config/load[0]"]
      },
      "relative_path": {
        "type": "string",
        "default": "",
        "description": "Optional. Restrict search to this file or directory. If None, searches entire codebase."
      },
      "depth": {
        "type": "integer",
        "default": 0,
        "description": "Depth up to which descendants shall be retrieved (e.g., use 1 to also retrieve immediate children; for the case where the symbol is a class, this will return its methods)."
      },
      "include_body": {
        "type": "boolean",
        "default": false,
        "description": "If True, include the symbol's source code. Use judiciously."
      }
    },
    "required": ["name_path_pattern"]
  },

  "returns": {
    "type": "array",
    "items": {
      "type": "object",
      "properties": {
        "name": "string",
        "file_path": "string",
        "line_number": "integer",
        "kind": "string (e.g., 'class', 'function')",
        "body": "string (if include_body=true)"
      }
    }
  },

  "examples": [
    {
      "query": {"name_path_pattern": "UserController"},
      "description": "Find all symbols named 'UserController'"
    },
    {
      "query": {"name_path_pattern": "get*", "relative_path": "src/api/"},
      "description": "Find all symbols starting with 'get' in src/api/ directory"
    }
  ],

  "performance": {
    "avg_latency_ms": 47,
    "p95_latency_ms": 89,
    "success_rate": 98.7,
    "total_invocations": 12453
  }
}
```

**SQL Query**:
```sql
SELECT
    t.*,
    s.server_name,
    s.display_name AS server_display_name,
    s.docker_image,
    s.network_mode
FROM mcp_tools t
JOIN mcp_servers s ON t.server_id = s.id
WHERE t.tool_name = 'find_symbol'
  AND s.server_name = 'serena-mcp-server';
```

---

## Loading Strategy

### Lazy Loading Flow

```
User starts conversation
   ↓
[T0] Load hot list (1,500 tokens)
   ↓ (Initial context: 10-15 popular tools)

User: "Show me code analysis tools"
   ↓
[T1] Load category overview (+ 1,500 tokens = 3,000 total)
   ↓ (User sees: 10 categories with tool counts)

User: "Show me tools in code_analysis category"
   ↓
[T2] Load tool summaries for code_analysis (+ 3,000 tokens = 6,000 total)
   ↓ (User sees: 30-50 tools with brief descriptions)

User: "I want to use serena::find_symbol"
   ↓
[T3] Load full schema for serena::find_symbol (+ 4,000 tokens = 10,000 total)
   ↓ (Agent has: Complete parameter schema, ready to invoke)
```

### API Endpoints

```python
# FastAPI endpoints for progressive disclosure

@app.get("/api/v1/tools/hot")
async def get_hot_tools() -> HotToolsResponse:
    """T0: Get top 10-15 most popular tools."""
    # Query: WHERE tier = 'hot' ORDER BY tier_score DESC LIMIT 15
    # Token budget: 1,500-2,000

@app.get("/api/v1/tools/categories")
async def get_categories() -> CategoryOverviewResponse:
    """T1: Get category overview with tool counts."""
    # Query: GROUP BY category, COUNT(tools)
    # Token budget: 3,000-4,000 (incremental)

@app.get("/api/v1/tools/category/{category_name}")
async def get_tools_in_category(category_name: str) -> ToolSummariesResponse:
    """T2: Get tool summaries for a specific category."""
    # Query: WHERE category = ? ORDER BY tier_score DESC LIMIT 50
    # Token budget: 6,000-8,000 (incremental)

@app.get("/api/v1/tools/{server_name}/{tool_name}")
async def get_tool_schema(server_name: str, tool_name: str) -> FullToolSchemaResponse:
    """T3: Get full schema for a specific tool."""
    # Query: WHERE server_name = ? AND tool_name = ?
    # Token budget: 10,000-12,000 (incremental)
```

---

## Tier Assignment Algorithm

### Computing `tier_score`

```python
def compute_tier_score(tool: MCPTool) -> float:
    """
    Compute weighted score for tier assignment.

    Factors:
    - Popularity (40%): Total invocations
    - Reliability (30%): Success rate
    - Performance (20%): Latency (lower is better)
    - Recency (10%): Recent usage trend
    """
    # Normalize to 0-1 scale
    popularity_score = min(tool.total_invocations / 10000, 1.0)  # Cap at 10k
    reliability_score = tool.success_count / max(tool.total_invocations, 1)
    performance_score = max(0, 1 - tool.avg_latency_ms / 1000)  # Cap at 1s

    # Recency: Usage in last 7 days vs last 30 days
    recent_usage = await get_usage_count(tool.id, days=7)
    historical_usage = await get_usage_count(tool.id, days=30)
    recency_score = recent_usage / max(historical_usage, 1) if historical_usage > 0 else 0

    # Weighted average
    tier_score = (
        0.40 * popularity_score +
        0.30 * reliability_score +
        0.20 * performance_score +
        0.10 * recency_score
    )

    return round(tier_score, 2)

def assign_tier(tier_score: float) -> str:
    """Assign tier based on score thresholds."""
    if tier_score >= 0.80:
        return "hot"      # Top 10-15 tools
    elif tier_score >= 0.60:
        return "warm"     # Next 20-30 tools
    elif tier_score >= 0.30:
        return "standard" # Common tools
    else:
        return "cold"     # Rarely used or new tools
```

### Batch Update Job

```python
# Cron job: Run daily to update tier assignments
async def update_tier_scores():
    """Recompute tier scores for all tools."""
    tools = await db.query(MCPTool).all()

    for tool in tools:
        new_score = await compute_tier_score(tool)
        new_tier = assign_tier(new_score)

        await db.execute(
            "UPDATE mcp_tools SET tier_score = ?, tier = ? WHERE id = ?",
            (new_score, new_tier, tool.id)
        )

    await db.commit()
    logger.info(f"Updated tier scores for {len(tools)} tools")
```

---

## Context Window Budget Verification

### Token Calculation

```python
import tiktoken

def estimate_tokens(text: str) -> int:
    """Estimate token count using tiktoken (Claude's tokenizer)."""
    encoding = tiktoken.encoding_for_model("claude-3-sonnet")
    return len(encoding.encode(text))

async def verify_tier_budget():
    """Verify that each tier stays within token budget."""

    # T0: Hot list
    hot_tools = await get_hot_tools()
    hot_json = json.dumps(hot_tools, indent=2)
    hot_tokens = estimate_tokens(hot_json)
    assert hot_tokens <= 2000, f"T0 exceeds budget: {hot_tokens} tokens"

    # T1: Category overview
    categories = await get_categories()
    cat_json = json.dumps(categories, indent=2)
    cat_tokens = estimate_tokens(cat_json)
    total_t1 = hot_tokens + cat_tokens
    assert total_t1 <= 4000, f"T1 exceeds budget: {total_t1} tokens"

    # T2: Tool summaries (worst case: largest category)
    largest_category = await get_largest_category()
    tools = await get_tools_in_category(largest_category)
    tools_json = json.dumps(tools, indent=2)
    tools_tokens = estimate_tokens(tools_json)
    total_t2 = total_t1 + tools_tokens
    assert total_t2 <= 8000, f"T2 exceeds budget: {total_t2} tokens"

    # T3: Full schema (worst case: 10 largest tools)
    largest_tools = await get_largest_tools(limit=10)
    full_schema_json = json.dumps(largest_tools, indent=2)
    schema_tokens = estimate_tokens(full_schema_json)
    total_t3 = total_t2 + schema_tokens
    assert total_t3 <= 12000, f"T3 exceeds budget: {total_t3} tokens"

    logger.info(f"Budget verification: T0={hot_tokens}, T1={total_t1}, T2={total_t2}, T3={total_t3}")
```

---

## Fallback Strategy

### Context Window Overflow Protection

```python
async def load_tools_with_budget(
    category: str,
    max_tokens: int = 6000
) -> list[ToolSummary]:
    """Load tools until token budget is exhausted."""

    tools = await get_tools_in_category(category)
    loaded = []
    total_tokens = 0

    for tool in tools:
        tool_json = json.dumps(tool.to_summary())
        tool_tokens = estimate_tokens(tool_json)

        if total_tokens + tool_tokens > max_tokens:
            logger.warning(
                f"Token budget exhausted at {len(loaded)}/{len(tools)} tools. "
                f"Use pagination or narrower search."
            )
            break

        loaded.append(tool)
        total_tokens += tool_tokens

    return loaded
```

### Pagination Support

```python
@app.get("/api/v1/tools/category/{category_name}")
async def get_tools_in_category(
    category_name: str,
    page: int = 1,
    page_size: int = 20  # Adjustable for token budget
) -> ToolSummariesResponse:
    """T2: Get tool summaries with pagination."""

    offset = (page - 1) * page_size
    tools = await db.query(MCPTool).filter(
        MCPTool.primary_category == category_name
    ).order_by(
        MCPTool.tier_score.desc()
    ).limit(page_size).offset(offset).all()

    total_count = await db.query(MCPTool).filter(
        MCPTool.primary_category == category_name
    ).count()

    return {
        "tools": tools,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_count": total_count,
            "total_pages": (total_count + page_size - 1) // page_size
        }
    }
```

---

## Performance Targets

| Tier | Query Latency (P95) | Token Count | Cache Hit Rate |
|------|---------------------|-------------|----------------|
| T0   | <20ms               | 1,500-2,000 | 95%+ (static) |
| T1   | <30ms               | 3,000-4,000 | 90%+ (daily update) |
| T2   | <50ms               | 6,000-8,000 | 70%+ (category-dependent) |
| T3   | <100ms              | 10,000-12,000 | 50%+ (tool-specific) |

### Caching Strategy

```python
from functools import lru_cache
import asyncio

# T0: Cache hot list for 1 hour (rarely changes)
@lru_cache(maxsize=1)
async def get_hot_tools_cached() -> HotToolsResponse:
    tools = await get_hot_tools()
    asyncio.create_task(asyncio.sleep(3600))  # Invalidate after 1 hour
    return tools

# T1: Cache category overview for 6 hours
@lru_cache(maxsize=1)
async def get_categories_cached() -> CategoryOverviewResponse:
    categories = await get_categories()
    asyncio.create_task(asyncio.sleep(21600))
    return categories

# T2: Cache category tools for 1 hour per category
category_cache: dict[str, tuple[float, list[ToolSummary]]] = {}

async def get_tools_in_category_cached(category: str) -> list[ToolSummary]:
    if category in category_cache:
        cached_time, cached_tools = category_cache[category]
        if time.time() - cached_time < 3600:  # 1 hour
            return cached_tools

    tools = await get_tools_in_category(category)
    category_cache[category] = (time.time(), tools)
    return tools
```

---

## User Experience Examples

### Example 1: New User Discovery

```
Claude: "I'm loading the 10 most popular tools for you..."
   ↓ (T0: 1,500 tokens)

Available tools:
1. serena::find_symbol - Find code symbols
2. playwright::browser_snapshot - Capture web page
3. grep::search_for_pattern - Search text patterns
... (7 more)

Claude: "You can browse by category or search by intent. What would you like to do?"

User: "Show me categories"
   ↓ (T1: +1,500 tokens = 3,000 total)

Categories:
📁 Code Analysis (12 tools)
📁 Web Automation (15 tools)
📁 Document Generation (7 tools)
... (7 more)
```

### Example 2: Expert Power User

```
User: "Find Python static analysis tools with <100ms latency"
   ↓ (Direct to T2 with filters)

Claude: [Queries DB with filters, loads 8 matching tools]
   ↓ (T2: 4,000 tokens directly)

8 tools match your criteria:
1. serena-mcp-server (47ms avg, 98.7% success)
2. mypy-mcp (82ms avg, 97.2% success)
3. pylint-mcp (95ms avg, 96.1% success)
... (5 more)

User: "Use serena::find_symbol"
   ↓ (T3: Full schema loaded)

Claude: [Loads full schema, ready to invoke]
```

---

## Conclusion

**4-Tier Progressive Disclosure**:
- ✅ **T0 (Hot)**: 1,500 tokens - Most popular tools, instant context
- ✅ **T1 (Categories)**: 3,000 tokens - Menu navigation
- ✅ **T2 (Summaries)**: 6,000 tokens - Filtered tool list
- ✅ **T3 (Full)**: 10,000 tokens - Invocation-ready schemas

**Result**: 92-94% token reduction (from 95,000-140,000 to 8,000-12,000 tokens)

**Performance**: <50ms query latency with aggressive caching.
