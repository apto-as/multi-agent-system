# MCP Tool Catalog
## The "Restaurant Menu" for Trinitas Agents

**Version**: 1.0.0
**Last Updated**: 2025-11-20
**Status**: Production-ready
**Tool Count**: 60+ tools across 8 MCP servers

---

## 🍽️ Welcome to the MCP Tool Catalog

This catalog provides a **restaurant menu-like experience** for discovering and using MCP tools. Browse by category, search by intent, or explore our "Chef's Specials" — the most popular and effective tools.

### How to Use This Catalog

1. **Browse by Category** → Find tools organized by domain (Code, Web, Data, etc.)
2. **Search by Intent** → Describe what you want to do, get tool recommendations
3. **Check "Today's Specials"** → See popular tools with high success rates
4. **Read the "Recipe Card"** → Get detailed usage examples for each tool

---

## 🏆 TODAY'S SPECIALS
### Most Popular & Highest Success Rate

<table>
<tr>
<td width="50%">

### ⭐ serena-mcp-server
**Category**: Code Analysis
**Success Rate**: 98.3% ⭐⭐⭐⭐⭐
**Average Latency**: ~15ms 🚀

**Best for**: Finding symbols, analyzing code structure, and refactoring support across Python, TypeScript, JavaScript codebases.

**Why it's special**: Intelligent symbol search with zero false positives. Understands code structure better than grep.

[→ See Tools](#serena-mcp-server) | [→ Examples](#serena-examples)

</td>
<td width="50%">

### ⭐ playwright-mcp
**Category**: Web Automation
**Success Rate**: 96.7% ⭐⭐⭐⭐⭐
**Average Latency**: ~50ms ⚡

**Best for**: E2E testing, browser automation, and dynamic web scraping.

**Why it's special**: Full browser control with screenshot support. Works with any modern web app.

[→ See Tools](#playwright-mcp) | [→ Examples](#playwright-examples)

</td>
</tr>
<tr>
<td width="50%">

### ⭐ tmws (TMWS Memory)
**Category**: Knowledge Management
**Success Rate**: 99.1% ⭐⭐⭐⭐⭐
**Average Latency**: ~5ms 🚀

**Best for**: Semantic memory storage, cross-agent knowledge sharing, and task coordination.

**Why it's special**: Dual storage (SQLite + ChromaDB) with 1024-dim semantic search. Perfect for agent collaboration.

[→ See Tools](#tmws) | [→ Examples](#tmws-examples)

</td>
<td width="50%">

### ⭐ context7
**Category**: Documentation
**Success Rate**: 94.5% ⭐⭐⭐⭐
**Average Latency**: ~200ms

**Best for**: Fetching latest library documentation, API references, and best practices.

**Why it's special**: Always up-to-date docs from official sources. Supports 1000+ libraries.

[→ See Tools](#context7) | [→ Examples](#context7-examples)

</td>
</tr>
</table>

---

## 📋 BROWSE BY CATEGORY

### Quick Navigation

- [🔍 Code Analysis & Search](#category-code-analysis) (12 tools)
- [📁 File Operations](#category-file-operations) (8 tools)
- [🌐 Web Automation](#category-web-automation) (15 tools)
- [📊 Data Processing](#category-data-processing) (4 tools)
- [📝 Documentation & Knowledge](#category-documentation) (6 tools)
- [🧠 Memory & Workflow](#category-memory-workflow) (21 tools)
- [🔗 Cloud & Integration](#category-cloud-integration) (5 tools)

---

## 🔍 Category: Code Analysis & Search {#category-code-analysis}

**When to use**: Understanding codebases, finding symbols, refactoring, analyzing dependencies.

### serena-mcp-server {#serena-mcp-server}

**Description**: Intelligent code analysis with symbol search, refactoring support, and pattern matching.

**Supported Languages**: Python, TypeScript, JavaScript, Go, Rust
**Performance**: ~15ms average 🚀
**Security**: ⚠️ Read access to project files (Docker isolated)

#### Available Tools (12)

| Tool | Purpose | Latency | Success Rate |
|------|---------|---------|--------------|
| `find_symbol` | Locate classes, functions, variables | ~15ms | 98.3% ⭐⭐⭐⭐⭐ |
| `get_symbols_overview` | High-level code structure | ~20ms | 97.1% ⭐⭐⭐⭐⭐ |
| `search_for_pattern` | Regex search across codebase | ~25ms | 96.5% ⭐⭐⭐⭐ |
| `find_referencing_symbols` | Find all usages of a symbol | ~30ms | 95.8% ⭐⭐⭐⭐ |
| `replace_symbol_body` | Replace symbol implementation | ~40ms | 94.2% ⭐⭐⭐⭐ |
| `insert_after_symbol` | Add code after a symbol | ~35ms | 93.7% ⭐⭐⭐⭐ |
| `insert_before_symbol` | Add code before a symbol | ~35ms | 93.7% ⭐⭐⭐⭐ |
| `rename_symbol` | Rename symbol across codebase | ~50ms | 92.1% ⭐⭐⭐⭐ |
| `list_dir` | List files and directories | ~10ms | 99.0% ⭐⭐⭐⭐⭐ |
| `find_file` | Find files by name/pattern | ~12ms | 98.5% ⭐⭐⭐⭐⭐ |
| `initial_instructions` | Get Serena usage guide | ~5ms | 100% ⭐⭐⭐⭐⭐ |
| `activate_project` | Switch between projects | ~15ms | 99.2% ⭐⭐⭐⭐⭐ |

#### Examples {#serena-examples}

**Example 1: Find a specific class**
```python
# Find UserController class
mcp__serena-mcp-server__find_symbol(
    name_path_pattern="UserController",
    relative_path="",
    depth=0,
    include_body=False
)

# Returns: Location, signature, and metadata
```

**Example 2: Find all usages of a function**
```python
# Find everywhere calculate_total is called
mcp__serena-mcp-server__find_referencing_symbols(
    name_path="calculate_total",
    relative_path="src/services/payment_service.py"
)

# Returns: All call sites with code snippets
```

**Example 3: Refactor - rename a method**
```python
# Rename process_payment → handle_payment (across entire codebase)
mcp__serena-mcp-server__rename_symbol(
    name_path="PaymentService/process_payment",
    relative_path="src/services/payment_service.py",
    new_name="handle_payment"
)

# Automatically updates all references
```

**Best Practices**:
- ✅ Use `depth=1` to include immediate children (e.g., class methods)
- ✅ Use `relative_path` to narrow search scope for faster results
- ✅ Always use `find_referencing_symbols` before `rename_symbol` to check impact
- ⚠️ `replace_symbol_body` is destructive - verify symbol body first with `include_body=True`

---

## 📁 Category: File Operations {#category-file-operations}

**When to use**: Reading files, listing directories, searching file contents.

### serena-mcp-server (File Tools)

| Tool | Purpose | Latency | Use Case |
|------|---------|---------|----------|
| `list_dir` | List directory contents | ~10ms | Explore project structure |
| `find_file` | Find files by glob pattern | ~12ms | Locate specific files |

**Note**: Use native `Read`, `Write`, `Edit` tools for file content operations (faster, no overhead).

---

## 🌐 Category: Web Automation {#category-web-automation}

**When to use**: E2E testing, browser automation, web scraping, screenshot generation.

### playwright-mcp {#playwright-mcp}

**Description**: Full browser automation with support for Chromium, Firefox, and WebKit.

**Performance**: ~50ms average ⚡
**Security**: ⚠️ Network access required, runs in sandboxed browser

#### Available Tools (15)

| Tool | Purpose | Latency | Success Rate |
|------|---------|---------|--------------|
| `browser_navigate` | Navigate to URL | ~50ms | 98.1% ⭐⭐⭐⭐⭐ |
| `browser_snapshot` | Capture accessibility tree | ~40ms | 97.8% ⭐⭐⭐⭐⭐ |
| `browser_click` | Click element | ~30ms | 96.5% ⭐⭐⭐⭐ |
| `browser_type` | Type text into element | ~35ms | 96.2% ⭐⭐⭐⭐ |
| `browser_fill_form` | Fill multiple form fields | ~60ms | 95.1% ⭐⭐⭐⭐ |
| `browser_take_screenshot` | Take screenshot (PNG/JPEG) | ~80ms | 99.0% ⭐⭐⭐⭐⭐ |
| `browser_evaluate` | Execute JavaScript | ~45ms | 94.3% ⭐⭐⭐⭐ |
| `browser_wait_for` | Wait for condition | ~100ms | 93.7% ⭐⭐⭐⭐ |
| `browser_console_messages` | Get console logs | ~20ms | 98.5% ⭐⭐⭐⭐⭐ |
| `browser_network_requests` | Get network activity | ~25ms | 97.2% ⭐⭐⭐⭐ |
| `browser_tabs` | Manage browser tabs | ~30ms | 96.8% ⭐⭐⭐⭐ |
| `browser_resize` | Resize browser window | ~15ms | 99.1% ⭐⭐⭐⭐⭐ |
| `browser_close` | Close browser session | ~10ms | 100% ⭐⭐⭐⭐⭐ |
| `browser_file_upload` | Upload files | ~50ms | 94.5% ⭐⭐⭐⭐ |
| `browser_handle_dialog` | Handle alerts/confirms | ~40ms | 95.3% ⭐⭐⭐⭐ |

#### Examples {#playwright-examples}

**Example 1: Navigate and take screenshot**
```python
# Navigate to page
mcp__playwright__browser_navigate(url="https://example.com")

# Take full-page screenshot
mcp__playwright__browser_take_screenshot(
    filename="homepage.png",
    fullPage=True,
    type="png"
)
```

**Example 2: Fill login form and submit**
```python
# Fill form fields
mcp__playwright__browser_fill_form(
    fields=[
        {"name": "Email", "type": "textbox", "ref": "input#email", "value": "test@example.com"},
        {"name": "Password", "type": "textbox", "ref": "input#password", "value": "secret123"}
    ]
)

# Click submit button
mcp__playwright__browser_click(
    element="Login button",
    ref="button[type='submit']"
)

# Wait for redirect
mcp__playwright__browser_wait_for(text="Dashboard")
```

**Example 3: Get network logs for debugging**
```python
# Get all network requests
requests = mcp__playwright__browser_network_requests()

# Filter failed requests
failed = [r for r in requests if r['status'] >= 400]
print(f"Failed requests: {len(failed)}")
```

**Best Practices**:
- ✅ Use `browser_snapshot` before interactions to get element refs
- ✅ Use `browser_wait_for` to avoid flaky tests
- ✅ Always call `browser_close` when done to free resources
- ⚠️ Screenshots consume memory - use sparingly in loops

---

## 📊 Category: Data Processing {#category-data-processing}

**When to use**: Converting documents, parsing PDFs, transforming data formats.

### markitdown {#markitdown}

**Description**: Convert web pages, PDFs, Word docs to clean Markdown.

**Supported Formats**: HTML, PDF, DOCX, PPTX, XLSX
**Performance**: ~500ms average (depends on document size)
**Security**: ✅ No network access, local processing only

#### Available Tools (1)

| Tool | Purpose | Use Case |
|------|---------|----------|
| `convert` | Convert document to Markdown | Import external docs, parse PDFs |

**Example**:
```python
# Convert PDF to Markdown
markdown = mcp__markitdown__convert(
    file_path="/path/to/document.pdf"
)

# Store in knowledge base
await store_memory(
    content=markdown,
    tags=["external-doc", "pdf"],
    importance_score=0.8
)
```

---

## 📝 Category: Documentation & Knowledge {#category-documentation}

**When to use**: Fetching library docs, API references, best practices.

### context7 {#context7}

**Description**: Fetch up-to-date documentation from official sources for 1000+ libraries.

**Coverage**: Python, JavaScript/TypeScript, Go, Rust, Java
**Performance**: ~200ms average
**Security**: ✅ Read-only, official sources only

#### Available Tools (2)

| Tool | Purpose | Latency | Use Case |
|------|---------|---------|----------|
| `resolve-library-id` | Find Context7 library ID | ~100ms | Resolve ambiguous library names |
| `get-library-docs` | Fetch documentation | ~200ms | Get API reference, usage examples |

#### Examples {#context7-examples}

**Example 1: Get FastAPI documentation**
```python
# Step 1: Resolve library ID
library_info = mcp__context7__resolve-library-id(
    libraryName="fastapi"
)
# Returns: "/tiangolo/fastapi"

# Step 2: Get docs
docs = mcp__context7__get-library-docs(
    context7CompatibleLibraryID="/tiangolo/fastapi",
    topic="authentication",  # Optional: focus on specific topic
    page=1
)

# Returns: Authentication guide with code examples
```

**Example 2: Version-specific docs**
```python
# Get Next.js v14 docs specifically
docs = mcp__context7__get-library-docs(
    context7CompatibleLibraryID="/vercel/next.js/v14.0.0",
    topic="server-components"
)
```

**Best Practices**:
- ✅ Always use `resolve-library-id` first (handles aliases and versions)
- ✅ Use `topic` parameter to narrow results (faster, more relevant)
- ✅ Check multiple pages (`page=2`, `page=3`) if first page insufficient
- ⚠️ Respect rate limits - cache docs in TMWS memory for reuse

---

## 🧠 Category: Memory & Workflow {#category-memory-workflow}

**When to use**: Agent collaboration, knowledge sharing, task coordination, trust verification.

### tmws {#tmws}

**Description**: Semantic memory storage with ChromaDB vector search, task management, and agent trust verification.

**Storage**: Dual (SQLite + ChromaDB)
**Embedding**: Multilingual-E5-Large (1024 dimensions)
**Performance**: ~2-20ms P95 🚀
**Security**: ⚠️ Namespace isolation, RBAC enforcement

#### Tool Categories (21 tools total)

**Core Memory (3 tools)**
- `store_memory` - Store information with semantic search
- `search_memories` - Vector similarity search
- `create_task` - Coordinated multi-agent tasks

**System Management (3 tools)**
- `get_agent_status` - Check connected agents
- `get_memory_stats` - Storage statistics
- `invalidate_cache` - Clear vector cache (testing only)

**Expiration Management (10 tools)**
- `prune_expired_memories` - Remove expired items
- `get_expiration_stats` - Expiration analytics
- `set_memory_ttl` - Update memory lifespan
- `cleanup_namespace` - Delete all (admin only)
- `get_namespace_stats` - Namespace analytics
- `get_scheduler_status` - Check auto-cleanup
- `configure_scheduler` - Set cleanup interval
- `start_scheduler` - Start auto-cleanup
- `stop_scheduler` - Stop auto-cleanup
- `trigger_scheduler` - Manual cleanup

**Trust & Verification (5 tools)**
- `verify_and_record` - Verify agent claims
- `get_agent_trust_score` - Get trust metrics
- `get_verification_history` - Audit trail
- `get_verification_statistics` - Trust analytics
- `get_trust_history` - Trust score evolution

#### Examples {#tmws-examples}

**Example 1: Store daily progress (cross-agent sharing)**
```python
# Artemis stores progress
result = await mcp__tmws__store_memory(
    content="Phase 1-2 completed: JWT authentication + refresh tokens implemented. All 28 tests passing.",
    importance_score=0.85,
    tags=["milestone", "phase1-2", "authentication"],
    namespace="trinitas-agents"  # Shared namespace
)

# Hestia can search it later
results = await mcp__tmws__search_memories(
    query="What authentication features were completed?",
    namespace="trinitas-agents",
    limit=5
)
```

**Example 2: Verify agent claims**
```python
# Artemis claims tests passed
verification = await mcp__tmws__verify_and_record(
    agent_id="artemis-optimizer",
    claim_type="test_result",
    claim_content={
        "passed": 150,
        "failed": 0,
        "coverage": 92.5
    },
    verification_command="pytest tests/unit/ -v --cov=src",
    verified_by_agent_id="hestia-auditor"
)

if verification['accurate']:
    print("✅ Trust score increased")
else:
    print(f"⚠️ Claim inaccurate! New trust score: {verification['new_trust_score']:.2f}")
```

**Example 3: Task coordination**
```python
# Hera creates task for Artemis
task = await mcp__tmws__create_task(
    title="Implement rate limiting for API endpoints",
    description="Add Redis-based rate limiting (100 req/min per user)",
    priority="high",
    assigned_agent_id="artemis-optimizer",
    estimated_duration=120,  # 2 hours
    due_date="2025-11-21T17:00:00Z"
)
```

**Best Practices**:
- ✅ Use `importance_score` 0.8+ for critical information (never expires automatically)
- ✅ Use descriptive `tags` for efficient filtering
- ✅ Share across agents via `namespace` (team collaboration)
- ✅ Verify critical claims with `verify_and_record` (builds trust)
- ⚠️ Set TTL for temporary information (`set_memory_ttl`)

---

## 🔗 Category: Cloud & Integration {#category-cloud-integration}

**When to use**: Google Drive access, Google Sheets manipulation, cloud storage.

### gdrive {#gdrive}

**Description**: Search and read files from Google Drive, manipulate Google Sheets.

**Performance**: ~300-500ms (network dependent)
**Security**: ⚠️ OAuth required, read/write access to Drive

#### Available Tools (5)

| Tool | Purpose | Use Case |
|------|---------|----------|
| `gdrive_search` | Search Drive files | Find documents by query |
| `gdrive_read_file` | Read file contents | Import docs to memory |
| `gsheets_read` | Read spreadsheet data | Import tabular data |
| `gsheets_update_cell` | Update cell value | Write results back |

**Example**:
```python
# Search for project docs
files = mcp__gdrive__gdrive_search(
    query="name contains 'TMWS' and mimeType='application/pdf'",
    pageSize=10
)

# Read first file
content = mcp__gdrive__gdrive_read_file(
    fileId=files['files'][0]['id']
)
```

---

## 🔎 SEARCH BY INTENT

**How it works**: Describe what you want to do, get tool recommendations.

### Example Queries

**Query**: "I want to find where a Python function is defined"
**Recommended Tools**:
1. `serena__find_symbol` (relevance: 98%) ⭐⭐⭐⭐⭐
2. `serena__search_for_pattern` (relevance: 75%) ⭐⭐⭐⭐

---

**Query**: "I need to test login functionality in a web app"
**Recommended Tools**:
1. `playwright__browser_navigate` (relevance: 95%) ⭐⭐⭐⭐⭐
2. `playwright__browser_fill_form` (relevance: 92%) ⭐⭐⭐⭐⭐
3. `playwright__browser_click` (relevance: 90%) ⭐⭐⭐⭐⭐

---

**Query**: "I want to remember important project decisions"
**Recommended Tools**:
1. `tmws__store_memory` (relevance: 97%) ⭐⭐⭐⭐⭐
2. `tmws__search_memories` (relevance: 85%) ⭐⭐⭐⭐⭐

---

**Query**: "I need the latest FastAPI documentation"
**Recommended Tools**:
1. `context7__get-library-docs` (relevance: 99%) ⭐⭐⭐⭐⭐
2. `context7__resolve-library-id` (relevance: 90%) ⭐⭐⭐⭐⭐

---

**Query**: "Convert PDF report to markdown"
**Recommended Tools**:
1. `markitdown__convert` (relevance: 100%) ⭐⭐⭐⭐⭐

---

## 📊 PERFORMANCE REFERENCE

### Latency Categories

| Symbol | Latency | Description |
|--------|---------|-------------|
| 🚀 | < 20ms | Blazing fast (local operations) |
| ⚡ | 20-100ms | Fast (efficient operations) |
| ⏱️ | 100-500ms | Moderate (network/heavy compute) |
| 🐢 | > 500ms | Slow (complex operations) |

### Success Rate Interpretation

| Stars | Rate | Reliability |
|-------|------|-------------|
| ⭐⭐⭐⭐⭐ | 95-100% | Highly Reliable |
| ⭐⭐⭐⭐ | 90-94% | Reliable |
| ⭐⭐⭐ | 80-89% | Moderate |
| ⭐⭐ | 70-79% | Use with caution |
| ⭐ | < 70% | Experimental |

---

## 🔒 SECURITY REFERENCE

### Security Levels

| Symbol | Meaning | Examples |
|--------|---------|----------|
| ✅ | Safe (no sensitive access) | `context7`, `markitdown` |
| ⚠️ | Caution (requires authorization) | `serena`, `tmws`, `playwright` |
| 🔴 | Critical (admin-only operations) | `tmws__cleanup_namespace` |

### Common Requirements

- **OAuth**: `gdrive` (Google account required)
- **API Key/JWT**: `tmws` (namespace-specific auth)
- **File Access**: `serena` (read-only to project files)
- **Network**: `playwright`, `context7` (internet required)

---

## 📚 DETAILED TOOL DOCUMENTATION

For detailed "recipe cards" (parameter reference, examples, troubleshooting):

- **TMWS Tools**: [MCP_TOOLS_REFERENCE.md](../MCP_TOOLS_REFERENCE.md)
- **Serena Tools**: [serena-mcp-server/README.md](servers/serena-mcp-server.md)
- **Playwright Tools**: [playwright-mcp/README.md](servers/playwright-mcp.md)
- **Context7 Tools**: [context7/README.md](servers/context7.md)
- **Markitdown Tools**: [markitdown/README.md](servers/markitdown.md)
- **Google Drive Tools**: [gdrive/README.md](servers/gdrive.md)

---

## 🎯 GETTING STARTED

### For New Agents

1. **Start with "Today's Specials"** - Try the 4 most popular tools first
2. **Browse by Category** - Find tools matching your domain
3. **Read Examples** - Copy-paste working code to get started quickly
4. **Check Security** - Understand authorization requirements
5. **Monitor Performance** - Use latency info to optimize workflows

### For Experienced Agents

1. **Use Search by Intent** - Fastest way to find the right tool
2. **Combine Tools** - Chain multiple tools for complex workflows
3. **Monitor Success Rates** - Stick to high-reliability tools for critical tasks
4. **Share Knowledge** - Store patterns in TMWS for team reuse

---

## 🆘 TROUBLESHOOTING

### Common Issues

**Issue**: "Tool not found"
- **Solution**: Check MCP server is running (`claude_desktop_config.json`)

**Issue**: "Authentication failed"
- **Solution**: Verify API key/JWT in tool parameters

**Issue**: "Timeout errors"
- **Solution**: Check network connectivity, increase timeout if needed

**Issue**: "Rate limit exceeded"
- **Solution**: Reduce call frequency, batch operations if possible

---

## 📞 SUPPORT & FEEDBACK

- **Questions**: See detailed docs in `docs/mcp-tools/servers/`
- **Bug Reports**: Create issue with tool name, error message, and reproduction steps
- **Feature Requests**: Describe use case and expected behavior
- **Performance Issues**: Include latency measurements and tool call details

---

**Document Author**: Muses (Knowledge Architect) 📚
**Reviewed By**: Athena (Harmonious Conductor), Artemis (Technical Perfectionist)
**Last Updated**: 2025-11-20
**Status**: Production-ready
**Version**: 1.0.0

---

*"Every tool tells a story. This menu helps you find the perfect tool for yours."*
*— Muses*
