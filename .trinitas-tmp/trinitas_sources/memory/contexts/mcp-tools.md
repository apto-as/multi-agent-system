# MCP Tools Usage Context v2.2.1

**Load Condition**: `coding` or `full` context profile
**Estimated Size**: ~3k tokens
**Integration**: All agents use MCP tools based on specialization

---

## MCP Tools Overview

Trinitas integrates with 4 MCP servers, each providing specialized capabilities.

### Available MCP Servers

| Server | Purpose | Primary Users | Tools Count |
|--------|---------|--------------|-------------|
| **context7** | Library documentation | All agents | 2 |
| **markitdown** | Content conversion | Muses, Athena | 1 |
| **playwright** | Browser automation | Hestia, Artemis | 15+ |
| **serena** | Codebase analysis | All agents | 10+ |

---

## 1. context7 - Documentation Retrieval

### Purpose
Retrieve up-to-date documentation for libraries and frameworks.

### When to Use
- Learning new library API
- Checking version-specific features
- Finding best practices
- Investigating breaking changes

### Tools

**resolve-library-id**: Find correct library identifier
```python
# Example usage
library_id = await context7.resolve_library_id("next.js")
# Returns: "/vercel/next.js"
```

**get-library-docs**: Retrieve documentation
```python
# Example usage
docs = await context7.get_library_docs(
    context7CompatibleLibraryID="/vercel/next.js/v14.0.0",
    topic="server actions",
    tokens=5000
)
```

### Agent-Specific Usage

**Athena** (Architecture Design):
```python
# Research technology options
nextjs_docs = await context7.get_library_docs("/vercel/next.js")
remix_docs = await context7.get_library_docs("/remix-run/remix")
# Compare and make strategic decision
```

**Artemis** (Technical Implementation):
```python
# Find performance best practices
docs = await context7.get_library_docs(
    "/tanstack/query",
    topic="caching strategies"
)
# Apply to implementation
```

**Muses** (Documentation):
```python
# Verify library information for docs
official_docs = await context7.get_library_docs("/library/name")
# Incorporate accurate information
```

---

## 2. markitdown - Content Conversion

### Purpose
Convert web content and PDFs to Markdown format.

### When to Use
- Importing external documentation
- Processing PDF specifications
- Archiving web articles
- Converting design documents

### Tools

**convert_to_markdown**: Universal content converter
```python
# Web URL conversion
md_content = await markitdown.convert_to_markdown(
    source="https://example.com/technical-spec",
    options={"include_images": True, "clean_html": True}
)

# PDF conversion
md_content = await markitdown.convert_to_markdown(
    source="/path/to/specification.pdf",
    options={"extract_tables": True}
)
```

### Agent-Specific Usage

**Muses** (Documentation Integration):
```python
# Import external documentation
external_spec = await markitdown.convert_to_markdown(
    source="https://api-provider.com/docs",
    options={"preserve_structure": True}
)

# Structure and integrate
muses.integrate_external_documentation(external_spec)
```

**Athena** (Competitive Analysis):
```python
# Analyze competitor documentation
competitor_docs = await markitdown.convert_to_markdown(
    source="https://competitor.com/product-specs"
)
# Extract strategic insights
```

---

## 3. playwright - Browser Automation

### Purpose
Automated browser testing, web scraping, UI validation.

### When to Use
- E2E testing
- Security vulnerability testing
- Performance benchmarking
- Screenshot capture for documentation

### Core Tools

**browser_navigate**: Load web pages
```python
await playwright.browser_navigate(url="https://app.example.com/login")
```

**browser_snapshot**: Capture accessibility tree
```python
snapshot = await playwright.browser_snapshot()
# Returns structured page content
```

**browser_click**: Interact with elements
```python
await playwright.browser_click(
    element="Login button",
    ref="button[type='submit']"
)
```

**browser_type**: Input text
```python
await playwright.browser_type(
    element="Email input",
    ref="input[name='email']",
    text="test@example.com"
)
```

**browser_take_screenshot**: Visual capture
```python
await playwright.browser_take_screenshot(
    filename="dashboard.png",
    fullPage=True
)
```

### Agent-Specific Usage

**Hestia** (Security Testing):
```python
# XSS vulnerability test
await playwright.browser_navigate("https://app.example.com/search")
await playwright.browser_type(
    element="Search input",
    ref="input[name='q']",
    text="<script>alert('xss')</script>"
)
await playwright.browser_click(element="Search", ref="button[type='submit']")

# Check if script executed (shouldn't!)
snapshot = await playwright.browser_snapshot()
# Analyze for XSS indicators
```

**Artemis** (Performance Testing):
```python
# Measure page load performance
await playwright.browser_navigate("https://app.example.com")

# Get performance metrics
await playwright.browser_evaluate(
    function="() => JSON.stringify(window.performance.timing)"
)

# Calculate load time
load_time = timing.loadEventEnd - timing.navigationStart
```

**Muses** (Documentation Screenshots):
```python
# Capture UI states for documentation
await playwright.browser_navigate("https://app.example.com")
await playwright.browser_take_screenshot(
    filename="docs/login-page.png"
)

await playwright.browser_click(element="Dashboard", ref="nav a[href='/dashboard']")
await playwright.browser_take_screenshot(
    filename="docs/dashboard-page.png"
)
```

**Eris** (Integration Testing):
```python
# Multi-step workflow validation
test_steps = [
    {"action": "navigate", "url": "/login"},
    {"action": "type", "ref": "input[name='email']", "text": "test@example.com"},
    {"action": "type", "ref": "input[name='password']", "text": "password"},
    {"action": "click", "ref": "button[type='submit']"},
    {"action": "wait", "selector": ".dashboard"},
    {"action": "screenshot", "filename": "test-result.png"}
]

# Execute coordinated test
for step in test_steps:
    await eris.execute_test_step(step)
```

---

## 4. serena - Codebase Analysis

### Purpose
Semantic code analysis, symbol search, dependency tracking.

### When to Use
- Understanding large codebases
- Finding function/class usage
- Refactoring impact analysis
- Architecture discovery

### Core Tools

**list_dir**: Directory exploration
```python
# List project structure
structure = await serena.list_dir(
    relative_path=".",
    recursive=True,
    skip_ignored_files=True
)
```

**find_file**: File pattern matching
```python
# Find all test files
test_files = await serena.find_file(
    file_mask="*test*.py",
    relative_path="."
)
```

**search_for_pattern**: Regex search
```python
# Find potential security issues
results = await serena.search_for_pattern(
    substring_pattern=r"password|secret|token",
    relative_path=".",
    restrict_search_to_code_files=True,
    context_lines_before=2,
    context_lines_after=2
)
```

**get_symbols_overview**: File structure
```python
# Understand file organization
overview = await serena.get_symbols_overview(
    relative_path="src/services/user_service.py"
)
```

**find_symbol**: Semantic search
```python
# Find specific function
symbols = await serena.find_symbol(
    name_path="UserService/authenticate",
    depth=1,
    include_body=True
)
```

**find_referencing_symbols**: Usage tracking
```python
# Find all usages of deprecated function
references = await serena.find_referencing_symbols(
    name_path="deprecated_function",
    relative_path="src/utils/old_api.py"
)
```

### Agent-Specific Usage

**Artemis** (Code Quality Analysis):
```python
# Find complex functions for refactoring
complex_code = await serena.search_for_pattern(
    substring_pattern=r"def .+\(.*\):.*\n(.*\n){20,}",  # 20+ line functions
    restrict_search_to_code_files=True
)

# Analyze cyclomatic complexity
for code in complex_code:
    complexity = artemis.analyze_complexity(code)
    if complexity > 10:
        artemis.flag_for_refactoring(code)
```

**Athena** (Architecture Discovery):
```python
# Map system architecture
components = await serena.list_dir("src", recursive=True)

# Identify service boundaries
services = {}
for component in components:
    overview = await serena.get_symbols_overview(component)
    services[component] = overview

# Analyze dependencies
architecture_map = athena.build_architecture_map(services)
```

**Hestia** (Security Audit):
```python
# Find SQL queries (injection risk)
sql_code = await serena.search_for_pattern(
    substring_pattern=r"(execute|query|sql).*\+.*",  # String concatenation in SQL
    restrict_search_to_code_files=True
)

# Find eval/exec usage (code injection risk)
dangerous_code = await serena.search_for_pattern(
    substring_pattern=r"(eval|exec)\s*\(",
    restrict_search_to_code_files=True
)

# Audit findings
hestia.report_security_findings([sql_code, dangerous_code])
```

**Hera** (Dependency Analysis):
```python
# Identify parallel execution opportunities
async_candidates = await serena.search_for_pattern(
    substring_pattern=r"await\s+\w+\(\)",
    restrict_search_to_code_files=True
)

# Analyze for parallelization
for candidate in async_candidates:
    dependencies = await serena.find_referencing_symbols(candidate)
    if hera.is_parallelizable(dependencies):
        hera.suggest_parallel_optimization(candidate)
```

---

## Tool Selection Guidelines

### Decision Matrix

| Task | Recommended Tool | Reason |
|------|-----------------|--------|
| Library API lookup | context7 | Latest official docs |
| Code impact analysis | serena | Semantic symbol search |
| Web UI testing | playwright | Real browser automation |
| PDF spec import | markitdown | Format conversion |
| Security scan | serena + playwright | Static + dynamic |
| Dependency check | serena | Code analysis |
| Documentation capture | playwright + markitdown | Screenshots + conversion |

### Combination Patterns

**Pattern: Security Audit**
```python
# 1. Static analysis (serena)
vulnerabilities = await serena.search_for_pattern(
    substring_pattern="(password|secret|api_key)\s*=\s*['\"]"
)

# 2. Dynamic testing (playwright)
await playwright.browser_navigate("https://app.example.com")
xss_test_result = await hestia.test_xss_vulnerabilities()

# 3. Documentation (markitdown)
security_policy = await markitdown.convert_to_markdown(
    source="https://company.com/security-policy.pdf"
)

# 4. Report compilation
hestia.compile_security_report([vulnerabilities, xss_test_result, security_policy])
```

**Pattern: Performance Optimization**
```python
# 1. Find slow functions (serena)
slow_code = await serena.search_for_pattern(
    substring_pattern=r"@performance\.measure",
    context_lines_after=10
)

# 2. Check best practices (context7)
optimization_docs = await context7.get_library_docs(
    "/library/performance-guide"
)

# 3. Benchmark (playwright)
await playwright.browser_navigate("https://app.example.com")
metrics = await playwright.browser_evaluate(
    function="() => window.performance.getEntriesByType('measure')"
)

# 4. Apply optimization (artemis)
artemis.optimize_based_on_findings([slow_code, optimization_docs, metrics])
```

**Pattern: Documentation Generation**
```python
# 1. Code structure (serena)
symbols = await serena.get_symbols_overview("src/api/")

# 2. Library references (context7)
library_docs = await context7.get_library_docs("/fastapi/fastapi")

# 3. External specs (markitdown)
api_spec = await markitdown.convert_to_markdown(
    source="https://swagger.io/specification.yaml"
)

# 4. UI screenshots (playwright)
await playwright.browser_take_screenshot(
    filename="docs/api-explorer.png"
)

# 5. Generate docs (muses)
muses.generate_comprehensive_docs([symbols, library_docs, api_spec, screenshots])
```

---

## Error Handling

### Common Issues & Solutions

**context7 - Library Not Found**:
```python
try:
    docs = await context7.get_library_docs("/unknown/library")
except LibraryNotFoundError:
    # Try alternative search
    alternatives = await context7.resolve_library_id("library-name")
    docs = await context7.get_library_docs(alternatives[0])
```

**serena - Symbol Not Found**:
```python
try:
    symbol = await serena.find_symbol("ExactName")
except SymbolNotFoundError:
    # Use substring matching
    symbols = await serena.find_symbol(
        "PartialName",
        substring_matching=True
    )
```

**playwright - Element Not Found**:
```python
try:
    await playwright.browser_click(element="Button", ref="button.submit")
except TimeoutError:
    # Wait longer
    await playwright.browser_wait_for(text="Button", time=10)
    await playwright.browser_click(element="Button", ref="button.submit")
```

---

## Performance Considerations

### Token Usage Optimization

**Minimize context7 calls**:
```python
# Bad: Multiple small calls
docs1 = await context7.get_library_docs("/lib", topic="feature1", tokens=1000)
docs2 = await context7.get_library_docs("/lib", topic="feature2", tokens=1000)

# Good: Single comprehensive call
docs = await context7.get_library_docs("/lib", tokens=5000)
```

**Efficient serena searches**:
```python
# Bad: Search entire codebase
await serena.search_for_pattern(pattern, relative_path=".")

# Good: Restrict to relevant directory
await serena.search_for_pattern(pattern, relative_path="src/services/")
```

---

## Integration with Agents

### Agent MCP Tool Preferences

| Agent | Primary Tools | Secondary Tools |
|-------|--------------|-----------------|
| **Athena** | context7, serena | markitdown, playwright |
| **Artemis** | serena, context7 | playwright (benchmarks) |
| **Hestia** | serena, playwright | context7 (security guides) |
| **Eris** | serena (coordination) | playwright (testing) |
| **Hera** | serena (analysis) | All tools (orchestration) |
| **Muses** | markitdown, playwright | context7, serena |

---

**MCP Tools Context v2.2.1**
*Multi-tool integration for comprehensive analysis*
*Reference: @core/system.md for tool availability*
