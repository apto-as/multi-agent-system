# MCP Tool Categorization System
## "Restaurant Menu" Navigation Design

**Status**: Phase 2E-2 Design Document
**Created**: 2025-11-20
**Architect**: Artemis (Technical Perfectionist)

---

## Overview

A hybrid categorization system combining:
1. **Primary Category**: Single taxonomy for top-level menu navigation
2. **Tags**: Multi-dimensional discovery (function, language, framework)
3. **Use Cases**: User-intent keywords for semantic search

---

## 1. Primary Category Taxonomy

### Top-Level Menu Structure

```
📁 Code Analysis & Refactoring
   ├─ Static Analysis (serena, pylint, mypy)
   ├─ Dependency Management (dependency-graph, npm-audit)
   └─ Code Quality (sonarqube, complexity-analyzer)

📁 File & Text Operations
   ├─ Search & Discovery (find, grep, ripgrep)
   ├─ File Manipulation (file-ops, batch-renamer)
   └─ Archive Management (tar-mcp, zip-mcp)

📁 Web Automation & Scraping
   ├─ Browser Automation (playwright, selenium)
   ├─ HTTP Clients (http-mcp, curl-mcp)
   └─ Web Scraping (beautiful-soup-mcp, scrapy-mcp)

📁 Document Generation
   ├─ Markdown & Text (muses-documenter, pandoc-mcp)
   ├─ Diagrams & Charts (mermaid-mcp, plantuml-mcp)
   └─ PDF & Office (pdf-generator, docx-mcp)

📁 Data Processing & Analysis
   ├─ Spreadsheets (pandas-mcp, excel-mcp)
   ├─ Databases (sql-query-mcp, nosql-mcp)
   └─ Visualization (chart-generator, dashboard-mcp)

📁 Infrastructure & DevOps
   ├─ Docker & Containers (docker-mcp, k8s-mcp)
   ├─ CI/CD (github-actions-mcp, jenkins-mcp)
   └─ Monitoring (prometheus-mcp, grafana-mcp)

📁 AI & Machine Learning
   ├─ Model Training (pytorch-mcp, tensorflow-mcp)
   ├─ Inference (ollama-mcp, openai-mcp)
   └─ Data Prep (dataset-mcp, annotation-mcp)

📁 Security & Compliance
   ├─ Vulnerability Scanning (snyk-mcp, owasp-mcp)
   ├─ Secret Management (vault-mcp, keychain-mcp)
   └─ Audit & Compliance (audit-log-mcp, gdpr-checker)

📁 Communication & Collaboration
   ├─ Messaging (slack-mcp, discord-mcp)
   ├─ Email (smtp-mcp, gmail-mcp)
   └─ Project Management (jira-mcp, trello-mcp)

📁 Utilities & Helpers
   ├─ Date/Time (datetime-mcp, timezone-mcp)
   ├─ Math & Conversion (calculator-mcp, unit-converter)
   └─ Random Data (faker-mcp, uuid-generator)
```

### Category Assignment Rules

1. **Single Primary Category**: Each server has exactly one primary category
2. **Most Specific**: Choose deepest applicable category
3. **Consistency**: Related tools should be in same category

---

## 2. Tag System (Multi-Dimensional Discovery)

### Tag Dimensions

#### Function Tags (What it does)
```python
function_tags = [
    "static_analysis", "code_generation", "refactoring",
    "testing", "debugging", "profiling",
    "search", "replace", "transform",
    "fetch", "parse", "render",
    "create", "update", "delete"
]
```

#### Language Tags (What it works with)
```python
language_tags = [
    "python", "javascript", "typescript", "rust", "go",
    "java", "c++", "ruby", "php", "kotlin",
    "language_agnostic"  # Works with any language
]
```

#### Framework Tags (Ecosystem)
```python
framework_tags = [
    "react", "vue", "angular", "django", "fastapi",
    "spring", "laravel", "rails", "express",
    "framework_agnostic"
]
```

#### Technology Tags (Platform/Protocol)
```python
technology_tags = [
    "rest_api", "graphql", "grpc", "websocket",
    "docker", "kubernetes", "aws", "azure", "gcp",
    "sql", "nosql", "redis", "elasticsearch"
]
```

### Example: Serena MCP Server

```yaml
server:
  name: "serena-mcp-server"
  primary_category: "code_analysis"
  tags:
    function: ["static_analysis", "search", "refactoring"]
    language: ["python", "javascript", "typescript", "rust"]
    framework: ["framework_agnostic"]
    technology: ["ast", "lsp"]
```

---

## 3. Use Case Keywords (User-Intent Discovery)

### Intent-Based Search

Instead of knowing the exact tool name, users can search by intent:

```python
use_case_examples = {
    "I want to find a function in my codebase": [
        "serena::find_symbol",
        "grep::search_for_pattern"
    ],

    "I want to test my website": [
        "playwright::browser_snapshot",
        "selenium::run_test"
    ],

    "I want to generate API documentation": [
        "muses-documenter::document",
        "swagger-generator::generate"
    ],

    "I want to analyze security vulnerabilities": [
        "snyk-mcp::scan_dependencies",
        "owasp-mcp::check_vulnerabilities"
    ]
}
```

### Use Case Extraction Strategy

```python
# Stored in mcp_tools.use_cases column (TEXT[])
use_cases = [
    "find function definition",
    "search for code pattern",
    "analyze symbol references",
    "refactor code structure",
    "detect circular dependencies"
]
```

**How to Generate**:
1. **Manual Curation**: Developers add use cases during tool registration
2. **LLM Extraction**: Use Claude to analyze tool descriptions
3. **Usage Mining**: Learn from actual user queries over time

---

## 4. Browsing Patterns

### Pattern A: Hierarchical Navigation

```
User: "Show me code analysis tools"
   ↓
Response: 📁 Code Analysis & Refactoring (12 servers)
   ├─ Static Analysis (4 servers)
   ├─ Dependency Management (3 servers)
   └─ Code Quality (5 servers)

User: "Show me static analysis tools"
   ↓
Response:
   - serena-mcp-server (Python, JS, TS, Rust)
   - pylint-mcp (Python only)
   - mypy-mcp (Python type checking)
   - eslint-mcp (JavaScript, TypeScript)
```

### Pattern B: Tag-Based Filtering

```
User: "Show me Python tools"
   ↓
Query: SELECT * FROM mcp_tools WHERE 'python' = ANY(tags)
   ↓
Response: 47 tools support Python
   ├─ Code Analysis: serena, pylint, mypy (3)
   ├─ Testing: pytest-mcp, unittest-mcp (2)
   ├─ Data: pandas-mcp, numpy-mcp (2)
   └─ ... (40 more)
```

### Pattern C: Intent-Based Search

```
User: "I want to analyze code for bugs"
   ↓
Semantic Search:
   1. Embed query: "analyze code for bugs" → [vector]
   2. ChromaDB similarity search
   3. Rank by relevance
   ↓
Response:
   1. serena-mcp-server (relevance: 0.95)
   2. pylint-mcp (relevance: 0.87)
   3. sonarqube-mcp (relevance: 0.82)
```

---

## 5. Implementation: Category Assignment

### Automatic Category Suggestion

```python
async def suggest_category(
    tool_name: str,
    tool_description: str,
    existing_tags: list[str]
) -> str:
    """Use LLM to suggest primary category during registration."""

    prompt = f"""
    Analyze this MCP tool and suggest the SINGLE most appropriate primary category.

    Tool: {tool_name}
    Description: {tool_description}
    Tags: {', '.join(existing_tags)}

    Available categories:
    - code_analysis
    - file_operations
    - web_automation
    - document_generation
    - data_processing
    - infrastructure
    - ai_ml
    - security
    - communication
    - utilities

    Respond with ONLY the category name (e.g., "code_analysis").
    """

    response = await claude.complete(prompt, max_tokens=10)
    return response.strip()
```

### Manual Override

```yaml
# .tmws/mcps/custom-tool.yml
server:
  name: "my-custom-tool"
  category: "code_analysis"  # User can override LLM suggestion
  auto_categorize: false      # Disable automatic categorization
```

---

## 6. Performance Considerations

### Category Index Selectivity

```sql
-- Bad: Too many tools per category (poor selectivity)
SELECT COUNT(*) FROM mcp_tools WHERE primary_category = 'utilities';
-- Result: 89 tools (browsing is overwhelming)

-- Good: Balanced distribution
SELECT primary_category, COUNT(*) FROM mcp_tools GROUP BY primary_category;
-- Result:
--   code_analysis: 12
--   file_operations: 8
--   web_automation: 15
--   document_generation: 7
--   ... (balanced)
```

**Target Distribution**: 5-20 tools per category (comfortable browsing)

### Tag Cardinality

- **Low Cardinality Tags** (e.g., language): Fast filtering, but less precise
- **High Cardinality Tags** (e.g., framework): More precise, but slower queries

**Optimization**: Use GIN indexes on PostgreSQL, or separate `mcp_tool_tags` table for SQLite.

---

## 7. User Experience Examples

### Example 1: Newcomer Exploration

```
Newcomer: "What tools are available?"
   ↓
System: Shows top 10 categories with tool counts
   ↓
Newcomer: "What's in Code Analysis?"
   ↓
System: Shows 12 servers with 1-line descriptions
   ↓
Newcomer: "Tell me about serena"
   ↓
System: Full schema, examples, performance metrics
```

**Token Usage**: 500 → 1,500 → 3,000 tokens (progressive disclosure)

### Example 2: Expert Direct Query

```
Expert: "Find tools for Python static analysis with <100ms latency"
   ↓
Query:
   SELECT * FROM mcp_tools
   WHERE 'python' = ANY(tags)
     AND 'static_analysis' = ANY(tags)
     AND avg_latency_ms < 100
   ORDER BY tier_score DESC;
   ↓
Response:
   1. serena-mcp-server (avg: 47ms, tier: hot)
   2. mypy-mcp (avg: 82ms, tier: warm)
```

**Token Usage**: 2,000 tokens (full details immediately)

---

## 8. Future Enhancements

### Learning from Usage Patterns

```python
# After 30 days of usage analytics:
"Users who searched for 'refactoring' also used:"
  - serena-mcp-server (87% of users)
  - ast-analyzer-mcp (54% of users)
  - code-formatter-mcp (41% of users)

# Update use_cases based on actual user queries
UPDATE mcp_tools
SET use_cases = array_append(use_cases, 'refactoring')
WHERE tool_name = 'serena-mcp-server'
  AND 'refactoring' NOT IN (use_cases);
```

### Personalized Menu Ordering

```sql
-- User's "favorites" appear first
SELECT t.* FROM mcp_tools t
JOIN mcp_tool_metrics m ON t.id = m.tool_id
WHERE m.invoked_by_agent_id = 'user-123'
ORDER BY m.invoked_at DESC
LIMIT 5;
```

---

## Conclusion

**Hybrid Categorization Benefits**:
- ✅ **Primary Category**: Simple hierarchical navigation
- ✅ **Tags**: Multi-dimensional filtering (language, framework, function)
- ✅ **Use Cases**: Intent-based semantic search
- ✅ **Progressive Disclosure**: Category → Server → Tool → Details (500 → 3,000 tokens)

**Performance**: <50ms for category browsing, <200ms for semantic search.
