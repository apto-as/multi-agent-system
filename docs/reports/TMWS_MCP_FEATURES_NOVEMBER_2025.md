# TMWS MCP Features Catalog - November 2025
## Complete Model Context Protocol Implementation

**Document Version**: 1.0.0
**Created**: 2025-11-28
**Author**: Muses (Knowledge Architect)
**Status**: Production-ready
**TMWS Version**: v2.4.3+

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [MCP Tools Catalog (26 Tools)](#mcp-tools-catalog)
3. [Dynamic MCP Server Management](#dynamic-mcp-server-management)
4. [License System Integration](#license-system-integration)
5. [MCP Server Implementation](#mcp-server-implementation)
6. [External MCP Integration](#external-mcp-integration)
7. [Performance Metrics](#performance-metrics)
8. [Security Architecture](#security-architecture)
9. [November 2025 Enhancements](#november-2025-enhancements)

---

## Executive Summary

TMWS implements a complete **Model Context Protocol (MCP)** server providing 26 tools across 4 categories, with dynamic external server management capabilities introduced in November 2025. The system supports both native Python tools and Go-based wrapper tools for high-performance operations.

### Key Statistics

- **Total MCP Tools**: 26 (21 Python + 5 Go wrapper)
- **Tool Categories**: 4 (Core Memory, System, Expiration Management, Trust & Verification)
- **External Server Support**: 4 preset servers (context7, playwright, serena, markitdown)
- **License Tiers**: 4 (FREE, PRO, ENTERPRISE, ADMINISTRATOR)
- **Average Latency**: 2-20ms P95
- **Active Development Period**: November 2025 (123 commits)

---

## MCP Tools Catalog

### Category 1: Core Memory Tools (3 tools)

Essential tools for memory storage and retrieval using hybrid SQLite + ChromaDB architecture.

#### 1.1 store_memory

**File**: `src/mcp_server.py:141-167`
**Performance**: ~2-4ms P95 ✅
**License**: FREE+

Stores information in hybrid semantic memory (SQLite metadata + ChromaDB vectors).

**Signature**:
```python
store_memory(
    content: str,
    importance_score: float = 0.5,
    tags: list[str] = None,
    namespace: str = None,
    context: dict = None
) -> dict
```

**Response Fields**:
- `memory_id`: UUID of stored memory
- `status`: "stored"
- `importance_score`: Assigned importance (0.0-1.0)
- `latency_ms`: Storage latency
- `stored_in`: ["sqlite", "chroma"]
- `embedding_model`: "multilingual-e5-large"
- `embedding_dimension`: 1024

**Security**:
- Namespace auto-detection from project context
- Rejects explicit "default" namespace (V-1 path traversal fix)
- SQLite + ChromaDB write-through pattern

---

#### 1.2 search_memories

**File**: `src/mcp_server.py:169-195`
**Performance**: ~5-20ms P95 ✅
**License**: FREE+

Searches semantic memories using ChromaDB vector search.

**Signature**:
```python
search_memories(
    query: str,
    limit: int = 10,
    min_similarity: float = 0.7,
    namespace: str = None,
    tags: list[str] = None
) -> dict
```

**Response Fields**:
- `query`: Original search query
- `results`: List of memory dictionaries with similarity scores
- `count`: Number of results returned
- `latency_ms`: Search latency
- `search_source`: "chromadb" or "chromadb_slow"
- `embedding_model`: "multilingual-e5-large"

**Architecture**:
- ChromaDB vector search first (0.47ms P95)
- SQLite metadata fallback
- 1024-dimensional embeddings via Ollama

---

#### 1.3 create_task

**File**: `src/mcp_server.py:197-207`
**Performance**: ~5-10ms P95 ✅
**License**: FREE+

Creates a coordinated task for multi-agent workflow.

**Signature**:
```python
create_task(
    title: str,
    description: str = None,
    priority: str = "medium",
    assigned_agent_id: str = None,
    estimated_duration: int = None,
    due_date: str = None  # ISO 8601 format
) -> dict
```

**Response Fields**:
- `task_id`: UUID of created task
- `status`: "created"
- `assigned_to`: Agent ID
- `priority`: "low", "medium", "high"
- `estimated_duration`: Minutes
- `due_date`: ISO 8601 timestamp
- `storage`: "sqlite"

---

### Category 2: System Tools (8 tools)

Administrative, monitoring, and dynamic server management tools.

#### 2.1 get_agent_status

**File**: `src/mcp_server.py:209-212`
**License**: FREE+

Get status of connected agents in the TMWS system.

**Signature**:
```python
get_agent_status() -> dict
```

**Response Fields**:
- `agents`: List of agent dictionaries (agent_id, namespace, status, capabilities)
- `total`: Total number of active agents
- `current_instance`: Server instance ID
- `storage`: "sqlite"

---

#### 2.2 get_memory_stats

**File**: `src/mcp_server.py:214-217`
**License**: FREE+

Get combined SQLite + ChromaDB statistics.

**Signature**:
```python
get_memory_stats() -> dict
```

**Response Fields**:
- `total_memories`: Total count across SQLite + ChromaDB
- `mcp_metrics`: Dictionary with request counts, hit rates, latency
- `chroma_hit_rate`: Percentage of ChromaDB cache hits

---

#### 2.3 invalidate_cache

**File**: `src/mcp_server.py:219-222`
**License**: FREE+

Clear ChromaDB cache (use with caution, testing only).

**Signature**:
```python
invalidate_cache() -> dict
```

⚠️ **Warning**: This clears vector embeddings. Use only for testing/debugging.

**Response Fields**:
- `status`: "cleared"
- `warning`: Informational message

---

#### 2.4 list_mcp_servers

**File**: `src/mcp_server.py:229-279`
**License**: PRO+
**Version**: v2.4.3+

List available MCP servers from presets and their connection status.

**Signature**:
```python
list_mcp_servers() -> dict
```

**Response Fields**:
- `status`: "success"
- `server_count`: Number of available servers
- `servers`: List of server dictionaries with:
  - `name`: Server identifier
  - `transport_type`: "stdio" or "http"
  - `auto_connect`: Boolean
  - `is_connected`: Boolean
  - `tool_count`: Number of available tools
  - `command`: STDIO command (if applicable)
  - `url`: HTTP URL (if applicable)

**Configuration Sources**:
1. `~/.tmws/mcp.json` (user-level presets)
2. `.mcp.json` (project-level presets)

---

#### 2.5 connect_mcp_server

**File**: `src/mcp_server.py:281-359`
**License**: PRO+
**Version**: v2.4.3+

Connect to a preset MCP server by name.

**Signature**:
```python
connect_mcp_server(server_name: str) -> dict
```

**Security Features**:
- **Preset-only connections**: Only servers defined in `mcp.json` can be connected
- **Command execution prevention**: No arbitrary commands allowed
- **Resource limits**: Maximum 10 concurrent connections
- **Connection pooling**: Reuses existing connections

**Response Fields**:
- `status`: "connected" or "already_connected"
- `server`: Server name
- `transport_type`: "stdio" or "http"
- `tool_count`: Number of available tools
- `tools`: List of tool names

---

#### 2.6 disconnect_mcp_server

**File**: `src/mcp_server.py:361-402`
**License**: PRO+
**Version**: v2.4.3+

Disconnect from an MCP server.

**Signature**:
```python
disconnect_mcp_server(server_name: str) -> dict
```

**Response Fields**:
- `status`: "disconnected"
- `server`: Server name

---

#### 2.7 get_mcp_status

**File**: `src/mcp_server.py:404-439`
**License**: PRO+
**Version**: v2.4.3+

Get current status of all MCP server connections.

**Signature**:
```python
get_mcp_status() -> dict
```

**Response Fields**:
- `status`: "success"
- `manager_initialized`: Boolean
- `connection_count`: Number of active connections
- `connections`: List of connection dictionaries
- `total_tools`: Total tools from all connected servers

---

### Category 3: Expiration Management Tools (10 tools)

TTL (Time-To-Live) system for automatic memory cleanup with security enforcement.

#### Security Model (All Expiration Tools)

**REQ-1**: Authentication required (API key or JWT token)
**REQ-2**: Namespace isolation (P0-1 pattern)
**REQ-3**: Mass deletion protection (>10 items requires `confirm_mass_deletion=True`)
**REQ-4**: Rate limiting (tool-specific limits)
**REQ-5**: Role-based access control (admin-only for destructive operations)

---

#### 3.1 prune_expired_memories

**File**: `src/tools/expiration_tools.py`
**License**: PRO+
**Rate Limit**: 5 deletions/hour

Remove expired memories from a namespace.

**Signature**:
```python
prune_expired_memories(
    agent_id: str,
    namespace: str,
    api_key: str | None = None,
    jwt_token: str | None = None,
    dry_run: bool = False,
    confirm_mass_deletion: bool = False
) -> dict
```

**Security**:
- REQ-1: Authentication (API key or JWT)
- REQ-2: Namespace isolation (verified from DB)
- REQ-3: Mass deletion protection (>10 items)
- REQ-4: Rate limit (5/hour)

**Response Fields**:
- `deleted_count`: Number of memories deleted
- `would_delete_count`: Number of memories that would be deleted (dry_run)
- `namespace`: Target namespace

---

#### 3.2 get_expiration_stats

**File**: `src/tools/expiration_tools.py`
**License**: PRO+
**Rate Limit**: 30 queries/minute

Get expiration statistics for a namespace.

**Signature**:
```python
get_expiration_stats(
    agent_id: str,
    namespace: str,
    api_key: str | None = None,
    jwt_token: str | None = None
) -> dict
```

**Response Fields**:
- `expired`: Count of expired memories
- `expiring_soon_24h`: Count expiring within 24 hours
- `expiring_soon_7d`: Count expiring within 7 days
- `permanent`: Count of permanent memories (no TTL)
- `total`: Total memory count

---

#### 3.3 set_memory_ttl

**File**: `src/tools/expiration_tools.py`
**License**: PRO+

Update TTL for an existing memory.

**Signature**:
```python
set_memory_ttl(
    agent_id: str,
    memory_id: str,
    ttl_days: int | None,
    api_key: str | None = None,
    jwt_token: str | None = None
) -> dict
```

**Security**: Only memory owner can modify TTL (P0-1 pattern)

**Response Fields**:
- `memory_id`: UUID
- `ttl_days`: New TTL value (None = permanent)
- `expires_at`: ISO 8601 timestamp (None = no expiration)

---

#### 3.4 cleanup_namespace

**File**: `src/tools/expiration_tools.py`
**License**: ENTERPRISE
**Rate Limit**: 2 cleanups/day

Delete ALL memories from a namespace (admin-only, destructive).

⚠️ **WARNING**: DESTRUCTIVE OPERATION - Deletes ALL memories in namespace.

**Signature**:
```python
cleanup_namespace(
    agent_id: str,
    namespace: str,
    api_key: str | None = None,
    jwt_token: str | None = None,
    dry_run: bool = False,
    confirm_mass_deletion: bool = False
) -> dict
```

**Security**:
- REQ-5: Admin-only (requires special role)
- REQ-3: Mass deletion confirmation required
- REQ-4: Very strict rate limit (2/day)

---

#### 3.5 get_namespace_stats

**File**: `src/tools/expiration_tools.py`
**License**: PRO+
**Rate Limit**: 20 queries/minute

Get comprehensive statistics for a namespace.

**Signature**:
```python
get_namespace_stats(
    agent_id: str,
    namespace: str,
    api_key: str | None = None,
    jwt_token: str | None = None
) -> dict
```

---

#### 3.6-3.10 Scheduler Tools (5 tools)

**License**: ENTERPRISE

Tools for controlling the automatic expiration scheduler:

1. **get_scheduler_status**: Get scheduler status (read-only, 60/min)
2. **configure_scheduler**: Configure interval (admin-only, 3/hour)
3. **start_scheduler**: Start scheduler (admin-only, 5/hour)
4. **stop_scheduler**: Stop scheduler (admin-only, 2/day)
5. **trigger_scheduler**: Manual cleanup (10/hour)

**Example**:
```python
# Check scheduler status
status = await get_scheduler_status(
    agent_id="artemis-optimizer",
    api_key="your-api-key"
)
if status['is_running']:
    print(f"Next cleanup: {status['next_run_time']}")
```

---

### Category 4: Trust & Verification Tools (5 tools)

Agent trust scoring system for claim verification.

#### 4.1 verify_and_record

**File**: `src/tools/verification_tools.py`
**License**: ENTERPRISE
**Performance**: 350-450ms P95 ✅

Verify a claim and record evidence with trust score update.

**Signature**:
```python
verify_and_record(
    agent_id: str,
    claim_type: str,
    claim_content: dict,
    verification_command: str,
    verified_by_agent_id: str | None = None
) -> dict
```

**Claim Types**:
- `test_result`: Test execution results
- `performance_metric`: Performance measurements
- `code_quality`: Code quality metrics
- `security_finding`: Security audit findings
- `deployment_status`: Deployment status
- `custom`: Other claim types

**Security (V-VERIFY-*)**:
- **V-VERIFY-1**: Command injection prevention (21 allowed commands)
- **V-VERIFY-2**: Verifier authorization (RBAC role check)
- **V-VERIFY-3**: Namespace isolation (verified from DB)
- **V-VERIFY-4**: Pattern eligibility validation
- **V-TRUST-5**: Self-verification prevention

**Response Fields**:
- `verification_id`: UUID
- `accurate`: Boolean
- `evidence_id`: UUID
- `new_trust_score`: Float (0.0-1.0)
- `trust_delta`: Float
- `pattern_linked`: Boolean

---

#### 4.2 get_agent_trust_score

**File**: `src/tools/verification_tools.py`
**License**: ENTERPRISE

Get agent trust score and statistics.

**Signature**:
```python
get_agent_trust_score(agent_id: str) -> dict
```

**Trust Score Interpretation**:
- 0.9-1.0: Highly Reliable (verification rarely needed)
- 0.7-0.89: Reliable (spot verification recommended)
- 0.5-0.69: Moderate (regular verification needed)
- 0.3-0.49: Low Trust (verification required for critical claims)
- 0.0-0.29: Untrusted (verification required for all claims)

**Response Fields**:
- `trust_score`: Float (0.0-1.0)
- `requires_verification`: Boolean
- `total_verifications`: Integer
- `accurate_count`: Integer
- `accuracy_rate`: Float

---

#### 4.3-4.5 Additional Verification Tools

**License**: ENTERPRISE

3. **get_verification_history**: Get verification history (filter by claim type)
4. **get_verification_statistics**: Get comprehensive statistics by claim type
5. **get_trust_history**: Get trust score evolution over time

---

## Dynamic MCP Server Management

**Version**: v2.4.3+
**Files**: `src/infrastructure/mcp/`

### Architecture

TMWS supports dynamic connection to external MCP servers via preset configuration files. This enables agents to access additional capabilities from specialized MCP servers.

### Preset Configuration

**Configuration Locations** (priority order):

1. **Project-level**: `./.mcp.json` (version controlled)
2. **User-level**: `~/.tmws/mcp.json` (personal presets)
3. **Environment**: `TMWS_MCP_SERVERS_PATH` (custom location)

### Default Preset Servers

**File**: `src/mcp_server.py:1096-1133` (first-run setup)

#### 1. context7

**Purpose**: Documentation lookup for libraries and frameworks
**Command**: `npx -y @upstash/context7-mcp@latest`
**Transport**: STDIO
**Auto-connect**: True
**Website**: https://context7.com

**Use Cases**:
- Latest API documentation retrieval
- Version-specific feature documentation
- Library best practices lookup

---

#### 2. playwright

**Purpose**: Browser automation and E2E testing
**Command**: `npx -y @anthropic/mcp-playwright@latest`
**Transport**: STDIO
**Auto-connect**: True
**Website**: https://playwright.dev

**Use Cases**:
- Web application testing
- UI interaction automation
- Screenshot capture
- Form filling and validation

---

#### 3. serena

**Purpose**: Code analysis and symbol search
**Command**: `uvx --from serena-mcp-server serena`
**Transport**: STDIO
**Auto-connect**: True
**Website**: https://github.com/oraios/serena

**Use Cases**:
- Symbol search (functions, classes, variables)
- Dependency analysis
- Refactoring impact assessment
- Code structure understanding

---

#### 4. chrome-devtools (optional)

**Purpose**: Chrome DevTools Protocol integration
**Command**: `npx -y @anthropic/mcp-chrome-devtools@latest`
**Transport**: STDIO
**Auto-connect**: False (requires Chrome with remote debugging)
**Requirement**: `chrome --remote-debugging-port=9222`

**Use Cases**:
- Real-time DOM inspection
- Network request monitoring
- JavaScript debugging

---

### Transport Types

**File**: `src/infrastructure/mcp/preset_config.py:31-36`

#### STDIO Transport

**Implementation**: `src/infrastructure/mcp/stdio_transport.py`

Launches MCP server as subprocess, communicates via stdin/stdout.

**Advantages**:
- Process isolation
- Standard I/O communication
- Compatible with Node.js, Python, Go tools

**Example Configuration**:
```json
{
  "context7": {
    "type": "stdio",
    "command": "npx",
    "args": ["-y", "@upstash/context7-mcp@latest"],
    "autoConnect": true,
    "env": {
      "API_KEY": "${CONTEXT7_API_KEY}"
    }
  }
}
```

---

#### HTTP/SSE Transport

**Status**: Planned (not yet implemented)

**Future Use Cases**:
- Remote MCP servers
- Cluster-based deployments
- Cloud-hosted specialized tools

---

### MCPManager

**File**: `src/infrastructure/mcp/manager.py`

Central manager for all MCP server connections.

**Key Methods**:

```python
class MCPManager:
    async def connect(preset: MCPServerPreset) -> MCPConnection
    async def disconnect(server_name: str) -> None
    async def disconnect_all() -> None
    def get_connection(server_name: str) -> MCPConnection | None
    def list_connections() -> list[dict]
    async def list_all_tools() -> dict[str, list[Tool]]
    async def auto_connect_from_config(project_dir: Path) -> list[str]
```

**Security Features**:
- Maximum 10 concurrent connections (resource exhaustion prevention)
- Preset-only server connections (no arbitrary command execution)
- Environment variable interpolation (`${VAR_NAME}`)
- Process lifecycle management

---

## License System Integration

**File**: `src/services/license_service.py`
**Version**: 3.0.0 (Ed25519 public key cryptography)

### License Tiers

#### FREE Tier

**Agents**: 10 max
**Memories**: 1,000 per agent
**Rate Limit**: 60 requests/minute
**Token Budget**: 10,000 tokens/hour
**MCP Tools**: 6 (Core Memory + System basics)
**Support**: Community

**Available Tools**:
- store_memory
- search_memories
- create_task
- get_agent_status
- get_memory_stats
- invalidate_cache

---

#### PRO Tier

**Agents**: 50 max
**Memories**: 10,000 per agent
**Rate Limit**: 300 requests/minute
**Token Budget**: 50,000 tokens/hour
**MCP Tools**: 16 (+ Expiration Management + MCP Server Management)
**Support**: Email

**Additional Tools**:
- All FREE tools
- prune_expired_memories
- get_expiration_stats
- set_memory_ttl
- cleanup_namespace
- get_namespace_stats
- list_mcp_servers (NEW v2.4.3)
- connect_mcp_server (NEW v2.4.3)
- disconnect_mcp_server (NEW v2.4.3)
- get_mcp_status (NEW v2.4.3)

---

#### ENTERPRISE Tier

**Agents**: 200 max
**Memories**: 100,000 per agent
**Rate Limit**: 1000 requests/minute
**Token Budget**: 200,000 tokens/hour
**MCP Tools**: 26 (All tools + Trust & Verification)
**Support**: Priority

**Additional Tools**:
- All PRO tools
- 5 Scheduler tools (get/configure/start/stop/trigger)
- 5 Verification tools (verify_and_record, trust scores, history)

---

#### ADMINISTRATOR Tier

**Agents**: Unlimited
**Memories**: Unlimited
**Rate Limit**: None
**Token Budget**: Unlimited
**MCP Tools**: 26 (All tools)
**Support**: Dedicated
**Expiration**: Perpetual

**Use Case**: Internal Trinitas development and testing

---

### License Validation

**Phase 2E-2**: Startup License Gate (v2.4.0+)

**File**: `src/mcp_server.py:1289-1358`

**Process**:

1. Check `TMWS_LICENSE_KEY` environment variable
2. Validate license key format: `TMWS-{TIER}-{UUID}-{EXPIRY}-{SIGNATURE}`
3. Verify Ed25519 signature (v2.4.1+) or HMAC (legacy)
4. Check expiration date (7-day grace period)
5. Load tier-specific limits
6. Start MCP server with tier-enforced capabilities

**Security**:
- Ed25519 public key verification (primary)
- HMAC-SHA256 fallback (legacy compatibility)
- Database-independent validation (tampering has zero effect)
- Offline-first validation (no network dependency)
- Constant-time comparison (timing attack resistance)

**Grace Period**:
- Expired licenses get 7-day grace period
- Warning logged daily during grace period
- Fail-fast after grace period expires

---

## MCP Server Implementation

**File**: `src/mcp_server.py` (1,363 lines)

### HybridMCPServer Class

**Lines**: 89-1053

**Architecture**:
- **HybridMemoryService**: SQLite + Chroma unified interface
- **MultilingualEmbeddingService**: 1024-dimensional embeddings via Ollama
- **VectorSearchService**: ChromaDB with P95 latency 0.47ms

**Initialization Phases**:

#### Phase 1: Database & Vector Services

**Lines**: 445-455

- Namespace detection (auto-detection from git/project context)
- ChromaDB initialization
- Embedding service initialization

---

#### Phase 2: Expiration Tools Registration

**Lines**: 457-465

- 10 secure MCP tools registered
- Scheduler not auto-started (manual control via MCP tools)
- Session lifecycle separation

---

#### Phase 3: Verification Tools Registration

**Lines**: 467-470

- 5 MCP tools for agent trust & verification
- Integration with learning pattern system

---

#### Phase 4: Trinitas Agent Auto-Registration

**Lines**: 472-656
**Version**: v2.4.0+

**Conditional**: `TMWS_ENABLE_TRINITAS=true`

**Process**:

1. License validation (PRO+ required)
2. Create "trinitas" namespace if not exists
3. Register 6 Trinitas agents to database:
   - athena-conductor (Harmonious Conductor)
   - artemis-optimizer (Technical Perfectionist)
   - hestia-auditor (Security Guardian)
   - eris-coordinator (Tactical Coordinator)
   - hera-strategist (Strategic Commander)
   - muses-documenter (Knowledge Architect)
4. Agent file generation to `~/.claude/agents/`
5. Integrity verification (Ed25519 signature check)

**Graceful Degradation**: Agent registration failure doesn't block server startup

---

#### Phase 5: External MCP Server Auto-Connection

**Lines**: 658-691
**Version**: v2.4.2+

**Process**:

1. Load presets from `.mcp.json` or `~/.tmws/mcp.json`
2. Connect to servers with `autoConnect: true`
3. List available tools from connected servers
4. Log connection status

**Default Auto-Connected Servers**:
- context7
- playwright
- serena

**Graceful Degradation**: External server connection failure doesn't block startup

---

### Performance Improvements

**Legacy vs Hybrid Architecture**:

| Operation | Legacy | Hybrid | Improvement |
|-----------|--------|--------|-------------|
| store_memory | 10ms | 2ms | 5x faster |
| search_memories | 200ms | 0.5ms | 400x faster |
| Vector search | N/A | 0.47ms | ChromaDB-first |

**ChromaDB Optimization**:
- Hot cache (P95: 0.47ms)
- 1024-dimensional embeddings
- HNSW index for fast nearest neighbor search
- Persistent storage with DuckDB backend

---

## External MCP Integration

**Files**: `src/infrastructure/mcp/*.py`

### Integration Patterns

#### Pattern A: New Technology Introduction

**Use Case**: Adopting a new library/framework

```bash
# Step 1: Documentation lookup
context7.get_library_docs("next.js/v14")  # Athena

# Step 2: Impact assessment
serena.find_symbol("pages/*")  # Artemis

# Step 3: Migration plan documentation
# (using markitdown if available)

# Step 4: Functional testing
playwright.test_migration()  # Hestia
```

---

#### Pattern B: Security Audit

**Use Case**: Comprehensive security review

```bash
# Step 1: Vulnerability pattern search
serena.search_for_pattern("password|secret|token")  # Hestia

# Step 2: Dynamic testing
playwright.security_test()  # Hestia

# Step 3: Best practices verification
context7.get_library_docs("owasp/security-guide")  # Hestia

# Step 4: Audit report generation
# (using TMWS store_memory)
```

---

#### Pattern C: Performance Optimization

**Use Case**: Database query optimization

```bash
# Step 1: Bottleneck identification
serena.find_symbol("*Query*", include_body=True)  # Artemis

# Step 2: Best practices research
context7.get_library_docs("database/optimization")  # Artemis

# Step 3: Benchmark execution
playwright.performance_test()  # Artemis

# Step 4: Results documentation
# (using TMWS store_memory with performance metrics)
```

---

## Performance Metrics

### Latency Targets (P95)

| Operation | Target | Achieved | Status |
|-----------|--------|----------|--------|
| store_memory | < 5ms | 2-4ms | ✅ 50-100% better |
| search_memories | < 20ms | 5-20ms | ✅ On target |
| create_task | < 10ms | 5-10ms | ✅ On target |
| verify_and_record | < 550ms | 350-450ms | ✅ 18-36% better |
| Vector search | < 10ms | 0.47ms | ✅ 95% better |
| Metadata queries | < 20ms | 2.63ms | ✅ 87% better |

### ChromaDB Performance

- **Vector similarity search**: < 10ms P95 ✅
- **Metadata filtering**: < 20ms P95 ✅
- **Hot cache hit rate**: > 90% ✅
- **Embedding generation**: 70-90ms (Ollama, external dependency)

### External MCP Server Latency

| Server | Connection | Tool Execution | Total Overhead |
|--------|------------|----------------|----------------|
| context7 | 50-100ms | 200-500ms | 250-600ms |
| playwright | 50-100ms | 1000-3000ms | 1050-3100ms |
| serena | 50-100ms | 100-300ms | 150-400ms |

**Note**: External server latency depends on network, subprocess startup, and tool complexity.

---

## Security Architecture

### Authentication & Authorization

**File**: `src/security/mcp_auth.py`

**Phase 0.5 Fixes** (2025-11-01):
- bcrypt migration for API keys (CVSS 7.5 HIGH → 0.0)
- P0 + P0.1 authentication fixes (CVSS 9.1 → 0.0)

**Security Layers**:

1. **API Key Authentication**
   - bcrypt hashing (work factor: 12)
   - 90-day expiration (configurable)
   - Status tracking (active/inactive/suspended)

2. **JWT Token Authentication**
   - Ed25519 signature verification
   - Short-lived access tokens (15 minutes)
   - Refresh token rotation (7 days)

3. **RBAC (Role-Based Access Control)**
   - FREE/PRO/ENTERPRISE/ADMIN roles
   - Tool-level authorization
   - Tier-based feature gating

4. **Namespace Isolation**
   - P0-1 security pattern (verified from DB)
   - Prevents cross-tenant access (V-1 fix)
   - Rejects explicit "default" namespace

---

### Verification System Security

**File**: `src/services/verification_service.py`

**V-VERIFY-* Security Controls**:

#### V-VERIFY-1: Command Injection Prevention

**Lines**: 36-62

**Allowed Commands** (21 total):
- Testing: pytest, ruff, mypy, coverage
- Git: git status/diff/log/show
- Node: npm test/run/list
- Docker: docker ps/inspect/logs
- System: ls, cat, grep, wc, echo

**Enforcement**:
- Whitelist-only execution
- Argument validation
- No shell metacharacters allowed

---

#### V-VERIFY-2: Verifier Authorization

**Requirement**: RBAC role check (AGENT/ADMIN role required, OBSERVER blocked)

---

#### V-VERIFY-3: Namespace Isolation

**Pattern**: P0-1 (namespace verified from database, not user input)

---

#### V-VERIFY-4: Pattern Eligibility Validation

**Restriction**: Only public/system patterns can be linked (no self-owned patterns)

---

#### V-TRUST-5: Self-Verification Prevention

**Rule**: Agent cannot verify its own claims

---

### Rate Limiting

**File**: `src/security/mcp_rate_limiter.py`

**Tier-Based Limits**:

| Tier | Global | Tool-Specific | Burst |
|------|--------|--------------|-------|
| FREE | 60/min | 5-30/min | 10 |
| PRO | 300/min | 10-60/min | 50 |
| ENTERPRISE | 1000/min | 20-100/min | 100 |
| ADMIN | None | None | None |

**Fail-Secure Pattern**: Rate limit failures block request (no silent degradation)

---

## November 2025 Enhancements

### v2.4.3 - Dynamic MCP Server Management (2025-11-27)

**Commit**: `3258c4c`

**Added**:
1. **4 New MCP Tools** (lines 229-439):
   - list_mcp_servers
   - connect_mcp_server
   - disconnect_mcp_server
   - get_mcp_status

2. **Preset Configuration System** (`src/infrastructure/mcp/preset_config.py`):
   - MCPServerPreset dataclass
   - MCPPresetLoader
   - Environment variable interpolation
   - Multi-source configuration (project/.mcp.json + user/~/.tmws/mcp.json)

3. **STDIO Transport Implementation** (`src/infrastructure/mcp/stdio_transport.py`):
   - Subprocess management
   - stdin/stdout communication
   - Process lifecycle handling

4. **MCPManager** (`src/infrastructure/mcp/manager.py`):
   - Connection pooling
   - Auto-connect from config
   - Tool discovery
   - Resource limits (max 10 connections)

**Performance**: Connection overhead 50-100ms (subprocess startup)

**Security**:
- Preset-only connections (no arbitrary commands)
- Resource exhaustion prevention (max 10 connections)
- Process isolation
- Graceful degradation on connection failure

---

### v2.4.2 - External MCP Auto-Connection (2025-11-26)

**Phase 6**: Auto-connection to preset servers on startup

**Process**:
1. Load presets from configuration files
2. Filter servers with `autoConnect: true`
3. Connect in parallel
4. Log success/failure
5. Continue server startup regardless of connection status

**Default Auto-Connected** (4 servers):
- context7
- playwright
- serena
- markitdown (if available)

---

### v2.4.1 - Ed25519 License Verification (2025-11-25)

**Phase 2E-1**: Public key cryptography for license keys

**Security Improvements**:
- Ed25519 signature verification (primary)
- HMAC-SHA256 fallback (legacy compatibility)
- Database-independent validation
- Offline-first validation
- Performance: <5ms P95 (pure crypto, no I/O)

**License Key Format v3**:
```
TMWS-{TIER}-{UUID}-{EXPIRY}-{ED25519_SIGNATURE_B64}
```

**Docker Distribution**:
- Public key embedded in image
- Private key NEVER distributed
- Signature verification only (no key generation in production)

---

### v2.4.0 - Trinitas Agent Integration (2025-11-20)

**Phase 2E-3**: Agent auto-registration and file generation

**Features**:

1. **Agent Auto-Registration** (lines 527-656):
   - 6 Trinitas agents registered to database
   - License-gated (PRO+ required)
   - Graceful degradation on failure

2. **Agent File Generation** (lines 472-525):
   - Markdown files to `~/.claude/agents/`
   - Ed25519 integrity verification
   - Bundled agent definitions

3. **License-Gated Features**:
   - Trinitas agents require PRO+ license
   - Agent count enforced by tier limits
   - Progressive disclosure (token budgets)

---

### v2.3.0 - Verification-Trust Integration (2025-11-10)

**Phase 2B**: Trust score system with verification

**Added**:
- verify_and_record MCP tool
- 4 additional verification tools
- Pattern linkage infrastructure
- Trust score propagation
- EWMA algorithm for trust calculation

**Security**:
- V-VERIFY-1/2/3/4 compliance
- V-TRUST-5 compliance
- 21/21 integration tests PASS

**Performance**:
- verify_and_record: 350-450ms P95 (18-36% better than target)
- Pattern propagation: <35ms P95 (6.8% overhead)

---

## Conclusion

TMWS implements a comprehensive MCP server with 26 tools across 4 categories, dynamic external server management, and a robust license system. November 2025 saw significant enhancements including dynamic MCP server management (v2.4.3), Ed25519 license verification (v2.4.1), and Trinitas agent integration (v2.4.0).

### Key Achievements

✅ **26 Production-Ready MCP Tools** (21 Python + 5 Go wrapper)
✅ **4 External MCP Servers** (context7, playwright, serena, chrome-devtools)
✅ **4 License Tiers** (FREE, PRO, ENTERPRISE, ADMINISTRATOR)
✅ **Ed25519 Public Key Cryptography** (license verification)
✅ **Hybrid Architecture** (SQLite + ChromaDB)
✅ **Performance Targets Met** (2-450ms P95, all tools within target)
✅ **Security Hardened** (V-VERIFY-* compliance, P0-1 pattern, bcrypt migration)

### Development Activity (November 2025)

- **Total Commits**: 123
- **Major Versions**: 4 (v2.3.0, v2.4.0, v2.4.1, v2.4.3)
- **New MCP Tools**: 4 (dynamic server management)
- **Security Fixes**: 7 (V-VERIFY-1/2/3/4, V-TRUST-5, P0, P0.1)

---

**Document Maintenance**:
- Review frequency: Monthly
- Next review: 2025-12-28
- Owner: Muses (Knowledge Architect)
- Approvers: Artemis (Technical), Hestia (Security)

---

**References**:

1. MCP Tools Reference: `docs/MCP_TOOLS_REFERENCE.md`
2. MCP Integration Guide: `docs/MCP_INTEGRATION.md`
3. License Service: `src/services/license_service.py`
4. MCP Server: `src/mcp_server.py`
5. Verification Service: `src/services/verification_service.py`
6. Changelog: `CHANGELOG.md`

---

**End of Document**
