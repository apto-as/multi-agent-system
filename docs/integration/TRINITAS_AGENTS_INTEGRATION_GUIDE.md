# Trinitas-agents Integration Guide

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team
**Last Updated**: 2025-11-13
**Status**: Production-ready

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Technical Architecture](#technical-architecture)
3. [REST API Specification Summary](#rest-api-specification-summary)
4. [Required MCP Tools Implementation](#required-mcp-tools-implementation)
5. [Agent Skills Migration](#agent-skills-migration)
6. [Security Requirements](#security-requirements)
7. [Testing Guide](#testing-guide)
8. [Deployment Considerations](#deployment-considerations)
9. [Example Implementation](#example-implementation)
10. [Breaking Changes Checklist](#breaking-changes-checklist)
11. [FAQ](#faq)
12. [Timeline and Support](#timeline-and-support)

---

## Executive Summary

### What Changed in TMWS v2.3.0

**Phase 1: MCP Connection Management REST API** has been implemented, providing 4 new HTTP endpoints that enable external MCP server connections.

**Key Changes**:
- ✅ **New REST API**: 4 endpoints for MCP connection lifecycle management
- ✅ **Authentication**: JWT Bearer token authentication required for all endpoints
- ✅ **Security**: P0-1 namespace isolation enforced (CVSS 8.7 protection)
- ✅ **Rate Limiting**: Fail-secure rate limiting with degraded mode support
- ✅ **Production-ready**: 20 integration tests + 4 E2E tests (100% pass rate)

### Why Trinitas-agents Needs to Be Updated

**Current State**: Trinitas-agents connects to TMWS MCP Server (21 internal tools)

**New Capability**: Trinitas-agents needs to expose REST API functionality as MCP tools so that Claude Code can:
1. Connect to external MCP servers (e.g., playwright, serena, context7)
2. Discover tools available on connected servers
3. Execute tools on connected servers
4. Manage connection lifecycle (disconnect)

**Value Proposition**: This enables Claude Code to dynamically extend its capabilities by connecting to any MCP-compliant server at runtime.

### Expected Timeline and Effort Estimate

| Phase | Tasks | Effort | Timeline |
|-------|-------|--------|----------|
| **Phase 1: Implementation** | 4 MCP tools, JWT auth, error handling | 8-12 hours | Week 1 |
| **Phase 2: Testing** | Unit tests (16 tests), integration tests (8 tests) | 4-6 hours | Week 1 |
| **Phase 3: Documentation** | Update Agent Skills documentation | 2-3 hours | Week 2 |
| **Phase 4: Deployment** | Environment configuration, validation | 2-3 hours | Week 2 |
| **Total** | | **16-24 hours** | **2 weeks** |

**Confidence Level**: High (API is stable, fully tested, production-ready)

---

## Technical Architecture

### Current: Trinitas-agents → TMWS MCP Server (21 tools)

```
┌──────────────────┐
│  Claude Code     │
└────────┬─────────┘
         │ MCP Protocol
         ▼
┌──────────────────┐
│ Trinitas-agents  │  (21 MCP tools)
│  MCP Server      │
└────────┬─────────┘
         │ Direct MCP connection
         ▼
┌──────────────────┐
│  TMWS MCP Server │  (21 internal tools)
│  • store_memory  │
│  • search_memories
│  • create_task   │
│  • ...           │
└──────────────────┘
```

### New: Trinitas-agents → TMWS REST API → External MCP Servers

```
┌────────────────────────────────────────────────────────────────────┐
│  Claude Code                                                       │
└────────────────────────────────────────────────────────────────────┘
         │ MCP Protocol
         ▼
┌────────────────────────────────────────────────────────────────────┐
│ Trinitas-agents MCP Server                                         │
│                                                                      │
│  Existing 21 tools          + New 4 MCP tools                       │
│  ├─ store_memory              ├─ connect_to_mcp_server             │
│  ├─ search_memories           ├─ disconnect_from_mcp_server        │
│  ├─ create_task               ├─ discover_mcp_tools                │
│  └─ ...                       └─ execute_mcp_tool                  │
└────────────────────┬───────────────────────────────────────────────┘
                     │ Direct MCP                │ HTTP REST API (JWT)
                     ▼                           ▼
         ┌──────────────────┐      ┌───────────────────────┐
         │  TMWS MCP Server │      │  TMWS REST API        │
         │  (21 tools)      │      │  (4 endpoints)        │
         └──────────────────┘      └───────────┬───────────┘
                                               │ MCP Protocol
                     ┌─────────────────────────┼────────────────────┐
                     ▼                         ▼                    ▼
         ┌──────────────────┐      ┌──────────────────┐  ┌──────────────────┐
         │  Playwright MCP  │      │  Serena MCP      │  │  Context7 MCP    │
         │  (Browser tools) │      │  (Code analysis) │  │  (Docs search)   │
         └──────────────────┘      └──────────────────┘  └──────────────────┘
```

**Key Changes**:
1. **4 New MCP Tools**: Trinitas-agents implements new tools that call TMWS REST API
2. **REST API Client**: Trinitas-agents includes HTTP client with JWT authentication
3. **Connection Management**: TMWS REST API manages external MCP server connections
4. **Unified Interface**: Claude Code uses same MCP protocol for all operations

---

## REST API Specification Summary

### Base Configuration

- **Base URL**: `http://localhost:8000/api/v1/mcp` (development) or `https://your-domain.com/api/v1/mcp` (production)
- **Authentication**: JWT Bearer token (required for all endpoints)
- **Content-Type**: `application/json`
- **Rate Limiting**: Production (strict), Development (lenient), Test (disabled)

### 4 Endpoints Overview

| Endpoint | Method | Rate Limit (Prod) | Purpose |
|----------|--------|-------------------|---------|
| `/connections` | POST | 10/min (+2 burst) | Create new MCP connection |
| `/connections/{id}` | DELETE | 20/min (+5 burst) | Disconnect from MCP server |
| `/connections/{id}/tools` | GET | 50/min (+10 burst) | Discover available tools |
| `/connections/{id}/tools/{tool}/execute` | POST | 100/min (+20 burst) | Execute specific tool |

### Authentication Requirements

**JWT Token Structure**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "agent-uuid",
  "exp": 1699876543
}
```

**Required Claims**:
- `sub`: Agent UUID (must exist in TMWS database)
- `exp`: Expiration timestamp (Unix time)

**Header Format**:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Rate Limiting (Production vs Development)

#### Production Limits (Strict)

| Endpoint | Requests/min | Burst | Block Duration |
|----------|--------------|-------|----------------|
| Create Connection | 10 | +2 | 5 min |
| Discover Tools | 50 | +10 | 1 min |
| Execute Tool | 100 | +20 | 1 min |
| Disconnect | 20 | +5 | 1 min |

#### Development Limits (Lenient)

| Endpoint | Requests/min | Burst | Block Duration |
|----------|--------------|-------|----------------|
| Create Connection | 30 | +10 | 5 min |
| Discover Tools | 100 | +20 | 1 min |
| Execute Tool | 200 | +50 | 1 min |
| Disconnect | 50 | +10 | 1 min |

**Environment Variable**: `TMWS_ENVIRONMENT=production` or `development` or `test`

### Error Handling

**Standard Error Response**:
```json
{
  "error_code": "VALIDATION_ERROR",
  "message": "Invalid request parameters",
  "details": {
    "field": "url",
    "issue": "Invalid URL format"
  },
  "timestamp": "2025-11-13T10:30:00.123456Z",
  "request_id": "req-abc123"
}
```

**Common Error Codes**:

| HTTP Status | Error Code | Description | Retry Strategy |
|-------------|------------|-------------|----------------|
| 400 | `VALIDATION_ERROR` | Invalid parameters | Fix input, retry |
| 401 | N/A | Missing/invalid JWT | Refresh token, retry |
| 403 | `AUTHORIZATION_ERROR` | Namespace mismatch | Do not retry |
| 404 | `CONNECTION_NOT_FOUND` | Connection doesn't exist | Do not retry |
| 409 | `DUPLICATE_CONNECTION` | Connection name exists | Use different name |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests | Wait, exponential backoff |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server failed | Retry with backoff |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure | Wait, retry |

---

## Required MCP Tools Implementation

### Tool 1: `connect_to_mcp_server`

**Description**: Establish a connection to an external MCP server

**Input Parameters**:
```python
{
  "server_name": str,      # Unique name (e.g., "playwright", "serena")
  "url": str,              # MCP server URL (http/https)
  "timeout": int,          # Connection timeout in seconds (5-300)
  "namespace": str,        # Agent namespace (verified from DB)
  "agent_id": str          # Agent UUID (from JWT token)
}
```

**Output Format**:
```python
{
  "id": "UUID",                     # Connection ID
  "server_name": "my-server",
  "status": "active",
  "namespace": "my-namespace",
  "agent_id": "agent-uuid",
  "config": {
    "url": "http://localhost:8080/",
    "timeout": 30
  },
  "tools": [                        # Discovered tools
    {
      "name": "search",
      "description": "Search documents",
      "input_schema": {
        "type": "object",
        "properties": {
          "query": {"type": "string"}
        }
      }
    }
  ],
  "connected_at": "2025-11-13T10:30:00.123456Z",
  "created_at": "2025-11-13T10:30:00.123456Z",
  "updated_at": "2025-11-13T10:30:00.123456Z"
}
```

**Example Implementation** (Python):

```python
import httpx
from jose import jwt
from datetime import datetime, timedelta
from typing import Dict, Any

class TMWSRestClient:
    """HTTP client for TMWS REST API"""

    def __init__(self, base_url: str, secret_key: str, agent_id: str, namespace: str):
        self.base_url = base_url.rstrip('/')
        self.secret_key = secret_key
        self.agent_id = agent_id
        self.namespace = namespace
        self.client = httpx.AsyncClient(timeout=30.0)

    def _create_jwt_token(self, expires_delta: timedelta = None) -> str:
        """Generate JWT token for authentication"""
        if expires_delta is None:
            expires_delta = timedelta(hours=24)

        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": self.agent_id,
            "exp": expire,
            "iat": datetime.utcnow()
        }

        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers with JWT token"""
        token = self._create_jwt_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    async def connect_to_mcp_server(
        self,
        server_name: str,
        url: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Connect to external MCP server

        Args:
            server_name: Unique name for connection
            url: MCP server URL (http/https)
            timeout: Connection timeout (5-300 seconds)

        Returns:
            Connection details with discovered tools

        Raises:
            httpx.HTTPStatusError: If request fails
        """
        request_body = {
            "server_name": server_name,
            "url": url,
            "timeout": timeout,
            "namespace": self.namespace,
            "agent_id": self.agent_id
        }

        response = await self.client.post(
            f"{self.base_url}/api/v1/mcp/connections",
            json=request_body,
            headers=self._get_auth_headers()
        )

        response.raise_for_status()
        return response.json()

# Example usage in MCP tool
async def mcp_tool_connect_to_mcp_server(
    server_name: str,
    url: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """MCP tool: Connect to external MCP server"""

    # Get configuration from environment
    import os
    base_url = os.getenv("TMWS_BASE_URL", "http://localhost:8000")
    secret_key = os.getenv("TMWS_SECRET_KEY")
    agent_id = os.getenv("TMWS_AGENT_ID")
    namespace = os.getenv("TMWS_NAMESPACE", "default")

    # Create client
    client = TMWSRestClient(base_url, secret_key, agent_id, namespace)

    try:
        # Call REST API
        result = await client.connect_to_mcp_server(server_name, url, timeout)
        return result
    except httpx.HTTPStatusError as e:
        # Handle HTTP errors
        if e.response.status_code == 409:
            return {
                "error": f"Connection '{server_name}' already exists",
                "error_code": "DUPLICATE_CONNECTION"
            }
        elif e.response.status_code == 502:
            return {
                "error": f"Failed to connect to MCP server at {url}",
                "error_code": "EXTERNAL_SERVICE_ERROR"
            }
        else:
            return {
                "error": str(e),
                "error_code": "HTTP_ERROR",
                "status_code": e.response.status_code
            }
    except Exception as e:
        # Handle unexpected errors
        return {
            "error": str(e),
            "error_code": "UNEXPECTED_ERROR"
        }
```

**Example Usage from Claude Code**:
```
/trinitas execute artemis "Connect to playwright MCP server at http://localhost:3000"
→ Artemis: Calling connect_to_mcp_server(server_name="playwright", url="http://localhost:3000")
→ Result: Connection established, 15 tools discovered (browser_navigate, browser_click, ...)
```

---

### Tool 2: `disconnect_from_mcp_server`

**Description**: Terminate an existing MCP connection

**Input Parameters**:
```python
{
  "connection_id": str  # UUID of connection to disconnect
}
```

**Output Format**:
```python
{
  "status": "disconnected",
  "connection_id": "UUID"
}
```

**Example Implementation** (Python):

```python
async def disconnect_from_mcp_server(self, connection_id: str) -> Dict[str, Any]:
    """Disconnect from MCP server

    Args:
        connection_id: UUID of connection to disconnect

    Returns:
        Status confirmation

    Raises:
        httpx.HTTPStatusError: If request fails
    """
    response = await self.client.delete(
        f"{self.base_url}/api/v1/mcp/connections/{connection_id}",
        headers=self._get_auth_headers()
    )

    # 204 No Content = success
    if response.status_code == 204:
        return {
            "status": "disconnected",
            "connection_id": connection_id
        }

    response.raise_for_status()
    return response.json()

# MCP tool wrapper
async def mcp_tool_disconnect_from_mcp_server(connection_id: str) -> Dict[str, Any]:
    """MCP tool: Disconnect from MCP server"""

    client = TMWSRestClient(...)  # Initialize as before

    try:
        result = await client.disconnect_from_mcp_server(connection_id)
        return result
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {
                "error": f"Connection {connection_id} not found",
                "error_code": "CONNECTION_NOT_FOUND"
            }
        elif e.response.status_code == 403:
            return {
                "error": f"Connection {connection_id} belongs to different agent",
                "error_code": "AUTHORIZATION_ERROR"
            }
        else:
            return {
                "error": str(e),
                "error_code": "HTTP_ERROR",
                "status_code": e.response.status_code
            }
```

**Example Usage from Claude Code**:
```
/trinitas execute artemis "Disconnect from playwright MCP server"
→ Artemis: Calling disconnect_from_mcp_server(connection_id="550e8400-...")
→ Result: Connection terminated successfully
```

---

### Tool 3: `discover_mcp_tools`

**Description**: List all available tools on a connected MCP server

**Input Parameters**:
```python
{
  "connection_id": str  # UUID of connection to query
}
```

**Output Format**:
```python
{
  "id": "UUID",
  "server_name": "my-server",
  "status": "active",
  "namespace": "my-namespace",
  "agent_id": "agent-uuid",
  "config": {
    "url": "http://localhost:8080/",
    "timeout": 30
  },
  "tools": [
    {
      "name": "search",
      "description": "Search through documents",
      "input_schema": {
        "type": "object",
        "properties": {
          "query": {"type": "string"},
          "max_results": {"type": "integer", "default": 10}
        },
        "required": ["query"]
      }
    },
    {
      "name": "retrieve",
      "description": "Retrieve document by ID",
      "input_schema": {
        "type": "object",
        "properties": {
          "document_id": {"type": "string"}
        },
        "required": ["document_id"]
      }
    }
  ],
  "connected_at": "2025-11-13T10:30:00.123456Z",
  "created_at": "2025-11-13T10:30:00.123456Z",
  "updated_at": "2025-11-13T10:30:00.123456Z"
}
```

**Example Implementation** (Python):

```python
async def discover_mcp_tools(self, connection_id: str) -> Dict[str, Any]:
    """Discover tools available on MCP server

    Args:
        connection_id: UUID of connection

    Returns:
        Connection details with available tools

    Raises:
        httpx.HTTPStatusError: If request fails
    """
    response = await self.client.get(
        f"{self.base_url}/api/v1/mcp/connections/{connection_id}/tools",
        headers=self._get_auth_headers()
    )

    response.raise_for_status()
    return response.json()

# MCP tool wrapper
async def mcp_tool_discover_mcp_tools(connection_id: str) -> Dict[str, Any]:
    """MCP tool: Discover MCP tools"""

    client = TMWSRestClient(...)  # Initialize as before

    try:
        result = await client.discover_mcp_tools(connection_id)
        return result
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {
                "error": f"Connection {connection_id} not found",
                "error_code": "CONNECTION_NOT_FOUND"
            }
        elif e.response.status_code == 502:
            return {
                "error": "MCP server unreachable or tool discovery failed",
                "error_code": "EXTERNAL_SERVICE_ERROR"
            }
        else:
            return {
                "error": str(e),
                "error_code": "HTTP_ERROR",
                "status_code": e.response.status_code
            }
```

**Example Usage from Claude Code**:
```
/trinitas execute artemis "List all tools available on playwright MCP server"
→ Artemis: Calling discover_mcp_tools(connection_id="550e8400-...")
→ Result: 15 tools found: browser_navigate, browser_click, browser_screenshot, ...
```

---

### Tool 4: `execute_mcp_tool`

**Description**: Execute a specific tool on a connected MCP server

**Input Parameters**:
```python
{
  "connection_id": str,    # UUID of connection
  "tool_name": str,        # Name of tool to execute
  "arguments": dict        # Tool-specific arguments
}
```

**Output Format**:
```python
{
  "connection_id": "UUID",
  "tool_name": "search",
  "result": {
    "status": "completed",
    "result": [              # Tool-specific result structure
      {
        "id": "doc-123",
        "title": "Relevant Document",
        "score": 0.95
      }
    ],
    "execution_time_ms": 45
  }
}
```

**Example Implementation** (Python):

```python
async def execute_mcp_tool(
    self,
    connection_id: str,
    tool_name: str,
    arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute tool on MCP server

    Args:
        connection_id: UUID of connection
        tool_name: Name of tool to execute
        arguments: Tool-specific arguments

    Returns:
        Tool execution result

    Raises:
        httpx.HTTPStatusError: If request fails
    """
    request_body = {
        "arguments": arguments
    }

    response = await self.client.post(
        f"{self.base_url}/api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute",
        json=request_body,
        headers=self._get_auth_headers()
    )

    response.raise_for_status()
    return response.json()

# MCP tool wrapper
async def mcp_tool_execute_mcp_tool(
    connection_id: str,
    tool_name: str,
    arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """MCP tool: Execute MCP tool"""

    client = TMWSRestClient(...)  # Initialize as before

    try:
        result = await client.execute_mcp_tool(connection_id, tool_name, arguments)
        return result
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            error_body = e.response.json()
            if error_body.get("error_code") == "TOOL_NOT_FOUND":
                return {
                    "error": f"Tool '{tool_name}' not found in connection",
                    "error_code": "TOOL_NOT_FOUND"
                }
            else:
                return {
                    "error": f"Invalid tool arguments: {error_body.get('message')}",
                    "error_code": "VALIDATION_ERROR"
                }
        elif e.response.status_code == 502:
            return {
                "error": f"MCP server failed to execute tool '{tool_name}'",
                "error_code": "EXTERNAL_SERVICE_ERROR"
            }
        else:
            return {
                "error": str(e),
                "error_code": "HTTP_ERROR",
                "status_code": e.response.status_code
            }
```

**Example Usage from Claude Code**:
```
/trinitas execute artemis "Use playwright to navigate to https://example.com"
→ Artemis: Calling execute_mcp_tool(
    connection_id="550e8400-...",
    tool_name="browser_navigate",
    arguments={"url": "https://example.com"}
  )
→ Result: Browser navigated successfully, page loaded in 234ms
```

---

## Agent Skills Migration

### What is Agent Skills?

**Agent Skills** is the system where Trinitas agents define their capabilities. It's maintained in:
- Repository: `trinitas-agents/agent-skills/`
- Format: YAML files defining agent personas, capabilities, and tool mappings

### Old Version vs TMWS Version Comparison

**Before v2.3.0** (TMWS v2.2.x):
```yaml
# trinitas-agents/agent-skills/artemis.yaml
capabilities:
  - code_optimization
  - performance_tuning
  - quality_assurance

tools:
  # Only TMWS internal tools
  - store_memory
  - search_memories
  - create_task
  # ... (18 more TMWS tools)
```

**After v2.3.0** (TMWS v2.3.0+):
```yaml
# trinitas-agents/agent-skills/artemis.yaml
capabilities:
  - code_optimization
  - performance_tuning
  - quality_assurance
  - external_mcp_integration  # NEW

tools:
  # TMWS internal tools (21 tools)
  - store_memory
  - search_memories
  - create_task
  # ... (18 more TMWS tools)

  # TMWS MCP connection tools (4 new tools)
  - connect_to_mcp_server
  - disconnect_from_mcp_server
  - discover_mcp_tools
  - execute_mcp_tool
```

### Breaking Changes

**None**. This is a **backwards-compatible addition**.

- ✅ Existing 21 TMWS tools continue to work unchanged
- ✅ New 4 MCP connection tools are additive
- ✅ No changes to existing tool interfaces
- ✅ No changes to authentication or authorization

### Migration Steps

1. **Update Agent Skills YAML files** (5 minutes):
   - Add 4 new tools to each agent's capabilities
   - No changes to existing tools required

2. **Implement 4 new MCP tools** (8-12 hours):
   - Implement `TMWSRestClient` class
   - Implement 4 MCP tool wrappers
   - Add error handling and retry logic

3. **Update documentation** (2 hours):
   - Document new tools in Agent Skills README
   - Add usage examples for each persona
   - Update integration test documentation

4. **Test integration** (4 hours):
   - Unit tests for REST client
   - Integration tests with TMWS REST API
   - End-to-end tests with external MCP servers

---

## Security Requirements

### JWT Token Generation

**Implementation** (Python):

```python
from jose import jwt
from datetime import datetime, timedelta
import os

def create_tmws_jwt_token(
    agent_id: str,
    secret_key: str = None,
    expires_delta: timedelta = None
) -> str:
    """Generate JWT token for TMWS REST API authentication

    Args:
        agent_id: UUID of agent (must exist in TMWS database)
        secret_key: TMWS secret key (from environment if not provided)
        expires_delta: Token lifetime (default: 24 hours)

    Returns:
        JWT token string

    Raises:
        ValueError: If secret_key not provided and TMWS_SECRET_KEY not set
    """
    # Get secret key from environment if not provided
    if secret_key is None:
        secret_key = os.getenv("TMWS_SECRET_KEY")
        if not secret_key:
            raise ValueError(
                "Secret key required. Provide secret_key parameter or set TMWS_SECRET_KEY environment variable"
            )

    # Default expiration: 24 hours
    if expires_delta is None:
        expires_delta = timedelta(hours=24)

    # Create payload
    expire = datetime.utcnow() + expires_delta
    payload = {
        "sub": agent_id,  # Subject (agent UUID)
        "exp": expire,    # Expiration timestamp
        "iat": datetime.utcnow()  # Issued at timestamp
    }

    # Sign token with HS256
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

# Example usage
agent_id = os.getenv("TMWS_AGENT_ID", "550e8400-e29b-41d4-a716-446655440000")
secret_key = os.getenv("TMWS_SECRET_KEY")

token = create_tmws_jwt_token(
    agent_id=agent_id,
    secret_key=secret_key,
    expires_delta=timedelta(hours=24)
)

print(f"JWT Token: {token}")
```

### P0-1 Namespace Isolation Enforcement

**Critical Security Requirement**: Namespace must NEVER be trusted from client input.

**❌ WRONG** (Security Vulnerability):
```python
# DON'T trust namespace from user input
async def connect_to_mcp_server(server_name: str, url: str, namespace: str):
    # ❌ WRONG: Using user-provided namespace directly
    request_body = {
        "namespace": namespace,  # ❌ Can be forged!
        ...
    }
```

**✅ CORRECT** (Secure Implementation):
```python
# DO verify namespace from environment/configuration
async def connect_to_mcp_server(server_name: str, url: str):
    # ✅ CORRECT: Namespace from verified source
    namespace = os.getenv("TMWS_NAMESPACE")  # From environment
    # or
    namespace = get_agent_namespace_from_db(agent_id)  # From database

    request_body = {
        "namespace": namespace,  # ✅ Verified namespace
        ...
    }
```

**Why This Matters**:
- **Multi-tenancy**: Multiple agents share TMWS database
- **Data isolation**: Agent A cannot access Agent B's connections
- **Compliance**: Prevents CVSS 8.7 HIGH cross-tenant data leakage

**TMWS Enforcement**:
1. JWT token is validated → `agent_id` extracted
2. Agent record fetched from database → `namespace` verified
3. Request namespace compared with agent's verified namespace
4. Request denied if mismatch (403 Forbidden)

### Secret Key Management

**Production**:
```bash
# Generate secure random key (64 hex chars = 32 bytes)
openssl rand -hex 32

# Store in secure secret manager (AWS Secrets Manager, Azure Key Vault, etc.)
# or environment variable (NEVER commit to git)
export TMWS_SECRET_KEY="your-generated-key-here"
```

**Development**:
```bash
# For local development only
export TMWS_SECRET_KEY="development-secret-key-min-32-chars-required"
```

**Using .env File** (add to `.gitignore`!):
```bash
# .env
TMWS_SECRET_KEY=your-secret-key-here
TMWS_ENVIRONMENT=development
TMWS_AGENT_ID=agent-uuid-here
TMWS_NAMESPACE=your-namespace
```

### HTTPS Requirement for Production

**Development** (HTTP acceptable):
```python
TMWS_BASE_URL = "http://localhost:8000"
```

**Production** (HTTPS mandatory):
```python
TMWS_BASE_URL = "https://tmws.your-domain.com"
```

**Validation**:
```python
def validate_base_url(base_url: str, environment: str):
    """Validate TMWS base URL based on environment"""
    if environment == "production":
        if not base_url.startswith("https://"):
            raise ValueError(
                f"Production environment requires HTTPS. Got: {base_url}"
            )

    # Ensure URL is well-formed
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid base URL: {base_url}")
```

---

## Testing Guide

### Unit Test Examples for New MCP Tools

**Test 1: JWT Token Generation**

```python
# tests/unit/test_tmws_jwt.py
import pytest
from jose import jwt
from datetime import datetime, timedelta
from trinitas_agents.tmws_client import create_tmws_jwt_token

def test_jwt_token_generation():
    """Test JWT token can be generated and decoded"""
    agent_id = "550e8400-e29b-41d4-a716-446655440000"
    secret_key = "test-secret-key-min-32-chars-12345"

    # Generate token
    token = create_tmws_jwt_token(
        agent_id=agent_id,
        secret_key=secret_key,
        expires_delta=timedelta(hours=1)
    )

    # Decode token
    payload = jwt.decode(token, secret_key, algorithms=["HS256"])

    # Verify claims
    assert payload["sub"] == agent_id
    assert "exp" in payload
    assert "iat" in payload

    # Verify expiration is in future
    exp_time = datetime.utcfromtimestamp(payload["exp"])
    assert exp_time > datetime.utcnow()

def test_jwt_token_expiration_enforced():
    """Test expired token is rejected"""
    agent_id = "550e8400-e29b-41d4-a716-446655440000"
    secret_key = "test-secret-key-min-32-chars-12345"

    # Generate expired token
    token = create_tmws_jwt_token(
        agent_id=agent_id,
        secret_key=secret_key,
        expires_delta=timedelta(seconds=-1)  # Already expired
    )

    # Verify token is rejected
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, secret_key, algorithms=["HS256"])
```

**Test 2: REST Client - Connect to MCP Server**

```python
# tests/unit/test_tmws_rest_client.py
import pytest
from httpx import AsyncClient, Response
from unittest.mock import AsyncMock, patch
from trinitas_agents.tmws_client import TMWSRestClient

@pytest.mark.asyncio
async def test_connect_to_mcp_server_success():
    """Test successful MCP connection"""
    client = TMWSRestClient(
        base_url="http://localhost:8000",
        secret_key="test-secret-key",
        agent_id="agent-uuid",
        namespace="test-namespace"
    )

    # Mock HTTP response
    mock_response = {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "server_name": "playwright",
        "status": "active",
        "namespace": "test-namespace",
        "agent_id": "agent-uuid",
        "tools": [
            {"name": "browser_navigate", "description": "Navigate browser"}
        ]
    }

    # Patch httpx client
    with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = Response(201, json=mock_response)

        result = await client.connect_to_mcp_server(
            server_name="playwright",
            url="http://localhost:3000",
            timeout=30
        )

        # Verify result
        assert result["server_name"] == "playwright"
        assert result["status"] == "active"
        assert len(result["tools"]) == 1

        # Verify request was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "/api/v1/mcp/connections" in call_args.args[0]

@pytest.mark.asyncio
async def test_connect_to_mcp_server_duplicate_error():
    """Test duplicate connection name error"""
    client = TMWSRestClient(
        base_url="http://localhost:8000",
        secret_key="test-secret-key",
        agent_id="agent-uuid",
        namespace="test-namespace"
    )

    # Mock 409 Conflict response
    from httpx import HTTPStatusError
    mock_response = Response(
        409,
        json={"error_code": "DUPLICATE_CONNECTION", "message": "Connection already exists"}
    )

    with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = HTTPStatusError(
            "409 Conflict",
            request=None,
            response=mock_response
        )

        # Call should handle error gracefully
        result = await client.connect_to_mcp_server(
            server_name="playwright",
            url="http://localhost:3000"
        )

        # Verify error response
        assert "error" in result
        assert result["error_code"] == "DUPLICATE_CONNECTION"
```

**Test 3: REST Client - Execute Tool**

```python
@pytest.mark.asyncio
async def test_execute_mcp_tool_success():
    """Test successful tool execution"""
    client = TMWSRestClient(
        base_url="http://localhost:8000",
        secret_key="test-secret-key",
        agent_id="agent-uuid",
        namespace="test-namespace"
    )

    # Mock tool execution response
    mock_response = {
        "connection_id": "550e8400-e29b-41d4-a716-446655440000",
        "tool_name": "browser_navigate",
        "result": {
            "status": "completed",
            "result": {"page_title": "Example Domain"},
            "execution_time_ms": 234
        }
    }

    with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
        mock_post.return_value = Response(200, json=mock_response)

        result = await client.execute_mcp_tool(
            connection_id="550e8400-e29b-41d4-a716-446655440000",
            tool_name="browser_navigate",
            arguments={"url": "https://example.com"}
        )

        # Verify result
        assert result["tool_name"] == "browser_navigate"
        assert result["result"]["status"] == "completed"
        assert result["result"]["execution_time_ms"] == 234
```

### Integration Test Scenarios

**Test 1: Full Connection Lifecycle**

```python
# tests/integration/test_mcp_connection_lifecycle.py
import pytest
from trinitas_agents.tmws_client import TMWSRestClient

@pytest.mark.asyncio
@pytest.mark.integration
async def test_full_mcp_connection_lifecycle(tmws_server_running):
    """Test complete MCP connection lifecycle"""
    # Setup
    client = TMWSRestClient(
        base_url="http://localhost:8000",
        secret_key="test-secret-key",
        agent_id="test-agent-uuid",
        namespace="test-namespace"
    )

    # Step 1: Connect to MCP server
    connection = await client.connect_to_mcp_server(
        server_name="test-server",
        url="http://localhost:3000",
        timeout=30
    )

    assert connection["status"] == "active"
    assert len(connection["tools"]) > 0
    connection_id = connection["id"]

    # Step 2: Discover tools
    discovered = await client.discover_mcp_tools(connection_id)

    assert discovered["id"] == connection_id
    assert len(discovered["tools"]) > 0
    tool_name = discovered["tools"][0]["name"]

    # Step 3: Execute tool
    result = await client.execute_mcp_tool(
        connection_id=connection_id,
        tool_name=tool_name,
        arguments={"test_param": "value"}
    )

    assert result["connection_id"] == connection_id
    assert result["tool_name"] == tool_name
    assert "result" in result

    # Step 4: Disconnect
    disconnect_result = await client.disconnect_from_mcp_server(connection_id)

    assert disconnect_result["status"] == "disconnected"
    assert disconnect_result["connection_id"] == connection_id
```

### Manual Testing Checklist

**Prerequisites**:
- [ ] TMWS REST API running (`http://localhost:8000`)
- [ ] Environment variables configured (`TMWS_SECRET_KEY`, `TMWS_AGENT_ID`, `TMWS_NAMESPACE`)
- [ ] Test MCP server running (`http://localhost:3000`)

**Test Cases**:

1. **JWT Token Generation**:
   - [ ] Token can be generated with valid agent_id
   - [ ] Token can be decoded to extract claims
   - [ ] Token expiration is enforced
   - [ ] Invalid token is rejected (401)

2. **Connect to MCP Server**:
   - [ ] Valid connection request succeeds (201)
   - [ ] Duplicate server_name returns 409 error
   - [ ] Invalid URL returns 400 error
   - [ ] Timeout out of range (0 or >300) returns 400 error
   - [ ] Namespace mismatch returns 403 error
   - [ ] Unreachable MCP server returns 502 error

3. **Discover Tools**:
   - [ ] Valid connection returns tool list (200)
   - [ ] Non-existent connection returns 404 error
   - [ ] Connection from different agent returns 403 error
   - [ ] Unreachable MCP server returns 502 error

4. **Execute Tool**:
   - [ ] Valid tool execution succeeds (200)
   - [ ] Non-existent tool returns 400 error
   - [ ] Invalid tool arguments return 400 error
   - [ ] Non-existent connection returns 404 error
   - [ ] Connection from different agent returns 403 error
   - [ ] Tool execution failure returns 502 error

5. **Disconnect**:
   - [ ] Valid disconnect succeeds (204)
   - [ ] Non-existent connection returns 404 error
   - [ ] Connection from different agent returns 403 error

6. **Rate Limiting** (production environment):
   - [ ] Exceeding rate limit returns 429 error
   - [ ] `Retry-After` header is present
   - [ ] Exponential backoff works correctly
   - [ ] Rate limit resets after specified time

### Performance Benchmarks to Verify

| Operation | Target P95 Latency | Target P99 Latency |
|-----------|-------------------|--------------------|
| JWT Token Generation | < 5ms | < 10ms |
| Connect to MCP Server | < 500ms | < 1000ms |
| Discover Tools | < 200ms | < 500ms |
| Execute Tool | < 1000ms | < 2000ms |
| Disconnect | < 100ms | < 200ms |

**Benchmark Script**:

```python
# tests/performance/benchmark_mcp_tools.py
import asyncio
import time
from statistics import median, quantiles

async def benchmark_operation(operation, iterations=100):
    """Benchmark an async operation"""
    latencies = []

    for _ in range(iterations):
        start = time.perf_counter()
        await operation()
        elapsed = (time.perf_counter() - start) * 1000  # ms
        latencies.append(elapsed)

    latencies.sort()
    p50 = median(latencies)
    p95, p99 = quantiles(latencies, n=100)[94], quantiles(latencies, n=100)[98]

    return {
        "p50": round(p50, 2),
        "p95": round(p95, 2),
        "p99": round(p99, 2),
        "min": round(min(latencies), 2),
        "max": round(max(latencies), 2)
    }

# Example usage
async def main():
    client = TMWSRestClient(...)

    # Benchmark Connect
    async def connect_op():
        await client.connect_to_mcp_server("test", "http://localhost:3000")

    connect_stats = await benchmark_operation(connect_op, iterations=50)
    print(f"Connect to MCP Server: {connect_stats}")

    # Benchmark Execute Tool
    # ... (similar for other operations)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Deployment Considerations

### Environment Variables to Configure

**Required**:
```bash
# TMWS REST API connection
export TMWS_BASE_URL="http://localhost:8000"  # Development
# export TMWS_BASE_URL="https://tmws.your-domain.com"  # Production

# Authentication
export TMWS_SECRET_KEY="your-secret-key-here"  # 32+ characters
export TMWS_AGENT_ID="agent-uuid-here"
export TMWS_NAMESPACE="your-namespace"

# Environment mode
export TMWS_ENVIRONMENT="development"  # or "production" or "test"
```

**Optional**:
```bash
# HTTP client configuration
export TMWS_HTTP_TIMEOUT=30  # Request timeout in seconds
export TMWS_MAX_RETRIES=3    # Max retry attempts for failed requests
export TMWS_RETRY_BACKOFF=2  # Exponential backoff multiplier

# Logging
export TMWS_LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### TMWS Base URL Configuration

**Development** (local TMWS server):
```bash
export TMWS_BASE_URL="http://localhost:8000"
```

**Staging** (internal network):
```bash
export TMWS_BASE_URL="https://tmws-staging.internal.your-domain.com"
```

**Production** (public HTTPS):
```bash
export TMWS_BASE_URL="https://tmws.your-domain.com"
```

**Validation**:
```python
def load_tmws_config():
    """Load and validate TMWS configuration"""
    import os

    base_url = os.getenv("TMWS_BASE_URL")
    if not base_url:
        raise ValueError("TMWS_BASE_URL environment variable required")

    environment = os.getenv("TMWS_ENVIRONMENT", "development")

    # Validate HTTPS in production
    if environment == "production" and not base_url.startswith("https://"):
        raise ValueError(
            f"Production requires HTTPS. Got: {base_url}"
        )

    return {
        "base_url": base_url,
        "secret_key": os.getenv("TMWS_SECRET_KEY"),
        "agent_id": os.getenv("TMWS_AGENT_ID"),
        "namespace": os.getenv("TMWS_NAMESPACE"),
        "environment": environment
    }
```

### Error Retry Strategies

**Exponential Backoff with Jitter**:

```python
import asyncio
import random
from typing import TypeVar, Callable, Awaitable

T = TypeVar('T')

async def retry_with_exponential_backoff(
    operation: Callable[[], Awaitable[T]],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_errors: tuple = (Exception,)
) -> T:
    """Retry operation with exponential backoff

    Args:
        operation: Async function to retry
        max_retries: Maximum retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap
        exponential_base: Backoff multiplier
        jitter: Add random jitter to delay
        retryable_errors: Exception types to retry on

    Returns:
        Operation result

    Raises:
        Last exception if all retries exhausted
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return await operation()
        except retryable_errors as e:
            last_exception = e

            if attempt >= max_retries:
                # Final attempt failed
                raise

            # Calculate delay with exponential backoff
            delay = min(base_delay * (exponential_base ** attempt), max_delay)

            # Add jitter to prevent thundering herd
            if jitter:
                delay = delay * (0.5 + random.random())

            logger.warning(
                f"Retry {attempt + 1}/{max_retries} after {delay:.2f}s: {e}"
            )

            await asyncio.sleep(delay)

    # Should never reach here
    raise last_exception

# Example usage
async def call_tmws_with_retry():
    """Call TMWS REST API with retry logic"""
    client = TMWSRestClient(...)

    async def connect_operation():
        return await client.connect_to_mcp_server(
            server_name="playwright",
            url="http://localhost:3000"
        )

    # Retry on network errors and 502/503
    from httpx import NetworkError, HTTPStatusError

    result = await retry_with_exponential_backoff(
        connect_operation,
        max_retries=3,
        base_delay=1.0,
        retryable_errors=(NetworkError, HTTPStatusError)
    )

    return result
```

**Retry Strategy by Error Type**:

| Error Type | Retry Strategy | Max Retries | Backoff |
|------------|----------------|-------------|---------|
| Network timeout | Exponential backoff | 3 | 1s → 2s → 4s |
| 429 Rate Limited | Use `Retry-After` header | 5 | As specified |
| 502 Bad Gateway | Exponential backoff | 3 | 2s → 4s → 8s |
| 503 Service Unavailable | Exponential backoff | 3 | 2s → 4s → 8s |
| 400 Validation Error | Do not retry | 0 | N/A |
| 401 Unauthorized | Refresh token, retry once | 1 | 0s |
| 403 Forbidden | Do not retry | 0 | N/A |
| 404 Not Found | Do not retry | 0 | N/A |

### Monitoring and Logging

**Structured Logging**:

```python
import logging
import json

logger = logging.getLogger("trinitas_agents.tmws_client")

def log_tmws_request(
    operation: str,
    connection_id: str = None,
    tool_name: str = None,
    latency_ms: float = None,
    success: bool = True,
    error: str = None
):
    """Log TMWS REST API request with structured metadata"""
    log_data = {
        "operation": operation,
        "connection_id": connection_id,
        "tool_name": tool_name,
        "latency_ms": round(latency_ms, 2) if latency_ms else None,
        "success": success,
        "error": error,
        "timestamp": datetime.utcnow().isoformat()
    }

    if success:
        logger.info(f"TMWS {operation} succeeded", extra=log_data)
    else:
        logger.error(f"TMWS {operation} failed", extra=log_data)

# Example usage
import time

async def connect_to_mcp_server_with_logging(server_name: str, url: str):
    """Connect to MCP server with structured logging"""
    start = time.perf_counter()

    try:
        client = TMWSRestClient(...)
        result = await client.connect_to_mcp_server(server_name, url)

        latency_ms = (time.perf_counter() - start) * 1000
        log_tmws_request(
            operation="connect",
            connection_id=result.get("id"),
            latency_ms=latency_ms,
            success=True
        )

        return result

    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        log_tmws_request(
            operation="connect",
            latency_ms=latency_ms,
            success=False,
            error=str(e)
        )
        raise
```

**Metrics Collection** (Prometheus-style):

```python
from prometheus_client import Counter, Histogram

# Define metrics
tmws_requests_total = Counter(
    'tmws_requests_total',
    'Total TMWS REST API requests',
    ['operation', 'status']
)

tmws_request_duration_seconds = Histogram(
    'tmws_request_duration_seconds',
    'TMWS REST API request duration',
    ['operation']
)

# Example usage
async def execute_mcp_tool_with_metrics(connection_id, tool_name, arguments):
    """Execute MCP tool with metrics collection"""

    with tmws_request_duration_seconds.labels(operation='execute_tool').time():
        try:
            client = TMWSRestClient(...)
            result = await client.execute_mcp_tool(
                connection_id, tool_name, arguments
            )

            # Success metric
            tmws_requests_total.labels(
                operation='execute_tool',
                status='success'
            ).inc()

            return result

        except Exception as e:
            # Failure metric
            tmws_requests_total.labels(
                operation='execute_tool',
                status='failure'
            ).inc()
            raise
```

---

## Example Implementation

### Complete Example: `connect_to_mcp_server` Tool

This example shows a complete, production-ready implementation of one MCP tool with:
- Parameter validation
- JWT authentication
- REST API call
- Error handling
- Retry logic
- Logging
- Response mapping

```python
# trinitas_agents/mcp_tools/tmws_connection_tools.py
"""MCP tools for TMWS REST API integration"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from uuid import UUID

import httpx
from jose import jwt, JWTError

logger = logging.getLogger(__name__)

class TMWSRestClient:
    """HTTP client for TMWS REST API

    Provides methods to interact with TMWS MCP Connection Management API.
    Handles JWT authentication, error handling, and retry logic.
    """

    def __init__(
        self,
        base_url: str,
        secret_key: str,
        agent_id: str,
        namespace: str,
        timeout: float = 30.0,
        max_retries: int = 3
    ):
        """Initialize TMWS REST client

        Args:
            base_url: TMWS REST API base URL (e.g., http://localhost:8000)
            secret_key: TMWS secret key for JWT signing
            agent_id: Agent UUID
            namespace: Agent namespace
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
        """
        self.base_url = base_url.rstrip('/')
        self.secret_key = secret_key
        self.agent_id = agent_id
        self.namespace = namespace
        self.max_retries = max_retries

        # Initialize HTTP client
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True
        )

        logger.info(
            f"TMWSRestClient initialized: base_url={base_url}, "
            f"agent_id={agent_id}, namespace={namespace}"
        )

    def _create_jwt_token(self, expires_delta: timedelta = None) -> str:
        """Generate JWT token for authentication

        Args:
            expires_delta: Token lifetime (default: 24 hours)

        Returns:
            JWT token string
        """
        if expires_delta is None:
            expires_delta = timedelta(hours=24)

        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": self.agent_id,  # Subject (agent UUID)
            "exp": expire,         # Expiration timestamp
            "iat": datetime.utcnow()  # Issued at timestamp
        }

        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        return token

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers with JWT token

        Returns:
            Dict with Authorization and Content-Type headers
        """
        token = self._create_jwt_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    async def _retry_request(
        self,
        operation: str,
        request_func: callable,
        *args,
        **kwargs
    ) -> httpx.Response:
        """Execute HTTP request with retry logic

        Args:
            operation: Operation name (for logging)
            request_func: HTTP request function (e.g., self.client.post)
            *args: Positional arguments for request_func
            **kwargs: Keyword arguments for request_func

        Returns:
            HTTP response

        Raises:
            httpx.HTTPStatusError: If request fails after all retries
        """
        import random

        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                response = await request_func(*args, **kwargs)
                response.raise_for_status()
                return response

            except httpx.HTTPStatusError as e:
                last_exception = e

                # Don't retry on client errors (4xx) except 429
                if 400 <= e.response.status_code < 500 and e.response.status_code != 429:
                    raise

                # Don't retry on final attempt
                if attempt >= self.max_retries:
                    raise

                # Calculate exponential backoff with jitter
                if e.response.status_code == 429:
                    # Use Retry-After header if available
                    retry_after = e.response.headers.get("Retry-After", "60")
                    delay = float(retry_after)
                else:
                    # Exponential backoff for 502/503
                    delay = min(2 ** attempt, 60) * (0.5 + random.random())

                logger.warning(
                    f"TMWS {operation} failed (attempt {attempt + 1}/{self.max_retries}), "
                    f"retrying in {delay:.2f}s: {e}"
                )

                await asyncio.sleep(delay)

        # Should never reach here
        raise last_exception

    async def connect_to_mcp_server(
        self,
        server_name: str,
        url: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Connect to external MCP server

        Args:
            server_name: Unique name for connection (alphanumeric + hyphens, 1-100 chars)
            url: MCP server URL (http/https)
            timeout: Connection timeout in seconds (5-300)

        Returns:
            Connection details with discovered tools:
            {
                "id": "UUID",
                "server_name": "my-server",
                "status": "active",
                "namespace": "my-namespace",
                "agent_id": "agent-uuid",
                "config": {
                    "url": "http://localhost:8080/",
                    "timeout": 30
                },
                "tools": [
                    {
                        "name": "search",
                        "description": "Search documents",
                        "input_schema": {...}
                    }
                ],
                "connected_at": "2025-11-13T10:30:00.123456Z",
                "created_at": "2025-11-13T10:30:00.123456Z",
                "updated_at": "2025-11-13T10:30:00.123456Z"
            }

        Raises:
            ValueError: If parameters are invalid
            httpx.HTTPStatusError: If request fails
        """
        # Validate parameters
        if not server_name or len(server_name) > 100:
            raise ValueError(f"server_name must be 1-100 characters: {server_name}")

        if not url or not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError(f"url must be http/https URL: {url}")

        if not (5 <= timeout <= 300):
            raise ValueError(f"timeout must be 5-300 seconds: {timeout}")

        # Build request
        request_body = {
            "server_name": server_name,
            "url": url,
            "timeout": timeout,
            "namespace": self.namespace,  # ✅ Verified from environment
            "agent_id": self.agent_id
        }

        logger.info(
            f"Connecting to MCP server: server_name={server_name}, url={url}"
        )

        try:
            # Execute request with retry logic
            response = await self._retry_request(
                operation="connect",
                request_func=self.client.post,
                url=f"{self.base_url}/api/v1/mcp/connections",
                json=request_body,
                headers=self._get_auth_headers()
            )

            result = response.json()

            logger.info(
                f"MCP connection established: id={result['id']}, "
                f"tools={len(result.get('tools', []))}"
            )

            return result

        except httpx.HTTPStatusError as e:
            # Handle specific error cases
            if e.response.status_code == 409:
                error_body = e.response.json()
                logger.error(f"Duplicate connection name: {server_name}")
                return {
                    "error": f"Connection '{server_name}' already exists",
                    "error_code": "DUPLICATE_CONNECTION",
                    "details": error_body.get("details")
                }

            elif e.response.status_code == 502:
                logger.error(f"MCP server unreachable: {url}")
                return {
                    "error": f"Failed to connect to MCP server at {url}",
                    "error_code": "EXTERNAL_SERVICE_ERROR",
                    "details": {"url": url}
                }

            else:
                logger.error(f"HTTP error: {e}")
                return {
                    "error": str(e),
                    "error_code": "HTTP_ERROR",
                    "status_code": e.response.status_code
                }

        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "error": str(e),
                "error_code": "UNEXPECTED_ERROR"
            }

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()


# MCP Tool Wrapper
async def mcp_tool_connect_to_mcp_server(
    server_name: str,
    url: str,
    timeout: int = 30
) -> Dict[str, Any]:
    """MCP tool: Connect to external MCP server

    This tool enables Claude Code to connect to external MCP servers
    (e.g., playwright, serena, context7) and discover their tools.

    Args:
        server_name: Unique name for connection (e.g., "playwright")
        url: MCP server URL (e.g., "http://localhost:3000")
        timeout: Connection timeout in seconds (default: 30)

    Returns:
        Connection details with discovered tools

    Example:
        >>> result = await mcp_tool_connect_to_mcp_server(
        ...     server_name="playwright",
        ...     url="http://localhost:3000",
        ...     timeout=30
        ... )
        >>> print(f"Connected to {result['server_name']}, found {len(result['tools'])} tools")
    """
    # Load configuration from environment
    base_url = os.getenv("TMWS_BASE_URL", "http://localhost:8000")
    secret_key = os.getenv("TMWS_SECRET_KEY")
    agent_id = os.getenv("TMWS_AGENT_ID")
    namespace = os.getenv("TMWS_NAMESPACE", "default")

    # Validate required environment variables
    if not secret_key:
        return {
            "error": "TMWS_SECRET_KEY environment variable not set",
            "error_code": "CONFIGURATION_ERROR"
        }

    if not agent_id:
        return {
            "error": "TMWS_AGENT_ID environment variable not set",
            "error_code": "CONFIGURATION_ERROR"
        }

    # Create client
    client = TMWSRestClient(
        base_url=base_url,
        secret_key=secret_key,
        agent_id=agent_id,
        namespace=namespace
    )

    try:
        # Call REST API
        result = await client.connect_to_mcp_server(server_name, url, timeout)
        return result

    finally:
        # Always close client
        await client.close()


# Register MCP tool with FastMCP
def register_tmws_connection_tools(mcp):
    """Register TMWS MCP connection tools with FastMCP server

    Args:
        mcp: FastMCP server instance
    """

    @mcp.tool(
        name="connect_to_mcp_server",
        description=(
            "Connect to external MCP server and discover available tools. "
            "Returns connection ID and list of discovered tools."
        )
    )
    async def connect_to_mcp_server(
        server_name: str,
        url: str,
        timeout: int = 30
    ) -> dict:
        return await mcp_tool_connect_to_mcp_server(server_name, url, timeout)

    # Register other 3 tools similarly...

    logger.info("TMWS MCP connection tools registered (4 tools)")
```

**Usage Example**:

```python
# trinitas_agents/main.py
from fastmcp import FastMCP
from trinitas_agents.mcp_tools.tmws_connection_tools import register_tmws_connection_tools

# Initialize MCP server
mcp = FastMCP(name="trinitas-agents", version="2.3.0")

# Register TMWS connection tools
register_tmws_connection_tools(mcp)

# Run MCP server
if __name__ == "__main__":
    mcp.run()
```

---

## Breaking Changes Checklist

### Summary

**✅ NO BREAKING CHANGES**

This integration is **100% backwards-compatible** with existing Trinitas-agents functionality.

### Detailed Checklist

- [x] **Existing 21 TMWS tools unchanged**
  - `store_memory`, `search_memories`, `create_task`, etc. continue to work exactly as before
  - No changes to tool interfaces, parameters, or return values

- [x] **Authentication unchanged**
  - Existing JWT authentication for direct MCP connection continues to work
  - New JWT authentication for REST API is additive (separate concern)

- [x] **No changes to Agent Skills interfaces**
  - Agent YAML files can be updated incrementally
  - Old YAML files without new tools will continue to work

- [x] **No changes to existing dependencies**
  - New dependencies (`httpx`, `python-jose`) are additive
  - No version conflicts with existing packages

- [x] **No database schema changes**
  - TMWS database schema unchanged
  - No migrations required

- [x] **No configuration changes required**
  - Existing `TMWS_*` environment variables unchanged
  - New environment variables are optional (with defaults)

### Migration Path

**Option 1: Gradual Rollout** (Recommended)
1. Deploy new code with 4 MCP tools (week 1)
2. Test internally with development environment (week 1-2)
3. Update Agent Skills YAML files incrementally (week 2)
4. Enable in production when validated (week 3)

**Option 2: Immediate Deployment**
1. Deploy all changes at once
2. Validate with integration tests
3. Monitor for 24 hours before enabling in production

**Rollback Plan**:
- Remove 4 new MCP tools from code
- Revert Agent Skills YAML changes
- No database rollback required (no schema changes)

---

## FAQ

### Q1: Do I need to update all 6 agent personas at once?

**A**: No, you can update incrementally. Each persona can be updated independently. The 4 new MCP tools are optional - agents without them will continue to work normally.

**Recommendation**: Start with Artemis (Technical Perfectionist) as he's most likely to use external MCP servers for code analysis and browser testing.

---

### Q2: What happens if TMWS REST API is down?

**A**: The 4 new MCP tools will return error responses, but the existing 21 TMWS tools (direct MCP connection) will continue to work normally.

**Error Response Example**:
```python
{
    "error": "TMWS REST API unreachable at http://localhost:8000",
    "error_code": "CONNECTION_ERROR",
    "fallback": "Direct TMWS MCP tools (store_memory, search_memories) still available"
}
```

---

### Q3: How do I test locally without setting up external MCP servers?

**A**: Use mock MCP servers or test against TMWS's own REST API.

**Option 1: Mock MCP Server**:
```python
# tests/fixtures/mock_mcp_server.py
from fastapi import FastAPI

app = FastAPI()

@app.get("/mcp/tools")
def list_tools():
    return {
        "tools": [
            {"name": "test_tool", "description": "Test tool"}
        ]
    }

@app.post("/mcp/tools/{tool_name}/execute")
def execute_tool(tool_name: str, arguments: dict):
    return {
        "status": "completed",
        "result": {"message": f"Executed {tool_name}"}
    }

# Run with: uvicorn tests.fixtures.mock_mcp_server:app --port 3000
```

**Option 2: Test Against TMWS REST API**:
```bash
# TMWS REST API is always available locally
export TMWS_BASE_URL="http://localhost:8000"
pytest tests/integration/test_mcp_tools.py
```

---

### Q4: How do I handle rate limiting in production?

**A**: Implement exponential backoff and respect `Retry-After` headers.

**Implementation**:
```python
# See "Error Retry Strategies" section above for complete implementation

async def call_with_rate_limit_handling():
    try:
        result = await client.connect_to_mcp_server(...)
        return result
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            # Rate limited
            retry_after = int(e.response.headers.get("Retry-After", 60))
            logger.warning(f"Rate limited, retrying in {retry_after}s")
            await asyncio.sleep(retry_after)
            # Retry once
            return await client.connect_to_mcp_server(...)
        else:
            raise
```

---

### Q5: Can I use the same JWT token for multiple requests?

**A**: Yes, but implement token caching with expiration awareness.

**Best Practice**:
```python
class TMWSRestClientWithTokenCache:
    def __init__(self, ...):
        self._cached_token = None
        self._token_expires_at = None

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authorization headers with cached token"""
        now = datetime.utcnow()

        # Refresh token if expired or about to expire (5 min buffer)
        if (not self._cached_token or
            not self._token_expires_at or
            self._token_expires_at < now + timedelta(minutes=5)):

            # Generate new token (24 hour expiration)
            expires_delta = timedelta(hours=24)
            self._cached_token = self._create_jwt_token(expires_delta)
            self._token_expires_at = now + expires_delta

        return {
            "Authorization": f"Bearer {self._cached_token}",
            "Content-Type": "application/json"
        }
```

---

### Q6: What's the difference between namespace from JWT vs environment?

**A**: **Critical Security**: NEVER trust namespace from JWT claims. Always use verified namespace from environment/database.

**❌ WRONG** (Security Vulnerability):
```python
# DON'T trust JWT claims
token_payload = jwt.decode(token, verify=False)
namespace = token_payload.get("namespace")  # ❌ Can be forged!
```

**✅ CORRECT** (Secure):
```python
# DO use verified namespace from environment/database
namespace = os.getenv("TMWS_NAMESPACE")  # ✅ Verified source
# or
namespace = await get_agent_namespace_from_db(agent_id)  # ✅ Database truth
```

**Why**: JWT claims can be modified by attackers before signing. TMWS REST API validates namespace by fetching agent record from database, not from JWT claims.

---

### Q7: How do I debug REST API authentication failures?

**A**: Enable debug logging and use JWT debugging tools.

**Step 1: Enable Debug Logging**:
```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("trinitas_agents.tmws_client")
logger.setLevel(logging.DEBUG)
```

**Step 2: Decode JWT Token** (without verification):
```python
from jose import jwt

token = "eyJhbGc..."
payload = jwt.decode(token, options={"verify_signature": False})
print(f"Token claims: {payload}")

# Check expiration
from datetime import datetime
exp_time = datetime.utcfromtimestamp(payload["exp"])
print(f"Expires at: {exp_time} (in {exp_time - datetime.utcnow()})")
```

**Step 3: Test Token with cURL**:
```bash
curl -X GET http://localhost:8000/api/v1/mcp/connections/test-connection-id/tools \
  -H "Authorization: Bearer $TOKEN" \
  -v  # Verbose mode shows full request/response
```

**Step 4: Check TMWS Logs**:
```bash
# TMWS server logs show authentication failures
tail -f logs/tmws.log | grep -i "auth\|jwt\|401\|403"
```

---

### Q8: Can I connect to the same MCP server multiple times?

**A**: No, each `server_name` must be unique per agent. Use different names for multiple connections.

**❌ WRONG**:
```python
# Both connections use same server_name
await connect_to_mcp_server("playwright", "http://localhost:3000")
await connect_to_mcp_server("playwright", "http://localhost:3001")  # ❌ 409 Duplicate
```

**✅ CORRECT**:
```python
# Use different server_name for each connection
await connect_to_mcp_server("playwright-primary", "http://localhost:3000")
await connect_to_mcp_server("playwright-backup", "http://localhost:3001")
```

---

## Timeline and Support

### Implementation Timeline

**Week 1: Core Implementation** (8-12 hours)
- Day 1-2: Implement `TMWSRestClient` class (4 hours)
- Day 2-3: Implement 4 MCP tool wrappers (4 hours)
- Day 3-4: Error handling and retry logic (2 hours)
- Day 4-5: Integration testing (2 hours)

**Week 2: Testing & Documentation** (8-10 hours)
- Day 1-2: Unit tests (16 tests) (4 hours)
- Day 2-3: Integration tests (8 tests) (3 hours)
- Day 3-4: Update Agent Skills documentation (2 hours)
- Day 4-5: Deployment configuration (2 hours)

**Week 3: Production Deployment** (4-6 hours)
- Day 1: Deploy to staging environment (2 hours)
- Day 2-3: Validate with real external MCP servers (2 hours)
- Day 4: Deploy to production (1 hour)
- Day 5: Monitor and adjust (1 hour)

**Total Effort**: 20-28 hours over 3 weeks

### Milestones

| Milestone | Target Date | Deliverables |
|-----------|-------------|--------------|
| **M1: Core Implementation** | Week 1 End | `TMWSRestClient` + 4 MCP tools |
| **M2: Testing Complete** | Week 2 End | 24 tests passing, documentation updated |
| **M3: Staging Validated** | Week 3 Day 3 | Staging environment fully functional |
| **M4: Production Ready** | Week 3 Day 5 | Production deployment validated |

### Support Resources

**Documentation**:
- TMWS REST API Spec: `docs/api/MCP_CONNECTION_API.md`
- Authentication Guide: `docs/guides/AUTHENTICATION_GUIDE.md`
- Rate Limiting Guide: `docs/guides/RATE_LIMITING_GUIDE.md`
- This Integration Guide: `docs/integration/TRINITAS_AGENTS_INTEGRATION_GUIDE.md`

**Code Examples**:
- REST Client: `src/api/routers/mcp_connections.py`
- MCP Server: `src/mcp_server.py`
- Tests: `tests/integration/api/test_mcp_connection_api.py`

**Support Channels**:
- GitHub Issues: [Report bugs](https://github.com/apto-as/tmws/issues)
- Development Chat: (configure team chat here)
- Email: (configure support email here)

**Key Contacts**:
- **TMWS Maintainer**: (name/email)
- **Trinitas-agents Lead**: (name/email)
- **DevOps**: (name/email)

### Success Criteria

**Phase 1 (Week 1)**:
- [ ] `TMWSRestClient` class implemented and tested
- [ ] 4 MCP tools implemented with error handling
- [ ] Integration tests passing with mock MCP server

**Phase 2 (Week 2)**:
- [ ] 16 unit tests passing (JWT, REST client, error handling)
- [ ] 8 integration tests passing (full lifecycle)
- [ ] Agent Skills documentation updated

**Phase 3 (Week 3)**:
- [ ] Staging deployment successful
- [ ] Validated with real external MCP servers (playwright, serena, context7)
- [ ] Production deployment successful
- [ ] Zero critical issues in first 48 hours

### Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| External MCP server compatibility issues | Medium | Medium | Test with multiple MCP servers (playwright, serena, context7) |
| Rate limiting in production | Low | Medium | Implement exponential backoff, monitor usage patterns |
| Authentication failures | Low | High | Comprehensive JWT testing, clear error messages |
| Network connectivity issues | Low | Medium | Retry logic with exponential backoff |
| Namespace isolation bypass | Very Low | Critical | Security test suite (20 tests), P0-1 compliance verified |

---

## Conclusion

This guide provides everything the Trinitas-agents development team needs to successfully integrate TMWS v2.3.0 MCP Connection Management REST API.

**Key Takeaways**:
1. ✅ **Backwards Compatible**: Existing functionality unchanged
2. ✅ **Well-Tested**: 24 tests (integration + E2E) with 100% pass rate
3. ✅ **Production-Ready**: Security, rate limiting, error handling all implemented
4. ✅ **Clear Timeline**: 20-28 hours over 3 weeks with defined milestones

**Next Steps**:
1. Review this document with the team
2. Set up development environment (TMWS REST API locally)
3. Implement `TMWSRestClient` class (Week 1)
4. Implement 4 MCP tools (Week 1)
5. Test and deploy (Week 2-3)

**Questions?** Refer to the FAQ section or reach out to support channels listed above.

---

**Document Author**: Muses (Knowledge Architect)
**Last Reviewed**: 2025-11-13
**Status**: Production-ready
**Version**: 1.0
