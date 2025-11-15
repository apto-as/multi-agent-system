# TMWS REST API Guide
## MCP Connection Management for External Servers

**Version**: v2.3.0
**Target Audience**: Trinitas-agents Development Team & Web Application Developers
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Base URL**: `http://localhost:8000/api/v1/mcp` (development)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture: MCP Server vs REST API](#architecture-mcp-server-vs-rest-api)
3. [Authentication](#authentication)
4. [The 4 Endpoints](#the-4-endpoints)
5. [Complete Workflow Example](#complete-workflow-example)
6. [Security: P0-1 Namespace Isolation](#security-p0-1-namespace-isolation)
7. [Rate Limiting](#rate-limiting)
8. [Error Handling](#error-handling)
9. [Integration Examples](#integration-examples)
10. [Troubleshooting](#troubleshooting)

---

## Overview

TMWS REST API provides **MCP Connection Management** - allowing applications to:
- Connect to **external MCP servers** (like context7, serena, playwright)
- Discover available tools on those servers
- Execute tools remotely
- Manage connection lifecycle

### Key Concept

**TMWS has TWO interfaces**:

| Interface | Purpose | Used By |
|-----------|---------|---------|
| **MCP Server** | Provides 21 tools for memory/workflow | Claude Code directly |
| **REST API** | Manages connections to EXTERNAL MCP servers | Web applications, scripts |

**This guide covers**: REST API (MCP Connection Management)

**For TMWS MCP tools**: See [MCP_TOOLS_REFERENCE.md](MCP_TOOLS_REFERENCE.md)

---

## Architecture: MCP Server vs REST API

### Visual Architecture

```
┌─────────────────────────────────────────────────────┐
│                   TMWS System                        │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌───────────────────────┐  ┌──────────────────┐   │
│  │   MCP Server          │  │   REST API       │   │
│  │   (21 tools)          │  │   (4 endpoints)  │   │
│  │                       │  │                  │   │
│  │  - store_memory       │  │  - POST /connect │   │
│  │  - search_memories    │  │  - DELETE /disco │   │
│  │  - create_task        │  │  - GET /tools    │   │
│  │  - verify_and_record  │  │  - POST /execute │   │
│  │  - ... (17 more)      │  │                  │   │
│  └───────────────────────┘  └──────────────────┘   │
│           ▲                          ▲              │
│           │                          │              │
└───────────┼──────────────────────────┼──────────────┘
            │                          │
            │                          │
   ┌────────┴─────────┐       ┌───────┴────────┐
   │  Claude Code     │       │  Web App       │
   │  (Direct MCP)    │       │  (HTTP/JSON)   │
   └──────────────────┘       └────────────────┘
            │                          │
            │                          │
            ▼                          ▼
     Uses TMWS tools          Connects to external
     (memory, tasks)          MCP servers (context7,
                              serena, playwright)
```

### Example Use Cases

**MCP Server (21 tools)**:
- Claude Code stores conversation context → `store_memory`
- Claude Code searches past learnings → `search_memories`
- Claude Code creates task for Artemis → `create_task`
- Claude Code verifies Hestia's security claim → `verify_and_record`

**REST API (4 endpoints)**:
- Web app connects to context7 MCP server → `POST /connections`
- Web app discovers context7 tools → `GET /connections/{id}/tools`
- Web app executes context7's `get-library-docs` → `POST /connections/{id}/tools/{name}/execute`
- Web app disconnects when done → `DELETE /connections/{id}`

---

## Authentication

### JWT Bearer Token Required

All REST API endpoints require **JWT Bearer Token** authentication.

#### Token Structure

```json
{
  "sub": "agent-uuid",  // Agent ID (subject)
  "exp": 1731571200,    // Expiration timestamp
  "iat": 1731567600     // Issued at timestamp
}
```

**CRITICAL**: Token is signed with `TMWS_SECRET_KEY` (HS256 algorithm)

#### Generating JWT Token

**Python Example**:
```python
from jose import jwt
from datetime import datetime, timedelta
import os

# Load secret from environment
SECRET_KEY = os.getenv("TMWS_SECRET_KEY")  # Must be 32+ characters

# Create token payload
payload = {
    "sub": "550e8400-e29b-41d4-a716-446655440000",  # Agent UUID
    "exp": datetime.utcnow() + timedelta(hours=24),
    "iat": datetime.utcnow()
}

# Generate token
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
print(f"Token: {token}")
```

**JavaScript Example**:
```javascript
const jose = require('jose');

const secret = new TextEncoder().encode(process.env.TMWS_SECRET_KEY);

const token = await new jose.SignJWT({ sub: 'agent-uuid' })
  .setProtectedHeader({ alg: 'HS256' })
  .setExpirationTime('24h')
  .setIssuedAt()
  .sign(secret);

console.log(`Token: ${token}`);
```

#### Using Token in Requests

**HTTP Header**:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**cURL Example**:
```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{"server_name": "context7", ...}'
```

---

## The 4 Endpoints

### 1. Create Connection

**Endpoint**: `POST /api/v1/mcp/connections`

**Purpose**: Establish connection to an external MCP server

**Request**:
```http
POST /api/v1/mcp/connections
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "server_name": "context7",
  "url": "http://localhost:3000",
  "timeout": 30,
  "namespace": "my-project",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Parameters**:
| Field | Type | Required | Description | Constraints |
|-------|------|----------|-------------|-------------|
| `server_name` | string | Yes | Unique connection name | Alphanumeric + hyphens, 1-100 chars |
| `url` | string | Yes | MCP server URL | Valid http/https URL |
| `timeout` | integer | Yes | Connection timeout (seconds) | 5-300 |
| `namespace` | string | Yes | Agent's namespace | Must match JWT agent's namespace |
| `agent_id` | string (UUID) | Yes | Agent identifier | Must match JWT subject |

**Response** (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "server_name": "context7",
  "status": "active",
  "namespace": "my-project",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "config": {
    "url": "http://localhost:3000/",
    "timeout": 30
  },
  "tools": [
    {
      "name": "resolve-library-id",
      "description": "Resolve library name to Context7 ID",
      "input_schema": {...}
    },
    {
      "name": "get-library-docs",
      "description": "Fetch library documentation",
      "input_schema": {...}
    }
  ],
  "connected_at": "2025-11-14T10:30:00.123456Z",
  "created_at": "2025-11-14T10:30:00.123456Z",
  "updated_at": "2025-11-14T10:30:00.123456Z"
}
```

**Response Headers**:
```http
Location: /api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000
```

**Error Responses**:
| Status | Error Code | Cause | Solution |
|--------|------------|-------|----------|
| 400 | `VALIDATION_ERROR` | Invalid URL or parameters | Fix request parameters |
| 401 | N/A | Invalid JWT token | Check token signature/expiration |
| 403 | `AUTHORIZATION_ERROR` | Namespace mismatch | Ensure namespace matches agent |
| 409 | `DUPLICATE_CONNECTION` | Connection already exists | Use different `server_name` |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server unreachable | Check MCP server is running |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure | Wait and retry |

**Example**:
```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "context7",
    "url": "http://localhost:3000",
    "timeout": 30,
    "namespace": "trinitas-agents",
    "agent_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

---

### 2. Discover Tools

**Endpoint**: `GET /api/v1/mcp/connections/{connection_id}/tools`

**Purpose**: List all tools available on a connected MCP server

**Request**:
```http
GET /api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools
Authorization: Bearer <jwt_token>
```

**Response** (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "server_name": "context7",
  "status": "active",
  "namespace": "trinitas-agents",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "config": {
    "url": "http://localhost:3000/",
    "timeout": 30
  },
  "tools": [
    {
      "name": "resolve-library-id",
      "description": "Resolve library name to Context7-compatible ID",
      "input_schema": {
        "type": "object",
        "properties": {
          "libraryName": {"type": "string", "description": "Library name"}
        },
        "required": ["libraryName"]
      }
    },
    {
      "name": "get-library-docs",
      "description": "Fetch library documentation",
      "input_schema": {
        "type": "object",
        "properties": {
          "context7CompatibleLibraryID": {"type": "string"},
          "topic": {"type": "string"},
          "tokens": {"type": "number"}
        },
        "required": ["context7CompatibleLibraryID"]
      }
    }
  ],
  "connected_at": "2025-11-14T10:30:00.123456Z",
  "created_at": "2025-11-14T10:30:00.123456Z",
  "updated_at": "2025-11-14T10:30:00.123456Z"
}
```

**Error Responses**:
| Status | Error Code | Cause | Solution |
|--------|------------|-------|----------|
| 401 | N/A | Invalid JWT token | Check authentication |
| 403 | `AUTHORIZATION_ERROR` | Connection belongs to different agent/namespace | Check connection ownership |
| 404 | `CONNECTION_NOT_FOUND` | Connection does not exist | Verify connection ID |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server unreachable | Check MCP server status |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure | Wait and retry |

**Example**:
```bash
curl http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools \
  -H "Authorization: Bearer eyJhbGc..."
```

---

### 3. Execute Tool

**Endpoint**: `POST /api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute`

**Purpose**: Execute a tool on the connected MCP server

**Request**:
```http
POST /api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools/get-library-docs/execute
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "arguments": {
    "context7CompatibleLibraryID": "/vercel/next.js/v14.0.0",
    "topic": "routing",
    "tokens": 5000
  }
}
```

**Parameters**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `arguments` | object | Yes | Tool-specific arguments (schema from tool's `input_schema`) |

**Response** (200 OK):
```json
{
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_name": "get-library-docs",
  "result": {
    "status": "completed",
    "result": {
      "library": "/vercel/next.js/v14.0.0",
      "topic": "routing",
      "documentation": "# Next.js Routing\n\n## App Router\n...",
      "tokens_used": 4523
    },
    "execution_time_ms": 245
  }
}
```

**Error Responses**:
| Status | Error Code | Cause | Solution |
|--------|------------|-------|----------|
| 400 | `TOOL_NOT_FOUND` | Tool does not exist on server | Check available tools |
| 400 | `VALIDATION_ERROR` | Invalid tool arguments | Check tool's `input_schema` |
| 401 | N/A | Invalid JWT token | Check authentication |
| 403 | `AUTHORIZATION_ERROR` | Connection belongs to different agent/namespace | Check ownership |
| 404 | `CONNECTION_NOT_FOUND` | Connection does not exist | Verify connection ID |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server error or unreachable | Check MCP server logs |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure | Wait and retry |

**Example**:
```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools/get-library-docs/execute \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "arguments": {
      "context7CompatibleLibraryID": "/vercel/next.js/v14.0.0",
      "topic": "routing"
    }
  }'
```

---

### 4. Disconnect

**Endpoint**: `DELETE /api/v1/mcp/connections/{connection_id}`

**Purpose**: Terminate connection to MCP server and clean up resources

**Request**:
```http
DELETE /api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000
Authorization: Bearer <jwt_token>
```

**Response** (204 No Content):
```
(empty response body)
```

**Error Responses**:
| Status | Error Code | Cause | Solution |
|--------|------------|-------|----------|
| 401 | N/A | Invalid JWT token | Check authentication |
| 403 | `AUTHORIZATION_ERROR` | Connection belongs to different agent/namespace | Check ownership |
| 404 | `CONNECTION_NOT_FOUND` | Connection does not exist | Connection already deleted or never existed |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure | Wait and retry |

**Example**:
```bash
curl -X DELETE http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer eyJhbGc..."
```

---

## Complete Workflow Example

### Scenario: Web App Uses Context7 to Fetch Next.js Docs

**Step 1: Generate JWT Token**

```python
from jose import jwt
from datetime import datetime, timedelta
import os

SECRET_KEY = os.getenv("TMWS_SECRET_KEY")

token = jwt.encode(
    {
        "sub": "artemis-optimizer",  # Agent ID
        "exp": datetime.utcnow() + timedelta(hours=1)
    },
    SECRET_KEY,
    algorithm="HS256"
)
```

---

**Step 2: Create Connection to Context7**

```bash
connection_response=$(curl -s -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "context7",
    "url": "http://localhost:3000",
    "timeout": 30,
    "namespace": "trinitas-agents",
    "agent_id": "artemis-optimizer"
  }')

connection_id=$(echo $connection_response | jq -r '.id')
echo "Connected: $connection_id"
```

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "server_name": "context7",
  "status": "active",
  "tools": [
    {"name": "resolve-library-id", ...},
    {"name": "get-library-docs", ...}
  ]
}
```

---

**Step 3: Discover Available Tools**

```bash
tools=$(curl -s http://localhost:8000/api/v1/mcp/connections/$connection_id/tools \
  -H "Authorization: Bearer $token")

echo $tools | jq '.tools[] | {name, description}'
```

**Response**:
```json
{
  "name": "resolve-library-id",
  "description": "Resolve library name to Context7 ID"
}
{
  "name": "get-library-docs",
  "description": "Fetch library documentation"
}
```

---

**Step 4: Execute Tool - Resolve Library ID**

```bash
library_id=$(curl -s -X POST \
  http://localhost:8000/api/v1/mcp/connections/$connection_id/tools/resolve-library-id/execute \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"arguments": {"libraryName": "next.js"}}' \
  | jq -r '.result.result.id')

echo "Library ID: $library_id"
```

**Response**:
```json
{
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_name": "resolve-library-id",
  "result": {
    "status": "completed",
    "result": {
      "id": "/vercel/next.js",
      "name": "Next.js",
      "description": "React framework for production"
    }
  }
}
```

---

**Step 5: Execute Tool - Get Documentation**

```bash
docs=$(curl -s -X POST \
  http://localhost:8000/api/v1/mcp/connections/$connection_id/tools/get-library-docs/execute \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d "{
    \"arguments\": {
      \"context7CompatibleLibraryID\": \"$library_id\",
      \"topic\": \"routing\",
      \"tokens\": 5000
    }
  }")

echo $docs | jq '.result.result.documentation' | head -20
```

**Response**:
```json
{
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_name": "get-library-docs",
  "result": {
    "status": "completed",
    "result": {
      "library": "/vercel/next.js",
      "topic": "routing",
      "documentation": "# Next.js Routing\n\n## App Router (v13+)\n...",
      "tokens_used": 4523,
      "execution_time_ms": 245
    }
  }
}
```

---

**Step 6: Disconnect**

```bash
curl -X DELETE http://localhost:8000/api/v1/mcp/connections/$connection_id \
  -H "Authorization: Bearer $token"

# Response: 204 No Content (empty)
```

---

### Complete Python Script

```python
#!/usr/bin/env python3
"""Complete workflow: Connect to context7, fetch Next.js docs, disconnect"""

import os
import requests
from jose import jwt
from datetime import datetime, timedelta

# Configuration
TMWS_BASE_URL = "http://localhost:8000/api/v1/mcp"
SECRET_KEY = os.getenv("TMWS_SECRET_KEY")
AGENT_ID = "artemis-optimizer"
NAMESPACE = "trinitas-agents"

# Step 1: Generate JWT token
token = jwt.encode(
    {
        "sub": AGENT_ID,
        "exp": datetime.utcnow() + timedelta(hours=1)
    },
    SECRET_KEY,
    algorithm="HS256"
)

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# Step 2: Create connection
connection_data = {
    "server_name": "context7",
    "url": "http://localhost:3000",
    "timeout": 30,
    "namespace": NAMESPACE,
    "agent_id": AGENT_ID
}

response = requests.post(
    f"{TMWS_BASE_URL}/connections",
    json=connection_data,
    headers=headers
)
response.raise_for_status()

connection = response.json()
connection_id = connection["id"]
print(f"✅ Connected: {connection_id}")

# Step 3: Discover tools
response = requests.get(
    f"{TMWS_BASE_URL}/connections/{connection_id}/tools",
    headers=headers
)
response.raise_for_status()

tools = response.json()["tools"]
print(f"✅ Discovered {len(tools)} tools")

# Step 4: Resolve library ID
response = requests.post(
    f"{TMWS_BASE_URL}/connections/{connection_id}/tools/resolve-library-id/execute",
    json={"arguments": {"libraryName": "next.js"}},
    headers=headers
)
response.raise_for_status()

library_id = response.json()["result"]["result"]["id"]
print(f"✅ Resolved: {library_id}")

# Step 5: Get documentation
response = requests.post(
    f"{TMWS_BASE_URL}/connections/{connection_id}/tools/get-library-docs/execute",
    json={
        "arguments": {
            "context7CompatibleLibraryID": library_id,
            "topic": "routing",
            "tokens": 5000
        }
    },
    headers=headers
)
response.raise_for_status()

result = response.json()["result"]["result"]
docs = result["documentation"]
tokens_used = result["tokens_used"]

print(f"✅ Fetched documentation ({tokens_used} tokens)")
print(f"\nFirst 500 chars:\n{docs[:500]}...")

# Step 6: Disconnect
response = requests.delete(
    f"{TMWS_BASE_URL}/connections/{connection_id}",
    headers=headers
)
response.raise_for_status()

print("✅ Disconnected")
```

**Run**:
```bash
export TMWS_SECRET_KEY="your-secret-key"
python workflow_example.py
```

---

## Security: P0-1 Namespace Isolation

### Critical Security Pattern

**P0-1**: Namespace must be verified from **database**, never from JWT claims.

#### Why?

**Attack Vector**:
```python
# Attacker creates JWT with malicious namespace claim
malicious_token = jwt.encode(
    {
        "sub": "attacker-agent",
        "namespace": "victim-namespace"  # ❌ Claim victim's namespace
    },
    SECRET_KEY,
    algorithm="HS256"
)

# Without P0-1: Attacker gains access to victim's connections
# With P0-1: Namespace verified from database → 403 Forbidden
```

#### P0-1 Implementation

**Flow** (from `src/api/dependencies.py:57-127`):

```python
async def get_current_user(credentials, session) -> User:
    """Extract and verify user from JWT token
    
    Security Flow (P0-1 Compliant):
    1. Decode JWT token to get agent_id
    2. Fetch agent from database (VERIFY existence)
    3. Extract namespace from database record (NOT from JWT)
    4. Return User with verified namespace
    """
    # 1. Decode JWT
    payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
    agent_id_str = payload.get("sub")
    
    # 2. SECURITY CRITICAL: Verify agent exists in database
    agent_repo = AgentRepository(session)
    agent = await agent_repo.get_by_id(agent_id_str)
    
    if not agent:
        raise HTTPException(401, "Agent not found")
    
    # 3. Extract VERIFIED namespace from database (NOT from JWT)
    verified_namespace = agent.namespace  # ✅ Source of truth
    
    # 4. Return User with verified namespace
    return User(
        agent_id=str(agent.agent_id),
        namespace=verified_namespace,  # ✅ Database-verified
        roles=["user"]
    )
```

#### Authorization Enforcement

**All endpoints verify namespace**:

```python
@router.post("/connections")
async def create_connection(
    request: MCPConnectionRequest,
    current_user: User = Depends(get_current_user)  # ✅ P0-1 verified
):
    # Check namespace matches
    if request.namespace != current_user.namespace:
        raise HTTPException(403, "Namespace mismatch")  # ✅ Reject
    
    # Proceed with verified namespace
    connection = await use_case.execute(request, current_user.namespace)
```

#### Testing P0-1

**Test Case** (from `tests/security/test_namespace_isolation.py`):

```python
async def test_namespace_isolation():
    # Agent A creates connection
    agent_a = create_agent(namespace="namespace-a")
    connection_a = create_connection(agent_id=agent_a.id, namespace="namespace-a")
    
    # Agent B tries to access Agent A's connection
    agent_b = create_agent(namespace="namespace-b")
    token_b = create_jwt(sub=agent_b.id)
    
    # Attempt access (should fail)
    response = requests.get(
        f"/api/v1/mcp/connections/{connection_a.id}/tools",
        headers={"Authorization": f"Bearer {token_b}"}
    )
    
    # Verify 403 Forbidden
    assert response.status_code == 403
    assert response.json()["error_code"] == "AUTHORIZATION_ERROR"
```

---

## Rate Limiting

### Default Limits (Production)

| Endpoint | Limit | Burst | Purpose |
|----------|-------|-------|---------|
| Create Connection | 10/min | 2 | Prevent connection pool exhaustion |
| Discover Tools | 50/min | 10 | Reduce MCP server load |
| Execute Tool | 100/min | 20 | Prevent MCP server overload |
| Disconnect | 20/min | 5 | Normal operation |

### Rate Limit Headers

**Every response includes**:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1731571200
```

### Rate Limit Exceeded

**Response** (429 Too Many Requests):
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30

{
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded for mcp_execute_tool",
  "retry_after": 30
}
```

### Handling Rate Limits

**Python Example with Backoff**:
```python
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session_with_retry():
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=5,
        status_forcelist=[429, 503],
        allowed_methods=["GET", "POST", "DELETE"],
        backoff_factor=2  # 1s, 2s, 4s, 8s, 16s
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

# Usage
session = create_session_with_retry()
response = session.post(
    "http://localhost:8000/api/v1/mcp/connections",
    json=connection_data,
    headers=headers
)
```

---

## Error Handling

### Standardized Error Format

**All errors return**:
```json
{
  "error_code": "ERROR_TYPE",
  "message": "Human-readable error message",
  "details": {
    "field": "specific_field",
    "issue": "what went wrong"
  },
  "timestamp": "2025-11-14T10:30:00.123456Z",
  "request_id": "req-abc123"
}
```

### Complete Error Reference

| Error Code | HTTP Status | Cause | Retry Strategy |
|------------|-------------|-------|----------------|
| `VALIDATION_ERROR` | 400 | Invalid parameters | Fix input, do not retry |
| `TOOL_NOT_FOUND` | 400 | Tool doesn't exist | Check tool name, do not retry |
| `AUTHORIZATION_ERROR` | 403 | Namespace mismatch | Do not retry |
| `CONNECTION_NOT_FOUND` | 404 | Connection doesn't exist | Do not retry |
| `DUPLICATE_CONNECTION` | 409 | Connection already exists | Use different `server_name` |
| `EXTERNAL_SERVICE_ERROR` | 502 | MCP server error | Retry with exponential backoff |
| `SERVICE_UNAVAILABLE` | 503 | Rate limiter failure | Wait and retry |

### Error Handling Best Practices

**Python Example**:
```python
import requests
from requests.exceptions import HTTPError
import time

def execute_tool_with_retry(connection_id, tool_name, arguments, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.post(
                f"{TMWS_BASE_URL}/connections/{connection_id}/tools/{tool_name}/execute",
                json={"arguments": arguments},
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        
        except HTTPError as e:
            status = e.response.status_code
            error_data = e.response.json()
            error_code = error_data.get("error_code")
            
            # 400-level errors: Do not retry
            if 400 <= status < 500:
                if error_code == "TOOL_NOT_FOUND":
                    raise ValueError(f"Tool '{tool_name}' not found") from e
                elif error_code == "VALIDATION_ERROR":
                    raise ValueError(f"Invalid arguments: {error_data}") from e
                else:
                    raise
            
            # 500-level errors: Retry with backoff
            elif status >= 500:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    print(f"Server error, retrying in {wait_time}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    raise
            
            else:
                raise
```

---

## Integration Examples

### Example 1: React Web App

**Context**: React app uses TMWS to connect to context7 for library documentation

**Frontend** (React + TypeScript):
```typescript
// src/services/tmws.ts
import axios from 'axios';

const TMWS_BASE_URL = 'http://localhost:8000/api/v1/mcp';

class TMWSService {
  private token: string;
  
  constructor(token: string) {
    this.token = token;
  }
  
  private get headers() {
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  }
  
  async createConnection(config: {
    server_name: string;
    url: string;
    namespace: string;
    agent_id: string;
  }) {
    const response = await axios.post(
      `${TMWS_BASE_URL}/connections`,
      { ...config, timeout: 30 },
      { headers: this.headers }
    );
    return response.data;
  }
  
  async getTools(connectionId: string) {
    const response = await axios.get(
      `${TMWS_BASE_URL}/connections/${connectionId}/tools`,
      { headers: this.headers }
    );
    return response.data.tools;
  }
  
  async executeTool(connectionId: string, toolName: string, args: any) {
    const response = await axios.post(
      `${TMWS_BASE_URL}/connections/${connectionId}/tools/${toolName}/execute`,
      { arguments: args },
      { headers: this.headers }
    );
    return response.data.result.result;
  }
  
  async disconnect(connectionId: string) {
    await axios.delete(
      `${TMWS_BASE_URL}/connections/${connectionId}`,
      { headers: this.headers }
    );
  }
}

export default TMWSService;
```

**Component Usage**:
```tsx
// src/components/LibraryDocs.tsx
import React, { useState, useEffect } from 'react';
import TMWSService from '../services/tmws';

const LibraryDocs: React.FC = () => {
  const [docs, setDocs] = useState<string>('');
  const [loading, setLoading] = useState(false);
  
  const fetchDocs = async (libraryName: string) => {
    setLoading(true);
    
    const tmws = new TMWSService(process.env.REACT_APP_TMWS_TOKEN!);
    
    try {
      // 1. Connect to context7
      const connection = await tmws.createConnection({
        server_name: 'context7',
        url: 'http://localhost:3000',
        namespace: 'my-app',
        agent_id: 'web-app-agent'
      });
      
      // 2. Resolve library ID
      const libraryData = await tmws.executeTool(
        connection.id,
        'resolve-library-id',
        { libraryName }
      );
      
      // 3. Get documentation
      const docsData = await tmws.executeTool(
        connection.id,
        'get-library-docs',
        {
          context7CompatibleLibraryID: libraryData.id,
          topic: 'routing',
          tokens: 5000
        }
      );
      
      setDocs(docsData.documentation);
      
      // 4. Disconnect
      await tmws.disconnect(connection.id);
    } catch (error) {
      console.error('Error fetching docs:', error);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div>
      <button onClick={() => fetchDocs('next.js')}>
        Fetch Next.js Docs
      </button>
      {loading ? <p>Loading...</p> : <pre>{docs}</pre>}
    </div>
  );
};

export default LibraryDocs;
```

---

### Example 2: FastAPI Backend Integration

**Context**: FastAPI backend uses TMWS as a proxy to multiple MCP servers

**Backend** (FastAPI + Python):
```python
# app/services/mcp_proxy.py
from typing import Any
import httpx
from jose import jwt
from datetime import datetime, timedelta
import os

class MCPProxy:
    """Proxy service for managing MCP connections via TMWS"""
    
    def __init__(self):
        self.base_url = "http://localhost:8000/api/v1/mcp"
        self.secret_key = os.getenv("TMWS_SECRET_KEY")
        self.agent_id = "fastapi-backend"
        self.namespace = "production"
    
    def _generate_token(self) -> str:
        """Generate JWT token for TMWS authentication"""
        return jwt.encode(
            {
                "sub": self.agent_id,
                "exp": datetime.utcnow() + timedelta(hours=1)
            },
            self.secret_key,
            algorithm="HS256"
        )
    
    async def connect_to_server(self, server_name: str, url: str) -> dict:
        """Create connection to external MCP server"""
        token = self._generate_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/connections",
                json={
                    "server_name": server_name,
                    "url": url,
                    "timeout": 30,
                    "namespace": self.namespace,
                    "agent_id": self.agent_id
                },
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            return response.json()
    
    async def execute_tool(
        self,
        connection_id: str,
        tool_name: str,
        arguments: dict[str, Any]
    ) -> Any:
        """Execute tool on connected MCP server"""
        token = self._generate_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/connections/{connection_id}/tools/{tool_name}/execute",
                json={"arguments": arguments},
                headers={"Authorization": f"Bearer {token}"}
            )
            response.raise_for_status()
            return response.json()["result"]["result"]
    
    async def disconnect(self, connection_id: str):
        """Disconnect from MCP server"""
        token = self._generate_token()
        
        async with httpx.AsyncClient() as client:
            await client.delete(
                f"{self.base_url}/connections/{connection_id}",
                headers={"Authorization": f"Bearer {token}"}
            )

# Singleton instance
mcp_proxy = MCPProxy()
```

**FastAPI Router**:
```python
# app/routers/library_docs.py
from fastapi import APIRouter, HTTPException
from app.services.mcp_proxy import mcp_proxy

router = APIRouter(prefix="/api/library-docs", tags=["library-docs"])

@router.get("/{library_name}")
async def get_library_docs(library_name: str, topic: str = "routing"):
    """Fetch library documentation via context7 MCP server"""
    
    try:
        # 1. Connect to context7
        connection = await mcp_proxy.connect_to_server(
            server_name="context7",
            url="http://localhost:3000"
        )
        connection_id = connection["id"]
        
        # 2. Resolve library ID
        library_data = await mcp_proxy.execute_tool(
            connection_id,
            "resolve-library-id",
            {"libraryName": library_name}
        )
        
        # 3. Get documentation
        docs = await mcp_proxy.execute_tool(
            connection_id,
            "get-library-docs",
            {
                "context7CompatibleLibraryID": library_data["id"],
                "topic": topic,
                "tokens": 5000
            }
        )
        
        # 4. Disconnect
        await mcp_proxy.disconnect(connection_id)
        
        return {
            "library": library_name,
            "topic": topic,
            "documentation": docs["documentation"],
            "tokens_used": docs["tokens_used"]
        }
    
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=e.response.json()
        )
```

---

## Troubleshooting

### Common Issues

#### Issue 1: 401 Unauthorized

**Symptom**:
```json
{
  "detail": "Could not validate credentials"
}
```

**Causes**:
1. Invalid JWT token signature
2. Expired token
3. Wrong `TMWS_SECRET_KEY`

**Solution**:
```python
# Verify secret key matches
print(f"Using secret key: {os.getenv('TMWS_SECRET_KEY')[:10]}...")

# Check token expiration
import jwt
decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
print(f"Token expires: {datetime.fromtimestamp(decoded['exp'])}")
```

---

#### Issue 2: 403 Authorization Error

**Symptom**:
```json
{
  "error_code": "AUTHORIZATION_ERROR",
  "message": "Namespace mismatch"
}
```

**Cause**: Request namespace doesn't match agent's verified namespace

**Solution**:
```python
# Get agent's namespace from database
from src.infrastructure.repositories.agent_repository import AgentRepository

agent = await agent_repo.get_by_id("your-agent-id")
print(f"Agent namespace: {agent.namespace}")

# Use correct namespace in request
request_data["namespace"] = agent.namespace  # ✅ Must match
```

---

#### Issue 3: 502 External Service Error

**Symptom**:
```json
{
  "error_code": "EXTERNAL_SERVICE_ERROR",
  "message": "MCP server connection failed"
}
```

**Causes**:
1. MCP server not running
2. Wrong URL
3. Firewall blocking connection

**Solution**:
```bash
# 1. Check MCP server is running
curl http://localhost:3000/health

# 2. Test connection manually
telnet localhost 3000

# 3. Check firewall
sudo iptables -L | grep 3000  # Linux
sudo pfctl -s rules | grep 3000  # macOS
```

---

#### Issue 4: 429 Rate Limit Exceeded

**Symptom**:
```json
{
  "error_code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 30
}
```

**Solution**:
```python
import time

response = requests.post(...)
if response.status_code == 429:
    retry_after = response.json().get("retry_after", 60)
    print(f"Rate limited. Waiting {retry_after}s...")
    time.sleep(retry_after)
    response = requests.post(...)  # Retry
```

---

### Debug Checklist

Before asking for help, verify:

- [ ] JWT token is valid and not expired
- [ ] `TMWS_SECRET_KEY` environment variable is set (32+ chars)
- [ ] Agent exists in database with correct namespace
- [ ] Request namespace matches agent's namespace
- [ ] MCP server (context7, serena, etc.) is running
- [ ] MCP server URL is reachable from TMWS
- [ ] Rate limit not exceeded (check `X-RateLimit-Remaining` header)
- [ ] Firewall allows connections to both TMWS and MCP server

---

## Summary

### Key Takeaways

1. **REST API Purpose**: Manage connections to **external MCP servers** (not TMWS's own tools)

2. **4 Endpoints**:
   - `POST /connections` - Create connection
   - `GET /connections/{id}/tools` - Discover tools
   - `POST /connections/{id}/tools/{name}/execute` - Execute tool
   - `DELETE /connections/{id}` - Disconnect

3. **Security**:
   - JWT Bearer Token required
   - P0-1 namespace isolation enforced
   - Namespace verified from database (never from JWT claims)

4. **Rate Limiting**:
   - 10-100 requests/minute (endpoint-dependent)
   - Exponential backoff on 429/503 errors

5. **Workflow**:
   ```
   Generate Token → Create Connection → Discover Tools
   → Execute Tools (multiple times) → Disconnect
   ```

---

## Next Steps

1. **Setup**: [QUICK_START_GUIDE.md](QUICK_START_GUIDE.md) - Install and configure TMWS
2. **MCP Tools**: [MCP_TOOLS_REFERENCE.md](MCP_TOOLS_REFERENCE.md) - Use TMWS's 21 tools
3. **Learning Patterns**: [LEARNING_PATTERN_API.md](LEARNING_PATTERN_API.md) - Agent Skills
4. **Integration**: Try the Python/React examples above
5. **Security**: [SECURITY_GUIDE.md](SECURITY_GUIDE.md) - P0-1 compliance details

---

**Document Author**: Muses (Knowledge Architect) + Artemis (Technical Perfectionist)
**Reviewed By**: Hera, Athena
**Last Updated**: 2025-11-14
**Status**: Production-ready
**Version**: 1.0.0
