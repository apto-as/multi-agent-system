# MCP Connection Management API Documentation

**Version**: v2.3.0
**Base URL**: `/api/v1/mcp`
**Authentication**: JWT Bearer Token (Required)
**Last Updated**: 2025-11-13

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Endpoints](#endpoints)
   - [Create Connection](#create-connection)
   - [Disconnect](#disconnect)
   - [Discover Tools](#discover-tools)
   - [Execute Tool](#execute-tool)
4. [Error Responses](#error-responses)
5. [Security Considerations](#security-considerations)
6. [Rate Limiting](#rate-limiting)

---

## Overview

The MCP Connection Management API enables agents to connect to external MCP (Model Context Protocol) servers, discover available tools, execute tools, and manage connection lifecycles. All operations enforce namespace isolation (P0-1 security standard) to ensure multi-tenant data separation.

### Key Features

- **Multi-connection management**: Agents can connect to multiple MCP servers simultaneously
- **Tool discovery**: Automatic discovery of available tools on connection
- **Secure execution**: Sandboxed tool execution with namespace isolation
- **Lifecycle management**: Complete control over connection creation and termination
- **Error recovery**: Robust error handling with detailed error codes

---

## Authentication

All endpoints require JWT Bearer token authentication.

### Request Header

```http
Authorization: Bearer <jwt_token>
```

### Token Requirements

- Token must be signed with server's secret key (HS256 algorithm)
- Token payload must include `sub` (subject) field with agent_id
- Agent must exist in database
- Token expiration is enforced

### Example Token Generation

See [Authentication Guide](../guides/AUTHENTICATION_GUIDE.md) for detailed instructions.

---

## Endpoints

### Create Connection

Establish a connection to an MCP server.

#### Request

```http
POST /api/v1/mcp/connections
Content-Type: application/json
Authorization: Bearer <jwt_token>
```

**Body:**

```json
{
  "server_name": "my-mcp-server",
  "url": "http://localhost:8080",
  "timeout": 30,
  "namespace": "my-namespace",
  "agent_id": "agent-uuid"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `server_name` | string | Yes | Unique name for this connection (per agent) |
| `url` | string (URL) | Yes | MCP server URL (http/https) |
| `timeout` | integer | Yes | Connection timeout in seconds (5-300) |
| `namespace` | string | Yes | Agent's namespace (must match JWT agent) |
| `agent_id` | string (UUID) | Yes | Agent identifier (must match JWT subject) |

#### Response

**Success (201 Created):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "server_name": "my-mcp-server",
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

**Headers:**

```http
Location: /api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000
```

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `VALIDATION_ERROR` | Invalid request parameters (e.g., malformed URL) |
| 401 | N/A | Missing or invalid JWT token |
| 403 | `AUTHORIZATION_ERROR` | Namespace mismatch or insufficient permissions |
| 409 | `DUPLICATE_CONNECTION` | Connection with same server_name already exists |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server connection failed |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure (fail-secure mode) |

#### Example

```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "context7",
    "url": "http://localhost:3000",
    "timeout": 30,
    "namespace": "my-project",
    "agent_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

---

### Disconnect

Terminate an MCP connection.

#### Request

```http
DELETE /api/v1/mcp/connections/{connection_id}
Authorization: Bearer <jwt_token>
```

**Path Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | UUID | Connection identifier |

#### Response

**Success (204 No Content):**

Empty response body.

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 401 | N/A | Missing or invalid JWT token |
| 403 | `AUTHORIZATION_ERROR` | Connection belongs to different agent/namespace |
| 404 | `CONNECTION_NOT_FOUND` | Connection does not exist |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure (fail-secure mode) |

#### Example

```bash
curl -X DELETE http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer eyJhbGc..."
```

---

### Discover Tools

List all available tools on an MCP connection.

#### Request

```http
GET /api/v1/mcp/connections/{connection_id}/tools
Authorization: Bearer <jwt_token>
```

**Path Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | UUID | Connection identifier |

#### Response

**Success (200 OK):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "server_name": "my-mcp-server",
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

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 401 | N/A | Missing or invalid JWT token |
| 403 | `AUTHORIZATION_ERROR` | Connection belongs to different agent/namespace |
| 404 | `CONNECTION_NOT_FOUND` | Connection does not exist |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server unreachable or tool discovery failed |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure (fail-secure mode) |

#### Example

```bash
curl http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools \
  -H "Authorization: Bearer eyJhbGc..."
```

---

### Execute Tool

Execute a tool on an MCP connection.

#### Request

```http
POST /api/v1/mcp/connections/{connection_id}/tools/{tool_name}/execute
Content-Type: application/json
Authorization: Bearer <jwt_token>
```

**Path Parameters:**

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | UUID | Connection identifier |
| `tool_name` | string | Name of tool to execute |

**Body:**

```json
{
  "arguments": {
    "query": "search term",
    "max_results": 10
  }
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `arguments` | object | Yes | Tool-specific arguments (schema defined by tool's `input_schema`) |

#### Response

**Success (200 OK):**

```json
{
  "connection_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_name": "search",
  "result": {
    "status": "completed",
    "result": [
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

**Note**: The `result` structure is tool-specific and defined by the MCP server.

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `TOOL_NOT_FOUND` | Tool does not exist in connection |
| 400 | `VALIDATION_ERROR` | Invalid tool arguments |
| 401 | N/A | Missing or invalid JWT token |
| 403 | `AUTHORIZATION_ERROR` | Connection belongs to different agent/namespace |
| 404 | `CONNECTION_NOT_FOUND` | Connection does not exist |
| 502 | `EXTERNAL_SERVICE_ERROR` | MCP server unreachable or tool execution failed |
| 503 | `SERVICE_UNAVAILABLE` | Rate limiter failure (fail-secure mode) |

#### Example

```bash
curl -X POST http://localhost:8000/api/v1/mcp/connections/550e8400-e29b-41d4-a716-446655440000/tools/search/execute \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "arguments": {
      "query": "artificial intelligence",
      "max_results": 5
    }
  }'
```

---

## Error Responses

All error responses follow a standardized format:

### Error Response Structure

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

### Error Codes

| Error Code | HTTP Status | Description | Retry Strategy |
|------------|-------------|-------------|----------------|
| `VALIDATION_ERROR` | 400 | Invalid request parameters | Fix input and retry |
| `AUTHORIZATION_ERROR` | 403 | Namespace mismatch or insufficient permissions | Do not retry |
| `CONNECTION_NOT_FOUND` | 404 | Connection does not exist | Do not retry |
| `DUPLICATE_CONNECTION` | 409 | Connection already exists | Use different server_name |
| `TOOL_NOT_FOUND` | 400 | Tool not available on connection | Check tool name |
| `EXTERNAL_SERVICE_ERROR` | 502 | MCP server connection/execution failed | Retry with exponential backoff |
| `SERVICE_UNAVAILABLE` | 503 | Rate limiter failure (fail-secure mode) | Wait and retry after specified time |

### Security Error Sanitization

⚠️ **Security Note**: All error responses are sanitized to prevent information leakage:
- Internal stack traces are never exposed
- Database errors are mapped to generic messages
- Sensitive configuration details are redacted

---

## Security Considerations

### P0-1 Namespace Isolation

**Critical Security Requirement**: All operations enforce namespace isolation.

#### How It Works

1. **Authentication**: JWT token is validated and agent_id is extracted
2. **Database Verification**: Agent is fetched from database to get verified namespace
3. **Authorization**: Request namespace must match agent's verified namespace
4. **Enforcement**: Repository layer filters all queries by namespace

#### Why It Matters

- **Multi-tenancy**: Multiple agents share the same database
- **Data separation**: Agent A cannot access Agent B's connections
- **Compliance**: Prevents cross-tenant data leakage (CVSS 8.7 HIGH)

#### Example Attack Prevention

```http
# Agent A creates connection
POST /api/v1/mcp/connections
Authorization: Bearer <agent_a_token>
{
  "namespace": "agent-a-namespace",
  "server_name": "server-x"
}

# Agent B tries to access Agent A's connection (BLOCKED)
GET /api/v1/mcp/connections/{connection_id_from_agent_a}/tools
Authorization: Bearer <agent_b_token>
→ 403 Forbidden (Authorization Error)
```

### JWT Token Security

- **Algorithm**: HS256 (HMAC with SHA-256)
- **Secret Key**: Must be 32+ characters, stored securely
- **Expiration**: Enforced (configurable per environment)
- **Verification**: Agent existence verified from database (not just token)

### Input Validation

- **URL Validation**: Only http/https schemes allowed
- **Timeout Bounds**: 5-300 seconds enforced
- **Server Name**: Alphanumeric + hyphens only, 1-100 chars
- **Agent ID**: Must be valid UUID format

### Tool Execution Sandboxing

- **Isolation**: Tools execute within MCP server's sandbox
- **No Direct Access**: API layer never directly executes tools
- **Timeout Enforcement**: Execution timeouts prevent resource exhaustion
- **Error Sanitization**: Tool errors sanitized before returning

---

## Rate Limiting

All endpoints have rate limits to prevent abuse. See [Rate Limiting Guide](../guides/RATE_LIMITING_GUIDE.md) for details.

### Default Limits (Production)

| Endpoint | Limit | Burst | Purpose |
|----------|-------|-------|---------|
| Create Connection | 10/min | 2 | Prevent connection pool exhaustion |
| Discover Tools | 50/min | 10 | Reduce MCP server load |
| Execute Tool | 100/min | 20 | Prevent MCP server overload |
| Disconnect | 20/min | 5 | Normal operation |

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699876543
```

### Rate Limit Exceeded Response

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30

{
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded for mcp_execute_tool",
  "retry_after": 30
}
```

---

## Testing

### Local Development

Rate limiting is disabled in test environment:

```bash
export TMWS_ENVIRONMENT=test
```

### Integration Testing

See test examples in:
- `tests/integration/api/test_mcp_connection_api.py`
- `tests/e2e/test_mcp_connection_e2e.py`

---

## Changelog

### v2.3.0 (2025-11-13)
- **Phase 1-3**: Complete MCP Connection Management API
- **Security**: P0-1 namespace isolation implemented
- **Rate Limiting**: Fail-secure rate limiting with degraded mode
- **Testing**: 20 integration tests, 4 E2E tests (100% pass rate)

---

## Support

For issues or questions:
- GitHub Issues: [Report bugs](https://github.com/apto-as/tmws/issues)
- Documentation: `docs/` directory
- Security Issues: See [Security Policy](../../SECURITY.md)

---

**Document Author**: Muses (Knowledge Architect)
**Last Reviewed**: 2025-11-13
**Status**: Production-ready
