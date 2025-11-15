# Application Service Layer - Use Cases

**TMWS Phase 1-2**: MCP Connection Management
**Architecture**: Domain-Driven Design (DDD)
**Last Updated**: 2025-11-12

---

## Table of Contents

1. [Overview](#overview)
2. [Use Case Pattern in DDD](#use-case-pattern-in-ddd)
3. [Security Patterns](#security-patterns)
4. [Use Case Catalog](#use-case-catalog)
   - [ConnectMCPServerUseCase](#1-connectmcpserverusecase)
   - [DisconnectMCPServerUseCase](#2-disconnectmcpserverusecase)
   - [DiscoverToolsUseCase](#3-discovertoolsusecase)
   - [ExecuteToolUseCase](#4-executetoolsusecase)
5. [Common Patterns](#common-patterns)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Overview

The Application Service Layer implements the **Use Case pattern** from Domain-Driven Design (DDD). Each use case represents a single business operation that coordinates domain aggregates, repositories, and external adapters to fulfill a specific user goal.

**Purpose**:
- Orchestrate domain logic without containing business rules
- Manage transactions and persistence
- Coordinate between domain and infrastructure layers
- Dispatch domain events after successful commit

**Key Responsibilities**:
1. Input validation (via Request DTOs)
2. Namespace verification (SECURITY CRITICAL)
3. Authorization checks
4. Transaction management
5. Domain aggregate coordination
6. External service integration
7. Event dispatching (after commit)
8. Response DTO creation

---

## Use Case Pattern in DDD

### Flow Diagram

```
┌──────────────┐
│ Presentation │ (FastAPI Router)
│    Layer     │
└──────┬───────┘
       │ CreateConnectionRequest (DTO)
       ↓
┌──────────────────────────────────────────┐
│     Application Layer (Use Case)         │
│                                          │
│  1. Validate Input                       │
│  2. Verify Namespace (from DB) 🔒        │
│  3. Check Authorization       🔒         │
│  4. BEGIN TRANSACTION                    │
│  5. Execute Domain Logic                 │
│  6. Call External Services               │
│  7. Update Aggregate State               │
│  8. COMMIT TRANSACTION                   │
│  9. Dispatch Events (after commit)       │
│ 10. Return Response DTO                  │
└──────┬───────────────────────────────────┘
       │
       ├─→ Domain Layer (Aggregates, Entities, VOs)
       ├─→ Infrastructure Layer (Repositories, Adapters)
       └─→ Event Dispatcher (After commit)
```

### Transaction Boundaries

**CRITICAL RULE**: Domain events must be dispatched **AFTER** successful commit.

```python
async with self._uow:  # BEGIN TRANSACTION
    # Create/modify aggregate
    connection = MCPConnection(...)

    # Persist changes
    await self._repository.add(connection)

    # Commit transaction
    await self._uow.commit()  # ← Transaction ends here

# Events dispatched AFTER successful commit
await self._event_dispatcher.dispatch_all(
    connection.domain_events
)  # ✅ CORRECT
```

**Why?**
- Events represent **facts** that already happened
- If commit fails, the state change never happened → no event
- Event handlers may fail without affecting main transaction

---

## Security Patterns

### P0-1: Namespace Verification from Database

**CRITICAL**: All use cases MUST verify namespace from database, NEVER from user input (JWT claims, request body).

#### The Threat

```python
# ❌ VULNERABILITY: Trusting user input
namespace = request.namespace  # From JWT or request body
connection = await repository.get_by_id(id, namespace)  # Attacker controls namespace!
```

**Attack Scenario**:
1. Attacker has valid JWT for namespace "attacker-ns"
2. Attacker modifies JWT claims to "victim-ns"
3. Backend trusts JWT → grants access to victim's data

#### The Solution (P0-1 Pattern)

```python
# ✅ SECURE: Verify from database
# [1] Fetch agent from database (source of truth)
agent = await self._agent_repository.get_by_id(request.agent_id)
if not agent:
    raise AuthorizationError("Agent not found")

# [2] Extract verified namespace
verified_namespace = agent.namespace  # ✅ From DB, not user input

# [3] Verify claimed namespace matches database
if request.namespace != verified_namespace:
    logger.warning(
        f"Namespace mismatch for agent {request.agent_id}: "
        f"claimed={request.namespace}, actual={verified_namespace}"
    )
    raise AuthorizationError("Namespace verification failed")

# [4] Use verified namespace for all operations
connection = await self._repository.get_by_id(
    id, verified_namespace  # ✅ Verified from DB
)
```

**Implementation Files**:
- All 4 use cases implement `_verify_namespace()` method
- Line 82-91 in `connect_mcp_server_use_case.py`
- Lines 95-132 in other use cases (shared implementation pattern)

---

## Use Case Catalog

### 1. ConnectMCPServerUseCase

**Purpose**: Establish connection to MCP server and discover available tools.

**File**: `src/application/use_cases/connect_mcp_server_use_case.py` (150 lines)

**Responsibility**:
- Create new MCP connection aggregate
- Connect to external MCP server
- Discover tools from server
- Persist connection in ACTIVE state
- Dispatch MCPConnectedEvent

---

#### Input (CreateConnectionRequest)

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `server_name` | `str` | ✅ | 1-100 chars, alphanumeric/-/_ | MCP server identifier |
| `url` | `HttpUrl` | ✅ | Valid HTTP/HTTPS URL | Server endpoint |
| `namespace` | `str` | ✅ | 1-255 chars | Isolation namespace (SECURITY) |
| `agent_id` | `UUID` | ✅ | Valid UUID | Agent identifier |
| `timeout` | `int` | ❌ (default: 30) | 1-300 seconds | Connection timeout |
| `retry_attempts` | `int` | ❌ (default: 3) | 0-10 | Number of retries |
| `auth_required` | `bool` | ❌ (default: False) | - | Whether auth needed |
| `api_key` | `str` | ❌ (conditional) | Required if `auth_required=True` | API key for auth |

**Validation Rules** (Pydantic, lines 41-55 in `request_dtos.py`):
```python
@field_validator("server_name")
def validate_server_name(cls, v):
    if not v.replace("-", "").replace("_", "").isalnum():
        raise ValueError(
            "Server name must contain only alphanumeric, hyphen, or underscore"
        )
    return v

@field_validator("api_key")
def validate_api_key(cls, v, info):
    if info.data.get("auth_required") and not v:
        raise ValueError("API key required when auth_required is True")
    return v
```

---

#### Output (MCPConnectionDTO)

| Field | Type | Description |
|-------|------|-------------|
| `id` | `UUID` | Connection unique identifier |
| `server_name` | `str` | Server name |
| `url` | `str` | Server URL |
| `namespace` | `str` | Isolation namespace |
| `agent_id` | `UUID` | Owner agent ID |
| `status` | `str` | Connection status ("ACTIVE", "DISCONNECTED", "ERROR") |
| `tools` | `list[ToolDTO]` | Available tools |
| `created_at` | `datetime` | Creation timestamp |
| `connected_at` | `datetime` | Connection timestamp |
| `disconnected_at` | `datetime?` | Disconnection timestamp (nullable) |
| `error_message` | `str?` | Error message if status=ERROR (nullable) |

---

#### Business Rules

1. **Namespace Verification** (SECURITY CRITICAL)
   - Namespace MUST be verified from database (line 83)
   - Claimed namespace MUST match verified namespace (line 90)
   - Failure → `AuthorizationError` (403 Forbidden)

2. **No Duplicate Connections**
   - Only one connection per (server_name, namespace) pair (lines 93-100)
   - Duplicate → `ValidationError` (400 Bad Request)

3. **External Connection Required**
   - Must successfully connect to MCP server (line 119)
   - Must discover tools (line 125)
   - Failure → `ExternalServiceError` (502 Bad Gateway)

4. **Atomic State Change**
   - Connection persisted in DISCONNECTED state first (line 115)
   - Updated to ACTIVE only after successful external connection (line 128)
   - Partial state is persisted to enable debugging

---

#### Security Patterns

```python
# [1] Input validation (lines 68-80)
server_name = ServerName(request.server_name)  # Value Object validation
server_url = ServerURL(str(request.url))       # Value Object validation
config = ConnectionConfig(...)                  # Aggregate validation

# [2] Namespace verification from DB (lines 82-91) - SECURITY CRITICAL
agent = await self._agent_repository.get_by_id(request.agent_id)
if not agent:
    raise AuthorizationError("Agent not found")

verified_namespace = agent.namespace  # ✅ From DB, not from request

# [3] Authorization check
if request.namespace != verified_namespace:
    raise AuthorizationError("Namespace mismatch")

# [4] Repository namespace filtering (line 94)
existing = await self._repository.get_by_server_name_and_namespace(
    request.server_name,
    verified_namespace  # ✅ Repository filters by verified namespace
)
```

---

#### Transaction Flow (14 Steps)

```python
# [1] Input validation (lines 68-80)
try:
    server_name = ServerName(request.server_name)
    server_url = ServerURL(str(request.url))
    config = ConnectionConfig(...)
except ValueError as e:
    raise ValidationError(f"Invalid input: {e}") from e

# [2] Namespace verification from DB (line 83) 🔒
agent = await self._agent_repository.get_by_id(request.agent_id)
if not agent:
    raise AuthorizationError("Agent not found")

# [3] Extract verified namespace (line 87) 🔒
verified_namespace = agent.namespace  # ✅ From DB

# [4] Authorization check (line 90) 🔒
if request.namespace != verified_namespace:
    raise AuthorizationError("Namespace mismatch")

# [5] Check for duplicates (lines 93-100)
existing = await self._repository.get_by_server_name_and_namespace(
    request.server_name, verified_namespace
)
if existing:
    raise ValidationError(f"Connection to {request.server_name} already exists")

# [6] BEGIN TRANSACTION (line 102)
async with self._uow:
    # [7] Create aggregate (lines 106-112)
    connection = MCPConnection(
        id=uuid4(),
        server_name=config.server_name,
        config=config,
        namespace=verified_namespace,  # ✅ Verified
        agent_id=str(request.agent_id),
    )

    # [8] Persist aggregate (line 115)
    await self._repository.add(connection)

    # [9] Attempt external connection (lines 119-123)
    try:
        await self._adapter.connect(
            connection_id=connection.id,
            url=str(connection.config.url),
            config=config,
        )

        # [10] Discover tools (line 125)
        tools = await self._adapter.discover_tools(connection.id)

        # [11] Update aggregate state to ACTIVE (line 128)
        connection.mark_as_active(tools)

    except MCPConnectionError as e:
        # [12] Handle external failure (lines 130-138)
        connection.mark_as_error(str(e))
        await self._repository.update(connection)
        await self._uow.commit()
        raise ExternalServiceError(f"Failed to connect: {e}") from e

    # [13] Persist updated state (line 141)
    await self._repository.update(connection)

    # [14] COMMIT TRANSACTION (line 144)
    await self._uow.commit()

# END TRANSACTION - State is now persisted

# [15] Dispatch events AFTER commit (line 147)
await self._event_dispatcher.dispatch_all(connection.domain_events)

# [16] Return DTO (line 150)
return MCPConnectionDTO.from_aggregate(connection)
```

---

#### Code Example (Complete Implementation)

```python
from src.application.use_cases.connect_mcp_server_use_case import ConnectMCPServerUseCase
from src.application.dtos.request_dtos import CreateConnectionRequest
from pydantic import HttpUrl
from uuid import UUID

# Initialize dependencies (in production, use DI container)
use_case = ConnectMCPServerUseCase(
    repository=mcp_connection_repository,
    adapter=mcp_client_adapter,
    agent_repository=agent_repository,
    uow=unit_of_work,
    event_dispatcher=event_dispatcher,
)

# Create request DTO
request = CreateConnectionRequest(
    server_name="my-mcp-server",
    url=HttpUrl("https://api.example.com/mcp"),
    namespace="engineering-team",
    agent_id=UUID("12345678-1234-1234-1234-123456789abc"),
    timeout=60,
    retry_attempts=5,
    auth_required=True,
    api_key="secret-api-key-xyz",
)

# Execute use case
try:
    result = await use_case.execute(request)
    print(f"✅ Connected to {result.server_name}")
    print(f"   Status: {result.status}")
    print(f"   Tools: {len(result.tools)}")
    for tool in result.tools:
        print(f"   - {tool.name}: {tool.description}")
except ValidationError as e:
    print(f"❌ Validation error: {e.message}")
except AuthorizationError as e:
    print(f"🔒 Authorization error: {e.message}")
except ExternalServiceError as e:
    print(f"🌐 External service error: {e.message}")
```

---

#### Usage Example (FastAPI Router)

```python
from fastapi import APIRouter, Depends, HTTPException, status
from src.application.dtos.request_dtos import CreateConnectionRequest
from src.application.dtos.response_dtos import MCPConnectionDTO
from src.application.use_cases.connect_mcp_server_use_case import ConnectMCPServerUseCase
from src.api.dependencies import (
    get_connect_use_case,
    get_current_user,
)

router = APIRouter(prefix="/api/v1/connections", tags=["MCP Connections"])

@router.post(
    "/",
    response_model=MCPConnectionDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Create MCP connection",
    description="Establish connection to MCP server and discover tools",
)
async def create_connection(
    request: CreateConnectionRequest,
    use_case: ConnectMCPServerUseCase = Depends(get_connect_use_case),
    user: User = Depends(get_current_user),
) -> dict:
    """
    Create new MCP connection.

    Security:
    - Requires authentication (JWT token)
    - Namespace is verified from database
    - User must own the agent_id

    Returns:
    - 201: Connection created successfully
    - 400: Validation error (duplicate connection, invalid input)
    - 403: Authorization error (namespace mismatch)
    - 502: External service error (MCP server unreachable)
    """
    try:
        result = await use_case.execute(request)
        return result.to_dict()

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": e.error_code, "message": e.message},
        )

    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": e.error_code, "message": e.message},
        )

    except ExternalServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": e.error_code, "message": e.message},
        )
```

---

#### Error Scenarios

| Scenario | Exception | HTTP Status | Resolution |
|----------|-----------|-------------|------------|
| Invalid server name format | `ValidationError` | 400 | Use alphanumeric/-/_ only |
| Invalid URL format | `ValidationError` | 400 | Provide valid HTTP/HTTPS URL |
| Namespace mismatch (P0-1) | `AuthorizationError` | 403 | Namespace verification failed (security) |
| Agent not found | `AuthorizationError` | 403 | Agent ID does not exist |
| Duplicate connection | `ValidationError` | 400 | Connection already exists, use existing one |
| MCP server unreachable | `ExternalServiceError` | 502 | Check server URL, network, firewall |
| MCP authentication failure | `ExternalServiceError` | 502 | Verify API key is correct |
| Tool discovery failure | `ExternalServiceError` | 502 | MCP server may not support tool listing |

---

#### Domain Events Dispatched

**MCPConnectedEvent** (dispatched on success, line 147)

```python
@dataclass(frozen=True)
class MCPConnectedEvent(DomainEvent):
    connection_id: UUID
    server_name: str
    namespace: str
    tools: list[dict]
    url: str
    agent_id: str
    tool_count: int
```

**When Dispatched**:
- After successful transaction commit (line 147)
- After external connection is established
- After tools are discovered

**Use Cases**:
- Send notification to agent
- Update monitoring dashboard
- Trigger webhook
- Record audit log
- Update tool registry

---

### 2. DisconnectMCPServerUseCase

**Purpose**: Gracefully disconnect from MCP server and mark connection as inactive.

**File**: `src/application/use_cases/disconnect_mcp_server_use_case.py` (132 lines)

**Responsibility**:
- Disconnect from external MCP server
- Update aggregate to DISCONNECTED state
- Persist state change
- Dispatch MCPDisconnectedEvent

---

#### Input (DisconnectRequest)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connection_id` | `UUID` | ✅ | Connection to disconnect |
| `namespace` | `str` | ✅ | Namespace for authorization (SECURITY) |
| `agent_id` | `UUID` | ✅ | Agent making request |

---

#### Output (DisconnectionResultDTO)

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | `UUID` | Disconnected connection ID |
| `server_name` | `str` | Server name |
| `disconnected_at` | `datetime` | Timestamp of disconnection |

---

#### Business Rules

1. **Namespace Verification** (SECURITY CRITICAL)
   - Namespace MUST be verified from database (line 55)
   - Implemented via `_verify_namespace()` helper (lines 95-132)

2. **Connection Ownership**
   - Connection MUST exist in verified namespace (line 60)
   - Non-existent → `AggregateNotFoundError` (404 Not Found)

3. **Graceful Degradation**
   - External disconnect failure does NOT fail entire operation (lines 69-73)
   - Internal state is updated even if external service fails
   - Failure is logged but not raised

---

#### Security Patterns

```python
# [1] Namespace verification (lines 54-57)
verified_namespace = await self._verify_namespace(
    request.agent_id,
    request.namespace
)

# [2] Retrieve with verified namespace (lines 60-66)
connection = await self._repository.get_by_id(
    request.connection_id,
    verified_namespace  # ✅ Verified
)
if not connection:
    raise AggregateNotFoundError("MCPConnection", str(request.connection_id))

# [3] _verify_namespace implementation (lines 95-132)
async def _verify_namespace(self, agent_id, claimed_namespace: str) -> str:
    # [a] Fetch from database
    agent = await self._agent_repository.get_by_id(agent_id)
    if not agent:
        raise AuthorizationError(f"Agent {agent_id} not found")

    # [b] Verify namespace
    verified_namespace = agent.namespace
    if claimed_namespace != verified_namespace:
        logger.warning(
            f"Namespace mismatch for agent {agent_id}: "
            f"claimed={claimed_namespace}, actual={verified_namespace}"
        )
        raise AuthorizationError("Namespace verification failed (access denied)")

    # [c] Return verified value
    return verified_namespace
```

---

#### Transaction Flow (10 Steps)

```python
# [1-2] Namespace verification (line 55)
verified_namespace = await self._verify_namespace(
    request.agent_id, request.namespace
)

# [3] Retrieve connection (line 60)
connection = await self._repository.get_by_id(
    request.connection_id, verified_namespace
)
if not connection:
    raise AggregateNotFoundError("MCPConnection", str(request.connection_id))

# [4] Disconnect from external server (lines 69-73)
try:
    await self._adapter.disconnect(connection.id)
except MCPConnectionError as e:
    # Graceful degradation: log but don't fail
    logger.warning(f"Failed to disconnect from MCP server: {e}")

# [5] BEGIN TRANSACTION (line 75)
async with self._uow:
    # [6] Update aggregate (line 77)
    connection.mark_as_disconnected()

    # [7] Persist (line 80)
    await self._repository.update(connection)

    # [8] COMMIT (line 83)
    await self._uow.commit()

# END TRANSACTION

# [9] Dispatch events AFTER commit (line 86)
await self._event_dispatcher.dispatch_all(connection.domain_events)

# [10] Return result (line 89)
return DisconnectionResultDTO(
    connection_id=connection.id,
    server_name=str(connection.server_name),
    disconnected_at=connection.disconnected_at,
)
```

---

#### Graceful Degradation Pattern

**Philosophy**: External service failure should NOT prevent internal state cleanup.

```python
# [1] Attempt external disconnect (lines 69-73)
try:
    await self._adapter.disconnect(connection.id)
except MCPConnectionError as e:
    # [2] Log failure (line 73)
    logger.warning(f"Failed to disconnect from MCP server: {e}")
    # [3] DO NOT raise - continue with internal cleanup

# [4] Internal state is updated regardless (line 77)
async with self._uow:
    connection.mark_as_disconnected()  # ✅ Always executed
    await self._repository.update(connection)
    await self._uow.commit()
```

**Rationale**:
- MCP server may already be down
- Network may be unavailable
- Internal state must reflect reality (disconnected)
- User should not be blocked by external failures

---

#### Code Example

```python
from src.application.use_cases.disconnect_mcp_server_use_case import DisconnectMCPServerUseCase
from src.application.dtos.request_dtos import DisconnectRequest
from uuid import UUID

# Initialize use case
use_case = DisconnectMCPServerUseCase(
    repository=mcp_connection_repository,
    adapter=mcp_client_adapter,
    agent_repository=agent_repository,
    uow=unit_of_work,
    event_dispatcher=event_dispatcher,
)

# Create request
request = DisconnectRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)

# Execute use case
try:
    result = await use_case.execute(request)
    print(f"✅ Disconnected from {result.server_name}")
    print(f"   Disconnected at: {result.disconnected_at}")
except AuthorizationError as e:
    print(f"🔒 Authorization error: {e.message}")
except AggregateNotFoundError as e:
    print(f"❌ Connection not found: {e}")
```

---

#### Domain Events Dispatched

**MCPDisconnectedEvent** (dispatched on success, line 86)

```python
@dataclass(frozen=True)
class MCPDisconnectedEvent(DomainEvent):
    connection_id: UUID
    server_name: str
    namespace: str
    reason: str | None
    was_graceful: bool
```

---

### 3. DiscoverToolsUseCase

**Purpose**: Discover or refresh tools from active MCP connection.

**File**: `src/application/use_cases/discover_tools_use_case.py` (141 lines)

**Responsibility**:
- Retrieve active connection
- Discover tools from MCP server
- Update connection with new tools
- Dispatch ToolsDiscoveredEvent

---

#### Input (DiscoverToolsRequest)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connection_id` | `UUID` | ✅ | Connection ID |
| `namespace` | `str` | ✅ | Namespace (SECURITY) |
| `agent_id` | `UUID` | ✅ | Agent ID |

---

#### Output (MCPConnectionDTO)

Full connection details including updated tools list.

---

#### Business Rules

1. **Namespace Verification** (SECURITY CRITICAL)
   - Lines 62-65: `_verify_namespace()` helper

2. **Connection Ownership**
   - Connection MUST exist in verified namespace (line 68)

3. **Connection MUST be ACTIVE**
   - Status must be `ConnectionStatus.ACTIVE` (line 77)
   - Non-active → `ValidationError` (400 Bad Request)

4. **Tool Discovery Required**
   - Must successfully discover tools from MCP server (line 84)
   - Failure → `ExternalServiceError` (502 Bad Gateway)

---

#### Transaction Flow (11 Steps)

```python
# [1-2] Namespace verification (line 63)
verified_namespace = await self._verify_namespace(
    request.agent_id, request.namespace
)

# [3] Retrieve connection (line 68)
connection = await self._repository.get_by_id(
    request.connection_id, verified_namespace
)
if not connection:
    raise AggregateNotFoundError("MCPConnection", str(request.connection_id))

# [4] Verify active (line 77)
if connection.status != ConnectionStatus.ACTIVE:
    raise ValidationError(
        f"Connection is not active (status: {connection.status.value})"
    )

# [5] Discover tools (line 84)
try:
    tools = await self._adapter.discover_tools(connection.id)
except MCPConnectionError as e:
    raise ExternalServiceError(f"Failed to discover tools: {e}") from e

# [6] BEGIN TRANSACTION (line 88)
async with self._uow:
    # [7] Update connection (line 90)
    connection.update_tools(tools)

    # [8] Persist (line 93)
    await self._repository.update(connection)

    # [9] COMMIT (line 96)
    await self._uow.commit()

# [10] Dispatch events (line 99)
await self._event_dispatcher.dispatch_all(connection.domain_events)

# [11] Return DTO (line 102)
return MCPConnectionDTO.from_aggregate(connection)
```

---

#### Code Example

```python
from src.application.use_cases.discover_tools_use_case import DiscoverToolsUseCase
from src.application.dtos.request_dtos import DiscoverToolsRequest

# Initialize use case
use_case = DiscoverToolsUseCase(
    repository=mcp_connection_repository,
    adapter=mcp_client_adapter,
    agent_repository=agent_repository,
    uow=unit_of_work,
    event_dispatcher=event_dispatcher,
)

# Create request
request = DiscoverToolsRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)

# Execute use case
try:
    result = await use_case.execute(request)
    print(f"✅ Discovered {len(result.tools)} tools from {result.server_name}")
    for tool in result.tools:
        print(f"   - {tool.name}: {tool.description}")
except ValidationError as e:
    print(f"❌ Validation error: {e.message}")
    # Connection may not be ACTIVE
except ExternalServiceError as e:
    print(f"🌐 External service error: {e.message}")
    # MCP server may be unreachable
```

---

#### Domain Events Dispatched

**ToolsDiscoveredEvent** (dispatched on success, line 99)

```python
@dataclass(frozen=True)
class ToolsDiscoveredEvent(DomainEvent):
    connection_id: UUID
    tools: list[dict]
    server_name: str
```

---

### 4. ExecuteToolUseCase

**Purpose**: Execute tool via active MCP connection (READ-ONLY operation).

**File**: `src/application/use_cases/execute_tool_use_case.py` (135 lines)

**Responsibility**:
- Retrieve active connection
- Verify tool exists
- Execute tool via adapter
- Return execution result

**Note**: This is a READ-ONLY operation - no state change in aggregate, no transaction, no events.

---

#### Input (ExecuteToolRequest)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connection_id` | `UUID` | ✅ | Connection ID |
| `tool_name` | `str` | ✅ | Tool to execute (1-100 chars) |
| `arguments` | `dict` | ❌ (default: {}) | Tool-specific arguments |
| `namespace` | `str` | ✅ | Namespace (SECURITY) |
| `agent_id` | `UUID` | ✅ | Agent ID |

---

#### Output (ToolExecutionResultDTO)

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | `UUID` | Connection ID |
| `tool_name` | `str` | Executed tool name |
| `result` | `dict` | Tool execution result |

---

#### Business Rules

1. **Namespace Verification** (SECURITY CRITICAL)
   - Lines 52-55: `_verify_namespace()` helper

2. **Connection Ownership**
   - Connection MUST exist in verified namespace (line 58)

3. **Connection MUST be ACTIVE**
   - Status must be `ConnectionStatus.ACTIVE` (line 67)

4. **Tool MUST Exist**
   - Tool must be in connection's tool list (line 73)
   - Non-existent → `ValidationError` (400 Bad Request)

5. **External Execution**
   - Tool execution is delegated to adapter (line 81)
   - Failure → `ExternalServiceError` (502 Bad Gateway)

---

#### Transaction Flow (7 Steps - NO TRANSACTION)

```python
# [1-2] Namespace verification (line 53)
verified_namespace = await self._verify_namespace(
    request.agent_id, request.namespace
)

# [3] Retrieve connection (line 58)
connection = await self._repository.get_by_id(
    request.connection_id, verified_namespace
)
if not connection:
    raise AggregateNotFoundError("MCPConnection", str(request.connection_id))

# [4] Verify active (line 67)
if connection.status != ConnectionStatus.ACTIVE:
    raise ValidationError(
        f"Connection is not active (status: {connection.status.value})"
    )

# [5] Verify tool exists (line 73)
tool = connection.get_tool_by_name(request.tool_name)
if not tool:
    raise ValidationError(
        f"Tool '{request.tool_name}' not found in connection"
    )

# [6] Execute tool (line 81)
try:
    result = await self._adapter.execute_tool(
        connection_id=connection.id,
        tool_name=request.tool_name,
        arguments=request.arguments,
    )
except MCPToolExecutionError as e:
    raise ExternalServiceError(f"Tool execution failed: {e}") from e

# [7] Return result (line 90)
return ToolExecutionResultDTO(
    connection_id=connection.id,
    tool_name=request.tool_name,
    result=result,
)
```

**Key Difference**: No `async with self._uow` block - this is a READ-ONLY operation.

---

#### Code Example

```python
from src.application.use_cases.execute_tool_use_case import ExecuteToolUseCase
from src.application.dtos.request_dtos import ExecuteToolRequest

# Initialize use case
use_case = ExecuteToolUseCase(
    repository=mcp_connection_repository,
    adapter=mcp_client_adapter,
    agent_repository=agent_repository,
    # NO uow, NO event_dispatcher - READ-ONLY
)

# Create request
request = ExecuteToolRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    tool_name="list_files",
    arguments={"path": "/home/user", "recursive": False},
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)

# Execute use case
try:
    result = await use_case.execute(request)
    print(f"✅ Tool '{result.tool_name}' executed successfully")
    print(f"   Result: {result.result}")
except ValidationError as e:
    print(f"❌ Validation error: {e.message}")
    # Tool may not exist or connection not ACTIVE
except ExternalServiceError as e:
    print(f"🌐 Tool execution failed: {e.message}")
```

---

#### Domain Events Dispatched

**NONE** - This is a READ-ONLY operation. No state change → no events.

---

## Common Patterns

### 1. Namespace Verification Helper

All use cases (except ConnectMCPServerUseCase which inlines it) share the same `_verify_namespace()` implementation:

```python
async def _verify_namespace(self, agent_id, claimed_namespace: str) -> str:
    """
    Verify namespace from database (SECURITY CRITICAL)

    Args:
        agent_id: Agent making the request
        claimed_namespace: Namespace from request DTO

    Returns:
        Verified namespace from database

    Raises:
        AuthorizationError: If namespace mismatch (possible attack)
    """
    # [1] Fetch agent from database (NEVER from JWT claims)
    agent = await self._agent_repository.get_by_id(agent_id)

    if not agent:
        raise AuthorizationError(f"Agent {agent_id} not found")

    # [2] Verify namespace matches database
    verified_namespace = agent.namespace

    if claimed_namespace != verified_namespace:
        # Log potential attack attempt
        logger.warning(
            f"Namespace mismatch for agent {agent_id}: "
            f"claimed={claimed_namespace}, actual={verified_namespace}"
        )

        raise AuthorizationError(
            "Namespace verification failed (access denied)"
        )

    # [3] Return verified namespace
    return verified_namespace
```

**Location**:
- Lines 95-132 in `disconnect_mcp_server_use_case.py`
- Lines 104-141 in `discover_tools_use_case.py`
- Lines 96-133 in `execute_tool_use_case.py`

---

### 2. Repository Namespace Filtering

All repository methods accept `namespace` parameter and filter by it:

```python
# Repository interface (domain layer)
class MCPConnectionRepository(ABC):
    @abstractmethod
    async def get_by_id(
        self,
        connection_id: UUID,
        namespace: str  # ✅ Namespace filter
    ) -> MCPConnection | None:
        pass

# Repository implementation (infrastructure layer)
class SQLAlchemyMCPConnectionRepository(MCPConnectionRepository):
    async def get_by_id(
        self,
        connection_id: UUID,
        namespace: str
    ) -> MCPConnection | None:
        result = await self._session.execute(
            select(MCPConnection)
            .where(
                MCPConnection.id == connection_id,
                MCPConnection.namespace == namespace  # ✅ Namespace filter in SQL
            )
        )
        return result.scalar_one_or_none()
```

**Security**: Even if namespace verification is bypassed, repository provides defense-in-depth.

---

### 3. Exception Translation

Use cases catch infrastructure exceptions and translate to application exceptions:

```python
# Domain/Infrastructure exceptions → Application exceptions
try:
    tools = await self._adapter.discover_tools(connection.id)
except MCPConnectionError as e:  # Infrastructure exception
    raise ExternalServiceError(  # Application exception
        f"Failed to discover tools: {e}"
    ) from e
```

**Layers**:
- **Infrastructure**: `MCPConnectionError`, `MCPToolExecutionError`
- **Application**: `ExternalServiceError`, `ValidationError`, `AuthorizationError`
- **Presentation**: HTTP status codes (400, 403, 502)

---

### 4. Event Dispatching After Commit

**CRITICAL**: Events must be dispatched AFTER successful commit.

```python
async with self._uow:
    # ... domain logic ...
    await self._uow.commit()  # ← Transaction ends here

# Events dispatched AFTER commit
await self._event_dispatcher.dispatch_all(
    aggregate.domain_events
)  # ✅ CORRECT
```

**Incorrect Pattern**:
```python
async with self._uow:
    # ... domain logic ...

    # ❌ WRONG: Events dispatched INSIDE transaction
    await self._event_dispatcher.dispatch_all(aggregate.domain_events)

    await self._uow.commit()
```

**Why?**:
- Events represent **facts** that already happened
- If commit fails, the fact never happened → no event
- Event handlers may fail without affecting main transaction

---

## Best Practices

### ✅ DO

1. **Always verify namespace from database**
   ```python
   agent = await self._agent_repository.get_by_id(agent_id)
   verified_namespace = agent.namespace  # ✅ From DB
   ```

2. **Use verified namespace in all operations**
   ```python
   connection = await self._repository.get_by_id(id, verified_namespace)
   ```

3. **Dispatch events after commit**
   ```python
   await self._uow.commit()
   await self._event_dispatcher.dispatch_all(events)
   ```

4. **Translate infrastructure exceptions**
   ```python
   try:
       result = await adapter.execute()
   except AdapterError as e:
       raise ExternalServiceError(...) from e
   ```

5. **Use Request DTOs for validation**
   ```python
   request = CreateConnectionRequest(...)  # Pydantic validation
   ```

6. **Return Response DTOs**
   ```python
   return MCPConnectionDTO.from_aggregate(connection)
   ```

---

### ❌ DON'T

1. **Never trust user-provided namespace**
   ```python
   namespace = request.namespace  # ❌ From user input
   connection = await repository.get_by_id(id, namespace)  # ❌ SECURITY RISK
   ```

2. **Never dispatch events before commit**
   ```python
   async with self._uow:
       await self._event_dispatcher.dispatch_all(events)  # ❌ WRONG
       await self._uow.commit()
   ```

3. **Never expose infrastructure exceptions**
   ```python
   # ❌ WRONG
   try:
       await adapter.execute()
   except AdapterError:
       raise  # ❌ Exposes infrastructure details
   ```

4. **Never skip input validation**
   ```python
   # ❌ WRONG
   connection = MCPConnection(
       server_name=request.server_name  # ❌ No validation
   )
   ```

5. **Never return domain aggregates directly**
   ```python
   # ❌ WRONG
   return connection  # ❌ Exposes domain model

   # ✅ CORRECT
   return MCPConnectionDTO.from_aggregate(connection)
   ```

---

## Troubleshooting

### Issue: AuthorizationError "Namespace mismatch"

**Symptom**: Use case raises `AuthorizationError` with "Namespace mismatch" message.

**Cause**: Claimed namespace (from request) does not match verified namespace (from database).

**Possible Reasons**:
1. User tampered with JWT claims
2. Agent was moved to different namespace
3. Request DTO contains incorrect namespace

**Resolution**:
```python
# Check agent's current namespace
agent = await agent_repository.get_by_id(agent_id)
print(f"Agent namespace: {agent.namespace}")

# Ensure request matches
request = CreateConnectionRequest(
    namespace=agent.namespace,  # ✅ Use verified namespace
    ...
)
```

---

### Issue: ValidationError "Connection already exists"

**Symptom**: `ConnectMCPServerUseCase` raises `ValidationError`.

**Cause**: Connection with same (server_name, namespace) already exists.

**Resolution**:
```python
# Option 1: Use existing connection
existing = await repository.get_by_server_name_and_namespace(
    server_name, namespace
)
if existing:
    print(f"Using existing connection: {existing.id}")

# Option 2: Disconnect old connection first
await disconnect_use_case.execute(DisconnectRequest(...))
await connect_use_case.execute(CreateConnectionRequest(...))
```

---

### Issue: ExternalServiceError "Failed to connect"

**Symptom**: `ConnectMCPServerUseCase` raises `ExternalServiceError`.

**Cause**: MCP server is unreachable, authentication failed, or timeout.

**Debugging**:
```python
# Check connection details
print(f"URL: {request.url}")
print(f"Timeout: {request.timeout}")
print(f"Auth required: {request.auth_required}")

# Test connectivity manually
import httpx
response = await httpx.get(str(request.url), timeout=request.timeout)
print(f"Status: {response.status_code}")
```

**Common Issues**:
- URL is incorrect (typo)
- MCP server is down
- Firewall blocks connection
- API key is invalid
- Timeout is too short

---

### Issue: ValidationError "Connection is not active"

**Symptom**: `DiscoverToolsUseCase` or `ExecuteToolUseCase` raises `ValidationError`.

**Cause**: Connection status is not `ACTIVE` (may be `DISCONNECTED` or `ERROR`).

**Resolution**:
```python
# Check connection status
connection = await repository.get_by_id(id, namespace)
print(f"Status: {connection.status.value}")
print(f"Error message: {connection.error_message}")

# Reconnect if needed
if connection.status != ConnectionStatus.ACTIVE:
    # Disconnect old connection
    await disconnect_use_case.execute(DisconnectRequest(...))

    # Establish new connection
    await connect_use_case.execute(CreateConnectionRequest(...))
```

---

### Issue: ValidationError "Tool not found"

**Symptom**: `ExecuteToolUseCase` raises `ValidationError`.

**Cause**: Tool name does not exist in connection's tool list.

**Resolution**:
```python
# List available tools
connection = await repository.get_by_id(id, namespace)
print("Available tools:")
for tool in connection.tools:
    print(f"  - {tool.name}")

# Refresh tools from server
result = await discover_tools_use_case.execute(DiscoverToolsRequest(...))
print(f"Refreshed tools: {[t.name for t in result.tools]}")
```

---

### Issue: Events not being dispatched

**Symptom**: Event handlers are not called after use case execution.

**Cause**: Events are dispatched before commit, or event handlers not registered.

**Debugging**:
```python
# [1] Verify event dispatcher is initialized
print(f"Event dispatcher: {event_dispatcher}")

# [2] Verify handlers are registered
print(f"Handlers: {event_dispatcher._handlers}")

# [3] Verify events are collected
print(f"Domain events: {connection.domain_events}")

# [4] Verify dispatch order (AFTER commit)
async with uow:
    # ... logic ...
    await uow.commit()  # ← Must come BEFORE dispatch

await event_dispatcher.dispatch_all(events)  # ← AFTER commit
```

---

## Related Documentation

- **DTOs**: See `docs/application/DTOS.md` for detailed DTO specifications
- **Event Dispatcher**: See `docs/application/EVENT_DISPATCHER.md` for event handling patterns
- **Domain Model**: See `docs/domain/AGGREGATES.md` for MCPConnection aggregate
- **Repositories**: See `docs/infrastructure/REPOSITORIES.md` for repository implementations
- **Security**: See `docs/security/NAMESPACE_ISOLATION.md` for P0-1 pattern details

---

**Last Updated**: 2025-11-12
**Authors**: Muses (Documentation), Hera (Architecture), Artemis (Implementation)
**Phase**: 1-2-F (Documentation Update)
