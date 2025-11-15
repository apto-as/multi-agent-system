# Application Service Layer - Data Transfer Objects (DTOs)

**TMWS Phase 1-2**: MCP Connection Management
**Architecture**: Domain-Driven Design (DDD)
**Last Updated**: 2025-11-12

---

## Table of Contents

1. [Overview](#overview)
2. [DTO Pattern in DDD](#dto-pattern-in-ddd)
3. [DTO Categories](#dto-categories)
4. [Request DTOs](#request-dtos)
   - [CreateConnectionRequest](#1-createconnectionrequest)
   - [DiscoverToolsRequest](#2-discovertoolsrequest)
   - [ExecuteToolRequest](#3-executetoolrequest)
   - [DisconnectRequest](#4-disconnectrequest)
5. [Response DTOs](#response-dtos)
   - [MCPConnectionDTO](#1-mcpconnectiondto)
   - [ToolDTO](#2-tooldto)
   - [ToolExecutionResultDTO](#3-toolexecutionresultdto)
   - [DisconnectionResultDTO](#4-disconnectionresultdto)
6. [Conversion Patterns](#conversion-patterns)
7. [JSON Serialization](#json-serialization)
8. [Validation Patterns](#validation-patterns)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

---

## Overview

**Data Transfer Objects (DTOs)** are simple data structures used to transfer data between application boundaries. In TMWS, DTOs serve as the contract between the Presentation layer (FastAPI routers) and the Application layer (use cases).

**Purpose**:
- Decouple external API from internal domain model
- Provide clear validation rules at system boundaries
- Enable API versioning without affecting domain
- Serialize domain concepts to JSON
- Prevent accidental exposure of domain internals

**Key Principle**: DTOs exist ONLY at external boundaries, never inside the application layer.

---

## DTO Pattern in DDD

### Layered Architecture

```
┌─────────────────────────────────────────────┐
│         Presentation Layer (FastAPI)        │
│  - Receives JSON from HTTP requests         │
│  - Creates Request DTOs (Pydantic)          │
│  - Returns Response DTOs as JSON            │
└────────────────┬────────────────────────────┘
                 │ Request DTO
                 ↓
┌─────────────────────────────────────────────┐
│      Application Layer (Use Cases)          │
│  - Receives Request DTOs                    │
│  - Executes business logic                  │
│  - Returns Response DTOs                    │
└────────────────┬────────────────────────────┘
                 │ Domain Entities/Aggregates
                 ↓
┌─────────────────────────────────────────────┐
│          Domain Layer (Core Logic)          │
│  - Pure domain objects (NO DTOs)            │
│  - MCPConnection aggregate                  │
│  - Tool entity, Value Objects               │
└────────────────┬────────────────────────────┘
                 │ Repository interface
                 ↓
┌─────────────────────────────────────────────┐
│   Infrastructure Layer (Persistence)        │
│  - SQLAlchemy models                        │
│  - Database operations                      │
└─────────────────────────────────────────────┘
```

**Flow**:
1. **Presentation → Application**: Request DTO (with validation)
2. **Application → Domain**: Domain entities/aggregates (no DTOs)
3. **Domain → Application**: Domain entities/aggregates
4. **Application → Presentation**: Response DTO (serializable)

---

## DTO Categories

TMWS has **two types of DTOs**:

### 1. Request DTOs (Pydantic Models)

**Purpose**: Input validation and deserialization

**Characteristics**:
- Inherit from `pydantic.BaseModel`
- Automatic validation on instantiation
- Field-level validators using `@field_validator`
- Clear error messages for invalid input
- Mutable (can be modified before use case execution)

**Files**: `src/application/dtos/request_dtos.py` (91 lines)

---

### 2. Response DTOs (Frozen Dataclasses)

**Purpose**: Output serialization and immutability

**Characteristics**:
- Use `@dataclass(frozen=True)` for immutability
- Convert domain aggregates/entities to DTOs via `from_aggregate()`, `from_entity()`
- Serialize to JSON via `to_dict()`
- No validation (domain model already validated)
- Immutable (cannot be modified after creation)

**Files**: `src/application/dtos/response_dtos.py` (131 lines)

---

## Request DTOs

All request DTOs use **Pydantic** for validation and provide clear error messages.

---

### 1. CreateConnectionRequest

**Purpose**: Request to create new MCP connection.

**File**: `src/application/dtos/request_dtos.py` (lines 12-56)

---

#### Fields

| Field | Type | Required | Default | Constraints | Description |
|-------|------|----------|---------|-------------|-------------|
| `server_name` | `str` | ✅ | - | 1-100 chars | MCP server name |
| `url` | `HttpUrl` | ✅ | - | Valid HTTP/HTTPS URL | Server endpoint |
| `namespace` | `str` | ✅ | - | 1-255 chars | Isolation namespace (SECURITY) |
| `agent_id` | `UUID` | ✅ | - | Valid UUID | Agent identifier |
| `timeout` | `int` | ❌ | 30 | 1-300 seconds | Connection timeout |
| `retry_attempts` | `int` | ❌ | 3 | 0-10 | Number of retries |
| `auth_required` | `bool` | ❌ | False | - | Whether authentication needed |
| `api_key` | `str?` | ❌ | None | Required if `auth_required=True` | API key for auth |

---

#### Validation Rules

**1. Server Name Format** (lines 41-48)

```python
@field_validator("server_name")
def validate_server_name(cls, v):
    """Validate server name format"""
    if not v.replace("-", "").replace("_", "").isalnum():
        raise ValueError(
            "Server name must contain only alphanumeric, hyphen, or underscore"
        )
    return v
```

**Valid Examples**:
- `my-mcp-server` ✅
- `mcp_server_123` ✅
- `MCPServer2024` ✅

**Invalid Examples**:
- `mcp@server` ❌ (contains @)
- `mcp server` ❌ (contains space)
- `mcp.server` ❌ (contains .)

---

**2. API Key Conditional Requirement** (lines 50-55)

```python
@field_validator("api_key")
def validate_api_key(cls, v, info):
    """Validate API key when auth_required is True"""
    if info.data.get("auth_required") and not v:
        raise ValueError("API key required when auth_required is True")
    return v
```

**Valid Examples**:
```python
# Case 1: No auth
CreateConnectionRequest(
    auth_required=False,
    api_key=None  # ✅ OK
)

# Case 2: Auth with key
CreateConnectionRequest(
    auth_required=True,
    api_key="secret-key-xyz"  # ✅ OK
)
```

**Invalid Example**:
```python
# Case 3: Auth without key
CreateConnectionRequest(
    auth_required=True,
    api_key=None  # ❌ ValidationError
)
```

---

#### Usage Example

```python
from pydantic import HttpUrl, ValidationError
from uuid import UUID
from src.application.dtos.request_dtos import CreateConnectionRequest

# Valid request
try:
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
    print(f"✅ Valid request: {request.server_name}")
except ValidationError as e:
    print(f"❌ Validation failed: {e}")

# Invalid request (missing API key)
try:
    request = CreateConnectionRequest(
        server_name="my-mcp-server",
        url=HttpUrl("https://api.example.com/mcp"),
        namespace="engineering-team",
        agent_id=UUID("12345678-1234-1234-1234-123456789abc"),
        auth_required=True,
        api_key=None,  # ❌ Missing API key
    )
except ValidationError as e:
    print(f"❌ Validation failed: {e}")
    # Output: API key required when auth_required is True
```

---

#### JSON Schema

```json
{
  "server_name": "my-mcp-server",
  "url": "https://api.example.com/mcp",
  "namespace": "engineering-team",
  "agent_id": "12345678-1234-1234-1234-123456789abc",
  "timeout": 60,
  "retry_attempts": 5,
  "auth_required": true,
  "api_key": "secret-api-key-xyz"
}
```

---

### 2. DiscoverToolsRequest

**Purpose**: Request to discover tools from active MCP connection.

**File**: `src/application/dtos/request_dtos.py` (lines 58-65)

---

#### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connection_id` | `UUID` | ✅ | MCP connection identifier |
| `namespace` | `str` | ✅ | Namespace for authorization (SECURITY) |
| `agent_id` | `UUID` | ✅ | Agent identifier |

---

#### Validation Rules

- **connection_id**: Must be valid UUID
- **namespace**: 1-255 characters
- **agent_id**: Must be valid UUID

**No custom validators** - all validation is handled by Pydantic field types.

---

#### Usage Example

```python
from uuid import UUID
from src.application.dtos.request_dtos import DiscoverToolsRequest

request = DiscoverToolsRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)
```

---

#### JSON Schema

```json
{
  "connection_id": "12345678-1234-1234-1234-123456789abc",
  "namespace": "engineering-team",
  "agent_id": "87654321-4321-4321-4321-cba987654321"
}
```

---

### 3. ExecuteToolRequest

**Purpose**: Request to execute tool on active MCP connection.

**File**: `src/application/dtos/request_dtos.py` (lines 68-81)

---

#### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `connection_id` | `UUID` | ✅ | - | MCP connection identifier |
| `tool_name` | `str` | ✅ | - | Tool name to execute (1-100 chars) |
| `arguments` | `dict` | ❌ | `{}` | Tool-specific arguments |
| `namespace` | `str` | ✅ | - | Namespace for authorization (SECURITY) |
| `agent_id` | `UUID` | ✅ | - | Agent identifier |

---

#### Validation Rules

- **connection_id**: Valid UUID
- **tool_name**: 1-100 characters
- **arguments**: Dictionary (can be empty)
- **namespace**: 1-255 characters
- **agent_id**: Valid UUID

---

#### Usage Example

```python
from uuid import UUID
from src.application.dtos.request_dtos import ExecuteToolRequest

# Example 1: Tool with arguments
request = ExecuteToolRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    tool_name="list_files",
    arguments={"path": "/home/user", "recursive": False},
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)

# Example 2: Tool without arguments
request = ExecuteToolRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    tool_name="get_status",
    arguments={},  # Empty dict (default)
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)
```

---

#### JSON Schema

```json
{
  "connection_id": "12345678-1234-1234-1234-123456789abc",
  "tool_name": "list_files",
  "arguments": {
    "path": "/home/user",
    "recursive": false
  },
  "namespace": "engineering-team",
  "agent_id": "87654321-4321-4321-4321-cba987654321"
}
```

---

### 4. DisconnectRequest

**Purpose**: Request to disconnect from MCP server.

**File**: `src/application/dtos/request_dtos.py` (lines 84-91)

---

#### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connection_id` | `UUID` | ✅ | Connection to disconnect |
| `namespace` | `str` | ✅ | Namespace for authorization (SECURITY) |
| `agent_id` | `UUID` | ✅ | Agent identifier |

---

#### Validation Rules

- **connection_id**: Valid UUID
- **namespace**: 1-255 characters
- **agent_id**: Valid UUID

---

#### Usage Example

```python
from uuid import UUID
from src.application.dtos.request_dtos import DisconnectRequest

request = DisconnectRequest(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    namespace="engineering-team",
    agent_id=UUID("87654321-4321-4321-4321-cba987654321"),
)
```

---

#### JSON Schema

```json
{
  "connection_id": "12345678-1234-1234-1234-123456789abc",
  "namespace": "engineering-team",
  "agent_id": "87654321-4321-4321-4321-cba987654321"
}
```

---

## Response DTOs

All response DTOs are **frozen dataclasses** for immutability and provide `from_aggregate()` / `from_entity()` and `to_dict()` methods.

---

### 1. MCPConnectionDTO

**Purpose**: Response DTO for MCP connection details.

**File**: `src/application/dtos/response_dtos.py` (lines 44-96)

---

#### Fields

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
| `connected_at` | `datetime?` | Connection timestamp (nullable) |
| `disconnected_at` | `datetime?` | Disconnection timestamp (nullable) |
| `error_message` | `str?` | Error message if status=ERROR (nullable) |

---

#### Conversion: from_aggregate()

**Purpose**: Convert `MCPConnection` aggregate to DTO.

**Implementation** (lines 60-74):

```python
@classmethod
def from_aggregate(cls, connection) -> "MCPConnectionDTO":
    """Convert MCPConnection aggregate to DTO"""
    return cls(
        id=connection.id,
        server_name=str(connection.server_name),
        url=str(connection.config.url),  # URL is in config
        namespace=connection.namespace,
        agent_id=connection.agent_id,
        status=connection.status.value,
        tools=[ToolDTO.from_entity(tool) for tool in connection.tools],
        created_at=connection.created_at,
        connected_at=connection.connected_at,
        disconnected_at=connection.disconnected_at,
        error_message=connection.error_message,
    )
```

**Key Conversions**:
- `connection.server_name` (ServerName value object) → `str`
- `connection.config.url` (ServerURL value object) → `str`
- `connection.status` (ConnectionStatus enum) → `str` (enum value)
- `connection.tools` (list[Tool]) → `list[ToolDTO]`
- `connection.agent_id` (UUID/str) → `UUID`

---

#### Serialization: to_dict()

**Purpose**: Serialize DTO to JSON-compatible dict.

**Implementation** (lines 76-96):

```python
def to_dict(self) -> dict:
    """Serialize to JSON-compatible dict"""
    return {
        "id": str(self.id),
        "server_name": self.server_name,
        "url": self.url,
        "namespace": self.namespace,
        "agent_id": str(self.agent_id),
        "status": self.status,
        "tools": [tool.to_dict() for tool in self.tools],
        "created_at": self.created_at.isoformat(),
        "connected_at": (
            self.connected_at.isoformat() if self.connected_at else None
        ),
        "disconnected_at": (
            self.disconnected_at.isoformat()
            if self.disconnected_at
            else None
        ),
        "error_message": self.error_message,
    }
```

**Key Serializations**:
- `UUID` → `str` (via `str()`)
- `datetime` → `str` (via `.isoformat()`)
- `list[ToolDTO]` → `list[dict]` (via `.to_dict()` recursively)
- `None` values preserved as `null` in JSON

---

#### Usage Example

```python
from src.application.dtos.response_dtos import MCPConnectionDTO
from src.domain.aggregates.mcp_connection import MCPConnection

# Given a domain aggregate
connection = MCPConnection(...)  # From repository

# [1] Convert to DTO
dto = MCPConnectionDTO.from_aggregate(connection)

# [2] Access fields (immutable)
print(f"Connection: {dto.server_name}")
print(f"Status: {dto.status}")
print(f"Tools: {len(dto.tools)}")

# [3] Serialize to JSON
json_data = dto.to_dict()
print(json_data)

# [4] Return from API
from fastapi import JSONResponse
return JSONResponse(content=json_data, status_code=200)
```

---

#### JSON Example

```json
{
  "id": "12345678-1234-1234-1234-123456789abc",
  "server_name": "my-mcp-server",
  "url": "https://api.example.com/mcp",
  "namespace": "engineering-team",
  "agent_id": "87654321-4321-4321-4321-cba987654321",
  "status": "ACTIVE",
  "tools": [
    {
      "name": "list_files",
      "description": "List files in a directory",
      "input_schema": {"path": "string", "recursive": "boolean"},
      "category": "filesystem"
    },
    {
      "name": "read_file",
      "description": "Read file contents",
      "input_schema": {"path": "string"},
      "category": "filesystem"
    }
  ],
  "created_at": "2025-11-12T10:00:00.000000",
  "connected_at": "2025-11-12T10:00:05.123456",
  "disconnected_at": null,
  "error_message": null
}
```

---

### 2. ToolDTO

**Purpose**: Response DTO for MCP tool details.

**File**: `src/application/dtos/response_dtos.py` (lines 15-40)

---

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Tool name |
| `description` | `str` | Tool description |
| `input_schema` | `dict` | Tool input schema (JSON Schema) |
| `category` | `str` | Tool category |

---

#### Conversion: from_entity()

**Purpose**: Convert `Tool` entity to DTO.

**Implementation** (lines 24-31):

```python
@classmethod
def from_entity(cls, tool) -> "ToolDTO":
    """Convert Tool entity to DTO"""
    return cls(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        category=tool.category.value,
    )
```

**Key Conversions**:
- `tool.category` (ToolCategory enum) → `str` (enum value)

---

#### Serialization: to_dict()

**Purpose**: Serialize DTO to JSON-compatible dict.

**Implementation** (lines 33-40):

```python
def to_dict(self) -> dict:
    """Serialize to JSON-compatible dict"""
    return {
        "name": self.name,
        "description": self.description,
        "input_schema": self.input_schema,
        "category": self.category,
    }
```

---

#### Usage Example

```python
from src.application.dtos.response_dtos import ToolDTO
from src.domain.entities.tool import Tool

# Given a domain entity
tool = Tool(
    name="list_files",
    description="List files in a directory",
    input_schema={"path": "string", "recursive": "boolean"},
    category=ToolCategory.FILESYSTEM
)

# [1] Convert to DTO
dto = ToolDTO.from_entity(tool)

# [2] Serialize to JSON
json_data = dto.to_dict()
print(json_data)
```

---

#### JSON Example

```json
{
  "name": "list_files",
  "description": "List files in a directory",
  "input_schema": {
    "path": "string",
    "recursive": "boolean"
  },
  "category": "filesystem"
}
```

---

### 3. ToolExecutionResultDTO

**Purpose**: Response DTO for tool execution result.

**File**: `src/application/dtos/response_dtos.py` (lines 100-113)

---

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | `UUID` | Connection ID |
| `tool_name` | `str` | Executed tool name |
| `result` | `dict` | Tool execution result |

**Note**: No `success` or `error_message` fields - if execution fails, an exception is raised by the use case.

---

#### Serialization: to_dict()

**Implementation** (lines 107-113):

```python
def to_dict(self) -> dict:
    """Serialize to JSON-compatible dict"""
    return {
        "connection_id": str(self.connection_id),
        "tool_name": self.tool_name,
        "result": self.result,
    }
```

---

#### Usage Example

```python
from src.application.dtos.response_dtos import ToolExecutionResultDTO
from uuid import UUID

# Create DTO
dto = ToolExecutionResultDTO(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    tool_name="list_files",
    result={"files": ["file1.txt", "file2.txt", "file3.txt"], "count": 3},
)

# Serialize to JSON
json_data = dto.to_dict()
print(json_data)
```

---

#### JSON Example

```json
{
  "connection_id": "12345678-1234-1234-1234-123456789abc",
  "tool_name": "list_files",
  "result": {
    "files": ["file1.txt", "file2.txt", "file3.txt"],
    "count": 3
  }
}
```

---

### 4. DisconnectionResultDTO

**Purpose**: Response DTO for disconnection result.

**File**: `src/application/dtos/response_dtos.py` (lines 117-130)

---

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | `UUID` | Disconnected connection ID |
| `server_name` | `str` | Server name |
| `disconnected_at` | `datetime` | Timestamp of disconnection |

---

#### Serialization: to_dict()

**Implementation** (lines 124-130):

```python
def to_dict(self) -> dict:
    """Serialize to JSON-compatible dict"""
    return {
        "connection_id": str(self.connection_id),
        "server_name": self.server_name,
        "disconnected_at": self.disconnected_at.isoformat(),
    }
```

---

#### Usage Example

```python
from src.application.dtos.response_dtos import DisconnectionResultDTO
from uuid import UUID
from datetime import datetime

# Create DTO
dto = DisconnectionResultDTO(
    connection_id=UUID("12345678-1234-1234-1234-123456789abc"),
    server_name="my-mcp-server",
    disconnected_at=datetime.utcnow(),
)

# Serialize to JSON
json_data = dto.to_dict()
print(json_data)
```

---

#### JSON Example

```json
{
  "connection_id": "12345678-1234-1234-1234-123456789abc",
  "server_name": "my-mcp-server",
  "disconnected_at": "2025-11-12T11:30:00.123456"
}
```

---

## Conversion Patterns

### Pattern 1: Aggregate → DTO (Response)

```python
# Domain layer → Application layer
@classmethod
def from_aggregate(cls, connection: MCPConnection) -> "MCPConnectionDTO":
    return cls(
        id=connection.id,
        server_name=str(connection.server_name),  # Value Object → str
        url=str(connection.config.url),           # Value Object → str
        status=connection.status.value,           # Enum → str
        tools=[ToolDTO.from_entity(t) for t in connection.tools],  # Recursive
        # ... other fields ...
    )
```

**Key Conversions**:
- Value Objects → primitive types
- Enums → string values
- Nested entities → nested DTOs (recursive)
- Domain concepts → serializable data

---

### Pattern 2: Entity → DTO (Response)

```python
# Domain layer → Application layer
@classmethod
def from_entity(cls, tool: Tool) -> "ToolDTO":
    return cls(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        category=tool.category.value,  # Enum → str
    )
```

---

### Pattern 3: DTO → JSON (Serialization)

```python
# Application layer → Presentation layer
def to_dict(self) -> dict:
    return {
        "id": str(self.id),                      # UUID → str
        "created_at": self.created_at.isoformat(),  # datetime → ISO string
        "tools": [t.to_dict() for t in self.tools],  # Recursive serialization
        "nullable_field": self.field if self.field else None,  # Handle None
    }
```

**Key Serializations**:
- `UUID` → `str`
- `datetime` → ISO 8601 string
- Nested DTOs → recursive `to_dict()`
- `None` → `null` in JSON

---

### Pattern 4: JSON → DTO (Deserialization - Pydantic)

```python
# Presentation layer → Application layer
# Automatic via Pydantic
request = CreateConnectionRequest(
    **json_data  # Pydantic handles conversion & validation
)
```

---

## JSON Serialization

### Serialization Guidelines

| Python Type | JSON Type | Method | Example |
|-------------|-----------|--------|---------|
| `UUID` | `string` | `str(uuid)` | `"12345678-1234-1234-1234-123456789abc"` |
| `datetime` | `string` | `.isoformat()` | `"2025-11-12T10:00:00.123456"` |
| `Enum` | `string` | `.value` | `"ACTIVE"` |
| `list[DTO]` | `array` | `[dto.to_dict() for dto in list]` | `[{...}, {...}]` |
| `dict` | `object` | Pass through | `{"key": "value"}` |
| `None` | `null` | Pass through | `null` |
| `bool` | `boolean` | Pass through | `true` / `false` |
| `int`, `float` | `number` | Pass through | `42`, `3.14` |
| `str` | `string` | Pass through | `"text"` |

---

### FastAPI Integration

**Automatic JSON Response** (FastAPI handles serialization):

```python
from fastapi import APIRouter
from src.application.dtos.response_dtos import MCPConnectionDTO

router = APIRouter()

@router.post("/connections", response_model=dict)
async def create_connection(...) -> dict:
    # Use case returns DTO
    result: MCPConnectionDTO = await use_case.execute(request)

    # Convert to dict
    return result.to_dict()  # FastAPI converts to JSON automatically
```

**Manual JSON Response** (explicit control):

```python
from fastapi.responses import JSONResponse

@router.post("/connections")
async def create_connection(...):
    result: MCPConnectionDTO = await use_case.execute(request)

    # Explicit JSON response with status code
    return JSONResponse(
        content=result.to_dict(),
        status_code=201,
        headers={"X-Request-ID": request_id}
    )
```

---

## Validation Patterns

### Pydantic Field Validation

**Built-in Validators**:

```python
from pydantic import BaseModel, Field, HttpUrl, UUID4

class MyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    age: int = Field(..., ge=0, le=150)
    url: HttpUrl  # Validates URL format
    user_id: UUID4  # Validates UUID format
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
```

---

**Custom Validators**:

```python
from pydantic import field_validator

class CreateConnectionRequest(BaseModel):
    server_name: str

    @field_validator("server_name")
    def validate_server_name(cls, v):
        # Custom validation logic
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Invalid server name format")
        return v
```

---

**Cross-Field Validators**:

```python
class CreateConnectionRequest(BaseModel):
    auth_required: bool
    api_key: str | None

    @field_validator("api_key")
    def validate_api_key(cls, v, info):
        # Validate based on another field
        if info.data.get("auth_required") and not v:
            raise ValueError("API key required when auth_required is True")
        return v
```

---

### Validation Error Handling

```python
from pydantic import ValidationError

try:
    request = CreateConnectionRequest(**data)
except ValidationError as e:
    # Pydantic provides detailed error messages
    print(e.json())
    # Output:
    # [
    #   {
    #     "loc": ["api_key"],
    #     "msg": "API key required when auth_required is True",
    #     "type": "value_error"
    #   }
    # ]
```

---

## Best Practices

### ✅ DO

1. **Use Request DTOs for input validation**
   ```python
   request = CreateConnectionRequest(**data)  # ✅ Pydantic validates
   ```

2. **Use Response DTOs for output serialization**
   ```python
   dto = MCPConnectionDTO.from_aggregate(connection)
   return dto.to_dict()  # ✅ Serializes to JSON
   ```

3. **Keep DTOs immutable (frozen dataclasses)**
   ```python
   @dataclass(frozen=True)
   class MyResponseDTO:  # ✅ Immutable
       field: str
   ```

4. **Convert at boundaries only**
   ```python
   # Presentation → Application
   request_dto = CreateConnectionRequest(...)

   # Application → Domain
   aggregate = MCPConnection(...)  # No DTOs in domain

   # Domain → Application
   response_dto = MCPConnectionDTO.from_aggregate(aggregate)

   # Application → Presentation
   return response_dto.to_dict()
   ```

5. **Use descriptive field names**
   ```python
   connection_id: UUID  # ✅ Clear
   id: UUID             # ❌ Ambiguous in large DTOs
   ```

6. **Provide clear validation error messages**
   ```python
   @field_validator("server_name")
   def validate_server_name(cls, v):
       if not v.isalnum():
           raise ValueError(
               "Server name must contain only alphanumeric characters"
           )  # ✅ Clear message
   ```

---

### ❌ DON'T

1. **Don't use DTOs inside domain layer**
   ```python
   # ❌ WRONG
   class MCPConnection:
       def update(self, dto: MCPConnectionDTO):  # ❌ DTO in domain
           ...
   ```

2. **Don't expose domain aggregates directly**
   ```python
   # ❌ WRONG
   @router.get("/connections/{id}")
   async def get_connection(...) -> MCPConnection:  # ❌ Exposes domain
       return await repository.get(id)
   ```

3. **Don't make response DTOs mutable**
   ```python
   # ❌ WRONG
   @dataclass  # ❌ Missing frozen=True
   class MyResponseDTO:
       field: str

   dto = MyResponseDTO(field="value")
   dto.field = "changed"  # ❌ Mutation allowed
   ```

4. **Don't skip validation**
   ```python
   # ❌ WRONG
   def create_connection(data: dict):  # ❌ No validation
       # Direct use of dict
       connection = MCPConnection(
           server_name=data["server_name"]  # ❌ No validation
       )
   ```

5. **Don't return raw dictionaries**
   ```python
   # ❌ WRONG
   @router.get("/connections/{id}")
   async def get_connection(...) -> dict:  # ❌ Untyped
       connection = await repository.get(id)
       return {
           "id": str(connection.id),
           "name": connection.name,
           # ... manual serialization (error-prone)
       }
   ```

6. **Don't use DTOs for internal communication**
   ```python
   # ❌ WRONG
   class MyService:
       async def process(self, dto: CreateConnectionRequest):  # ❌ DTO internal
           # Should use domain entities internally
   ```

---

## Troubleshooting

### Issue: ValidationError "API key required when auth_required is True"

**Symptom**: Pydantic raises `ValidationError` when creating `CreateConnectionRequest`.

**Cause**: `auth_required=True` but `api_key=None`.

**Resolution**:
```python
# Option 1: Provide API key
request = CreateConnectionRequest(
    auth_required=True,
    api_key="secret-key-xyz"  # ✅ Provide key
)

# Option 2: Disable auth
request = CreateConnectionRequest(
    auth_required=False,
    api_key=None  # ✅ OK when auth not required
)
```

---

### Issue: ValidationError "Server name must contain only alphanumeric..."

**Symptom**: Pydantic raises `ValidationError` for `server_name` field.

**Cause**: Server name contains invalid characters (spaces, special characters).

**Resolution**:
```python
# ❌ Invalid
server_name = "my mcp server"  # Contains spaces

# ✅ Valid
server_name = "my-mcp-server"  # Use hyphens
server_name = "my_mcp_server"  # Use underscores
server_name = "mcpserver123"   # Alphanumeric
```

---

### Issue: TypeError when serializing datetime

**Symptom**: `TypeError: Object of type datetime is not JSON serializable`.

**Cause**: Trying to serialize `datetime` directly without `.isoformat()`.

**Resolution**:
```python
# ❌ WRONG
return {"created_at": dto.created_at}  # ❌ datetime not serializable

# ✅ CORRECT
return {"created_at": dto.created_at.isoformat()}  # ✅ ISO string
```

---

### Issue: UUID serialization error

**Symptom**: `TypeError: Object of type UUID is not JSON serializable`.

**Cause**: Trying to serialize `UUID` directly without `str()`.

**Resolution**:
```python
# ❌ WRONG
return {"id": dto.id}  # ❌ UUID not serializable

# ✅ CORRECT
return {"id": str(dto.id)}  # ✅ Convert to string
```

---

### Issue: DTO mutation after creation

**Symptom**: Response DTO fields are accidentally modified.

**Cause**: DTO is not frozen (missing `frozen=True` in `@dataclass`).

**Resolution**:
```python
# ❌ WRONG
@dataclass  # ❌ Not frozen
class MyDTO:
    field: str

dto = MyDTO(field="value")
dto.field = "changed"  # ❌ Mutation allowed

# ✅ CORRECT
@dataclass(frozen=True)  # ✅ Frozen
class MyDTO:
    field: str

dto = MyDTO(field="value")
dto.field = "changed"  # ✅ Raises FrozenInstanceError
```

---

## Related Documentation

- **Use Cases**: See `docs/application/USE_CASES.md` for DTO usage in use cases
- **Event Dispatcher**: See `docs/application/EVENT_DISPATCHER.md` for event patterns
- **Domain Model**: See `docs/domain/AGGREGATES.md` for aggregate → DTO conversion
- **API Layer**: See `docs/api/ROUTERS.md` for FastAPI integration examples

---

**Last Updated**: 2025-11-12
**Authors**: Muses (Documentation), Hera (Architecture), Artemis (Implementation)
**Phase**: 1-2-F (Documentation Update)
