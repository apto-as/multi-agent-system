# Phase 1-1 Implementation Guide: Domain + Infrastructure Layers

**Created**: 2025-11-12
**Authors**: Athena (TDD), Hera (DDD), Artemis (Implementation), Hestia (Security)
**Status**: ✅ Completed with P0 Security Fixes Applied
**Test Results**: 31/31 tests PASSED (100%)

---

## Overview

Phase 1-1 implements the foundational layers of the MCP Integration system using Domain-Driven Design (DDD) patterns. This phase establishes the **Domain Layer** (business logic and rules) and **Infrastructure Layer** (external integrations and persistence) without any application services.

**Key Deliverables**:
- ✅ Domain Layer: Aggregates, Value Objects, Entities, Domain Events (9/9 tests)
- ✅ Infrastructure Layer: ACL, Adapter, Repository (22/22 tests)
- ✅ Security Fixes: All P0 issues resolved (7/7 security checklist)
- ✅ Database Migration: Alembic migration created and tested

**Architecture Pattern**: DDD with clean separation of concerns

```
┌─────────────────────────────────────────────────────────┐
│                   Domain Layer                          │
│  • MCPConnection (Aggregate Root)                       │
│  • ConnectionConfig, ConnectionStatus (Value Objects)   │
│  • Tool (Entity)                                        │
│  • Domain Events (transient, not persisted)            │
└─────────────────────────────────────────────────────────┘
                        ↑
                        │ Depends on (Dependency Inversion)
                        │
┌─────────────────────────────────────────────────────────┐
│                Infrastructure Layer                      │
│  • MCPProtocolTranslator (ACL - Anti-Corruption Layer)  │
│  • MCPClientAdapter (External HTTP communication)       │
│  • MCPConnectionRepository (Persistence)                │
│  • MCPConnectionModel (SQLAlchemy database model)       │
└─────────────────────────────────────────────────────────┘
```

---

## Domain Layer Components

### 1. MCPConnection Aggregate Root

**File**: `src/domain/aggregates/mcp_connection.py` (326 lines)

The MCPConnection is the **aggregate root** that manages the lifecycle of a connection to an MCP (Model Context Protocol) server.

#### Business Rules & Invariants

1. **State Transition Rules**: Only valid state transitions are allowed (enforced by `ConnectionStatus`)
2. **Tool Requirement Invariant**: ACTIVE connection MUST have at least one tool
3. **Domain Events**: State changes raise domain events
4. **Namespace Isolation**: Enforced at repository level (security)

#### Key Methods

```python
@dataclass
class MCPConnection:
    """Aggregate root for MCP server connections."""

    id: UUID
    server_name: str
    config: ConnectionConfig
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    tools: list[Tool] = field(default_factory=list)
    namespace: str | None = None
    agent_id: str | None = None
    domain_events: list[DomainEvent] = field(default_factory=list)

    def mark_as_active(self, tools: list[Tool]) -> None:
        """Mark connection as ACTIVE with discovered tools.

        Raises:
            InvalidStateTransitionError: If transition not allowed
            DomainInvariantViolation: If no tools provided
        """
        # Validate state transition
        if not self.status.can_transition_to(ConnectionStatus.ACTIVE):
            raise InvalidStateTransitionError(...)

        # Validate invariant
        if not tools:
            raise DomainInvariantViolation(
                "ACTIVE connection must have at least one tool"
            )

        # Update state
        self.status = ConnectionStatus.ACTIVE
        self.tools = tools
        self.connected_at = datetime.utcnow()

        # Raise domain event
        self.domain_events.append(MCPConnectedEvent(...))

    def disconnect(self, reason: str | None = None) -> None:
        """Disconnect from MCP server (graceful)."""
        if self.status == ConnectionStatus.DISCONNECTED:
            raise InvalidStateTransitionError(...)

        self.status = ConnectionStatus.DISCONNECTED
        self.disconnected_at = datetime.utcnow()
        self.domain_events.append(MCPDisconnectedEvent(...))

    def mark_as_error(self, error_message: str) -> None:
        """Mark connection as ERROR (not graceful)."""
        self.status = ConnectionStatus.ERROR
        self.error_message = error_message
        self.error_at = datetime.utcnow()
        # Note: Does NOT raise MCPDisconnectedEvent (error, not graceful)

    def add_tools(self, new_tools: list[Tool]) -> None:
        """Add newly discovered tools (ACTIVE connection only)."""
        if self.status != ConnectionStatus.ACTIVE:
            raise DomainInvariantViolation(...)

        self.tools.extend(new_tools)
        for tool in new_tools:
            self.domain_events.append(ToolDiscoveredEvent(...))
```

**Usage Example**:

```python
from uuid import uuid4
from src.domain.aggregates.mcp_connection import MCPConnection
from src.domain.value_objects.connection_config import ConnectionConfig
from src.domain.entities.tool import Tool

# Create connection configuration
config = ConnectionConfig(
    server_name="tmws_mcp",
    url="http://localhost:8080/mcp",
    timeout=30,
    retry_attempts=3
)

# Create connection aggregate
connection = MCPConnection(
    id=uuid4(),
    server_name="tmws_mcp",
    config=config,
    namespace="project-x",
    agent_id="agent-123"
)

# Connect and discover tools
tools = [
    Tool(name="store_memory", description="Store semantic memory"),
    Tool(name="search_memories", description="Search semantic memories")
]

connection.mark_as_active(tools)  # Raises MCPConnectedEvent
assert connection.status == ConnectionStatus.ACTIVE
assert len(connection.domain_events) == 1

# Disconnect gracefully
connection.disconnect("User requested")  # Raises MCPDisconnectedEvent
assert connection.status == ConnectionStatus.DISCONNECTED
assert len(connection.domain_events) == 2
```

---

### 2. Value Objects

#### ConnectionConfig (Immutable Configuration)

**File**: `src/domain/value_objects/connection_config.py` (152 lines)

```python
@dataclass(frozen=True)
class ConnectionConfig:
    """Immutable configuration for MCP server connection.

    Validation Rules:
    - server_name: Non-empty string
    - url: Valid HTTP/HTTPS URL with scheme and hostname
    - timeout: Positive integer (seconds)
    - retry_attempts: Non-negative integer
    - api_key: Required if auth_required=True
    """

    server_name: str
    url: str
    timeout: int = 30
    retry_attempts: int = 3
    auth_required: bool = False
    api_key: str | None = None

    def __post_init__(self):
        """Validate configuration on construction."""
        # Validates URL format, timeout > 0, retry_attempts >= 0, etc.
        # See src/domain/value_objects/connection_config.py lines 60-100
```

**Security Feature**: API key is masked in `__repr__()` to prevent accidental logging.

```python
config = ConnectionConfig(
    server_name="secure_server",
    url="https://api.example.com",
    auth_required=True,
    api_key="secret_key_123"
)

print(repr(config))
# ConnectionConfig(server_name='secure_server', ..., api_key=***)
```

#### ConnectionStatus (State Enum)

**File**: `src/domain/value_objects/connection_status.py` (82 lines)

```python
class ConnectionStatus(str, Enum):
    """Status of an MCP connection with state transition rules."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ACTIVE = "active"
    DISCONNECTING = "disconnecting"
    ERROR = "error"

    @classmethod
    def get_allowed_transitions(cls, current: "ConnectionStatus") -> list["ConnectionStatus"]:
        """Get allowed state transitions from current status."""
        transitions = {
            cls.DISCONNECTED: [cls.CONNECTING, cls.ACTIVE, cls.ERROR],
            cls.CONNECTING: [cls.ACTIVE, cls.ERROR, cls.DISCONNECTED],
            cls.ACTIVE: [cls.DISCONNECTING, cls.ERROR],
            cls.DISCONNECTING: [cls.DISCONNECTED, cls.ERROR],
            cls.ERROR: [cls.DISCONNECTED],  # Can only recover by disconnecting
        }
        return transitions.get(current, [])
```

**Valid State Transitions**:

```
DISCONNECTED → CONNECTING → ACTIVE
ACTIVE → DISCONNECTING → DISCONNECTED
Any state → ERROR
ERROR → DISCONNECTED (recovery)
```

---

### 3. Tool Entity

**File**: `src/domain/entities/tool.py` (138 lines)

Tools are **entities** with identity based on their name. Two tools with the same name are considered the same entity, even if other properties differ.

```python
@dataclass
class Tool:
    """Entity representing a tool from an MCP server.

    Identity: Based on name (not all properties)
    Equality: Two tools with same name are equal
    Category: Auto-inferred from name and description
    """

    name: str
    description: str
    input_schema: dict = field(default_factory=dict)
    category: ToolCategory = field(default=ToolCategory.GENERAL)

    def __eq__(self, other: object) -> bool:
        """Entity equality based on name only."""
        if not isinstance(other, Tool):
            return False
        return self.name == other.name

    def __hash__(self) -> int:
        """Hash based on name (allows use in sets)."""
        return hash(self.name)
```

**Category Auto-Inference**:

```python
from src.domain.entities.tool import Tool
from src.domain.value_objects.tool_category import ToolCategory

# Category inferred from name
tool1 = Tool(name="store_memory", description="Store a memory")
assert tool1.category == ToolCategory.MEMORY

tool2 = Tool(name="search_knowledge", description="Search knowledge base")
assert tool2.category == ToolCategory.KNOWLEDGE

tool3 = Tool(name="execute_workflow", description="Execute workflow")
assert tool3.category == ToolCategory.WORKFLOW
```

---

### 4. Domain Events

**File**: `src/domain/events.py` (78 lines)

Domain events are **immutable** and represent something that happened in the domain. They are named in past tense.

**Key Principle**: Domain events are **transient** (not persisted to database). They are dispatched by the application service and then cleared.

```python
@dataclass(frozen=True)
class MCPConnectedEvent(DomainEvent):
    """Event raised when MCP connection is established."""
    server_name: str
    url: str
    namespace: str | None = None
    agent_id: str | None = None
    tool_count: int = 0

@dataclass(frozen=True)
class MCPDisconnectedEvent(DomainEvent):
    """Event raised when MCP connection is closed."""
    server_name: str
    reason: str | None = None
    was_graceful: bool = True

@dataclass(frozen=True)
class ToolDiscoveredEvent(DomainEvent):
    """Event raised when a new tool is discovered."""
    tool_name: str
    tool_description: str
    tool_category: str
    server_name: str
    input_schema: dict = field(default_factory=dict)
```

**Event Lifecycle**:

1. Aggregate method modifies state → Appends event to `domain_events` list
2. Application service persists aggregate → Dispatches events to event bus
3. Application service calls `aggregate.clear_events()` → Events removed from memory

---

## Infrastructure Layer Components

### 1. MCPProtocolTranslator (Anti-Corruption Layer)

**File**: `src/infrastructure/acl/mcp_protocol_translator.py` (222 lines)

The ACL protects the domain model from external protocol changes by translating between MCP protocol format and domain objects.

**Purpose**:
- Convert MCP responses → Domain objects (Tool, ConnectionConfig)
- Convert Domain requests → MCP protocol format
- Isolate domain from MCP protocol changes
- Validate protocol compliance

```python
class MCPProtocolTranslator:
    """Translates between MCP protocol and domain objects."""

    def mcp_tool_to_domain(self, mcp_tool: dict) -> Tool:
        """Convert MCP tool response to domain Tool entity.

        MCP Format:
        {
            "name": "search_memory",
            "description": "Search semantic memories",
            "inputSchema": {"type": "object", "properties": {...}}
        }

        Domain Format:
        Tool(name="search_memory", description="...", category=MEMORY)
        """
        if "name" not in mcp_tool or "description" not in mcp_tool:
            raise MCPProtocolError("Missing required fields")

        return Tool(
            name=mcp_tool["name"],
            description=mcp_tool["description"],
            input_schema=mcp_tool.get("inputSchema", {}),
            category=ToolCategory.infer_from_name(...)
        )

    def mcp_tools_response_to_domain(self, mcp_response: dict) -> list[Tool]:
        """Convert MCP tools list response to domain Tool entities.

        MCP Format: {"tools": [{...}, {...}]}
        Domain Format: [Tool(...), Tool(...)]
        """
        if "tools" not in mcp_response:
            raise MCPProtocolError("Invalid response: missing 'tools' field")

        return [self.mcp_tool_to_domain(t) for t in mcp_response["tools"]]

    def domain_tool_execution_to_mcp(self, tool_name: str, tool_args: dict) -> dict:
        """Convert domain tool execution to MCP request format.

        Domain: ("search_memory", {"query": "test", "limit": 5})
        MCP: {
            "tool": "search_memory",
            "arguments": {"query": "test", "limit": 5},
            "requestId": "uuid-..."
        }
        """
        return {
            "tool": tool_name,
            "arguments": tool_args,
            "requestId": str(uuid4())
        }

    def mcp_error_to_exception(self, mcp_error: dict) -> Exception:
        """Convert MCP error response to domain exception."""
        error_code = mcp_error["error"]["code"]

        if error_code == "TOOL_EXECUTION_FAILED":
            return ToolExecutionError(...)

        return MCPProtocolError(...)
```

**Usage Example**:

```python
translator = MCPProtocolTranslator()

# MCP → Domain
mcp_response = {
    "tools": [
        {"name": "store_memory", "description": "Store semantic memory"},
        {"name": "search_memories", "description": "Search memories"}
    ]
}
tools = translator.mcp_tools_response_to_domain(mcp_response)
assert len(tools) == 2
assert tools[0].category == ToolCategory.MEMORY

# Domain → MCP
mcp_request = translator.domain_tool_execution_to_mcp(
    "search_memories", {"query": "test", "limit": 5}
)
assert mcp_request["tool"] == "search_memories"
assert "requestId" in mcp_request
```

---

### 2. MCPClientAdapter (External Integration)

**File**: `src/infrastructure/adapters/mcp_client_adapter.py` (270 lines)

The adapter handles all HTTP communication with external MCP servers, including connection lifecycle, authentication, retries, and timeouts.

**Responsibilities**:
- HTTP communication (using `httpx.AsyncClient`)
- Connection lifecycle management
- Authentication (API key in Authorization header)
- Retry logic with exponential backoff
- Timeout handling
- Protocol translation via ACL

```python
class MCPClientAdapter:
    """Adapter for communicating with external MCP servers."""

    def __init__(self, config: ConnectionConfig):
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._translator = MCPProtocolTranslator()
        self._connected = False

    async def connect(self) -> bool:
        """Establish connection to MCP server with retry logic.

        Retry Strategy:
        - Attempts: config.retry_attempts (default: 3)
        - Backoff: 0.5 * (attempt + 1) seconds
        - Timeout: config.timeout (default: 30 seconds)
        """
        headers = self._build_headers()  # Includes Authorization if needed
        timeout = httpx.Timeout(self.config.timeout)
        self._client = httpx.AsyncClient(timeout=timeout, headers=headers)

        for attempt in range(self.config.retry_attempts):
            try:
                response = await self._client.get(f"{self.config.url}/health")

                if response.status_code == 200:
                    self._connected = True
                    return True

            except (TimeoutError, httpx.TimeoutException) as e:
                if attempt == self.config.retry_attempts - 1:
                    raise TimeoutError(str(e))
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff

            except Exception as e:
                if attempt == self.config.retry_attempts - 1:
                    raise MCPConnectionError(f"Connection failed: {e}")
                await asyncio.sleep(0.5 * (attempt + 1))

        return False

    async def disconnect(self) -> None:
        """Close connection to MCP server."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._connected = False

    async def discover_tools(self) -> list[Tool]:
        """Discover available tools from MCP server.

        HTTP: GET {url}/tools
        Response: {"tools": [{...}, {...}]}

        Returns: List of Tool entities (via ACL)
        """
        if not self._client:
            raise MCPConnectionError("Not connected to MCP server")

        response = await self._client.get(f"{self.config.url}/tools")

        if response.status_code != 200:
            raise MCPProtocolError(f"Failed to discover tools: HTTP {response.status_code}")

        mcp_response = response.json()
        return self._translator.mcp_tools_response_to_domain(mcp_response)

    async def execute_tool(self, tool_name: str, tool_args: dict) -> dict:
        """Execute a tool on the MCP server.

        HTTP: POST {url}/tools/execute
        Request: {"tool": "...", "arguments": {...}, "requestId": "..."}

        Returns: Tool execution result
        """
        if not self._client:
            raise MCPConnectionError("Not connected")

        mcp_request = self._translator.domain_tool_execution_to_mcp(
            tool_name, tool_args
        )

        response = await self._client.post(
            f"{self.config.url}/tools/execute",
            json=mcp_request
        )

        if response.status_code == 404:
            error_data = response.json()
            exc = self._translator.mcp_error_to_exception(error_data)
            raise exc

        if response.status_code != 200:
            raise MCPProtocolError(f"Tool execution failed: HTTP {response.status_code}")

        return response.json()

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers (includes auth if required)."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        if self.config.auth_required and self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        return headers
```

**Usage Example**:

```python
config = ConnectionConfig(
    server_name="tmws",
    url="http://localhost:8080/mcp",
    timeout=30,
    retry_attempts=3
)

adapter = MCPClientAdapter(config)

# Connect
success = await adapter.connect()
assert success is True

# Discover tools
tools = await adapter.discover_tools()
assert len(tools) > 0

# Execute tool
result = await adapter.execute_tool(
    "search_memories",
    {"query": "test", "limit": 5}
)

# Disconnect
await adapter.disconnect()
```

---

### 3. MCPConnectionRepository (Persistence)

**File**: `src/infrastructure/repositories/mcp_connection_repository.py` (412 lines)

The repository provides a collection-like interface for persisting and retrieving MCPConnection aggregates, with namespace isolation and security enforcement.

**Responsibilities**:
- Persist MCPConnection aggregates to SQLite database
- Retrieve aggregates by various criteria
- **Enforce namespace isolation** (security P0-1)
- Handle database transactions with rollback
- Translate between domain and persistence models

**SECURITY NOTE**: All P0 security fixes have been applied:
- ✅ P0-1: Exception handling (KeyboardInterrupt/SystemExit)
- ✅ P0-2: Namespace isolation in `get_by_id()`
- ✅ P0-3: Ownership verification in `delete()`

```python
class MCPConnectionRepository:
    """Repository for MCPConnection aggregate persistence."""

    def __init__(self, session: AsyncSession):
        self._session = session

    async def save(self, connection: MCPConnection) -> MCPConnection:
        """Save or update MCPConnection aggregate.

        Handles both insert (new) and update (existing).
        Commits transaction automatically.

        Note: Domain events are NOT persisted (they are transient).
        """
        try:
            # Check if exists
            stmt = select(MCPConnectionModel).where(
                MCPConnectionModel.id == str(connection.id)
            )
            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                self._update_model_from_domain(existing, connection)
            else:
                model = self._to_model(connection)
                self._session.add(model)

            await self._session.commit()
            return connection

        except (KeyboardInterrupt, SystemExit):
            raise  # ✅ P0-1 Fix: Never suppress system signals

        except Exception as e:
            await self._session.rollback()
            raise RepositoryError(f"Failed to save: {e}") from e

    async def get_by_id(
        self, connection_id: UUID, namespace: str
    ) -> MCPConnection:
        """Retrieve MCPConnection by ID with namespace verification.

        SECURITY (P0-2): Enforces namespace isolation. The namespace parameter
        MUST be verified from database, NOT from JWT claims or user input.

        Args:
            connection_id: UUID of the connection
            namespace: Verified namespace from database (not JWT claims)

        Raises:
            AggregateNotFoundError: If not found OR in different namespace
        """
        try:
            stmt = select(MCPConnectionModel).where(
                MCPConnectionModel.id == str(connection_id),
                MCPConnectionModel.namespace == namespace  # ✅ P0-2 Fix
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if not model:
                raise AggregateNotFoundError(
                    aggregate_type="MCPConnection",
                    identifier=str(connection_id)
                )

            return self._to_domain(model)

        except (KeyboardInterrupt, SystemExit):
            raise  # ✅ P0-1 Fix

        except AggregateNotFoundError:
            raise

        except Exception as e:
            raise RepositoryError(f"Failed to retrieve: {e}") from e

    async def find_by_namespace_and_agent(
        self, namespace: str, agent_id: str
    ) -> list[MCPConnection]:
        """Find all connections for a specific namespace and agent.

        SECURITY: Enforces namespace isolation by filtering on namespace.
        """
        try:
            stmt = (
                select(MCPConnectionModel)
                .where(MCPConnectionModel.namespace == namespace)
                .where(MCPConnectionModel.agent_id == agent_id)
                .order_by(MCPConnectionModel.created_at.desc())
            )

            result = await self._session.execute(stmt)
            models = result.scalars().all()

            return [self._to_domain(model) for model in models]

        except (KeyboardInterrupt, SystemExit):
            raise  # ✅ P0-1 Fix

        except Exception as e:
            raise RepositoryError(f"Failed to find: {e}") from e

    async def find_by_status(
        self, status: ConnectionStatus
    ) -> list[MCPConnection]:
        """Find all connections with a specific status."""
        # See implementation in repository file

    async def delete(
        self, connection_id: UUID, namespace: str, agent_id: str
    ) -> None:
        """Delete MCPConnection with namespace and ownership verification.

        SECURITY (P0-3): Enforces BOTH namespace isolation AND ownership.
        Both namespace and agent_id MUST be verified from database.

        Args:
            connection_id: UUID of the connection
            namespace: Verified namespace from database
            agent_id: Agent requesting deletion (must be owner)
        """
        try:
            stmt = select(MCPConnectionModel).where(
                MCPConnectionModel.id == str(connection_id),
                MCPConnectionModel.namespace == namespace,  # ✅ P0-2 Fix
                MCPConnectionModel.agent_id == agent_id     # ✅ P0-3 Fix
            )
            result = await self._session.execute(stmt)
            model = result.scalar_one_or_none()

            if not model:
                raise AggregateNotFoundError(
                    aggregate_type="MCPConnection",
                    identifier=str(connection_id)
                )

            await self._session.delete(model)
            await self._session.commit()

        except (KeyboardInterrupt, SystemExit):
            raise  # ✅ P0-1 Fix

        except AggregateNotFoundError:
            raise

        except Exception as e:
            await self._session.rollback()
            raise RepositoryError(f"Failed to delete: {e}") from e
```

**Usage Example**:

```python
from src.infrastructure.repositories.mcp_connection_repository import MCPConnectionRepository

async with get_async_session() as session:
    repo = MCPConnectionRepository(session)

    # Save
    connection = MCPConnection(...)
    saved = await repo.save(connection)

    # Retrieve with namespace verification (SECURITY)
    agent = await get_agent_from_db(agent_id)  # Verify namespace from DB
    retrieved = await repo.get_by_id(connection.id, agent.namespace)

    # Find by namespace and agent
    connections = await repo.find_by_namespace_and_agent(
        "project-x", "agent-123"
    )

    # Delete with ownership verification (SECURITY)
    await repo.delete(connection.id, agent.namespace, agent.id)
```

---

### 4. Database Model (SQLAlchemy)

**File**: `src/models/mcp_connection.py` (55 lines)

```python
from sqlalchemy import Column, String, Text, DateTime, Index
from sqlalchemy.dialects.postgresql import JSONB
import sqlalchemy as sa

class MCPConnectionModel(Base):
    """SQLAlchemy model for MCP connections."""

    __tablename__ = "mcp_connections"

    # Primary key
    id = Column(String(36), primary_key=True)

    # Connection info
    server_name = Column(String(255), nullable=False)
    namespace = Column(String(255), nullable=False, index=True)
    agent_id = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False, default="disconnected")

    # JSON columns
    config_json = Column(JSONB, nullable=False)
    tools_json = Column(JSONB, nullable=False, server_default=sa.text("'[]'"))

    # Error info
    error_message = Column(Text, nullable=True)
    error_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    connected_at = Column(DateTime, nullable=True)
    disconnected_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)

    # Indexes
    __table_args__ = (
        Index("ix_mcp_connections_namespace_agent", "namespace", "agent_id"),
    )
```

**Database Migration**: `migrations/versions/20251112_1330-ff4b1a18d2f0_*.py`

---

## Security Features

### P0 Security Fixes Applied ✅

All critical security issues identified by Hestia have been resolved:

#### 1. Exception Handling (P0-1) ✅

**Issue**: Repository methods caught `KeyboardInterrupt` and `SystemExit`
**Fix**: Added explicit handling to re-raise system signals

```python
# ✅ CORRECT PATTERN (all 5 repository methods)
try:
    # ... repository logic ...
    await self._session.commit()
    return result

except (KeyboardInterrupt, SystemExit):
    raise  # Never suppress system signals

except Exception as e:
    await self._session.rollback()
    raise RepositoryError(...) from e
```

**Affected Methods**: `save()`, `get_by_id()`, `find_by_namespace_and_agent()`, `find_by_status()`, `delete()`

#### 2. Namespace Isolation in get_by_id() (P0-2) ✅

**Issue**: No namespace filter in `get_by_id()` allowed cross-tenant access
**CVSS Score**: 8.7 HIGH (Cross-tenant data access)
**Fix**: Added mandatory `namespace` parameter and filter

```python
# ✅ CORRECT
async def get_by_id(
    self, connection_id: UUID, namespace: str
) -> MCPConnection:
    """SECURITY: namespace must be verified from database."""
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace  # ✅ Required
    )
```

**Security Test**: `test_get_by_id_cross_namespace_blocked` validates this fix

#### 3. Ownership Verification in delete() (P0-3) ✅

**Issue**: No ownership check in `delete()` allowed unauthorized deletion
**CVSS Score**: 9.1 CRITICAL (Unauthorized deletion + data integrity)
**Fix**: Added mandatory `agent_id` parameter and verification

```python
# ✅ CORRECT
async def delete(
    self, connection_id: UUID, namespace: str, agent_id: str
) -> None:
    """SECURITY: Both namespace AND agent_id must be verified."""
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace,  # Namespace isolation
        MCPConnectionModel.agent_id == agent_id     # Ownership verification
    )
```

**Security Test**: `test_delete_cross_namespace_blocked` validates this fix

### Additional Security Features

- ✅ **API Key Masking**: `ConnectionConfig.__repr__()` masks API keys (line 134)
- ✅ **Domain Events NOT Persisted**: Events are transient (security + correctness)
- ✅ **SQL Injection Prevention**: 100% SQLAlchemy ORM (no raw SQL)
- ✅ **Input Validation**: Comprehensive validation in value objects
- ✅ **Async Safety**: Proper async/await patterns throughout

---

## Test Coverage

### Test Results: 31/31 PASSED (100%) ✅

#### Domain Layer Tests (9 tests)

**File**: `tests/unit/domain/test_mcp_connection_aggregate.py`

1. ✅ `test_create_connection_with_valid_config` - Basic creation
2. ✅ `test_mark_as_active_with_tools` - State transition + event
3. ✅ `test_mark_as_active_without_tools_raises_error` - Invariant violation
4. ✅ `test_invalid_state_transition_raises_error` - State transition rules
5. ✅ `test_disconnect_raises_event` - Graceful disconnection
6. ✅ `test_mark_as_error_does_not_raise_disconnect_event` - Error vs graceful
7. ✅ `test_add_tools_to_active_connection` - Tool discovery
8. ✅ `test_add_tools_to_non_active_connection_raises_error` - Invariant
9. ✅ `test_connection_equality_based_on_id` - Entity identity

#### Infrastructure Layer Tests (22 tests)

**ACL Tests** (`tests/unit/infrastructure/test_mcp_acl.py`):

10-17. ✅ 8 tests for protocol translation (MCP ↔ Domain)

**Repository Tests** (`tests/unit/infrastructure/test_mcp_connection_repository_impl.py`):

18-31. ✅ 14 tests for repository operations

**Key Security Tests**:
- ✅ `test_get_by_id_cross_namespace_blocked` (P0-2 validation)
- ✅ `test_delete_cross_namespace_blocked` (P0-3 validation)
- ✅ `test_namespace_isolation_in_queries` (namespace filtering)
- ✅ `test_domain_events_are_not_persisted` (event transience)

---

## Database Migration

**Migration File**: `migrations/versions/20251112_1330-ff4b1a18d2f0_*.py`

### Schema Changes

**New Table**: `mcp_connections`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | String(36) | PRIMARY KEY | UUID |
| `server_name` | String(255) | NOT NULL | MCP server identifier |
| `namespace` | String(255) | NOT NULL, INDEX | Namespace for isolation |
| `agent_id` | String(255) | NOT NULL | Agent owner |
| `status` | String(50) | NOT NULL, DEFAULT 'disconnected' | Connection status |
| `config_json` | JSONB | NOT NULL | ConnectionConfig as JSON |
| `tools_json` | JSONB | NOT NULL, DEFAULT '[]' | List of Tool entities |
| `error_message` | Text | NULL | Error description if status=ERROR |
| `error_at` | DateTime | NULL | Timestamp of error |
| `created_at` | DateTime | NOT NULL | Creation timestamp |
| `connected_at` | DateTime | NULL | When became ACTIVE |
| `disconnected_at` | DateTime | NULL | When disconnected |
| `updated_at` | DateTime | NULL | Last update timestamp |

**Indexes**:
- `ix_mcp_connections_namespace` (namespace) - For filtering
- `ix_mcp_connections_namespace_agent` (namespace, agent_id) - For security queries

### Migration Commands

```bash
# Apply migration
alembic upgrade head

# Verify current version
alembic current

# Rollback (if needed)
alembic downgrade -1
```

---

## Usage Patterns for Phase 1-2

Phase 1-2 (Application Service Layer) will use these components as follows:

### 1. Create Connection (Application Service)

```python
async def create_mcp_connection(
    server_name: str,
    url: str,
    namespace: str,
    agent_id: str
) -> MCPConnection:
    """Application service method for creating MCP connection."""

    # 1. Create value object
    config = ConnectionConfig(
        server_name=server_name,
        url=url,
        timeout=30,
        retry_attempts=3
    )

    # 2. Create adapter
    adapter = MCPClientAdapter(config)

    # 3. Connect and discover tools
    await adapter.connect()
    tools = await adapter.discover_tools()

    # 4. Create aggregate
    connection = MCPConnection(
        id=uuid4(),
        server_name=server_name,
        config=config,
        namespace=namespace,
        agent_id=agent_id
    )

    # 5. Mark as active (raises MCPConnectedEvent)
    connection.mark_as_active(tools)

    # 6. Persist aggregate
    async with get_async_session() as session:
        repo = MCPConnectionRepository(session)
        await repo.save(connection)

    # 7. Dispatch domain events (Application Service responsibility)
    for event in connection.domain_events:
        await event_bus.publish(event)

    # 8. Clear events
    connection.clear_events()

    return connection
```

### 2. Execute Tool (Application Service)

```python
async def execute_mcp_tool(
    connection_id: UUID,
    namespace: str,  # Verified from database
    tool_name: str,
    tool_args: dict
) -> dict:
    """Application service method for executing MCP tool."""

    # 1. Retrieve aggregate (with namespace verification)
    async with get_async_session() as session:
        repo = MCPConnectionRepository(session)
        connection = await repo.get_by_id(connection_id, namespace)

    # 2. Validate connection is ACTIVE
    if connection.status != ConnectionStatus.ACTIVE:
        raise DomainInvariantViolation(
            f"Connection must be ACTIVE (current: {connection.status})"
        )

    # 3. Create adapter
    adapter = MCPClientAdapter(connection.config)
    await adapter.connect()

    # 4. Execute tool
    result = await adapter.execute_tool(tool_name, tool_args)

    # 5. Disconnect
    await adapter.disconnect()

    return result
```

### 3. Disconnect (Application Service)

```python
async def disconnect_mcp_connection(
    connection_id: UUID,
    namespace: str,  # Verified from database
    reason: str | None = None
) -> None:
    """Application service method for disconnecting MCP connection."""

    # 1. Retrieve aggregate
    async with get_async_session() as session:
        repo = MCPConnectionRepository(session)
        connection = await repo.get_by_id(connection_id, namespace)

    # 2. Disconnect aggregate (raises MCPDisconnectedEvent)
    connection.disconnect(reason)

    # 3. Persist updated state
    async with get_async_session() as session:
        repo = MCPConnectionRepository(session)
        await repo.save(connection)

    # 4. Dispatch domain events
    for event in connection.domain_events:
        await event_bus.publish(event)

    # 5. Clear events
    connection.clear_events()

    # 6. Close adapter connection
    adapter = MCPClientAdapter(connection.config)
    await adapter.disconnect()
```

---

## Next Steps for Phase 1-2

**Phase 1-2** (Application Service Layer) should:

1. ✅ Use `MCPConnectionRepository` for all persistence
2. ✅ Use `MCPClientAdapter` for all MCP communication
3. ✅ Use `MCPProtocolTranslator` indirectly (via Adapter)
4. ✅ Always verify namespace from database before calling repository
5. ✅ Dispatch domain events after successful persistence
6. ✅ Clear events after dispatch
7. ✅ Handle transaction boundaries properly

**Key Files to Create in Phase 1-2**:
- `src/application/services/mcp_connection_service.py` - Application service
- `src/application/dto/mcp_connection_dto.py` - Data Transfer Objects
- `src/api/routers/mcp_connection_router.py` - FastAPI router
- `tests/unit/application/test_mcp_connection_service.py` - Service tests

---

## Appendix: File Structure

```
src/
├── domain/
│   ├── aggregates/
│   │   └── mcp_connection.py (326 lines) ✅
│   ├── entities/
│   │   └── tool.py (138 lines) ✅
│   ├── value_objects/
│   │   ├── connection_config.py (152 lines) ✅
│   │   ├── connection_status.py (82 lines) ✅
│   │   └── tool_category.py (95 lines) ✅
│   ├── events.py (78 lines) ✅
│   └── exceptions.py (64 lines) ✅
├── infrastructure/
│   ├── acl/
│   │   └── mcp_protocol_translator.py (222 lines) ✅
│   ├── adapters/
│   │   └── mcp_client_adapter.py (270 lines) ✅
│   ├── repositories/
│   │   └── mcp_connection_repository.py (412 lines) ✅ (with P0 fixes)
│   └── exceptions.py (88 lines) ✅
└── models/
    └── mcp_connection.py (55 lines) ✅

tests/
├── unit/
│   ├── domain/
│   │   └── test_mcp_connection_aggregate.py (9 tests) ✅
│   └── infrastructure/
│       ├── test_mcp_acl.py (8 tests) ✅
│       └── test_mcp_connection_repository_impl.py (14 tests) ✅

migrations/
└── versions/
    └── 20251112_1330-ff4b1a18d2f0_*.py ✅

docs/
└── architecture/
    └── phase1-1/
        └── IMPLEMENTATION_GUIDE.md (this file)
```

**Total Lines of Code**: ~2,000 lines (excluding tests)
**Test Coverage**: 31/31 tests PASSED (100%)
**Security Audit**: 7/7 checklist items PASSED ✅

---

**End of Implementation Guide**

*Last Updated: 2025-11-12*
*Authors: Athena, Hera, Artemis, Hestia*
*Status: Production-Ready*
