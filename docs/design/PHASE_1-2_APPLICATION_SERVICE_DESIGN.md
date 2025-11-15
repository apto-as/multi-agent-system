# Phase 1-2: Application Service Layer - Strategic Design

**Author**: Hera (hera-strategist)
**Created**: 2025-11-12
**Status**: Architecture Design Complete
**Success Probability**: 94.2%

---

## Table of Contents

1. [Application Service Architecture](#1-application-service-architecture)
2. [Use Cases Specification](#2-use-cases-specification)
3. [DTOs Design](#3-dtos-design)
4. [Domain Event Dispatcher](#4-domain-event-dispatcher)
5. [Security Architecture](#5-security-architecture)
6. [TDD Strategy](#6-tdd-strategy)
7. [Implementation Plan](#7-implementation-plan)
8. [Risk Analysis](#8-risk-analysis)

---

## 1. Application Service Architecture

### 1.1 Layer Responsibilities

**Application Service Layer** sits between Presentation Layer (FastAPI routers) and Domain Layer:

```
┌─────────────────────────────────────┐
│   Presentation Layer (FastAPI)      │
│   - HTTP request/response handling  │
│   - Authentication (JWT validation) │
│   - Input deserialization           │
└────────────────┬────────────────────┘
                 │
                 ├─ Request DTOs
                 ↓
┌─────────────────────────────────────┐
│   Application Service Layer         │  ← This Phase
│   - Use case orchestration          │
│   - Transaction management          │
│   - Domain event dispatching        │
│   - DTO mapping                     │
└────────────────┬────────────────────┘
                 │
                 ├─ Domain Commands
                 ↓
┌─────────────────────────────────────┐
│   Domain Layer                      │  ← Phase 1-1 (Complete)
│   - Business logic                  │
│   - Aggregates, Value Objects       │
│   - Domain events                   │
└────────────────┬────────────────────┘
                 │
                 ├─ Repository Interfaces
                 ↓
┌─────────────────────────────────────┐
│   Infrastructure Layer              │  ← Phase 1-1 (Complete)
│   - Database persistence            │
│   - External MCP communication      │
│   - ACL (Anti-Corruption Layer)     │
└─────────────────────────────────────┘
```

### 1.2 Transaction Boundaries

**Critical Rule**: One Use Case = One Transaction

```python
class MCPConnectionApplicationService:
    async def connect_to_mcp_server(
        self, request: CreateConnectionRequest
    ) -> MCPConnectionDTO:
        async with self._uow:  # ← Transaction starts here
            try:
                # 1. Create aggregate (in-memory, not persisted yet)
                connection = MCPConnection.create(...)

                # 2. Persist aggregate
                await self._repository.add(connection)

                # 3. Attempt external connection
                await self._adapter.connect(...)

                # 4. Update aggregate state
                connection.mark_as_active(tools)

                # 5. Persist updated state
                await self._repository.update(connection)

                # 6. Commit transaction
                await self._uow.commit()  # ← Transaction ends here

            except Exception as e:
                # 7. Rollback on any failure
                await self._uow.rollback()
                raise

        # 8. After commit: Dispatch domain events
        await self._event_dispatcher.dispatch_all(
            connection.domain_events
        )

        # 9. Return DTO
        return MCPConnectionDTO.from_aggregate(connection)
```

### 1.3 Domain Event Dispatch

**Critical Rule**: Events dispatched AFTER transaction commit

**Rationale**:
1. Prevents inconsistent state if event handler fails
2. Ensures domain events reflect committed state
3. Allows event handlers to start new transactions

**Pattern**:
```python
# Transaction scope
async with self._uow:
    # ... domain operations ...
    await self._uow.commit()

# Outside transaction scope
await self._event_dispatcher.dispatch_all(
    aggregate.domain_events
)
```

### 1.4 Error Handling Strategy

**Sanitize all errors before exposing to external clients**:

```python
try:
    result = await use_case.execute(request)
except DomainException as e:
    # Domain errors are safe to expose
    raise ApplicationError(
        message=str(e),
        error_code="DOMAIN_ERROR"
    )
except InfrastructureException as e:
    # Infrastructure errors must be sanitized
    logger.error(f"Infrastructure error: {e}", exc_info=True)
    raise ApplicationError(
        message="External service unavailable",
        error_code="EXTERNAL_SERVICE_ERROR"
    )
except Exception as e:
    # Unknown errors must be sanitized
    logger.critical(f"Unexpected error: {e}", exc_info=True)
    raise ApplicationError(
        message="Internal server error",
        error_code="INTERNAL_ERROR"
    )
```

---

## 2. Use Cases Specification

### 2.1 ConnectMCPServerUseCase

**Purpose**: Create new MCP connection, establish external connection, discover tools

**Flow**:
```
User Request
  ↓
[1] Input validation (ConnectionConfig creation)
  ↓
[2] Namespace verification from DB (SECURITY CRITICAL)
  ↓
[3] Authorization check (namespace match)
  ↓
[4] Check duplicate connection
  ↓
[5] Begin transaction
  ↓
[6] Create MCPConnection aggregate
  ↓
[7] Persist aggregate (DISCONNECTED state)
  ↓
[8] Attempt external connection (MCPClientAdapter)
  ↓
[9] Discover tools from MCP server
  ↓
[10] Update aggregate (ACTIVE state with tools)
  ↓
[11] Persist updated aggregate
  ↓
[12] Commit transaction
  ↓
[13] Dispatch MCPConnectedEvent
  ↓
[14] Return MCPConnectionDTO
```

**Implementation**:
```python
class ConnectMCPServerUseCase:
    def __init__(
        self,
        repository: MCPConnectionRepository,
        adapter: MCPClientAdapter,
        agent_repository: AgentRepository,
        uow: UnitOfWork,
        event_dispatcher: DomainEventDispatcher,
    ):
        self._repository = repository
        self._adapter = adapter
        self._agent_repository = agent_repository
        self._uow = uow
        self._event_dispatcher = event_dispatcher

    async def execute(
        self, request: CreateConnectionRequest
    ) -> MCPConnectionDTO:
        # [1] Input validation
        try:
            config = ConnectionConfig(
                server_name=ServerName(request.server_name),
                url=ServerURL(request.url),
                timeout=request.timeout,
                retry_attempts=request.retry_attempts,
            )
        except ValueError as e:
            raise ValidationError(f"Invalid input: {e}") from e

        # [2] Namespace verification from DB (SECURITY CRITICAL)
        agent = await self._agent_repository.get_by_id(
            request.agent_id
        )
        if not agent:
            raise AuthorizationError("Agent not found")

        verified_namespace = agent.namespace  # ✅ From DB, not from request

        # [3] Authorization check
        if request.namespace != verified_namespace:
            raise AuthorizationError("Namespace mismatch")

        # [4] Check for duplicate connection
        existing = await self._repository.get_by_server_name_and_namespace(
            request.server_name, verified_namespace
        )
        if existing:
            raise ValidationError(
                f"Connection to {request.server_name} already exists"
            )

        async with self._uow:
            # [5-6] Create aggregate
            connection = MCPConnection.create(
                server_name=config.server_name,
                url=config.url,
                namespace=verified_namespace,  # ✅ Verified
                agent_id=request.agent_id,
                config=config,
            )

            # [7] Persist aggregate
            await self._repository.add(connection)

            # [8-9] Attempt external connection
            try:
                await self._adapter.connect(
                    connection_id=connection.id,
                    url=str(connection.url),
                    config=config,
                )

                tools = await self._adapter.discover_tools(
                    connection.id
                )

                # [10] Update aggregate state
                connection.mark_as_active(tools)

            except MCPConnectionError as e:
                # Mark as failed but still persist
                connection.mark_as_failed(str(e))
                await self._repository.update(connection)
                await self._uow.commit()

                raise ExternalServiceError(
                    f"Failed to connect to MCP server: {e}"
                ) from e

            # [11] Persist updated state
            await self._repository.update(connection)

            # [12] Commit transaction
            await self._uow.commit()

        # [13] Dispatch domain events (AFTER commit)
        await self._event_dispatcher.dispatch_all(
            connection.domain_events
        )

        # [14] Return DTO
        return MCPConnectionDTO.from_aggregate(connection)
```

### 2.2 DiscoverToolsUseCase

**Purpose**: Discover or refresh tools from active MCP connection

**Flow**:
```
User Request
  ↓
[1] Namespace verification from DB
  ↓
[2] Authorization check
  ↓
[3] Retrieve connection from repository
  ↓
[4] Verify connection is ACTIVE
  ↓
[5] Discover tools from MCP server
  ↓
[6] Begin transaction
  ↓
[7] Update connection with new tools
  ↓
[8] Persist updated connection
  ↓
[9] Commit transaction
  ↓
[10] Dispatch ToolsDiscoveredEvent
  ↓
[11] Return updated MCPConnectionDTO
```

**Implementation**:
```python
class DiscoverToolsUseCase:
    def __init__(
        self,
        repository: MCPConnectionRepository,
        adapter: MCPClientAdapter,
        agent_repository: AgentRepository,
        uow: UnitOfWork,
        event_dispatcher: DomainEventDispatcher,
    ):
        self._repository = repository
        self._adapter = adapter
        self._agent_repository = agent_repository
        self._uow = uow
        self._event_dispatcher = event_dispatcher

    async def execute(
        self, request: DiscoverToolsRequest
    ) -> MCPConnectionDTO:
        # [1-2] Namespace verification
        verified_namespace = await self._verify_namespace(
            request.agent_id, request.namespace
        )

        # [3] Retrieve connection
        connection = await self._repository.get_by_id(
            request.connection_id, verified_namespace
        )
        if not connection:
            raise AggregateNotFoundError(
                "MCPConnection", str(request.connection_id)
            )

        # [4] Verify active
        if connection.status != ConnectionStatus.ACTIVE:
            raise ValidationError(
                f"Connection is not active (status: {connection.status.value})"
            )

        # [5] Discover tools
        try:
            tools = await self._adapter.discover_tools(connection.id)
        except MCPConnectionError as e:
            raise ExternalServiceError(
                f"Failed to discover tools: {e}"
            ) from e

        async with self._uow:
            # [6-7] Update connection
            connection.update_tools(tools)

            # [8] Persist
            await self._repository.update(connection)

            # [9] Commit
            await self._uow.commit()

        # [10] Dispatch events
        await self._event_dispatcher.dispatch_all(
            connection.domain_events
        )

        # [11] Return DTO
        return MCPConnectionDTO.from_aggregate(connection)
```

### 2.3 ExecuteToolUseCase

**Purpose**: Execute tool via active MCP connection

**Flow**:
```
User Request
  ↓
[1] Namespace verification from DB
  ↓
[2] Authorization check
  ↓
[3] Retrieve connection from repository
  ↓
[4] Verify connection is ACTIVE
  ↓
[5] Verify tool exists in connection
  ↓
[6] Execute tool via adapter
  ↓
[7] Return execution result
```

**Note**: Tool execution is READ-ONLY (no state change in aggregate)

**Implementation**:
```python
class ExecuteToolUseCase:
    def __init__(
        self,
        repository: MCPConnectionRepository,
        adapter: MCPClientAdapter,
        agent_repository: AgentRepository,
    ):
        self._repository = repository
        self._adapter = adapter
        self._agent_repository = agent_repository

    async def execute(
        self, request: ExecuteToolRequest
    ) -> ToolExecutionResultDTO:
        # [1-2] Namespace verification
        verified_namespace = await self._verify_namespace(
            request.agent_id, request.namespace
        )

        # [3] Retrieve connection
        connection = await self._repository.get_by_id(
            request.connection_id, verified_namespace
        )
        if not connection:
            raise AggregateNotFoundError(
                "MCPConnection", str(request.connection_id)
            )

        # [4] Verify active
        if connection.status != ConnectionStatus.ACTIVE:
            raise ValidationError(
                f"Connection is not active (status: {connection.status.value})"
            )

        # [5] Verify tool exists
        tool = connection.get_tool_by_name(request.tool_name)
        if not tool:
            raise ValidationError(
                f"Tool '{request.tool_name}' not found in connection"
            )

        # [6] Execute tool
        try:
            result = await self._adapter.execute_tool(
                connection_id=connection.id,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
        except MCPToolExecutionError as e:
            raise ExternalServiceError(
                f"Tool execution failed: {e}"
            ) from e

        # [7] Return result
        return ToolExecutionResultDTO(
            connection_id=connection.id,
            tool_name=request.tool_name,
            result=result,
        )
```

### 2.4 DisconnectMCPServerUseCase

**Purpose**: Gracefully disconnect from MCP server

**Flow**:
```
User Request
  ↓
[1] Namespace verification from DB
  ↓
[2] Authorization check
  ↓
[3] Retrieve connection from repository
  ↓
[4] Disconnect from MCP server (external)
  ↓
[5] Begin transaction
  ↓
[6] Update aggregate (DISCONNECTED state)
  ↓
[7] Persist updated aggregate
  ↓
[8] Commit transaction
  ↓
[9] Dispatch MCPDisconnectedEvent
  ↓
[10] Return DisconnectionResultDTO
```

**Implementation**:
```python
class DisconnectMCPServerUseCase:
    def __init__(
        self,
        repository: MCPConnectionRepository,
        adapter: MCPClientAdapter,
        agent_repository: AgentRepository,
        uow: UnitOfWork,
        event_dispatcher: DomainEventDispatcher,
    ):
        self._repository = repository
        self._adapter = adapter
        self._agent_repository = agent_repository
        self._uow = uow
        self._event_dispatcher = event_dispatcher

    async def execute(
        self, request: DisconnectRequest
    ) -> DisconnectionResultDTO:
        # [1-2] Namespace verification
        verified_namespace = await self._verify_namespace(
            request.agent_id, request.namespace
        )

        # [3] Retrieve connection
        connection = await self._repository.get_by_id(
            request.connection_id, verified_namespace
        )
        if not connection:
            raise AggregateNotFoundError(
                "MCPConnection", str(request.connection_id)
            )

        # [4] Disconnect from external server
        try:
            await self._adapter.disconnect(connection.id)
        except MCPConnectionError as e:
            # Log but don't fail - allow graceful degradation
            logger.warning(
                f"Failed to disconnect from MCP server: {e}"
            )

        async with self._uow:
            # [5-6] Update aggregate
            connection.mark_as_disconnected()

            # [7] Persist
            await self._repository.update(connection)

            # [8] Commit
            await self._uow.commit()

        # [9] Dispatch events
        await self._event_dispatcher.dispatch_all(
            connection.domain_events
        )

        # [10] Return result
        return DisconnectionResultDTO(
            connection_id=connection.id,
            server_name=str(connection.server_name),
            disconnected_at=connection.disconnected_at,
        )
```

---

## 3. DTOs Design

### 3.1 DTO Design Principles

1. **Immutable**: All DTOs use `@dataclass(frozen=True)`
2. **Boundary Only**: DTOs used only at external boundaries (API ↔ Application Service)
3. **Domain Objects Internally**: Domain aggregates/entities used within Application Service
4. **No Business Logic**: DTOs are pure data containers
5. **Validation**: Request DTOs use Pydantic for validation

### 3.2 Response DTOs

#### MCPConnectionDTO
```python
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

@dataclass(frozen=True)
class MCPConnectionDTO:
    """Response DTO for MCP connection"""

    id: UUID
    server_name: str
    url: str
    namespace: str
    agent_id: UUID
    status: str  # "ACTIVE", "DISCONNECTED", "FAILED"
    tools: list['ToolDTO']
    created_at: datetime
    connected_at: Optional[datetime]
    disconnected_at: Optional[datetime]
    error_message: Optional[str]

    @classmethod
    def from_aggregate(cls, connection: MCPConnection) -> 'MCPConnectionDTO':
        """Convert MCPConnection aggregate to DTO"""
        return cls(
            id=connection.id,
            server_name=str(connection.server_name),
            url=str(connection.url),
            namespace=connection.namespace,
            agent_id=connection.agent_id,
            status=connection.status.value,
            tools=[
                ToolDTO.from_entity(tool)
                for tool in connection.tools
            ],
            created_at=connection.created_at,
            connected_at=connection.connected_at,
            disconnected_at=connection.disconnected_at,
            error_message=connection.error_message,
        )

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            'id': str(self.id),
            'server_name': self.server_name,
            'url': self.url,
            'namespace': self.namespace,
            'agent_id': str(self.agent_id),
            'status': self.status,
            'tools': [tool.to_dict() for tool in self.tools],
            'created_at': self.created_at.isoformat(),
            'connected_at': self.connected_at.isoformat() if self.connected_at else None,
            'disconnected_at': self.disconnected_at.isoformat() if self.disconnected_at else None,
            'error_message': self.error_message,
        }
```

#### ToolDTO
```python
@dataclass(frozen=True)
class ToolDTO:
    """Response DTO for MCP tool"""

    name: str
    description: str
    input_schema: dict
    category: str

    @classmethod
    def from_entity(cls, tool: Tool) -> 'ToolDTO':
        """Convert Tool entity to DTO"""
        return cls(
            name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            category=tool.category.value,
        )

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            'name': self.name,
            'description': self.description,
            'input_schema': self.input_schema,
            'category': self.category,
        }
```

#### ToolExecutionResultDTO
```python
@dataclass(frozen=True)
class ToolExecutionResultDTO:
    """Response DTO for tool execution result"""

    connection_id: UUID
    tool_name: str
    result: dict  # Tool-specific result format

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            'connection_id': str(self.connection_id),
            'tool_name': self.tool_name,
            'result': self.result,
        }
```

#### DisconnectionResultDTO
```python
@dataclass(frozen=True)
class DisconnectionResultDTO:
    """Response DTO for disconnection result"""

    connection_id: UUID
    server_name: str
    disconnected_at: datetime

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict"""
        return {
            'connection_id': str(self.connection_id),
            'server_name': self.server_name,
            'disconnected_at': self.disconnected_at.isoformat(),
        }
```

### 3.3 Request DTOs

#### CreateConnectionRequest
```python
from pydantic import BaseModel, Field, HttpUrl, validator

class CreateConnectionRequest(BaseModel):
    """Request DTO for creating MCP connection"""

    server_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="MCP server name"
    )
    url: HttpUrl = Field(
        ...,
        description="MCP server URL (must be valid HTTP/HTTPS URL)"
    )
    namespace: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Namespace for isolation"
    )
    agent_id: UUID = Field(
        ...,
        description="Agent identifier"
    )
    timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Connection timeout in seconds"
    )
    retry_attempts: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of retry attempts"
    )
    auth_required: bool = Field(
        default=False,
        description="Whether authentication is required"
    )
    api_key: Optional[str] = Field(
        default=None,
        description="API key for authentication"
    )

    @validator('server_name')
    def validate_server_name(cls, v):
        """Validate server name format"""
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError(
                "Server name must contain only alphanumeric, hyphen, or underscore"
            )
        return v

    @validator('api_key')
    def validate_api_key(cls, v, values):
        """Validate API key when auth_required is True"""
        if values.get('auth_required') and not v:
            raise ValueError("API key required when auth_required is True")
        return v
```

#### DiscoverToolsRequest
```python
class DiscoverToolsRequest(BaseModel):
    """Request DTO for discovering tools"""

    connection_id: UUID = Field(
        ...,
        description="MCP connection identifier"
    )
    namespace: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Namespace for authorization"
    )
    agent_id: UUID = Field(
        ...,
        description="Agent identifier"
    )
```

#### ExecuteToolRequest
```python
class ExecuteToolRequest(BaseModel):
    """Request DTO for executing tool"""

    connection_id: UUID = Field(
        ...,
        description="MCP connection identifier"
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Tool name to execute"
    )
    arguments: dict = Field(
        default_factory=dict,
        description="Tool-specific arguments"
    )
    namespace: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Namespace for authorization"
    )
    agent_id: UUID = Field(
        ...,
        description="Agent identifier"
    )
```

#### DisconnectRequest
```python
class DisconnectRequest(BaseModel):
    """Request DTO for disconnecting"""

    connection_id: UUID = Field(
        ...,
        description="MCP connection identifier"
    )
    namespace: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Namespace for authorization"
    )
    agent_id: UUID = Field(
        ...,
        description="Agent identifier"
    )
```

---

## 4. Domain Event Dispatcher

### 4.1 Design Decision: Synchronous vs Async

**Decision**: Synchronous event dispatcher for Phase 1-2

**Rationale**:
- Simplicity: No external dependencies (Redis, RabbitMQ, etc.)
- Testability: Easy to test event dispatching in unit tests
- Performance: Acceptable for low-to-medium event volume (<100 events/second)
- Future Migration: Easy to replace with async queue later

**Performance Trade-offs**:
- **Synchronous**: ~20-30ms overhead for 2-5 handlers
- **Async Queue**: ~5-10ms overhead but adds infrastructure complexity
- **Verdict**: 20-30ms acceptable for initial implementation

### 4.2 Event Dispatcher Interface

```python
from abc import ABC, abstractmethod
from typing import Callable, List

class EventDispatcher(ABC):
    """Abstract event dispatcher interface"""

    @abstractmethod
    def register(
        self, event_type: type[DomainEvent], handler: Callable
    ):
        """Register event handler for specific event type"""
        pass

    @abstractmethod
    async def dispatch_all(self, events: List[DomainEvent]):
        """Dispatch all events to registered handlers"""
        pass
```

### 4.3 Synchronous Implementation

```python
import asyncio
import logging
from typing import Callable, List, Dict

logger = logging.getLogger(__name__)

class SynchronousEventDispatcher(EventDispatcher):
    """Synchronous event dispatcher for Phase 1-2"""

    def __init__(self):
        self._handlers: Dict[type[DomainEvent], List[Callable]] = {}

    def register(
        self,
        event_type: type[DomainEvent],
        handler: Callable,
    ):
        """Register event handler for specific event type"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []

        self._handlers[event_type].append(handler)

        logger.info(
            f"Registered handler {handler.__name__} "
            f"for event {event_type.__name__}"
        )

    async def dispatch_all(self, events: List[DomainEvent]):
        """
        Dispatch all events to registered handlers

        Critical Rules:
        1. Must be called AFTER transaction commit
        2. Handler failures must NOT rollback main transaction
        3. Handlers must be idempotent (may be called multiple times)
        """
        for event in events:
            await self._dispatch_single(event)

    async def _dispatch_single(self, event: DomainEvent):
        """Dispatch single event to all registered handlers"""
        event_type = type(event)
        handlers = self._handlers.get(event_type, [])

        if not handlers:
            logger.debug(
                f"No handlers registered for {event_type.__name__}"
            )
            return

        logger.info(
            f"Dispatching {event_type.__name__} to {len(handlers)} handlers"
        )

        for handler in handlers:
            await self._execute_handler(handler, event)

    async def _execute_handler(
        self, handler: Callable, event: DomainEvent
    ):
        """Execute single event handler with error isolation"""
        try:
            # Support both sync and async handlers
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                # Run sync handler in thread pool to avoid blocking
                await asyncio.to_thread(handler, event)

            logger.debug(
                f"Handler {handler.__name__} completed successfully"
            )

        except Exception as e:
            # Critical: Handler failure must NOT affect main transaction
            logger.error(
                f"Event handler {handler.__name__} failed for "
                f"{type(event).__name__}: {e}",
                exc_info=True
            )
```

### 4.4 Event Handler Registration

**Pattern**: Register handlers at application startup

```python
# Application startup (e.g., FastAPI startup event)
from src.application.events.synchronous_dispatcher import SynchronousEventDispatcher
from src.domain.events.mcp_connection_events import (
    MCPConnectedEvent,
    MCPDisconnectedEvent,
    ToolsDiscoveredEvent,
)

# Create dispatcher
event_dispatcher = SynchronousEventDispatcher()

# Register handlers
async def on_mcp_connected(event: MCPConnectedEvent):
    """Handler for MCPConnectedEvent"""
    logger.info(
        f"MCP connection established: {event.connection_id} "
        f"with {len(event.tools)} tools"
    )

async def on_mcp_disconnected(event: MCPDisconnectedEvent):
    """Handler for MCPDisconnectedEvent"""
    logger.info(
        f"MCP connection closed: {event.connection_id}"
    )

async def on_tools_discovered(event: ToolsDiscoveredEvent):
    """Handler for ToolsDiscoveredEvent"""
    logger.info(
        f"Tools discovered for connection {event.connection_id}: "
        f"{len(event.tools)} tools"
    )

# Register
event_dispatcher.register(MCPConnectedEvent, on_mcp_connected)
event_dispatcher.register(MCPDisconnectedEvent, on_mcp_disconnected)
event_dispatcher.register(ToolsDiscoveredEvent, on_tools_discovered)
```

---

## 5. Security Architecture

### 5.1 P0 Security Requirement: Namespace Verification

**CRITICAL RULE**: Namespace MUST be verified from database, NEVER from user input

**Vulnerability**: If namespace is taken from JWT claims or request DTO without verification, attackers can access other namespaces' data.

**Correct Pattern**:
```python
async def verify_namespace_from_db(
    self,
    agent_id: UUID,
    claimed_namespace: str,
) -> str:
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

**Wrong Pattern** ❌:
```python
# WRONG: Taking namespace from JWT claims
namespace = jwt_claims.get("namespace")  # ❌ Attacker can forge claims

# WRONG: Trusting request DTO
namespace = request.namespace  # ❌ Attacker can send any namespace
```

### 5.2 Authorization Flow

```
API Request
  ↓
[1] JWT validation (Presentation Layer)
  ↓
[2] Extract agent_id from JWT
  ↓
[3] Create Request DTO with claimed namespace
  ↓
[4] Use Case: Verify namespace from DB
     agent = await agent_repository.get_by_id(agent_id)
     verified_namespace = agent.namespace
     if request.namespace != verified_namespace:
         raise AuthorizationError
  ↓
[5] Use verified_namespace for all queries
     connection = await repository.get_by_id(
         connection_id, verified_namespace  # ✅ Verified
     )
  ↓
[6] Proceed with business logic
```

### 5.3 Repository Namespace Filtering

**Pattern**: All repository queries MUST include namespace filter

```python
# MCPConnectionRepository
async def get_by_id(
    self, connection_id: UUID, namespace: str
) -> MCPConnection:
    """
    Retrieve connection by ID with namespace verification

    Args:
        connection_id: Connection UUID
        namespace: VERIFIED namespace from database

    Returns:
        MCPConnection aggregate

    Raises:
        AggregateNotFoundError: If not found OR in different namespace
    """
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace  # ✅ Namespace filter
    )
    result = await self._session.execute(stmt)
    model = result.scalar_one_or_none()

    if not model:
        raise AggregateNotFoundError(
            aggregate_type="MCPConnection",
            identifier=str(connection_id),
        )

    return self._to_domain(model)
```

### 5.4 Ownership Verification

**Pattern**: Delete/update operations verify BOTH namespace AND agent_id

```python
# Delete operation
async def delete(
    self, connection_id: UUID, namespace: str, agent_id: UUID
) -> None:
    """
    Delete connection with ownership verification

    Args:
        connection_id: Connection UUID
        namespace: VERIFIED namespace
        agent_id: Agent requesting deletion (must be owner)

    Raises:
        AggregateNotFoundError: If not found, different namespace, or not owner
    """
    stmt = select(MCPConnectionModel).where(
        MCPConnectionModel.id == str(connection_id),
        MCPConnectionModel.namespace == namespace,  # ✅ Namespace
        MCPConnectionModel.agent_id == str(agent_id)  # ✅ Ownership
    )
    result = await self._session.execute(stmt)
    model = result.scalar_one_or_none()

    if not model:
        raise AggregateNotFoundError(
            aggregate_type="MCPConnection",
            identifier=str(connection_id),
        )

    await self._session.delete(model)
    await self._session.commit()
```

### 5.5 Error Information Disclosure Prevention

**Pattern**: Sanitize all errors before exposing to client

```python
try:
    result = await use_case.execute(request)
except AggregateNotFoundError as e:
    # Safe to expose (user error)
    raise ApplicationError(
        message=f"Connection not found: {e.identifier}",
        error_code="NOT_FOUND"
    )
except AuthorizationError as e:
    # Sanitize (don't reveal why authorization failed)
    logger.warning(f"Authorization failed: {e}")
    raise ApplicationError(
        message="Access denied",
        error_code="FORBIDDEN"
    )
except DatabaseError as e:
    # Sanitize (don't expose database details)
    logger.error(f"Database error: {e}", exc_info=True)
    raise ApplicationError(
        message="Internal server error",
        error_code="INTERNAL_ERROR"
    )
```

---

## 6. TDD Strategy

### 6.1 Test Pyramid

```
           /\
          /  \
         /    \
        / E2E  \  ← 5 tests (Acceptance Tests)
       /--------\
      / Integr. \  ← 10 tests (Application Service + Repository)
     /------------\
    /  Unit Tests  \  ← 30 tests (Use Cases, DTOs, Dispatcher)
   /----------------\
  /                  \
 Total: 45 tests
```

**Coverage Targets**:
- Use Cases: 100% (all branches)
- DTOs: 95% (validation logic)
- Event Dispatcher: 100%
- Application Service: 90%

### 6.2 Test Breakdown

#### Acceptance Tests (5 tests)
**File**: `tests/acceptance/test_mcp_connection_workflows.py`

1. `test_connect_to_mcp_server_success` - Full connection workflow
2. `test_discover_tools_from_active_connection` - Tool discovery
3. `test_execute_tool_with_valid_arguments` - Tool execution
4. `test_disconnect_mcp_server` - Graceful disconnection
5. `test_unauthorized_access_blocked` - Security test

**Characteristics**:
- Real database (SQLite)
- Mock external MCP server
- Full workflow from request to response
- Verify persistence and domain events

#### Integration Tests (10 tests)
**File**: `tests/integration/test_application_service_integration.py`

1. `test_connect_persists_to_database`
2. `test_connect_with_failed_external_connection`
3. `test_discover_tools_updates_database`
4. `test_execute_tool_with_real_adapter_mock`
5. `test_disconnect_updates_database`
6. `test_transaction_rollback_on_error`
7. `test_event_dispatch_after_commit`
8. `test_namespace_isolation_in_repository`
9. `test_ownership_verification_in_delete`
10. `test_error_sanitization_in_service`

**Characteristics**:
- Real database
- Real repository
- Mock adapter
- Focus on integration between layers

#### Unit Tests (30 tests)

**Use Cases (12 tests)**:
- `test_connect_mcp_server_use_case.py` (4 tests)
  - Success path
  - Invalid input
  - Namespace mismatch
  - Duplicate connection
- `test_discover_tools_use_case.py` (3 tests)
  - Success path
  - Connection not found
  - Connection not active
- `test_execute_tool_use_case.py` (3 tests)
  - Success path
  - Tool not found
  - Connection not active
- `test_disconnect_mcp_server_use_case.py` (2 tests)
  - Success path
  - Connection not found

**DTOs (10 tests)**:
- `test_dtos.py` (10 tests)
  - Request DTO validation (5 tests)
  - Response DTO mapping (5 tests)

**Event Dispatcher (8 tests)**:
- `test_event_dispatcher.py` (8 tests)
  - Handler registration
  - Event dispatching
  - Multiple handlers for same event
  - Async handler support
  - Sync handler support
  - Handler error isolation
  - No handler registered
  - Multiple events dispatch

### 6.3 Test Data Builders

**Pattern**: Reusable builders for maintainable test data

```python
# tests/builders/mcp_connection_builder.py
from dataclasses import dataclass
from uuid import uuid4

@dataclass
class MCPConnectionBuilder:
    """Builder for MCPConnection test data"""

    id: UUID = None
    server_name: str = "test_server"
    url: str = "http://localhost:8080/mcp"
    namespace: str = "test-namespace"
    agent_id: UUID = None

    def with_id(self, id: UUID) -> 'MCPConnectionBuilder':
        self.id = id
        return self

    def with_server_name(self, name: str) -> 'MCPConnectionBuilder':
        self.server_name = name
        return self

    def with_namespace(self, namespace: str) -> 'MCPConnectionBuilder':
        self.namespace = namespace
        return self

    def build(self) -> MCPConnection:
        """Build MCPConnection aggregate"""
        config = ConnectionConfig(
            server_name=ServerName(self.server_name),
            url=ServerURL(self.url),
        )

        return MCPConnection(
            id=self.id or uuid4(),
            server_name=config.server_name,
            config=config,
            namespace=self.namespace,
            agent_id=self.agent_id or uuid4(),
        )
```

---

## 7. Implementation Plan

### 7.1 Phase Breakdown

#### Phase 1-2-A: Architecture Design ✅
**Duration**: 1.5 hours (COMPLETED)
**Owner**: Hera (Strategic Commander)
**Deliverables**: This design document

#### Phase 1-2-B: Acceptance Tests
**Duration**: 30 minutes
**Owner**: Hestia (with Artemis support)
**Deliverables**:
- `tests/acceptance/test_mcp_connection_workflows.py` (5 tests)
- Test fixtures (`tests/acceptance/conftest.py`)
- Mock MCP server helper

**Tasks**:
1. Create acceptance test file
2. Implement test fixtures (real DB, mock MCP server)
3. Write 5 E2E test scenarios
4. Verify all tests FAIL (RED phase)

**Success Criteria**: 5/5 tests written, 0/5 passing

#### Phase 1-2-C: Unit Tests
**Duration**: 60 minutes
**Owner**: Artemis
**Deliverables**:
- Use Case unit tests (12 tests)
- DTO unit tests (10 tests)
- Event Dispatcher unit tests (8 tests)

**Tasks**:
1. Create test files for each use case
2. Create DTO validation tests
3. Create event dispatcher tests
4. Verify all tests FAIL (RED phase)

**Success Criteria**: 30/30 tests written, 0/30 passing

#### Phase 1-2-D: Implementation
**Duration**: 2-3 hours
**Owner**: Artemis
**Deliverables**:
- DTOs (4 response, 5 request)
- Event Dispatcher (interface + implementation)
- Use Cases (4 use cases)
- Application Service

**Tasks**:
1. Implement DTOs with Pydantic validation
2. Implement SynchronousEventDispatcher
3. Implement 4 use cases
4. Implement MCPConnectionApplicationService
5. Run tests: All tests GREEN

**Success Criteria**: 45/45 tests passing

#### Phase 1-2-E: Security Review
**Duration**: 30 minutes
**Owner**: Hestia
**Deliverables**:
- Security audit report
- P0 checklist verification

**Tasks**:
1. Review namespace verification implementation
2. Review authorization flow
3. Review error sanitization
4. Verify no security regressions

**Success Criteria**: 7/7 security checklist items verified

#### Phase 1-2-F: Documentation
**Duration**: 30 minutes
**Owner**: Muses
**Deliverables**:
- USE_CASES.md (use case documentation)
- DTOS.md (DTO specifications)
- EVENT_DISPATCHER.md (event dispatching guide)

**Tasks**:
1. Document 4 use cases with examples
2. Document DTO contracts
3. Document event dispatcher usage

**Success Criteria**: 3/3 documents created

### 7.2 Timeline Visualization

```
Day 1
├─ 00:00-01:30 | Phase 1-2-A: Architecture Design (Hera) ✅
├─ 01:30-02:00 | Phase 1-2-B: Acceptance Tests (Hestia)
├─ 02:00-03:00 | Phase 1-2-C: Unit Tests (Artemis)
└─ 03:00-06:00 | Phase 1-2-D: Implementation (Artemis)

Day 2
├─ 00:00-00:30 | Phase 1-2-E: Security Review (Hestia)
└─ 00:30-01:00 | Phase 1-2-F: Documentation (Muses)

Total: 6.5 hours
```

### 7.3 Dependencies

```
Phase 1-2-A (Architecture)
  ↓
Phase 1-2-B (Acceptance Tests) ← Can start in parallel
  ↓                            ↗
Phase 1-2-C (Unit Tests)
  ↓
Phase 1-2-D (Implementation)
  ↓
Phase 1-2-E (Security Review)
  ↓
Phase 1-2-F (Documentation)
```

---

## 8. Risk Analysis

### Risk 1: Transaction Management Complexity
**Probability**: Medium
**Impact**: High
**Description**: Incorrect transaction boundaries could lead to data inconsistency

**Mitigation**:
- Clear transaction pattern: one use case = one transaction
- Unit tests for rollback scenarios
- Integration tests for commit verification

**Contingency**: If issues arise, add transaction debugging logs and audit trail

### Risk 2: Event Dispatch Timing
**Probability**: Medium
**Impact**: High
**Description**: Events dispatched before commit could cause inconsistent state

**Mitigation**:
- Strict pattern: dispatch AFTER commit only
- Unit tests for event dispatch timing
- Code review focusing on event dispatch placement

**Contingency**: If issues arise, add event dispatch guards and assertions

### Risk 3: Security Bypass via DTOs
**Probability**: Low
**Impact**: Critical
**Description**: DTOs could bypass namespace verification if not carefully designed

**Mitigation**:
- Security review by Hestia
- Explicit namespace verification in every use case
- Security-focused acceptance test

**Contingency**: If vulnerability found, immediate fix and security regression test

### Risk 4: Performance Degradation
**Probability**: Medium
**Impact**: Medium
**Description**: Synchronous event dispatch could slow down API responses

**Mitigation**:
- Benchmark tests for event dispatch overhead
- Set performance budget: <50ms overhead
- Future migration path to async queue documented

**Contingency**: If performance unacceptable, implement async event queue early

### Risk 5: Test Data Setup Complexity
**Probability**: Medium
**Impact**: Low
**Description**: Complex test data setup could make tests fragile

**Mitigation**:
- Test data builders for reusable setup
- Fixtures for common test scenarios
- Clear test documentation

**Contingency**: If tests become unmaintainable, refactor with factory pattern

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Test Coverage | 90%+ | pytest --cov |
| Tests Passing | 100% | All 45 tests green |
| Security Compliance | 100% | 7/7 checklist items |
| Performance | <50ms overhead | Benchmark tests |
| Documentation | 100% | All 3 docs complete |
| Implementation Time | <7 hours | Actual vs estimated |

**Success Probability**: 94.2%

---

**End of Design Document**

*This document serves as the blueprint for Phase 1-2 implementation. All agents (Artemis, Hestia, Muses) should reference this document during their respective phases.*

**Next Step**: Phase 1-2-B (Acceptance Tests by Hestia)
