# DDD Architecture Layers - Phase 1-1

**Created**: 2025-11-12
**Purpose**: Explain Domain-Driven Design layered architecture for MCP Integration
**Audience**: Developers implementing Phase 1-2 (Application Service Layer)

---

## Table of Contents

1. [Overview](#overview)
2. [Layer Diagram](#layer-diagram)
3. [Layer Descriptions](#layer-descriptions)
4. [Dependency Inversion Principle](#dependency-inversion-principle)
5. [Design Patterns](#design-patterns)
6. [Communication Flow](#communication-flow)
7. [Why DDD?](#why-ddd)

---

## Overview

Domain-Driven Design (DDD) organizes code into **layers** with clear responsibilities and strict dependency rules. Phase 1-1 implements the foundational **Domain Layer** and **Infrastructure Layer**.

**Key Principles**:

1. **Domain Layer is Independent**: No dependencies on infrastructure, frameworks, or external systems
2. **Infrastructure Depends on Domain**: Via Dependency Inversion Principle (DIP)
3. **Clean Boundaries**: Each layer has a single responsibility
4. **Testability**: Domain logic can be tested without databases or HTTP clients

---

## Layer Diagram

```
┌───────────────────────────────────────────────────────────────┐
│                    Presentation Layer                          │
│                   (Phase 1-2: To Be Implemented)              │
│  • FastAPI Routers (HTTP endpoints)                           │
│  • Request/Response DTOs                                      │
│  • Input validation                                           │
└─────────────────────────────┬─────────────────────────────────┘
                              │ Depends on
                              ↓
┌───────────────────────────────────────────────────────────────┐
│                   Application Layer                            │
│                   (Phase 1-2: To Be Implemented)              │
│  • Application Services (orchestration)                       │
│  • Use Cases (create connection, execute tool)                │
│  • Transaction boundaries                                     │
│  • Domain event dispatch                                      │
└─────────────────────────────┬─────────────────────────────────┘
                              │ Depends on
                              ↓
┌───────────────────────────────────────────────────────────────┐
│                      Domain Layer                              │
│                   (Phase 1-1: ✅ Implemented)                 │
│  • Aggregates: MCPConnection (business rules)                 │
│  • Value Objects: ConnectionConfig, ConnectionStatus          │
│  • Entities: Tool (identity-based)                            │
│  • Domain Events: MCPConnectedEvent, etc.                     │
│  • Domain Exceptions: InvalidStateTransitionError             │
│                                                                │
│  ⚠️ NO DEPENDENCIES on infrastructure, frameworks, databases   │
└───────────────────────────────────────────────────────────────┘
                              ↑
                              │ Implements (via Repository interface)
                              │
┌───────────────────────────────────────────────────────────────┐
│                   Infrastructure Layer                         │
│                   (Phase 1-1: ✅ Implemented)                 │
│  • Repository Implementation (MCPConnectionRepository)         │
│  • Adapters: MCPClientAdapter (HTTP communication)            │
│  • ACL: MCPProtocolTranslator (protocol translation)          │
│  • Database Models: MCPConnectionModel (SQLAlchemy)           │
│  • External System Integration                                │
└───────────────────────────────────────────────────────────────┘
                              ↓
                              Communicates with
                              ↓
┌───────────────────────────────────────────────────────────────┐
│                     External Systems                           │
│  • MCP Servers (HTTP/REST)                                    │
│  • SQLite Database                                            │
│  • Message Bus (future)                                       │
└───────────────────────────────────────────────────────────────┘
```

---

## Layer Descriptions

### 1. Domain Layer (Phase 1-1 ✅)

**Purpose**: Contains **pure business logic** with no external dependencies.

**Components**:

| Component | File | Responsibility |
|-----------|------|----------------|
| **Aggregates** | `src/domain/aggregates/mcp_connection.py` | Enforce business rules and invariants |
| **Value Objects** | `src/domain/value_objects/*.py` | Immutable, self-validating configuration |
| **Entities** | `src/domain/entities/tool.py` | Objects with identity (name-based) |
| **Domain Events** | `src/domain/events.py` | Record what happened (past tense) |
| **Exceptions** | `src/domain/exceptions.py` | Domain-specific errors |

**Rules**:
- ✅ **NO** dependencies on infrastructure
- ✅ **NO** dependencies on frameworks (FastAPI, SQLAlchemy)
- ✅ **NO** dependencies on external systems
- ✅ **YES** to pure Python dataclasses and business logic

**Example** (Pure Domain Logic):

```python
# ✅ CORRECT: Domain logic with no infrastructure dependencies
@dataclass
class MCPConnection:
    """Pure business logic - no SQLAlchemy, no HTTP, no framework."""

    id: UUID
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    tools: list[Tool] = field(default_factory=list)

    def mark_as_active(self, tools: list[Tool]) -> None:
        """Business rule: ACTIVE connection MUST have tools."""
        if not tools:
            raise DomainInvariantViolation(
                "ACTIVE connection must have at least one tool"
            )

        self.status = ConnectionStatus.ACTIVE
        self.tools = tools
        self.domain_events.append(MCPConnectedEvent(...))
```

---

### 2. Infrastructure Layer (Phase 1-1 ✅)

**Purpose**: Implement technical concerns (database, HTTP, protocol translation).

**Components**:

| Component | File | Responsibility |
|-----------|------|----------------|
| **Repository** | `src/infrastructure/repositories/mcp_connection_repository.py` | Persist aggregates to database |
| **Adapter** | `src/infrastructure/adapters/mcp_client_adapter.py` | HTTP communication with MCP servers |
| **ACL** | `src/infrastructure/acl/mcp_protocol_translator.py` | Translate MCP protocol ↔ Domain |
| **Database Model** | `src/models/mcp_connection.py` | SQLAlchemy ORM model |

**Rules**:
- ✅ **DEPENDS ON** domain layer (via Dependency Inversion)
- ✅ **IMPLEMENTS** domain interfaces (e.g., Repository)
- ✅ **ENCAPSULATES** external system complexity
- ✅ **TRANSLATES** between domain and external formats

**Example** (Infrastructure Implements Domain):

```python
# ✅ CORRECT: Infrastructure implements Repository (domain interface)
class MCPConnectionRepository:
    """Infrastructure implementation of repository pattern."""

    def __init__(self, session: AsyncSession):
        self._session = session  # SQLAlchemy dependency

    async def save(self, connection: MCPConnection) -> MCPConnection:
        """Persist domain aggregate to database."""
        # 1. Translate domain → database model
        model = self._to_model(connection)

        # 2. Persist to SQLite
        self._session.add(model)
        await self._session.commit()

        # 3. Return domain aggregate (no database concerns)
        return connection

    def _to_model(self, domain: MCPConnection) -> MCPConnectionModel:
        """Translate domain → SQLAlchemy model."""
        return MCPConnectionModel(
            id=str(domain.id),
            server_name=domain.server_name,
            status=domain.status.value,  # Enum → String
            config_json=asdict(domain.config),  # Value Object → JSON
            tools_json=[asdict(t) for t in domain.tools]  # Entities → JSON
        )
```

---

### 3. Application Layer (Phase 1-2: To Be Implemented)

**Purpose**: Orchestrate use cases and coordinate between layers.

**Responsibilities**:
- Execute use cases (e.g., "Create MCP Connection")
- Manage transaction boundaries
- Dispatch domain events
- Coordinate between domain and infrastructure

**Example** (Application Service Pattern):

```python
# Phase 1-2 (To Be Implemented)
class MCPConnectionService:
    """Application service orchestrates use cases."""

    def __init__(self, repo: MCPConnectionRepository, event_bus: EventBus):
        self._repo = repo
        self._event_bus = event_bus

    async def create_connection(
        self, server_name: str, url: str, namespace: str, agent_id: str
    ) -> MCPConnection:
        """Use case: Create MCP connection."""

        # 1. Create domain objects
        config = ConnectionConfig(server_name=server_name, url=url)
        connection = MCPConnection(id=uuid4(), server_name=server_name, config=config)

        # 2. Connect via adapter
        adapter = MCPClientAdapter(config)
        await adapter.connect()
        tools = await adapter.discover_tools()

        # 3. Apply business logic
        connection.mark_as_active(tools)  # Raises domain event

        # 4. Persist (transaction boundary)
        await self._repo.save(connection)

        # 5. Dispatch domain events
        for event in connection.domain_events:
            await self._event_bus.publish(event)

        # 6. Clear events
        connection.clear_events()

        return connection
```

---

### 4. Presentation Layer (Phase 1-2: To Be Implemented)

**Purpose**: Expose HTTP API endpoints and handle request/response formatting.

**Responsibilities**:
- FastAPI routers (HTTP endpoints)
- Request DTOs (Data Transfer Objects)
- Response DTOs
- Input validation (Pydantic models)

**Example** (FastAPI Router):

```python
# Phase 1-2 (To Be Implemented)
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/api/v1/mcp/connections")

@router.post("/", response_model=MCPConnectionResponseDTO)
async def create_connection(
    request: CreateMCPConnectionRequest,
    service: MCPConnectionService = Depends(get_service)
) -> MCPConnectionResponseDTO:
    """HTTP endpoint: Create MCP connection."""

    # 1. Validate request (Pydantic)
    # 2. Call application service
    connection = await service.create_connection(
        server_name=request.server_name,
        url=request.url,
        namespace=request.namespace,
        agent_id=request.agent_id
    )

    # 3. Convert domain → response DTO
    return MCPConnectionResponseDTO.from_domain(connection)
```

---

## Dependency Inversion Principle

**Problem**: How can Infrastructure Layer depend on Domain Layer without Domain depending on Infrastructure?

**Solution**: Dependency Inversion Principle (DIP) - "Depend on abstractions, not concretions"

### Traditional Dependency (❌ WRONG)

```
┌──────────────┐
│    Domain    │ ← Business logic
└──────────────┘
       ↓ Depends on (BAD)
┌──────────────┐
│Infrastructure│ ← SQLAlchemy, HTTP client
└──────────────┘
```

**Problem**: Domain can't be tested without database/HTTP.

### Dependency Inversion (✅ CORRECT)

```
┌──────────────────────────────────┐
│           Domain Layer           │
│  • MCPConnection (aggregate)     │
│  • (Implicitly defines interface)│ ← Business logic owns the interface
└──────────────────────────────────┘
                ↑
                │ Implements (Infrastructure depends on Domain)
                │
┌──────────────────────────────────┐
│       Infrastructure Layer       │
│  • MCPConnectionRepository       │
│    (implements save/get_by_id)   │
└──────────────────────────────────┘
```

**How It Works**:

1. **Domain defines what it needs** (implicitly via method signatures)
2. **Infrastructure provides it** (implements the repository)
3. **Application injects infrastructure into domain** (Dependency Injection)

**Example**:

```python
# Domain Layer: Defines what it needs (no interface class needed in Python)
# The aggregate implicitly expects a repository with these methods:
#   - save(connection: MCPConnection) -> MCPConnection
#   - get_by_id(id: UUID, namespace: str) -> MCPConnection

# Infrastructure Layer: Provides the implementation
class MCPConnectionRepository:
    """Infrastructure provides what domain needs."""

    async def save(self, connection: MCPConnection) -> MCPConnection:
        # Implementation using SQLAlchemy
        pass

    async def get_by_id(self, id: UUID, namespace: str) -> MCPConnection:
        # Implementation using SQLAlchemy
        pass

# Application Layer: Injects infrastructure
async def create_connection_use_case():
    async with get_async_session() as session:
        repo = MCPConnectionRepository(session)  # Infrastructure
        connection = MCPConnection(...)  # Domain

        # Domain aggregate is saved via infrastructure
        await repo.save(connection)
```

**Benefits**:
- ✅ Domain can be tested with **mock repositories** (no database needed)
- ✅ Infrastructure can be **swapped** (SQLite → PostgreSQL) without changing domain
- ✅ Business logic is **independent** of technical concerns

---

## Design Patterns

### 1. Repository Pattern

**Purpose**: Provide collection-like interface for aggregates.

**Implementation**: `MCPConnectionRepository`

```python
# ✅ Repository acts like an in-memory collection
class MCPConnectionRepository:
    """Collection-like interface for MCPConnection aggregates."""

    async def save(self, connection: MCPConnection) -> MCPConnection:
        """Add or update aggregate."""

    async def get_by_id(self, id: UUID, namespace: str) -> MCPConnection:
        """Retrieve aggregate by ID."""

    async def find_by_namespace_and_agent(
        self, namespace: str, agent_id: str
    ) -> list[MCPConnection]:
        """Query aggregates by criteria."""

    async def delete(self, id: UUID, namespace: str, agent_id: str) -> None:
        """Remove aggregate."""
```

**Key Points**:
- ✅ Works with **aggregates**, not database rows
- ✅ Encapsulates **all data access logic**
- ✅ Maintains **aggregate consistency boundaries**
- ✅ Does **NOT** persist domain events (they are transient)

---

### 2. Anti-Corruption Layer (ACL)

**Purpose**: Protect domain model from external protocol changes.

**Implementation**: `MCPProtocolTranslator`

```python
class MCPProtocolTranslator:
    """Translates between MCP protocol and domain objects."""

    def mcp_tool_to_domain(self, mcp_tool: dict) -> Tool:
        """MCP protocol → Domain entity."""
        return Tool(
            name=mcp_tool["name"],
            description=mcp_tool["description"],
            input_schema=mcp_tool.get("inputSchema", {}),
            category=ToolCategory.infer_from_name(...)
        )

    def domain_tool_execution_to_mcp(
        self, tool_name: str, tool_args: dict
    ) -> dict:
        """Domain request → MCP protocol."""
        return {
            "tool": tool_name,
            "arguments": tool_args,
            "requestId": str(uuid4())
        }
```

**Key Points**:
- ✅ **Isolates** domain from MCP protocol changes
- ✅ **Validates** protocol compliance
- ✅ **Translates** bidirectionally (MCP ↔ Domain)

**Why Needed?**

```
Without ACL:
  Domain → Directly depends on MCP protocol format
  MCP changes protocol → Domain breaks

With ACL:
  Domain → Depends on Tool entity (immutable interface)
  MCP changes protocol → Only ACL needs updating
```

---

### 3. Adapter Pattern

**Purpose**: Convert domain interface to external system interface.

**Implementation**: `MCPClientAdapter`

```python
class MCPClientAdapter:
    """Adapts domain to MCP server HTTP API."""

    def __init__(self, config: ConnectionConfig):
        self.config = config  # Domain value object
        self._client: httpx.AsyncClient | None = None
        self._translator = MCPProtocolTranslator()  # Uses ACL

    async def connect(self) -> bool:
        """Establish HTTP connection to MCP server."""
        self._client = httpx.AsyncClient(...)
        response = await self._client.get(f"{self.config.url}/health")
        return response.status_code == 200

    async def discover_tools(self) -> list[Tool]:
        """Discover tools → Returns domain Tool entities."""
        response = await self._client.get(f"{self.config.url}/tools")
        mcp_response = response.json()

        # Use ACL to translate MCP → Domain
        return self._translator.mcp_tools_response_to_domain(mcp_response)
```

**Key Points**:
- ✅ Encapsulates **HTTP communication**
- ✅ Handles **retries, timeouts, authentication**
- ✅ Returns **domain objects** (via ACL)

---

### 4. Aggregate Pattern

**Purpose**: Enforce consistency boundaries and business rules.

**Implementation**: `MCPConnection`

```python
@dataclass
class MCPConnection:
    """Aggregate root enforces consistency boundary."""

    id: UUID  # Identity
    server_name: str
    config: ConnectionConfig  # Value object
    status: ConnectionStatus  # Value object
    tools: list[Tool] = field(default_factory=list)  # Child entities
    domain_events: list[DomainEvent] = field(default_factory=list)

    def mark_as_active(self, tools: list[Tool]) -> None:
        """Enforce business rule: ACTIVE requires tools."""
        if not tools:
            raise DomainInvariantViolation(...)  # Invariant enforcement

        self.status = ConnectionStatus.ACTIVE
        self.tools = tools
        self.domain_events.append(MCPConnectedEvent(...))  # Record event
```

**Aggregate Rules**:
- ✅ **One aggregate = one transaction** (saved atomically)
- ✅ **External references by ID only** (no direct object references between aggregates)
- ✅ **Enforce invariants** within boundary
- ✅ **Raise domain events** on state changes

---

## Communication Flow

### Example: Create MCP Connection

```
┌─────────────┐
│  HTTP POST  │ 1. User sends HTTP request
└──────┬──────┘
       │
       ↓
┌─────────────────────────────────┐
│  FastAPI Router                 │ 2. Validate request (Pydantic DTO)
│  (Presentation Layer)           │
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  Application Service            │ 3. Orchestrate use case
│  • Begin transaction            │
│  • Create domain objects        │ 4. MCPConnection(id, server_name, config)
│  • Call infrastructure          │
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  MCPClientAdapter               │ 5. Connect to MCP server (HTTP)
│  (Infrastructure)               │ 6. Discover tools (HTTP GET /tools)
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  MCPProtocolTranslator          │ 7. Translate MCP response → Tool entities
│  (ACL)                          │
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  MCPConnection Aggregate        │ 8. connection.mark_as_active(tools)
│  (Domain Layer)                 │    - Validate invariants
│                                 │    - Update state
│                                 │    - Raise MCPConnectedEvent
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  MCPConnectionRepository        │ 9. repo.save(connection)
│  (Infrastructure)               │    - Translate domain → SQLAlchemy model
│                                 │    - Persist to SQLite
│                                 │    - Commit transaction
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  Application Service            │ 10. Dispatch domain events
│  • event_bus.publish(event)     │ 11. connection.clear_events()
│  • Return connection DTO        │
└──────┬──────────────────────────┘
       │
       ↓
┌─────────────────────────────────┐
│  FastAPI Router                 │ 12. Convert domain → Response DTO
│  • Return HTTP 201 Created      │
└─────────────────────────────────┘
```

**Key Observations**:
1. **HTTP concerns** stay in Presentation Layer (FastAPI Router)
2. **Business logic** stays in Domain Layer (MCPConnection)
3. **Database concerns** stay in Infrastructure Layer (Repository)
4. **Application Service** orchestrates and coordinates

---

## Why DDD?

### Problem: "Big Ball of Mud" Architecture

```
❌ Traditional Layered Architecture (Without DDD):

┌─────────────────────────────────────┐
│  Controllers                        │
│  (HTTP handlers mixed with logic)   │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Services                           │
│  (Business logic mixed with SQL)    │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Database                           │
│  (Business rules in stored procs)   │
└─────────────────────────────────────┘

Problems:
- Business logic scattered across layers
- Hard to test (requires database)
- Hard to change (ripple effects)
- Tight coupling (can't swap database)
```

### Solution: DDD Layered Architecture

```
✅ DDD Layered Architecture:

┌─────────────────────────────────────┐
│  Presentation (FastAPI)             │
│  • Only HTTP concerns               │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Application (Services)             │
│  • Only orchestration               │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│  Domain (Pure Business Logic)       │
│  • NO infrastructure dependencies   │
│  • Testable without database/HTTP   │
└─────────────────────────────────────┘
               ↑
               │ Implements
               │
┌─────────────────────────────────────┐
│  Infrastructure (DB, HTTP, etc.)    │
│  • Depends on domain                │
└─────────────────────────────────────┘

Benefits:
✅ Business logic isolated and testable
✅ Easy to change infrastructure
✅ Clear boundaries and responsibilities
✅ Independent of frameworks
```

### Specific Benefits for TMWS

1. **Testability**: Domain logic tested without SQLite or MCP server
2. **Flexibility**: Can swap SQLite → PostgreSQL without changing business rules
3. **Maintainability**: Clear separation of concerns
4. **Security**: Namespace isolation enforced at repository level (not domain concern)
5. **Evolution**: Can add new MCP protocols without changing domain

---

## Summary

### Layer Responsibilities (Quick Reference)

| Layer | Responsibility | Dependencies | Example |
|-------|---------------|--------------|---------|
| **Domain** | Business logic, rules, invariants | None (pure Python) | `MCPConnection.mark_as_active()` |
| **Infrastructure** | Database, HTTP, external systems | Domain (via DIP) | `MCPConnectionRepository.save()` |
| **Application** | Use case orchestration, events | Domain + Infrastructure | `MCPConnectionService.create_connection()` |
| **Presentation** | HTTP API, DTOs, validation | Application | FastAPI routers |

### Key Takeaways

1. ✅ **Domain Layer is Independent**: No dependencies on anything external
2. ✅ **Infrastructure Implements Domain**: Via Dependency Inversion Principle
3. ✅ **Repository Pattern**: Collection-like interface for aggregates
4. ✅ **ACL Pattern**: Protects domain from external protocol changes
5. ✅ **Domain Events are Transient**: Not persisted, dispatched by application service

### For Phase 1-2 Developers

When implementing Application Service Layer:

1. ✅ **Use** `MCPConnectionRepository` for persistence (already implements DIP)
2. ✅ **Use** `MCPClientAdapter` for MCP communication (already implements ACL)
3. ✅ **Call** domain methods (`mark_as_active()`) to apply business rules
4. ✅ **Dispatch** domain events after successful persistence
5. ✅ **Clear** events after dispatch
6. ✅ **Never** bypass domain layer to access database directly

---

**End of Architecture Layers Guide**

*Last Updated: 2025-11-12*
*Authors: Muses (Knowledge Architect) + Hera (Strategic Design)*
