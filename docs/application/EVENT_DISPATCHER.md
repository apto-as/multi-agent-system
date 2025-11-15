# Application Service Layer - Event Dispatcher

**TMWS Phase 1-2**: MCP Connection Management
**Architecture**: Domain-Driven Design (DDD)
**Last Updated**: 2025-11-12

---

## Table of Contents

1. [Overview](#overview)
2. [Domain Events in DDD](#domain-events-in-ddd)
3. [Event Dispatcher Pattern](#event-dispatcher-pattern)
4. [Synchronous vs Asynchronous](#synchronous-vs-asynchronous)
5. [Implementation Details](#implementation-details)
6. [Domain Events](#domain-events)
7. [Event Handlers](#event-handlers)
8. [Critical Patterns](#critical-patterns)
9. [Error Isolation](#error-isolation)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)
12. [Future: Async Queue-Based Dispatcher](#future-async-queue-based-dispatcher)

---

## Overview

**Domain Events** represent something that happened in the domain. They are named in the **past tense** (e.g., `MCPConnectedEvent`, not `MCPConnectEvent`) because they describe facts that already occurred.

**Event Dispatcher** is responsible for delivering domain events to registered event handlers **after successful transaction commit**.

**Purpose**:
- Decouple domain logic from side effects (notifications, logging, webhooks)
- Enable reactive programming patterns
- Support eventual consistency
- Facilitate system integration

**Key Principle**: Events are dispatched **AFTER** transaction commit to ensure that events only represent **facts that actually happened**.

---

## Domain Events in DDD

### What are Domain Events?

**Definition**: A domain event is a record of a business-significant occurrence in the domain.

**Characteristics**:
1. **Immutable**: Events cannot be changed after creation (`@dataclass(frozen=True)`)
2. **Named in past tense**: Describes what happened (not what will happen)
3. **Include context**: Contain all relevant data about the occurrence
4. **Timestamped**: Include `occurred_at` timestamp for auditing
5. **Identified**: Have unique `event_id` for tracking

**Examples**:
- ✅ `MCPConnectedEvent` (past tense)
- ✅ `ToolsDiscoveredEvent` (past tense)
- ❌ `MCPConnectEvent` (present tense - WRONG)
- ❌ `DiscoverToolsEvent` (imperative - WRONG)

---

### Event Flow in DDD

```
┌──────────────────────────────────────────────┐
│         Domain Layer (Aggregate)             │
│  - MCPConnection aggregate                   │
│  - Collects domain events internally         │
│  - Events stored in `.domain_events` list    │
└────────────────┬─────────────────────────────┘
                 │
                 ↓
┌──────────────────────────────────────────────┐
│     Application Layer (Use Case)             │
│  1. BEGIN TRANSACTION                        │
│  2. Execute domain logic                     │
│  3. COMMIT TRANSACTION                       │
│  4. Dispatch events (AFTER commit) ←        │
└────────────────┬─────────────────────────────┘
                 │
                 ↓
┌──────────────────────────────────────────────┐
│        Event Dispatcher                      │
│  - Dispatches events to registered handlers  │
│  - Isolates handler failures from main flow  │
└────────────────┬─────────────────────────────┘
                 │
        ┌────────┴────────┐
        ↓                 ↓
┌──────────────┐   ┌──────────────┐
│   Handler 1  │   │   Handler 2  │
│  (Logging)   │   │  (Webhook)   │
└──────────────┘   └──────────────┘
```

**Critical Rule**: Events are dispatched **AFTER** commit, outside the transaction boundary.

---

### Why Dispatch After Commit?

**Problem with dispatching inside transaction**:

```python
# ❌ WRONG: Events dispatched INSIDE transaction
async with self._uow:
    connection.mark_as_active(tools)  # Domain logic
    await self._repository.update(connection)

    # ❌ Events dispatched BEFORE commit
    await self._event_dispatcher.dispatch_all(connection.domain_events)

    await self._uow.commit()  # What if this fails?
```

**Issues**:
1. If commit fails, events were already dispatched → **lie**
2. Event handlers see uncommitted data → **inconsistent state**
3. Handler failures can rollback main transaction → **tight coupling**

---

**Solution: Dispatch after commit**:

```python
# ✅ CORRECT: Events dispatched AFTER commit
async with self._uow:
    connection.mark_as_active(tools)  # Domain logic
    await self._repository.update(connection)
    await self._uow.commit()  # ← Commit first

# ✅ Events dispatched AFTER successful commit
await self._event_dispatcher.dispatch_all(
    connection.domain_events
)  # Outside transaction
```

**Benefits**:
1. Events only represent **facts** (commit succeeded)
2. Handlers see **consistent state** (committed data)
3. Handler failures **don't affect** main transaction

---

## Event Dispatcher Pattern

### Interface (Abstract Base Class)

**File**: `src/application/events/dispatcher.py`

```python
from abc import ABC, abstractmethod
from typing import List
from src.domain.events import DomainEvent

class EventDispatcher(ABC):
    """Abstract event dispatcher interface"""

    @abstractmethod
    def register(
        self,
        event_type: type[DomainEvent],
        handler: Callable,
    ):
        """Register event handler for specific event type"""
        pass

    @abstractmethod
    async def dispatch_all(self, events: List[DomainEvent]):
        """Dispatch all events to registered handlers"""
        pass
```

---

### Implementation (Synchronous)

**File**: `src/application/events/synchronous_dispatcher.py` (93 lines)

**Phase 1-2 Implementation**: Synchronous event dispatcher with error isolation.

**Characteristics**:
- Handlers executed sequentially (one after another)
- Errors are logged but NOT raised (error isolation)
- Supports both sync and async handlers
- Simple implementation for Phase 1-2

---

## Synchronous vs Asynchronous

### Current: Synchronous Dispatcher (Phase 1-2)

**Characteristics**:
- Handlers executed in same process
- Sequential execution (handler 1 → handler 2 → ...)
- Immediate feedback (all handlers complete before use case returns)
- No external dependencies (Redis, RabbitMQ, etc.)

**Trade-offs**:
- ✅ Simple implementation
- ✅ Easy debugging
- ✅ No infrastructure dependencies
- ❌ Blocks until all handlers complete
- ❌ Handler failures logged but not retried
- ❌ Not suitable for heavy workloads (e.g., sending 1000 emails)

---

### Future: Async Queue-Based Dispatcher (Phase 3+)

**Characteristics**:
- Events published to message queue (Redis, RabbitMQ, AWS SQS)
- Handlers executed by background workers
- Asynchronous processing (use case returns immediately)
- Retry mechanism for failed handlers
- Horizontal scaling (multiple workers)

**Trade-offs**:
- ✅ Non-blocking (fast response)
- ✅ Retry mechanism (reliability)
- ✅ Horizontal scaling (performance)
- ❌ Complex infrastructure
- ❌ Eventual consistency (handlers may execute later)
- ❌ Debugging harder (distributed tracing needed)

**Migration Path**: See [Future: Async Queue-Based Dispatcher](#future-async-queue-based-dispatcher) section.

---

## Implementation Details

### Synchronous Event Dispatcher

**File**: `src/application/events/synchronous_dispatcher.py`

---

#### Constructor (lines 24-25)

```python
class SynchronousEventDispatcher(EventDispatcher):
    """Synchronous event dispatcher for Phase 1-2"""

    def __init__(self):
        self._handlers: Dict[type[DomainEvent], List[Callable]] = {}
```

**Data Structure**:
- `_handlers`: Dict mapping event types to list of handler functions
- Example: `{MCPConnectedEvent: [handler1, handler2], MCPDisconnectedEvent: [handler3]}`

---

#### Handler Registration (lines 27-42)

```python
def register(
    self,
    event_type: type[DomainEvent],
    handler: Callable,
):
    """Register event handler for specific event type"""
    if event_type not in self._handlers:
        self._handlers[event_type] = []

    self._handlers[event_type].append(handler)

    handler_name = getattr(handler, "__name__", repr(handler))
    logger.info(
        f"Registered handler {handler_name} "
        f"for event {event_type.__name__}"
    )
```

**Usage**:
```python
# Initialize dispatcher
dispatcher = SynchronousEventDispatcher()

# Register handlers
dispatcher.register(MCPConnectedEvent, log_connection_handler)
dispatcher.register(MCPConnectedEvent, send_notification_handler)
dispatcher.register(MCPDisconnectedEvent, cleanup_resources_handler)
```

---

#### Event Dispatching (lines 43-54)

```python
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
```

**Critical Rules** (documented in docstring):
1. **AFTER commit**: Must be called after `await uow.commit()`
2. **Error isolation**: Handler failures don't affect main transaction
3. **Idempotency**: Handlers may be called multiple times (retry scenarios)

---

#### Single Event Dispatch (lines 55-69)

```python
async def _dispatch_single(self, event: DomainEvent):
    """Dispatch single event to all registered handlers"""
    event_type = type(event)
    handlers = self._handlers.get(event_type, [])

    if not handlers:
        logger.debug(f"No handlers registered for {event_type.__name__}")
        return

    logger.info(
        f"Dispatching {event_type.__name__} to {len(handlers)} handlers"
    )

    for handler in handlers:
        await self._execute_handler(handler, event)
```

**Flow**:
1. Get event type (e.g., `MCPConnectedEvent`)
2. Lookup registered handlers for that type
3. If no handlers, log and return (not an error)
4. Execute each handler sequentially

---

#### Handler Execution with Error Isolation (lines 71-93)

```python
async def _execute_handler(self, handler: Callable, event: DomainEvent):
    """Execute single event handler with error isolation"""
    handler_name = getattr(handler, "__name__", repr(handler))

    try:
        # Support both sync and async handlers
        if asyncio.iscoroutinefunction(handler):
            await handler(event)
        else:
            # Run sync handler in thread pool to avoid blocking
            await asyncio.to_thread(handler, event)

        logger.debug(f"Handler {handler_name} completed successfully")

    except Exception as e:
        # CRITICAL: Handler failure must NOT affect main transaction
        logger.error(
            f"Event handler {handler_name} failed for "
            f"{type(event).__name__}: {e}",
            exc_info=True,
        )
        # Error is logged but NOT raised - error isolation
```

**Key Features**:

1. **Sync/Async Support** (lines 77-81)
   - Async handlers: `await handler(event)`
   - Sync handlers: `await asyncio.to_thread(handler, event)` (non-blocking)

2. **Error Isolation** (lines 85-92)
   - Exceptions are **logged** but **NOT raised**
   - Main transaction is **not affected** by handler failures
   - Critical for system stability

---

## Domain Events

### Base Class: DomainEvent

**File**: `src/domain/events.py` (lines 18-29)

```python
@dataclass(frozen=True)
class DomainEvent:
    """Base class for all domain events.

    Domain events are immutable (frozen=True) to prevent accidental modification.
    They include an event ID and timestamp for auditing and correlation.
    """

    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    aggregate_id: UUID | None = None
```

**Fields**:
- `event_id`: Unique identifier for event (for tracking, correlation)
- `occurred_at`: Timestamp when event occurred (for auditing, ordering)
- `aggregate_id`: ID of aggregate that raised the event (optional)

---

### 1. MCPConnectedEvent

**Purpose**: Raised when MCP connection is established and becomes ACTIVE.

**File**: `src/domain/events.py` (lines 31-55)

```python
@dataclass(frozen=True)
class MCPConnectedEvent(DomainEvent):
    """Event raised when an MCP connection is established.

    This event indicates that:
    - Connection to MCP server was successful
    - Tools are ready to be discovered
    - Connection is in ACTIVE state
    """

    connection_id: UUID | None = None
    server_name: str | None = None
    namespace: str | None = None
    tools: list[dict] = field(default_factory=list)

    # Compatibility fields
    url: str | None = None
    agent_id: str | None = None
    tool_count: int = 0

    def __post_init__(self):
        # Set aggregate_id from connection_id if provided
        if self.connection_id and not self.aggregate_id:
            object.__setattr__(self, "aggregate_id", self.connection_id)
```

**When Raised**:
- After `connection.mark_as_active(tools)` in `ConnectMCPServerUseCase`
- After successful transaction commit

**Use Cases**:
- Log connection establishment
- Send notification to agent
- Update monitoring dashboard
- Trigger webhook to external system
- Record audit log

---

### 2. MCPDisconnectedEvent

**Purpose**: Raised when MCP connection is closed.

**File**: `src/domain/events.py` (lines 57-77)

```python
@dataclass(frozen=True)
class MCPDisconnectedEvent(DomainEvent):
    """Event raised when an MCP connection is closed.

    This event indicates that:
    - Connection to MCP server was closed (gracefully or due to error)
    - Tools are no longer available
    - Connection is in DISCONNECTED state
    """

    connection_id: UUID | None = None
    server_name: str | None = None
    namespace: str | None = None
    reason: str | None = None
    was_graceful: bool = True

    def __post_init__(self):
        # Set aggregate_id from connection_id if provided
        if self.connection_id and not self.aggregate_id:
            object.__setattr__(self, "aggregate_id", self.connection_id)
```

**When Raised**:
- After `connection.mark_as_disconnected()` in `DisconnectMCPServerUseCase`
- After successful transaction commit

**Use Cases**:
- Log disconnection
- Clean up resources (cached tools, etc.)
- Send notification to agent
- Update monitoring dashboard

---

### 3. ToolsDiscoveredEvent

**Purpose**: Raised when tools are discovered or refreshed from MCP connection.

**File**: `src/domain/events.py` (lines 96-113)

```python
@dataclass(frozen=True)
class ToolsDiscoveredEvent(DomainEvent):
    """Event raised when tools are discovered or refreshed from MCP connection.

    This event indicates that:
    - Tool discovery completed successfully
    - Multiple tools may have been added or updated
    - Connection tools list is now up to date
    """

    connection_id: UUID | None = None
    tools: list[dict] = field(default_factory=list)
    server_name: str | None = None

    def __post_init__(self):
        # Set aggregate_id from connection_id if provided
        if self.connection_id and not self.aggregate_id:
            object.__setattr__(self, "aggregate_id", self.connection_id)
```

**When Raised**:
- After `connection.update_tools(tools)` in `DiscoverToolsUseCase`
- After successful transaction commit

**Use Cases**:
- Update tool registry
- Invalidate cached tool lists
- Send notification to agent
- Log tool changes (added/removed)

---

### 4. ToolDiscoveredEvent (Single Tool)

**Purpose**: Raised when a single new tool is discovered.

**File**: `src/domain/events.py` (lines 79-94)

```python
@dataclass(frozen=True)
class ToolDiscoveredEvent(DomainEvent):
    """Event raised when a new tool is discovered from an MCP server.

    This event indicates that:
    - A new tool was added to the connection
    - Tool metadata is available
    - Tool is ready for use
    """

    tool_name: str | None = None
    tool_description: str | None = None
    tool_category: str | None = None
    server_name: str | None = None
    input_schema: dict = field(default_factory=dict)
```

**Note**: Currently not used in Phase 1-2 (use `ToolsDiscoveredEvent` instead). Reserved for future granular tool tracking.

---

## Event Handlers

### Handler Signature

**Async Handler**:
```python
async def my_handler(event: MCPConnectedEvent):
    """Async event handler"""
    logger.info(f"Connection established: {event.connection_id}")
    # Perform async operations (HTTP requests, database writes, etc.)
    await send_notification(event.agent_id, "Connection established")
```

**Sync Handler**:
```python
def my_handler(event: MCPConnectedEvent):
    """Sync event handler"""
    logger.info(f"Connection established: {event.connection_id}")
    # Perform sync operations (logging, simple calculations, etc.)
```

**Note**: Both sync and async handlers are supported. Sync handlers are executed in thread pool (`asyncio.to_thread()`) to avoid blocking the event loop.

---

### Example Handlers

#### 1. Logging Handler

```python
async def log_mcp_connected(event: MCPConnectedEvent):
    """Log MCP connection establishment"""
    logger.info(
        f"MCP connection established: "
        f"connection_id={event.connection_id}, "
        f"server_name={event.server_name}, "
        f"namespace={event.namespace}, "
        f"tools_count={len(event.tools)}"
    )
```

---

#### 2. Notification Handler

```python
async def send_connection_notification(event: MCPConnectedEvent):
    """Send notification to agent"""
    from src.services.notification_service import NotificationService

    notification = NotificationService()
    await notification.send(
        agent_id=event.agent_id,
        title="MCP Connection Established",
        message=f"Connected to {event.server_name} with {len(event.tools)} tools",
        event_id=str(event.event_id),
    )
```

---

#### 3. Webhook Handler

```python
async def trigger_webhook(event: MCPConnectedEvent):
    """Trigger webhook for external system"""
    import httpx

    webhook_url = "https://example.com/webhooks/mcp-connected"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            webhook_url,
            json={
                "event_type": "mcp_connected",
                "connection_id": str(event.connection_id),
                "server_name": event.server_name,
                "namespace": event.namespace,
                "tools_count": len(event.tools),
                "occurred_at": event.occurred_at.isoformat(),
            },
            timeout=10.0,
        )
        response.raise_for_status()
```

---

#### 4. Audit Log Handler

```python
async def record_audit_log(event: MCPConnectedEvent):
    """Record audit log for compliance"""
    from src.services.audit_service import AuditService

    audit = AuditService()
    await audit.record(
        event_type="mcp_connected",
        aggregate_id=event.connection_id,
        namespace=event.namespace,
        agent_id=event.agent_id,
        details={
            "server_name": event.server_name,
            "tools_count": len(event.tools),
        },
        occurred_at=event.occurred_at,
    )
```

---

### Handler Registration

**During Application Startup**:

```python
from src.application.events.synchronous_dispatcher import SynchronousEventDispatcher
from src.domain.events import MCPConnectedEvent, MCPDisconnectedEvent, ToolsDiscoveredEvent

# Initialize dispatcher
dispatcher = SynchronousEventDispatcher()

# Register handlers for MCPConnectedEvent
dispatcher.register(MCPConnectedEvent, log_mcp_connected)
dispatcher.register(MCPConnectedEvent, send_connection_notification)
dispatcher.register(MCPConnectedEvent, trigger_webhook)
dispatcher.register(MCPConnectedEvent, record_audit_log)

# Register handlers for MCPDisconnectedEvent
dispatcher.register(MCPDisconnectedEvent, log_mcp_disconnected)
dispatcher.register(MCPDisconnectedEvent, cleanup_resources)

# Register handlers for ToolsDiscoveredEvent
dispatcher.register(ToolsDiscoveredEvent, update_tool_registry)
dispatcher.register(ToolsDiscoveredEvent, log_tools_discovered)
```

---

## Critical Patterns

### Pattern 1: Dispatch After Commit

**CRITICAL**: Events must be dispatched **AFTER** successful commit.

```python
# ✅ CORRECT
async with self._uow:
    # 1. Domain logic
    connection = MCPConnection(...)
    await self._repository.add(connection)

    # 2. External operations
    await self._adapter.connect(...)
    tools = await self._adapter.discover_tools(...)
    connection.mark_as_active(tools)

    # 3. Persist
    await self._repository.update(connection)

    # 4. COMMIT (transaction ends here)
    await self._uow.commit()  # ← Transaction boundary

# 5. Dispatch events AFTER commit (outside transaction)
await self._event_dispatcher.dispatch_all(
    connection.domain_events
)  # ✅ CORRECT
```

---

**Incorrect Pattern**:

```python
# ❌ WRONG
async with self._uow:
    connection = MCPConnection(...)
    await self._repository.add(connection)

    # ❌ Dispatched INSIDE transaction
    await self._event_dispatcher.dispatch_all(connection.domain_events)

    await self._uow.commit()  # What if this fails?
```

**Problems**:
1. Events dispatched before commit → **lie** if commit fails
2. Handlers see uncommitted data → **inconsistent state**
3. Handler failures can rollback transaction → **tight coupling**

---

### Pattern 2: Error Isolation

**CRITICAL**: Handler failures must NOT affect main transaction.

```python
# Implementation in SynchronousEventDispatcher
async def _execute_handler(self, handler: Callable, event: DomainEvent):
    try:
        await handler(event)
        logger.debug(f"Handler {handler_name} completed successfully")

    except Exception as e:
        # ✅ CORRECT: Error logged but NOT raised
        logger.error(
            f"Event handler {handler_name} failed: {e}",
            exc_info=True,
        )
        # Error is isolated - main transaction is not affected
```

**Why?**:
- Main transaction already committed → cannot rollback
- Handler failures should not prevent other handlers from executing
- System stability is more important than individual handler success

---

### Pattern 3: Idempotent Handlers

**CRITICAL**: Handlers must be idempotent (safe to call multiple times).

```python
# ✅ IDEMPOTENT: Safe to call multiple times
async def send_notification(event: MCPConnectedEvent):
    """Send notification (idempotent)"""
    # Use event_id as idempotency key
    notification = await notification_service.find_by_event_id(event.event_id)
    if notification:
        # Already sent, skip
        return

    # Send notification
    await notification_service.send(
        agent_id=event.agent_id,
        message="Connection established",
        idempotency_key=str(event.event_id),  # ✅ Prevent duplicates
    )
```

**Why?**:
- Events may be dispatched multiple times (retry scenarios)
- Network failures may cause duplicate deliveries (future async queue)
- Idempotency prevents duplicate side effects

---

### Pattern 4: Collecting Events in Aggregate

**Pattern**: Aggregates collect domain events internally.

```python
# Domain aggregate
class MCPConnection:
    def __init__(self, ...):
        self._domain_events: List[DomainEvent] = []

    def mark_as_active(self, tools: List[Tool]):
        """Mark connection as active and raise event"""
        self._status = ConnectionStatus.ACTIVE
        self._connected_at = datetime.utcnow()
        self._tools = tools

        # Collect event
        self._domain_events.append(
            MCPConnectedEvent(
                connection_id=self.id,
                server_name=str(self.server_name),
                namespace=self.namespace,
                tools=[t.to_dict() for t in tools],
                url=str(self.config.url),
                agent_id=self.agent_id,
                tool_count=len(tools),
            )
        )

    @property
    def domain_events(self) -> List[DomainEvent]:
        """Get collected domain events"""
        return self._domain_events.copy()

    def clear_domain_events(self):
        """Clear collected events (after dispatch)"""
        self._domain_events.clear()
```

**Usage in Use Case**:

```python
async with self._uow:
    connection.mark_as_active(tools)  # Collects event internally
    await self._repository.update(connection)
    await self._uow.commit()

# Dispatch collected events
await self._event_dispatcher.dispatch_all(
    connection.domain_events  # ✅ Get events from aggregate
)

# Optionally clear events (if aggregate is kept in memory)
connection.clear_domain_events()
```

---

## Error Isolation

### Why Error Isolation?

**Problem without error isolation**:

```python
# ❌ WRONG: Handler failure affects main flow
async with self._uow:
    connection.mark_as_active(tools)
    await self._repository.update(connection)
    await self._uow.commit()

# ❌ Handler failure raises exception
await webhook_handler(event)  # Raises HTTPError

# Main transaction is committed, but use case fails
# User sees error even though operation succeeded
```

---

**Solution: Error isolation in dispatcher**:

```python
async def _execute_handler(self, handler: Callable, event: DomainEvent):
    try:
        await handler(event)
    except Exception as e:
        # ✅ Error is logged but NOT raised
        logger.error(f"Handler {handler_name} failed: {e}", exc_info=True)
        # Execution continues with next handler
```

**Benefits**:
1. Main transaction success is independent of handler success
2. One handler failure doesn't prevent other handlers from executing
3. User gets successful response even if side effects (webhooks, notifications) fail
4. Failures are logged for monitoring and debugging

---

### Monitoring Handler Failures

**Recommendation**: Monitor handler failure rates.

```python
# Example: Prometheus metrics
from prometheus_client import Counter

handler_failures = Counter(
    "event_handler_failures_total",
    "Total number of event handler failures",
    ["event_type", "handler_name"]
)

async def _execute_handler(self, handler: Callable, event: DomainEvent):
    try:
        await handler(event)
    except Exception as e:
        # Record failure metric
        handler_failures.labels(
            event_type=type(event).__name__,
            handler_name=handler.__name__
        ).inc()

        logger.error(f"Handler {handler_name} failed: {e}", exc_info=True)
```

**Alert on high failure rates**:
- If webhook handler fails >10% of the time → investigate
- If notification handler fails >5% of the time → investigate

---

## Best Practices

### ✅ DO

1. **Dispatch events after commit**
   ```python
   await self._uow.commit()  # ← Commit first
   await self._event_dispatcher.dispatch_all(events)  # ← Then dispatch
   ```

2. **Name events in past tense**
   ```python
   MCPConnectedEvent  # ✅ Past tense
   ToolsDiscoveredEvent  # ✅ Past tense
   ```

3. **Make events immutable**
   ```python
   @dataclass(frozen=True)  # ✅ Immutable
   class MyEvent(DomainEvent):
       field: str
   ```

4. **Make handlers idempotent**
   ```python
   async def my_handler(event: MyEvent):
       # Check if already processed
       if await is_processed(event.event_id):
           return  # ✅ Skip duplicate
       # Process event
       await process(event)
       await mark_as_processed(event.event_id)
   ```

5. **Isolate handler errors**
   ```python
   try:
       await handler(event)
   except Exception as e:
       logger.error(f"Handler failed: {e}")  # ✅ Log, don't raise
   ```

6. **Use structured logging**
   ```python
   logger.info(
       "Event dispatched",
       extra={
           "event_id": str(event.event_id),
           "event_type": type(event).__name__,
           "aggregate_id": str(event.aggregate_id),
       }
   )
   ```

---

### ❌ DON'T

1. **Don't dispatch events before commit**
   ```python
   async with self._uow:
       await self._event_dispatcher.dispatch_all(events)  # ❌ WRONG
       await self._uow.commit()
   ```

2. **Don't name events in present/future tense**
   ```python
   MCPConnectEvent  # ❌ Present tense
   DiscoverToolsEvent  # ❌ Imperative
   ```

3. **Don't make events mutable**
   ```python
   @dataclass  # ❌ Not frozen
   class MyEvent(DomainEvent):
       field: str

   event = MyEvent(field="value")
   event.field = "changed"  # ❌ Mutation allowed
   ```

4. **Don't let handler failures affect main transaction**
   ```python
   await self._uow.commit()
   await webhook_handler(event)  # ❌ May raise exception
   # If this fails, use case fails even though commit succeeded
   ```

5. **Don't create non-idempotent handlers**
   ```python
   async def send_email(event: MyEvent):
       # ❌ Not idempotent - may send duplicate emails
       await email_service.send(event.recipient, "Message")
   ```

6. **Don't expose domain events outside application layer**
   ```python
   # ❌ WRONG: Exposing domain event in API response
   @router.post("/connections")
   async def create_connection(...) -> MCPConnectedEvent:
       # Return DTO, not domain event
   ```

---

## Troubleshooting

### Issue: Events not being dispatched

**Symptom**: Event handlers are not called after use case execution.

**Possible Causes**:

1. **Events dispatched before commit**
   ```python
   # ❌ WRONG
   async with self._uow:
       await self._event_dispatcher.dispatch_all(events)  # Inside transaction
       await self._uow.commit()
   ```

   **Fix**: Move dispatch outside transaction.

2. **Handlers not registered**
   ```python
   # Check if handler is registered
   print(dispatcher._handlers)
   # Output: {MCPConnectedEvent: [handler1, handler2]}
   ```

   **Fix**: Register handler during application startup.

3. **No events collected by aggregate**
   ```python
   # Check if aggregate collected events
   print(connection.domain_events)
   # Output: []  # ← No events collected
   ```

   **Fix**: Ensure aggregate raises events (e.g., `connection.mark_as_active(tools)` should append event).

---

### Issue: Handler failures causing use case to fail

**Symptom**: Use case raises exception even though transaction committed.

**Possible Cause**: Handler exceptions not being caught.

**Fix**: Ensure error isolation in dispatcher:

```python
# Verify error isolation
try:
    await handler(event)
except Exception as e:
    logger.error(f"Handler failed: {e}")  # ✅ Log, don't raise
```

---

### Issue: Duplicate event processing

**Symptom**: Event handlers executed multiple times for same event.

**Possible Causes**:

1. **Events not cleared after dispatch**
   ```python
   await self._event_dispatcher.dispatch_all(connection.domain_events)
   connection.clear_domain_events()  # ✅ Clear after dispatch
   ```

2. **Handler not idempotent**
   ```python
   # ❌ Not idempotent
   async def send_notification(event):
       await notification_service.send(...)  # May send duplicates

   # ✅ Idempotent
   async def send_notification(event):
       if await is_processed(event.event_id):
           return  # Skip duplicate
       await notification_service.send(...)
       await mark_as_processed(event.event_id)
   ```

---

## Future: Async Queue-Based Dispatcher

**Status**: Planned for Phase 3+

**Motivation**: Current synchronous dispatcher blocks until all handlers complete. For heavy workloads (sending 1000 emails, processing large batches), this is not acceptable.

---

### Architecture

```
┌──────────────────────────────────────────────┐
│      Application Layer (Use Case)           │
│  1. COMMIT TRANSACTION                       │
│  2. Publish events to queue (non-blocking)   │
└────────────────┬─────────────────────────────┘
                 │
                 ↓
┌──────────────────────────────────────────────┐
│      Message Queue (Redis/RabbitMQ)          │
│  - Events stored persistently                │
│  - Retry mechanism for failures              │
│  - Dead letter queue for poison messages     │
└────────────────┬─────────────────────────────┘
                 │
        ┌────────┴────────┐
        ↓                 ↓
┌──────────────┐   ┌──────────────┐
│  Worker 1    │   │  Worker 2    │
│  (Handler A) │   │  (Handler B) │
└──────────────┘   └──────────────┘
```

---

### Implementation Sketch

```python
class AsyncQueueEventDispatcher(EventDispatcher):
    """Async queue-based event dispatcher (Phase 3+)"""

    def __init__(self, redis_client: Redis):
        self._redis = redis_client
        self._handlers: Dict[type[DomainEvent], List[Callable]] = {}

    def register(self, event_type: type[DomainEvent], handler: Callable):
        """Register handler (same as synchronous)"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    async def dispatch_all(self, events: List[DomainEvent]):
        """Publish events to Redis queue (non-blocking)"""
        for event in events:
            # Serialize event to JSON
            event_data = {
                "event_type": type(event).__name__,
                "event_id": str(event.event_id),
                "occurred_at": event.occurred_at.isoformat(),
                "data": asdict(event),
            }

            # Publish to Redis stream
            await self._redis.xadd(
                "events:stream",
                {"data": json.dumps(event_data)},
            )

        logger.info(f"Published {len(events)} events to queue")
```

---

### Background Worker

```python
class EventWorker:
    """Background worker for processing events"""

    def __init__(self, redis_client: Redis, dispatcher: AsyncQueueEventDispatcher):
        self._redis = redis_client
        self._dispatcher = dispatcher

    async def run(self):
        """Run worker (process events from queue)"""
        consumer_group = "event-workers"
        consumer_name = f"worker-{uuid4()}"

        # Create consumer group (if not exists)
        try:
            await self._redis.xgroup_create("events:stream", consumer_group, id="0")
        except Exception:
            pass  # Group already exists

        logger.info(f"Worker {consumer_name} started")

        while True:
            # Read events from stream
            events = await self._redis.xreadgroup(
                consumer_group,
                consumer_name,
                {"events:stream": ">"},
                count=10,
                block=5000,  # Block for 5 seconds
            )

            for stream, messages in events:
                for message_id, data in messages:
                    await self._process_event(message_id, data)

    async def _process_event(self, message_id: str, data: dict):
        """Process single event"""
        try:
            # Deserialize event
            event_data = json.loads(data[b"data"])
            event = self._deserialize_event(event_data)

            # Dispatch to handlers
            event_type = type(event)
            handlers = self._dispatcher._handlers.get(event_type, [])

            for handler in handlers:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Handler {handler.__name__} failed: {e}")
                    # Retry logic here (e.g., exponential backoff)

            # Acknowledge message (remove from stream)
            await self._redis.xack("events:stream", "event-workers", message_id)

        except Exception as e:
            logger.error(f"Failed to process event {message_id}: {e}")
            # Move to dead letter queue for manual inspection
```

---

### Benefits of Async Queue

1. **Non-blocking**: Use case returns immediately after publishing events
2. **Retry mechanism**: Failed handlers can be retried with exponential backoff
3. **Horizontal scaling**: Multiple workers can process events in parallel
4. **Durability**: Events are stored persistently (survive server restart)
5. **Dead letter queue**: Poison messages can be manually inspected and fixed

---

### Migration Path

**Phase 1-2**: Use `SynchronousEventDispatcher` (current)

**Phase 3**: Introduce `AsyncQueueEventDispatcher`
- Deploy Redis/RabbitMQ
- Implement async dispatcher
- Implement background workers
- Migrate handlers one by one

**Phase 4**: Deprecate synchronous dispatcher
- Remove synchronous dispatcher
- All events processed via async queue

---

## Related Documentation

- **Use Cases**: See `docs/application/USE_CASES.md` for event dispatching in use cases
- **DTOs**: See `docs/application/DTOS.md` for event serialization patterns
- **Domain Model**: See `docs/domain/AGGREGATES.md` for event collection in aggregates
- **Testing**: See `docs/testing/INTEGRATION_TESTS.md` for testing event handlers

---

**Last Updated**: 2025-11-12
**Authors**: Muses (Documentation), Hera (Architecture), Artemis (Implementation)
**Phase**: 1-2-F (Documentation Update)
