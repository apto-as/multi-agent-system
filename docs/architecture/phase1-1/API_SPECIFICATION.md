# Phase 1-1 API Specification

**Created**: 2025-11-12
**Version**: 1.0.0
**Status**: Production-Ready
**Scope**: Domain + Infrastructure Layer APIs

---

## Table of Contents

1. [Repository API](#repository-api)
2. [ACL API](#acl-api)
3. [Adapter API](#adapter-api)
4. [Domain API](#domain-api)
5. [Exceptions](#exceptions)

---

## Repository API

**Interface**: `MCPConnectionRepository`
**File**: `src/infrastructure/repositories/mcp_connection_repository.py`
**Purpose**: Collection-like interface for MCPConnection aggregates

### Constructor

```python
def __init__(self, session: AsyncSession) -> None:
    """Initialize repository with database session.

    Args:
        session: SQLAlchemy async session for database operations
    """
```

---

### save()

```python
async def save(self, connection: MCPConnection) -> MCPConnection:
    """Save or update MCPConnection aggregate.

    Handles both insert (new) and update (existing) operations.
    Commits transaction automatically.

    Args:
        connection: MCPConnection aggregate to persist

    Returns:
        The same aggregate (with updated metadata if applicable)

    Raises:
        RepositoryError: If persistence fails (database error, constraint violation)

    Example:
        >>> connection = MCPConnection(id=uuid4(), server_name="test", config=config)
        >>> saved = await repo.save(connection)
        >>> assert saved.id == connection.id

    Notes:
        - Domain events are NOT persisted (they are transient)
        - Application service should dispatch events before calling save()
        - Transaction is committed automatically
    """
```

**Transaction Behavior**:
- ✅ Auto-commit on success
- ✅ Auto-rollback on error
- ✅ Re-raises system signals (KeyboardInterrupt, SystemExit)

---

### get_by_id()

```python
async def get_by_id(
    self, connection_id: UUID, namespace: str
) -> MCPConnection:
    """Retrieve MCPConnection by ID with namespace verification.

    SECURITY: Enforces namespace isolation (P0-2). The namespace parameter
    MUST be verified from database, NOT from JWT claims or user input.

    Args:
        connection_id: UUID of the connection
        namespace: Verified namespace from database (not JWT claims)

    Returns:
        MCPConnection aggregate

    Raises:
        AggregateNotFoundError: If connection not found OR in different namespace

    Example:
        >>> # ✅ CORRECT: Verify namespace from database
        >>> agent = await agent_repo.get_by_id(agent_id)
        >>> connection = await repo.get_by_id(uuid, agent.namespace)

        >>> # ❌ WRONG: Never trust JWT claims
        >>> jwt_namespace = jwt_claims.get("namespace")  # ❌ Can be forged
        >>> connection = await repo.get_by_id(uuid, jwt_namespace)  # 🚨 SECURITY RISK

    Security:
        - Namespace filter in SQL query (enforces isolation)
        - Returns AggregateNotFoundError if namespace mismatch (no information leakage)
    """
```

**CRITICAL**: Always verify namespace from database before calling this method.

---

### find_by_namespace_and_agent()

```python
async def find_by_namespace_and_agent(
    self, namespace: str, agent_id: str
) -> list[MCPConnection]:
    """Find all connections for a specific namespace and agent.

    SECURITY: Enforces namespace isolation by filtering on namespace.

    Args:
        namespace: Namespace to filter by
        agent_id: Agent ID to filter by

    Returns:
        List of MCPConnection aggregates (may be empty)

    Raises:
        RepositoryError: If query fails

    Example:
        >>> connections = await repo.find_by_namespace_and_agent("project-x", "agent-1")
        >>> assert all(c.namespace == "project-x" for c in connections)
        >>> assert all(c.agent_id == "agent-1" for c in connections)

    Notes:
        - Results are ordered by created_at DESC (newest first)
        - Returns empty list if no connections found (does not raise exception)
    """
```

---

### find_by_status()

```python
async def find_by_status(
    self, status: ConnectionStatus
) -> list[MCPConnection]:
    """Find all connections with a specific status.

    Args:
        status: ConnectionStatus enum value (DISCONNECTED, CONNECTING, ACTIVE, etc.)

    Returns:
        List of MCPConnection aggregates (may be empty)

    Raises:
        RepositoryError: If query fails

    Example:
        >>> active_connections = await repo.find_by_status(ConnectionStatus.ACTIVE)
        >>> assert all(c.status == ConnectionStatus.ACTIVE for c in active_connections)

    Notes:
        - Results are ordered by created_at DESC (newest first)
        - Returns empty list if no connections found
        - No namespace filtering (returns connections from all namespaces)
    """
```

**WARNING**: This method does NOT enforce namespace isolation. Use with caution in multi-tenant environments.

---

### delete()

```python
async def delete(
    self, connection_id: UUID, namespace: str, agent_id: str
) -> None:
    """Delete MCPConnection with namespace and ownership verification.

    SECURITY (P0-3): Enforces BOTH namespace isolation AND ownership.
    Both namespace and agent_id MUST be verified from database.

    Args:
        connection_id: UUID of the connection to delete
        namespace: Verified namespace from database (not JWT claims)
        agent_id: Agent requesting deletion (must be owner)

    Raises:
        AggregateNotFoundError: If connection not found, in different namespace, or not owned by agent
        RepositoryError: If deletion fails

    Example:
        >>> # ✅ CORRECT: Verify namespace and agent_id from database
        >>> agent = await agent_repo.get_by_id(agent_id)
        >>> await repo.delete(connection_id, agent.namespace, agent.id)

        >>> # ❌ WRONG: Never trust JWT claims
        >>> jwt_namespace = jwt_claims.get("namespace")
        >>> jwt_agent_id = jwt_claims.get("agent_id")
        >>> await repo.delete(connection_id, jwt_namespace, jwt_agent_id)  # 🚨 SECURITY RISK

    Security:
        - Namespace filter in SQL query (namespace isolation)
        - Agent ID filter in SQL query (ownership verification)
        - Returns AggregateNotFoundError if not owner (no information leakage)
    """
```

**CRITICAL**: Always verify both namespace AND agent_id from database before calling this method.

---

## ACL API

**Class**: `MCPProtocolTranslator`
**File**: `src/infrastructure/acl/mcp_protocol_translator.py`
**Purpose**: Translate between MCP protocol format and domain objects

### mcp_tool_to_domain()

```python
def mcp_tool_to_domain(self, mcp_tool: dict[str, Any]) -> Tool:
    """Convert MCP tool response to domain Tool entity.

    Args:
        mcp_tool: MCP tool in protocol format
            Required fields: "name", "description"
            Optional fields: "inputSchema"

    Returns:
        Tool entity with auto-inferred category

    Raises:
        MCPProtocolError: If required fields are missing or invalid

    Example:
        >>> translator = MCPProtocolTranslator()
        >>> mcp_tool = {
        ...     "name": "search_memory",
        ...     "description": "Search semantic memories",
        ...     "inputSchema": {"type": "object", "properties": {...}}
        ... }
        >>> tool = translator.mcp_tool_to_domain(mcp_tool)
        >>> tool.name
        'search_memory'
        >>> tool.category
        ToolCategory.MEMORY

    Protocol Format (MCP):
        {
            "name": string (required),
            "description": string (required),
            "inputSchema": object (optional)
        }

    Domain Format:
        Tool(name=str, description=str, input_schema=dict, category=ToolCategory)
    """
```

---

### mcp_tools_response_to_domain()

```python
def mcp_tools_response_to_domain(
    self, mcp_response: dict[str, Any]
) -> list[Tool]:
    """Convert MCP tools list response to domain Tool entities.

    Args:
        mcp_response: MCP response containing tools list
            Required field: "tools" (list)

    Returns:
        List of Tool entities

    Raises:
        MCPProtocolError: If response format is invalid (missing "tools" field or not a list)

    Example:
        >>> translator = MCPProtocolTranslator()
        >>> response = {
        ...     "tools": [
        ...         {"name": "tool1", "description": "First tool"},
        ...         {"name": "tool2", "description": "Second tool"}
        ...     ]
        ... }
        >>> tools = translator.mcp_tools_response_to_domain(response)
        >>> len(tools)
        2
        >>> tools[0].name
        'tool1'

    Protocol Format (MCP):
        {
            "tools": [
                {"name": str, "description": str, ...},
                ...
            ]
        }

    Domain Format:
        [Tool(...), Tool(...), ...]
    """
```

---

### domain_tool_execution_to_mcp()

```python
def domain_tool_execution_to_mcp(
    self, tool_name: str, tool_args: dict[str, Any]
) -> dict[str, Any]:
    """Convert domain tool execution to MCP request format.

    Args:
        tool_name: Name of the tool to execute
        tool_args: Arguments for the tool (as dict)

    Returns:
        MCP tool execution request with auto-generated requestId

    Example:
        >>> translator = MCPProtocolTranslator()
        >>> request = translator.domain_tool_execution_to_mcp(
        ...     "search_memory", {"query": "test", "limit": 5}
        ... )
        >>> request["tool"]
        'search_memory'
        >>> request["arguments"]
        {'query': 'test', 'limit': 5}
        >>> "requestId" in request
        True

    Domain Format:
        ("search_memory", {"query": "test", "limit": 5})

    MCP Format:
        {
            "tool": "search_memory",
            "arguments": {"query": "test", "limit": 5},
            "requestId": "uuid-..."
        }
    """
```

**Note**: `requestId` is auto-generated (UUID4) as required by MCP protocol.

---

### mcp_error_to_exception()

```python
def mcp_error_to_exception(self, mcp_error: dict[str, Any]) -> Exception:
    """Convert MCP error response to domain exception.

    Args:
        mcp_error: MCP error response
            Required field: "error" (object with "code", "message", "details")

    Returns:
        Appropriate exception based on error type:
        - ToolExecutionError for "TOOL_EXECUTION_FAILED"
        - MCPProtocolError for other errors

    Raises:
        MCPProtocolError: If error format is invalid

    Example:
        >>> translator = MCPProtocolTranslator()
        >>> error = {
        ...     "error": {
        ...         "code": "TOOL_EXECUTION_FAILED",
        ...         "message": "Timeout",
        ...         "details": {"tool": "slow_tool"}
        ...     }
        ... }
        >>> exc = translator.mcp_error_to_exception(error)
        >>> isinstance(exc, ToolExecutionError)
        True
        >>> exc.tool_name
        'slow_tool'

    MCP Error Format:
        {
            "error": {
                "code": string,
                "message": string,
                "details": object
            }
        }
    """
```

---

## Adapter API

**Class**: `MCPClientAdapter`
**File**: `src/infrastructure/adapters/mcp_client_adapter.py`
**Purpose**: HTTP communication with MCP servers

### Constructor

```python
def __init__(self, config: ConnectionConfig) -> None:
    """Initialize MCP client adapter.

    Args:
        config: Connection configuration (URL, timeout, retries, auth)
    """
```

---

### connect()

```python
async def connect(self) -> bool:
    """Establish connection to MCP server.

    Retry Strategy:
    - Attempts: config.retry_attempts (default: 3)
    - Backoff: 0.5 * (attempt + 1) seconds (exponential)
    - Timeout: config.timeout (default: 30 seconds)

    Returns:
        True if connection successful

    Raises:
        MCPConnectionError: If connection fails after all retries
        TimeoutError: If connection timeout is reached

    Example:
        >>> config = ConnectionConfig(
        ...     server_name="tmws",
        ...     url="http://localhost:8080/mcp"
        ... )
        >>> adapter = MCPClientAdapter(config)
        >>> success = await adapter.connect()
        >>> assert success is True

    HTTP Request:
        GET {config.url}/health
        Headers:
            Content-Type: application/json
            Accept: application/json
            Authorization: Bearer {api_key} (if auth_required)

    Expected Response:
        200 OK
    """
```

---

### disconnect()

```python
async def disconnect(self) -> None:
    """Close connection to MCP server.

    Idempotent: Can be called multiple times safely.

    Example:
        >>> await adapter.disconnect()
    """
```

---

### discover_tools()

```python
async def discover_tools(self) -> list[Tool]:
    """Discover available tools from MCP server.

    Returns:
        List of Tool entities (via ACL translation)

    Raises:
        MCPConnectionError: If not connected
        MCPProtocolError: If response format is invalid

    Example:
        >>> tools = await adapter.discover_tools()
        >>> len(tools)
        5
        >>> tools[0].name
        'store_memory'
        >>> tools[0].category
        ToolCategory.MEMORY

    HTTP Request:
        GET {config.url}/tools
        Headers:
            Content-Type: application/json
            Accept: application/json

    Expected Response:
        200 OK
        {
            "tools": [
                {"name": "...", "description": "...", "inputSchema": {...}},
                ...
            ]
        }
    """
```

---

### execute_tool()

```python
async def execute_tool(
    self, tool_name: str, tool_args: dict[str, Any]
) -> dict[str, Any]:
    """Execute a tool on the MCP server.

    Args:
        tool_name: Name of the tool to execute
        tool_args: Arguments for the tool (as dict)

    Returns:
        Tool execution result (as dict)

    Raises:
        MCPConnectionError: If not connected
        MCPToolNotFoundError: If tool does not exist (404)
        MCPProtocolError: If execution fails (non-200 response)

    Example:
        >>> result = await adapter.execute_tool(
        ...     "search_memory", {"query": "test", "limit": 5}
        ... )
        >>> result["results"]
        ["memory1", "memory2"]

    HTTP Request:
        POST {config.url}/tools/execute
        Headers:
            Content-Type: application/json
            Accept: application/json
        Body:
            {
                "tool": "search_memory",
                "arguments": {"query": "test", "limit": 5},
                "requestId": "uuid-..."
            }

    Expected Response:
        200 OK
        {
            "results": [...],
            ...
        }

    Error Responses:
        404 Not Found: Tool does not exist → MCPToolNotFoundError
        500 Internal Server Error: Execution failed → MCPProtocolError
    """
```

---

## Domain API

**Class**: `MCPConnection`
**File**: `src/domain/aggregates/mcp_connection.py`
**Purpose**: Aggregate root for MCP server connections

### mark_as_active()

```python
def mark_as_active(self, tools: list[Tool]) -> None:
    """Mark connection as ACTIVE with discovered tools.

    Business Rules:
    - Can only transition to ACTIVE from CONNECTING or DISCONNECTED
    - Must provide at least one tool (invariant)
    - Raises MCPConnectedEvent

    Args:
        tools: List of tools discovered from the MCP server

    Raises:
        InvalidStateTransitionError: If transition is not allowed
        DomainInvariantViolation: If no tools provided

    Example:
        >>> connection = MCPConnection(id=uuid4(), server_name="test", config=config)
        >>> tools = [Tool(name="tool1", description="Tool 1")]
        >>> connection.mark_as_active(tools)
        >>> connection.status
        ConnectionStatus.ACTIVE
        >>> len(connection.domain_events)
        1
        >>> isinstance(connection.domain_events[0], MCPConnectedEvent)
        True
    """
```

---

### disconnect()

```python
def disconnect(self, reason: str | None = None) -> None:
    """Disconnect from MCP server (graceful).

    Business Rules:
    - Can disconnect from any state except DISCONNECTED
    - Raises MCPDisconnectedEvent
    - Graceful disconnection (not error-based)

    Args:
        reason: Optional reason for disconnection

    Raises:
        InvalidStateTransitionError: If already disconnected

    Example:
        >>> connection.disconnect("User requested")
        >>> connection.status
        ConnectionStatus.DISCONNECTED
        >>> connection.disconnected_at is not None
        True
        >>> len(connection.domain_events)
        1
        >>> connection.domain_events[0].was_graceful
        True
    """
```

---

### mark_as_error()

```python
def mark_as_error(self, error_message: str) -> None:
    """Mark connection as ERROR (not graceful).

    Business Rules:
    - Can transition to ERROR from any state
    - Does NOT raise MCPDisconnectedEvent (error, not graceful)

    Args:
        error_message: Description of the error

    Example:
        >>> connection.mark_as_error("Connection timeout")
        >>> connection.status
        ConnectionStatus.ERROR
        >>> connection.error_message
        'Connection timeout'
        >>> len(connection.domain_events)
        0  # No event raised for errors
    """
```

---

### add_tools()

```python
def add_tools(self, new_tools: list[Tool]) -> None:
    """Add newly discovered tools to the connection.

    Business Rules:
    - Can only add tools when connection is ACTIVE
    - Raises ToolDiscoveredEvent for each new tool

    Args:
        new_tools: List of newly discovered tools

    Raises:
        DomainInvariantViolation: If connection is not ACTIVE

    Example:
        >>> new_tools = [Tool(name="new_tool", description="New")]
        >>> connection.add_tools(new_tools)
        >>> len(connection.domain_events)
        1  # One ToolDiscoveredEvent per tool
    """
```

---

### clear_events()

```python
def clear_events(self) -> None:
    """Clear domain events after they have been dispatched.

    This should be called after events have been published to
    the event bus or message queue.

    Example:
        >>> len(connection.domain_events)
        3
        >>> connection.clear_events()
        >>> len(connection.domain_events)
        0
    """
```

---

## Exceptions

### Domain Exceptions

**File**: `src/domain/exceptions.py`

#### InvalidStateTransitionError

```python
class InvalidStateTransitionError(Exception):
    """Raised when attempting an invalid state transition.

    Attributes:
        current_state: Current status (string)
        attempted_state: Attempted target status (string)
        allowed_transitions: List of allowed transitions (list of strings)
    """

    def __init__(
        self,
        current_state: str,
        attempted_state: str,
        allowed_transitions: list[str]
    ):
        message = (
            f"Invalid state transition: {current_state} → {attempted_state}. "
            f"Allowed: {', '.join(allowed_transitions)}"
        )
        super().__init__(message)
```

#### DomainInvariantViolation

```python
class DomainInvariantViolation(Exception):
    """Raised when a domain invariant is violated.

    Attributes:
        invariant: Description of the violated invariant
        current_state: Current state when violation occurred (dict)
    """

    def __init__(self, invariant: str, current_state: dict | None = None):
        message = f"Domain invariant violated: {invariant}"
        if current_state:
            message += f"\nCurrent state: {current_state}"
        super().__init__(message)
```

#### InvalidConnectionError

```python
class InvalidConnectionError(Exception):
    """Raised when connection configuration is invalid.

    Attributes:
        field: Field name that failed validation
        value: Invalid value
        reason: Reason for failure
    """

    def __init__(self, field: str, value: Any, reason: str):
        message = f"Invalid connection config ({field}={value}): {reason}"
        super().__init__(message)
```

---

### Infrastructure Exceptions

**File**: `src/infrastructure/exceptions.py`

#### RepositoryError

```python
class RepositoryError(Exception):
    """Raised when repository operation fails.

    Attributes:
        message: Error description
        details: Additional context (dict)
    """

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}
```

#### AggregateNotFoundError

```python
class AggregateNotFoundError(Exception):
    """Raised when aggregate not found in repository.

    Attributes:
        aggregate_type: Type of aggregate (e.g., "MCPConnection")
        identifier: ID or other identifier used for search
    """

    def __init__(self, aggregate_type: str, identifier: str):
        message = f"{aggregate_type} not found: {identifier}"
        super().__init__(message)
```

#### MCPConnectionError

```python
class MCPConnectionError(Exception):
    """Raised when MCP server connection fails.

    Attributes:
        message: Error description
        details: Additional context (dict)
    """

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}
```

#### MCPProtocolError

```python
class MCPProtocolError(Exception):
    """Raised when MCP protocol format is invalid.

    Attributes:
        message: Error description
        details: Additional context (dict)
    """

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}
```

#### MCPToolNotFoundError

```python
class MCPToolNotFoundError(Exception):
    """Raised when requested tool does not exist on MCP server.

    Attributes:
        tool_name: Name of the tool that was not found
        available_tools: List of available tool names (if known)
    """

    def __init__(self, tool_name: str, available_tools: list[str] | None = None):
        message = f"Tool not found: {tool_name}"
        if available_tools:
            message += f"\nAvailable tools: {', '.join(available_tools)}"
        super().__init__(message)
```

#### ToolExecutionError

```python
class ToolExecutionError(Exception):
    """Raised when tool execution fails on MCP server.

    Attributes:
        tool_name: Name of the tool that failed
        error_message: Error message from MCP server
        details: Additional context (dict)
    """

    def __init__(
        self,
        tool_name: str,
        error_message: str,
        details: dict | None = None
    ):
        message = f"Tool execution failed ({tool_name}): {error_message}"
        super().__init__(message)
        self.details = details or {}
```

---

**End of API Specification**

*Last Updated: 2025-11-12*
*Version: 1.0.0*
*Status: Production-Ready*
