"""
Acceptance Test Fixtures for MCP Connection Application Service

This module provides comprehensive fixtures for E2E acceptance testing,
including real database setup, mock MCP server, and test data builders.

Security Note:
- Uses REAL database (SQLite with WAL mode) for acceptance tests
- Mocks only EXTERNAL services (MCPClientAdapter)
- Verifies namespace isolation rigorously
"""

import asyncio
from collections.abc import AsyncGenerator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

# Domain imports
from src.domain.aggregates.mcp_connection import (
    MCPConnection,
)
from src.domain.entities.tool import Tool, ToolCategory
from src.domain.value_objects.connection_config import ConnectionConfig
from src.models.agent import Agent as AgentModel

# Infrastructure imports (use existing TMWS models)
from src.models.base import TMWSBase as Base


class MockMCPServer:
    """
    Mock MCP server for testing

    Simulates external MCP server behavior without actual network calls.
    Used for acceptance tests to verify application service integration.

    Security Note:
    - Does NOT bypass namespace verification
    - Application service must still verify namespace from database
    """

    def __init__(self):
        self._connections: dict[UUID, dict] = {}
        self._tools: dict[UUID, list[Tool]] = {}

    async def connect(
        self,
        connection_id: UUID,
        url: str,
        config: ConnectionConfig,
    ) -> None:
        """
        Simulate successful connection to MCP server

        Args:
            connection_id: Connection UUID
            url: MCP server URL
            config: Connection configuration

        Raises:
            ConnectionError: If connection_id already exists (simulate conflict)
        """
        if connection_id in self._connections:
            raise ConnectionError(f"Connection {connection_id} already exists")

        self._connections[connection_id] = {
            "url": url,
            "config": config,
            "connected_at": asyncio.get_event_loop().time(),
        }

        # Simulate network delay
        await asyncio.sleep(0.01)

    async def discover_tools(self, connection_id: UUID) -> list[Tool]:
        """
        Return mock tools list for testing

        Args:
            connection_id: Connection UUID

        Returns:
            List of mock tools

        Raises:
            ValueError: If connection not found
        """
        if connection_id not in self._connections:
            raise ValueError(f"Connection {connection_id} not found")

        # Return predefined mock tools
        tools = [
            Tool(
                name="search_memory",
                description="Search semantic memories",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "default": 10},
                    },
                    "required": ["query"],
                },
                category=ToolCategory.API,
            ),
            Tool(
                name="create_task",
                description="Create a new task",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "priority": {
                            "type": "string",
                            "enum": ["low", "medium", "high"],
                        },
                    },
                    "required": ["title"],
                },
                category=ToolCategory.API_INTEGRATION,
            ),
            Tool(
                name="analyze_code",
                description="Analyze code quality",
                input_schema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "language": {"type": "string"},
                    },
                    "required": ["code", "language"],
                },
                category=ToolCategory.CLI,
            ),
        ]

        self._tools[connection_id] = tools

        # Simulate network delay
        await asyncio.sleep(0.01)

        return tools

    async def execute_tool(
        self,
        connection_id: UUID,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """
        Simulate tool execution

        Args:
            connection_id: Connection UUID
            tool_name: Tool name to execute
            arguments: Tool-specific arguments

        Returns:
            Mock execution result

        Raises:
            ValueError: If connection or tool not found
        """
        if connection_id not in self._connections:
            raise ValueError(f"Connection {connection_id} not found")

        tools = self._tools.get(connection_id, [])
        tool = next((t for t in tools if t.name == tool_name), None)

        if not tool:
            raise ValueError(f"Tool '{tool_name}' not found")

        # Simulate network delay
        await asyncio.sleep(0.01)

        # Return mock result
        return {
            "result": "success",
            "tool": tool_name,
            "arguments": arguments,
            "output": f"Mock execution of {tool_name} completed",
        }

    async def disconnect(self, connection_id: UUID) -> None:
        """
        Simulate graceful disconnection

        Args:
            connection_id: Connection UUID
        """
        # Remove connection (even if not found - idempotent)
        self._connections.pop(connection_id, None)
        self._tools.pop(connection_id, None)

        # Simulate network delay
        await asyncio.sleep(0.01)

    def reset(self) -> None:
        """Reset mock server state (for test isolation)"""
        self._connections.clear()
        self._tools.clear()


@pytest.fixture(scope="function")
def mock_mcp_server() -> MockMCPServer:
    """
    Provide mock MCP server for each test

    Scope: function (new instance per test for isolation)

    Returns:
        MockMCPServer instance
    """
    return MockMCPServer()


@pytest_asyncio.fixture(scope="function")
async def test_database() -> AsyncGenerator[AsyncEngine, None]:
    """
    Create real SQLite database for acceptance tests

    Uses StaticPool to ensure single shared connection for in-memory database.
    WAL mode is not applicable to in-memory database, but connection pooling
    ensures proper isolation.

    Scope: function (new database per test for isolation)

    Yields:
        AsyncEngine instance

    Cleanup:
        Drops all tables after test completion
    """
    # Create in-memory database with StaticPool
    # (required for :memory: to work with async SQLAlchemy)
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        echo=False,  # Set True for SQL debugging
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup: drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_session(
    test_database: AsyncEngine,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Create async SQLAlchemy session for tests

    Args:
        test_database: Test database engine

    Yields:
        AsyncSession instance

    Cleanup:
        Rolls back any uncommitted changes
    """
    async_session_maker = async_sessionmaker(
        test_database,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_maker() as session:
        yield session

        # Rollback any uncommitted changes
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def test_agent(test_session: AsyncSession) -> AgentModel:
    """
    Create test agent with verified namespace

    SECURITY CRITICAL:
    - Creates agent in database with specific namespace
    - This namespace will be verified in authorization checks
    - Do NOT use arbitrary namespaces in tests

    Args:
        test_session: Test database session

    Returns:
        AgentModel instance with namespace='test-namespace'
    """
    agent = AgentModel(
        agent_id="test_agent",
        display_name="Test Agent",
        namespace="test-namespace",  # ✅ This is the VERIFIED namespace
        agent_type="test",
        capabilities={"mcp_connection": True, "tool_execution": True},
        config={},
        default_access_level="private",  # ✅ lowercase enum value
        status="active",  # ✅ lowercase enum value
    )

    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)

    return agent


@pytest_asyncio.fixture(scope="function")
async def attacker_agent(test_session: AsyncSession) -> AgentModel:
    """
    Create attacker agent in DIFFERENT namespace

    SECURITY TEST FIXTURE:
    - Used to verify cross-namespace access is blocked
    - Namespace: 'attacker-namespace' (different from test_agent)
    - Should NOT be able to access test_agent's connections

    Args:
        test_session: Test database session

    Returns:
        AgentModel instance with namespace='attacker-namespace'
    """
    attacker = AgentModel(
        agent_id="attacker_agent",
        display_name="Attacker Agent",
        namespace="attacker-namespace",  # ✅ Different namespace
        agent_type="test",
        capabilities={"mcp_connection": True, "tool_execution": True},
        config={},
        default_access_level="private",  # ✅ lowercase enum value
        status="active",  # ✅ lowercase enum value
    )

    test_session.add(attacker)
    await test_session.commit()
    await test_session.refresh(attacker)

    return attacker


@pytest.fixture(scope="function")
def test_connection_config() -> ConnectionConfig:
    """
    Create valid ConnectionConfig for tests

    Returns:
        ConnectionConfig instance with sensible defaults
    """
    return ConnectionConfig(
        server_name="test-mcp-server",
        url="http://localhost:8080/mcp",
        timeout=30,
        retry_attempts=3,
        auth_required=False,
        api_key=None,
    )


@pytest.fixture(scope="function")
def connection_builder():
    """
    Provide MCPConnection builder for test data

    Returns:
        Builder function for creating test connections
    """

    def build(
        server_name: str = "test-server",
        url: str = "http://localhost:8080/mcp",
        namespace: str = "test-namespace",
        agent_id: UUID = None,
    ) -> MCPConnection:
        """
        Build MCPConnection aggregate for testing

        Args:
            server_name: Server name (default: "test-server")
            url: Server URL (default: localhost)
            namespace: Namespace (default: "test-namespace")
            agent_id: Agent UUID (default: random)

        Returns:
            MCPConnection aggregate in DISCONNECTED state
        """
        config = ConnectionConfig(
            server_name=server_name,
            url=url,
            timeout=30,
            retry_attempts=3,
        )

        return MCPConnection.create(
            server_name=server_name,
            url=url,
            namespace=namespace,
            agent_id=agent_id or uuid4(),
            config=config,
        )

    return build
