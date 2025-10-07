"""
Comprehensive unit tests for AgentMemoryTools with 100% coverage.
Tests all MCP tool functionality for agent memory operations.

Strategic coverage implementation by Hera for 80% target achievement.
"""

from datetime import datetime
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from src.tools.agent_memory_tools import AgentMemoryTools


class TestAgentMemoryTools:
    """Test AgentMemoryTools class functionality."""

    @pytest.fixture
    def mock_memory_service(self):
        """Mock memory service."""
        service = AsyncMock()
        service.create_memory = AsyncMock()
        service.get_memory = AsyncMock()
        service.search_memories = AsyncMock()
        service.share_memory = AsyncMock()
        service.consolidate_memories = AsyncMock()
        service.get_patterns = AsyncMock()
        return service

    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service."""
        service = Mock()
        service.check_memory_access = Mock(return_value=True)
        return service

    @pytest.fixture
    def agent_memory_tools(self, mock_memory_service, mock_auth_service):
        """Create AgentMemoryTools instance."""
        return AgentMemoryTools(mock_memory_service, mock_auth_service)

    @pytest.fixture
    def sample_memory(self):
        """Sample memory object for testing."""
        memory = Mock()
        memory.id = uuid4()
        memory.content = "Test memory content"
        memory.summary = "Test summary"
        memory.agent_id = "test_agent"
        memory.namespace = "default"
        memory.access_level = "private"
        memory.shared_with_agents = []
        memory.importance_score = 0.8
        memory.relevance_score = 0.9
        memory.tags = ["test", "memory"]
        memory.created_at = datetime.now()
        return memory

    def test_agent_memory_tools_initialization(self, mock_memory_service, mock_auth_service):
        """Test AgentMemoryTools initialization."""
        tools = AgentMemoryTools(mock_memory_service, mock_auth_service)

        assert tools.memory_service == mock_memory_service
        assert tools.auth_service == mock_auth_service

    @pytest.mark.asyncio
    async def test_create_memory_tool_success(self, agent_memory_tools, mock_memory_service, sample_memory):
        """Test successful memory creation."""
        mock_memory_service.create_memory.return_value = sample_memory

        result = await agent_memory_tools.create_memory_tool(
            agent_id="test_agent",
            content="Test content",
            namespace="default",
            access_level="private",
            tags=["test"],
            context={"test": "data"},
            importance=0.8
        )

        assert result["success"] is True
        assert "memory_id" in result
        assert result["message"] == "Memory created successfully"

        mock_memory_service.create_memory.assert_called_once_with(
            content="Test content",
            agent_id="test_agent",
            namespace="default",
            access_level="private",
            tags=["test"],
            context={"test": "data"},
            importance_score=0.8
        )

    @pytest.mark.asyncio
    async def test_create_memory_tool_invalid_agent(self, agent_memory_tools):
        """Test memory creation with invalid agent."""
        # Mock invalid agent validation
        agent_memory_tools._validate_agent = AsyncMock(return_value=False)

        result = await agent_memory_tools.create_memory_tool(
            agent_id="invalid_agent",
            content="Test content"
        )

        assert result["error"] == "Invalid agent credentials"

    @pytest.mark.asyncio
    async def test_create_memory_tool_defaults(self, agent_memory_tools, mock_memory_service, sample_memory):
        """Test memory creation with default values."""
        mock_memory_service.create_memory.return_value = sample_memory

        result = await agent_memory_tools.create_memory_tool(
            agent_id="test_agent",
            content="Test content"
        )

        assert result["success"] is True

        mock_memory_service.create_memory.assert_called_once_with(
            content="Test content",
            agent_id="test_agent",
            namespace="default",
            access_level="private",
            tags=[],
            context={},
            importance_score=0.5
        )

    @pytest.mark.asyncio
    async def test_search_memories_tool_success(self, agent_memory_tools, mock_memory_service,
                                              mock_auth_service, sample_memory):
        """Test successful memory search."""
        mock_memory_service.search_memories.return_value = [sample_memory]
        mock_auth_service.check_memory_access.return_value = True

        result = await agent_memory_tools.search_memories_tool(
            agent_id="test_agent",
            query="test query",
            namespace="default",
            limit=10,
            include_shared=True,
            min_importance=0.5
        )

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["memories"]) == 1

        memory_result = result["memories"][0]
        assert memory_result["content"] == "Test memory content"
        assert memory_result["summary"] == "Test summary"
        assert memory_result["agent_id"] == "test_agent"
        assert memory_result["importance"] == 0.8

    @pytest.mark.asyncio
    async def test_search_memories_tool_no_access(self, agent_memory_tools, mock_memory_service,
                                                 mock_auth_service, sample_memory):
        """Test memory search with no access permissions."""
        mock_memory_service.search_memories.return_value = [sample_memory]
        mock_auth_service.check_memory_access.return_value = False

        result = await agent_memory_tools.search_memories_tool(
            agent_id="test_agent",
            query="test query"
        )

        assert result["success"] is True
        assert result["count"] == 0
        assert len(result["memories"]) == 0

    @pytest.mark.asyncio
    async def test_search_memories_tool_invalid_agent(self, agent_memory_tools):
        """Test memory search with invalid agent."""
        agent_memory_tools._validate_agent = AsyncMock(return_value=False)

        result = await agent_memory_tools.search_memories_tool(
            agent_id="invalid_agent",
            query="test query"
        )

        assert result["error"] == "Invalid agent credentials"

    @pytest.mark.asyncio
    async def test_share_memory_tool_success(self, agent_memory_tools, mock_memory_service, sample_memory):
        """Test successful memory sharing."""
        sample_memory.agent_id = "test_agent"  # Set owner
        mock_memory_service.get_memory.return_value = sample_memory

        result = await agent_memory_tools.share_memory_tool(
            agent_id="test_agent",
            memory_id=str(sample_memory.id),
            share_with_agents=["agent1", "agent2"],
            permission="read"
        )

        assert result["success"] is True
        assert "agents" in result["message"]

        mock_memory_service.share_memory.assert_called_once_with(
            memory_id=str(sample_memory.id),
            shared_with_agents=["agent1", "agent2"],
            permission="read"
        )

    @pytest.mark.asyncio
    async def test_share_memory_tool_not_found(self, agent_memory_tools, mock_memory_service):
        """Test sharing non-existent memory."""
        mock_memory_service.get_memory.return_value = None

        result = await agent_memory_tools.share_memory_tool(
            agent_id="test_agent",
            memory_id="nonexistent",
            share_with_agents=["agent1"]
        )

        assert result["error"] == "Memory not found"

    @pytest.mark.asyncio
    async def test_share_memory_tool_not_owner(self, agent_memory_tools, mock_memory_service, sample_memory):
        """Test sharing memory without ownership."""
        sample_memory.agent_id = "other_agent"  # Different owner
        mock_memory_service.get_memory.return_value = sample_memory

        result = await agent_memory_tools.share_memory_tool(
            agent_id="test_agent",
            memory_id=str(sample_memory.id),
            share_with_agents=["agent1"]
        )

        assert result["error"] == "Only memory owner can share"

    @pytest.mark.asyncio
    async def test_consolidate_memories_tool_success(self, agent_memory_tools, mock_memory_service,
                                                    mock_auth_service, sample_memory):
        """Test successful memory consolidation."""
        # Create multiple memories
        memory1 = Mock()
        memory1.id = uuid4()
        memory1.agent_id = "test_agent"
        memory1.namespace = "default"
        memory1.access_level = "private"
        memory1.shared_with_agents = []

        memory2 = Mock()
        memory2.id = uuid4()
        memory2.agent_id = "test_agent"
        memory2.namespace = "default"
        memory2.access_level = "private"
        memory2.shared_with_agents = []

        consolidated = Mock()
        consolidated.id = uuid4()

        mock_memory_service.get_memory.side_effect = [memory1, memory2]
        mock_memory_service.consolidate_memories.return_value = consolidated
        mock_auth_service.check_memory_access.return_value = True

        result = await agent_memory_tools.consolidate_memories_tool(
            agent_id="test_agent",
            memory_ids=[str(memory1.id), str(memory2.id)],
            consolidation_type="summary",
            namespace="default"
        )

        assert result["success"] is True
        assert result["source_count"] == 2
        assert "consolidated_memory_id" in result

    @pytest.mark.asyncio
    async def test_consolidate_memories_tool_insufficient_memories(self, agent_memory_tools,
                                                                  mock_memory_service,
                                                                  mock_auth_service):
        """Test consolidation with insufficient memories."""
        mock_memory_service.get_memory.return_value = None

        result = await agent_memory_tools.consolidate_memories_tool(
            agent_id="test_agent",
            memory_ids=["id1"]
        )

        assert result["error"] == "Need at least 2 accessible memories to consolidate"

    @pytest.mark.asyncio
    async def test_consolidate_memories_tool_invalid_agent(self, agent_memory_tools):
        """Test consolidation with invalid agent."""
        agent_memory_tools._validate_agent = AsyncMock(return_value=False)

        result = await agent_memory_tools.consolidate_memories_tool(
            agent_id="invalid_agent",
            memory_ids=["id1", "id2"]
        )

        assert result["error"] == "Invalid agent credentials"

    @pytest.mark.asyncio
    async def test_get_memory_patterns_tool_success(self, agent_memory_tools, mock_memory_service):
        """Test successful pattern retrieval."""
        pattern = Mock()
        pattern.id = uuid4()
        pattern.pattern_type = "sequence"
        pattern.confidence = 0.8
        pattern.frequency = 5
        pattern.pattern_data = {"test": "data"}
        pattern.memory_ids = [uuid4(), uuid4()]

        mock_memory_service.get_patterns.return_value = [pattern]

        result = await agent_memory_tools.get_memory_patterns_tool(
            agent_id="test_agent",
            pattern_type="sequence",
            namespace="default",
            min_confidence=0.5
        )

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["patterns"]) == 1

        pattern_result = result["patterns"][0]
        assert pattern_result["type"] == "sequence"
        assert pattern_result["confidence"] == 0.8
        assert pattern_result["memory_count"] == 2

    @pytest.mark.asyncio
    async def test_get_memory_patterns_tool_invalid_agent(self, agent_memory_tools):
        """Test pattern retrieval with invalid agent."""
        agent_memory_tools._validate_agent = AsyncMock(return_value=False)

        result = await agent_memory_tools.get_memory_patterns_tool(
            agent_id="invalid_agent"
        )

        assert result["error"] == "Invalid agent credentials"

    @pytest.mark.asyncio
    async def test_validate_agent_valid(self, agent_memory_tools):
        """Test agent validation with valid agent."""
        result = await agent_memory_tools._validate_agent("test_agent", "default")
        assert result is True

    @pytest.mark.asyncio
    async def test_validate_agent_empty_id(self, agent_memory_tools):
        """Test agent validation with empty agent ID."""
        result = await agent_memory_tools._validate_agent("", "default")
        assert result is False

    @pytest.mark.asyncio
    async def test_validate_agent_empty_namespace(self, agent_memory_tools):
        """Test agent validation with empty namespace."""
        result = await agent_memory_tools._validate_agent("test_agent", "")
        assert result is False

    def test_register_tools(self, agent_memory_tools):
        """Test MCP tool registration."""
        tools = agent_memory_tools.register_tools()

        assert len(tools) == 5
        tool_names = [tool.name for tool in tools]

        assert "memory_create" in tool_names
        assert "memory_search" in tool_names
        assert "memory_share" in tool_names
        assert "memory_consolidate" in tool_names
        assert "memory_patterns" in tool_names

        # Test tool schema structure
        for tool in tools:
            assert hasattr(tool, 'name')
            assert hasattr(tool, 'description')
            assert hasattr(tool, 'input_schema')
            assert hasattr(tool, 'func')

            # Validate schema structure
            schema = tool.input_schema
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema


class TestAgentMemoryToolsIntegration:
    """Integration tests for AgentMemoryTools."""

    @pytest.fixture
    def agent_memory_tools(self):
        """Create AgentMemoryTools with real-like services."""
        memory_service = AsyncMock()
        auth_service = Mock()
        return AgentMemoryTools(memory_service, auth_service)

    @pytest.mark.asyncio
    async def test_full_memory_workflow(self, agent_memory_tools):
        """Test complete memory workflow: create -> search -> share -> consolidate."""
        agent_id = "test_agent"

        # Mock memory creation
        created_memory = Mock()
        created_memory.id = uuid4()
        agent_memory_tools.memory_service.create_memory.return_value = created_memory

        # Create memory
        create_result = await agent_memory_tools.create_memory_tool(
            agent_id=agent_id,
            content="Test memory content",
            tags=["test"]
        )
        assert create_result["success"] is True

        # Mock search results
        search_memory = Mock()
        search_memory.id = created_memory.id
        search_memory.content = "Test memory content"
        search_memory.summary = "Test summary"
        search_memory.agent_id = agent_id
        search_memory.namespace = "default"
        search_memory.access_level = "private"
        search_memory.shared_with_agents = []
        search_memory.importance_score = 0.5
        search_memory.relevance_score = 0.8
        search_memory.tags = ["test"]
        search_memory.created_at = datetime.now()

        agent_memory_tools.memory_service.search_memories.return_value = [search_memory]
        agent_memory_tools.auth_service.check_memory_access.return_value = True

        # Search memory
        search_result = await agent_memory_tools.search_memories_tool(
            agent_id=agent_id,
            query="test"
        )
        assert search_result["success"] is True
        assert search_result["count"] == 1

        # Mock memory for sharing
        agent_memory_tools.memory_service.get_memory.return_value = search_memory

        # Share memory
        share_result = await agent_memory_tools.share_memory_tool(
            agent_id=agent_id,
            memory_id=str(search_memory.id),
            share_with_agents=["other_agent"]
        )
        assert share_result["success"] is True

    @pytest.mark.asyncio
    async def test_error_handling_chain(self, agent_memory_tools):
        """Test error handling in operation chain."""
        # Test invalid agent throughout workflow
        agent_memory_tools._validate_agent = AsyncMock(return_value=False)

        # All operations should fail with invalid agent
        operations = [
            agent_memory_tools.create_memory_tool("invalid", "content"),
            agent_memory_tools.search_memories_tool("invalid", "query"),
            agent_memory_tools.consolidate_memories_tool("invalid", ["id1", "id2"]),
            agent_memory_tools.get_memory_patterns_tool("invalid")
        ]

        for operation in operations:
            result = await operation
            assert "error" in result
            assert result["error"] == "Invalid agent credentials"

    @pytest.mark.asyncio
    async def test_access_control_scenarios(self, agent_memory_tools):
        """Test various access control scenarios."""
        # Setup memory with different access levels
        private_memory = Mock()
        private_memory.agent_id = "owner_agent"
        private_memory.access_level = "private"

        public_memory = Mock()
        public_memory.agent_id = "owner_agent"
        public_memory.access_level = "public"

        # Test access control for different scenarios
        test_cases = [
            ("owner_agent", "private", True),
            ("other_agent", "private", False),
            ("any_agent", "public", True),
        ]

        for agent_id, access_level, expected_access in test_cases:
            agent_memory_tools.auth_service.check_memory_access.return_value = expected_access

            # Mock search with this memory
            memory = private_memory if access_level == "private" else public_memory
            agent_memory_tools.memory_service.search_memories.return_value = [memory]

            result = await agent_memory_tools.search_memories_tool(
                agent_id=agent_id,
                query="test"
            )

            assert result["success"] is True
            expected_count = 1 if expected_access else 0
            assert result["count"] == expected_count
