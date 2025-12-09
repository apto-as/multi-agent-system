"""Tests for Sparse Registry Manager.

Tests O(1) lookup, search, persistence, and thread safety.
"""

import asyncio
from datetime import datetime
from pathlib import Path

import pytest

from src.infrastructure.mcp.sparse_registry_manager import SparseRegistryManager
from src.models.registry import (
    MAX_REGISTRY_SIZE_MB,
    RegistryMetadata,
    RegistrySecurityError,
    ServerRegistryEntry,
    SparseRegistry,
    ToolCategory,
    ToolRegistryEntry,
    validate_server_command,
    validate_server_id,
    validate_tool_id,
)


@pytest.fixture
def temp_registry_path(tmp_path):
    """Temporary registry path for testing."""
    return tmp_path / "registry" / "index.json"


@pytest.fixture
def sample_server():
    """Sample server registry entry."""
    return ServerRegistryEntry(
        server_id="test_server",
        name="Test Server",
        command="python",
        args=["-m", "test.server"],
        env={"KEY": "value"},
        tool_count=3,
        category=ToolCategory.MEMORY,
        popularity_score=0.5,
        estimated_memory_mb=50,
        cold_start_ms=100,
    )


@pytest.fixture
def sample_tools():
    """Sample tool registry entries."""
    return [
        ToolRegistryEntry(
            tool_id="test_server::store_memory",
            name="store_memory",
            server_id="test_server",
            category=ToolCategory.MEMORY,
            description="Store data in memory",
            keywords=["store", "memory", "save"],
        ),
        ToolRegistryEntry(
            tool_id="test_server::search_memory",
            name="search_memory",
            server_id="test_server",
            category=ToolCategory.MEMORY,
            description="Search memory with semantic search",
            keywords=["search", "memory", "query"],
        ),
        ToolRegistryEntry(
            tool_id="test_server::get_stats",
            name="get_stats",
            server_id="test_server",
            category=ToolCategory.MEMORY,
            description="Get memory statistics",
            keywords=["stats", "memory", "info"],
        ),
    ]


@pytest.mark.asyncio
async def test_initialize_empty_registry(temp_registry_path):
    """Test initializing empty registry."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()

    assert manager._initialized
    assert len(manager._servers) == 0
    assert len(manager._tools) == 0
    assert temp_registry_path.exists()


@pytest.mark.asyncio
async def test_register_server(temp_registry_path, sample_server, sample_tools):
    """Test registering a server with tools."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()

    await manager.register_server(sample_server, sample_tools)

    # Verify server registered
    assert "test_server" in manager._servers
    assert manager._servers["test_server"] == sample_server

    # Verify tools registered
    assert len(manager._tools) == 3
    for tool in sample_tools:
        assert tool.tool_id in manager._tools

    # Verify tool-by-server mapping
    assert "test_server" in manager._tool_by_server
    assert len(manager._tool_by_server["test_server"]) == 3


@pytest.mark.asyncio
async def test_get_server_config(temp_registry_path, sample_server, sample_tools):
    """Test O(1) server config lookup."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()
    await manager.register_server(sample_server, sample_tools)

    # Test successful lookup
    server = manager.get_server_config("test_server")
    assert server is not None
    assert server.server_id == "test_server"
    assert server.name == "Test Server"

    # Test missing server
    missing = manager.get_server_config("missing_server")
    assert missing is None


@pytest.mark.asyncio
async def test_search_tools(temp_registry_path, sample_server, sample_tools):
    """Test tool search functionality."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()
    await manager.register_server(sample_server, sample_tools)

    # Search by name
    results = manager.search_tools("store")
    assert len(results) == 1
    assert results[0].name == "store_memory"

    # Search by keyword
    results = manager.search_tools("memory")
    assert len(results) == 3

    # Search with category filter
    results = manager.search_tools("memory", category=ToolCategory.MEMORY)
    assert len(results) == 3

    # Search with limit
    results = manager.search_tools("memory", limit=2)
    assert len(results) == 2

    # Search no match
    results = manager.search_tools("xyz123")
    assert len(results) == 0


@pytest.mark.asyncio
async def test_get_tools_for_server(temp_registry_path, sample_server, sample_tools):
    """Test getting tools for a server."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()
    await manager.register_server(sample_server, sample_tools)

    tools = manager.get_tools_for_server("test_server")
    assert len(tools) == 3

    # Test missing server
    tools = manager.get_tools_for_server("missing_server")
    assert len(tools) == 0


@pytest.mark.asyncio
async def test_update_popularity(temp_registry_path, sample_server, sample_tools):
    """Test updating server popularity score."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()
    await manager.register_server(sample_server, sample_tools)

    # Initial score
    assert manager._servers["test_server"].popularity_score == 0.5

    # Increase score
    await manager.update_popularity("test_server", delta=0.2)
    assert manager._servers["test_server"].popularity_score == 0.7

    # Decrease score
    await manager.update_popularity("test_server", delta=-0.3)
    assert abs(manager._servers["test_server"].popularity_score - 0.4) < 0.0001

    # Clamp to 0.0
    await manager.update_popularity("test_server", delta=-1.0)
    assert manager._servers["test_server"].popularity_score == 0.0

    # Clamp to 1.0
    await manager.update_popularity("test_server", delta=2.0)
    assert manager._servers["test_server"].popularity_score == 1.0


@pytest.mark.asyncio
async def test_persistence(temp_registry_path, sample_server, sample_tools):
    """Test registry persistence to disk."""
    # Register server
    manager1 = SparseRegistryManager(temp_registry_path)
    await manager1.initialize()
    await manager1.register_server(sample_server, sample_tools)

    # Load in new manager instance
    manager2 = SparseRegistryManager(temp_registry_path)
    await manager2.initialize()

    # Verify data persisted
    assert len(manager2._servers) == 1
    assert len(manager2._tools) == 3
    assert "test_server" in manager2._servers


@pytest.mark.asyncio
async def test_unregister_server(temp_registry_path, sample_server, sample_tools):
    """Test unregistering a server."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()
    await manager.register_server(sample_server, sample_tools)

    # Verify registered
    assert "test_server" in manager._servers
    assert len(manager._tools) == 3

    # Unregister
    await manager.unregister_server("test_server")

    # Verify removed
    assert "test_server" not in manager._servers
    assert len(manager._tools) == 0
    assert "test_server" not in manager._tool_by_server


@pytest.mark.asyncio
async def test_get_stats(temp_registry_path, sample_server, sample_tools):
    """Test getting registry statistics."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()
    await manager.register_server(sample_server, sample_tools)

    stats = manager.get_stats()
    assert stats["server_count"] == 1
    assert stats["tool_count"] == 3
    assert stats["total_estimated_memory_mb"] == 50
    assert "categories" in stats
    assert stats["categories"]["memory"] == 1


@pytest.mark.asyncio
async def test_thread_safety(temp_registry_path, sample_server, sample_tools):
    """Test concurrent access with asyncio.Lock."""
    manager = SparseRegistryManager(temp_registry_path)
    await manager.initialize()

    # Run concurrent updates
    tasks = []
    for i in range(10):
        server = ServerRegistryEntry(
            server_id=f"server_{i}",
            name=f"Server {i}",
            command="python",
            args=["-m", f"server_{i}"],
            tool_count=0,
            category=ToolCategory.OTHER,
            estimated_memory_mb=30,
            cold_start_ms=100,
        )
        tasks.append(manager.register_server(server, []))

    await asyncio.gather(*tasks)

    # Verify all servers registered
    assert len(manager._servers) == 10


def test_tool_registry_entry_matches_query():
    """Test tool query matching."""
    tool = ToolRegistryEntry(
        tool_id="test::store_memory",
        name="store_memory",
        server_id="test",
        category=ToolCategory.MEMORY,
        description="Store data in semantic memory",
        keywords=["store", "memory", "semantic"],
    )

    assert tool.matches_query("store")
    assert tool.matches_query("memory")
    assert tool.matches_query("semantic")
    assert tool.matches_query("STORE")  # Case-insensitive
    assert not tool.matches_query("xyz123")


def test_sparse_registry_serialization(sample_server, sample_tools):
    """Test SparseRegistry JSON serialization."""
    metadata = RegistryMetadata(
        version="1.0.0",
        created_at=datetime.now(),
        server_count=1,
        tool_count=3,
        total_size_bytes=1000,
    )

    servers = {sample_server.server_id: sample_server}
    tools = {tool.tool_id: tool for tool in sample_tools}
    tool_by_server = {sample_server.server_id: [t.tool_id for t in sample_tools]}

    registry = SparseRegistry(
        metadata=metadata, servers=servers, tools=tools, tool_by_server=tool_by_server
    )

    # Serialize to JSON
    json_str = registry.to_json()
    assert isinstance(json_str, str)
    assert "test_server" in json_str

    # Deserialize from JSON
    loaded_registry = SparseRegistry.from_json(json_str)
    assert len(loaded_registry.servers) == 1
    assert len(loaded_registry.tools) == 3
    assert loaded_registry.metadata.version == "1.0.0"


# ============================================================================
# Security Tests (Hestia Audit Compliance)
# ============================================================================


class TestSecurityValidation:
    """Tests for security validation functions."""

    def test_validate_server_id_valid(self):
        """Test valid server IDs."""
        assert validate_server_id("tmws") == "tmws"
        assert validate_server_id("my-server") == "my-server"
        assert validate_server_id("server_123") == "server_123"
        assert validate_server_id("A1") == "A1"

    def test_validate_server_id_invalid(self):
        """Test invalid server IDs are rejected."""
        invalid_ids = [
            "",  # Empty
            "-server",  # Starts with hyphen
            "_server",  # Starts with underscore
            "server;drop",  # Contains semicolon
            "server|pipe",  # Contains pipe
            "../traversal",  # Path traversal
            "a" * 65,  # Too long (>64 chars)
            "server\x00null",  # Contains null byte
        ]
        for invalid_id in invalid_ids:
            with pytest.raises(RegistrySecurityError):
                validate_server_id(invalid_id)

    def test_validate_tool_id_valid(self):
        """Test valid tool IDs."""
        assert validate_tool_id("tmws::store_memory") == "tmws::store_memory"
        assert validate_tool_id("my-server::my_tool") == "my-server::my_tool"

    def test_validate_tool_id_invalid(self):
        """Test invalid tool IDs are rejected."""
        invalid_ids = [
            "",  # Empty
            "no_separator",  # Missing ::
            "server:single",  # Single colon
            "server::tool;inject",  # Shell injection
            "../traversal::tool",  # Path traversal
        ]
        for invalid_id in invalid_ids:
            with pytest.raises(RegistrySecurityError):
                validate_tool_id(invalid_id)

    def test_validate_server_command_allowed(self):
        """Test allowed commands pass validation."""
        # Should not raise
        validate_server_command("python", ["-m", "myserver"], None)
        validate_server_command("node", ["index.js"], {"KEY": "value"})
        validate_server_command("/usr/bin/python3", ["-m", "server"], None)
        validate_server_command("uvx", ["mcp-server"], None)

    def test_validate_server_command_disallowed(self):
        """Test disallowed commands are rejected."""
        with pytest.raises(RegistrySecurityError, match="Command not allowed"):
            validate_server_command("bash", ["-c", "echo hi"], None)

        with pytest.raises(RegistrySecurityError, match="Command not allowed"):
            validate_server_command("/bin/sh", ["-c", "whoami"], None)

    def test_validate_server_command_dangerous_args(self):
        """Test dangerous args are rejected."""
        dangerous_args = [
            ["--config", "$(whoami)"],  # Command substitution
            ["-c", "import os; os.system('id')"],  # Not dangerous by char, but ok
            ["arg1", "arg2;rm -rf /"],  # Shell injection
            ["--flag", "value|cat /etc/passwd"],  # Pipe
            ["test", "test\x00null"],  # Null byte
        ]
        for args in dangerous_args:
            with pytest.raises(RegistrySecurityError, match="Dangerous characters"):
                validate_server_command("python", args, None)

    def test_validate_server_command_forbidden_env(self):
        """Test forbidden environment variables are rejected."""
        forbidden_envs = [
            {"LD_PRELOAD": "/tmp/evil.so"},
            {"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
            {"PYTHONPATH": "/tmp/evil"},
            {"pythonpath": "/tmp/evil"},  # Case insensitive
        ]
        for env in forbidden_envs:
            with pytest.raises(RegistrySecurityError, match="Forbidden environment"):
                validate_server_command("python", ["-m", "server"], env)


class TestJSONSizeLimit:
    """Tests for JSON size limit enforcement."""

    def test_json_size_limit_under_threshold(self):
        """Test JSON under size limit is accepted."""
        small_json = '{"metadata": {}, "servers": {}, "tools": {}, "tool_by_server": {}}'
        # Should not raise (but will fail on metadata parsing - that's ok)
        with pytest.raises(KeyError):  # Missing required keys
            SparseRegistry.from_json(small_json)

    def test_json_size_limit_over_threshold(self):
        """Test JSON over size limit is rejected."""
        # Create a JSON string larger than MAX_REGISTRY_SIZE_MB
        large_data = "x" * (MAX_REGISTRY_SIZE_MB * 1024 * 1024 + 1)
        large_json = f'{{"data": "{large_data}"}}'

        with pytest.raises(RegistrySecurityError, match="Registry JSON too large"):
            SparseRegistry.from_json(large_json)


class TestPathTraversal:
    """Tests for path traversal prevention."""

    def test_path_traversal_blocked(self):
        """Test path traversal attempts are blocked."""
        malicious_paths = [
            Path("/etc/passwd"),
            Path("/../../../etc/passwd"),
            Path("/home/user/../../etc/shadow"),
        ]
        for path in malicious_paths:
            with pytest.raises(RegistrySecurityError, match="allowed directories"):
                SparseRegistryManager(path)

    def test_allowed_path_accepted(self, tmp_path):
        """Test paths in /tmp are accepted."""
        valid_path = tmp_path / "registry" / "index.json"
        manager = SparseRegistryManager(valid_path)
        assert manager.registry_path == valid_path.resolve()

    def test_default_path_allowed(self):
        """Test default path is allowed."""
        manager = SparseRegistryManager()  # Uses default ~/.tmws/registry/index.json
        assert "tmws" in str(manager.registry_path)


class TestServerRegistrySecurityValidation:
    """Tests for ServerRegistryEntry security validation on deserialization."""

    def test_server_from_dict_validates_id(self):
        """Test ServerRegistryEntry.from_dict validates server_id."""
        invalid_data = {
            "server_id": "../malicious",
            "name": "Evil Server",
            "command": "python",
            "args": ["-m", "server"],
        }
        with pytest.raises(RegistrySecurityError):
            ServerRegistryEntry.from_dict(invalid_data)

    def test_server_from_dict_validates_command(self):
        """Test ServerRegistryEntry.from_dict validates command."""
        invalid_data = {
            "server_id": "valid_server",
            "name": "Server",
            "command": "bash",  # Not in allowlist
            "args": ["-c", "echo hi"],
        }
        with pytest.raises(RegistrySecurityError, match="Command not allowed"):
            ServerRegistryEntry.from_dict(invalid_data)

    def test_server_from_dict_validates_env(self):
        """Test ServerRegistryEntry.from_dict validates environment."""
        invalid_data = {
            "server_id": "valid_server",
            "name": "Server",
            "command": "python",
            "args": ["-m", "server"],
            "env": {"LD_PRELOAD": "/tmp/evil.so"},
        }
        with pytest.raises(RegistrySecurityError, match="Forbidden environment"):
            ServerRegistryEntry.from_dict(invalid_data)


class TestToolRegistrySecurityValidation:
    """Tests for ToolRegistryEntry security validation on deserialization."""

    def test_tool_from_dict_validates_ids(self):
        """Test ToolRegistryEntry.from_dict validates IDs."""
        invalid_data = {
            "tool_id": "invalid",  # Missing ::
            "name": "tool",
            "server_id": "server",
            "category": "other",
            "description": "Test tool",
        }
        with pytest.raises(RegistrySecurityError):
            ToolRegistryEntry.from_dict(invalid_data)

    def test_tool_from_dict_validates_server_id(self):
        """Test ToolRegistryEntry.from_dict validates server_id."""
        invalid_data = {
            "tool_id": "server::tool",
            "name": "tool",
            "server_id": "../malicious",  # Invalid server_id
            "category": "other",
            "description": "Test tool",
        }
        with pytest.raises(RegistrySecurityError):
            ToolRegistryEntry.from_dict(invalid_data)
