"""Example usage of Sparse Registry Manager.

Demonstrates:
- Initializing registry
- Registering servers and tools
- Searching tools
- Updating popularity
- Getting statistics
"""

import asyncio
from pathlib import Path

from src.models.registry import (
    ServerRegistryEntry,
    ToolRegistryEntry,
    ToolCategory,
)
from src.infrastructure.mcp.sparse_registry_manager import SparseRegistryManager


async def main():
    """Example usage of Sparse Registry Manager."""

    print("=" * 60)
    print("Sparse Registry Manager - Example Usage")
    print("=" * 60)

    # Initialize registry
    print("\n1. Initializing registry...")
    registry_path = Path("~/.tmws/registry/example.json").expanduser()
    manager = SparseRegistryManager(registry_path)
    await manager.initialize()
    print(f"   ✅ Registry initialized at {registry_path}")

    # Register a server
    print("\n2. Registering TMWS server...")
    tmws_server = ServerRegistryEntry(
        server_id="tmws",
        name="TMWS Memory System",
        command="python",
        args=["-m", "tmws.server"],
        env=None,
        tool_count=5,
        category=ToolCategory.MEMORY,
        popularity_score=0.0,
        estimated_memory_mb=60,
        cold_start_ms=120,
    )

    tmws_tools = [
        ToolRegistryEntry(
            tool_id="tmws::store_memory",
            name="store_memory",
            server_id="tmws",
            category=ToolCategory.MEMORY,
            description="Store information in semantic memory with vector embeddings",
            keywords=["store", "memory", "semantic", "vector"],
        ),
        ToolRegistryEntry(
            tool_id="tmws::search_memories",
            name="search_memories",
            server_id="tmws",
            category=ToolCategory.MEMORY,
            description="Search memories using semantic vector similarity",
            keywords=["search", "memory", "semantic", "query"],
        ),
        ToolRegistryEntry(
            tool_id="tmws::get_memory_stats",
            name="get_memory_stats",
            server_id="tmws",
            category=ToolCategory.MEMORY,
            description="Get statistics about memory usage and storage",
            keywords=["stats", "memory", "metrics"],
        ),
        ToolRegistryEntry(
            tool_id="tmws::verify_and_record",
            name="verify_and_record",
            server_id="tmws",
            category=ToolCategory.MEMORY,
            description="Verify agent actions and record verification evidence",
            keywords=["verify", "trust", "audit"],
        ),
        ToolRegistryEntry(
            tool_id="tmws::get_agent_trust_score",
            name="get_agent_trust_score",
            server_id="tmws",
            category=ToolCategory.MEMORY,
            description="Get trust score for a specific agent",
            keywords=["trust", "agent", "score"],
        ),
    ]

    await manager.register_server(tmws_server, tmws_tools)
    print(f"   ✅ Registered TMWS server with {len(tmws_tools)} tools")

    # Register another server
    print("\n3. Registering Serena server...")
    serena_server = ServerRegistryEntry(
        server_id="serena",
        name="Serena Code Assistant",
        command="python",
        args=["-m", "serena.server"],
        env=None,
        tool_count=3,
        category=ToolCategory.CODE,
        popularity_score=0.0,
        estimated_memory_mb=80,
        cold_start_ms=150,
    )

    serena_tools = [
        ToolRegistryEntry(
            tool_id="serena::find_symbol",
            name="find_symbol",
            server_id="serena",
            category=ToolCategory.CODE,
            description="Find code symbols by name path pattern",
            keywords=["find", "symbol", "code", "search"],
        ),
        ToolRegistryEntry(
            tool_id="serena::replace_symbol_body",
            name="replace_symbol_body",
            server_id="serena",
            category=ToolCategory.CODE,
            description="Replace the body of a code symbol",
            keywords=["replace", "symbol", "refactor", "edit"],
        ),
        ToolRegistryEntry(
            tool_id="serena::search_for_pattern",
            name="search_for_pattern",
            server_id="serena",
            category=ToolCategory.CODE,
            description="Search codebase for regex patterns",
            keywords=["search", "pattern", "regex", "grep"],
        ),
    ]

    await manager.register_server(serena_server, serena_tools)
    print(f"   ✅ Registered Serena server with {len(serena_tools)} tools")

    # O(1) lookup of server config
    print("\n4. O(1) Server Config Lookup...")
    server = manager.get_server_config("tmws")
    if server:
        print(f"   Server ID: {server.server_id}")
        print(f"   Name: {server.name}")
        print(f"   Category: {server.category.value}")
        print(f"   Tool Count: {server.tool_count}")
        print(f"   Memory: {server.estimated_memory_mb} MB")
        print(f"   Cold Start: {server.cold_start_ms} ms")

    # Search tools
    print("\n5. Tool Search...")

    print("   Search 'memory':")
    results = manager.search_tools("memory", limit=5)
    for i, tool in enumerate(results, 1):
        print(f"      {i}. {tool.name} ({tool.server_id})")
        print(f"         → {tool.description}")

    print("\n   Search 'search' with MEMORY category:")
    results = manager.search_tools("search", category=ToolCategory.MEMORY, limit=3)
    for i, tool in enumerate(results, 1):
        print(f"      {i}. {tool.name} ({tool.server_id})")

    print("\n   Search 'symbol' with CODE category:")
    results = manager.search_tools("symbol", category=ToolCategory.CODE, limit=3)
    for i, tool in enumerate(results, 1):
        print(f"      {i}. {tool.name} ({tool.server_id})")

    # Get tools for server
    print("\n6. Get Tools for Server...")
    tools = manager.get_tools_for_server("serena")
    print(f"   Serena server has {len(tools)} tools:")
    for tool in tools:
        print(f"      - {tool.name}")

    # Update popularity
    print("\n7. Update Popularity...")
    print(f"   TMWS initial popularity: {manager._servers['tmws'].popularity_score:.2f}")
    await manager.update_popularity("tmws", delta=0.15)
    print(f"   TMWS after +0.15: {manager._servers['tmws'].popularity_score:.2f}")
    await manager.update_popularity("tmws", delta=0.20)
    print(f"   TMWS after +0.20: {manager._servers['tmws'].popularity_score:.2f}")

    # Get statistics
    print("\n8. Registry Statistics...")
    stats = manager.get_stats()
    print(f"   Total Servers: {stats['server_count']}")
    print(f"   Total Tools: {stats['tool_count']}")
    print(f"   Total Memory: {stats['total_estimated_memory_mb']} MB")
    print(f"   Registry Size: {stats['registry_size_bytes']} bytes")
    print(f"   Categories:")
    for category, count in stats["categories"].items():
        print(f"      - {category}: {count} servers")

    print("\n" + "=" * 60)
    print("Example completed!")
    print(f"Registry saved to: {registry_path}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
