"""MCP tools for agent memory management in TMWS v2.0.
These tools allow external agents to interact with the memory system via MCP protocol.
"""

from typing import Any

from fastmcp import FastMCP


class AgentMemoryTools:
    """MCP tools for agent memory operations."""

    def __init__(self, memory_service, auth_service):
        self.memory_service = memory_service
        self.auth_service = auth_service

    async def create_memory_tool(
        self,
        agent_id: str,
        content: str,
        namespace: str = "default",
        access_level: str = "private",
        tags: list[str] = None,
        context: dict[str, Any] = None,
        importance: float = 0.5,
    ) -> dict[str, Any]:
        """Create a new memory for an agent.

        This tool is called by external agents via MCP to store memories.
        The agent_id identifies the calling agent.
        """

        # Validate agent permissions
        if not await self._validate_agent(agent_id, namespace):
            return {"error": "Invalid agent credentials"}

        # Create memory
        memory = await self.memory_service.create_memory(
            content=content,
            agent_id=agent_id,
            namespace=namespace,
            access_level=access_level,
            tags=tags or [],
            context=context or {},
            importance_score=importance,
        )

        return {
            "success": True,
            "memory_id": str(memory.id),
            "message": "Memory created successfully",
        }

    async def search_memories_tool(
        self,
        agent_id: str,
        query: str,
        namespace: str = "default",
        limit: int = 10,
        include_shared: bool = True,
        min_importance: float = 0.0,
    ) -> dict[str, Any]:
        """Search memories using semantic search.

        Returns memories that the agent has access to based on:
        - Owned memories
        - Team memories (same namespace)
        - Explicitly shared memories
        - Public memories
        """

        # Validate agent
        if not await self._validate_agent(agent_id, namespace):
            return {"error": "Invalid agent credentials"}

        # Search memories with access control
        results = await self.memory_service.search_memories(
            query=query,
            agent_id=agent_id,
            namespace=namespace,
            limit=limit,
            include_shared=include_shared,
            min_importance=min_importance,
        )

        # Filter based on access permissions
        accessible_results = []
        for memory in results:
            if self.auth_service.check_memory_access(
                agent_id=agent_id,
                agent_namespace=namespace,
                memory_agent_id=memory.agent_id,
                memory_namespace=memory.namespace,
                memory_access_level=memory.access_level,
                shared_agents=memory.shared_with_agents,
            ):
                accessible_results.append(
                    {
                        "id": str(memory.id),
                        "content": memory.content,
                        "summary": memory.summary,
                        "agent_id": memory.agent_id,
                        "importance": memory.importance_score,
                        "relevance": memory.relevance_score,
                        "tags": memory.tags,
                        "created_at": memory.created_at.isoformat() if memory.created_at else None,
                    },
                )

        return {"success": True, "count": len(accessible_results), "memories": accessible_results}

    async def share_memory_tool(
        self, agent_id: str, memory_id: str, share_with_agents: list[str], permission: str = "read",
    ) -> dict[str, Any]:
        """Share a memory with other agents.

        Only the owner of a memory can share it.
        """

        # Get memory
        memory = await self.memory_service.get_memory(memory_id)
        if not memory:
            return {"error": "Memory not found"}

        # Check ownership
        if memory.agent_id != agent_id:
            return {"error": "Only memory owner can share"}

        # Update sharing
        await self.memory_service.share_memory(
            memory_id=memory_id, shared_with_agents=share_with_agents, permission=permission,
        )

        return {"success": True, "message": f"Memory shared with {len(share_with_agents)} agents"}

    async def consolidate_memories_tool(
        self,
        agent_id: str,
        memory_ids: list[str],
        consolidation_type: str = "summary",
        namespace: str = "default",
    ) -> dict[str, Any]:
        """Consolidate multiple memories into a single memory.

        Types:
        - summary: Create a summary of all memories
        - merge: Combine related memories
        - compress: Reduce redundancy
        """

        # Validate agent
        if not await self._validate_agent(agent_id, namespace):
            return {"error": "Invalid agent credentials"}

        # Check access to all memories
        memories = []
        for mem_id in memory_ids:
            memory = await self.memory_service.get_memory(mem_id)
            if not memory:
                continue

            # Check access
            if self.auth_service.check_memory_access(
                agent_id=agent_id,
                agent_namespace=namespace,
                memory_agent_id=memory.agent_id,
                memory_namespace=memory.namespace,
                memory_access_level=memory.access_level,
                shared_agents=memory.shared_with_agents,
            ):
                memories.append(memory)

        if len(memories) < 2:
            return {"error": "Need at least 2 accessible memories to consolidate"}

        # Perform consolidation
        consolidated = await self.memory_service.consolidate_memories(
            agent_id=agent_id, memories=memories, consolidation_type=consolidation_type,
        )

        return {
            "success": True,
            "consolidated_memory_id": str(consolidated.id),
            "source_count": len(memories),
            "message": f"Consolidated {len(memories)} memories",
        }

    async def get_memory_patterns_tool(
        self,
        agent_id: str,
        pattern_type: str | None = None,
        namespace: str = "default",
        min_confidence: float = 0.5,
    ) -> dict[str, Any]:
        """Get learning patterns extracted from agent's memories.

        Pattern types:
        - sequence: Temporal patterns
        - correlation: Related memories
        - cluster: Grouped memories
        """

        # Validate agent
        if not await self._validate_agent(agent_id, namespace):
            return {"error": "Invalid agent credentials"}

        # Get patterns
        patterns = await self.memory_service.get_patterns(
            agent_id=agent_id,
            namespace=namespace,
            pattern_type=pattern_type,
            min_confidence=min_confidence,
        )

        pattern_list = []
        for pattern in patterns:
            pattern_list.append(
                {
                    "id": str(pattern.id),
                    "type": pattern.pattern_type,
                    "confidence": pattern.confidence,
                    "frequency": pattern.frequency,
                    "data": pattern.pattern_data,
                    "memory_count": len(pattern.memory_ids),
                },
            )

        return {"success": True, "count": len(pattern_list), "patterns": pattern_list}

    async def _validate_agent(self, agent_id: str, namespace: str) -> bool:
        """Validate agent exists and is active."""
        # In production, this would check against database
        # For now, simple validation
        return bool(agent_id and namespace)

    async def register_tools(self, mcp: FastMCP) -> None:
        """Register all MCP tools using FastMCP decorator pattern."""

        @mcp.tool()
        async def memory_create(
            agent_id: str,
            content: str,
            namespace: str = "default",
            access_level: str = "private",
            tags: list[str] = None,
            context: dict[str, Any] = None,
            importance: float = 0.5,
        ) -> dict[str, Any]:
            """Create a new memory for an agent.

            Args:
                agent_id: Agent identifier
                content: Memory content
                namespace: Memory namespace (default: "default")
                access_level: Access level (private, team, shared, public)
                tags: List of tags for categorization
                context: Additional context metadata
                importance: Importance score (0.0 to 1.0)

            Returns:
                Dict with success status, memory_id, and metadata
            """
            return await self.create_memory_tool(
                agent_id=agent_id,
                content=content,
                namespace=namespace,
                access_level=access_level,
                tags=tags,
                context=context,
                importance=importance,
            )

        @mcp.tool()
        async def memory_search(
            agent_id: str,
            query: str,
            namespace: str = "default",
            limit: int = 10,
            include_shared: bool = True,
            min_importance: float = None,
        ) -> dict[str, Any]:
            """Search memories using semantic search.

            Args:
                agent_id: Agent identifier
                query: Search query
                namespace: Memory namespace (default: "default")
                limit: Maximum number of results (default: 10)
                include_shared: Include shared memories (default: True)
                min_importance: Minimum importance threshold

            Returns:
                Dict with memories list and search metadata
            """
            return await self.search_memories_tool(
                agent_id=agent_id,
                query=query,
                namespace=namespace,
                limit=limit,
                include_shared=include_shared,
                min_importance=min_importance,
            )

        @mcp.tool()
        async def memory_share(
            agent_id: str,
            memory_id: str,
            share_with_agents: list[str],
            permission: str = "read",
        ) -> dict[str, Any]:
            """Share a memory with other agents.

            Args:
                agent_id: Owner agent identifier
                memory_id: Memory ID to share
                share_with_agents: List of agent IDs to share with
                permission: Permission level (read, write, delete)

            Returns:
                Dict with success status and sharing details
            """
            return await self.share_memory_tool(
                agent_id=agent_id,
                memory_id=memory_id,
                share_with_agents=share_with_agents,
                permission=permission,
            )

        @mcp.tool()
        async def memory_consolidate(
            agent_id: str,
            memory_ids: list[str],
            consolidation_type: str = "summary",
            namespace: str = "default",
        ) -> dict[str, Any]:
            """Consolidate multiple memories into one.

            Args:
                agent_id: Agent identifier
                memory_ids: List of memory IDs to consolidate
                consolidation_type: Type of consolidation (summary, merge, compress)
                namespace: Memory namespace (default: "default")

            Returns:
                Dict with consolidated memory details
            """
            return await self.consolidate_memories_tool(
                agent_id=agent_id,
                memory_ids=memory_ids,
                consolidation_type=consolidation_type,
                namespace=namespace,
            )

        @mcp.tool()
        async def memory_patterns(
            agent_id: str,
            pattern_type: str = "sequence",
            namespace: str = "default",
            min_confidence: float = None,
        ) -> dict[str, Any]:
            """Get learning patterns from agent memories.

            Args:
                agent_id: Agent identifier
                pattern_type: Pattern type (sequence, correlation, cluster)
                namespace: Memory namespace (default: "default")
                min_confidence: Minimum confidence threshold

            Returns:
                Dict with detected patterns and metadata
            """
            return await self.get_memory_patterns_tool(
                agent_id=agent_id,
                pattern_type=pattern_type,
                namespace=namespace,
                min_confidence=min_confidence,
            )
