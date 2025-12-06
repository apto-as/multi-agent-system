#!/usr/bin/env python3
"""TMWS MCP Server - Hybrid SQLite + Chroma Implementation

MCP Server providing Trinitas agents with:
- Ultra-fast vector search via Chroma (P95: 0.47ms)
- Multilingual-E5 embeddings (1024-dimensional, cross-lingual)
- SQLite as relational data store
- Agent coordination and task management

Architecture: SQLite + ChromaDB
"""

from importlib.metadata import version as get_version

try:
    __version__ = get_version("tmws")
except Exception:
    __version__ = "2.4.0"  # Fallback

import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastmcp import FastMCP

from src.core.config import get_settings
from src.core.database import get_session
from src.core.exceptions import (
    ChromaOperationError,
    MCPInitializationError,
    MemoryCreationError,
    MemorySearchError,
    ServiceInitializationError,
    log_and_raise,
)
from src.infrastructure.mcp import MCPManager
from src.services.memory_service import HybridMemoryService
from src.services.ollama_embedding_service import get_ollama_embedding_service
from src.services.vector_search_service import get_vector_search_service
from src.tools.expiration_tools import ExpirationTools

logger = logging.getLogger(__name__)
settings = get_settings()


# Trinitas Agent Definitions for Auto-Registration (v2.4.0+)
TRINITAS_AGENTS = {
    "athena-conductor": {
        "display_name": "Athena (Harmonious Conductor)",
        "agent_type": "trinitas",
        "agent_subtype": "conductor",
        "capabilities": ["orchestration", "workflow", "coordination"],
    },
    "artemis-optimizer": {
        "display_name": "Artemis (Technical Perfectionist)",
        "agent_type": "trinitas",
        "agent_subtype": "optimizer",
        "capabilities": ["performance", "optimization", "technical_excellence"],
    },
    "hestia-auditor": {
        "display_name": "Hestia (Security Guardian)",
        "agent_type": "trinitas",
        "agent_subtype": "auditor",
        "capabilities": ["security", "audit", "risk_assessment"],
    },
    "eris-coordinator": {
        "display_name": "Eris (Tactical Coordinator)",
        "agent_type": "trinitas",
        "agent_subtype": "coordinator",
        "capabilities": ["tactical", "team_coordination", "conflict_resolution"],
    },
    "hera-strategist": {
        "display_name": "Hera (Strategic Commander)",
        "agent_type": "trinitas",
        "agent_subtype": "strategist",
        "capabilities": ["strategy", "planning", "architecture"],
    },
    "muses-documenter": {
        "display_name": "Muses (Knowledge Architect)",
        "agent_type": "trinitas",
        "agent_subtype": "documenter",
        "capabilities": ["documentation", "knowledge", "archival"],
    },
    # Support Layer Agents (v2.4.7+)
    "aphrodite-designer": {
        "display_name": "Aphrodite (UI/UX Designer)",
        "agent_type": "trinitas",
        "agent_subtype": "designer",
        "capabilities": ["design", "ui", "ux", "interface", "accessibility"],
    },
    "metis-developer": {
        "display_name": "Metis (Development Assistant)",
        "agent_type": "trinitas",
        "agent_subtype": "developer",
        "capabilities": ["implementation", "testing", "debugging", "refactoring"],
    },
    "aurora-researcher": {
        "display_name": "Aurora (Research Assistant)",
        "agent_type": "trinitas",
        "agent_subtype": "researcher",
        "capabilities": ["search", "research", "context", "retrieval", "synthesis"],
    },
}


class HybridMCPServer:
    """MCP Server with Hybrid Memory Architecture.

    Architecture:
    - HybridMemoryService: SQLite + Chroma unified interface
    - MultilingualEmbeddingService: 1024-dimensional embeddings
    - VectorSearchService: Chroma with P95 latency 0.47ms

    Performance improvements over legacy:
    - store_memory: 10ms → 2ms (5x faster)
    - search_memories: 200ms → 0.5ms (400x faster, Chroma-first strategy)
    """

    def __init__(self):
        # Instance identification
        self.agent_id = os.getenv("TMWS_AGENT_ID", f"agent-{uuid4().hex[:8]}")
        self.instance_id = f"{self.agent_id}-{os.getpid()}"

        # Namespace (detected once at initialization)
        self.default_namespace = None

        # Services (initialized in initialize())
        self.memory_service = None
        self.embedding_service = get_ollama_embedding_service()
        self.vector_service = get_vector_search_service()

        # Expiration scheduler (initialized in initialize())
        self.scheduler = None

        # Performance metrics
        self.metrics = {
            "requests": 0,
            "chroma_hits": 0,
            "sqlite_fallbacks": 0,
            "errors": 0,
            "avg_latency_ms": 0.0,
        }

        # External MCP server manager (for preset connections)
        self.external_mcp_manager: MCPManager | None = None

        # MCP server setup
        self.mcp = FastMCP(name="tmws", version=__version__)

        # Register MCP tools
        self._register_tools()

        logger.info(f"HybridMCPServer created: {self.instance_id}")

    def _register_tools(self):
        """Register all MCP tools with Hybrid Memory Service."""

        @self.mcp.tool(
            name="store_memory",
            description="Store information in hybrid semantic memory (SQLite + Chroma)",
        )
        async def store_memory(
            content: str,
            importance_score: float = 0.5,
            tags: list[str] = None,
            namespace: str = None,
            context: dict = None,
        ) -> dict:
            """Store memory with ultra-fast Chroma sync.

            Performance: ~2ms P95 (5x faster than legacy)

            Security: Namespace is auto-detected from project context if not provided.
            Explicit 'default' namespace is rejected to prevent cross-project leakage.
            """
            # Use cached namespace if not provided (detected once at server startup)
            if namespace is None:
                namespace = self.default_namespace

            # Validate namespace (rejects 'default')
            from src.utils.namespace import validate_namespace

            validate_namespace(namespace)

            return await self.store_memory_hybrid(
                content, importance_score, tags, namespace, context
            )

        @self.mcp.tool(
            name="search_memories",
            description="Search semantic memories (Chroma vector search, 0.47ms P95)",
        )
        async def search_memories(
            query: str,
            limit: int = 10,
            min_similarity: float = 0.7,
            namespace: str = None,
            tags: list[str] = None,
        ) -> dict:
            """Search memories with Chroma ultra-fast vector search.

            Performance: ~0.5ms P95 (ChromaDB vector search + SQLite metadata)

            Security: Namespace is auto-detected from project context if not provided.
            Explicit 'default' namespace is rejected to prevent cross-project leakage.
            """
            # Use cached namespace if not provided (detected once at server startup)
            if namespace is None:
                namespace = self.default_namespace

            # Validate namespace (rejects 'default')
            from src.utils.namespace import validate_namespace

            validate_namespace(namespace)

            return await self.search_memories_hybrid(query, limit, min_similarity, namespace, tags)

        @self.mcp.tool(name="create_task", description="Create a coordinated task")
        async def create_task(
            title: str,
            description: str = None,
            priority: str = "medium",
            assigned_agent_id: str = None,
            estimated_duration: int = None,
            due_date: str = None,
        ) -> dict:
            """Create coordinated task."""
            return await self._create_task(
                title, description, priority, assigned_agent_id, estimated_duration, due_date
            )

        @self.mcp.tool(name="get_agent_status", description="Get status of connected agents")
        async def get_agent_status() -> dict:
            """Get status of connected agents."""
            return await self._get_agent_status()

        @self.mcp.tool(name="get_memory_stats", description="Get memory statistics")
        async def get_memory_stats() -> dict:
            """Get combined SQLite + ChromaDB statistics."""
            return await self.get_hybrid_memory_stats()

        @self.mcp.tool(name="invalidate_cache", description="Clear Chroma cache (for testing)")
        async def invalidate_cache() -> dict:
            """Clear Chroma collection (use with caution)."""
            return await self.clear_chroma_cache()

        # ========================================================================
        # External MCP Server Management Tools (v2.4.3+)
        # Allows agents to dynamically connect/disconnect to preset MCP servers
        # ========================================================================

        @self.mcp.tool(
            name="list_mcp_servers",
            description="List available MCP servers from presets and their connection status",
        )
        async def list_mcp_servers() -> dict:
            """List all MCP servers defined in presets with their current status.

            Returns available servers from ~/.tmws/mcp.json and .mcp.json,
            including whether they are currently connected.

            Returns:
                dict with 'servers' list containing server info
            """
            from src.infrastructure.mcp import load_mcp_presets

            try:
                presets = load_mcp_presets()
                servers = []

                for name, preset in presets.servers.items():
                    # Check if currently connected
                    is_connected = False
                    tool_count = 0
                    if self.external_mcp_manager:
                        conn = self.external_mcp_manager.get_connection(name)
                        if conn:
                            is_connected = conn.is_connected
                            tool_count = len(conn.tools)

                    servers.append(
                        {
                            "name": name,
                            "transport_type": preset.transport_type.value,
                            "auto_connect": preset.auto_connect,
                            "is_connected": is_connected,
                            "tool_count": tool_count,
                            "command": preset.command if preset.command else None,
                            "url": preset.url if preset.url else None,
                        }
                    )

                return {
                    "status": "success",
                    "server_count": len(servers),
                    "servers": servers,
                }
            except Exception as e:
                logger.error(f"Failed to list MCP servers: {e}")
                return {
                    "status": "error",
                    "error": str(e),
                    "servers": [],
                }

        @self.mcp.tool(
            name="connect_mcp_server", description="Connect to a preset MCP server by name"
        )
        async def connect_mcp_server(server_name: str) -> dict:
            """Connect to an MCP server defined in presets.

            Only servers defined in ~/.tmws/mcp.json or .mcp.json can be connected.
            This is a security measure to prevent arbitrary command execution.

            Args:
                server_name: Name of the server as defined in presets

            Returns:
                dict with connection status and available tools
            """
            from src.infrastructure.mcp import load_mcp_presets

            try:
                # Ensure manager is initialized
                if not self.external_mcp_manager:
                    from src.infrastructure.mcp import MCPManager

                    self.external_mcp_manager = MCPManager()

                # Check if already connected
                existing = self.external_mcp_manager.get_connection(server_name)
                if existing and existing.is_connected:
                    return {
                        "status": "already_connected",
                        "server": server_name,
                        "tool_count": len(existing.tools),
                        "tools": [t.name for t in existing.tools],
                    }

                # Load presets and find the server
                presets = load_mcp_presets()
                preset = presets.get_server(server_name)

                if not preset:
                    available = list(presets.servers.keys())
                    return {
                        "status": "error",
                        "error": f"Server '{server_name}' not found in presets",
                        "available_servers": available,
                    }

                # Security check: Enforce maximum connections (prevent resource exhaustion)
                MAX_CONNECTIONS = 10
                current_connections = len(
                    [c for c in self.external_mcp_manager.connections.values() if c.is_connected]
                )
                if current_connections >= MAX_CONNECTIONS:
                    return {
                        "status": "error",
                        "error": f"Max connections ({MAX_CONNECTIONS}) reached. "
                        f"Disconnect a server first.",
                        "current_connections": current_connections,
                    }

                # Connect to the server
                logger.info(f"Connecting to MCP server: {server_name}")
                connection = await self.external_mcp_manager.connect(preset)

                return {
                    "status": "connected",
                    "server": server_name,
                    "transport_type": preset.transport_type.value,
                    "tool_count": len(connection.tools),
                    "tools": [t.name for t in connection.tools],
                }

            except Exception as e:
                logger.error(f"Failed to connect to MCP server '{server_name}': {e}")
                return {
                    "status": "error",
                    "server": server_name,
                    "error": str(e),
                }

        @self.mcp.tool(name="disconnect_mcp_server", description="Disconnect from an MCP server")
        async def disconnect_mcp_server(server_name: str) -> dict:
            """Disconnect from an MCP server.

            Args:
                server_name: Name of the server to disconnect

            Returns:
                dict with disconnection status
            """
            try:
                if not self.external_mcp_manager:
                    return {
                        "status": "error",
                        "error": "No MCP manager initialized",
                    }

                connection = self.external_mcp_manager.get_connection(server_name)
                if not connection:
                    return {
                        "status": "error",
                        "error": f"Server '{server_name}' is not connected",
                    }

                await self.external_mcp_manager.disconnect(server_name)
                logger.info(f"Disconnected from MCP server: {server_name}")

                return {
                    "status": "disconnected",
                    "server": server_name,
                }

            except Exception as e:
                logger.error(f"Failed to disconnect from MCP server '{server_name}': {e}")
                return {
                    "status": "error",
                    "server": server_name,
                    "error": str(e),
                }

        @self.mcp.tool(
            name="get_mcp_status", description="Get current status of all MCP server connections"
        )
        async def get_mcp_status() -> dict:
            """Get status of all connected MCP servers.

            Returns:
                dict with connection status and tool counts
            """
            try:
                if not self.external_mcp_manager:
                    return {
                        "status": "success",
                        "manager_initialized": False,
                        "connections": [],
                        "total_tools": 0,
                    }

                connections = self.external_mcp_manager.list_connections()
                total_tools = sum(c.get("tool_count", 0) for c in connections)

                return {
                    "status": "success",
                    "manager_initialized": True,
                    "connection_count": len(connections),
                    "connections": connections,
                    "total_tools": total_tools,
                }

            except Exception as e:
                logger.error(f"Failed to get MCP status: {e}")
                return {
                    "status": "error",
                    "error": str(e),
                }

        # Register expiration tools (v2.3.0 security-integrated tools)
        # Note: ExpirationTools.register_tools() will be called during initialize()
        # after scheduler is created, since it needs scheduler instance

    async def initialize(self):
        """Initialize MCP server with database session and services."""
        try:
            # Detect namespace once at startup (cache for all subsequent operations)
            from src.utils.namespace import detect_project_namespace

            self.default_namespace = await detect_project_namespace()
            logger.info(f"🔖 Default namespace detected: {self.default_namespace}")

            # Initialize Chroma vector service (async)
            await self.vector_service.initialize()
            logger.info("Chroma vector service initialized")

            # Register expiration tools (v2.3.0 security-integrated tools)
            # Note: Scheduler is NOT started automatically.
            # Use start_scheduler MCP tool to start it.
            # This avoids session lifecycle issues during initialization.
            expiration_tools = ExpirationTools(
                memory_service=None,  # Tools create their own session
                scheduler=None,  # Scheduler will be created by start_scheduler tool
            )
            await expiration_tools.register_tools(self.mcp, get_session)
            logger.info(
                "Expiration tools registered (10 secure MCP tools, scheduler not auto-started)"
            )

            # Register verification tools (v2.3.0+ agent trust system)
            from src.tools.verification_tools import register_verification_tools

            await register_verification_tools(self.mcp)
            logger.info(
                "Verification tools registered (5 MCP tools for agent trust & verification)"
            )

            # Register skill tools (v2.4.7+ MCP-first architecture)
            from src.tools.skill_tools import SkillTools

            skill_tools = SkillTools()
            await skill_tools.register_tools(self.mcp, get_session)
            logger.info("Skill tools registered (8 MCP tools for skill lifecycle management)")

            # Register agent tools (v2.4.7+ MCP-first architecture)
            from src.tools.agent_tools import AgentTools

            agent_tools = AgentTools()
            await agent_tools.register_tools(self.mcp, get_session)
            logger.info("Agent tools registered (9 MCP tools for agent management)")

            # Register routing tools (v2.4.8+ Orchestration Layer)
            from src.tools.routing_tools import RoutingTools

            routing_tools = RoutingTools()
            await routing_tools.register_tools(self.mcp)
            logger.info("Routing tools registered (5 MCP tools for intelligent task routing)")

            # Register communication tools (v2.4.8+ Orchestration Layer)
            from src.tools.communication_tools import CommunicationTools

            communication_tools = CommunicationTools()
            await communication_tools.register_tools(self.mcp)
            logger.info("Communication tools registered (8 MCP tools for inter-agent messaging)")

            # Register orchestration tools (v2.4.8+ Orchestration Layer)
            from src.tools.orchestration_tools import OrchestrationTools

            orchestration_tools = OrchestrationTools()
            await orchestration_tools.register_tools(self.mcp)
            logger.info("Orchestration tools registered (7 MCP tools for phase-based execution)")

            # Register learning tools (v2.4.12+ Autonomous Learning System)
            from src.tools.learning_tools import LearningTools

            learning_tools = LearningTools()
            await learning_tools.register_tools(self.mcp)
            logger.info(
                "Learning tools registered "
                "(6 MCP tools for pattern learning, evolution & chain execution)"
            )

            # Register pattern-skill tools (v2.4.12+ Pattern to Skill Auto-Generation)
            from src.tools.pattern_skill_tools import PatternSkillTools

            pattern_skill_tools = PatternSkillTools()
            await pattern_skill_tools.register_tools(self.mcp, get_session)
            logger.info(
                "Pattern-skill tools registered (4 MCP tools for pattern-to-skill promotion)"
            )

            # Register tool search tools (v2.5.0+ Tool Search + MCP Hub)
            from src.tools import tool_search_tools

            await tool_search_tools.register_tools(
                self.mcp,
                embedding_service=self.embedding_service,
                persist_directory=settings.chroma_persist_directory,
            )
            logger.info("Tool search tools registered (2 MCP tools for semantic tool discovery)")

            # Register MCP Hub management tools (v2.5.0+ Tool Search + MCP Hub Phase 3)
            from src.tools import mcp_hub_tools

            await mcp_hub_tools.register_tools(self.mcp)
            logger.info("MCP Hub tools registered (5 MCP tools for server connection management)")

            # Register internal TMWS tools in Tool Search index (v2.4.17+)
            # This enables semantic search across all 42+ internal MCP tools
            try:
                import re

                from src.models.tool_search import ToolMetadata
                from src.services.tool_search_service import get_tool_search_service

                tool_search_service = get_tool_search_service()

                # Security C-4 Fix: Sanitize metadata before ChromaDB indexing
                def sanitize_metadata(text: str, max_length: int = 500) -> str:
                    """Sanitize text for safe ChromaDB storage."""
                    if not text:
                        return ""
                    # Remove control characters and null bytes
                    sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)
                    # Remove potential injection patterns
                    sanitized = sanitized.replace("${", "").replace("$(", "")
                    # Limit length
                    return sanitized[:max_length].strip()

                def sanitize_tag(tag: str) -> str:
                    """Sanitize a tag for ChromaDB."""
                    if not tag:
                        return ""
                    # Only allow alphanumeric, underscore, hyphen
                    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", tag)
                    return sanitized[:50]  # Max tag length

                # Extract internal tools from FastMCP registry
                internal_tools: list[ToolMetadata] = []

                # Skip tool search tools themselves to avoid recursion
                skip_tools = {
                    "search_tools", "search_tools_regex", "get_tool_search_stats",
                    "record_tool_outcome", "get_tool_details", "get_promotion_candidates",
                    "promote_tool", "list_mcp_servers", "connect_mcp_server",
                    "disconnect_mcp_server", "get_mcp_status", "invalidate_cache",
                }

                if hasattr(self.mcp, "_tool_manager") and hasattr(self.mcp._tool_manager, "_tools"):
                    for tool_name, tool_obj in self.mcp._tool_manager._tools.items():
                        if tool_name in skip_tools:
                            continue

                        # Validate tool_name format (Security C-4)
                        if not re.match(r"^[a-zA-Z0-9_-]+$", tool_name) or len(tool_name) > 100:
                            logger.warning(f"Skipping tool with invalid name: {tool_name[:20]}")
                            continue

                        # Extract and sanitize tool metadata (Security C-4)
                        raw_description = getattr(tool_obj, "description", "") or ""
                        description = sanitize_metadata(raw_description, 500)
                        parameters = getattr(tool_obj, "parameters", {}) or {}

                        # Auto-generate and sanitize tags from tool name
                        name_parts = tool_name.split("_")
                        tags = ["internal", "tmws"]
                        if name_parts:
                            sanitized_tag = sanitize_tag(name_parts[0])
                            if sanitized_tag:
                                tags.append(sanitized_tag)

                        internal_tools.append(ToolMetadata(
                            name=tool_name,
                            description=(
                                description if description
                                else f"TMWS internal tool: {tool_name}"
                            ),
                            input_schema=parameters,
                            tags=tags,
                        ))

                if internal_tools:
                    await tool_search_service.register_internal_tools(internal_tools)
                    logger.info(
                        f"Registered {len(internal_tools)} internal TMWS tools "
                        "in Tool Search index"
                    )

                # Register Skills from database (if available)
                try:
                    from src.services.skill_service import SkillService

                    async with get_session() as session:
                        skill_service = SkillService(session)
                        skills = await skill_service.list_skills(is_active=True, limit=100)

                        if skills:
                            skill_metadata = []
                            for skill in skills:
                                # Security C-4: Validate and sanitize skill metadata
                                if not skill.name or not re.match(r"^[a-zA-Z0-9_-]+$", skill.name):
                                    logger.warning("Skipping skill with invalid name")
                                    continue

                                # Sanitize description and tags
                                safe_desc = sanitize_metadata(
                                    skill.description or f"TMWS Skill: {skill.display_name}",
                                    500
                                )
                                raw_tags = list(skill.tags) if skill.tags else []
                                safe_tags = [sanitize_tag(t) for t in raw_tags if sanitize_tag(t)]
                                safe_tags.append("skill")
                                if skill.persona:
                                    safe_persona = sanitize_tag(skill.persona)
                                    if safe_persona:
                                        safe_tags.append(safe_persona)

                                skill_metadata.append(ToolMetadata(
                                    name=skill.name,
                                    description=safe_desc,
                                    tags=safe_tags,
                                ))

                            if skill_metadata:
                                await tool_search_service.register_skills(skill_metadata)
                                logger.info(
                                    f"Registered {len(skill_metadata)} Skills "
                                    "in Tool Search index"
                                )
                except Exception as skill_err:
                    logger.debug(f"Skills registration skipped (non-critical): {skill_err}")

            except Exception as index_err:
                logger.warning(f"Internal tools indexing failed (non-critical): {index_err}")

            # Phase 3: Trinitas Agent File Loading (v2.4.0+, license-gated, OPTIONAL)
            # This phase generates agent markdown files for Claude Desktop
            # Failure here is non-critical and doesn't block Phase 4
            if os.getenv("TMWS_ENABLE_TRINITAS", "false").lower() == "true":
                try:
                    from src.core.trinitas_loader import TrinitasLoader
                    from src.services.license_service import LicenseService

                    # Create LicenseService instance for tier validation
                    async with get_session() as session:
                        license_service = LicenseService(db_session=session)

                        # Create TrinitasLoader instance
                        trinitas_loader = TrinitasLoader(
                            license_service=license_service,
                            memory_service=None,  # v2.4.0: Uses bundled files, DB in v2.4.1
                        )

                        # Load Trinitas agents with license gating
                        trinitas_result = await trinitas_loader.load_trinitas()

                        if trinitas_result["enabled"]:
                            logger.info(
                                f"✅ Trinitas Agent Files loaded successfully\n"
                                f"   Tier: {trinitas_result['tier'].value}\n"
                                f"   Agents loaded: {trinitas_result['agents_loaded']}/6\n"
                                f"   Output: ~/.claude/agents/"
                            )

                            # Phase 5: Verify integrity of generated agent files
                            integrity_results = await trinitas_loader.verify_integrity()
                            invalid_agents = [
                                persona for persona, valid in integrity_results.items() if not valid
                            ]

                            if invalid_agents:
                                logger.error(
                                    f"🚨 SECURITY ALERT: Agent file integrity check failed\n"
                                    f"   Invalid agents: {', '.join(invalid_agents)}\n"
                                    f"   Possible tampering detected. Please regenerate agents."
                                )
                            else:
                                logger.info(
                                    f"✅ Trinitas integrity verified: "
                                    f"All {len(integrity_results)} agents valid"
                                )
                        else:
                            logger.warning(
                                f"⚠️  Trinitas Agent Files disabled: "
                                f"{trinitas_result.get('reason', 'Unknown')}\n"
                                f"   Current tier: {trinitas_result.get('tier', 'Unknown')}"
                            )
                except Exception as e:
                    # Non-critical error: Trinitas file loading is optional feature
                    logger.warning(f"Trinitas agent file loading failed (non-critical): {e}")
                    logger.info(
                        "TMWS will continue without agent files "
                        "(database registration will still work)"
                    )

                # Phase 4: Trinitas Agent Auto-Registration (v2.4.0+, INDEPENDENT)
                # This phase registers agents to database (NOT dependent on file loading)
                logger.info("Phase 4: Trinitas Agent Auto-Registration starting...")

                try:
                    from src.services.license_service import LicenseService

                    # Validate license tier for agent registration
                    async with get_session() as session:
                        license_service = LicenseService(db_session=session)

                        # Get license key from environment
                        license_key = os.getenv("TMWS_LICENSE_KEY")
                        if not license_key:
                            raise Exception("TMWS_LICENSE_KEY not set")

                        # Validate license and check tier
                        validation_result = await license_service.validate_license_key(
                            license_key, feature_accessed="trinitas_agent_registration"
                        )

                        if not validation_result.valid:
                            raise Exception(f"Invalid license: {validation_result.error_message}")

                        # Check if tier is sufficient (PRO/ENTERPRISE)
                        from src.services.license_service import TierEnum

                        if validation_result.tier == TierEnum.FREE:
                            logger.warning(
                                "Trinitas agent registration requires PRO+ license. "
                                f"Current tier: {validation_result.tier.value}. "
                                "Agent registration skipped."
                            )
                        else:
                            logger.info(
                                f"License validated for agent registration: "
                                f"{validation_result.tier.value} tier"
                            )

                            # Ensure "trinitas" namespace exists
                            # NOTE: We create namespace manually to avoid buggy create_namespace()
                            # which has display_name parameter mismatch with AgentNamespace model
                            from sqlalchemy import select

                            from src.models.agent import AgentNamespace

                            namespace_result = await session.execute(
                                select(AgentNamespace).where(AgentNamespace.namespace == "trinitas")
                            )
                            existing_namespace = namespace_result.scalar_one_or_none()

                            if not existing_namespace:
                                trinitas_namespace = AgentNamespace(
                                    namespace="trinitas",
                                    description="Trinitas AI Agent System - 6 specialized personas",
                                    default_access_level="system",
                                    is_active=True,
                                )
                                session.add(trinitas_namespace)
                                await session.commit()
                                logger.info("✅ Created 'trinitas' namespace")
                            else:
                                logger.debug("Namespace 'trinitas' already exists")

                            # Register agents to database (directly, bypassing buggy agent_service)
                            from sqlalchemy import select

                            from src.models.agent import AccessLevel, Agent, AgentStatus

                            registered_count = 0
                            skipped_count = 0

                            for agent_id, agent_data in TRINITAS_AGENTS.items():
                                try:
                                    # Check if agent already exists
                                    result = await session.execute(
                                        select(Agent).where(Agent.agent_id == agent_id)
                                    )
                                    existing_agent = result.scalar_one_or_none()

                                    if existing_agent:
                                        logger.debug(
                                            f"Agent {agent_id} already registered, skipping"
                                        )
                                        skipped_count += 1
                                        continue

                                    # Register new agent (direct model instantiation)
                                    # Store agent_subtype in config
                                    config = {"agent_subtype": agent_data.get("agent_subtype")}

                                    agent = Agent(
                                        agent_id=agent_id,
                                        display_name=agent_data["display_name"],
                                        agent_type=agent_data["agent_type"],
                                        capabilities=agent_data["capabilities"],
                                        config=config,
                                        namespace="trinitas",
                                        default_access_level=AccessLevel.SYSTEM,
                                        status=AgentStatus.ACTIVE,
                                    )

                                    session.add(agent)
                                    await session.commit()
                                    await session.refresh(agent)

                                    logger.info(f"✅ Registered Trinitas agent: {agent_id}")
                                    registered_count += 1

                                except Exception as e:
                                    # Individual agent registration failed (continue with others)
                                    await session.rollback()
                                    logger.warning(
                                        f"Failed to register agent {agent_id}: {e}",
                                        exc_info=True,
                                        extra={"agent_id": agent_id},
                                    )

                            logger.info(
                                f"✅ Trinitas Agent Auto-Registration completed: "
                                f"{registered_count} registered, {skipped_count} skipped"
                            )

                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    # Overall registration failure (graceful degradation)
                    logger.error(
                        f"Trinitas Agent Auto-Registration failed: {e}",
                        exc_info=True,
                        extra={"phase": "agent_auto_registration"},
                    )
                    logger.warning("TMWS will continue without Trinitas agent registration")

            # Phase 6: External MCP Server Auto-Connection (v2.4.2+)
            # Connect to preset MCP servers defined in .mcp.json or ~/.tmws/mcp_servers.json
            try:
                from pathlib import Path

                from src.infrastructure.mcp import MCPManager

                self.external_mcp_manager = MCPManager()

                # Try to load presets from project directory first, then user config
                project_dir = Path.cwd()
                connected_servers = await self.external_mcp_manager.auto_connect_from_config(
                    project_dir=project_dir
                )

                if connected_servers:
                    logger.info(
                        f"✅ External MCP servers connected: {len(connected_servers)}\n"
                        f"   Servers: {', '.join(connected_servers)}"
                    )

                    # Log available tools from connected servers
                    all_tools = await self.external_mcp_manager.list_all_tools()
                    total_tools = sum(len(tools) for tools in all_tools.values())
                    logger.info(f"   Total external tools available: {total_tools}")
                else:
                    logger.info("No external MCP servers configured for auto-connect")

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                # Non-critical: External MCP connections are optional
                logger.warning(f"External MCP server auto-connection failed (non-critical): {e}")
                logger.info("TMWS will continue without external MCP server connections")

            logger.info(
                f"HybridMCPServer initialized: {self.instance_id} "
                f"(Chroma: {self.vector_service.HOT_CACHE_SIZE} hot cache)",
            )

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (ChromaOperationError, ServiceInitializationError):
            # Expected initialization errors - already logged
            raise
        except Exception as e:
            # Unexpected initialization errors
            log_and_raise(
                MCPInitializationError,
                "Failed to initialize HybridMCPServer",
                original_exception=e,
                details={"instance_id": self.instance_id},
            )

    async def store_memory_hybrid(
        self,
        content: str,
        importance_score: float,
        tags: list[str],
        namespace: str,
        context: dict,
    ) -> dict:
        """Store memory using HybridMemoryService.

        Write-through pattern: SQLite + ChromaDB simultaneously.
        """
        start_time = datetime.utcnow()
        self.metrics["requests"] += 1

        try:
            # Get database session
            async with get_session() as session:
                memory_service = HybridMemoryService(session)

                # Create memory (writes to both SQLite and ChromaDB)
                memory = await memory_service.create_memory(
                    content=content,
                    agent_id=self.agent_id,
                    namespace=namespace,
                    importance_score=importance_score,
                    tags=tags or [],
                    context=context or {},
                )

                # Calculate latency
                latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                self._update_avg_latency(latency_ms)

                logger.info(
                    f"Memory stored: {memory.id} (latency: {latency_ms:.2f}ms, "
                    f"importance_score: {importance_score})",
                )

                return {
                    "memory_id": str(memory.id),
                    "status": "stored",
                    "importance_score": importance_score,
                    "latency_ms": round(latency_ms, 2),
                    "stored_in": ["sqlite", "chroma"],
                    "embedding_model": settings.embedding_model,
                    "embedding_dimension": settings.vector_dimension,
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (MemoryCreationError, ChromaOperationError) as e:
            # Expected errors - already logged
            self.metrics["errors"] += 1
            return {"error": str(e), "status": "failed", "error_type": e.__class__.__name__}
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected memory storage error: {e}", exc_info=True)
            return {"error": str(e), "status": "failed", "error_type": "UnexpectedError"}

    async def search_memories_hybrid(
        self,
        query: str,
        limit: int,
        min_similarity: float,
        namespace: str,
        tags: list[str],
    ) -> dict:
        """Search memories using HybridMemoryService.

        Read-first pattern: ChromaDB vector search (0.47ms) → SQLite fallback.
        """
        start_time = datetime.utcnow()
        self.metrics["requests"] += 1

        try:
            async with get_session() as session:
                memory_service = HybridMemoryService(session)

                # Search (ChromaDB vector search first, SQLite metadata fallback)
                memories = await memory_service.search_memories(
                    query=query,
                    agent_id=self.agent_id,
                    namespace=namespace,
                    tags=tags,
                    limit=limit,
                    min_similarity=min_similarity,
                )

                # Calculate latency
                latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
                self._update_avg_latency(latency_ms)

                # Track ChromaDB performance (TMWS always uses ChromaDB, no fallback)
                # Latency threshold adjusted for realistic Ollama embedding generation
                if latency_ms < 200.0:  # Normal: embedding (70-90ms) + search (<10ms)
                    self.metrics["chroma_hits"] += 1
                    search_source = "chromadb"
                else:
                    # Slow path (e.g., cold start, network issues)
                    self.metrics["sqlite_fallbacks"] += 1  # Metric name kept for compatibility
                    search_source = "chromadb_slow"  # Clarified: still ChromaDB, but slow

                logger.info(
                    f"Memory search: {len(memories)} results (latency: {latency_ms:.2f}ms, "
                    f"source: {search_source})",
                )

                # search_memories() now returns list[dict] with all fields
                return {
                    "query": query,
                    "results": memories,  # Already in dict format with similarity scores
                    "count": len(memories),
                    "latency_ms": round(latency_ms, 2),
                    "search_source": search_source,
                    "embedding_model": settings.embedding_model,
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (MemorySearchError, ChromaOperationError) as e:
            # Expected errors - already logged
            self.metrics["errors"] += 1
            return {
                "error": str(e),
                "results": [],
                "count": 0,
                "error_type": e.__class__.__name__,
            }
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected memory search error: {e}", exc_info=True)
            return {"error": str(e), "results": [], "count": 0, "error_type": "UnexpectedError"}

    async def _create_task(
        self,
        title: str,
        description: str,
        priority: str,
        assigned_agent_id: str,
        estimated_duration: int = None,
        due_date: str = None,
    ) -> dict:
        """Create task in SQLite database."""
        self.metrics["requests"] += 1

        try:
            from datetime import datetime

            from src.services.task_service import TaskService

            async with get_session() as session:
                task_service = TaskService(session)

                # Parse due_date if provided
                parsed_due_date = None
                if due_date:
                    try:
                        parsed_due_date = datetime.fromisoformat(due_date)
                    except ValueError:
                        return {
                            "error": f"Invalid due_date format: {due_date}",
                            "error_type": "ValidationError",
                        }

                task = await task_service.create_task(
                    title=title,
                    description=description,
                    priority=priority,
                    assigned_agent_id=assigned_agent_id,
                    estimated_duration=estimated_duration,
                    due_date=parsed_due_date,
                )

                return {
                    "task_id": str(task.id),
                    "status": "created",
                    "assigned_to": assigned_agent_id or self.agent_id,
                    "priority": priority,
                    "estimated_duration": estimated_duration,
                    "due_date": due_date,
                    "storage": "sqlite",
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ImportError as e:
            # TaskService not available (expected during development)
            self.metrics["errors"] += 1
            logger.warning(f"TaskService not available: {e}")
            return {"error": "TaskService not available", "error_type": "ImportError"}
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected task creation error: {e}", exc_info=True)
            return {"error": str(e), "error_type": "UnexpectedError"}

    async def _get_agent_status(self) -> dict:
        """Get agent status from SQLite database."""
        self.metrics["requests"] += 1

        try:
            from src.services.agent_service import AgentService

            async with get_session() as session:
                agent_service = AgentService(session)

                agents = await agent_service.list_agents(status="active")

                return {
                    "agents": [
                        {
                            "agent_id": a.agent_id,
                            "namespace": a.namespace,
                            "status": a.status,
                            "capabilities": a.capabilities,
                        }
                        for a in agents
                    ],
                    "total": len(agents),
                    "current_instance": self.instance_id,
                    "storage": "sqlite",
                }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ImportError as e:
            # AgentService not available (expected during development)
            self.metrics["errors"] += 1
            logger.warning(f"AgentService not available: {e}")
            return {
                "error": "AgentService not available",
                "agents": [],
                "total": 0,
                "error_type": "ImportError",
            }
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected agent status error: {e}", exc_info=True)
            return {"error": str(e), "agents": [], "total": 0, "error_type": "UnexpectedError"}

    async def get_hybrid_memory_stats(self) -> dict:
        """Get combined SQLite + ChromaDB statistics."""
        self.metrics["requests"] += 1

        try:
            async with get_session() as session:
                memory_service = HybridMemoryService(session)

                stats = await memory_service.get_memory_stats(
                    agent_id=self.agent_id,
                    namespace="default",
                )

                # Add MCP server metrics
                stats["mcp_metrics"] = {
                    "total_requests": self.metrics["requests"],
                    "chroma_hits": self.metrics["chroma_hits"],
                    "sqlite_fallbacks": self.metrics["sqlite_fallbacks"],
                    "errors": self.metrics["errors"],
                    "avg_latency_ms": round(self.metrics["avg_latency_ms"], 2),
                    "chroma_hit_rate": (
                        round(
                            self.metrics["chroma_hits"]
                            / (self.metrics["chroma_hits"] + self.metrics["sqlite_fallbacks"])
                            * 100,
                            1,
                        )
                        if (self.metrics["chroma_hits"] + self.metrics["sqlite_fallbacks"]) > 0
                        else 0.0
                    ),
                }

                return stats

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except Exception as e:
            # Unexpected errors - log and return error
            self.metrics["errors"] += 1
            logger.critical(f"Unexpected stats error: {e}", exc_info=True)
            return {"error": str(e), "error_type": "UnexpectedError"}

    async def clear_chroma_cache(self) -> dict:
        """Clear Chroma collection (use with caution)."""
        try:
            await self.vector_service.clear_collection()
            logger.warning("Chroma cache cleared")

            return {
                "status": "cleared",
                "warning": "ChromaDB cache cleared. SQLite data intact.",
            }

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except ChromaOperationError as e:
            # Expected ChromaDB errors
            logger.error(f"Cache clear error: {e}")
            return {"error": str(e), "error_type": "ChromaOperationError"}
        except Exception as e:
            # Unexpected errors - log critical
            logger.critical(f"Unexpected cache clear error: {e}", exc_info=True)
            return {"error": str(e), "error_type": "UnexpectedError"}

    def _update_avg_latency(self, latency_ms: float):
        """Update rolling average latency."""
        alpha = 0.1  # Exponential moving average factor
        self.metrics["avg_latency_ms"] = (
            alpha * latency_ms + (1 - alpha) * self.metrics["avg_latency_ms"]
        )

    async def cleanup(self):
        """Cleanup on shutdown."""
        try:
            # Disconnect external MCP servers
            if self.external_mcp_manager:
                try:
                    connections = self.external_mcp_manager.list_connections()
                    if connections:
                        logger.info(f"Disconnecting {len(connections)} external MCP servers...")
                    await self.external_mcp_manager.disconnect_all()
                except Exception as e:
                    logger.warning(f"Error disconnecting external MCP servers: {e}")

            # Log final metrics
            hit_rate = "N/A"
            if (self.metrics["chroma_hits"] + self.metrics["sqlite_fallbacks"]) > 0:
                total_searches = (
                    self.metrics["chroma_hits"] + self.metrics["sqlite_fallbacks"]
                )
                hit_percentage = (
                    self.metrics["chroma_hits"] / total_searches * 100
                )
                hit_rate = f"{hit_percentage:.1f}%"
            logger.info(
                f"HybridMCPServer shutdown: {self.instance_id}\n"
                f"Final metrics: {self.metrics}\n"
                f"ChromaDB hit rate: {hit_rate}",
            )

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts during cleanup
            raise
        except Exception as e:
            # Log but don't raise during cleanup
            logger.error(f"Cleanup error: {e}", exc_info=True)


def first_run_setup():
    """First-run setup for uvx one-command installation.

    Creates necessary directories, initializes database schema, and displays setup information.
    """
    import asyncio
    import logging
    import sys

    # Configure logging to stderr early to keep stdout clean for MCP STDIO protocol
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("sqlalchemy").handlers = []
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    TMWS_HOME = Path.home() / ".tmws"
    TMWS_DATA_DIR = TMWS_HOME / "data"
    TMWS_CHROMA_DIR = TMWS_HOME / "chroma"
    INITIALIZED_FLAG = TMWS_HOME / ".initialized"

    # Check if this is first run
    if not INITIALIZED_FLAG.exists():
        # Output to stderr for visibility
        print("=" * 60, file=sys.stderr)
        print(f"🚀 TMWS v{__version__} - First-time Setup", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(file=sys.stderr)
        print(f"📁 Data directory: {TMWS_HOME}", file=sys.stderr)
        print(f"   ├── Database: {TMWS_DATA_DIR}/tmws.db", file=sys.stderr)
        print(f"   ├── ChromaDB: {TMWS_CHROMA_DIR}", file=sys.stderr)
        print(f"   ├── MCP config: {TMWS_HOME}/mcp.json", file=sys.stderr)
        print(f"   └── Secret key: {TMWS_HOME}/.secret_key", file=sys.stderr)
        print(file=sys.stderr)
        print("✅ Smart defaults enabled:", file=sys.stderr)
        print("   • SQLite database (development)", file=sys.stderr)
        print("   • Auto-generated secret key", file=sys.stderr)
        print("   • Multilingual-E5 embeddings (1024-dim)", file=sys.stderr)
        print("   • ChromaDB vector search", file=sys.stderr)
        print(file=sys.stderr)

        # Create TMWS_HOME directory
        TMWS_HOME.mkdir(parents=True, exist_ok=True)
        TMWS_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Create default MCP configuration file
        MCP_CONFIG_FILE = TMWS_HOME / "mcp.json"
        if not MCP_CONFIG_FILE.exists():
            import json

            default_mcp_config = {
                "$schema": "https://tmws.dev/schemas/mcp-servers.json",
                "$comment": (
                    "TMWS MCP Server Configuration. "
                    "Edit this file to add/remove MCP servers."
                ),
                "mcpServers": {
                    "context7": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "@upstash/context7-mcp@latest"],
                        "autoConnect": True,
                        "$comment": "Documentation lookup - https://context7.com",
                    },
                    "playwright": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "@anthropic/mcp-playwright@latest"],
                        "autoConnect": True,
                        "$comment": "Browser automation - https://playwright.dev",
                    },
                    "serena": {
                        "type": "stdio",
                        "command": "uvx",
                        "args": ["--from", "serena-mcp-server", "serena"],
                        "autoConnect": True,
                        "$comment": "Code analysis - https://github.com/oraios/serena",
                    },
                    "chrome-devtools": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "@anthropic/mcp-chrome-devtools@latest"],
                        "autoConnect": False,
                        "$comment": (
                            "Chrome DevTools - requires Chrome with remote debugging "
                            "(chrome --remote-debugging-port=9222)"
                        ),
                    },
                },
            }
            with open(MCP_CONFIG_FILE, "w") as f:
                json.dump(default_mcp_config, f, indent=2)
            print(f"   └── MCP config: {MCP_CONFIG_FILE}", file=sys.stderr)

        # Initialize database schema
        print("🔧 Initializing database schema...", file=sys.stderr)
        try:
            from src.core.config import get_settings
            from src.core.database import get_engine
            from src.models import TMWSBase

            async def init_db_schema():
                import os

                settings = get_settings()
                print(f"🔍 Current working directory: {os.getcwd()}", file=sys.stderr)
                print(f"🔍 HOME: {os.environ.get('HOME')}", file=sys.stderr)
                print(f"🔍 USER: {os.environ.get('USER')}", file=sys.stderr)
                print(
                    f"🔍 Settings database_url_async: {settings.database_url_async}",
                    file=sys.stderr,
                )

                # Extract and verify database path
                if "sqlite" in settings.database_url_async:
                    db_path_str = settings.database_url_async.replace(
                        "sqlite+aiosqlite://", ""
                    ).replace("sqlite://", "")
                    db_path = Path(db_path_str)
                    print(f"🔍 Database file path: {db_path}", file=sys.stderr)
                    print(f"🔍 Database parent exists: {db_path.parent.exists()}", file=sys.stderr)
                    print(
                        f"🔍 Database parent writable: {os.access(db_path.parent, os.W_OK)}",
                        file=sys.stderr,
                    )

                # Get the engine - let aiosqlite create the database file automatically
                engine = get_engine()
                print(f"🔍 Engine URL: {engine.url}", file=sys.stderr)

                # Create tables (aiosqlite will create the database file if it doesn't exist)
                print("🔧 Creating database schema...", file=sys.stderr)
                async with engine.begin() as conn:
                    await conn.run_sync(TMWSBase.metadata.create_all)
                await engine.dispose()

                # Clear engine cache to avoid event loop conflicts
                import src.core.database as db_module

                db_module._engine = None

                print("✅ Database schema initialized", file=sys.stderr)

            asyncio.run(init_db_schema())
        except Exception as e:
            print(f"⚠️  Database initialization error: {e}", file=sys.stderr)
            import traceback

            traceback.print_exc(file=sys.stderr)

        print(file=sys.stderr)
        print("📝 For Claude Desktop, add to config:", file=sys.stderr)
        print(
            """
{
  "tmws": {
    "command": "uvx",
    "args": ["tmws-mcp-server"]
  }
}
""",
            file=sys.stderr,
        )
        print("=" * 60, file=sys.stderr)
        print(file=sys.stderr)

        # Mark as initialized
        INITIALIZED_FLAG.touch()


async def async_main():
    """Async main entry point for MCP server."""
    # Configure logging to stderr to keep stdout clean for MCP STDIO protocol
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,  # MCP STDIO: stdout is reserved for JSON-RPC
    )
    # Ensure SQLAlchemy logs also go to stderr
    logging.getLogger("sqlalchemy").handlers = []
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    server = HybridMCPServer()

    try:
        # Initialize server
        await server.initialize()

        logger.info(
            f"🚀 TMWS v{__version__} MCP Server Started\n"
            "   Architecture: Hybrid (SQLite + Chroma)\n"
            "   Embeddings: Multilingual-E5 (1024-dim)\n"
            "   Vector Search: Chroma (P95: 0.47ms)\n"
            f"   Agent ID: {server.agent_id}\n"
            f"   Instance: {server.instance_id}",
        )

        # Run MCP server (async version to work within existing event loop)
        await server.mcp.run_async()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except (MCPInitializationError, ServiceInitializationError) as e:
        # Expected initialization errors - already logged
        logger.error(f"Server failed to initialize: {e}")
    except Exception as e:
        # Unexpected errors - log critical
        logger.critical(f"Unexpected server error: {e}", exc_info=True)
    finally:
        await server.cleanup()


async def validate_license_at_startup(license_key: str) -> dict:
    """
    Validate license key synchronously at startup.

    Args:
        license_key: License key string (format: TMWS-{TIER}-{UUID}-{CHECKSUM})

    Returns:
        dict: Validation result with keys:
            - valid (bool): Whether license is valid
            - tier (str|None): License tier (FREE, STANDARD, ENTERPRISE, UNLIMITED)
            - expires_at (str|None): Expiration timestamp (ISO format)
            - error (str|None): Error message if invalid
            - grace_period (bool): True if in 7-day grace period for expired license
    """

    from src.core.database import get_db_session
    from src.services.license_service import LicenseService

    try:
        async with get_db_session() as session:
            service = LicenseService(db_session=session)
            result = await service.validate_license_key(key=license_key)

            # Check for grace period (7 days after expiration)
            grace_period = False
            if not result.valid and result.expires_at:
                days_expired = (datetime.utcnow() - result.expires_at).days
                if 0 <= days_expired <= 7:
                    grace_period = True
                    logger.warning(
                        f"⚠️  License expired {days_expired} days ago. "
                        f"Grace period: {7 - days_expired} days remaining."
                    )

            return {
                "valid": result.valid or grace_period,
                "tier": result.tier.value if result.tier else None,
                "expires_at": result.expires_at.isoformat() if result.expires_at else None,
                "error": result.error_message,
                "grace_period": grace_period,
            }
    except Exception as e:
        logger.error(f"License validation failed: {e}", exc_info=True)
        return {
            "valid": False,
            "tier": None,
            "expires_at": None,
            "error": f"Validation error: {str(e)}",
            "grace_period": False,
        }


def main():
    """
    CLI entry point with mandatory license validation.

    Phase 2E-2: Startup License Gate
    - Validates TMWS_LICENSE_KEY environment variable
    - Enforces license tier restrictions
    - 7-day grace period for expired licenses
    - Fail-fast on invalid/missing license
    """

    # ========================================
    # Phase 2E-2: License Validation (NEW)
    # ========================================
    license_key = os.getenv("TMWS_LICENSE_KEY")

    if not license_key:
        logger.critical(
            "❌ TMWS requires a valid license key to start.\n"
            "\n"
            "Please set the TMWS_LICENSE_KEY environment variable:\n"
            "  export TMWS_LICENSE_KEY='your-license-key'\n"
            "\n"
            "To obtain a license key:\n"
            "  - FREE tier: https://trinitas.ai/licensing/free\n"
            "  - STANDARD tier: https://trinitas.ai/licensing/standard\n"
            "  - ENTERPRISE tier: contact sales@trinitas.ai\n"
        )
        sys.exit(1)

    # Validate license (async call from sync context)
    validation = asyncio.run(validate_license_at_startup(license_key))

    if not validation["valid"]:
        logger.critical(
            f"❌ Invalid license key: {validation['error']}\n"
            "\n"
            "Please check:\n"
            "  1. License key format: TMWS-{{TIER}}-{{UUID}}-{{CHECKSUM}}\n"
            "  2. License has not been revoked\n"
            "  3. License has not expired (7-day grace period available)\n"
            "\n"
            "To renew or upgrade:\n"
            "  https://trinitas.ai/licensing/renew\n"
        )
        sys.exit(1)

    # Log successful validation
    if validation["grace_period"]:
        logger.warning(
            f"⚠️  TMWS starting with EXPIRED license (grace period active)\n"
            f"   Tier: {validation['tier']}\n"
            f"   Expired: {validation['expires_at']}\n"
            f"   Please renew soon: https://trinitas.ai/licensing/renew\n"
        )
    else:
        logger.info(
            f"✅ License validated successfully\n"
            f"   Tier: {validation['tier']}\n"
            f"   Expires: {validation['expires_at'] or 'Never (lifetime license)'}\n"
        )

    # ========================================
    # Phase 2: Server Startup (EXISTING)
    # ========================================
    # First-run setup (synchronous)
    first_run_setup()

    # Run async main
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
