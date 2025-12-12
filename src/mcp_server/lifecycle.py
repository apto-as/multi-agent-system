"""Server lifecycle management - initialization and cleanup.

This module contains the initialization logic for HybridMCPServer.
"""

import logging
import os
import re

from src.core.database import get_session
from src.models.tool_search import ToolMetadata
from src.services.tool_search_service import get_tool_search_service
from src.tools.expiration_tools import ExpirationTools

logger = logging.getLogger(__name__)


async def initialize_server(server):
    """Initialize MCP server with database session and services.

    Args:
        server: HybridMCPServer instance

    This function:
    1. Detects project namespace
    2. Initializes Chroma vector service
    3. Registers all tool categories (expiration, verification, skill, agent, etc.)
    4. Loads Trinitas agents if enabled
    5. Auto-connects to external MCP servers
    """
    from src.core.config import get_settings
    from src.core.exceptions import (
        ChromaOperationError,
        MCPInitializationError,
        ServiceInitializationError,
        log_and_raise,
    )

    settings = get_settings()

    try:
        # Detect namespace once at startup (cache for all subsequent operations)
        from src.utils.namespace import detect_project_namespace

        server.default_namespace = await detect_project_namespace()
        logger.info(f"🔖 Default namespace detected: {server.default_namespace}")

        # Initialize Chroma vector service (async)
        await server.vector_service.initialize()
        logger.info("Chroma vector service initialized")

        # Register expiration tools (v2.3.0 security-integrated tools)
        # Note: Scheduler is NOT started automatically.
        # Use start_scheduler MCP tool to start it.
        # This avoids session lifecycle issues during initialization.
        expiration_tools = ExpirationTools(
            memory_service=None,  # Tools create their own session
            scheduler=None,  # Scheduler will be created by start_scheduler tool
        )
        await expiration_tools.register_tools(server.mcp, get_session)
        logger.info(
            "Expiration tools registered (10 secure MCP tools, scheduler not auto-started)"
        )

        # Register verification tools (v2.3.0+ agent trust system)
        from src.tools.verification_tools import register_verification_tools

        await register_verification_tools(server.mcp)
        logger.info(
            "Verification tools registered (5 MCP tools for agent trust & verification)"
        )

        # Register skill tools (v2.4.7+ MCP-first architecture)
        from src.tools.skill_tools import SkillTools

        skill_tools = SkillTools()
        await skill_tools.register_tools(server.mcp, get_session)
        logger.info("Skill tools registered (8 MCP tools for skill lifecycle management)")

        # Register agent tools (v2.4.7+ MCP-first architecture)
        from src.tools.agent_tools import AgentTools

        agent_tools = AgentTools()
        await agent_tools.register_tools(server.mcp, get_session)
        logger.info("Agent tools registered (9 MCP tools for agent management)")

        # Register routing tools (v2.4.8+ Orchestration Layer)
        from src.tools.routing_tools import RoutingTools

        routing_tools = RoutingTools()
        await routing_tools.register_tools(server.mcp)
        logger.info("Routing tools registered (5 MCP tools for intelligent task routing)")

        # Register communication tools (v2.4.8+ Orchestration Layer)
        from src.tools.communication_tools import CommunicationTools

        communication_tools = CommunicationTools()
        await communication_tools.register_tools(server.mcp)
        logger.info("Communication tools registered (8 MCP tools for inter-agent messaging)")

        # Register orchestration tools (v2.4.8+ Orchestration Layer)
        from src.tools.orchestration_tools import OrchestrationTools

        orchestration_tools = OrchestrationTools()
        await orchestration_tools.register_tools(server.mcp)
        logger.info("Orchestration tools registered (7 MCP tools for phase-based execution)")

        # Register learning tools (v2.4.12+ Autonomous Learning System)
        from src.tools.learning_tools import LearningTools

        learning_tools = LearningTools()
        await learning_tools.register_tools(server.mcp)
        logger.info(
            "Learning tools registered "
            "(6 MCP tools for pattern learning, evolution & chain execution)"
        )

        # Register pattern-skill tools (v2.4.12+ Pattern to Skill Auto-Generation)
        from src.tools.pattern_skill_tools import PatternSkillTools

        pattern_skill_tools = PatternSkillTools()
        await pattern_skill_tools.register_tools(server.mcp, get_session)
        logger.info(
            "Pattern-skill tools registered (4 MCP tools for pattern-to-skill promotion)"
        )

        # Register tool search tools (v2.5.0+ Tool Search + MCP Hub)
        from src.tools import tool_search_tools

        await tool_search_tools.register_tools(
            server.mcp,
            embedding_service=server.embedding_service,
            persist_directory=settings.chroma_persist_directory,
        )
        logger.info("Tool search tools registered (2 MCP tools for semantic tool discovery)")

        # Register MCP Hub management tools (v2.5.0+ Tool Search + MCP Hub Phase 3)
        from src.tools import mcp_hub_tools

        await mcp_hub_tools.register_tools(server.mcp)
        logger.info("MCP Hub tools registered (5 MCP tools for server connection management)")

        # Register internal TMWS tools in Tool Search index (v2.4.17+)
        # This enables semantic search across all 42+ internal MCP tools
        try:
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

            if hasattr(server.mcp, "_tool_manager") and hasattr(server.mcp._tool_manager, "_tools"):
                for tool_name, tool_obj in server.mcp._tool_manager._tools.items():
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
                    # Use default namespace for skill listing (Issue #59 API change)
                    skills = await skill_service.list_skills(
                        agent_id="system",
                        namespace="default",
                        limit=100
                    )

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
                from src.mcp_server.constants import TRINITAS_AGENTS
                from src.services.license_service import LicenseService

                # Validate license tier for agent registration
                async with get_session() as session:
                    license_service = LicenseService(db_session=session)

                    # Get license key from environment
                    license_key = os.getenv("TMWS_LICENSE_KEY")
                    if not license_key:
                        log_and_raise(
                            Exception,
                            "TMWS_LICENSE_KEY not set for agent registration",
                            details={"feature": "trinitas_agent_registration"}
                        )

                    # Validate license and check tier
                    validation_result = await license_service.validate_license_key(
                        license_key, feature_accessed="trinitas_agent_registration"
                    )

                    if not validation_result.valid:
                        log_and_raise(
                            Exception,
                            "Invalid license for agent registration",
                            details={
                                "error_message": validation_result.error_message,
                                "feature": "trinitas_agent_registration",
                            }
                        )

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

            server.external_mcp_manager = MCPManager()

            # Try to load presets from project directory first, then user config
            project_dir = Path.cwd()
            connected_servers = await server.external_mcp_manager.auto_connect_from_config(
                project_dir=project_dir
            )

            if connected_servers:
                logger.info(
                    f"✅ External MCP servers connected: {len(connected_servers)}\n"
                    f"   Servers: {', '.join(connected_servers)}"
                )

                # Log available tools from connected servers
                all_tools = await server.external_mcp_manager.list_all_tools()
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
            f"HybridMCPServer initialized: {server.instance_id} "
            f"(Chroma: {server.vector_service.HOT_CACHE_SIZE} hot cache)",
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
            details={"instance_id": server.instance_id},
        )


async def cleanup_server(server):
    """Cleanup on shutdown.

    Args:
        server: HybridMCPServer instance
    """
    await server.cleanup()
