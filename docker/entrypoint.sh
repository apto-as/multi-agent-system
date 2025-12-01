#!/bin/bash
# ========================================
# TMWS Docker Entrypoint Script
# ========================================
# Handles:
# 1. Database initialization (if needed)
# 2. Trinitas agent auto-registration
# 3. MCP server startup
#
# Usage (Docker):
#   CMD ["./docker/entrypoint.sh"]
#
# Environment Variables:
#   TMWS_AUTO_REGISTER_AGENTS=true  # Enable agent auto-registration
#   TMWS_DATABASE_URL               # Database connection string
#
# Author: Athena (Harmonious Conductor)
# Created: 2025-11-29
# ========================================

set -e  # Exit on error

# All output goes to stderr to keep stdout clean for MCP STDIO protocol
exec 3>&1  # Save stdout
exec 1>&2  # Redirect stdout to stderr

echo "========================================="
echo "TMWS Entrypoint - Starting..."
echo "========================================="

# ========================================
# Phase 1: Database Initialization
# ========================================
echo "[1/3] Checking database..."

# Wait for database to be ready (SQLite should be immediate)
# For future PostgreSQL support, add connection retry logic here

# Check if database file exists (SQLite)
if [[ "${TMWS_DATABASE_URL}" == sqlite* ]]; then
    DB_PATH=$(echo "${TMWS_DATABASE_URL}" | sed -e 's|sqlite+aiosqlite://||' -e 's|sqlite://||')
    DB_DIR=$(dirname "${DB_PATH}")

    # Create directory if it doesn't exist
    if [ ! -d "${DB_DIR}" ]; then
        echo "Creating database directory: ${DB_DIR}"
        mkdir -p "${DB_DIR}"
    fi

    echo "SQLite database path: ${DB_PATH}"
fi

# ========================================
# Phase 1.5: Database Schema Initialization
# ========================================
echo "[1.5/3] Initializing database schema..."

python3 << 'INIT_SCHEMA'
import asyncio
import logging
import sys

# Configure logging to stderr to keep stdout clean for MCP STDIO protocol
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", stream=sys.stderr)
logging.getLogger("sqlalchemy").handlers = []
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

async def init_schema():
    """Initialize database schema (create tables if not exist)."""
    try:
        from src.core.database import get_engine
        from src.models import TMWSBase

        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(TMWSBase.metadata.create_all)
        await engine.dispose()

        # Clear engine cache to avoid event loop conflicts
        import src.core.database as db_module
        db_module._engine = None

        logger.info("Database schema initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Schema initialization failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(init_schema())
    sys.exit(0 if success else 1)
INIT_SCHEMA

if [ $? -eq 0 ]; then
    echo "Database schema initialized"
else
    echo "Warning: Schema initialization failed (non-fatal)"
fi

# ========================================
# Phase 2: Trinitas Agent Registration
# ========================================
if [ "${TMWS_AUTO_REGISTER_AGENTS:-true}" = "true" ]; then
    echo "[2/3] Registering Trinitas agents..."

    # Run agent registration script
    # Uses Python module from installed wheel (bytecode)
    python3 << 'PYTHON_SCRIPT'
import asyncio
import logging
import sys

# Configure logging to stderr to keep stdout clean for MCP STDIO protocol
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stderr
)
logging.getLogger("sqlalchemy").handlers = []
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# Trinitas agents configuration (6 core + 3 support)
TRINITAS_AGENTS = [
    {
        "agent_id": "athena-conductor",
        "display_name": "Athena - Harmonious Conductor",
        "agent_type": "trinitas/conductor",
        "namespace": "trinitas",
        "capabilities": {
            "orchestration": True,
            "workflow_automation": True,
            "resource_optimization": True,
            "parallel_execution": True,
            "subtype": "conductor",
        },
    },
    {
        "agent_id": "artemis-optimizer",
        "display_name": "Artemis - Technical Perfectionist",
        "agent_type": "trinitas/optimizer",
        "namespace": "trinitas",
        "capabilities": {
            "performance_optimization": True,
            "code_quality": True,
            "algorithm_design": True,
            "efficiency_improvement": True,
            "subtype": "optimizer",
        },
    },
    {
        "agent_id": "hestia-auditor",
        "display_name": "Hestia - Security Guardian",
        "agent_type": "trinitas/auditor",
        "namespace": "trinitas",
        "capabilities": {
            "security_analysis": True,
            "vulnerability_assessment": True,
            "risk_management": True,
            "threat_modeling": True,
            "subtype": "auditor",
        },
    },
    {
        "agent_id": "eris-coordinator",
        "display_name": "Eris - Tactical Coordinator",
        "agent_type": "trinitas/coordinator",
        "namespace": "trinitas",
        "capabilities": {
            "tactical_planning": True,
            "conflict_resolution": True,
            "workflow_adjustment": True,
            "balance_management": True,
            "subtype": "coordinator",
        },
    },
    {
        "agent_id": "hera-strategist",
        "display_name": "Hera - Strategic Commander",
        "agent_type": "trinitas/strategist",
        "namespace": "trinitas",
        "capabilities": {
            "strategic_planning": True,
            "architecture_design": True,
            "long_term_vision": True,
            "stakeholder_management": True,
            "subtype": "strategist",
        },
    },
    {
        "agent_id": "muses-documenter",
        "display_name": "Muses - Knowledge Architect",
        "agent_type": "trinitas/documenter",
        "namespace": "trinitas",
        "capabilities": {
            "documentation": True,
            "knowledge_management": True,
            "specification_writing": True,
            "api_documentation": True,
            "subtype": "documenter",
        },
    },
    # Support Agents (v2.4.7+)
    {
        "agent_id": "aphrodite-designer",
        "display_name": "Aphrodite - UI/UX Designer",
        "agent_type": "trinitas/designer",
        "namespace": "trinitas",
        "capabilities": {
            "ui_design": True,
            "ux_research": True,
            "accessibility": True,
            "visual_design": True,
            "subtype": "designer",
        },
    },
    {
        "agent_id": "metis-developer",
        "display_name": "Metis - Development Assistant",
        "agent_type": "trinitas/developer",
        "namespace": "trinitas",
        "capabilities": {
            "code_implementation": True,
            "testing": True,
            "debugging": True,
            "refactoring": True,
            "subtype": "developer",
        },
    },
    {
        "agent_id": "aurora-researcher",
        "display_name": "Aurora - Research Assistant",
        "agent_type": "trinitas/researcher",
        "namespace": "trinitas",
        "capabilities": {
            "memory_search": True,
            "context_retrieval": True,
            "knowledge_synthesis": True,
            "pattern_discovery": True,
            "subtype": "researcher",
        },
    },
]


async def ensure_trinitas_namespace(session):
    """Ensure the 'trinitas' namespace exists."""
    from sqlalchemy import select
    from src.models.agent import AgentNamespace

    result = await session.execute(
        select(AgentNamespace).where(AgentNamespace.namespace == "trinitas")
    )
    existing = result.scalar_one_or_none()

    if existing:
        logger.info("Namespace 'trinitas' already exists")
        return existing

    # Create namespace
    namespace_obj = AgentNamespace(
        namespace="trinitas",
        description="Trinitas AI persona system namespace",
    )
    session.add(namespace_obj)
    await session.commit()
    await session.refresh(namespace_obj)
    logger.info("Created namespace 'trinitas'")
    return namespace_obj


async def register_agents():
    """Register all Trinitas agents."""
    try:
        from src.core.database import get_db_session
    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("TMWS package not properly installed")
        return False

    registered = 0
    skipped = 0

    try:
        async with get_db_session() as session:
            # Ensure namespace exists
            await ensure_trinitas_namespace(session)

            from sqlalchemy import select
            from src.models.agent import Agent

            for agent_info in TRINITAS_AGENTS:
                try:
                    # Check if agent exists
                    result = await session.execute(
                        select(Agent).where(Agent.agent_id == agent_info["agent_id"])
                    )
                    existing = result.scalar_one_or_none()

                    if existing:
                        logger.debug(f"Skipped (exists): {agent_info['agent_id']}")
                        skipped += 1
                        continue

                    # Create agent
                    agent = Agent(
                        agent_id=agent_info["agent_id"],
                        display_name=agent_info["display_name"],
                        agent_type=agent_info["agent_type"],
                        namespace=agent_info["namespace"],
                        capabilities=agent_info["capabilities"],
                    )
                    session.add(agent)
                    await session.commit()
                    registered += 1
                    logger.info(f"Registered: {agent_info['agent_id']}")

                except Exception as e:
                    await session.rollback()
                    logger.error(f"Failed: {agent_info['agent_id']} - {e}")

        logger.info(f"Agent registration complete: {registered} new, {skipped} existing")
        return True

    except Exception as e:
        logger.error(f"Registration failed: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(register_agents())
    sys.exit(0 if success else 1)
PYTHON_SCRIPT

    if [ $? -eq 0 ]; then
        echo "Agent registration completed successfully"
    else
        echo "Warning: Agent registration failed (non-fatal)"
    fi
else
    echo "[2/3] Agent auto-registration disabled"
fi

# ========================================
# Phase 3: Start MCP Server
# ========================================
echo "[3/3] Starting MCP server..."
echo "========================================="

# Restore stdout for MCP STDIO protocol (MCP server needs clean stdout)
exec 1>&3 3>&-

# Execute MCP server (replace shell process)
exec tmws-mcp-server "$@"
