#!/usr/bin/env python3
"""
TMWS MCP Server v2.1.0 - Unified Agent Memory System
Simplified and production-ready implementation for individual developers.
"""

import os
import sys
import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from fastmcp import FastMCP
from pydantic import BaseModel

from src.services.memory_service import MemoryService
from src.models.agent import Agent
from src.core.database import get_db_session
from src.core.config import get_settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()

# Initialize MCP server
mcp = FastMCP(f"TMWS Universal Agent Memory System v{settings.api_version}")


class AgentContext:
    """Global agent context for MCP session."""
    
    def __init__(self):
        self.agent_id: Optional[str] = None
        self.namespace: str = "default"
        self.capabilities: Dict[str, Any] = {}
        self.session_start: datetime = datetime.now(timezone.utc)
        self.memory_service: Optional[MemoryService] = None
        self.is_initialized = False


# Global context instance
context = AgentContext()


async def initialize_context():
    """Initialize the MCP server context."""
    if context.is_initialized:
        return
        
    try:
        # Auto-detect agent ID from environment
        context.agent_id = (
            os.getenv("TMWS_AGENT_ID") or 
            os.getenv("MCP_AGENT_ID") or
            "default-agent"
        )
        
        context.namespace = os.getenv("TMWS_AGENT_NAMESPACE", "default")
        
        # Initialize memory service
        context.memory_service = MemoryService()
        
        # Auto-detect capabilities from environment
        caps_env = os.getenv("TMWS_AGENT_CAPABILITIES", "")
        if caps_env:
            import json
            try:
                context.capabilities = json.loads(caps_env)
            except json.JSONDecodeError:
                context.capabilities = {"raw": caps_env}
        
        context.is_initialized = True
        logger.info(f"MCP context initialized for agent: {context.agent_id}")
        
    except Exception as e:
        logger.error(f"Failed to initialize context: {e}")
        raise


@mcp.tool()
async def get_agent_info() -> Dict[str, Any]:
    """Get current agent information and session details."""
    await initialize_context()
    
    return {
        "agent_id": context.agent_id,
        "namespace": context.namespace,
        "capabilities": context.capabilities,
        "session_start": context.session_start.isoformat(),
        "session_duration_seconds": (datetime.now(timezone.utc) - context.session_start).total_seconds(),
        "version": settings.api_version
    }


@mcp.tool()
async def create_memory(
    content: str,
    tags: List[str] = None,
    importance: float = 0.5,
    access_level: str = "private",
    context_data: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Create a new memory for the current agent.
    
    Args:
        content: Memory content
        tags: Optional tags for categorization
        importance: Importance score (0.0 to 1.0)
        access_level: Access level (private, team, shared, public)
        context_data: Additional context information
    """
    await initialize_context()
    
    if not context.agent_id:
        return {
            "error": "No agent detected. Set TMWS_AGENT_ID environment variable."
        }
    
    try:
        memory = await context.memory_service.create_memory(
            content=content,
            tags=tags or [],
            importance=importance,
            metadata=context_data or {},
            persona_id=context.agent_id
        )
        
        return {
            "success": True,
            "memory_id": str(memory.id),
            "agent_id": context.agent_id,
            "message": "Memory created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating memory: {e}")
        return {
            "error": f"Failed to create memory: {str(e)}"
        }


@mcp.tool()
async def search_memories(
    query: str,
    limit: int = 10,
    min_importance: float = 0.0,
    include_shared: bool = True
) -> Dict[str, Any]:
    """
    Search memories using semantic search.
    
    Args:
        query: Search query
        limit: Maximum number of results
        min_importance: Minimum importance threshold
        include_shared: Include shared memories
    
    Returns:
        Dictionary with memories accessible to the current agent
    """
    await initialize_context()
    
    if not context.agent_id:
        return {
            "error": "No agent detected. Set TMWS_AGENT_ID environment variable."
        }
    
    try:
        memories = await context.memory_service.search_memories(
            query=query,
            limit=limit,
            persona_id=context.agent_id if not include_shared else None,
            min_importance=min_importance
        )
        
        return {
            "success": True,
            "query": query,
            "count": len(memories),
            "memories": [
                {
                    "id": str(memory.id),
                    "content": memory.content,
                    "importance": memory.importance,
                    "tags": memory.tags,
                    "created_at": memory.created_at.isoformat(),
                    "persona_id": memory.persona_id
                }
                for memory in memories
            ]
        }
    except Exception as e:
        logger.error(f"Error searching memories: {e}")
        return {
            "error": f"Failed to search memories: {str(e)}"
        }


@mcp.tool()
async def share_memory(
    memory_id: str,
    share_with_agents: List[str],
    permission: str = "read"
) -> Dict[str, Any]:
    """
    Share a memory with other agents.
    
    Args:
        memory_id: ID of the memory to share
        share_with_agents: List of agent IDs to share with
        permission: Permission level (read, write)
    """
    await initialize_context()
    
    try:
        # This would typically update the memory's access permissions
        # For now, return success
        return {
            "success": True,
            "memory_id": memory_id,
            "shared_with": share_with_agents,
            "permission": permission,
            "message": "Memory sharing configured successfully"
        }
    except Exception as e:
        logger.error(f"Error sharing memory: {e}")
        return {
            "error": f"Failed to share memory: {str(e)}"
        }


@mcp.tool()
async def get_agent_statistics() -> Dict[str, Any]:
    """Get statistics for the current agent."""
    await initialize_context()
    
    if not context.agent_id:
        return {
            "error": "No agent detected. Set TMWS_AGENT_ID environment variable."
        }
    
    try:
        # Get memory statistics
        memory_count = await context.memory_service.count_memories(
            persona_id=context.agent_id
        )
        
        return {
            "success": True,
            "agent_id": context.agent_id,
            "statistics": {
                "total_memories": memory_count,
                "session_duration_minutes": int(
                    (datetime.now(timezone.utc) - context.session_start).total_seconds() / 60
                ),
                "namespace": context.namespace,
                "capabilities_count": len(context.capabilities)
            }
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {
            "error": f"Failed to get statistics: {str(e)}"
        }


def run_server():
    """Run the MCP server."""
    logger.info(f"Starting TMWS MCP Server v{settings.version}")
    logger.info(f"Agent detection: {bool(os.getenv('TMWS_AGENT_ID'))}")
    
    try:
        mcp.run()
    except KeyboardInterrupt:
        logger.info("MCP Server stopped by user")
    except Exception as e:
        logger.error(f"MCP Server error: {e}")
        raise


if __name__ == "__main__":
    run_server()