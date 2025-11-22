"""Tool Discovery Service - Dynamic Tool Orchestration

This service provides tool discovery and management with:
- SQLite as source of truth for tool metadata
- Namespace isolation (V-TOOL-1) for multi-tenant security
- Covering indexes for <20ms P95 query performance
- Integration with Go Orchestrator for container lifecycle

Performance Targets:
- Tool registration: <10ms P95 (INSERT operation)
- Tool lookup: <5ms P95 (covering index on tool_id)
- Tool listing: <15ms P95 (covering index on category + namespace)
- Tool verification: <50ms P95 (includes Docker inspect)

Phase: 4-Day1 (TMWS v2.3.0)
"""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    NotFoundError,
    ValidationError,
    log_and_raise,
)
from src.models.tool_discovery import (
    DiscoveredTool,
    ToolVerificationHistory,
)
from src.schemas.tool_metadata import ToolMetadata

logger = logging.getLogger(__name__)


def _validate_tool_category(category: str) -> None:
    """Validate tool category for security.

    Prevents injection of arbitrary categories that could bypass security controls.

    Args:
        category: Tool category to validate

    Raises:
        ValueError: If category is not in allowed list

    Security: V-TOOL-2 - Category whitelist enforcement
    """
    ALLOWED_CATEGORIES = {"MCP", "CLI", "API", "LIBRARY", "CONTAINER"}

    if category.upper() not in ALLOWED_CATEGORIES:
        raise ValueError(
            f"Invalid tool category '{category}'. "
            f"Allowed categories: {', '.join(sorted(ALLOWED_CATEGORIES))}"
        )


def _validate_namespace(namespace: str) -> None:
    """Validate namespace format for security.

    Prevents path traversal and injection attacks via namespace parameter.

    Args:
        namespace: Namespace to validate

    Raises:
        ValueError: If namespace contains invalid characters or is too long

    Security: V-TOOL-1 - Namespace isolation enforcement
    Reference: See V-1 fix (2025-10-27) - Path traversal prevention
    """
    # V-1 Fix: Prevent path traversal
    if "." in namespace or "/" in namespace or "\\" in namespace:
        raise ValueError(
            f"Invalid namespace '{namespace}': "
            "Path separators (., /, \\) are not allowed"
        )

    # Length validation
    if len(namespace) > 100:
        raise ValueError(
            f"Namespace too long: {len(namespace)} chars (max: 100)"
        )

    # Empty namespace check
    if not namespace.strip():
        raise ValueError("Namespace cannot be empty")


class ToolDiscoveryService:
    """
    Service for managing discovered tools with namespace isolation.

    Security: V-TOOL-1 - Namespace isolation enforced on all queries
    Performance: Uses covering indexes for <20ms P95 queries

    Example:
        async with get_session() as session:
            service = ToolDiscoveryService(session)
            tool = await service.register_tool(
                tool_id="genai-toolbox-v1",
                name="GenAI Toolbox",
                category="MCP",
                source_path="/tools/genai-toolbox",
                version="1.0.0",
                namespace="project-x"
            )
    """

    def __init__(self, session: AsyncSession):
        """Initialize service with database session.

        Args:
            session: Async SQLAlchemy session
        """
        self.session = session

    async def register_tool(
        self,
        tool_id: str,
        name: str,
        category: str,
        source_path: str,
        version: str,
        namespace: str,
        metadata: ToolMetadata | None = None,
    ) -> DiscoveredTool:
        """
        Register a newly discovered tool.

        Performance: <10ms P95 (INSERT operation)
        Security: V-TOOL-1 (namespace), V-TOOL-2 (category), V-DISC-2 (metadata)

        Args:
            tool_id: Unique tool identifier (e.g., "genai-toolbox-v1")
            name: Human-readable tool name
            category: Tool category (MCP, CLI, API, LIBRARY)
            source_path: File system path or container image URL
            version: Semantic version (e.g., "1.0.0")
            namespace: Project-specific namespace
            metadata: Optional validated tool metadata (V-DISC-2 fix)

        Returns:
            Created DiscoveredTool instance

        Raises:
            ValidationError: If namespace, category, or metadata is invalid
            SQLAlchemyError: If database operation fails

        Example:
            tool = await service.register_tool(
                tool_id="playwright-v1",
                name="Playwright",
                category="LIBRARY",
                source_path="/tools/playwright",
                version="1.40.0",
                namespace="project-x",
                metadata=ToolMetadata(
                    description="Browser automation library",
                    author="Microsoft",
                    license="Apache-2.0",
                    tags=["browser", "automation"]
                )
            )
        """
        # V-TOOL-1: Namespace validation
        try:
            _validate_namespace(namespace)
        except ValueError as e:
            log_and_raise(ValidationError, str(e))

        # V-TOOL-2: Category validation
        try:
            _validate_tool_category(category)
        except ValueError as e:
            log_and_raise(ValidationError, str(e))

        # V-DISC-2: Convert validated metadata to dict (HTML sanitized, schema-validated)
        tool_metadata_dict = metadata.model_dump() if metadata else {}

        # Create tool instance
        tool = DiscoveredTool(
            tool_id=tool_id,
            name=name,
            category=category.upper(),
            source_path=source_path,
            version=version,
            namespace=namespace,
            tool_metadata=tool_metadata_dict,
            discovered_at=datetime.now(timezone.utc),
            is_active=True,
        )

        try:
            self.session.add(tool)
            await self.session.commit()
            await self.session.refresh(tool)

            logger.info(
                f"Tool registered: {tool_id} (v{version}) in namespace '{namespace}'"
            )
            return tool

        except SQLAlchemyError as e:
            await self.session.rollback()
            log_and_raise(
                ValidationError,
                f"Failed to register tool '{tool_id}'",
                original_exception=e,
                details={"tool_id": tool_id, "namespace": namespace},
            )

    async def get_tool(
        self, tool_id: str, namespace: str
    ) -> DiscoveredTool | None:
        """
        Get tool by ID (namespace-isolated).

        Performance: <5ms P95 (covering index on tool_id)
        Security: V-TOOL-1 - Namespace isolation enforced

        Args:
            tool_id: Tool identifier
            namespace: Project namespace (verified from DB, not user input)

        Returns:
            DiscoveredTool if found, None otherwise

        Example:
            tool = await service.get_tool("playwright-v1", "project-x")
            if tool:
                print(f"Found: {tool.name} v{tool.version}")
        """
        stmt = select(DiscoveredTool).where(
            and_(
                DiscoveredTool.tool_id == tool_id,
                DiscoveredTool.namespace == namespace,
                DiscoveredTool.is_active == True,  # noqa: E712
            )
        )

        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_tools(
        self, namespace: str, category: str | None = None
    ) -> list[DiscoveredTool]:
        """
        List all tools in namespace (optionally filtered by category).

        Performance: <15ms P95 (covering index on category + namespace)
        Security: V-TOOL-1 - Namespace isolation enforced

        Args:
            namespace: Project namespace
            category: Optional category filter (MCP, CLI, API, LIBRARY)

        Returns:
            List of DiscoveredTool instances

        Example:
            # List all MCP tools in project-x
            mcp_tools = await service.list_tools("project-x", category="MCP")
            for tool in mcp_tools:
                print(f"{tool.name} v{tool.version}")
        """
        stmt = select(DiscoveredTool).where(
            and_(
                DiscoveredTool.namespace == namespace,
                DiscoveredTool.is_active == True,  # noqa: E712
            )
        )

        if category:
            # V-TOOL-2: Validate category before query
            try:
                _validate_tool_category(category)
            except ValueError as e:
                log_and_raise(ValidationError, str(e))

            stmt = stmt.where(DiscoveredTool.category == category.upper())

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def verify_tool(
        self,
        tool_id: UUID,
        namespace: str,
        verification_method: str,
        success: bool,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ToolVerificationHistory:
        """
        Record tool verification result.

        Performance: <20ms P95 (INSERT + UPDATE)
        Security: V-TOOL-1 - Namespace isolation enforced

        Args:
            tool_id: Tool UUID
            namespace: Project namespace
            verification_method: Verification method (docker_inspect, health_check, manual)
            success: True if verification passed
            error_message: Optional error message if failed
            metadata: Optional verification-specific metadata

        Returns:
            Created ToolVerificationHistory instance

        Raises:
            NotFoundError: If tool not found in namespace

        Example:
            verification = await service.verify_tool(
                tool_id=tool.id,
                namespace="project-x",
                verification_method="health_check",
                success=True,
                metadata={"response_time_ms": 42}
            )
        """
        # Verify tool exists in namespace (V-TOOL-1)
        tool = await self.session.get(DiscoveredTool, tool_id)
        if not tool or tool.namespace != namespace or not tool.is_active:
            log_and_raise(
                NotFoundError,
                f"Tool {tool_id} not found in namespace '{namespace}'",
            )

        # Create verification record
        verification = ToolVerificationHistory(
            tool_id=tool_id,
            verified_at=datetime.now(timezone.utc),
            success=success,
            verification_method=verification_method,
            error_message=error_message,
            verification_metadata=metadata or {},
        )

        # Update tool's last_verified_at if successful
        if success:
            tool.last_verified_at = datetime.now(timezone.utc)

        try:
            self.session.add(verification)
            await self.session.commit()
            await self.session.refresh(verification)

            logger.info(
                f"Tool verification recorded: {tool.tool_id} "
                f"(method: {verification_method}, success: {success})"
            )
            return verification

        except SQLAlchemyError as e:
            await self.session.rollback()
            log_and_raise(
                ValidationError,
                f"Failed to record verification for tool {tool_id}",
                original_exception=e,
            )

    async def deactivate_tool(self, tool_id: str, namespace: str) -> None:
        """
        Deactivate a tool (soft delete).

        Performance: <10ms P95 (UPDATE operation)
        Security: V-TOOL-1 - Namespace isolation enforced

        Args:
            tool_id: Tool identifier
            namespace: Project namespace

        Raises:
            NotFoundError: If tool not found in namespace

        Example:
            await service.deactivate_tool("old-tool-v1", "project-x")
        """
        tool = await self.get_tool(tool_id, namespace)
        if not tool:
            log_and_raise(
                NotFoundError,
                f"Tool '{tool_id}' not found in namespace '{namespace}'",
            )

        tool.is_active = False

        try:
            await self.session.commit()
            logger.info(f"Tool deactivated: {tool_id} in namespace '{namespace}'")

        except SQLAlchemyError as e:
            await self.session.rollback()
            log_and_raise(
                ValidationError,
                f"Failed to deactivate tool '{tool_id}'",
                original_exception=e,
            )


# Singleton pattern for service factory
def get_tool_discovery_service(session: AsyncSession) -> ToolDiscoveryService:
    """Factory function for ToolDiscoveryService.

    Args:
        session: Async SQLAlchemy session

    Returns:
        ToolDiscoveryService instance

    Example:
        async with get_session() as session:
            service = get_tool_discovery_service(session)
            tools = await service.list_tools("project-x")
    """
    return ToolDiscoveryService(session)
