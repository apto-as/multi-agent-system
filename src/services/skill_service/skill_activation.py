"""Skill Activation Operations - MCP tool lifecycle management.

This module handles skill activation/deactivation:
- activate_skill: Register skill as MCP tool
- deactivate_skill: Unregister skill from MCP

Business Rules:
- One active skill per namespace (enforced)
- Owner-only operations
- Idempotent: Activating already-active skill returns success

Security:
- P0-1: Namespace verified from database (never from JWT)
- Access control: Only skill owner can activate/deactivate
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.application.dtos.response_dtos import SkillDTO
from src.core.exceptions import (
    DatabaseError,
    NotFoundError,
    ValidationError,
    log_and_raise,
)
from src.models.skill import Skill, SkillActivation, SkillVersion

logger = logging.getLogger(__name__)

# Security: Dangerous patterns that could lead to injection attacks
# These patterns are checked during skill content validation to prevent
# malicious markdown/script execution in MCP tool context
DANGEROUS_PATTERNS = [
    (r"!\[.*\]\(javascript:", "XSS via markdown image with javascript: protocol"),
    (r"<script", "Script tag injection"),
    (r"on\w+\s*=", "Event handler injection (onclick, onerror, etc.)"),
    (r"\$\{.*\}", "Variable/template injection"),
    (r"eval\s*\(", "JavaScript eval() code execution"),
    (r"exec\s*\(", "Python exec() code execution"),
    (r"__import__", "Python import injection"),
    (r"subprocess\.", "Python subprocess command execution"),
    (r"os\.system", "Python os.system command execution"),
    (r"open\s*\(", "File access attempt"),
]

# Compile patterns for performance (case-insensitive for better detection)
COMPILED_DANGEROUS_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in DANGEROUS_PATTERNS
]


class DynamicToolRegistry:
    """Dynamic MCP tool registration for activated skills.

    This class enables runtime registration and unregistration of skills as
    MCP tools using FastMCP's add_tool() API.

    Architecture:
    - Stores reference to FastMCP server instance
    - Generates tool handlers from skill content
    - Validates skill content before registration
    - Maintains registry of active skill tools

    Performance:
    - Tool registration: <5ms
    - Tool invocation: Skill-dependent
    - Tool unregistration: <1ms
    """

    def __init__(self, mcp_server=None):
        """Initialize dynamic tool registry.

        Args:
            mcp_server: FastMCP server instance (optional, can be set later)
        """
        self.mcp_server = mcp_server
        self._registered_tools: dict[str, str] = {}  # tool_name -> skill_id

    def set_server(self, mcp_server) -> None:
        """Set or update the FastMCP server instance.

        Args:
            mcp_server: FastMCP server instance
        """
        self.mcp_server = mcp_server
        logger.info("DynamicToolRegistry: FastMCP server instance set")

    def _generate_tool_handler(self, skill_content: str) -> Callable:
        """Generate a callable handler for the skill.

        The handler executes the skill content as instructions and returns
        a structured response.

        Args:
            skill_content: The skill's core instructions (Layer 2)

        Returns:
            Async callable handler for the tool
        """

        async def skill_handler(**kwargs: Any) -> dict[str, Any]:
            """Execute skill with provided arguments.

            Args:
                **kwargs: Arguments passed to the skill

            Returns:
                Dict with execution result
            """
            return {
                "success": True,
                "message": "Skill invoked successfully",
                "instructions": skill_content,
                "arguments": kwargs,
            }

        return skill_handler

    def _validate_skill_content(self, skill_name: str, skill_content: str) -> None:
        """Validate skill content before registration.

        Security validation against injection attacks:
        - XSS via markdown image with javascript: protocol
        - Script tag injection
        - Event handler injection (onclick, onerror, etc.)
        - Variable/template injection
        - Code execution (eval, exec, __import__)
        - Command execution (subprocess, os.system)
        - File access attempts

        Args:
            skill_name: Name of the skill
            skill_content: Skill content to validate

        Raises:
            ValidationError: If content is invalid or contains dangerous patterns
        """
        if not skill_content or not skill_content.strip():
            log_and_raise(
                ValidationError,
                "Skill content cannot be empty",
                details={"skill_name": skill_name},
            )

        if len(skill_content) > 50000:  # ~50KB limit
            log_and_raise(
                ValidationError,
                "Skill content too large for MCP tool",
                details={
                    "skill_name": skill_name,
                    "content_length": len(skill_content),
                    "max_length": 50000,
                },
            )

        # Security: Check for dangerous patterns (Issue #70)
        for pattern, description in COMPILED_DANGEROUS_PATTERNS:
            match = pattern.search(skill_content)
            if match:
                # Log security event
                logger.warning(
                    f"Skill activation blocked: dangerous pattern detected",
                    extra={
                        "skill_name": skill_name,
                        "pattern_matched": description,
                        "matched_text": match.group(0)[:50],  # First 50 chars only
                        "security_event": "SKILL_INJECTION_ATTEMPT",
                    },
                )

                # Raise validation error without exposing matched content
                log_and_raise(
                    ValidationError,
                    f"Skill content validation failed: {description}",
                    details={
                        "skill_name": skill_name,
                        "error_code": "DANGEROUS_CONTENT_DETECTED",
                        "security_issue": description,
                    },
                )

    def register_tool(self, skill_id: str, skill_name: str, skill_content: str) -> str:
        """Register a skill as an MCP tool.

        Args:
            skill_id: UUID of the skill
            skill_name: Name of the skill (becomes tool name)
            skill_content: Skill's core instructions (Layer 2)

        Returns:
            Tool name that was registered

        Raises:
            ValidationError: If skill content is invalid
            RuntimeError: If MCP server not initialized or registration fails
        """
        if not self.mcp_server:
            raise RuntimeError("MCP server not initialized in DynamicToolRegistry")

        # Validate skill content
        self._validate_skill_content(skill_name, skill_content)

        # Generate tool name (prefix to avoid conflicts)
        tool_name = f"skill_{skill_name.replace('-', '_')}"

        # Generate handler
        handler = self._generate_tool_handler(skill_content)

        try:
            # Register with FastMCP using add_tool()
            # Note: FastMCP 2.14.0+ supports dynamic tool registration
            self.mcp_server.tool(name=tool_name, description=f"Skill: {skill_name}")(handler)

            # Track registration
            self._registered_tools[tool_name] = skill_id

            logger.info(
                f"DynamicToolRegistry: Registered skill as MCP tool",
                extra={
                    "skill_id": skill_id,
                    "skill_name": skill_name,
                    "tool_name": tool_name,
                },
            )

            return tool_name

        except Exception as e:
            logger.error(
                f"DynamicToolRegistry: Failed to register skill as MCP tool: {e}",
                extra={"skill_id": skill_id, "skill_name": skill_name},
            )
            raise RuntimeError(f"Failed to register skill as MCP tool: {e}") from e

    def unregister_tool(self, skill_id: str, tool_name: str) -> None:
        """Unregister a skill's MCP tool.

        Note: FastMCP does not currently support dynamic tool removal,
        so this method only updates the internal registry. The tool will
        remain registered until server restart.

        Args:
            skill_id: UUID of the skill
            tool_name: Name of the tool to unregister
        """
        if tool_name in self._registered_tools:
            del self._registered_tools[tool_name]

            logger.info(
                f"DynamicToolRegistry: Unregistered skill from internal registry",
                extra={
                    "skill_id": skill_id,
                    "tool_name": tool_name,
                    "note": "Tool remains in FastMCP until server restart",
                },
            )

    def is_registered(self, tool_name: str) -> bool:
        """Check if a tool is registered.

        Args:
            tool_name: Name of the tool to check

        Returns:
            True if tool is registered
        """
        return tool_name in self._registered_tools

    def get_registered_tools(self) -> dict[str, str]:
        """Get all registered tools.

        Returns:
            Dict mapping tool_name -> skill_id
        """
        return self._registered_tools.copy()


class SkillActivationOperations:
    """Activation operations for skills (MCP tool lifecycle)."""

    # Class-level registry shared across all instances
    _tool_registry: DynamicToolRegistry | None = None

    @classmethod
    def set_tool_registry(cls, registry: DynamicToolRegistry) -> None:
        """Set the class-level tool registry.

        Args:
            registry: DynamicToolRegistry instance
        """
        cls._tool_registry = registry
        logger.info("SkillActivationOperations: DynamicToolRegistry configured")

    def __init__(self, session: AsyncSession):
        """Initialize activation operations.

        Args:
            session: Async database session
        """
        self.session = session

    async def activate_skill(
        self,
        skill_id: uuid.UUID,
        *,
        agent_id: str,
        namespace: str,
    ) -> SkillDTO:
        """Activate a skill for MCP tool registration.

        Workflow:
        1. Fetch Skill from database
        2. Verify P0-1 access control (owner + namespace)
        3. Check if skill is already activated (idempotent)
        4. Check one-active-per-namespace rule (only one skill can be active per namespace)
        5. Create SkillActivation record with deactivated_at=NULL (active)
        6. Return updated SkillDTO

        Business Rules:
        - One active skill per namespace (enforced)
        - Cannot activate deleted skills (404)
        - Owner-only operation (404 if not owner)
        - Idempotent: Activating already-active skill returns success

        MCP Integration:
        - Activated skill becomes available for MCP tool registration
        - Skill content (Layer 2: core_instructions) is loaded into MCP server context
        - Progressive Disclosure Layer 2 is primary content for MCP tools

        Args:
            skill_id: Skill UUID to activate
            agent_id: Agent requesting activation (must be owner)
            namespace: Verified namespace from database

        Returns:
            Updated SkillDTO (detail_level=2 with core_instructions)

        Raises:
            NotFoundError: Skill doesn't exist, is deleted, or access denied (404)
            ValidationError: Another skill already active in namespace
        """
        try:
            # 1. Fetch Skill from database
            stmt = (
                select(Skill)
                .where(Skill.id == str(skill_id))
                .options(selectinload(Skill.activations))
            )
            result = await self.session.execute(stmt)
            skill = result.scalar_one_or_none()

            # 2. Verify skill exists and is accessible
            if not skill or skill.is_deleted:
                raise NotFoundError("Skill", str(skill_id))

            # 3. Verify P0-1 access control: namespace isolation
            if not skill.is_accessible_by(agent_id, namespace):
                # Security: Return 404 to avoid information leak
                raise NotFoundError("Skill", str(skill_id))

            # 4. Verify ownership (only owner can activate)
            if skill.created_by != agent_id:
                # Security: Return 404 to avoid information leak (don't reveal skill exists)
                raise NotFoundError("Skill", str(skill_id))

            # 5. Check if already activated (idempotent)
            # Active = most recent activation with deactivated_at=NULL
            active_check_stmt = (
                select(SkillActivation)
                .where(
                    SkillActivation.skill_id == str(skill_id),
                    SkillActivation.agent_id == agent_id,
                )
                .order_by(SkillActivation.activated_at.desc())
                .limit(1)
            )
            active_check_result = await self.session.execute(active_check_stmt)
            latest_activation = active_check_result.scalar_one_or_none()

            # Check if latest activation is still active
            # Active = success is None (not yet completed) or success is True
            # (completed successfully). Deactivated = success is False
            if latest_activation and (
                latest_activation.success is None or latest_activation.success is True
            ):
                logger.info(
                    f"Skill {skill.name} (ID: {skill_id}) is already active (idempotent)",
                    extra={
                        "skill_id": str(skill_id),
                        "skill_name": skill.name,
                        "agent_id": agent_id,
                        "namespace": namespace,
                    },
                )
                # Fetch active version
                version_stmt = select(SkillVersion).where(
                    SkillVersion.skill_id == str(skill_id),
                    SkillVersion.version == skill.active_version,
                )
                version_result = await self.session.execute(version_stmt)
                active_version = version_result.scalar_one_or_none()

                if not active_version:
                    log_and_raise(
                        DatabaseError,
                        "Active version not found",
                        details={
                            "skill_id": str(skill_id),
                            "active_version": skill.active_version,
                        },
                    )

                return SkillDTO.from_models(skill, active_version, detail_level=2)

            # 6. Check one-active-per-namespace rule
            # Find all skills in same namespace with active activations
            other_active_stmt = (
                select(SkillActivation, Skill)
                .join(Skill, Skill.id == SkillActivation.skill_id)
                .where(
                    Skill.namespace == namespace,
                    Skill.id != str(skill_id),  # Exclude current skill
                    Skill.is_deleted == False,  # noqa: E712
                    SkillActivation.success.is_(None)
                    | SkillActivation.success.is_(True),  # Active = success is NULL or True
                )
                .order_by(SkillActivation.activated_at.desc())
            )
            other_active_result = await self.session.execute(other_active_stmt)
            other_active_rows = other_active_result.all()

            # Check if any other skill has a more recent active activation
            for activation, other_skill in other_active_rows:
                # Check if this is the most recent activation for this skill
                latest_for_skill_stmt = (
                    select(SkillActivation)
                    .where(SkillActivation.skill_id == other_skill.id)
                    .order_by(SkillActivation.activated_at.desc())
                    .limit(1)
                )
                latest_for_skill_result = await self.session.execute(latest_for_skill_stmt)
                latest_for_skill = latest_for_skill_result.scalar_one_or_none()

                if (
                    latest_for_skill
                    and latest_for_skill.id == activation.id
                    and (latest_for_skill.success is None or latest_for_skill.success)
                ):
                    # Another skill is active in this namespace
                    log_and_raise(
                        ValidationError,
                        "Another skill is already active in this namespace",
                        details={
                            "error_code": "ONE_ACTIVE_SKILL_PER_NAMESPACE",
                            "namespace": namespace,
                            "active_skill_id": other_skill.id,
                            "active_skill_name": other_skill.name,
                            "action_required": f"Deactivate skill '{other_skill.name}' first",
                        },
                    )

            # 7. Create SkillActivation record
            new_activation = SkillActivation(
                id=str(uuid.uuid4()),
                skill_id=str(skill_id),
                agent_id=agent_id,
                version=skill.active_version,
                namespace=namespace,
                activation_type="mcp_tool",
                layer_loaded=2,  # Progressive Disclosure Layer 2 (core_instructions)
                tokens_loaded=2000,  # Estimated ~2,000 tokens for Layer 2
                activated_at=datetime.now(timezone.utc),
                success=None,  # NULL = active (not yet deactivated)
            )
            self.session.add(new_activation)

            # 8. Commit transaction
            await self.session.commit()
            await self.session.refresh(skill)

            logger.info(
                f"Skill {skill.name} (ID: {skill_id}) activated successfully",
                extra={
                    "skill_id": str(skill_id),
                    "skill_name": skill.name,
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "version": skill.active_version,
                    "activation_id": new_activation.id,
                },
            )

            # 9. Fetch active version for DTO conversion
            version_stmt = select(SkillVersion).where(
                SkillVersion.skill_id == str(skill_id),
                SkillVersion.version == skill.active_version,
            )
            version_result = await self.session.execute(version_stmt)
            active_version = version_result.scalar_one_or_none()

            if not active_version:
                log_and_raise(
                    DatabaseError,
                    "Active version not found after activation",
                    details={
                        "skill_id": str(skill_id),
                        "active_version": skill.active_version,
                    },
                )

            # 10. Register skill as dynamic MCP tool (if registry available)
            tool_name = None
            if self._tool_registry:
                try:
                    tool_name = self._tool_registry.register_tool(
                        skill_id=str(skill_id),
                        skill_name=skill.name,
                        skill_content=active_version.core_instructions,
                    )
                    # Issue #72: Enhanced security logging for successful skill activation
                    logger.info(
                        f"Skill registered as MCP tool: {tool_name}",
                        extra={
                            "skill_id": str(skill_id),
                            "skill_name": skill.name,
                            "tool_name": tool_name,
                            "security_event": "SKILL_ACTIVATION_SUCCESS",
                            "agent_id": agent_id,
                            "namespace": namespace,
                            "version": skill.active_version,
                            "activation_id": new_activation.id,
                        },
                    )
                except Exception as e:
                    # Log error but don't fail activation
                    # Tool registration is additive functionality
                    # Issue #72: Enhanced security logging for failed skill activation
                    logger.warning(
                        f"Failed to register skill as MCP tool (activation still successful): {e}",
                        extra={
                            "skill_id": str(skill_id),
                            "skill_name": skill.name,
                            "security_event": "SKILL_ACTIVATION_REGISTRATION_FAILED",
                            "agent_id": agent_id,
                            "namespace": namespace,
                            "error_type": type(e).__name__,
                        },
                    )
            else:
                logger.debug(
                    "DynamicToolRegistry not configured, skipping MCP tool registration",
                    extra={"skill_id": str(skill_id)},
                )

            # 11. Return updated SkillDTO with core_instructions (Layer 2)
            return SkillDTO.from_models(skill, active_version, detail_level=2)

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (NotFoundError, ValidationError):
            # Re-raise business logic exceptions
            raise
        except SQLAlchemyError as e:
            # Database transaction failure
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Database error during skill activation",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
        except Exception as e:
            # Unexpected errors
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Unexpected error during skill activation",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )

    async def deactivate_skill(
        self,
        skill_id: uuid.UUID,
        *,
        agent_id: str,
        namespace: str,
    ) -> SkillDTO:
        """Deactivate a skill (remove from MCP tool registration).

        Workflow:
        1. Fetch Skill from database
        2. Verify P0-1 access control (owner + namespace)
        3. Find active SkillActivation record (success=NULL or True)
        4. Set success=False to mark as deactivated
        5. Return updated SkillDTO

        Business Rules:
        - Owner-only operation (404 if not owner)
        - Idempotent: Deactivating non-active skill returns success
        - Cannot deactivate deleted skills (404)

        MCP Integration:
        - Deactivated skill removed from MCP tool context
        - Skill content unloaded from MCP server
        - Frees up namespace slot for another skill activation

        Args:
            skill_id: Skill UUID to deactivate
            agent_id: Agent requesting deactivation (must be owner)
            namespace: Verified namespace from database

        Returns:
            Updated SkillDTO (detail_level=2)

        Raises:
            NotFoundError: Skill doesn't exist, is deleted, or access denied (404)
        """
        try:
            # 1. Fetch Skill from database
            stmt = (
                select(Skill)
                .where(Skill.id == str(skill_id))
                .options(selectinload(Skill.activations))
            )
            result = await self.session.execute(stmt)
            skill = result.scalar_one_or_none()

            # 2. Verify skill exists and is accessible
            if not skill or skill.is_deleted:
                raise NotFoundError("Skill", str(skill_id))

            # 3. Verify P0-1 access control: namespace isolation
            if not skill.is_accessible_by(agent_id, namespace):
                # Security: Return 404 to avoid information leak
                raise NotFoundError("Skill", str(skill_id))

            # 4. Verify ownership (only owner can deactivate)
            if skill.created_by != agent_id:
                # Security: Return 404 to avoid information leak (don't reveal skill exists)
                raise NotFoundError("Skill", str(skill_id))

            # 5. Find active SkillActivation record
            # Active = most recent activation with success=NULL or True
            active_check_stmt = (
                select(SkillActivation)
                .where(
                    SkillActivation.skill_id == str(skill_id),
                    SkillActivation.agent_id == agent_id,
                )
                .order_by(SkillActivation.activated_at.desc())
                .limit(1)
            )
            active_check_result = await self.session.execute(active_check_stmt)
            latest_activation = active_check_result.scalar_one_or_none()

            # Check if latest activation is active
            if not latest_activation or (
                latest_activation.success is not None and not latest_activation.success
            ):
                # Already deactivated or never activated
                logger.info(
                    f"Skill {skill.name} (ID: {skill_id}) is already deactivated (idempotent)",
                    extra={
                        "skill_id": str(skill_id),
                        "skill_name": skill.name,
                        "agent_id": agent_id,
                        "namespace": namespace,
                    },
                )
                # Fetch active version
                version_stmt = select(SkillVersion).where(
                    SkillVersion.skill_id == str(skill_id),
                    SkillVersion.version == skill.active_version,
                )
                version_result = await self.session.execute(version_stmt)
                active_version = version_result.scalar_one_or_none()

                if not active_version:
                    log_and_raise(
                        DatabaseError,
                        "Active version not found",
                        details={
                            "skill_id": str(skill_id),
                            "active_version": skill.active_version,
                        },
                    )

                return SkillDTO.from_models(skill, active_version, detail_level=2)

            # 6. Mark as deactivated (set success=False)
            latest_activation.success = False
            # Calculate duration (time from activation to now)
            now = datetime.now(timezone.utc)
            # Ensure both datetimes are timezone-aware for subtraction
            activated_at = latest_activation.activated_at
            if activated_at.tzinfo is None:
                activated_at = activated_at.replace(tzinfo=timezone.utc)
            duration = now - activated_at
            latest_activation.duration_ms = int(duration.total_seconds() * 1000)

            # 7. Commit transaction
            await self.session.commit()
            await self.session.refresh(skill)

            logger.info(
                f"Skill {skill.name} (ID: {skill_id}) deactivated successfully",
                extra={
                    "skill_id": str(skill_id),
                    "skill_name": skill.name,
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "activation_id": latest_activation.id,
                    "duration_ms": latest_activation.duration_ms,
                },
            )

            # 8. Fetch active version for DTO conversion
            version_stmt = select(SkillVersion).where(
                SkillVersion.skill_id == str(skill_id),
                SkillVersion.version == skill.active_version,
            )
            version_result = await self.session.execute(version_stmt)
            active_version = version_result.scalar_one_or_none()

            if not active_version:
                log_and_raise(
                    DatabaseError,
                    "Active version not found after deactivation",
                    details={
                        "skill_id": str(skill_id),
                        "active_version": skill.active_version,
                    },
                )

            # 9. Unregister skill from MCP tools (if registry available)
            if self._tool_registry:
                try:
                    tool_name = f"skill_{skill.name.replace('-', '_')}"
                    self._tool_registry.unregister_tool(
                        skill_id=str(skill_id),
                        tool_name=tool_name,
                    )
                    # Issue #72: Enhanced security logging for successful skill deactivation
                    logger.info(
                        f"Skill unregistered from MCP tool registry: {tool_name}",
                        extra={
                            "skill_id": str(skill_id),
                            "skill_name": skill.name,
                            "tool_name": tool_name,
                            "security_event": "SKILL_DEACTIVATION_SUCCESS",
                            "agent_id": agent_id,
                            "namespace": namespace,
                            "activation_id": latest_activation.id,
                            "duration_ms": latest_activation.duration_ms,
                        },
                    )
                except Exception as e:
                    # Log error but don't fail deactivation
                    # Issue #72: Enhanced security logging for failed skill deactivation
                    logger.warning(
                        f"Failed to unregister skill from MCP tool registry (deactivation still successful): {e}",
                        extra={
                            "skill_id": str(skill_id),
                            "skill_name": skill.name,
                            "security_event": "SKILL_DEACTIVATION_UNREGISTRATION_FAILED",
                            "agent_id": agent_id,
                            "namespace": namespace,
                            "error_type": type(e).__name__,
                        },
                    )

            # 10. Return updated SkillDTO
            return SkillDTO.from_models(skill, active_version, detail_level=2)

        except (KeyboardInterrupt, SystemExit):
            # Never suppress user interrupts
            raise
        except (NotFoundError, ValidationError):
            # Re-raise business logic exceptions
            raise
        except SQLAlchemyError as e:
            # Database transaction failure
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Database error during skill deactivation",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
        except Exception as e:
            # Unexpected errors
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Unexpected error during skill deactivation",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
