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
import uuid
from datetime import datetime, timezone

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


class SkillActivationOperations:
    """Activation operations for skills (MCP tool lifecycle)."""

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

            # 10. Return updated SkillDTO with core_instructions (Layer 2)
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

            # 9. Return updated SkillDTO
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
