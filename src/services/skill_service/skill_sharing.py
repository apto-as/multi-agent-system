"""Skill Sharing Operations - SHARED access control whitelist management.

This module handles skill sharing operations:
- share_skill: Add/remove agents from SHARED access whitelist

Security:
- P0-1: Namespace verified from database (never from JWT)
- Access control: Only skill owner can modify sharing
- Validation: All agent_ids must exist and be in same namespace
- Business rule: Only SHARED skills can be explicitly shared
"""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, select
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
from src.models.agent import AccessLevel
from src.models.skill import Skill, SkillSharedAgent, SkillVersion

logger = logging.getLogger(__name__)


class SkillSharingOperations:
    """Sharing operations for skills (SHARED access control)."""

    def __init__(self, session: AsyncSession):
        """Initialize sharing operations.

        Args:
            session: Async database session
        """
        self.session = session

    async def share_skill(
        self,
        skill_id: uuid.UUID,
        *,
        agent_id: str,
        namespace: str,
        agent_ids_to_add: list[str] | None = None,
        agent_ids_to_remove: list[str] | None = None,
    ) -> SkillDTO:
        """Share or unshare a skill with specific agents (SHARED access control).

        This method modifies the SHARED access whitelist for a skill. Only the skill owner
        can modify sharing, and the skill MUST have access_level=SHARED.

        Workflow:
        1. Fetch Skill from database
        2. Verify P0-1 access control (owner only + namespace verification)
        3. Verify skill access_level is SHARED (only SHARED skills can be explicitly shared)
        4. Validate all agent_ids (must exist in database, same namespace)
        5. Add new shared agents to SkillSharedAgent table (idempotent)
        6. Remove agents from SkillSharedAgent table (idempotent)
        7. Return updated SkillDTO with detail_level=2

        Security:
        - P0-1: Namespace MUST be verified from database (Agent.namespace)
        - Access control: Only owner (created_by) can modify sharing
        - Validation: All agent_ids must exist and be in same namespace
        - Business rule: Only SHARED skills can be shared (other access levels use different logic)

        Sharing Logic:
        - agent_ids_to_add: Add agents to whitelist (grant access)
        - agent_ids_to_remove: Remove agents from whitelist (revoke access)
        - Both can be specified in single call (add some, remove others)
        - Cannot share with self (agent_id == created_by, automatically filtered out)
        - Idempotent: Adding already-shared agent is no-op, removing non-shared agent is no-op

        Args:
            skill_id: Skill UUID to share
            agent_id: Agent requesting sharing operation (must be owner)
            namespace: Verified namespace from database (SECURITY-CRITICAL)
            agent_ids_to_add: List of agent_ids to grant access (optional)
            agent_ids_to_remove: List of agent_ids to revoke access (optional)

        Returns:
            Updated SkillDTO with detail_level=2 (includes sharing metadata)

        Raises:
            NotFoundError: Skill doesn't exist, access denied, or not owner (404 for all)
            ValidationError: Invalid operation (wrong access_level, invalid agent_id, etc.)
            DatabaseError: Database transaction failure
        """
        try:
            # 1. Fetch skill from database (with eager loading of shared_agents)
            stmt = (
                select(Skill)
                .where(Skill.id == str(skill_id))
                .options(selectinload(Skill.shared_agents))
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

            # 4. Verify ownership (only owner can modify sharing)
            if skill.created_by != agent_id:
                # Security: Return 404 to avoid information leak (don't reveal skill exists)
                raise NotFoundError("Skill", str(skill_id))

            # 5. Verify skill is SHARED (only SHARED skills can be explicitly shared)
            if skill.access_level != AccessLevel.SHARED:
                log_and_raise(
                    ValidationError,
                    "Only SHARED skills can be explicitly shared with agents",
                    details={
                        "error_code": "INVALID_ACCESS_LEVEL_FOR_SHARING",
                        "current_access_level": skill.access_level.value,
                        "required_access_level": AccessLevel.SHARED.value,
                        "suggestion": "Update skill access_level to SHARED first",
                    },
                )

            # 6. Combine and validate all agent_ids
            all_agent_ids = set()
            if agent_ids_to_add:
                all_agent_ids.update(agent_ids_to_add)
            if agent_ids_to_remove:
                all_agent_ids.update(agent_ids_to_remove)

            # Remove self (cannot share with owner, owner already has full access)
            all_agent_ids.discard(agent_id)

            # If no valid agent_ids to process, return current state
            if not all_agent_ids:
                logger.info(
                    f"No valid agents to share/unshare skill {skill.name} (ID: {skill_id})",
                    extra={
                        "skill_id": str(skill_id),
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

            # 7. Validate all agent_ids (must exist and be in same namespace)
            from src.models.agent import Agent

            agents_stmt = select(Agent).where(
                Agent.agent_id.in_(all_agent_ids),
                Agent.namespace == namespace,  # CRITICAL: Same namespace only
            )
            agents_result = await self.session.execute(agents_stmt)
            valid_agents = {agent.agent_id for agent in agents_result.scalars().all()}

            # Check if all agent_ids are valid
            invalid_agent_ids = all_agent_ids - valid_agents
            if invalid_agent_ids:
                log_and_raise(
                    ValidationError,
                    "Invalid agent IDs for sharing",
                    details={
                        "error_code": "INVALID_AGENT_IDS",
                        "invalid_agent_ids": sorted(invalid_agent_ids),
                        "reason": "Agents not found or not in same namespace",
                        "namespace": namespace,
                    },
                )

            # 8. Add shared agents (idempotent)
            added_count = 0
            if agent_ids_to_add:
                for target_agent_id in agent_ids_to_add:
                    if target_agent_id not in valid_agents:
                        continue  # Skip invalid (already validated above, defensive)

                    # Check if already shared (idempotent)
                    existing_stmt = select(SkillSharedAgent).where(
                        SkillSharedAgent.skill_id == str(skill_id),
                        SkillSharedAgent.agent_id == target_agent_id,
                    )
                    existing_result = await self.session.execute(existing_stmt)
                    if existing_result.scalar_one_or_none():
                        continue  # Already shared, skip

                    # Create new sharing record
                    shared_agent = SkillSharedAgent(
                        id=str(uuid.uuid4()),
                        skill_id=str(skill_id),
                        agent_id=target_agent_id,
                        shared_at=datetime.now(timezone.utc),
                    )
                    self.session.add(shared_agent)
                    added_count += 1

            # 9. Remove shared agents (idempotent)
            removed_count = 0
            if agent_ids_to_remove:
                for target_agent_id in agent_ids_to_remove:
                    # Delete sharing record (idempotent, no error if not exists)
                    delete_stmt = delete(SkillSharedAgent).where(
                        SkillSharedAgent.skill_id == str(skill_id),
                        SkillSharedAgent.agent_id == target_agent_id,
                    )
                    result = await self.session.execute(delete_stmt)
                    removed_count += result.rowcount

            # 10. Commit transaction
            await self.session.commit()
            await self.session.refresh(skill)

            logger.info(
                f"Skill {skill.name} (ID: {skill_id}) sharing updated: "
                f"+{added_count} agents, -{removed_count} agents",
                extra={
                    "skill_id": str(skill_id),
                    "skill_name": skill.name,
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "added_count": added_count,
                    "removed_count": removed_count,
                },
            )

            # 11. Fetch active version for DTO conversion
            version_stmt = select(SkillVersion).where(
                SkillVersion.skill_id == str(skill_id),
                SkillVersion.version == skill.active_version,
            )
            version_result = await self.session.execute(version_stmt)
            active_version = version_result.scalar_one_or_none()

            if not active_version:
                log_and_raise(
                    DatabaseError,
                    "Active version not found after sharing update",
                    details={
                        "skill_id": str(skill_id),
                        "active_version": skill.active_version,
                    },
                )

            # 12. Return updated SkillDTO with sharing metadata
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
                "Database error during skill sharing",
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
                "Unexpected error during skill sharing",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
