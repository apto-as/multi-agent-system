"""Skill CRUD Operations - Create, Read, Update, Delete, List.

This module handles core database operations for skills:
- create_skill: Create new skill with auto-versioning (v1)
- get_skill: Retrieve skill with Progressive Disclosure
- update_skill: Update skill (creates new version if content changes)
- list_skills: List accessible skills with filtering and pagination
- delete_skill: Soft delete skill (set is_deleted=True)

Security:
- P0-1: Namespace verified from database (never from JWT)
- S-3-M1/M2/M3: Input validation via SkillValidationService
- Access control: skill.is_accessible_by() enforcement
- No information leak: 404 for both "not found" and "access denied"
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.application.dtos.response_dtos import SkillDTO
from src.core.exceptions import (
    DatabaseError,
    NotFoundError,
    PermissionError,
    ValidationError,
    log_and_raise,
)
from src.models.agent import AccessLevel
from src.models.skill import Skill, SkillActivation, SkillSharedAgent, SkillVersion
from src.services.skill_validation_service import SkillValidationService

logger = logging.getLogger(__name__)


class SkillCRUDOperations:
    """CRUD operations for skills."""

    def __init__(self, session: AsyncSession, validation_service: SkillValidationService):
        """Initialize CRUD operations.

        Args:
            session: Async database session
            validation_service: Skill validation service instance
        """
        self.session = session
        self.validation_service = validation_service

    async def create_skill(
        self,
        *,
        name: str,
        namespace: str,
        content: str,
        created_by: str,
        display_name: str | None = None,
        description: str | None = None,
        persona: str | None = None,
        tags: list[str] | None = None,
        access_level: AccessLevel | str = AccessLevel.PRIVATE,
    ) -> SkillDTO:
        """Create new skill with auto-versioning (v1).

        Workflow:
        1. Validate all inputs using SkillValidationService
        2. Verify agent ownership (created_by must exist in database)
        3. Parse Progressive Disclosure layers (metadata, core, auxiliary)
        4. Create Skill record (master table)
        5. Create SkillVersion v1 record
        6. Commit transaction
        7. Return SkillDTO

        Args:
            name: Skill name (lowercase, alphanumeric, hyphens, underscores, 2-255 chars)
            namespace: Namespace for isolation (lowercase, alphanumeric, 1-255 chars)
            content: Full SKILL.md content
            created_by: Agent ID who creates this skill
            display_name: Human-readable name (optional)
            description: Brief description (optional)
            persona: Associated persona (optional, e.g., "hestia-auditor")
            tags: List of tags (optional, max 20 tags)
            access_level: Access control level (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)

        Returns:
            SkillDTO with detail_level=2 (metadata + core instructions)

        Raises:
            ValidationError: Invalid input (S-3-M1/M2/M3 violations)
            PermissionError: Agent not found or not authorized
            DatabaseError: Transaction failure or duplicate skill name
        """
        try:
            logger.info(
                f"Creating skill: {name} in namespace {namespace}",
                extra={
                    "name": name,
                    "namespace": namespace,
                    "created_by": created_by,
                    "persona": persona,
                },
            )

            # 1. Validate all inputs using SkillValidationService
            validated_name = self.validation_service.validate_skill_name(name)
            validated_namespace = self.validation_service.validate_namespace(namespace)
            validated_content = self.validation_service.validate_content(content)
            validated_tags = self.validation_service.validate_tags(tags)

            # Validate access level
            if isinstance(access_level, str):
                validated_access_level = self.validation_service.validate_access_level(access_level)
            else:
                validated_access_level = access_level

            # 2. Verify agent ownership (P0-1: namespace from database)
            from src.models.agent import Agent

            agent_result = await self.session.execute(
                select(Agent).where(Agent.agent_id == created_by)
            )
            agent = agent_result.scalar_one_or_none()

            if not agent:
                log_and_raise(
                    PermissionError,
                    f"Agent not found: {created_by}",
                    details={
                        "created_by": created_by,
                        "error_code": "AGENT_NOT_FOUND",
                    },
                )

            # P0-1: Verify namespace matches agent's namespace
            if agent.namespace != validated_namespace:
                log_and_raise(
                    PermissionError,
                    "Namespace mismatch: Agent cannot create skill in different namespace",
                    details={
                        "agent_namespace": agent.namespace,
                        "requested_namespace": validated_namespace,
                        "error_code": "NAMESPACE_MISMATCH",
                    },
                )

            # 3. Parse Progressive Disclosure layers
            layers = self.validation_service.parse_progressive_disclosure_layers(validated_content)

            # 4. Create Skill record (master table)
            skill_id = str(uuid.uuid4())  # SQLite requires string, not UUID object
            now = datetime.now(timezone.utc)

            skill = Skill(
                id=skill_id,
                name=validated_name,
                namespace=validated_namespace,
                created_by=created_by,
                display_name=display_name,
                description=description,
                persona=persona,
                tags=validated_tags,  # Property setter handles JSON serialization
                access_level=validated_access_level,
                version_count=1,
                active_version=1,
                is_deleted=False,
                created_at=now,
                updated_at=now,
            )

            self.session.add(skill)

            # 5. Create SkillVersion v1 record
            version_id = str(uuid.uuid4())  # SQLite requires string, not UUID object

            skill_version = SkillVersion(
                id=version_id,
                skill_id=skill_id,
                version=1,
                content=validated_content,
                metadata_json=(
                    None
                    if not layers["metadata"]
                    else json.dumps(layers["metadata"])  # Convert dict to JSON string
                ),
                core_instructions=layers["core_instructions"],
                auxiliary_content=layers["auxiliary_content"],
                content_hash=layers["content_hash"],
                created_by=created_by,
                created_at=now,
            )

            self.session.add(skill_version)

            # 6. Commit transaction
            try:
                await self.session.commit()
                logger.info(
                    f"Skill created: {validated_name} (ID: {skill_id})",
                    extra={
                        "skill_id": str(skill_id),
                        "name": validated_name,
                        "namespace": validated_namespace,
                        "version": 1,
                    },
                )
            except IntegrityError as e:
                await self.session.rollback()
                # Duplicate skill name in same namespace
                if "UNIQUE constraint failed" in str(e) or "unique constraint" in str(e).lower():
                    log_and_raise(
                        ValidationError,
                        f"Skill name already exists in namespace: {validated_name}",
                        details={
                            "name": validated_name,
                            "namespace": validated_namespace,
                            "error_code": "DUPLICATE_SKILL_NAME",
                        },
                        original_exception=e,
                    )
                else:
                    log_and_raise(
                        DatabaseError,
                        "Database integrity error during skill creation",
                        details={
                            "name": validated_name,
                            "namespace": validated_namespace,
                        },
                        original_exception=e,
                    )

            # 7. Return SkillDTO (detail_level=2: metadata + core instructions)
            return SkillDTO.from_models(
                skill=skill,
                skill_version=skill_version,
                detail_level=2,
            )

        except (ValidationError, PermissionError):
            # Re-raise validation and permission errors without wrapping
            raise
        except SQLAlchemyError as e:
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Database error during skill creation",
                details={
                    "name": name,
                    "namespace": namespace,
                },
                original_exception=e,
            )
        except Exception as e:
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Unexpected error during skill creation",
                details={
                    "name": name,
                    "namespace": namespace,
                },
                original_exception=e,
            )

    async def get_skill(
        self,
        *,
        skill_id: str,  # UUID as string (SQLite-compatible)
        agent_id: str,
        namespace: str,
        detail_level: int = 2,
    ) -> SkillDTO:
        """Get skill by ID with Progressive Disclosure.

        Workflow:
        1. Fetch Skill from database
        2. Verify namespace (P0-1 pattern: namespace from database)
        3. Check access control: skill.is_accessible_by(agent_id, namespace)
        4. Fetch active SkillVersion
        5. Apply Progressive Disclosure filtering based on detail_level
        6. Return SkillDTO

        Args:
            skill_id: Skill UUID
            agent_id: Requesting agent ID
            namespace: Verified namespace from database (P0-1)
            detail_level: Progressive Disclosure level (1, 2, or 3)

        Returns:
            SkillDTO with appropriate content based on detail_level

        Raises:
            NotFoundError: Skill not found OR access denied (no information leak)
            ValidationError: Invalid detail_level (must be 1, 2, or 3)
        """
        try:
            logger.debug(
                f"Getting skill: {skill_id} for agent {agent_id}",
                extra={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "detail_level": detail_level,
                },
            )

            # Validate detail_level
            if detail_level not in [1, 2, 3]:
                log_and_raise(
                    ValidationError,
                    "Invalid detail_level: must be 1, 2, or 3",
                    details={
                        "detail_level": detail_level,
                        "valid_levels": [1, 2, 3],
                        "error_code": "INVALID_DETAIL_LEVEL",
                    },
                )

            # 1. Fetch Skill from database (with active SkillVersion)
            # JOIN optimization: Single query for both Skill and SkillVersion
            # Eager load shared_agents for SHARED access level checks
            stmt = (
                select(Skill, SkillVersion)
                .join(
                    SkillVersion,
                    (SkillVersion.skill_id == Skill.id)
                    & (SkillVersion.version == Skill.active_version),
                )
                .options(selectinload(Skill.shared_agents))
                .where(Skill.id == str(skill_id))
            )

            result = await self.session.execute(stmt)
            row = result.one_or_none()

            # 2. Check if skill exists
            if not row:
                # Return 404 for both "not found" and "access denied"
                # (security: no information leak)
                raise NotFoundError("Skill", str(skill_id))

            skill, skill_version = row

            # 3. Check access control (P0-1: namespace from database)
            # SECURITY-CRITICAL: namespace parameter MUST be verified from Agent record
            if not skill.is_accessible_by(agent_id, namespace):
                # Return 404 for access denied (security: no information leak)
                logger.warning(
                    f"Access denied: Agent {agent_id} cannot access skill {skill_id}",
                    extra={
                        "skill_id": str(skill_id),
                        "agent_id": agent_id,
                        "namespace": namespace,
                        "skill_access_level": skill.access_level.value,
                    },
                )
                raise NotFoundError("Skill", str(skill_id))

            # 4. Return SkillDTO with Progressive Disclosure
            logger.info(
                f"Skill retrieved: {skill.name} (detail_level={detail_level})",
                extra={
                    "skill_id": str(skill_id),
                    "name": skill.name,
                    "namespace": skill.namespace,
                    "detail_level": detail_level,
                    "agent_id": agent_id,
                },
            )

            return SkillDTO.from_models(
                skill=skill,
                skill_version=skill_version,
                detail_level=detail_level,
            )

        except (ValidationError, NotFoundError):
            # Re-raise validation and not-found errors without wrapping
            raise
        except SQLAlchemyError as e:
            log_and_raise(
                DatabaseError,
                "Database error during skill retrieval",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
        except Exception as e:
            log_and_raise(
                DatabaseError,
                "Unexpected error during skill retrieval",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )

    async def update_skill(
        self,
        skill_id: str,
        *,
        agent_id: str,
        namespace: str,
        name: str | None = None,
        content: str | None = None,
        tags: list[str] | None = None,
        access_level: AccessLevel | str | None = None,
    ) -> SkillDTO:
        """Update an existing skill (creates new version if content changes).

        Workflow:
        1. Fetch existing Skill from database
        2. Verify P0-1 access control (agent ownership + namespace)
        3. Validate all provided fields (SkillValidationService)
        4. Determine if versioning needed (content changed?)
        5. If content changed:
           - Parse Progressive Disclosure layers
           - Create new SkillVersion (increment version number)
           - Update Skill.active_version
        6. Update Skill metadata (name, tags, access_level)
        7. Commit transaction
        8. Return updated SkillDTO

        Args:
            skill_id: Skill UUID to update
            agent_id: Agent making the update
            namespace: Verified namespace from database
            name: New name (optional, metadata-only)
            content: New Progressive Disclosure content (optional, triggers versioning)
            tags: New tags (optional, metadata-only, replaces existing)
            access_level: New access level (optional, metadata-only)

        Returns:
            Updated SkillDTO with current active version

        Raises:
            NotFoundError: Skill doesn't exist or access denied (404 for both)
            ValidationError: Invalid update data
            PermissionError: Agent doesn't own skill (internal, converted to 404)
        """
        try:
            logger.info(
                f"Updating skill: {skill_id} by agent {agent_id}",
                extra={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "has_name": name is not None,
                    "has_content": content is not None,
                    "has_tags": tags is not None,
                    "has_access_level": access_level is not None,
                },
            )

            # 1. Fetch skill from database
            skill = await self.session.get(Skill, str(skill_id))
            if not skill or skill.is_deleted:
                raise NotFoundError("Skill", str(skill_id))

            # 2. Verify P0-1 access control
            if not skill.is_accessible_by(agent_id, namespace):
                # Return 404 for access denied (no information leak)
                logger.warning(
                    f"Access denied: Agent {agent_id} cannot access skill {skill_id}",
                    extra={
                        "skill_id": str(skill_id),
                        "agent_id": agent_id,
                        "namespace": namespace,
                    },
                )
                raise NotFoundError("Skill", str(skill_id))

            # Verify ownership (only owner can update)
            if skill.created_by != agent_id:
                logger.warning(
                    f"Update denied: Agent {agent_id} does not own skill {skill_id}",
                    extra={
                        "skill_id": str(skill_id),
                        "agent_id": agent_id,
                        "owner": skill.created_by,
                    },
                )
                raise NotFoundError("Skill", str(skill_id))  # 404, not 403

            # 3. Validate all provided fields
            if name is not None:
                name = self.validation_service.validate_skill_name(name)

            if tags is not None:
                tags = self.validation_service.validate_tags(tags)

            if access_level is not None and isinstance(access_level, str):
                access_level = self.validation_service.validate_access_level(access_level)

            if content is not None:
                content = self.validation_service.validate_content(content)

            # 4. Determine if new version needed
            create_new_version = content is not None

            if create_new_version:
                # Parse Progressive Disclosure layers
                layers = self.validation_service.parse_progressive_disclosure_layers(content)

                # Create new SkillVersion
                new_version_number = skill.active_version + 1
                now = datetime.now(timezone.utc)

                new_version = SkillVersion(
                    id=str(uuid.uuid4()),
                    skill_id=str(skill_id),
                    version=new_version_number,
                    content=content,
                    metadata_json=(
                        None if not layers["metadata"] else json.dumps(layers["metadata"])
                    ),
                    core_instructions=layers["core_instructions"],
                    auxiliary_content=layers["auxiliary_content"],
                    content_hash=layers["content_hash"],
                    created_by=agent_id,
                    created_at=now,
                )

                self.session.add(new_version)
                skill.active_version = new_version_number
                skill.version_count += 1

                logger.info(
                    f"Creating new version {new_version_number} for skill {skill_id}",
                    extra={
                        "skill_id": str(skill_id),
                        "version": new_version_number,
                        "content_hash": layers["content_hash"],
                    },
                )

            # 5. Update metadata (always, even if no version change)
            if name is not None:
                skill.name = name

            if tags is not None:
                skill.tags = tags  # Property setter handles JSON serialization

            if access_level is not None:
                skill.access_level = access_level

            skill.updated_at = datetime.now(timezone.utc)

            # 6. Commit transaction
            try:
                await self.session.commit()
                await self.session.refresh(skill)

                logger.info(
                    f"Skill updated: {skill.name} (ID: {skill_id})",
                    extra={
                        "skill_id": str(skill_id),
                        "name": skill.name,
                        "version": skill.active_version,
                        "version_count": skill.version_count,
                        "new_version_created": create_new_version,
                    },
                )
            except IntegrityError as e:
                await self.session.rollback()
                # Duplicate skill name in same namespace
                if "UNIQUE constraint failed" in str(e) or "unique constraint" in str(e).lower():
                    log_and_raise(
                        ValidationError,
                        f"Skill name already exists in namespace: {name}",
                        details={
                            "name": name,
                            "namespace": namespace,
                            "error_code": "DUPLICATE_SKILL_NAME",
                        },
                        original_exception=e,
                    )
                else:
                    log_and_raise(
                        DatabaseError,
                        "Database integrity error during skill update",
                        details={
                            "skill_id": str(skill_id),
                            "namespace": namespace,
                        },
                        original_exception=e,
                    )

            # 7. Fetch active version for DTO
            stmt = select(SkillVersion).where(
                (SkillVersion.skill_id == str(skill.id))
                & (SkillVersion.version == skill.active_version)
            )
            result = await self.session.execute(stmt)
            active_version = result.scalar_one_or_none()

            if not active_version:
                # Should never happen, but defensive programming
                log_and_raise(
                    DatabaseError,
                    "Active version not found after update",
                    details={
                        "skill_id": str(skill_id),
                        "active_version": skill.active_version,
                    },
                )

            # Return SkillDTO with detail_level=3 (full content after update)
            return SkillDTO.from_models(skill, active_version, detail_level=3)

        except (ValidationError, NotFoundError):
            # Re-raise validation and not-found errors without wrapping
            raise
        except SQLAlchemyError as e:
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Database error during skill update",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
        except Exception as e:
            await self.session.rollback()
            log_and_raise(
                DatabaseError,
                "Unexpected error during skill update",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )

    async def list_skills(
        self,
        *,
        agent_id: str,
        namespace: str,
        tags: list[str] | None = None,
        access_level: AccessLevel | None = None,
        detail_level: int = 2,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SkillDTO]:
        """List accessible skills with Progressive Disclosure and filtering.

        Workflow:
        1. Validate input parameters (detail_level, limit, offset, tags)
        2. Build base query (SELECT from skills JOIN skill_versions)
        3. Apply access control filter (is_accessible_by logic in SQL)
        4. Apply optional filters (tags, access_level)
        5. Apply pagination (limit, offset, order by updated_at DESC)
        6. Execute query and build DTOs with Progressive Disclosure
        7. Return list of SkillDTO

        Args:
            agent_id: Agent making the request
            namespace: Verified namespace from database (P0-1 pattern)
            tags: Filter by tags (AND logic, optional)
            access_level: Filter by access level (optional)
            detail_level: Progressive Disclosure level (1/2/3, default 2)
            limit: Max results (1-100, default 50)
            offset: Pagination offset (default 0)

        Returns:
            List of SkillDTO instances at specified detail level

        Raises:
            ValidationError: Invalid parameters (detail_level, limit, offset, tags)
            DatabaseError: Query execution failure
        """
        try:
            logger.debug(
                f"Listing skills for agent {agent_id}",
                extra={
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "tags": tags,
                    "access_level": access_level.value if access_level else None,
                    "detail_level": detail_level,
                    "limit": limit,
                    "offset": offset,
                },
            )

            # 1. Validate input parameters
            if detail_level not in [1, 2, 3]:
                log_and_raise(
                    ValidationError,
                    "Invalid detail_level: must be 1, 2, or 3",
                    details={
                        "detail_level": detail_level,
                        "valid_levels": [1, 2, 3],
                        "error_code": "INVALID_DETAIL_LEVEL",
                    },
                )

            if not (1 <= limit <= 100):
                log_and_raise(
                    ValidationError,
                    "Invalid limit: must be between 1 and 100",
                    details={
                        "limit": limit,
                        "valid_range": "1-100",
                        "error_code": "INVALID_LIMIT",
                    },
                )

            if offset < 0:
                log_and_raise(
                    ValidationError,
                    "Invalid offset: must be >= 0",
                    details={
                        "offset": offset,
                        "min": 0,
                        "error_code": "INVALID_OFFSET",
                    },
                )

            # Validate tags (if provided)
            if tags is not None:
                tags = self.validation_service.validate_tags(tags)

            # 2. Build base query (JOIN Skill with active SkillVersion)
            stmt = (
                select(Skill, SkillVersion)
                .join(
                    SkillVersion,
                    and_(
                        Skill.id == SkillVersion.skill_id,
                        Skill.active_version == SkillVersion.version,
                    ),
                )
                .where(Skill.is_deleted == False)  # noqa: E712
            )

            # 3. Apply access control filter (P0-1 pattern)
            # Option 1: PRIVATE skills (owner only)
            private_condition = and_(
                Skill.access_level == AccessLevel.PRIVATE,
                Skill.created_by == agent_id,
            )

            # Option 2: TEAM skills (same namespace)
            team_condition = and_(
                Skill.access_level == AccessLevel.TEAM,
                Skill.namespace == namespace,
            )

            # Option 3: PUBLIC/SYSTEM skills (all agents)
            public_condition = Skill.access_level.in_([AccessLevel.PUBLIC, AccessLevel.SYSTEM])

            # Option 4: SHARED skills (explicitly shared to this agent)
            # Subquery to check if agent_id is in skill_shared_agents table
            shared_condition = and_(
                Skill.access_level == AccessLevel.SHARED,
                Skill.id.in_(
                    select(SkillSharedAgent.skill_id).where(SkillSharedAgent.agent_id == agent_id)
                ),
                Skill.namespace == namespace,  # Additional namespace check for SHARED
            )

            # Combine all conditions with OR
            access_control = or_(
                private_condition,
                team_condition,
                public_condition,
                shared_condition,
            )

            stmt = stmt.where(access_control)

            # 4. Apply optional filters
            # Filter by tags (AND logic)
            if tags:
                for tag in tags:
                    # SQLite JSON contains check - must check each tag individually
                    stmt = stmt.where(Skill.tags_json.like(f'%"{tag}"%'))

            # Filter by access_level (exact match)
            if access_level is not None:
                stmt = stmt.where(Skill.access_level == access_level)

            # 5. Apply pagination and ordering
            stmt = stmt.order_by(Skill.updated_at.desc())
            stmt = stmt.limit(limit).offset(offset)

            # 6. Execute query
            result = await self.session.execute(stmt)
            rows = result.all()

            # 7. Build DTOs with Progressive Disclosure
            skills = []
            for skill, skill_version in rows:
                dto = SkillDTO.from_models(skill, skill_version, detail_level=detail_level)
                skills.append(dto)

            logger.info(
                f"Listed {len(skills)} skills "
                f"(agent: {agent_id}, limit: {limit}, offset: {offset})",
                extra={
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "result_count": len(skills),
                    "detail_level": detail_level,
                    "limit": limit,
                    "offset": offset,
                    "has_tags_filter": tags is not None,
                    "has_access_level_filter": access_level is not None,
                },
            )

            return skills

        except ValidationError:
            # Re-raise validation errors without wrapping
            raise
        except SQLAlchemyError as e:
            log_and_raise(
                DatabaseError,
                "Database error during skill listing",
                details={
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "limit": limit,
                    "offset": offset,
                },
                original_exception=e,
            )
        except Exception as e:
            log_and_raise(
                DatabaseError,
                "Unexpected error during skill listing",
                details={
                    "agent_id": agent_id,
                    "namespace": namespace,
                    "limit": limit,
                    "offset": offset,
                },
                original_exception=e,
            )

    async def delete_skill(
        self,
        *,
        skill_id: str,  # UUID as string (SQLite-compatible)
        agent_id: str,
        namespace: str,
    ) -> None:
        """Delete a skill (soft delete - set is_deleted=True).

        Workflow:
        1. Fetch Skill from database
        2. Verify P0-1 access control (owner only + namespace)
        3. Check if skill is activated (cannot delete activated skills)
        4. Set is_deleted=True
        5. Set updated_at to current time
        6. Commit transaction

        Args:
            skill_id: Skill UUID as string (SQLite-compatible)
            agent_id: Agent requesting deletion
            namespace: Verified namespace from database (P0-1 pattern)

        Returns:
            None (success indicated by no exception)

        Raises:
            NotFoundError: Skill doesn't exist, already deleted, or access denied
            ValidationError: Skill is activated (cannot delete, must deactivate first)
            DatabaseError: Transaction failure
        """
        try:
            logger.debug(
                f"Deleting skill {skill_id} for agent {agent_id}",
                extra={
                    "skill_id": skill_id,
                    "agent_id": agent_id,
                    "namespace": namespace,
                },
            )

            # 1. Fetch skill from database
            skill = await self.session.get(Skill, str(skill_id))

            # 2. Verify P0-1 access control
            # Return 404 if skill doesn't exist or is already deleted (no information leak)
            if not skill or skill.is_deleted:
                raise NotFoundError("Skill", skill_id)

            # Verify access (namespace + ownership check)
            # Return 404 for access denied (no information leak)
            if not skill.is_accessible_by(agent_id, namespace):
                raise NotFoundError("Skill", skill_id)

            # Verify ownership (only owner can delete)
            # Return 404 for non-owner (no information leak)
            if skill.created_by != agent_id:
                raise NotFoundError("Skill", skill_id)

            # 3. Check if skill is activated
            # NOTE: We check if there are any active SkillActivation records
            # For now, we'll implement a simple check based on recent activations
            # A skill is considered "activated" if it has activations in the last 24 hours
            recent_activations_stmt = (
                select(SkillActivation)
                .where(
                    SkillActivation.skill_id == skill_id,
                    SkillActivation.activated_at > datetime.now(timezone.utc) - timedelta(hours=24),
                )
                .limit(1)
            )
            result = await self.session.execute(recent_activations_stmt)
            has_recent_activation = result.scalar_one_or_none() is not None

            if has_recent_activation:
                log_and_raise(
                    ValidationError,
                    "Cannot delete activated skill",
                    details={
                        "skill_id": str(skill_id),
                        "error_code": "SKILL_ACTIVATED",
                        "action_required": (
                            "Skill has been activated in the last 24 hours. "
                            "Please wait before deletion."
                        ),
                    },
                )

            # 4. Soft delete: Set is_deleted=True
            skill.is_deleted = True
            skill.updated_at = datetime.now(timezone.utc)

            # 5. Commit transaction
            await self.session.commit()

            logger.info(
                f"Skill {skill.name} (ID: {skill_id}) soft-deleted by agent {agent_id}",
                extra={
                    "skill_id": str(skill_id),
                    "skill_name": skill.name,
                    "agent_id": agent_id,
                    "namespace": namespace,
                },
            )

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
                "Database error during skill deletion",
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
                "Unexpected error during skill deletion",
                details={
                    "skill_id": str(skill_id),
                    "agent_id": agent_id,
                },
                original_exception=e,
            )
