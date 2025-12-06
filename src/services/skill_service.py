"""Skill Service for TMWS v2.4.0 - Progressive Disclosure Skills System

This service provides CRUD operations for skills with:
- Progressive Disclosure (3 layers: metadata, core instructions, full content)
- Access control (PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM)
- Namespace isolation (P0-1 security pattern)
- Version management (auto-versioning)
- Content integrity (SHA256 hashing)

Architecture:
- Service layer pattern (business logic)
- Database session management (async)
- DTO conversion (models -> DTOs)
- Security enforcement (P0-1 access control)

Performance targets:
- create_skill(): < 100ms P95
- get_skill(): < 50ms P95 (single query with JOIN)
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


class SkillService:
    """Service for skill management with Progressive Disclosure support.

    This service handles:
    - Skill creation with auto-versioning (v1)
    - Skill retrieval with Progressive Disclosure (3 levels)
    - Skill updates with version increments (future)
    - Access control enforcement (P0-1 pattern)
    - Content integrity verification (SHA256)

    Security:
    - P0-1: Namespace verified from database (never from JWT)
    - S-3-M1/M2/M3: Input validation via SkillValidationService
    - Access control: Skill.is_accessible_by() enforcement
    - No information leak: 404 for both "not found" and "access denied"
    """

    def __init__(self, session: AsyncSession):
        """Initialize skill service.

        Args:
            session: Async database session
        """
        self.session = session
        self.validation_service = SkillValidationService()

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

        Security:
            - S-3-M1/M2/M3: Input validation via SkillValidationService
            - P0-1: Namespace verified from Agent record (not from JWT)
            - Access control: Only owner can create (created_by must match agent_id)

        Performance:
            - Single transaction with 2 INSERTs
            - No N+1 queries
            - Target: < 100ms P95
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
                    f"✅ Skill created: {validated_name} (ID: {skill_id})",
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

        Progressive Disclosure:
            - detail_level=1: Metadata only (name, persona, namespace, tags)
            - detail_level=2: + Core Instructions (~2000 tokens)
            - detail_level=3: Full Content (~10000 tokens)

        Security:
            - P0-1: Namespace MUST be verified from database, not from JWT
            - Access control via skill.is_accessible_by()
            - 404 if skill not found OR access denied (no information leak)

        Performance:
            - Single query with JOIN (Skill + SkillVersion)
            - No N+1 queries
            - Target: < 50ms P95
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
                f"✅ Skill retrieved: {skill.name} (detail_level={detail_level})",
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

        Security:
        - P0-1: Namespace MUST be verified from database (Agent.namespace)
        - Access control: Only owner (created_by) can update
        - Validation: All inputs validated before any DB writes

        Versioning Logic:
        - Content change → New SkillVersion created (v2, v3, ...)
        - Metadata-only change → No new version (update in-place)

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

        Performance:
            - Single transaction
            - Metadata-only update: 1 UPDATE
            - Content update: 1 UPDATE + 1 INSERT
            - Target: < 100ms P95
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
                    f"✅ Skill updated: {skill.name} (ID: {skill_id})",
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

        Access Control Logic (P0-1):
        - PRIVATE: Only owner can see (created_by == agent_id)
        - TEAM: Same namespace agents (namespace == requesting_agent_namespace)
        - SHARED: Explicitly shared agents (check skill_shared_agents table)
        - PUBLIC: All agents
        - SYSTEM: All agents (read-only)
        - is_deleted=False (always filtered out)

        Progressive Disclosure:
        - detail_level=1: Metadata only (name, persona, namespace, tags, created_at)
        - detail_level=2: + Core instructions (~2000 tokens) [DEFAULT]
        - detail_level=3: Full content (~10000 tokens)

        Filtering:
        - tags: AND logic (skill must have ALL specified tags)
        - access_level: Exact match filter
        - is_deleted=False (always filtered out)

        Pagination:
        - limit: 1-100 (default 50)
        - offset: 0+ (default 0)
        - Ordered by: updated_at DESC (newest first)

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

        Security:
            - P0-1: Namespace MUST be verified from database (Agent.namespace)
            - Access control enforced in SQL query (no post-filtering)
            - No information leak (skills are filtered at query level)

        Performance:
            - Single query with JOIN
            - No N+1 queries
            - Index usage: ix_skills_namespace_name, ix_skills_is_deleted
            - Target: < 50ms P95 for 50 results
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
                f"✅ Listed {len(skills)} skills "
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

        Security:
        - P0-1: Namespace MUST be verified from database (Agent.namespace)
        - Access control: Only owner (created_by) can delete
        - Business rule: Cannot delete activated skills (must deactivate first)
        - Return 404 for all access denied cases (no information leak)

        Soft Delete Logic:
        - Does NOT physically remove from database
        - Sets is_deleted=True flag
        - Skill becomes invisible to list_skills() and get_skill()
        - Preserves data for audit/recovery purposes
        - Idempotent: Deleting already deleted skill returns NotFoundError

        Args:
            skill_id: Skill UUID as string (SQLite-compatible)
            agent_id: Agent requesting deletion
            namespace: Verified namespace from database (P0-1 pattern)

        Returns:
            None (success indicated by no exception)

        Raises:
            NotFoundError: Skill doesn't exist, already deleted, or access denied
                (404 for all cases)
            ValidationError: Skill is activated (cannot delete, must deactivate first)
            DatabaseError: Transaction failure

        Security Notes:
            - Namespace parameter MUST be verified from database before calling
            - Never accept namespace from user input or JWT claims directly
            - Always verify: SELECT namespace FROM agents WHERE agent_id = ?
            - Returns 404 (not 403) for access denied to prevent information leak

        Performance:
            - Single SELECT + UPDATE transaction
            - No N+1 queries
            - Index usage: PRIMARY KEY (id), ix_skills_is_deleted
            - Target: < 20ms P95
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

        Examples:
            # Share with single agent
            skill = await service.share_skill(
                skill_id=UUID("..."),
                agent_id="owner-agent-123",
                namespace="verified-namespace",
                agent_ids_to_add=["collaborator-456"]
            )

            # Share with multiple agent s
            skill = await service.share_skill(
                skill_id=UUID("..."),
                agent_id="owner-agent-123",
                namespace="verified-namespace",
                agent_ids_to_add=["agent-1", "agent-2", "agent-3"]
            )

            # Revoke access from agent
            skill = await service.share_skill(
                skill_id=UUID("..."),
                agent_id="owner-agent-123",
                namespace="verified-namespace",
                agent_ids_to_remove=["agent-1"]
            )

            # Add some, remove others (atomic operation)
            skill = await service.share_skill(
                skill_id=UUID("..."),
                agent_id="owner-agent-123",
                namespace="verified-namespace",
                agent_ids_to_add=["new-agent-4"],
                agent_ids_to_remove=["old-agent-1", "old-agent-2"]
            )
        """
        try:
            # 1. Fetch skill from database (with eager loading of shared_agents)
            from sqlalchemy.orm import selectinload

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
                    from sqlalchemy import delete

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

        Example:
            >>> skill_dto = await skill_service.activate_skill(
            ...     skill_id=UUID("12345678-1234-5678-1234-567812345678"),
            ...     agent_id="agent-artemis",
            ...     namespace="engineering",
            ... )
            >>> assert skill_dto.id == "12345678-1234-5678-1234-567812345678"
        """
        try:
            # 1. Fetch Skill from database
            from sqlalchemy.orm import selectinload

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

        Example:
            >>> skill_dto = await skill_service.deactivate_skill(
            ...     skill_id=UUID("12345678-1234-5678-1234-567812345678"),
            ...     agent_id="agent-artemis",
            ...     namespace="engineering",
            ... )
            >>> assert skill_dto.id == "12345678-1234-5678-1234-567812345678"
        """
        try:
            # 1. Fetch Skill from database
            from sqlalchemy.orm import selectinload

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
