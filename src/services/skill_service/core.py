"""SkillService Core - Coordinator class using composition pattern.

This module provides the main SkillService class that coordinates all skill operations
by delegating to specialized sub-services:
- SkillCRUDOperations: Create, Read, Update, Delete, List
- SkillSharingOperations: SHARED access control whitelist
- SkillActivationOperations: MCP tool lifecycle

Architecture:
- Composition pattern: Each sub-service handles a specific concern
- Session sharing: All sub-services share the same database session
- Backward compatible: Public API unchanged from original skill_service.py

Security:
- P0-1: Namespace verified from database (never from JWT)
- S-3-M1/M2/M3: Input validation via SkillValidationService
- Access control: skill.is_accessible_by() enforcement
"""

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from src.application.dtos.response_dtos import SkillDTO
from src.models.agent import AccessLevel
from src.services.skill_validation_service import SkillValidationService

from .skill_activation import SkillActivationOperations
from .skill_crud import SkillCRUDOperations
from .skill_sharing import SkillSharingOperations

logger = logging.getLogger(__name__)


class SkillService:
    """Service for skill management with Progressive Disclosure support.

    This service handles:
    - Skill creation with auto-versioning (v1)
    - Skill retrieval with Progressive Disclosure (3 levels)
    - Skill updates with version increments (future)
    - Access control enforcement (P0-1 pattern)
    - Content integrity verification (SHA256)

    Architecture:
    - Composition pattern with specialized sub-services
    - All sub-services share the same database session
    - Validation service is shared across CRUD operations

    Security:
    - P0-1: Namespace verified from database (never from JWT)
    - S-3-M1/M2/M3: Input validation via SkillValidationService
    - Access control: Skill.is_accessible_by() enforcement
    - No information leak: 404 for both "not found" and "access denied"
    """

    def __init__(self, session: AsyncSession):
        """Initialize skill service with composition pattern.

        Args:
            session: Async database session (shared by all sub-services)
        """
        self.session = session
        self.validation_service = SkillValidationService()

        # Initialize sub-services with shared session and validation
        self._crud = SkillCRUDOperations(session, self.validation_service)
        self._sharing = SkillSharingOperations(session)
        self._activation = SkillActivationOperations(session)

    # ========================================================================
    # CRUD Operations (delegated to SkillCRUDOperations)
    # ========================================================================

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
        return await self._crud.create_skill(
            name=name,
            namespace=namespace,
            content=content,
            created_by=created_by,
            display_name=display_name,
            description=description,
            persona=persona,
            tags=tags,
            access_level=access_level,
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
        return await self._crud.get_skill(
            skill_id=skill_id,
            agent_id=agent_id,
            namespace=namespace,
            detail_level=detail_level,
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
        - Content change -> New SkillVersion created (v2, v3, ...)
        - Metadata-only change -> No new version (update in-place)

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
        return await self._crud.update_skill(
            skill_id,
            agent_id=agent_id,
            namespace=namespace,
            name=name,
            content=content,
            tags=tags,
            access_level=access_level,
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
        return await self._crud.list_skills(
            agent_id=agent_id,
            namespace=namespace,
            tags=tags,
            access_level=access_level,
            detail_level=detail_level,
            limit=limit,
            offset=offset,
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

        Performance:
            - Single SELECT + UPDATE transaction
            - No N+1 queries
            - Index usage: PRIMARY KEY (id), ix_skills_is_deleted
            - Target: < 20ms P95
        """
        return await self._crud.delete_skill(
            skill_id=skill_id,
            agent_id=agent_id,
            namespace=namespace,
        )

    # ========================================================================
    # Sharing Operations (delegated to SkillSharingOperations)
    # ========================================================================

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
        return await self._sharing.share_skill(
            skill_id,
            agent_id=agent_id,
            namespace=namespace,
            agent_ids_to_add=agent_ids_to_add,
            agent_ids_to_remove=agent_ids_to_remove,
        )

    # ========================================================================
    # Activation Operations (delegated to SkillActivationOperations)
    # ========================================================================

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
        return await self._activation.activate_skill(
            skill_id,
            agent_id=agent_id,
            namespace=namespace,
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
        return await self._activation.deactivate_skill(
            skill_id,
            agent_id=agent_id,
            namespace=namespace,
        )
