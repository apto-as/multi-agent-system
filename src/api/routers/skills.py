"""Skills API Router - RESTful endpoints for skill management.

This module provides HTTP endpoints for comprehensive skill lifecycle management:

Endpoints (8 total):
- POST   /api/v1/skills                  - Create new skill
- GET    /api/v1/skills                  - List accessible skills
- GET    /api/v1/skills/{skill_id}       - Get skill by ID
- PUT    /api/v1/skills/{skill_id}       - Update skill
- DELETE /api/v1/skills/{skill_id}       - Delete skill (soft delete)
- POST   /api/v1/skills/{skill_id}/share - Share skill with other agents
- POST   /api/v1/skills/{skill_id}/activate   - Activate skill (MCP)
- POST   /api/v1/skills/{skill_id}/deactivate - Deactivate skill (MCP)

Security:
- P0-1 security pattern: Namespace verified from database
- Rate limiting: Per-endpoint limits (10-200 requests/hour)
- Request/response validation: Pydantic models
- Access control: PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM levels

Design Principles:
1. Thin controllers - delegate to SkillService
2. Security-first - namespace verification from DB
3. Pydantic validation - request/response models
4. Async-first - non-blocking I/O
5. Rate limiting - prevent abuse
6. Progressive Disclosure - detail_level parameter (1, 2, 3)

Performance:
- <200ms P95 per operation (target)
- Rate limited: 10-200 calls/hour depending on operation
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import (
    User,
    check_rate_limit_skill_activate,
    check_rate_limit_skill_create,
    check_rate_limit_skill_delete,
    check_rate_limit_skill_get,
    check_rate_limit_skill_list,
    check_rate_limit_skill_share,
    check_rate_limit_skill_update,
    get_current_user,
    get_db_session,
)
from src.application.dtos.response_dtos import SkillDTO
from src.core.exceptions import (
    NotFoundError,
    ValidationError,
)
from src.models.agent import AccessLevel, Agent
from src.services.skill_service import SkillService

# Router instance
router = APIRouter(
    prefix="/api/v1/skills",
    tags=["Skills"],
    responses={
        404: {"description": "Skill not found"},
        403: {"description": "Access denied"},
        400: {"description": "Validation error"},
    },
)


# ============================================================================
# Request Models
# ============================================================================


class CreateSkillRequest(BaseModel):
    """Request model for creating a skill."""

    name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Skill name (lowercase, alphanumeric, hyphens, underscores)",
        examples=["python-testing", "api-design"],
    )
    content: str = Field(
        ...,
        min_length=1,
        max_length=50000,
        description="Skill content in SKILL.md format (Progressive Disclosure structure)",
    )
    persona: str | None = Field(
        None,
        max_length=255,
        description="Target persona for this skill (e.g., 'artemis-optimizer', 'hestia-auditor')",
    )
    tags: list[str] | None = Field(
        None,
        max_items=20,
        description="Tags for categorization (lowercase, max 50 chars each)",
    )
    access_level: AccessLevel = Field(
        default=AccessLevel.PRIVATE,
        description="Access level: private, team, shared, public, system",
        examples=["private", "team", "shared"],
    )

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str] | None) -> list[str] | None:
        """Validate tags format.

        Note: Detailed validation (lowercase, length, no duplicates)
        happens in SkillService layer.
        """
        if v is None:
            return v
        # Basic validation
        for tag in v:
            if not tag or len(tag) > 50:
                raise ValueError(f"Invalid tag: {tag} (must be 1-50 chars)")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "name": "python-testing",
                "content": "# Python Testing Best Practices\n\n## Core Instructions\n...",
                "persona": "artemis-optimizer",
                "tags": ["python", "testing", "best-practices"],
                "access_level": "private",
            }
        }


class UpdateSkillRequest(BaseModel):
    """Request model for updating a skill."""

    name: str | None = Field(
        None,
        min_length=2,
        max_length=255,
        description="New skill name",
    )
    content: str | None = Field(
        None,
        min_length=1,
        max_length=50000,
        description="New skill content (triggers versioning)",
    )
    tags: list[str] | None = Field(
        None,
        max_items=20,
        description="New tags (replaces existing)",
    )
    access_level: AccessLevel | None = Field(
        None,
        description="New access level",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "python-testing-advanced",
                "content": "# Advanced Python Testing\n\n## Core Instructions\n...",
                "tags": ["python", "testing", "advanced"],
                "access_level": "team",
            }
        }


class ShareSkillRequest(BaseModel):
    """Request model for sharing/unsharing a skill."""

    agent_ids_to_add: list[str] | None = Field(
        None,
        max_items=100,
        description="Agent IDs to grant access",
    )
    agent_ids_to_remove: list[str] | None = Field(
        None,
        max_items=100,
        description="Agent IDs to revoke access",
    )

    @field_validator("agent_ids_to_add", "agent_ids_to_remove")
    @classmethod
    def validate_agent_ids(cls, v: list[str] | None) -> list[str] | None:
        """Validate agent IDs format."""
        if v is None:
            return v
        if not v:  # Empty list
            raise ValueError("Agent IDs list cannot be empty")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "agent_ids_to_add": ["agent-123", "agent-456"],
                "agent_ids_to_remove": ["agent-789"],
            }
        }


# ============================================================================
# Response Models
# ============================================================================


class SkillListResponse(BaseModel):
    """Response model for list_skills endpoint."""

    skills: list[SkillDTO]
    total: int = Field(
        description="Total number of accessible skills",
    )
    limit: int
    offset: int

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "skills": [
                    {
                        "id": "123e4567-e89b-12d3-a456-426614174000",
                        "name": "python-testing",
                        "namespace": "default",
                        "created_by": "agent-123",
                        "display_name": None,
                        "description": None,
                        "persona": "artemis-optimizer",
                        "tags": ["python", "testing"],
                        "access_level": "private",
                        "version": 1,
                        "version_count": 1,
                        "core_instructions": None,
                        "content": None,
                        "content_hash": None,
                        "created_at": "2025-01-01T12:00:00",
                        "updated_at": "2025-01-01T12:00:00",
                        "is_deleted": False,
                    }
                ],
                "total": 1,
                "limit": 100,
                "offset": 0,
            }
        }


class SkillResponse(BaseModel):
    """Response model for single skill endpoints."""

    skill: SkillDTO

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "skill": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "name": "python-testing",
                    "namespace": "default",
                    "created_by": "agent-123",
                    "display_name": None,
                    "description": None,
                    "persona": "artemis-optimizer",
                    "tags": ["python", "testing"],
                    "access_level": "private",
                    "version": 1,
                    "version_count": 1,
                    "core_instructions": "# Core Testing Practices...",
                    "content": None,
                    "content_hash": "abc123",
                    "created_at": "2025-01-01T12:00:00",
                    "updated_at": "2025-01-01T12:00:00",
                    "is_deleted": False,
                }
            }
        }


class SkillDeleteResponse(BaseModel):
    """Response model for delete endpoint."""

    success: bool = True
    skill_id: str
    message: str = "Skill deleted successfully"

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "skill_id": "123e4567-e89b-12d3-a456-426614174000",
                "message": "Skill deleted successfully",
            }
        }


class SkillShareResponse(BaseModel):
    """Response model for share endpoint."""

    success: bool = True
    skill_id: str
    shared_with: list[str]
    message: str = "Skill sharing updated successfully"

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "skill_id": "123e4567-e89b-12d3-a456-426614174000",
                "shared_with": ["agent-123", "agent-456"],
                "message": "Skill sharing updated successfully",
            }
        }


class SkillActivateResponse(BaseModel):
    """Response model for activate/deactivate endpoints."""

    success: bool = True
    skill_id: str
    is_active: bool
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "skill_id": "123e4567-e89b-12d3-a456-426614174000",
                "is_active": True,
                "message": "Skill activated successfully",
            }
        }


# ============================================================================
# Dependency Injection
# ============================================================================


async def get_skill_service(
    db: Annotated[AsyncSession, Depends(get_db_session)],
) -> SkillService:
    """Dependency: Get SkillService instance

    Args:
        db: Database session (injected)

    Returns:
        SkillService instance with shared session
    """
    return SkillService(db)


# ============================================================================
# Endpoints - CRUD Operations
# ============================================================================


@router.post(
    "",
    response_model=SkillResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new skill",
    description=(
        "Create a new skill with Progressive Disclosure structure. "
        "Requires authentication."
    ),
    dependencies=[Depends(check_rate_limit_skill_create)],
)
async def create_skill(
    request: CreateSkillRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
) -> SkillResponse:
    """Create a new skill.

    **Progressive Disclosure Structure**:
    - Layer 1: Metadata (JSON frontmatter)
    - Layer 2: Core Instructions (## Core Instructions section)
    - Layer 3: Full content (examples, references, etc.)

    **Access Control**:
    - P0-1 pattern: Namespace verified from database
    - Agent can only create skills in their own namespace
    - created_by set to current_user.agent_id

    **Versioning**:
    - New skill starts at version 1
    - Version auto-incremented on content updates

    **Rate Limiting**: 20 creations per hour

    Args:
        request: CreateSkillRequest with skill data
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance

    Returns:
        SkillResponse with created SkillDTO (detail_level=2)

    Raises:
        400: Validation error (invalid name, content, tags, etc.)
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Parse access_level
        try:
            access_level = AccessLevel(request.access_level)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid access_level: {request.access_level}",
            ) from e

        # Create skill via service
        skill_dto = await skill_service.create_skill(
            name=request.name,
            namespace=verified_namespace,
            content=request.content,
            created_by=current_user.agent_id,
            persona=request.persona,
            tags=request.tags,
            access_level=access_level,
        )

        return SkillResponse(skill=skill_dto)

    except HTTPException:
        # Re-raise HTTPException as-is (404, 400, etc.)
        raise
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "",
    response_model=SkillListResponse,
    summary="List accessible skills",
    description="List skills with filtering, pagination, and Progressive Disclosure support.",
    dependencies=[Depends(check_rate_limit_skill_list)],
)
async def list_skills(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
    tags: Annotated[list[str] | None, Query(description="Filter by tags (AND logic)")] = None,
    access_level: Annotated[str | None, Query(description="Filter by access level")] = None,
    detail_level: Annotated[
        int,
        Query(
            ge=1,
            le=3,
            description="Progressive Disclosure level (1=metadata, 2=+core, 3=+full)",
        ),
    ] = 2,
    limit: Annotated[int, Query(ge=1, le=100, description="Max results")] = 50,
    offset: Annotated[int, Query(ge=0, description="Pagination offset")] = 0,
) -> SkillListResponse:
    """List accessible skills with filtering and pagination.

    **Progressive Disclosure**:
    - detail_level=1: Metadata only (name, persona, tags, created_at)
    - detail_level=2: + Core instructions (~2000 tokens) [DEFAULT]
    - detail_level=3: + Full content (~10000 tokens)

    **Access Control**:
    - Returns only skills accessible to current user
    - PRIVATE: Owner only
    - TEAM: Same namespace agents
    - SHARED: Explicitly shared agents
    - PUBLIC/SYSTEM: All agents

    **Filtering**:
    - tags: AND logic (skill must have ALL specified tags)
    - access_level: Exact match filter

    **Pagination**:
    - limit: 1-100 (default 50)
    - offset: Starting position (default 0)
    - Order: updated_at DESC (newest first)

    **Rate Limiting**: 100 list operations per hour

    Args:
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance
        tags: Optional tag filters
        access_level: Optional access level filter
        detail_level: Progressive Disclosure level (1-3)
        limit: Max results
        offset: Pagination offset

    Returns:
        SkillListResponse with list of SkillDTO

    Raises:
        400: Invalid parameters (detail_level, limit out of range)
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Parse access_level (if provided)
        access_level_enum = None
        if access_level:
            try:
                access_level_enum = AccessLevel(access_level)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid access_level: {access_level}",
                ) from e

        # List skills via service
        skills = await skill_service.list_skills(
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
            tags=tags,
            access_level=access_level_enum,
            detail_level=detail_level,
            limit=limit,
            offset=offset,
        )

        return SkillListResponse(
            skills=skills,
            total=len(skills),  # TODO: Implement total count query
            limit=limit,
            offset=offset,
        )

    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.get(
    "/{skill_id}",
    response_model=SkillResponse,
    summary="Get skill by ID",
    description="Get a single skill with Progressive Disclosure support.",
    dependencies=[Depends(check_rate_limit_skill_get)],
)
async def get_skill(
    skill_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
    detail_level: Annotated[
        int,
        Query(ge=1, le=3, description="Progressive Disclosure level"),
    ] = 2,
) -> SkillResponse:
    """Get a single skill by ID.

    **Progressive Disclosure**:
    - detail_level=1: Metadata only
    - detail_level=2: + Core instructions [DEFAULT]
    - detail_level=3: + Full content

    **Access Control**:
    - P0-1 pattern enforced
    - Returns 404 for both "not found" and "access denied" (no information leak)

    **Rate Limiting**: 200 get operations per hour

    Args:
        skill_id: Skill UUID
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance
        detail_level: Progressive Disclosure level

    Returns:
        SkillResponse with SkillDTO

    Raises:
        404: Skill not found or access denied
        400: Invalid detail_level
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Get skill via service
        skill_dto = await skill_service.get_skill(
            skill_id=skill_id,
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
            detail_level=detail_level,
        )

        return SkillResponse(skill=skill_dto)

    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Skill not found",  # No information leak
        ) from e
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.put(
    "/{skill_id}",
    response_model=SkillResponse,
    summary="Update skill",
    description="Update skill metadata or content (content updates trigger versioning).",
    dependencies=[Depends(check_rate_limit_skill_update)],
)
async def update_skill(
    skill_id: UUID,
    request: UpdateSkillRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
) -> SkillResponse:
    """Update a skill (owner only).

    **Versioning Logic**:
    - Content update → New version created (v1 → v2 → v3...)
    - Metadata-only update → No version increment

    **Partial Updates**:
    - Only provided fields are updated
    - Omitted fields remain unchanged
    - NULL values not supported (use empty string/list if needed)

    **Access Control**:
    - Owner-only operation
    - P0-1 pattern enforced
    - Returns 404 for access denied (no information leak)

    **Rate Limiting**: 30 updates per hour

    Args:
        skill_id: Skill UUID to update
        request: UpdateSkillRequest with optional fields
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance

    Returns:
        SkillResponse with updated SkillDTO

    Raises:
        404: Skill not found or access denied
        400: Validation error
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Parse access_level (if provided)
        access_level_enum = None
        if request.access_level:
            try:
                access_level_enum = AccessLevel(request.access_level)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid access_level: {request.access_level}",
                ) from e

        # Update skill via service
        skill_dto = await skill_service.update_skill(
            skill_id=skill_id,
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
            name=request.name,
            content=request.content,
            tags=request.tags,
            access_level=access_level_enum,
        )

        return SkillResponse(skill=skill_dto)

    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found") from e
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.delete(
    "/{skill_id}",
    response_model=SkillDeleteResponse,
    summary="Delete skill",
    description="Soft delete a skill (owner only). Cannot delete activated skills.",
    dependencies=[Depends(check_rate_limit_skill_delete)],
)
async def delete_skill(
    skill_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
) -> SkillDeleteResponse:
    """Delete a skill (soft delete, owner only).

    **Soft Delete**:
    - Sets is_deleted=True
    - Preserves data for audit/recovery
    - Skill becomes invisible to list/get operations

    **Business Rules**:
    - Owner-only operation
    - Cannot delete activated skills (must deactivate first)
    - Idempotent: Deleting already-deleted skill returns 404

    **Access Control**:
    - P0-1 pattern enforced
    - Returns 404 for access denied (no information leak)

    **Rate Limiting**: 10 deletions per hour

    Args:
        skill_id: Skill UUID to delete
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance

    Returns:
        SkillDeleteResponse with success confirmation

    Raises:
        404: Skill not found or access denied
        400: Skill is activated (cannot delete)
        401: Authentication required
        429: Rate limit exceeded
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Delete skill via service
        await skill_service.delete_skill(
            skill_id=skill_id,
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
        )

        return SkillDeleteResponse(
            success=True,
            skill_id=str(skill_id),
            message="Skill deleted successfully",
        )

    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found") from e
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


# ============================================================================
# Endpoints - Advanced Operations
# ============================================================================


@router.post(
    "/{skill_id}/share",
    response_model=SkillShareResponse,
    summary="Share or unshare skill with agents",
    description="Add or remove agents from skill sharing list (SHARED access level only).",
    dependencies=[Depends(check_rate_limit_skill_share)],
)
async def share_skill(
    skill_id: UUID,
    request: ShareSkillRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
) -> SkillShareResponse:
    """Share or unshare a skill with other agents.

    **Access Control**:
    - Only works for SHARED access level skills
    - Owner-only operation
    - Agents must be in same namespace
    - P0-1 pattern enforced

    **Business Rules**:
    - Idempotent: Adding existing agent has no effect
    - Idempotent: Removing non-shared agent has no effect
    - All agent_ids validated before operation
    - Empty lists in request are allowed (no-op)

    **SHARED Access Enablement**:
    - SHARED access level without sharing list = 0 agents can access
    - This endpoint populates SkillSharedAgent table
    - Only agents in sharing list can access SHARED skills

    **Rate Limiting**: 30 share operations per hour

    Args:
        skill_id: Skill UUID to share
        request: ShareSkillRequest with agent IDs to add/remove
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance

    Returns:
        SkillShareResponse with updated sharing list

    Raises:
        404: Skill not found or access denied
        400: Invalid agent_ids, wrong access level, or validation error
        401: Authentication required
        429: Rate limit exceeded

    Example:
        ```json
        {
          "agent_ids_to_add": ["agent-123", "agent-456"],
          "agent_ids_to_remove": ["agent-789"]
        }
        ```
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Share skill via service
        _ = await skill_service.share_skill(
            skill_id=skill_id,
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
            agent_ids_to_add=request.agent_ids_to_add,
            agent_ids_to_remove=request.agent_ids_to_remove,
        )

        # Extract shared agent IDs from DTO (if available)
        # Note: SkillDTO doesn't expose shared_agents directly, so we return empty list
        # TODO: Consider adding shared_agents to SkillDTO for this response
        shared_with: list[str] = []

        return SkillShareResponse(
            success=True,
            skill_id=str(skill_id),
            shared_with=shared_with,
            message="Skill sharing updated successfully",
        )

    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found") from e
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/{skill_id}/activate",
    response_model=SkillActivateResponse,
    summary="Activate skill for MCP integration",
    description="Activate a skill to make it available for MCP tool registration.",
    dependencies=[Depends(check_rate_limit_skill_activate)],
)
async def activate_skill(
    skill_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
) -> SkillActivateResponse:
    """Activate a skill for MCP integration.

    **Activation**:
    - Marks skill as active for MCP tool registration
    - Creates SkillActivation record
    - Only one skill active per namespace (enforced)
    - Accessible skills can be activated

    **One-Active-Per-Namespace Rule**:
    - Attempting to activate when another skill is active → ValidationError
    - Must deactivate current active skill first
    - Prevents MCP tool conflicts

    **Access Control**:
    - Accessible skills can be activated (PRIVATE/TEAM/SHARED/PUBLIC/SYSTEM)
    - P0-1 pattern enforced
    - Not limited to owner

    **Rate Limiting**: 20 activations per hour

    Args:
        skill_id: Skill UUID to activate
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance

    Returns:
        SkillActivateResponse with activation confirmation

    Raises:
        404: Skill not found or access denied
        400: Another skill already active in namespace
        401: Authentication required
        429: Rate limit exceeded

    Example Response:
        ```json
        {
          "success": true,
          "skill_id": "123e4567-e89b-12d3-a456-426614174000",
          "is_active": true,
          "message": "Skill activated successfully"
        }
        ```
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Activate skill via service
        await skill_service.activate_skill(
            skill_id=skill_id,
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
        )

        return SkillActivateResponse(
            success=True,
            skill_id=str(skill_id),
            is_active=True,
            message="Skill activated successfully",
        )

    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found") from e
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


@router.post(
    "/{skill_id}/deactivate",
    response_model=SkillActivateResponse,
    summary="Deactivate skill",
    description="Deactivate a skill to remove it from MCP tool registration.",
    dependencies=[Depends(check_rate_limit_skill_activate)],
)
async def deactivate_skill(
    skill_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
    skill_service: Annotated[SkillService, Depends(get_skill_service)],
) -> SkillActivateResponse:
    """Deactivate a skill.

    **Deactivation**:
    - Marks skill as inactive
    - Updates SkillActivation record (is_active=False)
    - Tracks deactivation duration
    - Idempotent operation (deactivating inactive skill succeeds)

    **One-Active-Per-Namespace Rule**:
    - Deactivation frees up the namespace for another skill activation
    - Safe to deactivate and activate different skill

    **Access Control**:
    - Accessible skills can be deactivated
    - P0-1 pattern enforced
    - Not limited to owner

    **Rate Limiting**: 20 deactivations per hour (shared with activate)

    Args:
        skill_id: Skill UUID to deactivate
        current_user: Authenticated user
        db: Database session
        skill_service: SkillService instance

    Returns:
        SkillActivateResponse with deactivation confirmation

    Raises:
        404: Skill not found or access denied
        401: Authentication required
        429: Rate limit exceeded

    Example Response:
        ```json
        {
          "success": true,
          "skill_id": "123e4567-e89b-12d3-a456-426614174000",
          "is_active": false,
          "message": "Skill deactivated successfully"
        }
        ```
    """
    try:
        # Fetch agent from DB (P0-1 pattern)
        agent_stmt = select(Agent).where(Agent.agent_id == current_user.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

        verified_namespace = agent.namespace

        # Deactivate skill via service
        await skill_service.deactivate_skill(
            skill_id=skill_id,
            agent_id=current_user.agent_id,
            namespace=verified_namespace,
        )

        return SkillActivateResponse(
            success=True,
            skill_id=str(skill_id),
            is_active=False,
            message="Skill deactivated successfully",
        )

    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Skill not found") from e
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
