"""Memory Management FastAPI Router (Phase 1 - v2.4.0).

This module provides HTTP endpoints for memory management operations including
namespace cleanup, expired memory pruning, and TTL updates.

Endpoints:
- POST /api/v1/memory/cleanup-namespace - Delete old/unimportant memories
- POST /api/v1/memory/prune-expired - Remove expired memories
- POST /api/v1/memory/set-ttl - Update memory TTL

Security:
- V-NS-1: Namespace authorization (verified from database)
- V-PRUNE-1: Cross-namespace protection
- V-PRUNE-2: Parameter validation
- V-PRUNE-3: Rate limiting (5-30 calls/min)
- P0-1: Ownership verification (set-ttl only)

Design Principles:
1. Thin controllers - delegate to MemoryService
2. Security-first - namespace verification from DB
3. Pydantic validation - request/response models
4. Async-first - non-blocking I/O
5. Rate limiting - prevent abuse

Performance:
- <200ms P95 per operation (target)
- Rate limited: 5-30 calls/min depending on operation
"""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import (
    check_rate_limit_memory_cleanup,
    check_rate_limit_memory_prune,
    check_rate_limit_memory_ttl,
    get_current_user,
    get_db_session,
)
from src.core.exceptions import AuthorizationError, DatabaseError, ValidationError
from src.models.user import User
from src.services.memory_service import HybridMemoryService

router = APIRouter(prefix="/api/v1/memory", tags=["Memory Management"])


# ============================================================================
# Request/Response Models
# ============================================================================


class CleanupNamespaceRequest(BaseModel):
    """Request model for cleanup-namespace endpoint"""

    namespace: str = Field(
        ...,
        description="Target namespace to cleanup (must match agent's namespace)",
        examples=["default"],
    )
    days: int = Field(
        90,
        description="Delete memories older than this many days (1-3650)",
        ge=1,
        le=3650,
        examples=[90],
    )
    min_importance: float = Field(
        0.3,
        description="Delete memories below this importance score (0.0-1.0)",
        ge=0.0,
        le=1.0,
        examples=[0.3],
    )
    dry_run: bool = Field(
        False,
        description="If true, only count without deleting",
        examples=[False],
    )
    limit: int = Field(
        100_000,
        description="Maximum deletions per call (DoS prevention)",
        ge=1,
        le=100_000,
        examples=[100_000],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "namespace": "default",
                "days": 90,
                "min_importance": 0.3,
                "dry_run": False,
                "limit": 100_000,
            }
        }
    )


class CleanupNamespaceResponse(BaseModel):
    """Response model for cleanup-namespace endpoint"""

    deleted_count: int = Field(
        ...,
        description="Number of memories deleted (or would be deleted if dry_run)",
        examples=[42],
    )
    dry_run: bool = Field(
        ...,
        description="Whether this was a dry run",
        examples=[False],
    )
    namespace: str = Field(
        ...,
        description="Target namespace that was cleaned",
        examples=["default"],
    )
    criteria: dict[str, Any] = Field(
        ...,
        description="Criteria used for cleanup",
        examples=[{"days": 90, "min_importance": 0.3, "limit": 100_000}],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "deleted_count": 42,
                "dry_run": False,
                "namespace": "default",
                "criteria": {
                    "days": 90,
                    "min_importance": 0.3,
                    "limit": 100_000,
                },
            }
        }
    )


class PruneExpiredRequest(BaseModel):
    """Request model for prune-expired endpoint"""

    namespace: str = Field(
        ...,
        description="Target namespace to prune (must match agent's namespace)",
        examples=["default"],
    )
    limit: int = Field(
        1000,
        description="Maximum deletions per call (DoS prevention, max: 100k)",
        ge=1,
        le=100_000,
        examples=[1000],
    )
    dry_run: bool = Field(
        False,
        description="If true, only count without deleting",
        examples=[False],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "namespace": "default",
                "limit": 1000,
                "dry_run": False,
            }
        }
    )


class PruneExpiredResponse(BaseModel):
    """Response model for prune-expired endpoint"""

    deleted_count: int = Field(
        ...,
        description="Number of memories deleted",
        examples=[15],
    )
    expired_count: int = Field(
        ...,
        description="Total expired memories found (may exceed deleted_count if limited)",
        examples=[15],
    )
    dry_run: bool = Field(
        ...,
        description="Whether this was a dry run",
        examples=[False],
    )
    namespace: str = Field(
        ...,
        description="Target namespace that was pruned",
        examples=["default"],
    )
    deleted_ids: list[str] | None = Field(
        None,
        description="List of deleted memory UUIDs (only if not dry_run)",
        examples=[["123e4567-e89b-12d3-a456-426614174000"]],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "deleted_count": 15,
                "expired_count": 15,
                "dry_run": False,
                "namespace": "default",
                "deleted_ids": ["123e4567-e89b-12d3-a456-426614174000"],
            }
        }
    )


class SetMemoryTTLRequest(BaseModel):
    """Request model for set-ttl endpoint"""

    memory_id: UUID = Field(
        ...,
        description="Memory UUID to update",
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )
    ttl_days: int | None = Field(
        ...,
        description="New TTL in days (1-3650) or null for permanent",
        ge=1,
        le=3650,
        examples=[30],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "memory_id": "123e4567-e89b-12d3-a456-426614174000",
                "ttl_days": 30,
            }
        }
    )


class SetMemoryTTLResponse(BaseModel):
    """Response model for set-ttl endpoint"""

    success: bool = Field(
        ...,
        description="Whether TTL was successfully updated",
        examples=[True],
    )
    memory_id: str = Field(
        ...,
        description="Memory UUID that was updated",
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )
    expires_at: str | None = Field(
        ...,
        description="New expiration timestamp (ISO format) or null if permanent",
        examples=["2025-12-24T12:00:00"],
    )
    ttl_days: int | None = Field(
        ...,
        description="TTL value that was set (days) or null",
        examples=[30],
    )
    previous_ttl_days: int | None = Field(
        ...,
        description="Previous TTL value (days) or null",
        examples=[90],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "memory_id": "123e4567-e89b-12d3-a456-426614174000",
                "expires_at": "2025-12-24T12:00:00",
                "ttl_days": 30,
                "previous_ttl_days": 90,
            }
        }
    )


# ============================================================================
# Dependency Injection
# ============================================================================


async def get_memory_service(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> HybridMemoryService:
    """Dependency: Get HybridMemoryService instance

    Args:
        session: Database session (injected)

    Returns:
        HybridMemoryService instance with shared session
    """
    return HybridMemoryService(session)


# ============================================================================
# POST /api/v1/memory/cleanup-namespace
# ============================================================================


@router.post("/cleanup-namespace", response_model=CleanupNamespaceResponse)
async def cleanup_namespace_endpoint(
    request_body: CleanupNamespaceRequest,
    request: Request,  # noqa: ARG001 - Required by FastAPI for rate limiting
    current_user: Annotated[User, Depends(get_current_user)],
    memory_service: Annotated[HybridMemoryService, Depends(get_memory_service)],
    _rate_limit: Annotated[None, Depends(check_rate_limit_memory_cleanup)],
) -> CleanupNamespaceResponse:
    """Delete old and unimportant memories from a namespace

    This endpoint removes memories that are both old (>N days) AND have low
    importance scores. This is an administrative operation for namespace cleanup.

    Security:
    - Requires JWT/API Key authentication
    - V-NS-1: Namespace authorization (agent.namespace == target namespace)
    - V-PRUNE-2: Parameter validation (days: 1-3650, importance: 0.0-1.0)
    - V-PRUNE-3: Rate limiting (5 calls/min production, 10 calls/min development)
    - Audit logging (before + after deletion)

    Performance:
    - Target: <200ms P95
    - Rate limited: 5 calls/min (production)
    - Max deletions: 100k per call

    Args:
        request_body: Cleanup criteria (namespace, days, importance, etc.)
        request: FastAPI request object (for rate limiting)
        current_user: Authenticated user (from JWT/API Key)
        memory_service: Injected HybridMemoryService
        _rate_limit: Rate limit check (injected dependency)

    Returns:
        CleanupNamespaceResponse with deletion results

    Raises:
        HTTPException 400: Validation error (invalid parameters)
        HTTPException 403: Authorization error (namespace mismatch)
        HTTPException 429: Rate limit exceeded
        HTTPException 500: Internal server error

    Example:
        ```bash
        curl -X POST http://localhost:8000/api/v1/memory/cleanup-namespace \\
          -H "Authorization: Bearer $TOKEN" \\
          -H "Content-Type: application/json" \\
          -d '{
            "namespace": "default",
            "days": 90,
            "min_importance": 0.3,
            "dry_run": false
          }'
        ```
    """
    try:
        # Execute cleanup via MemoryService
        # Security checks (V-NS-1, V-PRUNE-2) happen in service layer
        result = await memory_service.cleanup_namespace(
            namespace=request_body.namespace,
            agent_id=current_user.agent_id,
            days=request_body.days,
            min_importance=request_body.min_importance,
            dry_run=request_body.dry_run,
            limit=request_body.limit,
        )

        # Construct response
        return CleanupNamespaceResponse(
            deleted_count=result["deleted_count"],
            dry_run=result["dry_run"],
            namespace=result["namespace"],
            criteria=result["criteria"],
        )

    except ValidationError as e:
        # 400 Bad Request: Invalid parameters
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    except AuthorizationError as e:
        # 403 Forbidden: Namespace mismatch
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        ) from e

    except DatabaseError as e:
        # 500 Internal Server Error: Database operation failed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed",
        ) from e

    except Exception as e:
        # 500 Internal Server Error: Unexpected error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


# ============================================================================
# POST /api/v1/memory/prune-expired
# ============================================================================


@router.post("/prune-expired", response_model=PruneExpiredResponse)
async def prune_expired_endpoint(
    request_body: PruneExpiredRequest,
    request: Request,  # noqa: ARG001 - Required by FastAPI for rate limiting
    current_user: Annotated[User, Depends(get_current_user)],
    memory_service: Annotated[HybridMemoryService, Depends(get_memory_service)],
    _rate_limit: Annotated[None, Depends(check_rate_limit_memory_prune)],
) -> PruneExpiredResponse:
    """Remove expired memories from a namespace

    This endpoint removes memories that have passed their expiration time (TTL).
    This is a maintenance operation for namespace cleanup.

    Security:
    - Requires JWT/API Key authentication
    - V-PRUNE-1: Cross-namespace protection (namespace parameter mandatory)
    - V-NS-1: Namespace authorization (agent.namespace == target namespace)
    - V-PRUNE-3: Rate limiting (5 calls/min production, 10 calls/min development)
    - Audit logging (expired memory IDs logged)

    Performance:
    - Target: <200ms P95
    - Rate limited: 5 calls/min (production)
    - Max deletions: 100k per call

    Args:
        request_body: Prune criteria (namespace, limit, dry_run)
        request: FastAPI request object (for rate limiting)
        current_user: Authenticated user (from JWT/API Key)
        memory_service: Injected HybridMemoryService
        _rate_limit: Rate limit check (injected dependency)

    Returns:
        PruneExpiredResponse with deletion results

    Raises:
        HTTPException 400: Validation error (invalid parameters)
        HTTPException 403: Authorization error (namespace mismatch)
        HTTPException 429: Rate limit exceeded
        HTTPException 500: Internal server error

    Example:
        ```bash
        curl -X POST http://localhost:8000/api/v1/memory/prune-expired \\
          -H "Authorization: Bearer $TOKEN" \\
          -H "Content-Type: application/json" \\
          -d '{
            "namespace": "default",
            "limit": 1000,
            "dry_run": false
          }'
        ```
    """
    try:
        # Execute prune via MemoryService
        # Security checks (V-PRUNE-1, V-NS-1) happen in service layer
        result = await memory_service.prune_expired_memories(
            namespace=request_body.namespace,
            agent_id=current_user.agent_id,
            limit=request_body.limit,
            dry_run=request_body.dry_run,
        )

        # Construct response
        return PruneExpiredResponse(
            deleted_count=result["deleted_count"],
            expired_count=result["expired_count"],
            dry_run=result["dry_run"],
            namespace=result["namespace"],
            deleted_ids=result.get("deleted_ids"),
        )

    except ValidationError as e:
        # 400 Bad Request: Invalid parameters
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    except AuthorizationError as e:
        # 403 Forbidden: Namespace mismatch
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        ) from e

    except DatabaseError as e:
        # 500 Internal Server Error: Database operation failed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed",
        ) from e

    except Exception as e:
        # 500 Internal Server Error: Unexpected error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e


# ============================================================================
# POST /api/v1/memory/set-ttl
# ============================================================================


@router.post("/set-ttl", response_model=SetMemoryTTLResponse)
async def set_memory_ttl_endpoint(
    request_body: SetMemoryTTLRequest,
    request: Request,  # noqa: ARG001 - Required by FastAPI for rate limiting
    current_user: Annotated[User, Depends(get_current_user)],
    memory_service: Annotated[HybridMemoryService, Depends(get_memory_service)],
    _rate_limit: Annotated[None, Depends(check_rate_limit_memory_ttl)],
) -> SetMemoryTTLResponse:
    """Update TTL (Time To Live) for an existing memory

    This endpoint allows the memory owner to change the expiration time.
    Set ttl_days to null for permanent (no expiration).

    Security:
    - Requires JWT/API Key authentication
    - P0-1: Ownership verification (memory.agent_id == requesting agent_id)
    - TTL validation (1-3650 days or null for permanent)
    - V-PRUNE-3: Rate limiting (30 calls/min production, 60 calls/min development)
    - Audit logging (TTL changes logged)

    Performance:
    - Target: <200ms P95
    - Rate limited: 30 calls/min (production)

    Args:
        request_body: TTL update request (memory_id, ttl_days)
        request: FastAPI request object (for rate limiting)
        current_user: Authenticated user (from JWT/API Key)
        memory_service: Injected HybridMemoryService
        _rate_limit: Rate limit check (injected dependency)

    Returns:
        SetMemoryTTLResponse with update results

    Raises:
        HTTPException 400: Validation error (invalid TTL)
        HTTPException 403: Authorization error (not memory owner)
        HTTPException 404: Memory not found
        HTTPException 429: Rate limit exceeded
        HTTPException 500: Internal server error

    Example:
        ```bash
        curl -X POST http://localhost:8000/api/v1/memory/set-ttl \\
          -H "Authorization: Bearer $TOKEN" \\
          -H "Content-Type: application/json" \\
          -d '{
            "memory_id": "123e4567-e89b-12d3-a456-426614174000",
            "ttl_days": 30
          }'
        ```
    """
    try:
        # Execute TTL update via MemoryService
        # Security checks (P0-1 ownership) happen in service layer
        result = await memory_service.set_memory_ttl(
            memory_id=request_body.memory_id,
            agent_id=current_user.agent_id,
            ttl_days=request_body.ttl_days,
        )

        # Construct response
        return SetMemoryTTLResponse(
            success=result["success"],
            memory_id=result["memory_id"],
            expires_at=result["expires_at"],
            ttl_days=result["ttl_days"],
            previous_ttl_days=result["previous_ttl_days"],
        )

    except ValidationError as e:
        # 400 Bad Request: Invalid TTL or memory not found
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            ) from e
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    except AuthorizationError as e:
        # 403 Forbidden: Not memory owner
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        ) from e

    except DatabaseError as e:
        # 500 Internal Server Error: Database operation failed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed",
        ) from e

    except Exception as e:
        # 500 Internal Server Error: Unexpected error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        ) from e
