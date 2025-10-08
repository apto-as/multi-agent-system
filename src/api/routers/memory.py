"""
Memory management endpoints for TMWS.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db_session_dependency
from ...models.memory import Memory
from ...models.user import APIKey, APIKeyScope, User
from ...security.validators import sanitize_input
from ...services.vectorization_service import VectorizationService
from ..dependencies import require_scope

logger = logging.getLogger(__name__)
router = APIRouter()


# Request/Response Models

# Base model with common string sanitization
class SanitizedStringModel(BaseModel):
    """Base model with automatic string sanitization for common fields."""

    @field_validator("content", "persona", "category", "query", mode="before", check_fields=False)
    @classmethod
    def sanitize_strings(cls, v):
        """Sanitize string fields to prevent XSS and injection attacks."""
        if isinstance(v, str):
            return sanitize_input(v)
        return v


class MemoryCreate(SanitizedStringModel):
    """Memory creation request."""

    content: str = Field(..., min_length=1, max_length=10000)
    persona: str | None = Field(None, max_length=50)
    category: str | None = Field(None, max_length=100)
    importance: float = Field(0.5, ge=0.0, le=1.0)
    is_shared: bool = Field(False)
    is_learned: bool = Field(False)
    metadata: dict[str, Any] | None = Field(default_factory=dict)


class MemoryUpdate(SanitizedStringModel):
    """Memory update request."""

    content: str | None = Field(None, min_length=1, max_length=10000)
    persona: str | None = Field(None, max_length=50)
    category: str | None = Field(None, max_length=100)
    importance: float | None = Field(None, ge=0.0, le=1.0)
    is_shared: bool | None = None
    is_learned: bool | None = None
    metadata: dict[str, Any] | None = None


class MemorySearch(SanitizedStringModel):
    """Memory search request."""

    query: str | None = Field(None, max_length=1000)
    persona: str | None = Field(None, max_length=50)
    category: str | None = Field(None, max_length=100)
    is_shared: bool | None = None
    is_learned: bool | None = None
    min_importance: float | None = Field(None, ge=0.0, le=1.0)
    max_importance: float | None = Field(None, ge=0.0, le=1.0)
    limit: int = Field(10, ge=1, le=100)
    offset: int = Field(0, ge=0)
    semantic_search: bool = Field(False, description="Enable semantic search")
    min_similarity: float = Field(
        0.7, ge=0.0, le=1.0, description="Minimum similarity for semantic search"
    )


class MemoryResponse(BaseModel):
    """Memory response model."""

    id: str
    content: str
    persona: str | None
    category: str | None
    importance: float
    is_shared: bool
    is_learned: bool
    metadata: dict[str, Any]
    access_count: int
    created_at: datetime
    updated_at: datetime
    accessed_at: datetime

    model_config = {"from_attributes": True}


class SemanticMemoryResponse(MemoryResponse):
    """Memory response model for semantic search."""

    similarity: float


class MemoryListResponse(BaseModel):
    """Memory list response."""

    memories: list[MemoryResponse | SemanticMemoryResponse]
    total: int
    offset: int
    limit: int
    has_more: bool


# Endpoints
@router.post("/", response_model=MemoryResponse, status_code=status.HTTP_201_CREATED)
async def create_memory(
    memory_data: MemoryCreate,
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.WRITE)
    ),
) -> MemoryResponse:
    """
    Create a new memory.

    Requires: WRITE scope or higher

    Args:
        memory_data: Memory creation data
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        Created memory
    """
    user, api_key = user_and_key
    try:
        # Vectorize content
        vectorization_service = VectorizationService()
        embedding = await vectorization_service.vectorize_text(memory_data.content)

        # Build metadata including all extra fields
        metadata = memory_data.metadata or {}
        if memory_data.persona:
            metadata["persona"] = memory_data.persona
        if memory_data.category:
            metadata["category"] = memory_data.category
        metadata["importance"] = memory_data.importance
        metadata["is_shared"] = memory_data.is_shared
        metadata["is_learned"] = memory_data.is_learned

        # Create memory
        memory = Memory(
            content=memory_data.content,
            embedding=embedding.tolist(),
            metadata=metadata,
        )

        db.add(memory)
        await db.commit()
        await db.refresh(memory)

        username = user.username if user else "anonymous"
        logger.info(f"Memory created: {memory.id} by user {username}")

        return MemoryResponse(
            id=str(memory.id),
            content=memory.content,
            persona=memory.metadata.get("persona") if memory.metadata else None,
            category=memory.metadata.get("category") if memory.metadata else None,
            importance=memory.metadata.get("importance", 0.5) if memory.metadata else 0.5,
            is_shared=memory.metadata.get("is_shared", False) if memory.metadata else False,
            is_learned=memory.metadata.get("is_learned", False) if memory.metadata else False,
            metadata=memory.metadata or {},
            access_count=memory.access_count,
            created_at=memory.created_at,
            updated_at=memory.updated_at,
            accessed_at=memory.accessed_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to create memory: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create memory"
        )


@router.get("/{memory_id}", response_model=MemoryResponse)
async def get_memory(
    memory_id: UUID,
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.READ)
    ),
) -> MemoryResponse:
    """
    Get a specific memory by ID.

    Requires: READ scope or higher

    Args:
        memory_id: Memory ID
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        Memory data
    """
    user, api_key = user_and_key
    try:
        memory = await db.get(Memory, memory_id)

        if not memory:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory not found")

        # Update access tracking
        memory.update_access()
        await db.commit()

        return MemoryResponse(
            id=str(memory.id),
            content=memory.content,
            persona=memory.metadata.get("persona") if memory.metadata else None,
            category=memory.metadata.get("category") if memory.metadata else None,
            importance=memory.metadata.get("importance", 0.5) if memory.metadata else 0.5,
            is_shared=memory.metadata.get("is_shared", False) if memory.metadata else False,
            is_learned=memory.metadata.get("is_learned", False) if memory.metadata else False,
            metadata=memory.metadata or {},
            access_count=memory.access_count,
            created_at=memory.created_at,
            updated_at=memory.updated_at,
            accessed_at=memory.accessed_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get memory {memory_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve memory"
        )


@router.put("/{memory_id}", response_model=MemoryResponse)
async def update_memory(
    memory_id: UUID,
    memory_data: MemoryUpdate,
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.WRITE)
    ),
) -> MemoryResponse:
    """
    Update a specific memory.

    Requires: WRITE scope or higher

    Args:
        memory_id: Memory ID
        memory_data: Memory update data
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        Updated memory
    """
    user, api_key = user_and_key
    try:
        memory = await db.get(Memory, memory_id)

        if not memory:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory not found")

        # Update fields
        update_data = memory_data.dict(exclude_unset=True)
        if "content" in update_data:
            # Vectorize content
            vectorization_service = VectorizationService()
            embedding = await vectorization_service.vectorize_text(update_data["content"])
            memory.embedding = embedding.tolist()

        for field, value in update_data.items():
            setattr(memory, field, value)

        memory.updated_at = datetime.utcnow()

        await db.commit()
        await db.refresh(memory)

        username = user.username if user else "anonymous"
        logger.info(f"Memory updated: {memory.id} by user {username}")

        return MemoryResponse(
            id=str(memory.id),
            content=memory.content,
            persona=memory.metadata.get("persona") if memory.metadata else None,
            category=memory.metadata.get("category") if memory.metadata else None,
            importance=memory.metadata.get("importance", 0.5) if memory.metadata else 0.5,
            is_shared=memory.metadata.get("is_shared", False) if memory.metadata else False,
            is_learned=memory.metadata.get("is_learned", False) if memory.metadata else False,
            metadata=memory.metadata or {},
            access_count=memory.access_count,
            created_at=memory.created_at,
            updated_at=memory.updated_at,
            accessed_at=memory.accessed_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to update memory {memory_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update memory"
        )


@router.delete("/{memory_id}")
async def delete_memory(
    memory_id: UUID,
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.ADMIN)
    ),
) -> dict[str, str]:
    """
    Delete a specific memory.

    Requires: ADMIN scope

    Args:
        memory_id: Memory ID
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        Deletion confirmation
    """
    user, api_key = user_and_key
    try:
        memory = await db.get(Memory, memory_id)

        if not memory:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory not found")

        memory_id_str = str(memory.id)
        await db.delete(memory)
        await db.commit()

        username = user.username if user else "anonymous"
        logger.info(f"Memory deleted: {memory_id_str} by user {username}")

        return {"message": f"Memory '{memory_id_str}' deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to delete memory {memory_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete memory"
        )


@router.post("/search", response_model=MemoryListResponse)
async def search_memories(
    search_data: MemorySearch,
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.READ)
    ),
) -> MemoryListResponse:
    """
    Search memories with various filters.

    Requires: READ scope or higher

    Args:
        search_data: Search criteria
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        List of matching memories
    """
    user, api_key = user_and_key
    try:
        # Build query
        query = select(Memory)
        conditions = []

        # Semantic search
        if search_data.semantic_search and search_data.query:
            vectorization_service = VectorizationService()
            query_embedding = await vectorization_service.vectorize_text(search_data.query)

            query = query.add_columns(
                Memory.embedding.l2_distance(query_embedding).label("similarity")
            )
            conditions.append(
                Memory.embedding.l2_distance(query_embedding) < (1 - search_data.min_similarity)
            )
            order_by = "similarity"
        # Text search
        elif search_data.query:
            conditions.append(
                or_(
                    Memory.key.ilike(f"%{search_data.query}%"),
                    Memory.content.ilike(f"%{search_data.query}%"),
                )
            )
            order_by = None
        else:
            order_by = None

        # Filter by persona
        if search_data.persona:
            conditions.append(Memory.persona == search_data.persona)

        # Filter by category
        if search_data.category:
            conditions.append(Memory.category == search_data.category)

        # Filter by shared status
        if search_data.is_shared is not None:
            conditions.append(Memory.is_shared == search_data.is_shared)

        # Filter by learned status
        if search_data.is_learned is not None:
            conditions.append(Memory.is_learned == search_data.is_learned)

        # Filter by importance range
        if search_data.min_importance is not None:
            conditions.append(Memory.importance >= search_data.min_importance)

        if search_data.max_importance is not None:
            conditions.append(Memory.importance <= search_data.max_importance)

        # Apply conditions
        if conditions:
            query = query.where(and_(*conditions))

        # Count total results
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply ordering, offset, and limit
        if order_by == "similarity":
            query = query.order_by("similarity")
        else:
            query = query.order_by(Memory.importance.desc(), Memory.updated_at.desc())

        query = query.offset(search_data.offset).limit(search_data.limit)

        # Execute query
        result = await db.execute(query)

        memories = []
        if search_data.semantic_search and search_data.query:
            for row in result.all():
                memory = row[0]
                similarity = row[1]
                mem_resp = SemanticMemoryResponse.from_orm(memory)
                mem_resp.similarity = 1 - similarity
                memories.append(mem_resp)
        else:
            memories = [MemoryResponse.from_orm(memory) for memory in result.scalars().all()]

        return MemoryListResponse(
            memories=memories,
            total=total,
            offset=search_data.offset,
            limit=search_data.limit,
            has_more=search_data.offset + len(memories) < total,
        )

    except Exception as e:
        logger.error(f"Failed to search memories: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to search memories"
        )


@router.get("/", response_model=MemoryListResponse)
async def list_memories(
    persona: str | None = Query(None, max_length=50),
    category: str | None = Query(None, max_length=100),
    is_shared: bool | None = Query(None),
    is_learned: bool | None = Query(None),
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.READ)
    ),
) -> MemoryListResponse:
    """
    List memories with optional filters.

    Requires: READ scope or higher

    Args:
        persona: Filter by persona
        category: Filter by category
        is_shared: Filter by shared status
        is_learned: Filter by learned status
        limit: Maximum number of results
        offset: Number of results to skip
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        List of memories
    """
    user, api_key = user_and_key
    search_data = MemorySearch(
        persona=persona,
        category=category,
        is_shared=is_shared,
        is_learned=is_learned,
        limit=limit,
        offset=offset,
    )

    return await search_memories(search_data, db, user_and_key)


@router.get("/stats/summary")
async def get_memory_stats(
    db: AsyncSession = Depends(get_db_session_dependency),
    user_and_key: tuple[User | None, APIKey | None] = Depends(
        require_scope(APIKeyScope.READ)
    ),
) -> dict[str, Any]:
    """
    Get memory statistics summary.

    Requires: READ scope or higher

    Args:
        db: Database session
        user_and_key: Current authenticated user and API key

    Returns:
        Memory statistics
    """
    user, api_key = user_and_key
    try:
        # Total memories
        total_result = await db.execute(select(func.count(Memory.id)))
        total_memories = total_result.scalar()

        # Memories by persona
        persona_stats = await db.execute(
            select(Memory.persona, func.count(Memory.id)).group_by(Memory.persona)
        )
        persona_counts = dict(persona_stats.all())

        # Memories by category
        category_stats = await db.execute(
            select(Memory.category, func.count(Memory.id)).group_by(Memory.category)
        )
        category_counts = dict(category_stats.all())

        # Shared vs private
        shared_stats = await db.execute(
            select(Memory.is_shared, func.count(Memory.id)).group_by(Memory.is_shared)
        )
        shared_counts = dict(shared_stats.all())

        # Learned memories
        learned_result = await db.execute(select(func.count(Memory.id)).where(Memory.is_learned))
        learned_memories = learned_result.scalar()

        # Average importance
        avg_importance_result = await db.execute(select(func.avg(Memory.importance)))
        avg_importance = avg_importance_result.scalar() or 0.0

        return {
            "total_memories": total_memories,
            "learned_memories": learned_memories,
            "average_importance": round(float(avg_importance), 3),
            "by_persona": persona_counts,
            "by_category": category_counts,
            "shared_distribution": {
                "shared": shared_counts.get(True, 0),
                "private": shared_counts.get(False, 0),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Failed to get memory stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get memory statistics",
        )
