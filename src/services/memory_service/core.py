"""Memory Service Core - HybridMemoryService coordinator.

This module contains the main HybridMemoryService class that coordinates
all memory operations through composition of sub-services.

Architecture:
- SQLite: Authoritative metadata storage
- ChromaDB: Vector embeddings for semantic search
- Lazy initialization: ChromaDB only initialized when needed
"""

import asyncio
import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.exceptions import ChromaOperationError
from src.models.agent import AccessLevel
from src.models.memory import Memory

from .crud_operations import MemoryCRUDOperations
from .expiration_manager import MemoryExpirationManager
from .namespace_operations import MemoryNamespaceOperations
from .search_operations import MemorySearchOperations
from .statistics import MemoryStatisticsService

if TYPE_CHECKING:
    from src.services.agent_service import AgentService
    from src.services.audit_service import AuditLogger
    from src.services.embedding_service import EmbeddingService
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


class HybridMemoryService:
    """Hybrid memory service combining SQLite (metadata) and ChromaDB (vectors).

    This service coordinates all memory operations through composition:
    - CRUD operations (create, get, update, delete, batch_create)
    - Search operations (semantic search with ChromaDB)
    - Expiration management (TTL cleanup)
    - Namespace operations (namespace-level cleanup)
    - Statistics (counts, stats, TTL management)

    Lazy Initialization:
    - ChromaDB is initialized only when first needed
    - AgentService is loaded lazily to avoid circular imports

    Security:
    - All operations enforce namespace isolation
    - Ownership verification (P0-1 pattern)
    - TTL validation (V-TTL-* patterns)
    """

    def __init__(
        self,
        session: AsyncSession,
        embedding_service: "EmbeddingService | None" = None,
        vector_service: "VectorSearchService | None" = None,
    ):
        """Initialize HybridMemoryService.

        Args:
            session: Async database session
            embedding_service: Optional embedding service (created if None)
            vector_service: Optional vector search service (created if None)
        """
        self.session = session
        self._embedding_service = embedding_service
        self._vector_service = vector_service
        self._agent_service: AgentService | None = None
        self._initialized = False
        self._init_lock = asyncio.Lock()

        # Get model info for metadata tracking
        model_info = self.embedding_service.get_model_info()
        self.embedding_model_name = model_info.get("model_name", settings.embedding_model)
        self.embedding_dimension = model_info.get("dimension", settings.vector_dimension)

        # Audit logger (lazy init)
        self.audit_logger: AuditLogger | None = None

        # Sub-services (initialized lazily after ChromaDB init)
        self._crud: MemoryCRUDOperations | None = None
        self._search: MemorySearchOperations | None = None
        self._expiration: MemoryExpirationManager | None = None
        self._namespace: MemoryNamespaceOperations | None = None
        self._statistics: MemoryStatisticsService | None = None

    @property
    def embedding_service(self) -> "EmbeddingService":
        """Get embedding service (lazy initialization)."""
        if self._embedding_service is None:
            # Import here to allow test mocking via parent package
            from src.services.memory_service import get_ollama_embedding_service

            self._embedding_service = get_ollama_embedding_service()
        return self._embedding_service

    @property
    def vector_service(self) -> "VectorSearchService | None":
        """Get vector service (may be None until initialized)."""
        return self._vector_service

    @vector_service.setter
    def vector_service(self, value: "VectorSearchService | None") -> None:
        """Set vector service (for testing)."""
        self._vector_service = value

    @property
    def agent_service(self) -> "AgentService":
        """Get agent service (lazy initialization to avoid circular imports)."""
        if self._agent_service is None:
            from src.services.agent_service import AgentService

            self._agent_service = AgentService(self.session)
        return self._agent_service

    async def _ensure_initialized(self) -> None:
        """Ensure ChromaDB is initialized (lazy initialization).

        Thread-safe with asyncio.Lock.
        """
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            try:
                # Import here to allow test mocking via parent package
                from src.services.memory_service import get_vector_search_service

                if self._vector_service is None:
                    self._vector_service = get_vector_search_service()
                    await self._vector_service.initialize()

                self._initialized = True
                logger.info("ChromaDB initialized successfully")

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                logger.error(f"Failed to initialize ChromaDB: {e}")
                raise ChromaOperationError(
                    f"ChromaDB initialization failed: {e}"
                ) from e

    async def _ensure_audit_initialized(self) -> None:
        """Ensure audit logger is initialized (lazy initialization)."""
        if self.audit_logger is not None:
            return

        try:
            from src.services.audit_service import AuditLogger

            self.audit_logger = AuditLogger(self.session)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.warning(f"Failed to initialize audit logger: {e}")
            # Continue without audit logging (graceful degradation)

    async def _sync_to_chroma(self, memory: Memory, embedding: list[float]) -> None:
        """Sync memory to ChromaDB vector storage.

        Args:
            memory: Memory object to sync
            embedding: Embedding vector
        """
        if not self._vector_service:
            return

        metadata = {
            "agent_id": memory.agent_id,
            "namespace": memory.namespace,
            "importance": memory.importance_score,
            "access_level": memory.access_level.value,
            "tags": memory.tags,
            "created_at": memory.created_at.isoformat()
            if hasattr(memory.created_at, "isoformat")
            else memory.created_at,
        }

        await self._vector_service.add_memory(
            memory_id=str(memory.id),
            embedding=embedding,
            metadata=metadata,
            document=memory.content,
        )

    def _get_agent_service(self) -> "AgentService":
        """Get agent service (helper for sub-services)."""
        return self.agent_service

    # ==================== Sub-service Initialization ====================

    def _init_crud(self) -> MemoryCRUDOperations:
        """Initialize CRUD operations sub-service."""
        if self._crud is None:
            self._crud = MemoryCRUDOperations(
                session=self.session,
                embedding_service=self.embedding_service,
                vector_service=self._vector_service,
                embedding_model_name=self.embedding_model_name,
                embedding_dimension=self.embedding_dimension,
                ensure_initialized=self._ensure_initialized,
                sync_to_chroma=self._sync_to_chroma,
                get_agent_service=self._get_agent_service,
            )
        return self._crud

    def _init_search(self) -> MemorySearchOperations:
        """Initialize search operations sub-service."""
        if self._search is None:
            self._search = MemorySearchOperations(
                session=self.session,
                embedding_service=self.embedding_service,
                vector_service=self._vector_service,
                ensure_initialized=self._ensure_initialized,
                fetch_memories_by_ids=self._init_crud().fetch_memories_by_ids,
            )
        return self._search

    def _init_expiration(self) -> MemoryExpirationManager:
        """Initialize expiration manager sub-service."""
        if self._expiration is None:
            self._expiration = MemoryExpirationManager(
                session=self.session,
                vector_service=self._vector_service,
                ensure_initialized=self._ensure_initialized,
            )
        return self._expiration

    def _init_namespace(self) -> MemoryNamespaceOperations:
        """Initialize namespace operations sub-service."""
        if self._namespace is None:
            self._namespace = MemoryNamespaceOperations(
                session=self.session,
                vector_service=self._vector_service,
                ensure_initialized=self._ensure_initialized,
                ensure_audit_initialized=self._ensure_audit_initialized,
                audit_logger=self.audit_logger,
            )
        return self._namespace

    def _init_statistics(self) -> MemoryStatisticsService:
        """Initialize statistics sub-service."""
        if self._statistics is None:
            self._statistics = MemoryStatisticsService(
                session=self.session,
                vector_service=self._vector_service,
                embedding_model_name=self.embedding_model_name,
                embedding_dimension=self.embedding_dimension,
                ensure_initialized=self._ensure_initialized,
                ensure_audit_initialized=self._ensure_audit_initialized,
                audit_logger=self.audit_logger,
            )
        return self._statistics

    # ==================== CRUD Operations ====================

    async def create_memory(
        self,
        content: str,
        agent_id: str,
        namespace: str,
        importance_score: float = 0.5,
        tags: list[str] | None = None,
        access_level: AccessLevel = AccessLevel.PRIVATE,
        shared_with_agents: list[str] | None = None,
        context: dict[str, Any] | None = None,
        ttl_days: int | None = None,
    ) -> Memory:
        """Create a new memory with embedding generation."""
        return await self._init_crud().create_memory(
            content=content,
            agent_id=agent_id,
            namespace=namespace,
            importance_score=importance_score,
            tags=tags,
            access_level=access_level,
            shared_with_agents=shared_with_agents,
            context=context,
            ttl_days=ttl_days,
        )

    async def get_memory(
        self,
        memory_id: UUID,
        caller_agent_id: str | None = None,
        track_access: bool = True,
    ) -> Memory | None:
        """Get a single memory by ID with access tracking."""
        return await self._init_crud().get_memory(
            memory_id=memory_id,
            caller_agent_id=caller_agent_id,
            track_access=track_access,
        )

    async def update_memory(
        self,
        memory_id: UUID,
        content: str | None = None,
        importance_score: float | None = None,
        tags: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Update memory with re-sync to ChromaDB."""
        return await self._init_crud().update_memory(
            memory_id=memory_id,
            content=content,
            importance_score=importance_score,
            tags=tags,
            context=context,
        )

    async def delete_memory(self, memory_id: UUID) -> bool:
        """Delete memory from both SQLite and ChromaDB."""
        return await self._init_crud().delete_memory(memory_id)

    async def batch_create_memories(
        self,
        memories_data: list[dict[str, Any]],
    ) -> list[Memory]:
        """Batch create memories with optimized ChromaDB sync."""
        return await self._init_crud().batch_create_memories(memories_data)

    # ==================== Search Operations ====================

    async def search_memories(
        self,
        query: str,
        agent_id: str | None = None,
        namespace: str | None = None,
        tags: list[str] | None = None,
        min_importance: float = 0.0,
        limit: int = 10,
        min_similarity: float = 0.7,
    ) -> list[dict[str, Any]]:
        """Semantic search with ChromaDB + SQLite."""
        return await self._init_search().search_memories(
            query=query,
            agent_id=agent_id,
            namespace=namespace,
            tags=tags,
            min_importance=min_importance,
            limit=limit,
            min_similarity=min_similarity,
        )

    # ==================== Expiration Operations ====================

    async def cleanup_old_memories(
        self,
        days: int = 90,
        min_importance: float = 0.3,
    ) -> int:
        """Cleanup old, low-importance memories."""
        return await self._init_expiration().cleanup_old_memories(
            days=days,
            min_importance=min_importance,
        )

    async def find_expired_memories(self) -> list[Memory]:
        """Find all memories that have expired."""
        return await self._init_expiration().find_expired_memories()

    async def cleanup_expired_memories(self, expired_memories: list[Memory]) -> int:
        """Delete expired memories from both stores."""
        return await self._init_expiration().cleanup_expired_memories(expired_memories)

    async def run_expiration_cleanup(self) -> int:
        """Complete workflow: find and cleanup all expired memories."""
        return await self._init_expiration().run_expiration_cleanup()

    # ==================== Namespace Operations ====================

    async def cleanup_namespace(
        self,
        namespace: str,
        agent_id: str,
        days: int = 90,
        min_importance: float = 0.3,
        dry_run: bool = False,
        limit: int = 100_000,
    ) -> dict[str, Any]:
        """Cleanup old memories in a namespace (SECURITY-CRITICAL)."""
        # Update audit_logger reference before operation
        ns_ops = self._init_namespace()
        ns_ops.audit_logger = self.audit_logger
        return await ns_ops.cleanup_namespace(
            namespace=namespace,
            agent_id=agent_id,
            days=days,
            min_importance=min_importance,
            dry_run=dry_run,
            limit=limit,
        )

    async def prune_expired_memories(
        self,
        namespace: str,
        agent_id: str,
        limit: int = 1000,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Prune expired memories from a namespace (SECURITY-CRITICAL)."""
        # Update audit_logger reference before operation
        ns_ops = self._init_namespace()
        ns_ops.audit_logger = self.audit_logger
        return await ns_ops.prune_expired_memories(
            namespace=namespace,
            agent_id=agent_id,
            limit=limit,
            dry_run=dry_run,
        )

    # ==================== Statistics Operations ====================

    async def count_memories(
        self,
        agent_id: str | None = None,
        namespace: str | None = None,
    ) -> int:
        """Count memories (SQLite source of truth)."""
        return await self._init_statistics().count_memories(
            agent_id=agent_id,
            namespace=namespace,
        )

    async def get_memory_stats(
        self,
        agent_id: str | None = None,
        namespace: str | None = None,
    ) -> dict[str, Any]:
        """Get memory statistics combining SQLite and ChromaDB."""
        return await self._init_statistics().get_memory_stats(
            agent_id=agent_id,
            namespace=namespace,
        )

    async def set_memory_ttl(
        self,
        memory_id: UUID,
        agent_id: str,
        ttl_days: int | None,
    ) -> dict[str, Any]:
        """Update TTL for an existing memory (P0-1 security pattern)."""
        # Update audit_logger reference before operation
        stats_ops = self._init_statistics()
        stats_ops.audit_logger = self.audit_logger
        return await stats_ops.set_memory_ttl(
            memory_id=memory_id,
            agent_id=agent_id,
            ttl_days=ttl_days,
        )

    # ==================== Internal Methods (for sub-services) ====================

    async def _fetch_memories_by_ids(
        self,
        memory_ids: list[str],
        agent_id: str | None,
        min_importance: float,
    ) -> list[Memory]:
        """Fetch memories from SQLite by IDs (internal method)."""
        return await self._init_crud().fetch_memories_by_ids(
            memory_ids=memory_ids,
            agent_id=agent_id,
            min_importance=min_importance,
        )
