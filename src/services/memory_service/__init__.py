"""Memory Service Package - Hybrid SQLite + ChromaDB memory management.

This package provides memory management with:
- SQLite: Authoritative metadata storage
- ChromaDB: Vector embeddings for semantic search
- Lazy initialization: ChromaDB only initialized when needed
- Security: Namespace isolation, ownership verification, TTL validation

Main components:
- HybridMemoryService: Main service class (coordinator)
- MemoryCRUDOperations: CRUD operations
- MemorySearchOperations: Semantic search
- MemoryExpirationManager: TTL cleanup
- MemoryNamespaceOperations: Namespace-level operations
- MemoryStatisticsService: Stats and TTL management

Backward compatibility:
- `from src.services.memory_service import HybridMemoryService` works unchanged
- `from src.services.memory_service import get_memory_service` works unchanged
"""

from src.core.database import get_session
from src.services.ollama_embedding_service import get_ollama_embedding_service
from src.services.vector_search_service import get_vector_search_service

from .core import HybridMemoryService
from .crud_operations import MemoryCRUDOperations
from .expiration_manager import MemoryExpirationManager
from .namespace_operations import MemoryNamespaceOperations
from .search_operations import MemorySearchOperations
from .statistics import MemoryStatisticsService
from .validation import (
    ACCESS_LEVEL_TTL_LIMITS,
    validate_access_level_ttl_limit,
    validate_ttl_days,
)

__all__ = [
    # Main service class
    "HybridMemoryService",
    # Sub-services (for advanced usage)
    "MemoryCRUDOperations",
    "MemorySearchOperations",
    "MemoryExpirationManager",
    "MemoryNamespaceOperations",
    "MemoryStatisticsService",
    # Validation functions
    "validate_ttl_days",
    "validate_access_level_ttl_limit",
    "ACCESS_LEVEL_TTL_LIMITS",
    # Dependency injection
    "get_memory_service",
    # Re-exported for backward compatibility
    "get_ollama_embedding_service",
    "get_vector_search_service",
]


# Dependency injection for FastAPI
async def get_memory_service() -> HybridMemoryService:
    """Get HybridMemoryService instance with database session."""
    async with get_session() as session:
        yield HybridMemoryService(session)
