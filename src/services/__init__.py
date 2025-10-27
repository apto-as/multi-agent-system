"""
TMWS Services Package
Business logic layer for TMWS operations
"""

from .memory_service import HybridMemoryService, get_memory_service
from .ollama_embedding_service import get_ollama_embedding_service
from .persona_service import PersonaService
from .task_service import TaskService
from .workflow_service import WorkflowService

# Export HybridMemoryService as default MemoryService
MemoryService = HybridMemoryService

# Export Ollama embedding service as the official embedding service
get_embedding_service = get_ollama_embedding_service

__all__ = [
    "MemoryService",
    "HybridMemoryService",
    "get_memory_service",
    "get_embedding_service",
    "PersonaService",
    "TaskService",
    "WorkflowService",
]
