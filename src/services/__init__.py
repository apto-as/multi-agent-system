"""TMWS Services Package
Business logic layer for TMWS operations
"""

from .agent_communication_service import AgentCommunicationService
from .memory_service import HybridMemoryService, get_memory_service
from .ollama_embedding_service import get_ollama_embedding_service
from .orchestration_engine import OrchestrationEngine
from .persona_service import PersonaService
from .task_routing_service import TaskRoutingService
from .task_service import TaskService
from .workflow_service import WorkflowService

# Export HybridMemoryService as default MemoryService
MemoryService = HybridMemoryService

# Export Ollama embedding service as the official embedding service
get_embedding_service = get_ollama_embedding_service

__all__ = [
    "AgentCommunicationService",
    "MemoryService",
    "HybridMemoryService",
    "get_memory_service",
    "get_embedding_service",
    "OrchestrationEngine",
    "PersonaService",
    "TaskService",
    "TaskRoutingService",
    "WorkflowService",
]
