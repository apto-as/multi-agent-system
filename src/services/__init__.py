"""TMWS Services Package
Business logic layer for TMWS operations
"""

from .agent_communication_service import AgentCommunicationService
from .execution_trace_service import ExecutionTraceService
from .learning_loop_service import LearningLoopService
from .memory_service import HybridMemoryService, get_memory_service
from .ollama_embedding_service import get_ollama_embedding_service
from .orchestration_engine import OrchestrationEngine
from .pattern_detection_service import PatternDetectionService
from .persona_service import PersonaService
from .proactive_context_service import ProactiveContextService
from .task_routing_service import TaskRoutingService
from .task_service import TaskService
from .template_service import TemplateService, PhaseTemplate
from .workflow_service import WorkflowService

# Export HybridMemoryService as default MemoryService
MemoryService = HybridMemoryService

# Export Ollama embedding service as the official embedding service
get_embedding_service = get_ollama_embedding_service

__all__ = [
    "AgentCommunicationService",
    "ExecutionTraceService",
    "LearningLoopService",
    "MemoryService",
    "HybridMemoryService",
    "get_memory_service",
    "get_embedding_service",
    "OrchestrationEngine",
    "PatternDetectionService",
    "PersonaService",
    "PhaseTemplate",
    "ProactiveContextService",
    "TaskService",
    "TaskRoutingService",
    "TemplateService",
    "WorkflowService",
]
