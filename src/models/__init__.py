"""Database models for TMWS v2.2.0."""

# Base classes
# Core Models
from .agent import Agent, AgentNamespace, AgentTeam

# API audit logging
from .api_audit_log import APIAuditLog
from .audit_log import SecurityAuditLog, SecurityEventSeverity, SecurityEventType
from .base import MetadataMixin, TimestampMixin, TMWSBase, UUIDMixin

# Autonomous Learning System (v2.5.0)
from .execution_trace import DetectedPattern, ExecutionTrace, SkillSuggestion
from .learning_pattern import LearningPattern
from .license_key import LicenseKey, LicenseKeyUsage
from .memory import Memory, MemoryConsolidation, MemoryPattern, MemorySharing
from .persona import Persona, PersonaRole, PersonaType
from .task import Task, TaskPriority, TaskStatus
from .token_consumption import TokenConsumption
from .tool_discovery import (
    DiscoveredTool,
    ToolDependency,
    ToolInstance,
    ToolVerificationHistory,
)
from .user import User
from .verification import TrustScoreHistory, VerificationRecord
from .workflow import Workflow, WorkflowStatus, WorkflowType
from .workflow_history import (
    WorkflowExecution,
    WorkflowExecutionLog,
    WorkflowSchedule,
    WorkflowStepExecution,
)

__all__ = [
    # Base classes
    "TMWSBase",
    "UUIDMixin",
    "TimestampMixin",
    "MetadataMixin",
    # Core Models
    "TokenConsumption",
    "Agent",
    "AgentTeam",
    "AgentNamespace",
    "Memory",
    "MemorySharing",
    "MemoryPattern",
    "MemoryConsolidation",
    "Persona",
    "PersonaType",
    "PersonaRole",
    "Task",
    "TaskStatus",
    "TaskPriority",
    "Workflow",
    "WorkflowStatus",
    "WorkflowType",
    "LearningPattern",
    "User",
    "WorkflowExecution",
    "WorkflowStepExecution",
    "WorkflowExecutionLog",
    "WorkflowSchedule",
    # API audit logging
    "APIAuditLog",
    "SecurityAuditLog",
    "SecurityEventType",
    "SecurityEventSeverity",
    # Trust and verification
    "VerificationRecord",
    "TrustScoreHistory",
    # Tool Discovery (Phase 4)
    "DiscoveredTool",
    "ToolDependency",
    "ToolInstance",
    "ToolVerificationHistory",
    # Autonomous Learning System (v2.5.0)
    "ExecutionTrace",
    "DetectedPattern",
    "SkillSuggestion",
]
