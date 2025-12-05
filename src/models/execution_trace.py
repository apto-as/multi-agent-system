"""Execution trace model for TMWS Autonomous Learning System.

Records MCP tool execution history in real-time for pattern detection
and autonomous SOP generation.

Architecture: Layer 1 of TMWS Native Autonomous Learning
- Records tool executions with <5ms P95 latency
- Enables SQL windowing for pattern detection
- Supports TTL-based automatic cleanup
- P0-1 compliant with namespace isolation

Security:
- Namespace isolation enforced at every query
- Agent-based access control
- TTL-based data retention (default 30 days)

Performance:
- Async recording (<5ms P95)
- Composite indexes for pattern queries
- Efficient windowing for sequence detection
"""

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import JSON, Boolean, CheckConstraint, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from .base import TMWSBase


class ExecutionTrace(TMWSBase):
    """MCP tool execution trace for autonomous learning.

    Records every MCP tool execution with parameters, results, and timing
    to enable pattern detection and automatic SOP generation.

    Key features:
    - Real-time async recording (<5ms P95)
    - Comprehensive execution context capture
    - Orchestration linkage for sequence analysis
    - TTL-based automatic cleanup
    - P0-1 namespace isolation compliance

    State Machine Integration:
    - Traces feed into PatternDetectionService
    - Detected patterns (N=3 threshold) become SOP drafts
    - Validated patterns promote to Skills
    """

    __tablename__ = "execution_traces"

    # Core identification
    agent_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        comment="Agent that executed the tool",
    )

    namespace: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Namespace for multi-tenant isolation (P0-1)",
    )

    # Tool execution details
    tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="MCP tool name (e.g., 'search_memories', 'store_memory')",
    )

    input_params: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        server_default=sa.text("'{}'"),
        comment="Tool input parameters (sanitized)",
    )

    output_result: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Tool output result (truncated if large)",
    )

    # Execution status
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=sa.text("1"),
        comment="Whether tool execution succeeded",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if execution failed",
    )

    error_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Exception class name if execution failed",
    )

    # Performance metrics
    execution_time_ms: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        server_default=sa.text("0.0"),
        comment="Tool execution time in milliseconds",
    )

    # Context for sequence analysis
    orchestration_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="Orchestration session ID for sequence grouping",
    )

    sequence_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Tool position within orchestration sequence",
    )

    context_snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="Context state at execution time (for pattern analysis)",
    )

    # Pattern detection metadata
    pattern_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="Linked detected pattern ID (if part of identified sequence)",
    )

    # Data retention
    ttl_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=30,
        server_default=sa.text("30"),
        comment="Time-to-live in days (default 30)",
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Calculated expiration timestamp",
    )

    # Table constraints and indexes
    __table_args__ = (
        # Check constraints
        CheckConstraint(
            "execution_time_ms >= 0",
            name="ck_execution_traces_execution_time_positive",
        ),
        CheckConstraint(
            "ttl_days >= 1 AND ttl_days <= 3650",
            name="ck_execution_traces_ttl_valid",
        ),
        # Composite indexes for pattern detection queries
        Index(
            "idx_execution_traces_pattern_detection",
            "namespace",
            "created_at",
            "orchestration_id",
            "tool_name",
        ),
        Index(
            "idx_execution_traces_agent_tool",
            "agent_id",
            "tool_name",
        ),
        Index(
            "idx_execution_traces_sequence",
            "orchestration_id",
            "sequence_number",
        ),
        Index(
            "idx_execution_traces_cleanup",
            "expires_at",
        ),
        {"comment": "MCP tool execution traces for autonomous learning pattern detection"},
    )

    def calculate_expiration(self) -> datetime:
        """Calculate expiration timestamp based on TTL."""
        from datetime import timedelta

        return datetime.utcnow() + timedelta(days=self.ttl_days)

    def mark_as_pattern_member(self, pattern_id: str) -> None:
        """Mark this trace as part of a detected pattern."""
        self.pattern_id = pattern_id

    def to_pattern_dict(self) -> dict[str, Any]:
        """Convert to dictionary format for pattern analysis."""
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "execution_time_ms": self.execution_time_ms,
            "orchestration_id": self.orchestration_id,
            "sequence_number": self.sequence_number,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": str(self.id),
            "tool_name": self.tool_name,
            "success": self.success,
            "execution_time_ms": self.execution_time_ms,
            "orchestration_id": self.orchestration_id,
            "sequence_number": self.sequence_number,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_sensitive:
            result.update(
                {
                    "agent_id": self.agent_id,
                    "namespace": self.namespace,
                    "input_params": self.input_params,
                    "output_result": self.output_result,
                    "error_message": self.error_message,
                    "error_type": self.error_type,
                    "context_snapshot": self.context_snapshot,
                    "pattern_id": self.pattern_id,
                    "ttl_days": self.ttl_days,
                    "expires_at": self.expires_at.isoformat() if self.expires_at else None,
                }
            )

        return result

    def __repr__(self) -> str:
        """String representation."""
        status = "✓" if self.success else "✗"
        return f"<ExecutionTrace({self.tool_name} {status} {self.execution_time_ms:.1f}ms)>"


class DetectedPattern(TMWSBase):
    """Detected recurring tool execution patterns.

    Stores patterns detected by PatternDetectionService when
    a tool sequence occurs N>=3 times with high success rate.

    State Machine:
    - DETECTED: Initial detection (N>=3 occurrences)
    - VALIDATING: Under validation review
    - VALIDATED: Passed all 6 validation checks
    - APPROVED: Ready for Skill promotion
    - SKILL_CREATED: Successfully converted to Skill
    - REJECTED: Failed validation or manual rejection
    """

    __tablename__ = "detected_patterns"

    # Pattern identification
    namespace: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Namespace for isolation (P0-1)",
    )

    agent_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        index=True,
        comment="Agent who created this pattern (null for system)",
    )

    # Pattern content
    tool_sequence: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        comment="Ordered list of tool names in the sequence",
    )

    pattern_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        comment="SHA256 hash of tool_sequence for deduplication",
    )

    # Statistics
    frequency: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default=sa.text("3"),
        comment="Number of occurrences detected",
    )

    avg_success_rate: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=1.0,
        server_default=sa.text("1.0"),
        comment="Average success rate of pattern executions",
    )

    avg_execution_time_ms: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Average total execution time of pattern",
    )

    # SOP generation
    sop_draft: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Auto-generated SOP markdown draft",
    )

    sop_title: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Generated SOP title",
    )

    # State machine
    state: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="DETECTED",
        server_default=sa.text("'DETECTED'"),
        index=True,
        comment="Pattern lifecycle state",
    )

    # Skill linkage
    skill_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        comment="Linked Skill ID after promotion",
    )

    # Validation tracking
    validation_errors: Mapped[list[str] | None] = mapped_column(
        JSON,
        nullable=True,
        comment="List of validation failure reasons",
    )

    validated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        comment="When pattern was validated",
    )

    approved_by: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        comment="Agent who approved the pattern",
    )

    approved_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        comment="When pattern was approved",
    )

    # Detection metadata
    detected_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        default=func.now,
        server_default=func.current_timestamp(),
        comment="When pattern was first detected",
    )

    last_occurrence_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        comment="When pattern was last observed",
    )

    # Table constraints and indexes
    __table_args__ = (
        # Check constraints
        CheckConstraint(
            "state IN ('DETECTED', 'VALIDATING', 'VALIDATED', 'APPROVED', 'SKILL_CREATED', 'REJECTED')",
            name="ck_detected_patterns_state",
        ),
        CheckConstraint(
            "frequency >= 3",
            name="ck_detected_patterns_min_frequency",
        ),
        CheckConstraint(
            "avg_success_rate >= 0.0 AND avg_success_rate <= 1.0",
            name="ck_detected_patterns_success_rate",
        ),
        # Indexes
        Index(
            "idx_detected_patterns_namespace_state",
            "namespace",
            "state",
        ),
        Index(
            "idx_detected_patterns_agent_state",
            "agent_id",
            "state",
        ),
        {"comment": "Detected recurring tool execution patterns for SOP generation"},
    )

    def transition_state(self, new_state: str, actor_id: str | None = None) -> bool:
        """Transition pattern state with validation.

        State transitions:
        - DETECTED → VALIDATING
        - VALIDATING → VALIDATED | REJECTED
        - VALIDATED → APPROVED | REJECTED
        - APPROVED → SKILL_CREATED | REJECTED

        Returns True if transition was valid, False otherwise.
        """
        valid_transitions = {
            "DETECTED": ["VALIDATING"],
            "VALIDATING": ["VALIDATED", "REJECTED"],
            "VALIDATED": ["APPROVED", "REJECTED"],
            "APPROVED": ["SKILL_CREATED", "REJECTED"],
            "SKILL_CREATED": [],  # Terminal state
            "REJECTED": [],  # Terminal state
        }

        if new_state not in valid_transitions.get(self.state, []):
            return False

        self.state = new_state

        if new_state == "VALIDATED":
            self.validated_at = func.now()
        elif new_state == "APPROVED":
            self.approved_by = actor_id
            self.approved_at = func.now()

        return True

    def increment_frequency(self) -> None:
        """Increment pattern occurrence count."""
        self.frequency += 1
        self.last_occurrence_at = func.now()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "namespace": self.namespace,
            "agent_id": self.agent_id,
            "tool_sequence": self.tool_sequence,
            "pattern_hash": self.pattern_hash,
            "frequency": self.frequency,
            "avg_success_rate": self.avg_success_rate,
            "avg_execution_time_ms": self.avg_execution_time_ms,
            "sop_title": self.sop_title,
            "state": self.state,
            "skill_id": self.skill_id,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "last_occurrence_at": self.last_occurrence_at.isoformat()
            if self.last_occurrence_at
            else None,
            "validated_at": self.validated_at.isoformat() if self.validated_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class SkillSuggestion(TMWSBase):
    """Skill suggestion tracking for proactive context injection.

    Records when skills are suggested at orchestration start
    and tracks their usage effectiveness.
    """

    __tablename__ = "skill_suggestions"

    # Suggestion context
    orchestration_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        comment="Orchestration where skill was suggested",
    )

    skill_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        comment="Suggested skill ID",
    )

    agent_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        comment="Agent receiving the suggestion",
    )

    namespace: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Namespace for isolation (P0-1)",
    )

    # Suggestion details
    relevance_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        comment="ChromaDB similarity score (0.0-1.0)",
    )

    suggestion_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reason for suggestion (semantic similarity, pattern match, etc.)",
    )

    # Usage tracking
    was_activated: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="Whether the suggested skill was activated",
    )

    was_helpful: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="User/agent feedback on suggestion helpfulness",
    )

    activated_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        comment="When skill was activated (if activated)",
    )

    feedback_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
        comment="When feedback was provided",
    )

    # Table constraints and indexes
    __table_args__ = (
        CheckConstraint(
            "relevance_score >= 0.0 AND relevance_score <= 1.0",
            name="ck_skill_suggestions_relevance_score",
        ),
        Index(
            "idx_skill_suggestions_orchestration",
            "orchestration_id",
        ),
        Index(
            "idx_skill_suggestions_effectiveness",
            "skill_id",
            "was_activated",
            "was_helpful",
        ),
        {"comment": "Skill suggestion tracking for proactive context injection"},
    )

    def mark_activated(self) -> None:
        """Mark this suggestion as activated."""
        self.was_activated = True
        self.activated_at = func.now()

    def provide_feedback(self, helpful: bool) -> None:
        """Record feedback on suggestion helpfulness."""
        self.was_helpful = helpful
        self.feedback_at = func.now()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "orchestration_id": self.orchestration_id,
            "skill_id": self.skill_id,
            "agent_id": self.agent_id,
            "namespace": self.namespace,
            "relevance_score": self.relevance_score,
            "suggestion_reason": self.suggestion_reason,
            "was_activated": self.was_activated,
            "was_helpful": self.was_helpful,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "feedback_at": self.feedback_at.isoformat() if self.feedback_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
