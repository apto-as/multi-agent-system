"""Conversation log models for SubAgent communication tracking.

This module provides models for logging SubAgent conversations, enabling:
1. Pattern learning from agent interactions
2. Automatic Skills generation from successful patterns
3. Context preservation for multi-turn dialogues
4. Performance analysis and optimization
"""

from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import MetadataMixin, TMWSBase


class ConversationLog(TMWSBase, MetadataMixin):
    """Log entry for SubAgent conversation messages.

    Tracks messages exchanged with SubAgents (Hera, Athena, Artemis, etc.)
    for pattern learning and Skills auto-generation.
    """

    __tablename__ = "conversation_logs"

    # Core identification
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Agent identifier (e.g., 'artemis-optimizer', 'hera-strategist')",
    )

    session_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Parent session ID for grouping related conversations",
    )

    # Message content
    role: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Message role: 'user' or 'assistant'",
    )

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Message content",
    )

    # Threading and relationships
    parent_message_id: Mapped[str | None] = mapped_column(
        String(36),  # UUID
        ForeignKey("conversation_logs.id"),
        nullable=True,
        comment="Parent message ID for threaded conversations",
    )

    # Contextual metadata (avoid "metadata" name - SQLAlchemy reserved)
    context_metadata: Mapped[dict[str, Any]] = mapped_column(
        sa.JSON,
        nullable=False,
        default=dict,
        comment="Additional context: task_type, phase, success_status, etc.",
    )

    # Timing and performance
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Message timestamp",
    )

    response_time_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Response time in milliseconds (for assistant messages)",
    )

    # Pattern learning flags
    pattern_extracted: Mapped[bool] = mapped_column(
        sa.Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether patterns have been extracted from this conversation",
    )

    skill_candidate: Mapped[bool] = mapped_column(
        sa.Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Whether this conversation is a candidate for Skill generation",
    )

    # Indexes for efficient queries
    __table_args__ = (
        Index("ix_conversation_agent_session", "agent_id", "session_id"),
        Index("ix_conversation_timestamp", "timestamp"),
        Index("ix_conversation_pattern_flags", "pattern_extracted", "skill_candidate"),
    )

    def __repr__(self) -> str:
        content_preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return f"<ConversationLog(agent='{self.agent_id}', role='{self.role}', content='{content_preview}')>"

    def to_dict(self) -> dict[str, Any]:
        """Convert conversation log to dictionary."""
        return {
            "id": str(self.id),
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "role": self.role,
            "content": self.content,
            "parent_message_id": str(self.parent_message_id) if self.parent_message_id else None,
            "metadata": self.context_metadata,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "response_time_ms": self.response_time_ms,
            "pattern_extracted": self.pattern_extracted,
            "skill_candidate": self.skill_candidate,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ConversationSession(TMWSBase, MetadataMixin):
    """Group of related conversation logs forming a complete interaction.

    Represents a single SubAgent invocation session with all its messages.
    """

    __tablename__ = "conversation_sessions"

    # Core identification
    session_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        unique=True,
        index=True,
        comment="Unique session identifier",
    )

    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
        comment="Primary agent for this session",
    )

    # Session metadata
    task_type: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Type of task: 'optimization', 'security_audit', 'strategic_planning', etc.",
    )

    phase: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Trinitas phase: 'phase_1_strategic', 'phase_2_implementation', etc.",
    )

    # Session lifecycle
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Success tracking
    success: Mapped[bool | None] = mapped_column(
        sa.Boolean,
        nullable=True,
        comment="Whether the session completed successfully",
    )

    outcome: Mapped[dict[str, Any]] = mapped_column(
        sa.JSON,
        nullable=False,
        default=dict,
        comment="Session outcome data: results, metrics, artifacts",
    )

    # Learning integration
    learning_patterns: Mapped[list[str]] = mapped_column(
        sa.JSON,
        nullable=False,
        default=list,
        comment="List of learning pattern IDs extracted from this session",
    )

    skills_generated: Mapped[list[str]] = mapped_column(
        sa.JSON,
        nullable=False,
        default=list,
        comment="List of skill IDs auto-generated from this session",
    )

    # Indexes
    __table_args__ = (
        Index("ix_session_agent_started", "agent_id", "started_at"),
        Index("ix_session_task_type", "task_type"),
        Index("ix_session_success", "success", "completed_at"),
    )

    def __repr__(self) -> str:
        return f"<ConversationSession(session_id='{self.session_id}', agent='{self.agent_id}', task='{self.task_type}')>"

    def to_dict(self) -> dict[str, Any]:
        """Convert conversation session to dictionary."""
        return {
            "id": str(self.id),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "task_type": self.task_type,
            "phase": self.phase,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "outcome": self.outcome,
            "learning_patterns": self.learning_patterns,
            "skills_generated": self.skills_generated,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
