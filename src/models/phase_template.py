"""Phase Template models for TMWS Full Mode execution.

Architecture:
- Template System: Pre-defined and user-defined phase configurations
- JSONB Storage: Full phase definitions with validation
- Selection Criteria: Smart template matching based on task characteristics
- Performance Tracking: Usage statistics and success rate analytics
- Lifecycle Management: System vs user-defined, versioning, activation control

Design:
- TemplateType: Enum for categorizing templates (quick_fix, security_audit, full, etc.)
- PhaseTemplate: Master model storing template metadata and phase configuration
- Indexes: Optimized for template discovery and filtering

Security:
- Validation: JSON schema validation for phases structure
- Namespace isolation: Future support for user-defined templates
- Soft delete: Preserves analytics and audit trail

Performance:
- Composite indexes for common query patterns
- JSONB storage for flexible phase configuration
- Efficient template matching with keyword-based lookup
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import MetadataMixin, TMWSBase


class TemplateType(str, Enum):
    """Template types for Full Mode execution.

    Each type represents a different execution pattern:
    - QUICK_FIX: Fast turnaround for urgent issues (<30min)
    - SECURITY_AUDIT: Security-focused analysis with Hestia
    - FULL_DEVELOPMENT: Complete 4-phase development cycle
    - RESEARCH: Research-heavy tasks with Aurora
    - CUSTOM: User-defined templates
    """

    QUICK_FIX = "quick_fix"
    SECURITY_AUDIT = "security_audit"
    FULL_DEVELOPMENT = "full"
    RESEARCH = "research"
    CUSTOM = "custom"


class TaskComplexity(str, Enum):
    """Task complexity levels for template selection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PhaseTemplate(TMWSBase, MetadataMixin):
    """Phase template storage for Full Mode execution.

    A PhaseTemplate defines a reusable execution pattern with:
    - Phase configuration (which personas, what order, approval gates)
    - Selection criteria (keywords, complexity, duration)
    - Performance metrics (usage count, success rate)
    - Lifecycle control (system vs user-defined, versioning, activation)

    Example:
        ```python
        template = PhaseTemplate(
            template_id="quick_fix",
            template_type=TemplateType.QUICK_FIX,
            display_name="Quick Fix",
            description="Fast turnaround for urgent bugs",
            phases={
                "phase_1": {
                    "name": "Emergency Analysis",
                    "personas": ["eris", "artemis"],
                    "parallel": True
                },
                "phase_2": {
                    "name": "Implementation",
                    "personas": ["metis"],
                    "approval_gate": False
                }
            },
            trigger_keywords=["urgent", "emergency", "hotfix"],
            task_complexity=TaskComplexity.LOW,
            estimated_duration="<30min",
            is_system=True
        )
        ```
    """

    __tablename__ = "phase_templates"

    # Core identification
    template_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment='Unique template identifier (e.g., "quick_fix", "security_audit")',
    )

    template_type: Mapped[TemplateType] = mapped_column(
        sa.Enum(TemplateType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True,
        comment="Template type category",
    )

    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment='Human-readable name (e.g., "Quick Fix", "Security Audit")',
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Brief description of template purpose and use cases",
    )

    # Phase configuration (JSONB)
    phases_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Full phase definitions as JSON (SQLite-compatible)",
    )

    # Selection criteria
    trigger_keywords_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
        server_default="[]",
        comment='JSON array of trigger keywords (e.g., ["urgent", "security", "optimize"])',
    )

    task_complexity: Mapped[TaskComplexity] = mapped_column(
        sa.Enum(TaskComplexity, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True,
        comment='Task complexity level ("low", "medium", "high")',
    )

    estimated_duration: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment='Estimated duration (e.g., "<30min", "1-4h", ">4h")',
    )

    # Lifecycle management
    is_system: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
        index=True,
        comment="System template (True) vs user-defined (False)",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="1",
        index=True,
        comment="Template activation status",
    )

    version: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="1.0.0",
        server_default="1.0.0",
        comment="Semantic version (e.g., '1.0.0', '2.1.3')",
    )

    # Statistics and analytics
    usage_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Total number of times this template was used",
    )

    success_rate: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        server_default="0.0",
        comment="Success rate (0.0-1.0) based on completed executions",
    )

    # Soft delete (preserves audit trail)
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
        comment="Soft delete flag (preserves analytics)",
    )

    # Indexes for performance
    __table_args__ = (
        Index("ix_phase_templates_type_active", "template_type", "is_active"),
        Index("ix_phase_templates_complexity_active", "task_complexity", "is_active"),
        Index("ix_phase_templates_system_active", "is_system", "is_active"),
        Index("ix_phase_templates_is_deleted", "is_deleted"),
    )

    # Properties for JSON serialization/deserialization

    @property
    def phases(self) -> dict[str, Any]:
        """Deserialize phases from JSON.

        Returns:
            dict: Phase configuration with structure:
                {
                    "phase_1": {
                        "name": "Phase Name",
                        "personas": ["persona1", "persona2"],
                        "parallel": True/False,
                        "approval_gate": True/False
                    },
                    ...
                }
        """
        try:
            return json.loads(self.phases_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    @phases.setter
    def phases(self, value: dict[str, Any]) -> None:
        """Serialize phases to JSON with validation.

        Args:
            value: Phase configuration dictionary

        Raises:
            ValueError: If phase structure is invalid
        """
        # Basic validation
        if not isinstance(value, dict):
            raise ValueError("Phases must be a dictionary")

        for phase_key, phase_config in value.items():
            if not isinstance(phase_config, dict):
                raise ValueError(f"Phase '{phase_key}' must be a dictionary")

            # Validate required fields
            if "name" not in phase_config:
                raise ValueError(f"Phase '{phase_key}' must have 'name' field")
            if "personas" not in phase_config:
                raise ValueError(f"Phase '{phase_key}' must have 'personas' field")
            if not isinstance(phase_config["personas"], list):
                raise ValueError(f"Phase '{phase_key}' personas must be a list")

        self.phases_json = json.dumps(value)

    @property
    def trigger_keywords(self) -> list[str]:
        """Deserialize trigger keywords from JSON."""
        try:
            return json.loads(self.trigger_keywords_json)
        except (json.JSONDecodeError, TypeError):
            return []

    @trigger_keywords.setter
    def trigger_keywords(self, value: list[str]) -> None:
        """Serialize trigger keywords to JSON."""
        if not isinstance(value, list):
            raise ValueError("Trigger keywords must be a list")
        self.trigger_keywords_json = json.dumps(value)

    # Methods

    def matches_keywords(self, task_description: str) -> bool:
        """Check if task description matches any trigger keywords.

        Args:
            task_description: Task description to match against

        Returns:
            bool: True if any keyword matches (case-insensitive)
        """
        if not self.trigger_keywords:
            return False

        task_lower = task_description.lower()
        return any(keyword.lower() in task_lower for keyword in self.trigger_keywords)

    def increment_usage(self) -> None:
        """Increment usage count."""
        self.usage_count += 1

    def update_success_rate(self, success: bool) -> None:
        """Update success rate with exponential moving average.

        Args:
            success: Whether the execution was successful
        """
        if self.usage_count == 0:
            self.success_rate = 1.0 if success else 0.0
        else:
            # Exponential moving average (weight recent executions more)
            alpha = 0.1  # Weight for new result
            new_value = 1.0 if success else 0.0
            self.success_rate = alpha * new_value + (1 - alpha) * self.success_rate

    def to_dict(self) -> dict[str, Any]:
        """Convert template to dictionary for API serialization."""
        result = super().to_dict()
        result["template_type"] = self.template_type.value
        result["task_complexity"] = self.task_complexity.value
        result["phases"] = self.phases  # Deserialize JSON
        result["trigger_keywords"] = self.trigger_keywords  # Deserialize JSON
        return result

    def __repr__(self) -> str:
        return (
            f"<PhaseTemplate(template_id='{self.template_id}', "
            f"type='{self.template_type.value}', "
            f"complexity='{self.task_complexity.value}')>"
        )


# Validation helper function
def validate_phase_structure(phases: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate phase configuration structure.

    Args:
        phases: Phase configuration dictionary

    Returns:
        tuple: (is_valid, error_message)
    """
    if not isinstance(phases, dict):
        return False, "Phases must be a dictionary"

    if not phases:
        return False, "Phases dictionary cannot be empty"

    for phase_key, phase_config in phases.items():
        if not isinstance(phase_config, dict):
            return False, f"Phase '{phase_key}' must be a dictionary"

        # Required fields
        if "name" not in phase_config:
            return False, f"Phase '{phase_key}' must have 'name' field"
        if "personas" not in phase_config:
            return False, f"Phase '{phase_key}' must have 'personas' field"

        # Type validation
        if not isinstance(phase_config["name"], str):
            return False, f"Phase '{phase_key}' name must be a string"
        if not isinstance(phase_config["personas"], list):
            return False, f"Phase '{phase_key}' personas must be a list"
        if not all(isinstance(p, str) for p in phase_config["personas"]):
            return False, f"Phase '{phase_key}' personas must be strings"

        # Optional fields validation
        if "parallel" in phase_config and not isinstance(phase_config["parallel"], bool):
            return False, f"Phase '{phase_key}' parallel must be a boolean"
        if "approval_gate" in phase_config and not isinstance(phase_config["approval_gate"], bool):
            return False, f"Phase '{phase_key}' approval_gate must be a boolean"

    return True, None
