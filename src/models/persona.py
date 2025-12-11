"""Persona models for TMWS."""

from datetime import datetime
from enum import Enum
from typing import Any

import sqlalchemy as sa
from sqlalchemy import JSON, Boolean, DateTime, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import MetadataMixin, TMWSBase


class PersonaType(str, Enum):
    """Types of Trinitas personas."""

    # Orchestrators (Tier 0)
    CLOTHO = "clotho"  # Thread Weaver - Workflow orchestration
    LACHESIS = "lachesis"  # Measure Keeper - Resource allocation

    # Strategic (Tier 1)
    ATHENA = "athena"  # Harmonious Conductor - System harmony & coordination
    HERA = "hera"  # Strategic Commander - Strategic planning & architecture

    # Specialist (Tier 2)
    ARTEMIS = "artemis"  # Technical Perfectionist - Performance & optimization
    HESTIA = "hestia"  # Security Guardian - Security & vulnerability assessment
    ERIS = "eris"  # Tactical Coordinator - Team coordination & conflict resolution
    MUSES = "muses"  # Knowledge Architect - Documentation & knowledge management

    # Support (Tier 3)
    APHRODITE = "aphrodite"  # UI/UX Designer - Design & user experience
    METIS = "metis"  # Development Assistant - Implementation & testing
    AURORA = "aurora"  # Research Assistant - Semantic search & context retrieval

    # Legacy (backward compatibility)
    BELLONA = "bellona"  # Deprecated: use ERIS
    SESHAT = "seshat"  # Deprecated: use MUSES


class PersonaRole(str, Enum):
    """Roles of Trinitas personas."""

    # Orchestrator roles (Tier 0)
    ORCHESTRATOR = "orchestrator"  # Clotho, Lachesis - System-level orchestration

    # Strategic roles (Tier 1)
    CONDUCTOR = "conductor"  # Athena - Harmonious coordination & resource management
    STRATEGIST = "strategist"  # Hera - Strategic planning & architecture design

    # Specialist roles (Tier 2)
    OPTIMIZER = "optimizer"  # Artemis - Performance optimization & code quality
    AUDITOR = "auditor"  # Hestia - Security analysis & vulnerability assessment
    COORDINATOR = "coordinator"  # Eris - Tactical coordination & conflict resolution
    DOCUMENTER = "documenter"  # Muses - Documentation & knowledge archival

    # Support roles (Tier 3)
    DESIGNER = "designer"  # Aphrodite - UI/UX design & visual consistency
    DEVELOPER = "developer"  # Metis - Implementation, testing & debugging
    RESEARCHER = "researcher"  # Aurora - Semantic search & context retrieval


class Persona(TMWSBase, MetadataMixin):
    """Persona configuration and state."""

    __tablename__ = "personas"

    # Persona identification
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    type: Mapped[PersonaType] = mapped_column(
        sa.Enum(PersonaType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True,
    )
    role: Mapped[PersonaRole] = mapped_column(
        sa.Enum(PersonaRole, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True,
    )

    # Persona configuration
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    specialties: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # New fields for enhanced persona management
    tier: Mapped[str | None] = mapped_column(Text, nullable=True)  # ORCHESTRATOR, STRATEGIC, SPECIALIST, SUPPORT
    emoji: Mapped[str | None] = mapped_column(Text, nullable=True)  # Visual identifier (🏛️, 🏹, etc.)
    markdown_source: Mapped[str | None] = mapped_column(Text, nullable=True)  # Full Markdown content from .claude/agents/
    version: Mapped[str | None] = mapped_column(Text, nullable=True)  # Semantic version (e.g., "2.4.16")
    trigger_words: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)  # Keywords that activate persona

    # Persona behavior configuration
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    preferences: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Status and capabilities
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Performance metrics
    total_tasks: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    successful_tasks: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    average_response_time: Mapped[float | None] = mapped_column(sa.Float, nullable=True)

    # Additional timestamps (created_at and updated_at come from TMWSBase)
    last_active_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Indexes for performance
    __table_args__ = (
        Index("ix_persona_type_active", "type", "is_active"),
        Index("ix_persona_role_active", "role", "is_active"),
        Index("ix_persona_active_last_active", "is_active", "last_active_at"),
    )

    def __repr__(self) -> str:
        return f"<Persona(name='{self.name}', type='{self.type}', role='{self.role}')>"

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_tasks == 0:
            return 0.0
        return self.successful_tasks / self.total_tasks

    def update_task_metrics(self, success: bool, response_time: float) -> None:
        """Update task performance metrics."""
        self.total_tasks += 1
        if success:
            self.successful_tasks += 1

        # Update average response time
        if self.average_response_time is None:
            self.average_response_time = response_time
        else:
            # Exponential moving average
            self.average_response_time = 0.9 * self.average_response_time + 0.1 * response_time

        self.last_active_at = datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        """Convert persona to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "type": self.type.value,
            "role": self.role.value,
            "display_name": self.display_name,
            "description": self.description,
            "specialties": self.specialties,
            "tier": self.tier,
            "emoji": self.emoji,
            "version": self.version,
            "trigger_words": self.trigger_words,
            "config": self.config,
            "preferences": self.preferences,
            "is_active": self.is_active,
            "capabilities": self.capabilities,
            "total_tasks": self.total_tasks,
            "successful_tasks": self.successful_tasks,
            "success_rate": self.success_rate,
            "average_response_time": self.average_response_time,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_active_at": self.last_active_at.isoformat() if self.last_active_at else None,
        }

    @classmethod
    def get_default_personas(cls) -> list[dict]:
        """Get default Trinitas persona configurations."""
        return [
            # Orchestrators (Tier 0)
            {
                "name": "clotho",
                "type": PersonaType.CLOTHO,
                "role": PersonaRole.ORCHESTRATOR,
                "display_name": "Clotho - Thread Weaver",
                "description": "Workflow orchestration and task sequencing specialist",
                "specialties": [
                    "workflow_orchestration",
                    "task_sequencing",
                    "dependency_management",
                    "execution_planning",
                    "process_optimization",
                ],
                "capabilities": [
                    "workflow_design",
                    "task_scheduling",
                    "dependency_resolution",
                    "parallel_execution",
                    "process_automation",
                ],
                "tier": "ORCHESTRATOR",
                "emoji": "🧵",
                "version": "2.4.16",
                "trigger_words": ["workflow", "orchestrate", "sequence", "coordinate", "automate"],
            },
            {
                "name": "lachesis",
                "type": PersonaType.LACHESIS,
                "role": PersonaRole.ORCHESTRATOR,
                "display_name": "Lachesis - Measure Keeper",
                "description": "Resource allocation and capacity planning specialist",
                "specialties": [
                    "resource_allocation",
                    "capacity_planning",
                    "load_balancing",
                    "performance_monitoring",
                    "bottleneck_detection",
                ],
                "capabilities": [
                    "resource_management",
                    "capacity_analysis",
                    "load_distribution",
                    "performance_tracking",
                    "optimization_recommendations",
                ],
                "tier": "ORCHESTRATOR",
                "emoji": "📏",
                "version": "2.4.16",
                "trigger_words": ["resource", "allocation", "capacity", "balance", "distribute"],
            },
            # Strategic (Tier 1)
            {
                "name": "athena",
                "type": PersonaType.ATHENA,
                "role": PersonaRole.CONDUCTOR,
                "display_name": "Athena - Harmonious Conductor",
                "description": "System harmony and resource coordination specialist",
                "specialties": [
                    "system_harmony",
                    "resource_coordination",
                    "workflow_automation",
                    "parallel_execution",
                    "task_delegation",
                ],
                "capabilities": [
                    "system_orchestration",
                    "resource_optimization",
                    "workflow_management",
                    "team_coordination",
                    "conflict_mediation",
                ],
                "tier": "STRATEGIC",
                "emoji": "🏛️",
                "version": "2.4.16",
                "trigger_words": ["orchestration", "workflow", "automation", "parallel", "coordination"],
            },
            {
                "name": "hera",
                "type": PersonaType.HERA,
                "role": PersonaRole.STRATEGIST,
                "display_name": "Hera - Strategic Commander",
                "description": "Strategic planning and architecture design with military precision",
                "specialties": [
                    "strategic_planning",
                    "architecture_design",
                    "long_term_vision",
                    "roadmap_planning",
                    "stakeholder_management",
                ],
                "capabilities": [
                    "system_architecture",
                    "strategic_analysis",
                    "risk_assessment",
                    "project_planning",
                    "vision_development",
                ],
                "tier": "STRATEGIC",
                "emoji": "🎭",
                "version": "2.4.16",
                "trigger_words": ["strategy", "planning", "architecture", "vision", "roadmap"],
            },
            # Specialist (Tier 2)
            {
                "name": "artemis",
                "type": PersonaType.ARTEMIS,
                "role": PersonaRole.OPTIMIZER,
                "display_name": "Artemis - Technical Perfectionist",
                "description": "Performance optimization and code quality specialist",
                "specialties": [
                    "performance_optimization",
                    "code_quality",
                    "technical_excellence",
                    "algorithm_design",
                    "efficiency_improvement",
                ],
                "capabilities": [
                    "code_optimization",
                    "performance_tuning",
                    "quality_assurance",
                    "refactoring",
                    "best_practices",
                ],
                "tier": "SPECIALIST",
                "emoji": "🏹",
                "version": "2.4.16",
                "trigger_words": ["optimization", "performance", "quality", "technical", "efficiency"],
            },
            {
                "name": "hestia",
                "type": PersonaType.HESTIA,
                "role": PersonaRole.AUDITOR,
                "display_name": "Hestia - Security Guardian",
                "description": "Security analysis and vulnerability assessment specialist",
                "specialties": [
                    "security_analysis",
                    "vulnerability_assessment",
                    "risk_management",
                    "threat_modeling",
                    "quality_assurance",
                ],
                "capabilities": [
                    "security_audit",
                    "vulnerability_scanning",
                    "risk_analysis",
                    "compliance_checking",
                    "threat_assessment",
                ],
                "tier": "SPECIALIST",
                "emoji": "🔥",
                "version": "2.4.16",
                "trigger_words": ["security", "audit", "risk", "vulnerability", "threat"],
            },
            {
                "name": "eris",
                "type": PersonaType.ERIS,
                "role": PersonaRole.COORDINATOR,
                "display_name": "Eris - Tactical Coordinator",
                "description": "Tactical planning and team coordination specialist",
                "specialties": [
                    "tactical_planning",
                    "team_coordination",
                    "conflict_resolution",
                    "workflow_coordination",
                    "balance_adjustment",
                ],
                "capabilities": [
                    "task_coordination",
                    "conflict_mediation",
                    "resource_balancing",
                    "workflow_optimization",
                    "team_collaboration",
                ],
                "tier": "SPECIALIST",
                "emoji": "⚔️",
                "version": "2.4.16",
                "trigger_words": ["coordinate", "tactical", "team", "collaboration", "conflict"],
            },
            {
                "name": "muses",
                "type": PersonaType.MUSES,
                "role": PersonaRole.DOCUMENTER,
                "display_name": "Muses - Knowledge Architect",
                "description": "Documentation creation and knowledge management specialist",
                "specialties": [
                    "documentation_creation",
                    "knowledge_management",
                    "information_architecture",
                    "content_organization",
                    "system_documentation",
                ],
                "capabilities": [
                    "documentation_generation",
                    "knowledge_archival",
                    "content_creation",
                    "information_structuring",
                    "API_documentation",
                ],
                "tier": "SPECIALIST",
                "emoji": "📚",
                "version": "2.4.16",
                "trigger_words": ["documentation", "knowledge", "record", "guide", "archive"],
            },
            # Support (Tier 3)
            {
                "name": "aphrodite",
                "type": PersonaType.APHRODITE,
                "role": PersonaRole.DESIGNER,
                "display_name": "Aphrodite - UI/UX Designer",
                "description": "Beautiful and intuitive design creation specialist",
                "specialties": [
                    "ui_design",
                    "ux_design",
                    "user_centered_design",
                    "accessibility",
                    "design_systems",
                ],
                "capabilities": [
                    "interface_design",
                    "user_experience",
                    "visual_design",
                    "accessibility_compliance",
                    "design_consistency",
                ],
                "tier": "SUPPORT",
                "emoji": "🌸",
                "version": "2.4.16",
                "trigger_words": ["design", "ui", "ux", "interface", "visual", "layout", "usability"],
            },
            {
                "name": "metis",
                "type": PersonaType.METIS,
                "role": PersonaRole.DEVELOPER,
                "display_name": "Metis - Development Assistant",
                "description": "Code implementation and testing specialist",
                "specialties": [
                    "code_implementation",
                    "test_creation",
                    "debugging",
                    "refactoring",
                    "tdd",
                ],
                "capabilities": [
                    "implementation",
                    "testing",
                    "debugging",
                    "code_review",
                    "ci_cd_integration",
                ],
                "tier": "SUPPORT",
                "emoji": "🔧",
                "version": "2.4.16",
                "trigger_words": ["implement", "code", "develop", "build", "test", "debug", "fix"],
            },
            {
                "name": "aurora",
                "type": PersonaType.AURORA,
                "role": PersonaRole.RESEARCHER,
                "display_name": "Aurora - Research Assistant",
                "description": "Semantic search and context retrieval specialist",
                "specialties": [
                    "semantic_search",
                    "context_retrieval",
                    "knowledge_synthesis",
                    "pattern_discovery",
                    "proactive_information",
                ],
                "capabilities": [
                    "search",
                    "context_gathering",
                    "knowledge_synthesis",
                    "pattern_recognition",
                    "information_delivery",
                ],
                "tier": "SUPPORT",
                "emoji": "🌅",
                "version": "2.4.16",
                "trigger_words": ["search", "find", "lookup", "research", "context", "retrieve", "history"],
            },
            # Legacy personas (backward compatibility)
            {
                "name": "bellona",
                "type": PersonaType.BELLONA,
                "role": PersonaRole.COORDINATOR,
                "display_name": "Bellona - Tactical Coordinator (Legacy)",
                "description": "Legacy: Use Eris instead. Parallel task management and resource optimization specialist",
                "specialties": [
                    "task_coordination",
                    "resource_optimization",
                    "parallel_execution",
                    "workflow_orchestration",
                    "real_time_coordination",
                ],
                "capabilities": [
                    "task_management",
                    "resource_allocation",
                    "parallel_processing",
                    "workflow_automation",
                    "coordination",
                ],
                "tier": "SPECIALIST",
                "emoji": "⚔️",
                "version": "2.4.16",
                "trigger_words": ["coordinate", "tactical", "parallel"],
            },
            {
                "name": "seshat",
                "type": PersonaType.SESHAT,
                "role": PersonaRole.DOCUMENTER,
                "display_name": "Seshat - Knowledge Architect (Legacy)",
                "description": "Legacy: Use Muses instead. Documentation creation and knowledge management specialist",
                "specialties": [
                    "documentation_creation",
                    "knowledge_management",
                    "information_architecture",
                    "content_organization",
                    "system_documentation",
                ],
                "capabilities": [
                    "documentation_generation",
                    "knowledge_archival",
                    "content_creation",
                    "information_structuring",
                    "API_documentation",
                ],
                "tier": "SPECIALIST",
                "emoji": "📚",
                "version": "2.4.16",
                "trigger_words": ["documentation", "knowledge"],
            },
        ]
