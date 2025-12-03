"""Add Autonomous Learning System foundation tables.

Revision ID: 20251202_autonomous_learning
Revises: 20251125_1713_add_skills_system
Create Date: 2025-12-02

TMWS Native Autonomous Learning System - Phase 1: Foundation
- execution_traces: Real-time MCP tool execution recording
- detected_patterns: Recurring tool sequence patterns
- skill_suggestions: Proactive context injection tracking

Architecture:
- Layer 1: ExecutionTraceService + execution_traces table
- Layer 2: PatternDetectionService + detected_patterns table
- Layer 4: ProactiveContextService + skill_suggestions table

Security:
- P0-1 Namespace isolation enforced at every table
- TTL-based data retention for execution traces (default 30 days)
- Foreign key constraints for referential integrity

Performance:
- Composite indexes for pattern detection queries
- Async recording target: <5ms P95
- SQL windowing optimization for sequence detection
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic
revision = '20251202_autonomous_learning'
down_revision = '20251125_1713_add_skills_system'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create Autonomous Learning System tables."""

    # Table 1: execution_traces (Layer 1)
    op.create_table(
        'execution_traces',
        # Primary key
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),

        # Core identification
        sa.Column('agent_id', sa.String(36), nullable=False,
                  comment='Agent that executed the tool'),
        sa.Column('namespace', sa.String(255), nullable=False,
                  comment='Namespace for multi-tenant isolation (P0-1)'),

        # Tool execution details
        sa.Column('tool_name', sa.String(255), nullable=False,
                  comment='MCP tool name'),
        sa.Column('input_params', sa.JSON, nullable=False, server_default='{}',
                  comment='Tool input parameters (sanitized)'),
        sa.Column('output_result', sa.JSON, nullable=True,
                  comment='Tool output result (truncated if large)'),

        # Execution status
        sa.Column('success', sa.Boolean, nullable=False, server_default='1',
                  comment='Whether tool execution succeeded'),
        sa.Column('error_message', sa.Text, nullable=True,
                  comment='Error message if execution failed'),
        sa.Column('error_type', sa.String(255), nullable=True,
                  comment='Exception class name if execution failed'),

        # Performance metrics
        sa.Column('execution_time_ms', sa.Float, nullable=False, server_default='0.0',
                  comment='Tool execution time in milliseconds'),

        # Context for sequence analysis
        sa.Column('orchestration_id', sa.String(36), nullable=True,
                  comment='Orchestration session ID for sequence grouping'),
        sa.Column('sequence_number', sa.Integer, nullable=True,
                  comment='Tool position within orchestration sequence'),
        sa.Column('context_snapshot', sa.JSON, nullable=True,
                  comment='Context state at execution time'),

        # Pattern detection metadata
        sa.Column('pattern_id', sa.String(36), nullable=True,
                  comment='Linked detected pattern ID'),

        # Data retention
        sa.Column('ttl_days', sa.Integer, nullable=False, server_default='30',
                  comment='Time-to-live in days (default 30)'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True,
                  comment='Calculated expiration timestamp'),

        # Timestamps (from TMWSBase)
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record last update timestamp'),

        # Check constraints
        sa.CheckConstraint('execution_time_ms >= 0',
                          name='ck_execution_traces_execution_time_positive'),
        sa.CheckConstraint('ttl_days >= 1 AND ttl_days <= 3650',
                          name='ck_execution_traces_ttl_valid'),

        comment='MCP tool execution traces for autonomous learning pattern detection'
    )

    # Indexes for execution_traces
    op.create_index('ix_execution_traces_agent_id', 'execution_traces', ['agent_id'])
    op.create_index('ix_execution_traces_namespace', 'execution_traces', ['namespace'])
    op.create_index('ix_execution_traces_tool_name', 'execution_traces', ['tool_name'])
    op.create_index('ix_execution_traces_orchestration_id', 'execution_traces', ['orchestration_id'])
    op.create_index('ix_execution_traces_pattern_id', 'execution_traces', ['pattern_id'])
    op.create_index('ix_execution_traces_expires_at', 'execution_traces', ['expires_at'])

    # Composite indexes for pattern detection
    op.create_index('idx_execution_traces_pattern_detection', 'execution_traces',
                   ['namespace', 'created_at', 'orchestration_id', 'tool_name'])
    op.create_index('idx_execution_traces_agent_tool', 'execution_traces',
                   ['agent_id', 'tool_name'])
    op.create_index('idx_execution_traces_sequence', 'execution_traces',
                   ['orchestration_id', 'sequence_number'])

    # Table 2: detected_patterns (Layer 2)
    op.create_table(
        'detected_patterns',
        # Primary key
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),

        # Pattern identification
        sa.Column('namespace', sa.String(255), nullable=False,
                  comment='Namespace for isolation (P0-1)'),
        sa.Column('agent_id', sa.String(36), nullable=True,
                  comment='Agent who created this pattern'),

        # Pattern content
        sa.Column('tool_sequence', sa.JSON, nullable=False,
                  comment='Ordered list of tool names in the sequence'),
        sa.Column('pattern_hash', sa.String(64), nullable=False, unique=True,
                  comment='SHA256 hash of tool_sequence for deduplication'),

        # Statistics
        sa.Column('frequency', sa.Integer, nullable=False, server_default='3',
                  comment='Number of occurrences detected'),
        sa.Column('avg_success_rate', sa.Float, nullable=False, server_default='1.0',
                  comment='Average success rate of pattern executions'),
        sa.Column('avg_execution_time_ms', sa.Float, nullable=True,
                  comment='Average total execution time of pattern'),

        # SOP generation
        sa.Column('sop_draft', sa.Text, nullable=True,
                  comment='Auto-generated SOP markdown draft'),
        sa.Column('sop_title', sa.String(255), nullable=True,
                  comment='Generated SOP title'),

        # State machine
        sa.Column('state', sa.String(50), nullable=False, server_default="'DETECTED'",
                  comment='Pattern lifecycle state'),

        # Skill linkage
        sa.Column('skill_id', sa.String(36), nullable=True,
                  comment='Linked Skill ID after promotion'),

        # Validation tracking
        sa.Column('validation_errors', sa.JSON, nullable=True,
                  comment='List of validation failure reasons'),
        sa.Column('validated_at', sa.DateTime(timezone=True), nullable=True,
                  comment='When pattern was validated'),
        sa.Column('approved_by', sa.String(36), nullable=True,
                  comment='Agent who approved the pattern'),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True,
                  comment='When pattern was approved'),

        # Detection metadata
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='When pattern was first detected'),
        sa.Column('last_occurrence_at', sa.DateTime(timezone=True), nullable=True,
                  comment='When pattern was last observed'),

        # Timestamps (from TMWSBase)
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record last update timestamp'),

        # Check constraints
        sa.CheckConstraint(
            "state IN ('DETECTED', 'VALIDATING', 'VALIDATED', 'APPROVED', 'SKILL_CREATED', 'REJECTED')",
            name='ck_detected_patterns_state'),
        sa.CheckConstraint('frequency >= 3',
                          name='ck_detected_patterns_min_frequency'),
        sa.CheckConstraint('avg_success_rate >= 0.0 AND avg_success_rate <= 1.0',
                          name='ck_detected_patterns_success_rate'),

        comment='Detected recurring tool execution patterns for SOP generation'
    )

    # Indexes for detected_patterns
    op.create_index('ix_detected_patterns_namespace', 'detected_patterns', ['namespace'])
    op.create_index('ix_detected_patterns_agent_id', 'detected_patterns', ['agent_id'])
    op.create_index('ix_detected_patterns_state', 'detected_patterns', ['state'])
    op.create_index('idx_detected_patterns_namespace_state', 'detected_patterns',
                   ['namespace', 'state'])
    op.create_index('idx_detected_patterns_agent_state', 'detected_patterns',
                   ['agent_id', 'state'])

    # Table 3: skill_suggestions (Layer 4)
    op.create_table(
        'skill_suggestions',
        # Primary key
        sa.Column('id', sa.String(36), primary_key=True, nullable=False,
                  comment='Primary key UUID (string format)'),

        # Suggestion context
        sa.Column('orchestration_id', sa.String(36), nullable=False,
                  comment='Orchestration where skill was suggested'),
        sa.Column('skill_id', sa.String(36), nullable=False,
                  comment='Suggested skill ID'),
        sa.Column('agent_id', sa.String(36), nullable=False,
                  comment='Agent receiving the suggestion'),
        sa.Column('namespace', sa.String(255), nullable=False,
                  comment='Namespace for isolation (P0-1)'),

        # Suggestion details
        sa.Column('relevance_score', sa.Float, nullable=False,
                  comment='ChromaDB similarity score (0.0-1.0)'),
        sa.Column('suggestion_reason', sa.Text, nullable=True,
                  comment='Reason for suggestion'),

        # Usage tracking
        sa.Column('was_activated', sa.Boolean, nullable=True,
                  comment='Whether the suggested skill was activated'),
        sa.Column('was_helpful', sa.Boolean, nullable=True,
                  comment='User/agent feedback on suggestion helpfulness'),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True,
                  comment='When skill was activated'),
        sa.Column('feedback_at', sa.DateTime(timezone=True), nullable=True,
                  comment='When feedback was provided'),

        # Timestamps (from TMWSBase)
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.current_timestamp(),
                  comment='Record last update timestamp'),

        # Check constraints
        sa.CheckConstraint('relevance_score >= 0.0 AND relevance_score <= 1.0',
                          name='ck_skill_suggestions_relevance_score'),

        # Foreign keys
        sa.ForeignKeyConstraint(['skill_id'], ['skills.id'], ondelete='CASCADE'),

        comment='Skill suggestion tracking for proactive context injection'
    )

    # Indexes for skill_suggestions
    op.create_index('ix_skill_suggestions_orchestration_id', 'skill_suggestions', ['orchestration_id'])
    op.create_index('ix_skill_suggestions_skill_id', 'skill_suggestions', ['skill_id'])
    op.create_index('ix_skill_suggestions_agent_id', 'skill_suggestions', ['agent_id'])
    op.create_index('ix_skill_suggestions_namespace', 'skill_suggestions', ['namespace'])
    op.create_index('idx_skill_suggestions_effectiveness', 'skill_suggestions',
                   ['skill_id', 'was_activated', 'was_helpful'])


def downgrade() -> None:
    """Drop Autonomous Learning System tables."""

    # Drop tables in reverse order (respects foreign key constraints)
    op.drop_table('skill_suggestions')
    op.drop_table('detected_patterns')
    op.drop_table('execution_traces')
