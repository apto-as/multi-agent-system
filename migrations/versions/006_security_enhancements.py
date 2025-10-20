"""Security Enhancements for Pattern Execution

Revision ID: 006
Revises: 005
Create Date: 2025-01-09

Implements Hestia's security recommendations:
- Enhanced audit logging table
- Pattern execution tracking
- Security event monitoring
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add security enhancement tables"""

    # Enhanced audit log table
    op.create_table(
        "audit_logs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("event_type", sa.String(50), nullable=False, index=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("agent_id", sa.String(100), nullable=True, index=True),
        sa.Column("pattern_name", sa.String(100), nullable=True, index=True),
        sa.Column("success", sa.Boolean, nullable=True),
        sa.Column("execution_time_ms", sa.Integer, nullable=True),
        sa.Column("tokens_used", sa.Integer, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column(
            "timestamp", sa.TIMESTAMP, nullable=False, server_default=sa.text("NOW()"), index=True
        ),
    )

    # Composite indexes for common queries
    op.create_index("idx_audit_event_time", "audit_logs", ["event_type", "timestamp"])
    op.create_index("idx_audit_agent_pattern", "audit_logs", ["agent_id", "pattern_name"])
    op.create_index("idx_audit_severity_time", "audit_logs", ["severity", "timestamp"])

    # Pattern permissions table
    op.create_table(
        "pattern_permissions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("pattern_name", sa.String(100), nullable=False, unique=True, index=True),
        sa.Column("required_role", sa.String(50), nullable=False),
        sa.Column("allowed_agents", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("rate_limit_per_minute", sa.Integer, nullable=False, server_default="60"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.TIMESTAMP, nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP, nullable=False, server_default=sa.text("NOW()")),
    )

    # Security events table (for alerting)
    op.create_table(
        "security_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("event_type", sa.String(50), nullable=False, index=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("agent_id", sa.String(100), nullable=True, index=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("context", postgresql.JSONB, nullable=True),
        sa.Column("resolved", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("resolved_at", sa.TIMESTAMP, nullable=True),
        sa.Column("resolved_by", sa.String(100), nullable=True),
        sa.Column(
            "created_at", sa.TIMESTAMP, nullable=False, server_default=sa.text("NOW()"), index=True
        ),
    )

    # Index for unresolved security events
    op.create_index("idx_security_unresolved", "security_events", ["resolved", "created_at"])

    # Trigger for audit log retention (optional - can be configured)
    # Keep only last 90 days of audit logs by default
    op.execute("""
        CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
        RETURNS trigger AS $$
        BEGIN
            DELETE FROM audit_logs
            WHERE timestamp < NOW() - INTERVAL '90 days';
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trigger_cleanup_audit_logs
        AFTER INSERT ON audit_logs
        FOR EACH STATEMENT
        EXECUTE FUNCTION cleanup_old_audit_logs();
    """)


def downgrade() -> None:
    """Remove security enhancement tables"""

    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_cleanup_audit_logs ON audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS cleanup_old_audit_logs();")

    # Drop tables
    op.drop_table("security_events")
    op.drop_table("pattern_permissions")
    op.drop_table("audit_logs")
