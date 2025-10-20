"""Multi-instance database schema

Revision ID: 004
Revises: 003
Create Date: 2025-01-17

This migration adds support for multiple Claude Code instances sharing
a single database with optimized performance and real-time synchronization.
"""

import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    """Create v2.2.0 schema with multi-instance support"""

    # 1. Add agent instances table for tracking active MCP servers
    op.create_table(
        "agent_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("instance_id", sa.String(100), nullable=False, unique=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, default="active"),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("connected_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("disconnected_at", sa.DateTime(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    # Create indexes for agent instances
    op.create_index("idx_agent_instances_agent_id", "agent_instances", ["agent_id"])
    op.create_index("idx_agent_instances_status", "agent_instances", ["status"])
    op.create_index("idx_agent_instances_heartbeat", "agent_instances", ["last_heartbeat"])

    # 2. Add shared memory table with optimizations
    op.create_table(
        "shared_memories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "embedding", postgresql.ARRAY(sa.Float), nullable=True
        ),  # Will use pgvector column type
        sa.Column("importance", sa.Float(), nullable=False, default=0.5),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("instance_id", sa.String(100), nullable=False),
        sa.Column("visibility", sa.String(50), nullable=False, default="shared"),
        sa.Column("memory_type", sa.String(100), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("access_count", sa.Integer(), default=0),
        sa.Column("last_accessed", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
    )

    # Add pgvector column for embeddings
    op.execute("ALTER TABLE shared_memories ADD COLUMN embedding_vector vector(384)")

    # Create indexes for shared memories
    op.create_index("idx_shared_memories_agent_id", "shared_memories", ["agent_id"])
    op.create_index("idx_shared_memories_instance_id", "shared_memories", ["instance_id"])
    op.create_index("idx_shared_memories_visibility", "shared_memories", ["visibility"])
    op.create_index("idx_shared_memories_importance", "shared_memories", ["importance"])
    op.create_index("idx_shared_memories_created_at", "shared_memories", ["created_at"])
    op.create_index("idx_shared_memories_tags", "shared_memories", ["tags"], postgresql_using="gin")
    op.create_index(
        "idx_shared_memories_metadata", "shared_memories", ["metadata"], postgresql_using="gin"
    )

    # Create IVFFlat index for vector similarity search
    op.execute("""
        CREATE INDEX idx_shared_memories_embedding_vector
        ON shared_memories
        USING ivfflat (embedding_vector vector_cosine_ops)
        WITH (lists = 100)
    """)

    # 3. Add task coordination table
    op.create_table(
        "task_coordination",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_agent", sa.String(100), nullable=False),
        sa.Column("assigned_instance", sa.String(100), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, default="pending"),
        sa.Column("priority", sa.Integer(), nullable=False, default=5),
        sa.Column("lock_acquired_at", sa.DateTime(), nullable=True),
        sa.Column("lock_expires_at", sa.DateTime(), nullable=True),
        sa.Column("result", postgresql.JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="CASCADE"),
    )

    # Create indexes for task coordination
    op.create_index("idx_task_coordination_task_id", "task_coordination", ["task_id"])
    op.create_index("idx_task_coordination_assigned_agent", "task_coordination", ["assigned_agent"])
    op.create_index("idx_task_coordination_status", "task_coordination", ["status"])
    op.create_index("idx_task_coordination_priority", "task_coordination", ["priority"])

    # 4. Add synchronization events table
    op.create_table(
        "sync_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("entity_type", sa.String(100), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("instance_id", sa.String(100), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    # Create indexes for sync events
    op.create_index("idx_sync_events_created_at", "sync_events", ["created_at"])
    op.create_index("idx_sync_events_entity", "sync_events", ["entity_type", "entity_id"])
    op.create_index("idx_sync_events_agent", "sync_events", ["agent_id", "instance_id"])

    # 5. Create notification triggers for real-time sync
    op.execute("""
        CREATE OR REPLACE FUNCTION notify_memory_change()
        RETURNS TRIGGER AS $$
        BEGIN
            PERFORM pg_notify(
                'memory_changes',
                json_build_object(
                    'operation', TG_OP,
                    'memory_id', NEW.id,
                    'agent_id', NEW.agent_id,
                    'instance_id', NEW.instance_id,
                    'visibility', NEW.visibility
                )::text
            );
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER memory_change_trigger
        AFTER INSERT OR UPDATE OR DELETE ON shared_memories
        FOR EACH ROW EXECUTE FUNCTION notify_memory_change();
    """)

    op.execute("""
        CREATE OR REPLACE FUNCTION notify_task_change()
        RETURNS TRIGGER AS $$
        BEGIN
            PERFORM pg_notify(
                'task_changes',
                json_build_object(
                    'operation', TG_OP,
                    'task_id', NEW.task_id,
                    'assigned_agent', NEW.assigned_agent,
                    'status', NEW.status
                )::text
            );
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER task_change_trigger
        AFTER INSERT OR UPDATE OR DELETE ON task_coordination
        FOR EACH ROW EXECUTE FUNCTION notify_task_change();
    """)

    # 6. Add connection pool statistics table
    op.create_table(
        "connection_stats",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("instance_id", sa.String(100), nullable=False),
        sa.Column("pool_size", sa.Integer(), nullable=False),
        sa.Column("active_connections", sa.Integer(), nullable=False),
        sa.Column("idle_connections", sa.Integer(), nullable=False),
        sa.Column("waiting_requests", sa.Integer(), nullable=False),
        sa.Column("total_requests", sa.BigInteger(), nullable=False),
        sa.Column("total_errors", sa.BigInteger(), nullable=False),
        sa.Column("avg_response_time_ms", sa.Float(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_index(
        "idx_connection_stats_instance", "connection_stats", ["instance_id", "recorded_at"]
    )

    # 7. Add cache invalidation table
    op.create_table(
        "cache_invalidations",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("cache_key", sa.String(255), nullable=False),
        sa.Column("invalidated_by", sa.String(100), nullable=False),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_index("idx_cache_invalidations_key", "cache_invalidations", ["cache_key"])
    op.create_index("idx_cache_invalidations_created", "cache_invalidations", ["created_at"])

    # 8. Add performance metrics table
    op.create_table(
        "performance_metrics",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("instance_id", sa.String(100), nullable=False),
        sa.Column("metric_type", sa.String(100), nullable=False),
        sa.Column("operation", sa.String(100), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False, default=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    op.create_index(
        "idx_performance_metrics_instance", "performance_metrics", ["instance_id", "recorded_at"]
    )
    op.create_index(
        "idx_performance_metrics_type", "performance_metrics", ["metric_type", "operation"]
    )

    # 9. Create materialized view for frequently accessed memories
    op.execute("""
        CREATE MATERIALIZED VIEW mv_recent_shared_memories AS
        SELECT
            id, content, importance, agent_id, visibility,
            memory_type, tags, created_at
        FROM shared_memories
        WHERE created_at > NOW() - INTERVAL '7 days'
            AND visibility = 'shared'
        ORDER BY importance DESC, created_at DESC
        WITH DATA;
    """)

    op.execute("""
        CREATE UNIQUE INDEX idx_mv_recent_shared_memories_id
        ON mv_recent_shared_memories (id);
    """)

    # 10. Create function for automatic cache refresh
    op.execute("""
        CREATE OR REPLACE FUNCTION refresh_memory_cache()
        RETURNS void AS $$
        BEGIN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_recent_shared_memories;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # 11. Add instance cleanup function
    op.execute("""
        CREATE OR REPLACE FUNCTION cleanup_stale_instances()
        RETURNS void AS $$
        BEGIN
            UPDATE agent_instances
            SET status = 'disconnected',
                disconnected_at = NOW()
            WHERE status = 'active'
                AND last_heartbeat < NOW() - INTERVAL '5 minutes';

            DELETE FROM agent_instances
            WHERE status = 'disconnected'
                AND disconnected_at < NOW() - INTERVAL '24 hours';
        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade():
    """Drop v2.2.0 schema"""

    # Drop functions
    op.execute("DROP FUNCTION IF EXISTS cleanup_stale_instances()")
    op.execute("DROP FUNCTION IF EXISTS refresh_memory_cache()")

    # Drop materialized view
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_recent_shared_memories")

    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS memory_change_trigger ON shared_memories")
    op.execute("DROP TRIGGER IF EXISTS task_change_trigger ON task_coordination")
    op.execute("DROP FUNCTION IF EXISTS notify_memory_change()")
    op.execute("DROP FUNCTION IF EXISTS notify_task_change()")

    # Drop tables
    op.drop_table("performance_metrics")
    op.drop_table("cache_invalidations")
    op.drop_table("connection_stats")
    op.drop_table("sync_events")
    op.drop_table("task_coordination")
    op.drop_table("shared_memories")
    op.drop_table("agent_instances")
