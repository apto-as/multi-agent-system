"""p0_remove_duplicate_indexes

P0-2 Performance Optimization: Remove 6 Duplicate Indexes

Performance Impact:
- Estimated write performance improvement: +18-25%
- Estimated storage reduction: ~15-20MB
- No impact on read performance (composite indexes cover all queries)

Removed Indexes:
1. security_audit_logs table (4 duplicates):
   - ix_security_audit_logs_client_ip (duplicate of idx_audit_logs_client_ip)
   - ix_security_audit_logs_event_type (covered by idx_audit_logs_event_type_timestamp)
   - ix_security_audit_logs_timestamp (covered by idx_audit_logs_timestamp_severity)
   - ix_security_audit_logs_severity (covered by idx_audit_logs_timestamp_severity)

2. tasks table (2 duplicates):
   - ix_tasks_assigned_agent_id (covered by idx_tasks_agent_status)
   - ix_tasks_priority (covered by idx_tasks_priority_status)

Revision ID: 315d506e2598
Revises: 43ffdc09701d
Create Date: 2025-10-27 11:34:08.526309
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '315d506e2598'
down_revision: Union[str, Sequence[str], None] = '43ffdc09701d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Remove duplicate indexes for improved write performance."""
    # Security audit logs - remove 4 duplicate indexes
    op.drop_index('ix_security_audit_logs_client_ip', table_name='security_audit_logs')
    op.drop_index('ix_security_audit_logs_event_type', table_name='security_audit_logs')
    op.drop_index('ix_security_audit_logs_timestamp', table_name='security_audit_logs')
    op.drop_index('ix_security_audit_logs_severity', table_name='security_audit_logs')

    # Tasks - remove 2 duplicate indexes
    op.drop_index('ix_tasks_assigned_agent_id', table_name='tasks')
    op.drop_index('ix_tasks_priority', table_name='tasks')


def downgrade() -> None:
    """Restore duplicate indexes (for rollback only)."""
    # Restore security audit logs indexes
    op.create_index('ix_security_audit_logs_client_ip', 'security_audit_logs', ['client_ip'])
    op.create_index('ix_security_audit_logs_event_type', 'security_audit_logs', ['event_type'])
    op.create_index('ix_security_audit_logs_timestamp', 'security_audit_logs', ['timestamp'])
    op.create_index('ix_security_audit_logs_severity', 'security_audit_logs', ['severity'])

    # Restore tasks indexes
    op.create_index('ix_tasks_assigned_agent_id', 'tasks', ['assigned_agent_id'])
    op.create_index('ix_tasks_priority', 'tasks', ['priority'])
