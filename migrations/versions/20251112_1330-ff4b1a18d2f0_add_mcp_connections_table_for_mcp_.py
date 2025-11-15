"""Add mcp_connections table for MCP integration

Revision ID: ff4b1a18d2f0
Revises: 26bc792cc433
Create Date: 2025-11-12 13:30:44.063857

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ff4b1a18d2f0'
down_revision: Union[str, Sequence[str], None] = '26bc792cc433'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add mcp_connections table for MCP Integration (Phase 1-1-B)."""
    op.create_table(
        'mcp_connections',
        sa.Column('id', sa.String(length=36), nullable=False, comment='Primary key UUID (string format)'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False, comment='Record creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False, comment='Record last update timestamp'),
        sa.Column('server_name', sa.Text(), nullable=False, comment='Name of the MCP server'),
        sa.Column('namespace', sa.Text(), nullable=False, comment='Namespace for multi-tenant isolation'),
        sa.Column('agent_id', sa.Text(), nullable=False, comment='Agent that owns this connection'),
        sa.Column('status', sa.Text(), nullable=False, comment='Connection status: disconnected, connecting, active, error'),
        sa.Column('config_json', sa.JSON(), nullable=False, comment='Connection configuration as JSON (server_name, url, timeout, etc.)'),
        sa.Column('tools_json', sa.JSON(), server_default=sa.text("'[]'"), nullable=False, comment='Discovered tools as JSON array'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error message if status is ERROR'),
        sa.Column('error_at', sa.DateTime(timezone=True), nullable=True, comment='When error occurred'),
        sa.Column('connected_at', sa.DateTime(timezone=True), nullable=True, comment='When connection became ACTIVE'),
        sa.Column('disconnected_at', sa.DateTime(timezone=True), nullable=True, comment='When connection was closed'),
        sa.PrimaryKeyConstraint('id'),
        comment='MCP server connections for Phase 1-1 Infrastructure Layer'
    )

    # Create indexes for performance
    op.create_index('ix_mcp_connection_namespace_agent', 'mcp_connections', ['namespace', 'agent_id'])
    op.create_index('ix_mcp_connection_status', 'mcp_connections', ['status'])
    op.create_index('ix_mcp_connection_server_name', 'mcp_connections', ['server_name'])


def downgrade() -> None:
    """Remove mcp_connections table."""
    op.drop_index('ix_mcp_connection_server_name', table_name='mcp_connections')
    op.drop_index('ix_mcp_connection_status', table_name='mcp_connections')
    op.drop_index('ix_mcp_connection_namespace_agent', table_name='mcp_connections')
    op.drop_table('mcp_connections')
