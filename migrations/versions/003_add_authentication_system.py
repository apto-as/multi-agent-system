"""Add authentication system with User and APIKey models

Revision ID: 003
Revises: 002
Create Date: 2025-01-05 12:00:00.000000

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add authentication system tables."""

    # Create user status and role enums
    user_status_enum = postgresql.ENUM(
        'active', 'inactive', 'suspended', 'locked', 'pending',
        name='userstatus'
    )
    user_status_enum.create(op.get_bind())

    user_role_enum = postgresql.ENUM(
        'super_admin', 'admin', 'user', 'readonly', 'service',
        name='userrole'
    )
    user_role_enum.create(op.get_bind())

    api_key_scope_enum = postgresql.ENUM(
        'full', 'read', 'write', 'admin', 'memory', 'tasks', 'workflows',
        name='apikeyscope'
    )
    api_key_scope_enum.create(op.get_bind())

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('username', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('full_name', sa.String(255), nullable=True),

        # Authentication
        sa.Column('password_hash', sa.Text, nullable=False),
        sa.Column('password_salt', sa.Text, nullable=False),

        # Security tracking
        sa.Column('failed_login_attempts', sa.Integer, nullable=False, default=0),
        sa.Column('last_failed_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column('last_login_ip', sa.String(45), nullable=True),

        # Account management
        sa.Column('status', user_status_enum, nullable=False, default='active', index=True),
        sa.Column('roles', postgresql.JSON, nullable=False, default=['user']),
        sa.Column('permissions', postgresql.JSON, nullable=False, default={}),

        # MFA and security
        sa.Column('mfa_enabled', sa.Boolean, nullable=False, default=False),
        sa.Column('mfa_secret', sa.Text, nullable=True),
        sa.Column('backup_codes', postgresql.JSON, nullable=True),

        # Session management
        sa.Column('force_password_change', sa.Boolean, nullable=False, default=False),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('session_timeout_minutes', sa.Integer, nullable=False, default=480),

        # Agent association
        sa.Column('preferred_agent_id', sa.Text, nullable=True),
        sa.Column('agent_namespace', sa.Text, nullable=False, default='default'),

        # Audit tracking
        sa.Column('created_by', sa.String(64), nullable=True),
        sa.Column('last_modified_by', sa.String(64), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),

        # Metadata
        sa.Column('metadata', postgresql.JSON, nullable=False, default={}),
    )

    # Create indexes for users
    op.create_index('ix_user_status_active', 'users', ['status', 'last_login_at'])
    op.create_index('ix_user_email_status', 'users', ['email', 'status'])
    op.create_index('ix_user_namespace', 'users', ['agent_namespace'])
    op.create_index(
        'ix_user_active_username',
        'users',
        ['username'],
        postgresql_where=sa.text("status = 'active'")
    )

    # Create api_keys table
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('key_id', sa.String(32), nullable=False, unique=True, index=True),
        sa.Column('name', sa.String(128), nullable=False),
        sa.Column('description', sa.Text, nullable=True),

        # Security
        sa.Column('key_hash', sa.Text, nullable=False),
        sa.Column('key_prefix', sa.String(8), nullable=False, index=True),

        # Access control
        sa.Column('scopes', postgresql.JSON, nullable=False, default=['read']),
        sa.Column('allowed_ips', postgresql.JSON, nullable=True),
        sa.Column('rate_limit_per_hour', sa.Integer, nullable=True),

        # Status and lifecycle
        sa.Column('is_active', sa.Boolean, nullable=False, default=True, index=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True, index=True),

        # Usage tracking
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_ip', sa.String(45), nullable=True),
        sa.Column('total_requests', sa.Integer, nullable=False, default=0),

        # User relationship
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),

        # Metadata
        sa.Column('metadata', postgresql.JSON, nullable=False, default={}),
    )

    # Create indexes for api_keys
    op.create_index('ix_api_key_active', 'api_keys', ['is_active', 'expires_at'])
    op.create_index('ix_api_key_user_active', 'api_keys', ['user_id', 'is_active'])

    # Create refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('token_id', sa.String(64), nullable=False, unique=True, index=True),
        sa.Column('token_hash', sa.Text, nullable=False),

        # Token lifecycle
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('is_revoked', sa.Boolean, nullable=False, default=False, index=True),

        # Usage tracking
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),

        # User relationship
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Create indexes for refresh_tokens
    op.create_index('ix_refresh_token_valid', 'refresh_tokens', ['is_revoked', 'expires_at'])
    op.create_index('ix_refresh_token_user', 'refresh_tokens', ['user_id', 'is_revoked'])

    # Add updated_at trigger for users
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)

    op.execute("""
        CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    """)

    op.execute("""
        CREATE TRIGGER update_api_keys_updated_at
        BEFORE UPDATE ON api_keys
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    """)

    op.execute("""
        CREATE TRIGGER update_refresh_tokens_updated_at
        BEFORE UPDATE ON refresh_tokens
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    """)

    # NOTE: Default admin user removed for security
    # Admin user should be created via secure setup process:
    # python -m tmws.setup create-admin or via environment variables


def downgrade() -> None:
    """Remove authentication system tables."""

    # Drop triggers
    op.execute("DROP TRIGGER IF EXISTS update_users_updated_at ON users;")
    op.execute("DROP TRIGGER IF EXISTS update_api_keys_updated_at ON api_keys;")
    op.execute("DROP TRIGGER IF EXISTS update_refresh_tokens_updated_at ON refresh_tokens;")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column();")

    # Drop tables (in reverse dependency order)
    op.drop_table('refresh_tokens')
    op.drop_table('api_keys')
    op.drop_table('users')

    # Drop enums
    sa.Enum(name='apikeyscope').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='userrole').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='userstatus').drop(op.get_bind(), checkfirst=True)
