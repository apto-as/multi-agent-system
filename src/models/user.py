"""
User and API Key models for TMWS authentication system.
Implements production-grade security with role-based access control.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Boolean, DateTime, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import MetadataMixin, TMWSBase


class UserRole(str, Enum):
    """User roles for role-based access control."""

    SUPER_ADMIN = "super_admin"  # Full system access
    ADMIN = "admin"  # Administrative access
    USER = "user"  # Standard user access
    READONLY = "readonly"  # Read-only access
    SERVICE = "service"  # Service account access


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    PENDING = "pending"


class APIKeyScope(str, Enum):
    """API key access scopes."""

    FULL = "full"  # Full API access
    READ = "read"  # Read-only access
    WRITE = "write"  # Read and write access
    ADMIN = "admin"  # Administrative operations
    MEMORY = "memory"  # Memory operations only
    TASKS = "tasks"  # Task operations only
    WORKFLOWS = "workflows"  # Workflow operations only


class User(TMWSBase, MetadataMixin):
    """User model with comprehensive security features."""

    __tablename__ = "users"

    # Primary identification
    username: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        comment="Unique username (2-64 characters)",
    )

    email: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True, comment="User email address"
    )

    full_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True, comment="User's full name"
    )

    # Authentication
    password_hash: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Bcrypt hashed password"
    )

    password_salt: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Password salt for additional security"
    )

    # Security tracking
    failed_login_attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, comment="Count of failed login attempts"
    )

    last_failed_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Timestamp of last failed login"
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of last successful login",
    )

    last_login_ip: Mapped[str | None] = mapped_column(
        String(45),  # IPv6 support
        nullable=True,
        comment="IP address of last login",
    )

    # Account management
    status: Mapped[UserStatus] = mapped_column(
        sa.Enum(UserStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        default=UserStatus.ACTIVE,
        index=True,
    )

    roles: Mapped[list[UserRole]] = mapped_column(
        JSON, nullable=False, default=lambda: [UserRole.USER], comment="List of user roles"
    )

    permissions: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict, comment="Additional granular permissions"
    )

    # MFA and security
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, comment="Multi-factor authentication enabled"
    )

    mfa_secret: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="TOTP secret for MFA"
    )

    backup_codes: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=True, comment="MFA backup codes"
    )

    # Session management
    force_password_change: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, comment="Force password change on next login"
    )

    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="When password was last changed"
    )

    session_timeout_minutes: Mapped[int] = mapped_column(
        sa.Integer,
        nullable=False,
        default=480,  # 8 hours
        comment="Session timeout in minutes",
    )

    # Agent association
    preferred_agent_id: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Preferred agent for operations"
    )

    agent_namespace: Mapped[str] = mapped_column(
        Text, nullable=False, default="default", comment="User's agent namespace"
    )

    # Audit tracking
    created_by: Mapped[str | None] = mapped_column(
        String(64), nullable=True, comment="Username of user who created this account"
    )

    last_modified_by: Mapped[str | None] = mapped_column(
        String(64), nullable=True, comment="Username of user who last modified this account"
    )

    # Relationships
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey", back_populates="user", cascade="all, delete-orphan", lazy="select"
    )

    # SQLite-compatible indexes (v2.2.6)
    __table_args__ = (
        Index("ix_user_status_active", "status", "last_login_at"),
        Index("ix_user_email_status", "email", "status"),
        Index("ix_user_namespace", "agent_namespace"),
    )

    def __repr__(self) -> str:
        return f"<User(username='{self.username}', status='{self.status}')>"

    def has_role(self, role: UserRole) -> bool:
        """Check if user has a specific role."""
        return role in self.roles

    def has_permission(self, permission: str, resource: str = None) -> bool:
        """Check if user has a specific permission."""
        # Super admin has all permissions
        if UserRole.SUPER_ADMIN in self.roles:
            return True

        # Check granular permissions
        if resource:
            resource_perms = self.permissions.get(resource, {})
            return resource_perms.get(permission, False)

        return self.permissions.get(permission, False)

    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.status == UserStatus.ACTIVE

    def is_locked(self) -> bool:
        """Check if user account is locked."""
        return self.status in [UserStatus.LOCKED, UserStatus.SUSPENDED]

    def should_force_password_change(self) -> bool:
        """Check if password change should be forced."""
        if self.force_password_change:
            return True

        # Force password change if it's older than 90 days
        if self.password_changed_at:
            days_since_change = (datetime.now(timezone.utc) - self.password_changed_at).days
            return days_since_change > 90

        return False

    def increment_failed_login(self) -> None:
        """Increment failed login counter."""
        self.failed_login_attempts += 1
        self.last_failed_login_at = datetime.now(timezone.utc)

        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.status = UserStatus.LOCKED

    def reset_failed_login(self) -> None:
        """Reset failed login counter after successful login."""
        self.failed_login_attempts = 0
        self.last_failed_login_at = None
        self.last_login_at = datetime.now(timezone.utc)

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert user to dictionary."""
        data = {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "status": self.status.value,
            "roles": [role.value for role in self.roles],
            "mfa_enabled": self.mfa_enabled,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "agent_namespace": self.agent_namespace,
            "preferred_agent_id": self.preferred_agent_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_sensitive:
            data.update(
                {
                    "permissions": self.permissions,
                    "failed_login_attempts": self.failed_login_attempts,
                    "force_password_change": self.force_password_change,
                    "session_timeout_minutes": self.session_timeout_minutes,
                }
            )

        return data


class APIKey(TMWSBase, MetadataMixin):
    """API Key model for service authentication."""

    __tablename__ = "api_keys"

    # Key identification
    key_id: Mapped[str] = mapped_column(
        String(32), nullable=False, unique=True, index=True, comment="Public key identifier"
    )

    name: Mapped[str] = mapped_column(
        String(128), nullable=False, comment="Human-readable key name"
    )

    description: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Key description and purpose"
    )

    # Security
    key_hash: Mapped[str] = mapped_column(Text, nullable=False, comment="Hashed API key value")

    key_prefix: Mapped[str] = mapped_column(
        String(8), nullable=False, comment="Key prefix for identification (first 8 chars)"
    )

    # Access control
    scopes: Mapped[list[APIKeyScope]] = mapped_column(
        JSON, nullable=False, default=lambda: [APIKeyScope.READ], comment="API key access scopes"
    )

    allowed_ips: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=True, comment="IP addresses allowed to use this key"
    )

    rate_limit_per_hour: Mapped[int | None] = mapped_column(
        sa.Integer, nullable=True, comment="Custom rate limit for this key"
    )

    # Status and lifecycle
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True, comment="Key expiration timestamp"
    )

    # Usage tracking
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="When key was last used"
    )

    last_used_ip: Mapped[str | None] = mapped_column(
        String(45), nullable=True, comment="IP address of last use"
    )

    total_requests: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, comment="Total requests made with this key"
    )

    # User relationship
    user_id: Mapped[str] = mapped_column(
        String(36),  # Match id column type (UUID as string)
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user: Mapped[User] = relationship("User", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_key_active", "is_active", "expires_at"),
        Index("ix_api_key_user_active", "user_id", "is_active"),
        Index("ix_api_key_prefix", "key_prefix"),
    )

    def __repr__(self) -> str:
        return f"<APIKey(key_id='{self.key_id}', name='{self.name}')>"

    def is_valid(self) -> bool:
        """Check if API key is valid and not expired."""
        if not self.is_active:
            return False

        return not (self.expires_at and datetime.now(timezone.utc) > self.expires_at)

    def has_scope(self, required_scope: APIKeyScope) -> bool:
        """Check if API key has required scope."""
        return required_scope in self.scopes or APIKeyScope.FULL in self.scopes

    def is_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP address is allowed to use this key."""
        if not self.allowed_ips:
            return True  # No IP restrictions

        return ip_address in self.allowed_ips

    def record_usage(self, ip_address: str) -> None:
        """Record API key usage."""
        self.last_used_at = datetime.now(timezone.utc)
        self.last_used_ip = ip_address
        self.total_requests += 1

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert API key to dictionary."""
        data = {
            "key_id": self.key_id,
            "name": self.name,
            "description": self.description,
            "key_prefix": self.key_prefix,
            "scopes": [scope.value for scope in self.scopes],
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "total_requests": self.total_requests,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

        if include_sensitive:
            data.update(
                {
                    "allowed_ips": self.allowed_ips,
                    "rate_limit_per_hour": self.rate_limit_per_hour,
                    "last_used_ip": self.last_used_ip,
                }
            )

        return data


class RefreshToken(TMWSBase):
    """Refresh token for JWT token renewal."""

    __tablename__ = "refresh_tokens"

    # Token identification
    token_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True, comment="Unique token identifier"
    )

    token_hash: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Hashed refresh token value"
    )

    # Token lifecycle
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True, comment="Token expiration timestamp"
    )

    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    # Usage tracking
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # User relationship
    user_id: Mapped[str] = mapped_column(
        String(36),  # Match id column type (UUID as string)
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user: Mapped[User] = relationship("User")

    __table_args__ = (
        Index("ix_refresh_token_valid", "is_revoked", "expires_at"),
        Index("ix_refresh_token_user", "user_id", "is_revoked"),
    )

    def is_valid(self) -> bool:
        """Check if refresh token is valid."""
        if self.is_revoked:
            return False

        return datetime.now(timezone.utc) < self.expires_at

    def revoke(self) -> None:
        """Revoke the refresh token."""
        self.is_revoked = True
