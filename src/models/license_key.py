"""
License Key Database Models

This module defines the SQLAlchemy models for license key storage and usage tracking.

Models:
- LicenseKey: Stores license key metadata and validation data
- LicenseKeyUsage: Tracks license key usage events

Author: Artemis (Technical Perfectionist)
Created: 2025-11-14
Phase: 2B - Database Migration
"""

from datetime import datetime, timezone
from enum import Enum as PyEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

from src.models.base import Base


class TierEnum(str, PyEnum):
    """License tier enumeration (duplicated from license_service to avoid circular import)."""

    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


class LicenseKey(Base):
    """
    License key storage and validation model.

    This model stores license key metadata for persistent validation,
    revocation management, and usage tracking.

    Attributes:
        id: License key UUID (primary key)
        agent_id: Associated agent UUID
        tier: License tier (FREE, PRO, ENTERPRISE)
        license_key_hash: SHA-256 hash of the full license key
        issued_at: Issuance timestamp
        expires_at: Expiration timestamp (None for perpetual)
        is_active: Active status flag
        revoked_at: Revocation timestamp (None if not revoked)
        revoked_reason: Reason for revocation (optional)

    Relationships:
        agent: Associated Agent model
        usage_records: List of LicenseKeyUsage records

    Indexes:
        - idx_license_keys_hash_lookup: Fast lookup by hash + active status
        - idx_license_keys_expiration: Expiration cleanup queries
        - idx_license_keys_agent: Agent-based queries

    Security:
        - license_key_hash stores SHA-256 hash, not plaintext
        - CheckConstraint ensures expires_at > issued_at
        - Revocation is immutable (revoked_at cannot be set to NULL)
    """

    __tablename__ = "license_keys"

    # Primary key
    id: UUID = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)

    # Foreign keys
    agent_id: UUID = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # License metadata
    tier: TierEnum = Column(Enum(TierEnum), nullable=False)
    license_key_hash: str = Column(String(64), nullable=False, unique=True)  # SHA-256

    # Timestamps
    issued_at: datetime = Column(DateTime(timezone=True), nullable=False)
    expires_at: datetime | None = Column(DateTime(timezone=True), nullable=True)

    # Status flags
    is_active: bool = Column(Boolean, default=True, nullable=False)
    revoked_at: datetime | None = Column(DateTime(timezone=True), nullable=True)
    revoked_reason: str | None = Column(Text, nullable=True)

    # Relationships
    agent = relationship("Agent", back_populates="license_keys")
    usage_records = relationship(
        "LicenseKeyUsage",
        back_populates="license_key",
        cascade="all, delete-orphan",
    )

    # Constraints
    __table_args__ = (
        # Expiration must be after issuance
        CheckConstraint(
            "expires_at IS NULL OR expires_at > issued_at",
            name="check_expiration_after_issuance",
        ),
        # Hash lookup index (most frequent query)
        Index(
            "idx_license_keys_hash_lookup",
            "license_key_hash",
            "is_active",
        ),
        # Expiration cleanup index (scheduled jobs)
        Index(
            "idx_license_keys_expiration",
            "expires_at",
            "is_active",
        ),
        # Agent lookup index
        Index(
            "idx_license_keys_agent",
            "agent_id",
            "is_active",
        ),
    )

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"<LicenseKey(id={self.id}, tier={self.tier}, "
            f"active={self.is_active}, expires={self.expires_at})>"
        )

    def is_expired(self) -> bool:
        """
        Check if license key has expired.

        Returns:
            True if expires_at is in the past, False otherwise
            (perpetual licenses return False)
        """
        if self.expires_at is None:
            return False  # Perpetual license
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """
        Check if license key is valid (active, not expired, not revoked).

        Returns:
            True if license is valid for use
        """
        return self.is_active and not self.is_expired() and self.revoked_at is None

    def revoke(self, reason: str | None = None) -> None:
        """
        Revoke this license key.

        Args:
            reason: Optional reason for revocation

        Side Effects:
            - Sets revoked_at to current UTC time
            - Sets revoked_reason if provided
            - Sets is_active to False
        """
        self.revoked_at = datetime.now(timezone.utc)
        self.revoked_reason = reason
        self.is_active = False


class LicenseKeyUsage(Base):
    """
    License key usage tracking model.

    This model tracks individual license key usage events for analytics,
    auditing, and usage-based billing.

    Attributes:
        id: Usage record UUID (primary key)
        license_key_id: Associated license key UUID
        used_at: Usage timestamp
        feature_accessed: Feature name (optional)
        usage_metadata: Additional metadata (JSON)

    Relationships:
        license_key: Associated LicenseKey model

    Indexes:
        - idx_license_key_usage_time: Time-based queries
        - idx_license_key_usage_feature: Feature-based analytics

    Use Cases:
        - Track API calls per license key
        - Monitor feature usage patterns
        - Generate usage reports
        - Detect unusual usage (security monitoring)
    """

    __tablename__ = "license_key_usage"

    # Primary key
    id: UUID = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)

    # Foreign keys
    license_key_id: UUID = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("license_keys.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Usage metadata
    used_at: datetime = Column(DateTime(timezone=True), nullable=False)
    feature_accessed: str | None = Column(String(128), nullable=True)
    usage_metadata: dict | None = Column(Text, nullable=True)  # JSON as TEXT

    # Relationships
    license_key = relationship("LicenseKey", back_populates="usage_records")

    # Indexes
    __table_args__ = (
        # Time-based usage queries
        Index(
            "idx_license_key_usage_time",
            "license_key_id",
            "used_at",
        ),
        # Feature-based analytics
        Index(
            "idx_license_key_usage_feature",
            "license_key_id",
            "feature_accessed",
        ),
    )

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"<LicenseKeyUsage(id={self.id}, "
            f"license_key_id={self.license_key_id}, "
            f"used_at={self.used_at}, feature={self.feature_accessed})>"
        )
