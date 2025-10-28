"""Base model classes for TMWS database models.

Architecture: SQLite + Chroma (lightweight, zero-config)
- SQLite: Metadata, relationships, ACID transactions
- Chroma: Vector storage for semantic search
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

# Import Base from core.database to ensure consistency across the application
from src.core.database import Base


class UUIDMixin:
    """Mixin for UUID primary key (SQLite-compatible)."""

    id: Mapped[str] = mapped_column(
        String(36),  # UUID as string (e.g., "550e8400-e29b-41d4-a716-446655440000")
        primary_key=True,
        default=lambda: str(uuid4()),
        nullable=False,
        comment="Primary key UUID (string format)",
    )


class TimestampMixin:
    """Mixin for timestamp fields."""

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        comment="Record creation timestamp",
    )

    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
        comment="Record last update timestamp",
    )


class MetadataMixin:
    """Mixin for JSON metadata fields (SQLite-compatible)."""

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",  # Actual column name in database
        JSON,  # Standard JSON type (SQLite-compatible)
        nullable=False,
        default=dict,
        server_default=sa.text("'{}'"),  # SQLite-compatible default
        comment="JSON metadata",
    )


class TMWSBase(Base, UUIDMixin, TimestampMixin):
    """Base class for all TMWS models with common fields."""

    __abstract__ = True

    def to_dict(self) -> dict[str, Any]:
        """Convert model to dictionary."""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            # UUID is already stored as string in SQLite
            result[column.name] = value
        return result

    def update_from_dict(self, data: dict[str, Any]) -> None:
        """Update model from dictionary."""
        for key, value in data.items():
            if hasattr(self, key) and key not in ("id", "created_at"):
                setattr(self, key, value)

    def __repr__(self) -> str:
        """String representation of the model."""
        return f"<{self.__class__.__name__}(id={self.id})>"
