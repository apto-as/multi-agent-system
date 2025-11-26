"""
Token Consumption Model - TMWS Token Budget Tracking

This model represents hourly token consumption records for agents,
used by the TokenBudgetService for budget enforcement.

Database Schema (SQLite):
- token_consumption table with composite primary key (agent_id, window_hour)
- Atomic upsert operations for race-condition-free tracking
- Indexes for efficient cleanup and agent lookup

Author: Artemis (Technical Perfectionist)
Created: 2025-11-24
Phase: 2D-2 - V-2 Progressive Disclosure Implementation (SQLite-Only)
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from src.core.database import Base


class TokenConsumption(Base):
    """
    Token consumption tracking for hourly budget enforcement.

    This model tracks token usage per agent per hour for the Progressive
    Disclosure system (v2.4.0).

    Attributes:
        agent_id: UUID of agent consuming tokens (FK to agents.id)
        window_hour: Hourly window identifier (format: YYYYMMDDHH)
        consumption_count: Total tokens consumed in this hour
        created_at: Record creation timestamp
        updated_at: Last update timestamp
        agent: Relationship to Agent model

    Indexes:
        - idx_token_consumption_cleanup: On window_hour (for automatic cleanup)
        - idx_token_consumption_agent_hour: On (agent_id, window_hour) (for lookups)

    Primary Key:
        Composite: (agent_id, window_hour)

    Example:
        >>> # Track token consumption
        >>> consumption = TokenConsumption(
        ...     agent_id=UUID("550e8400..."),
        ...     window_hour="2025112416",
        ...     consumption_count=1500
        ... )
        >>> session.add(consumption)
        >>> await session.commit()

        >>> # Atomic increment with upsert
        >>> stmt = insert(TokenConsumption).values(
        ...     agent_id=agent_id,
        ...     window_hour=window_hour,
        ...     consumption_count=tokens
        ... ).on_conflict_do_update(
        ...     index_elements=["agent_id", "window_hour"],
        ...     set_={"consumption_count": TokenConsumption.consumption_count + tokens}
        ... )
    """

    __tablename__ = "token_consumption"

    # Composite primary key (agent_id, window_hour)
    agent_id = Column(
        String(36),  # UUID stored as string
        ForeignKey("agents.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
        comment="Agent UUID (FK to agents.id)",
    )

    window_hour = Column(
        String(10),  # Format: YYYYMMDDHH (e.g., "2025112416")
        primary_key=True,
        nullable=False,
        comment="Hourly window identifier (format: YYYYMMDDHH)",
    )

    consumption_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Total tokens consumed in this hour",
    )

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="Record creation timestamp",
    )

    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        comment="Last update timestamp",
    )

    # Relationship to Agent model
    agent = relationship("Agent", back_populates="token_consumptions")

    def __repr__(self) -> str:
        """String representation of TokenConsumption."""
        return (
            f"<TokenConsumption("
            f"agent_id={self.agent_id}, "
            f"window_hour={self.window_hour}, "
            f"consumption_count={self.consumption_count}"
            f")>"
        )

    def to_dict(self) -> dict:
        """
        Convert TokenConsumption to dictionary.

        Returns:
            Dictionary representation of token consumption record

        Example:
            >>> consumption = TokenConsumption(...)
            >>> data = consumption.to_dict()
            >>> print(data)
            {
                "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                "window_hour": "2025112416",
                "consumption_count": 1500,
                "created_at": "2025-11-24T16:00:00+00:00",
                "updated_at": "2025-11-24T16:30:00+00:00"
            }
        """
        return {
            "agent_id": self.agent_id,
            "window_hour": self.window_hour,
            "consumption_count": self.consumption_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
