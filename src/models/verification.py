"""Verification and trust tracking models"""
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text, event
from sqlalchemy.orm import Mapped, mapped_column, relationship, Session

from src.models.base import TMWSBase
from src.core.exceptions import ImmutableRecordError


class VerificationRecord(TMWSBase):
    """Record of a claim verification"""

    __tablename__ = "verification_records"

    agent_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("agents.agent_id", name="fk_verification_agent"),
        nullable=False,
        index=True
    )
    claim_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    claim_content: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    verification_command: Mapped[str] = mapped_column(Text, nullable=False)
    verification_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    accurate: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    evidence_memory_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("memories.id", name="fk_verification_evidence"),
        nullable=True
    )
    verified_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    verified_by_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="verification_records")  # type: ignore
    evidence_memory: Mapped["Memory"] = relationship("Memory")  # type: ignore

    def __repr__(self) -> str:
        return (
            f"<VerificationRecord(id={self.id}, agent={self.agent_id}, "
            f"type={self.claim_type}, accurate={self.accurate})>"
        )


class TrustScoreHistory(TMWSBase):
    """Historical record of trust score changes"""

    __tablename__ = "trust_score_history"

    agent_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("agents.agent_id", name="fk_trust_history_agent"),
        nullable=False,
        index=True
    )
    old_score: Mapped[float] = mapped_column(Float, nullable=False)
    new_score: Mapped[float] = mapped_column(Float, nullable=False)
    verification_record_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("verification_records.id", name="fk_trust_history_verification"),
        nullable=True
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True, default=datetime.utcnow)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="trust_history")  # type: ignore
    verification_record: Mapped[VerificationRecord | None] = relationship("VerificationRecord")

    def __repr__(self) -> str:
        return (
            f"<TrustScoreHistory(agent={self.agent_id}, "
            f"old={self.old_score:.3f}, new={self.new_score:.3f})>"
        )


# Security: Prevent deletion of immutable records (V-TRUST-3, V-TRUST-6)
@event.listens_for(VerificationRecord, "before_delete")
def prevent_verification_record_deletion(mapper, connection, target):
    """Prevent deletion of VerificationRecord (immutable audit evidence)

    Security: V-TRUST-3 - Evidence deletion prevention
    Raises: ImmutableRecordError always (verification records are immutable)
    """
    raise ImmutableRecordError(
        f"Cannot delete VerificationRecord {target.id}: records are immutable for audit trail",
        details={
            "record_id": str(target.id),
            "agent_id": target.agent_id,
            "claim_type": target.claim_type,
            "verified_at": target.verified_at.isoformat() if target.verified_at else None
        }
    )


@event.listens_for(TrustScoreHistory, "before_delete")
def prevent_trust_history_deletion(mapper, connection, target):
    """Prevent deletion of TrustScoreHistory (immutable audit trail)

    Security: V-TRUST-6 - Audit tampering prevention
    Raises: ImmutableRecordError always (trust history is immutable)
    """
    raise ImmutableRecordError(
        f"Cannot delete TrustScoreHistory {target.id}: audit trail is immutable",
        details={
            "record_id": str(target.id),
            "agent_id": target.agent_id,
            "old_score": target.old_score,
            "new_score": target.new_score,
            "changed_at": target.changed_at.isoformat() if target.changed_at else None
        }
    )
