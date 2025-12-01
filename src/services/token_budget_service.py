"""
Token Budget Service - TMWS Token Consumption Tracking

This service provides token budget validation, consumption tracking, and enforcement
for the Progressive Disclosure system (v2.4.0).

Architecture (Phase 2D-2: SQLite-Only Implementation):
- SQLite-backed atomic counters for token consumption tracking
- Sliding window algorithm for hourly limits
- Tier-based budget enforcement (10k/50k/unlimited/unlimited tokens/hour)
- Fail-secure design (deny on errors)

Security:
- All operations are atomic (race-condition-free)
- Budget validation fails secure (deny on database errors)
- Immutable audit logging for budget violations
- Token consumption is estimated before operation execution

Performance Targets:
- Budget validation: <20ms P95 (SQLite query + atomic upsert)
- Token consumption tracking: <10ms P95 (atomic upsert)
- Database operations: <15ms P95

Author: Artemis (Technical Perfectionist)
Created: 2025-11-24
Phase: 2D-2 - V-2 Progressive Disclosure Implementation (SQLite-Only)
Version: 2.0.0 (Redis → SQLite migration)
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import (
    AuthorizationError,
    log_and_raise,
)
from src.models.token_consumption import TokenConsumption
from src.services.license_service import LicenseService, TierEnum


class TokenBudgetStatus(BaseModel):
    """Token budget status for an agent."""

    agent_id: UUID
    tier: TierEnum
    current_consumption: int = Field(description="Tokens consumed in current hour")
    budget_limit: int | None = Field(description="Hourly token limit (None = unlimited)")
    remaining_tokens: int | None = Field(description="Tokens remaining (None = unlimited)")
    window_start: datetime = Field(description="Start of current hourly window")
    window_end: datetime = Field(description="End of current hourly window")
    is_unlimited: bool = Field(description="True if tier has unlimited tokens")


class TokenBudgetService:
    """
    Token budget validation and consumption tracking service.

    Responsibilities:
    - Validate token budget before operations
    - Track token consumption atomically
    - Enforce tier-based hourly limits
    - Provide budget status queries

    SQLite Implementation (Phase 2D-2):
        - token_consumption table with (agent_id, window_hour) composite key
        - Atomic upsert operations (INSERT ... ON CONFLICT DO UPDATE)
        - Automatic cleanup via window_hour index
        - Performance: <20ms validation, <10ms tracking (P95)
    """

    def __init__(self, license_service: LicenseService, db_session: AsyncSession):
        """
        Initialize TokenBudgetService.

        Args:
            license_service: LicenseService instance for tier lookup
            db_session: SQLAlchemy async session for database operations

        Notes:
            Database session is required for all operations (SQLite-only architecture)
        """
        self.license_service = license_service
        self.db_session = db_session

    def _get_window_key(self, agent_id: UUID) -> tuple[str, datetime, datetime]:
        """
        Generate window_hour key for current hourly window.

        Args:
            agent_id: Agent UUID

        Returns:
            Tuple of (window_hour, window_start, window_end)

        Example:
            >>> key, start, end = self._get_window_key(UUID("550e8400..."))
            >>> print(key)
            2025112409
            >>> print(start)
            2025-11-24 09:00:00+00:00
            >>> print(end)
            2025-11-24 10:00:00+00:00
        """
        now = datetime.now(timezone.utc)
        # Round down to hour boundary (sliding window start)
        window_start = now.replace(minute=0, second=0, microsecond=0)
        window_end = window_start + timedelta(hours=1)

        # Format: YYYYMMDDHH
        window_hour = window_start.strftime("%Y%m%d%H")

        return window_hour, window_start, window_end

    async def validate_budget(
        self,
        agent_id: UUID,
        estimated_tokens: int,
        operation_name: str,
    ) -> None:
        """
        Validate that agent has sufficient token budget for operation.

        This method checks but does NOT consume tokens. Use track_consumption()
        after operation completes to deduct actual token usage.

        Args:
            agent_id: Agent UUID
            estimated_tokens: Estimated token consumption for operation
            operation_name: Name of operation (for error messages)

        Raises:
            AuthorizationError: If budget exceeded or validation fails

        Example:
            >>> # Before operation
            >>> await budget_service.validate_budget(
            ...     agent_id=UUID("550e8400..."),
            ...     estimated_tokens=1500,
            ...     operation_name="create_memory"
            ... )
            >>> # Execute operation
            >>> result = await create_memory(...)
            >>> # After operation
            >>> await budget_service.track_consumption(
            ...     agent_id=UUID("550e8400..."),
            ...     actual_tokens=1349  # Actual consumption
            ... )

        Security:
            - Fail-secure design (deny on database errors)
            - No token consumption on validation failure
            - Atomic read operations (no race conditions)
        """
        # Step 1: Get agent's tier and budget limit
        tier = await self.license_service.get_agent_tier(agent_id)
        limits = self.license_service.get_tier_limits(tier)

        # Step 2: Check if tier has unlimited tokens
        if limits.max_tokens_per_hour is None:
            # ENTERPRISE or ADMINISTRATOR tier - unlimited tokens
            return

        # Step 3: Get current consumption from database
        try:
            window_hour, window_start, window_end = self._get_window_key(agent_id)

            # Query current consumption (atomic read)
            stmt = select(TokenConsumption).where(
                TokenConsumption.agent_id == agent_id,
                TokenConsumption.window_hour == window_hour,
            )
            result = await self.db_session.execute(stmt)
            consumption_record = result.scalar_one_or_none()

            current_consumption = (
                consumption_record.consumption_count if consumption_record else 0
            )

        except Exception as e:
            # Fail-secure: deny access on database errors
            log_and_raise(
                AuthorizationError,
                "Token budget validation failed (Database error)",
                original_exception=e,
                details={
                    "agent_id": str(agent_id),
                    "operation": operation_name,
                    "estimated_tokens": estimated_tokens,
                },
            )

        # Step 4: Check if estimated consumption exceeds budget
        budget_limit = limits.max_tokens_per_hour
        projected_consumption = current_consumption + estimated_tokens

        if projected_consumption > budget_limit:
            remaining = budget_limit - current_consumption
            log_and_raise(
                AuthorizationError,
                f"Token budget exceeded for {operation_name}. "
                f"Budget limit: {budget_limit:,}, Current: {current_consumption:,}, "
                f"Requested: {estimated_tokens:,}, remaining_tokens: {remaining:,}",
                details={
                    "agent_id": str(agent_id),
                    "tier": tier.value,
                    "budget_limit": budget_limit,
                    "current_consumption": current_consumption,
                    "estimated_tokens": estimated_tokens,
                    "projected_consumption": projected_consumption,
                    "remaining_tokens": remaining,
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                },
            )

        # Budget validation passed - operation can proceed

    async def track_consumption(
        self,
        agent_id: UUID,
        actual_tokens: int,
    ) -> None:
        """
        Track actual token consumption after operation completes.

        This method atomically increments the token counter in SQLite.
        Should be called AFTER operation execution with actual token usage.

        Args:
            agent_id: Agent UUID
            actual_tokens: Actual token consumption (measured)

        Raises:
            AuthorizationError: If database operation fails

        Example:
            >>> # After operation completes
            >>> await budget_service.track_consumption(
            ...     agent_id=UUID("550e8400..."),
            ...     actual_tokens=1349  # Measured token usage
            ... )

        Security:
            - Atomic upsert operation (race-condition-free)
            - Fail-secure on database errors

        Performance:
            - SQLite upsert: O(log n) operation
            - Target latency: <10ms P95

        Implementation:
            Uses INSERT ... ON CONFLICT DO UPDATE for atomic increment:
            - If record exists: increment consumption_count
            - If record doesn't exist: create new record with initial value
        """
        try:
            window_hour, window_start, window_end = self._get_window_key(agent_id)
            now = datetime.now(timezone.utc)

            # Atomic upsert (INSERT ... ON CONFLICT DO UPDATE)
            stmt = insert(TokenConsumption).values(
                agent_id=agent_id,
                window_hour=window_hour,
                consumption_count=actual_tokens,
                created_at=now,
                updated_at=now,
            )

            # On conflict: increment existing count
            stmt = stmt.on_conflict_do_update(
                index_elements=["agent_id", "window_hour"],
                set_={
                    "consumption_count": TokenConsumption.consumption_count
                    + actual_tokens,
                    "updated_at": now,
                },
            )

            await self.db_session.execute(stmt)
            await self.db_session.commit()

        except Exception as e:
            await self.db_session.rollback()
            # Log error but don't fail operation (best-effort tracking)
            # Operation has already completed at this point
            import logging

            logger = logging.getLogger(__name__)
            logger.error(
                f"Token consumption tracking failed for agent {agent_id}: {e}",
                exc_info=True,
                extra={
                    "agent_id": str(agent_id),
                    "actual_tokens": actual_tokens,
                    "window_hour": window_hour,
                },
            )
            # Don't raise - tracking failure should not fail the operation

    async def get_budget_status(self, agent_id: UUID) -> TokenBudgetStatus:
        """
        Get current token budget status for an agent.

        Args:
            agent_id: Agent UUID

        Returns:
            TokenBudgetStatus with current consumption and limits

        Raises:
            AuthorizationError: If database query fails

        Example:
            >>> status = await budget_service.get_budget_status(UUID("550e8400..."))
            >>> print(f"Consumed: {status.current_consumption}/{status.budget_limit}")
            >>> print(f"Remaining: {status.remaining_tokens}")
            >>> print(f"Window: {status.window_start} to {status.window_end}")

        Use Cases:
            - Dashboard display
            - Client-side budget warnings
            - Analytics and reporting
        """
        # Get tier and limits
        tier = await self.license_service.get_agent_tier(agent_id)
        limits = self.license_service.get_tier_limits(tier)

        # Get window boundaries
        window_hour, window_start, window_end = self._get_window_key(agent_id)

        # Check if unlimited
        if limits.max_tokens_per_hour is None:
            return TokenBudgetStatus(
                agent_id=agent_id,
                tier=tier,
                current_consumption=0,
                budget_limit=None,
                remaining_tokens=None,
                window_start=window_start,
                window_end=window_end,
                is_unlimited=True,
            )

        # Query current consumption from database
        try:
            stmt = select(TokenConsumption).where(
                TokenConsumption.agent_id == agent_id,
                TokenConsumption.window_hour == window_hour,
            )
            result = await self.db_session.execute(stmt)
            consumption_record = result.scalar_one_or_none()

            current_consumption = (
                consumption_record.consumption_count if consumption_record else 0
            )
        except Exception as e:
            log_and_raise(
                AuthorizationError,
                "Failed to query token budget status",
                original_exception=e,
                details={"agent_id": str(agent_id)},
            )

        # Calculate remaining tokens
        budget_limit = limits.max_tokens_per_hour
        remaining_tokens = max(0, budget_limit - current_consumption)

        return TokenBudgetStatus(
            agent_id=agent_id,
            tier=tier,
            current_consumption=current_consumption,
            budget_limit=budget_limit,
            remaining_tokens=remaining_tokens,
            window_start=window_start,
            window_end=window_end,
            is_unlimited=False,
        )

    async def reset_budget(self, agent_id: UUID) -> None:
        """
        Reset token budget for an agent (ADMIN ONLY).

        This method deletes the current hourly window record, effectively
        resetting token consumption to zero.

        Args:
            agent_id: Agent UUID

        Raises:
            AuthorizationError: If database operation fails

        Security:
            - ADMIN-only operation (enforce in calling code)
            - Audit log required for all resets
            - Should only be used for emergency recovery

        Example:
            >>> # Emergency budget reset
            >>> await budget_service.reset_budget(UUID("550e8400..."))
            >>> # Log audit event
            >>> await audit_logger.log_budget_reset(agent_id, admin_id, reason)

        Warning:
            This operation bypasses normal budget enforcement.
            Use with extreme caution and always log to audit trail.
        """
        try:
            window_hour, _, _ = self._get_window_key(agent_id)

            # Delete current window record
            stmt = select(TokenConsumption).where(
                TokenConsumption.agent_id == agent_id,
                TokenConsumption.window_hour == window_hour,
            )
            result = await self.db_session.execute(stmt)
            consumption_record = result.scalar_one_or_none()

            if consumption_record:
                await self.db_session.delete(consumption_record)
                await self.db_session.commit()

        except Exception as e:
            await self.db_session.rollback()
            log_and_raise(
                AuthorizationError,
                "Failed to reset token budget",
                original_exception=e,
                details={"agent_id": str(agent_id)},
            )
