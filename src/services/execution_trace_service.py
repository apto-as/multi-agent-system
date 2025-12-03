"""Execution Trace Service for TMWS Autonomous Learning System.

Records MCP tool execution history in real-time for pattern detection
and autonomous SOP generation.

Architecture: Layer 1 of TMWS Native Autonomous Learning
- Async recording with <5ms P95 latency target
- Circuit breaker pattern for graceful degradation
- P0-1 namespace isolation enforced
- SQL windowing support for pattern detection

Performance Targets:
- record_execution(): <5ms P95
- get_execution_history(): <50ms P95
- analyze_tool_sequence(): <100ms P95

Security:
- Namespace isolation at every operation
- Input sanitization for parameters
- TTL-based automatic data retention
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Float, and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import NotFoundError
from ..models.execution_trace import ExecutionTrace
from .base_service import BaseService

logger = logging.getLogger(__name__)


class ExecutionTraceService(BaseService):
    """Service for recording and analyzing MCP tool execution traces.

    Provides real-time execution recording with circuit breaker pattern
    to ensure tool execution is never blocked by trace recording failures.

    Key Features:
    - Async trace recording (<5ms P95)
    - Namespace-isolated queries
    - Pattern detection support via SQL windowing
    - TTL-based automatic cleanup
    - Circuit breaker for graceful degradation
    """

    # Circuit breaker configuration
    CIRCUIT_BREAKER_THRESHOLD = 5  # Consecutive failures to trip
    CIRCUIT_BREAKER_RESET_SECONDS = 60  # Time to wait before retry

    def __init__(self, session: AsyncSession):
        """Initialize the execution trace service.

        Args:
            session: Async database session
        """
        super().__init__(session)
        self._circuit_breaker_failures = 0
        self._circuit_breaker_tripped_at: datetime | None = None

    def _is_circuit_open(self) -> bool:
        """Check if circuit breaker is open (blocking operations).

        Returns:
            True if circuit is open and operations should be skipped
        """
        if self._circuit_breaker_tripped_at is None:
            return False

        elapsed = (datetime.utcnow() - self._circuit_breaker_tripped_at).total_seconds()
        if elapsed >= self.CIRCUIT_BREAKER_RESET_SECONDS:
            # Reset circuit breaker after timeout
            self._circuit_breaker_failures = 0
            self._circuit_breaker_tripped_at = None
            logger.info("Circuit breaker reset - resuming trace recording")
            return False

        return True

    def _record_failure(self) -> None:
        """Record a trace recording failure for circuit breaker."""
        self._circuit_breaker_failures += 1
        if self._circuit_breaker_failures >= self.CIRCUIT_BREAKER_THRESHOLD:
            self._circuit_breaker_tripped_at = datetime.utcnow()
            logger.warning(
                f"Circuit breaker tripped after {self._circuit_breaker_failures} failures. "
                f"Trace recording disabled for {self.CIRCUIT_BREAKER_RESET_SECONDS}s"
            )

    def _record_success(self) -> None:
        """Record a successful trace recording."""
        self._circuit_breaker_failures = 0

    async def record_execution(
        self,
        agent_id: str,
        namespace: str,
        tool_name: str,
        input_params: dict[str, Any],
        output_result: dict[str, Any] | None = None,
        success: bool = True,
        error_message: str | None = None,
        error_type: str | None = None,
        execution_time_ms: float = 0.0,
        orchestration_id: str | None = None,
        sequence_number: int | None = None,
        context_snapshot: dict[str, Any] | None = None,
        ttl_days: int = 30,
    ) -> ExecutionTrace | None:
        """Record an MCP tool execution trace.

        Target latency: <5ms P95

        Args:
            agent_id: Agent that executed the tool
            namespace: Namespace for isolation (P0-1)
            tool_name: MCP tool name
            input_params: Tool input parameters (will be sanitized)
            output_result: Tool output result (will be truncated if large)
            success: Whether execution succeeded
            error_message: Error message if failed
            error_type: Exception class name if failed
            execution_time_ms: Execution time in milliseconds
            orchestration_id: Orchestration session ID for sequence grouping
            sequence_number: Position in orchestration sequence
            context_snapshot: Context state at execution time
            ttl_days: Time-to-live in days (1-3650)

        Returns:
            Created ExecutionTrace or None if circuit breaker is open
        """
        # Check circuit breaker
        if self._is_circuit_open():
            logger.debug(f"Circuit breaker open - skipping trace for {tool_name}")
            return None

        try:
            # Validate TTL
            if not 1 <= ttl_days <= 3650:
                ttl_days = 30  # Default to 30 days

            # Sanitize input parameters (remove sensitive data)
            sanitized_params = self._sanitize_params(input_params)

            # Truncate large output results
            truncated_output = self._truncate_output(output_result)

            # Calculate expiration
            expires_at = datetime.utcnow() + timedelta(days=ttl_days)

            # Create trace record
            trace = ExecutionTrace(
                agent_id=agent_id,
                namespace=namespace,
                tool_name=tool_name,
                input_params=sanitized_params,
                output_result=truncated_output,
                success=success,
                error_message=error_message,
                error_type=error_type,
                execution_time_ms=execution_time_ms,
                orchestration_id=orchestration_id,
                sequence_number=sequence_number,
                context_snapshot=context_snapshot,
                ttl_days=ttl_days,
                expires_at=expires_at,
            )

            self.session.add(trace)
            await self.session.flush()
            await self.session.refresh(trace)

            self._record_success()
            logger.debug(f"Recorded trace for {tool_name} ({execution_time_ms:.1f}ms)")
            return trace

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self._record_failure()
            logger.warning(f"Failed to record trace for {tool_name}: {e}")
            # Don't raise - circuit breaker pattern allows graceful degradation
            return None

    def _sanitize_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Sanitize input parameters by removing sensitive data.

        Args:
            params: Raw input parameters

        Returns:
            Sanitized parameters
        """
        if not params:
            return {}

        # List of sensitive keys to redact
        sensitive_keys = {
            "password", "secret", "token", "api_key", "apikey",
            "credential", "auth", "authorization", "bearer",
            "private_key", "privatekey", "access_token", "refresh_token"
        }

        sanitized = {}
        for key, value in params.items():
            lower_key = key.lower()
            if any(s in lower_key for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_params(value)
            else:
                sanitized[key] = value

        return sanitized

    def _truncate_output(
        self, output: dict[str, Any] | None, max_size: int = 10000
    ) -> dict[str, Any] | None:
        """Truncate large output results.

        Args:
            output: Output dictionary
            max_size: Maximum size in characters

        Returns:
            Truncated output
        """
        if output is None:
            return None

        import json
        try:
            output_str = json.dumps(output)
            if len(output_str) <= max_size:
                return output
            return {"_truncated": True, "_size": len(output_str)}
        except (TypeError, ValueError):
            return {"_error": "Failed to serialize output"}

    async def get_trace_by_id(
        self, trace_id: str, namespace: str
    ) -> ExecutionTrace:
        """Get a trace by ID with namespace validation.

        Args:
            trace_id: Trace UUID
            namespace: Namespace for P0-1 validation

        Returns:
            ExecutionTrace instance

        Raises:
            NotFoundError: If trace not found or namespace mismatch
        """
        result = await self.session.execute(
            select(ExecutionTrace).where(
                and_(
                    ExecutionTrace.id == trace_id,
                    ExecutionTrace.namespace == namespace,
                )
            )
        )
        trace = result.scalar_one_or_none()
        if not trace:
            raise NotFoundError("ExecutionTrace", trace_id)
        return trace

    async def get_execution_history(
        self,
        namespace: str,
        agent_id: str | None = None,
        tool_name: str | None = None,
        orchestration_id: str | None = None,
        success: bool | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionTrace]:
        """Get execution history with filters.

        Target latency: <50ms P95

        Args:
            namespace: Namespace for isolation (required, P0-1)
            agent_id: Filter by agent
            tool_name: Filter by tool name
            orchestration_id: Filter by orchestration session
            success: Filter by success status
            since: Filter by start time
            until: Filter by end time
            limit: Maximum results (1-1000)
            offset: Pagination offset

        Returns:
            List of ExecutionTrace instances
        """
        # Validate limit
        limit = max(1, min(1000, limit))

        # Build query with namespace isolation (P0-1)
        query = select(ExecutionTrace).where(ExecutionTrace.namespace == namespace)

        if agent_id:
            query = query.where(ExecutionTrace.agent_id == agent_id)
        if tool_name:
            query = query.where(ExecutionTrace.tool_name == tool_name)
        if orchestration_id:
            query = query.where(ExecutionTrace.orchestration_id == orchestration_id)
        if success is not None:
            query = query.where(ExecutionTrace.success == success)
        if since:
            query = query.where(ExecutionTrace.created_at >= since)
        if until:
            query = query.where(ExecutionTrace.created_at <= until)

        query = query.order_by(ExecutionTrace.created_at.desc())
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_orchestration_sequence(
        self, orchestration_id: str, namespace: str
    ) -> list[ExecutionTrace]:
        """Get all traces for an orchestration session in sequence order.

        Args:
            orchestration_id: Orchestration session ID
            namespace: Namespace for P0-1 validation

        Returns:
            List of traces ordered by sequence number
        """
        result = await self.session.execute(
            select(ExecutionTrace)
            .where(
                and_(
                    ExecutionTrace.orchestration_id == orchestration_id,
                    ExecutionTrace.namespace == namespace,
                )
            )
            .order_by(ExecutionTrace.sequence_number.asc())
        )
        return list(result.scalars().all())

    async def analyze_tool_sequence(
        self,
        namespace: str,
        min_occurrences: int = 3,
        window_hours: int = 168,  # 1 week
        max_sequence_length: int = 20,
    ) -> list[dict[str, Any]]:
        """Analyze tool sequences for pattern detection.

        Uses SQL windowing to find recurring tool sequences.
        Target latency: <100ms P95

        Args:
            namespace: Namespace for isolation (P0-1)
            min_occurrences: Minimum occurrences to report (default 3)
            window_hours: Analysis time window in hours
            max_sequence_length: Maximum sequence length to consider

        Returns:
            List of detected patterns with frequency and success rate
        """
        # Calculate time window
        since = datetime.utcnow() - timedelta(hours=window_hours)

        # Get all orchestration sequences in window
        result = await self.session.execute(
            select(
                ExecutionTrace.orchestration_id,
                func.group_concat(ExecutionTrace.tool_name).label("tool_sequence"),
                func.count(ExecutionTrace.id).label("tool_count"),
                func.avg(func.cast(ExecutionTrace.success, Float)).label("success_rate"),
                func.sum(ExecutionTrace.execution_time_ms).label("total_time_ms"),
            )
            .where(
                and_(
                    ExecutionTrace.namespace == namespace,
                    ExecutionTrace.orchestration_id.isnot(None),
                    ExecutionTrace.created_at >= since,
                )
            )
            .group_by(ExecutionTrace.orchestration_id)
            .having(func.count(ExecutionTrace.id) <= max_sequence_length)
        )

        sequences = list(result.all())

        # Count sequence occurrences
        sequence_counts: dict[str, dict[str, Any]] = {}
        for row in sequences:
            if row.tool_sequence:
                seq_key = row.tool_sequence
                if seq_key not in sequence_counts:
                    sequence_counts[seq_key] = {
                        "tool_sequence": seq_key.split(","),
                        "frequency": 0,
                        "total_success_rate": 0,
                        "total_time_ms": 0,
                    }
                sequence_counts[seq_key]["frequency"] += 1
                sequence_counts[seq_key]["total_success_rate"] += row.success_rate or 0
                sequence_counts[seq_key]["total_time_ms"] += row.total_time_ms or 0

        # Filter by minimum occurrences and calculate averages
        patterns = []
        for _seq_key, data in sequence_counts.items():
            if data["frequency"] >= min_occurrences:
                patterns.append({
                    "tool_sequence": data["tool_sequence"],
                    "frequency": data["frequency"],
                    "avg_success_rate": data["total_success_rate"] / data["frequency"],
                    "avg_execution_time_ms": data["total_time_ms"] / data["frequency"],
                    "pattern_hash": self._hash_sequence(data["tool_sequence"]),
                })

        # Sort by frequency
        patterns.sort(key=lambda x: x["frequency"], reverse=True)
        return patterns

    def _hash_sequence(self, tool_sequence: list[str]) -> str:
        """Generate SHA256 hash for a tool sequence.

        Args:
            tool_sequence: List of tool names

        Returns:
            SHA256 hex digest
        """
        sequence_str = ",".join(tool_sequence)
        return hashlib.sha256(sequence_str.encode()).hexdigest()

    async def cleanup_expired_traces(
        self, namespace: str | None = None, batch_size: int = 1000
    ) -> int:
        """Clean up expired execution traces.

        Args:
            namespace: Optional namespace filter (None = all namespaces)
            batch_size: Maximum traces to delete per batch

        Returns:
            Number of traces deleted
        """
        now = datetime.utcnow()

        query = delete(ExecutionTrace).where(
            and_(
                ExecutionTrace.expires_at.isnot(None),
                ExecutionTrace.expires_at < now,
            )
        )

        if namespace:
            query = query.where(ExecutionTrace.namespace == namespace)

        # SQLite doesn't support LIMIT in DELETE, so we need to use subquery
        subquery = (
            select(ExecutionTrace.id)
            .where(
                and_(
                    ExecutionTrace.expires_at.isnot(None),
                    ExecutionTrace.expires_at < now,
                )
            )
            .limit(batch_size)
        )
        if namespace:
            subquery = subquery.where(ExecutionTrace.namespace == namespace)

        result = await self.session.execute(
            delete(ExecutionTrace).where(ExecutionTrace.id.in_(subquery))
        )

        deleted_count = result.rowcount
        logger.info(f"Cleaned up {deleted_count} expired traces")
        return deleted_count

    async def get_trace_statistics(
        self,
        namespace: str,
        since: datetime | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Get execution trace statistics.

        Args:
            namespace: Namespace for isolation (P0-1)
            since: Statistics since this time
            agent_id: Filter by agent

        Returns:
            Statistics dictionary
        """
        since = since or (datetime.utcnow() - timedelta(days=7))

        # Build base query
        base_filter = and_(
            ExecutionTrace.namespace == namespace,
            ExecutionTrace.created_at >= since,
        )
        if agent_id:
            base_filter = and_(base_filter, ExecutionTrace.agent_id == agent_id)

        # Total count
        total_result = await self.session.execute(
            select(func.count(ExecutionTrace.id)).where(base_filter)
        )
        total_count = total_result.scalar() or 0

        # Success count
        success_result = await self.session.execute(
            select(func.count(ExecutionTrace.id)).where(
                and_(base_filter, ExecutionTrace.success == True)  # noqa: E712
            )
        )
        success_count = success_result.scalar() or 0

        # Average execution time
        avg_time_result = await self.session.execute(
            select(func.avg(ExecutionTrace.execution_time_ms)).where(base_filter)
        )
        avg_execution_time = avg_time_result.scalar() or 0

        # Most used tools
        tools_result = await self.session.execute(
            select(
                ExecutionTrace.tool_name,
                func.count(ExecutionTrace.id).label("count"),
            )
            .where(base_filter)
            .group_by(ExecutionTrace.tool_name)
            .order_by(func.count(ExecutionTrace.id).desc())
            .limit(10)
        )
        top_tools = [{"tool_name": r.tool_name, "count": r.count} for r in tools_result.all()]

        return {
            "total_traces": total_count,
            "success_count": success_count,
            "failure_count": total_count - success_count,
            "success_rate": success_count / total_count if total_count > 0 else 0,
            "avg_execution_time_ms": avg_execution_time,
            "top_tools": top_tools,
            "since": since.isoformat(),
            "namespace": namespace,
        }

    async def link_traces_to_pattern(
        self, trace_ids: list[str], pattern_id: str, namespace: str
    ) -> int:
        """Link execution traces to a detected pattern.

        Args:
            trace_ids: List of trace IDs to link
            pattern_id: Pattern ID to link to
            namespace: Namespace for P0-1 validation

        Returns:
            Number of traces updated
        """
        if not trace_ids:
            return 0

        # Update traces with namespace validation
        from sqlalchemy import update
        result = await self.session.execute(
            update(ExecutionTrace)
            .where(
                and_(
                    ExecutionTrace.id.in_(trace_ids),
                    ExecutionTrace.namespace == namespace,
                )
            )
            .values(pattern_id=pattern_id)
        )

        return result.rowcount
