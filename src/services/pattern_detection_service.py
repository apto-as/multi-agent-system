"""Pattern Detection Service for TMWS Autonomous Learning System.

Detects recurring tool execution patterns (Layer 2) using SQL aggregation
with Python-based deduplication and state machine management.

Architecture: Layer 2 of TMWS Native Autonomous Learning
- Receives traces from Layer 1 (ExecutionTraceService)
- Detects patterns with N>=3 threshold
- Generates SOP drafts for validated patterns
- Prepares patterns for Layer 3 (LearningLoopService)

Performance Targets:
- analyze_patterns(): <100ms P95
- detect_sequence(): <50ms P95
- generate_sop_draft(): <200ms P95

State Machine:
- DETECTED (N>=3) → VALIDATING → VALIDATED → APPROVED → SKILL_CREATED
- REJECTED (terminal state)

Security:
- P0-1 Namespace isolation enforced
- Agent-based access control
- State transition authorization
"""

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.exceptions import NotFoundError, ValidationError
from ..models.execution_trace import DetectedPattern, ExecutionTrace
from .base_service import BaseService

logger = logging.getLogger(__name__)


class PatternDetectionService(BaseService):
    """Service for detecting and managing recurring tool patterns.

    Implements the Hybrid Dual-Phase architecture (Hera's Option B):
    - Phase 1: SQL GROUP BY for fast aggregation
    - Phase 2: Python SHA256 deduplication + state machine

    Key Features:
    - Pattern detection with configurable thresholds
    - SOP draft generation from patterns
    - State machine for pattern lifecycle
    - asyncio.Lock for race condition prevention
    - P0-1 namespace isolation compliance
    """

    # Limits to prevent pattern explosion
    MAX_SEQUENCE_LENGTH = 20
    MIN_OCCURRENCES = 3
    MAX_OCCURRENCES = 10000
    DEFAULT_WINDOW_HOURS = 168  # 1 week
    MIN_SUCCESS_RATE = 0.7  # Minimum success rate for pattern detection

    # Valid state transitions
    VALID_TRANSITIONS = {
        "DETECTED": ["VALIDATING"],
        "VALIDATING": ["VALIDATED", "REJECTED"],
        "VALIDATED": ["APPROVED", "REJECTED"],
        "APPROVED": ["SKILL_CREATED", "REJECTED"],
        "SKILL_CREATED": [],  # Terminal
        "REJECTED": [],  # Terminal
    }

    def __init__(self, session: AsyncSession):
        """Initialize the pattern detection service.

        Args:
            session: Async database session
        """
        super().__init__(session)
        # Lock for state transitions to prevent race conditions
        self._state_locks: dict[str, asyncio.Lock] = {}

    def _get_pattern_lock(self, pattern_id: str) -> asyncio.Lock:
        """Get or create a lock for a specific pattern.

        Args:
            pattern_id: Pattern UUID

        Returns:
            asyncio.Lock for the pattern
        """
        if pattern_id not in self._state_locks:
            self._state_locks[pattern_id] = asyncio.Lock()
        return self._state_locks[pattern_id]

    async def analyze_patterns(
        self,
        namespace: str,
        min_occurrences: int = 3,
        window_hours: int = 168,
        min_success_rate: float = 0.7,
        max_sequence_length: int = 20,
    ) -> list[dict[str, Any]]:
        """Detect patterns from execution traces using SQL aggregation.

        Phase 1: SQL GROUP BY aggregation (fast, indexed)
        Phase 2: Python deduplication + pattern creation

        Target latency: <100ms P95

        Args:
            namespace: Namespace for isolation (P0-1)
            min_occurrences: Minimum pattern occurrences (3-10000)
            window_hours: Analysis time window in hours (1-8760)
            min_success_rate: Minimum average success rate (0.0-1.0)
            max_sequence_length: Maximum tools in sequence (1-50)

        Returns:
            List of detected patterns with:
            - tool_sequence: List of tool names
            - pattern_hash: SHA256 hash
            - frequency: Occurrence count
            - avg_success_rate: 0.0-1.0
            - avg_execution_time_ms: Average latency
            - is_new: Whether pattern was newly created
        """
        # Validate parameters
        min_occurrences = max(self.MIN_OCCURRENCES, min(self.MAX_OCCURRENCES, min_occurrences))
        window_hours = max(1, min(8760, window_hours))
        min_success_rate = max(0.0, min(1.0, min_success_rate))
        max_sequence_length = max(1, min(50, max_sequence_length))

        # Calculate time window
        since = datetime.utcnow() - timedelta(hours=window_hours)

        # Phase 1: SQL aggregation
        # Group traces by orchestration_id and aggregate tool sequences
        result = await self.session.execute(
            select(
                ExecutionTrace.orchestration_id,
                func.group_concat(ExecutionTrace.tool_name).label("tool_sequence"),
                func.count(ExecutionTrace.id).label("tool_count"),
                func.avg(
                    func.cast(ExecutionTrace.success, type_=func.sqlalchemy.types.Float)
                ).label("success_rate"),
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

        # Phase 2: Python deduplication
        sequence_counts: dict[str, dict[str, Any]] = {}
        for row in sequences:
            if row.tool_sequence:
                seq_key = row.tool_sequence
                if seq_key not in sequence_counts:
                    sequence_counts[seq_key] = {
                        "tool_sequence": seq_key.split(","),
                        "frequency": 0,
                        "total_success_rate": 0.0,
                        "total_time_ms": 0.0,
                    }
                sequence_counts[seq_key]["frequency"] += 1
                sequence_counts[seq_key]["total_success_rate"] += row.success_rate or 0.0
                sequence_counts[seq_key]["total_time_ms"] += row.total_time_ms or 0.0

        # Filter by thresholds and create/update patterns
        detected_patterns = []
        for data in sequence_counts.values():
            if data["frequency"] >= min_occurrences:
                avg_success_rate = data["total_success_rate"] / data["frequency"]
                if avg_success_rate >= min_success_rate:
                    pattern_hash = self._hash_sequence(data["tool_sequence"])
                    avg_execution_time = data["total_time_ms"] / data["frequency"]

                    # Create or update pattern
                    pattern, is_new = await self.create_or_update_pattern(
                        tool_sequence=data["tool_sequence"],
                        namespace=namespace,
                        frequency=data["frequency"],
                        avg_success_rate=avg_success_rate,
                        avg_execution_time_ms=avg_execution_time,
                    )

                    detected_patterns.append(
                        {
                            "tool_sequence": data["tool_sequence"],
                            "pattern_hash": pattern_hash,
                            "frequency": data["frequency"],
                            "avg_success_rate": avg_success_rate,
                            "avg_execution_time_ms": avg_execution_time,
                            "is_new": is_new,
                            "pattern_id": str(pattern.id),
                            "state": pattern.state,
                        }
                    )

        # Sort by frequency descending
        detected_patterns.sort(key=lambda x: x["frequency"], reverse=True)

        logger.info(
            f"Analyzed patterns in namespace {namespace}: "
            f"found {len(detected_patterns)} patterns from {len(sequences)} sequences"
        )

        return detected_patterns

    async def detect_sequence(
        self, tool_sequence: list[str], namespace: str
    ) -> DetectedPattern | None:
        """Check if a tool sequence already exists as a detected pattern.

        Target latency: <50ms P95 (O(1) hash lookup)

        Args:
            tool_sequence: List of tool names
            namespace: Namespace for P0-1 validation

        Returns:
            DetectedPattern if found, None otherwise
        """
        if not tool_sequence:
            return None

        pattern_hash = self._hash_sequence(tool_sequence)

        result = await self.session.execute(
            select(DetectedPattern).where(
                and_(
                    DetectedPattern.pattern_hash == pattern_hash,
                    DetectedPattern.namespace == namespace,
                )
            )
        )

        return result.scalar_one_or_none()

    async def create_or_update_pattern(
        self,
        tool_sequence: list[str],
        namespace: str,
        frequency: int,
        avg_success_rate: float,
        avg_execution_time_ms: float,
        agent_id: str | None = None,
    ) -> tuple[DetectedPattern, bool]:
        """Create new pattern or update existing one (UPSERT logic).

        Args:
            tool_sequence: List of tool names
            namespace: Namespace for isolation (P0-1)
            frequency: Occurrence count
            avg_success_rate: Average success rate (0.0-1.0)
            avg_execution_time_ms: Average execution time
            agent_id: Optional agent ID (for ownership)

        Returns:
            Tuple of (DetectedPattern, is_new)
        """
        pattern_hash = self._hash_sequence(tool_sequence)

        # Check for existing pattern
        existing = await self.session.execute(
            select(DetectedPattern).where(DetectedPattern.pattern_hash == pattern_hash)
        )
        pattern = existing.scalar_one_or_none()

        if pattern:
            # Update existing pattern
            if pattern.namespace != namespace:
                # Same sequence in different namespace - create new pattern
                pass
            else:
                # Update statistics
                pattern.frequency = max(pattern.frequency, frequency)
                pattern.avg_success_rate = (pattern.avg_success_rate + avg_success_rate) / 2
                if avg_execution_time_ms:
                    if pattern.avg_execution_time_ms:
                        pattern.avg_execution_time_ms = (
                            pattern.avg_execution_time_ms + avg_execution_time_ms
                        ) / 2
                    else:
                        pattern.avg_execution_time_ms = avg_execution_time_ms
                pattern.last_occurrence_at = func.now()

                await self.session.flush()
                return pattern, False

        # Create new pattern
        new_pattern = DetectedPattern(
            namespace=namespace,
            agent_id=agent_id,
            tool_sequence=tool_sequence,
            pattern_hash=pattern_hash,
            frequency=frequency,
            avg_success_rate=avg_success_rate,
            avg_execution_time_ms=avg_execution_time_ms,
            state="DETECTED",
            detected_at=func.now(),
            last_occurrence_at=func.now(),
        )

        self.session.add(new_pattern)
        await self.session.flush()
        await self.session.refresh(new_pattern)

        logger.info(
            f"Created new pattern: {tool_sequence[:3]}... "
            f"(hash={pattern_hash[:8]}, freq={frequency})"
        )

        return new_pattern, True

    async def get_pattern_by_id(self, pattern_id: str | UUID, namespace: str) -> DetectedPattern:
        """Get a pattern by ID with namespace validation.

        Args:
            pattern_id: Pattern UUID
            namespace: Namespace for P0-1 validation

        Returns:
            DetectedPattern instance

        Raises:
            NotFoundError: If pattern not found or namespace mismatch
        """
        result = await self.session.execute(
            select(DetectedPattern).where(
                and_(
                    DetectedPattern.id == str(pattern_id),
                    DetectedPattern.namespace == namespace,
                )
            )
        )
        pattern = result.scalar_one_or_none()
        if not pattern:
            raise NotFoundError("DetectedPattern", str(pattern_id))
        return pattern

    async def get_patterns_by_state(
        self,
        namespace: str,
        state: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectedPattern]:
        """Get patterns by state with namespace isolation.

        Args:
            namespace: Namespace for P0-1 validation
            state: Pattern state to filter by
            limit: Maximum results (1-1000)
            offset: Pagination offset

        Returns:
            List of DetectedPattern instances
        """
        # Validate state
        if state not in self.VALID_TRANSITIONS:
            raise ValidationError(
                f"Invalid state: {state}. Valid states: {list(self.VALID_TRANSITIONS.keys())}"
            )

        limit = max(1, min(1000, limit))

        result = await self.session.execute(
            select(DetectedPattern)
            .where(
                and_(
                    DetectedPattern.namespace == namespace,
                    DetectedPattern.state == state,
                )
            )
            .order_by(DetectedPattern.frequency.desc())
            .limit(limit)
            .offset(offset)
        )

        return list(result.scalars().all())

    async def transition_pattern_state(
        self,
        pattern_id: str | UUID,
        new_state: str,
        actor_id: str | None = None,
        namespace: str | None = None,
        validation_errors: list[str] | None = None,
    ) -> DetectedPattern:
        """Transition a pattern to a new state with validation.

        Uses asyncio.Lock to prevent race conditions.

        Args:
            pattern_id: Pattern UUID
            new_state: Target state
            actor_id: Agent performing the transition
            namespace: Namespace for P0-1 validation (required)
            validation_errors: Errors if transitioning to REJECTED

        Returns:
            Updated DetectedPattern

        Raises:
            NotFoundError: If pattern not found
            ValidationError: If transition is invalid
        """
        if namespace is None:
            raise ValidationError("Namespace is required for state transition")

        if new_state not in self.VALID_TRANSITIONS:
            raise ValidationError(
                f"Invalid target state: {new_state}. "
                f"Valid states: {list(self.VALID_TRANSITIONS.keys())}"
            )

        pattern_id_str = str(pattern_id)
        lock = self._get_pattern_lock(pattern_id_str)

        async with lock:
            # Get pattern with namespace validation
            pattern = await self.get_pattern_by_id(pattern_id_str, namespace)

            # Validate transition
            allowed_transitions = self.VALID_TRANSITIONS.get(pattern.state, [])
            if new_state not in allowed_transitions:
                raise ValidationError(
                    f"Invalid state transition: {pattern.state} → {new_state}. "
                    f"Allowed: {allowed_transitions}"
                )

            # Perform transition
            old_state = pattern.state
            pattern.state = new_state

            # Record metadata based on new state
            if new_state == "VALIDATED":
                pattern.validated_at = datetime.utcnow()
            elif new_state == "APPROVED":
                pattern.approved_by = actor_id
                pattern.approved_at = datetime.utcnow()
            elif new_state == "REJECTED" and validation_errors:
                pattern.validation_errors = validation_errors

            await self.session.flush()

            logger.info(
                f"Pattern {pattern_id_str[:8]} transitioned: "
                f"{old_state} → {new_state} (actor={actor_id})"
            )

            return pattern

    async def generate_sop_draft(self, pattern: DetectedPattern) -> str:
        """Generate Standard Operating Procedure markdown draft.

        Template-based generation (no LLM required for Phase 2).

        Target latency: <200ms P95

        Args:
            pattern: DetectedPattern to generate SOP for

        Returns:
            Markdown-formatted SOP draft
        """
        tools = pattern.tool_sequence
        freq = pattern.frequency
        success_rate = pattern.avg_success_rate
        exec_time = pattern.avg_execution_time_ms or 0

        # Generate title
        title = self._generate_sop_title(tools)

        # Build markdown
        sop_draft = f"""# {title}

## Overview

This SOP was automatically generated from a detected tool execution pattern.

**Pattern Statistics:**
- **Occurrences:** {freq}
- **Success Rate:** {success_rate:.1%}
- **Average Execution Time:** {exec_time:.1f}ms
- **Namespace:** {pattern.namespace}
- **Detected At:** {pattern.detected_at.isoformat() if pattern.detected_at else "N/A"}

## Tool Sequence

The following tools are executed in sequence:

"""
        # Add numbered steps
        for i, tool in enumerate(tools, 1):
            sop_draft += f"{i}. `{tool}`\n"

        sop_draft += """

## Prerequisites

Before executing this procedure:

1. Ensure appropriate permissions for all tools in the sequence
2. Verify namespace access
3. Check tool availability

## Execution Steps

"""
        # Add detailed steps
        for i, tool in enumerate(tools, 1):
            sop_draft += f"""### Step {i}: Execute `{tool}`

```
Tool: {tool}
Expected: Success
```

"""

        sop_draft += f"""## Validation

After execution, verify:

- All {len(tools)} tools completed successfully
- Expected success rate: {success_rate:.1%}
- Maximum execution time: {exec_time * 2:.1f}ms

## Notes

- This SOP was auto-generated and should be reviewed before production use
- Pattern hash: `{pattern.pattern_hash[:16]}...`
- Pattern ID: `{pattern.id}`
"""

        # Update pattern with draft
        pattern.sop_draft = sop_draft
        pattern.sop_title = title
        await self.session.flush()

        logger.info(f"Generated SOP draft for pattern {pattern.id}: '{title}'")

        return sop_draft

    def _generate_sop_title(self, tools: list[str]) -> str:
        """Generate a human-readable title from tool sequence.

        Args:
            tools: List of tool names

        Returns:
            Title string
        """
        if not tools:
            return "Empty Pattern"

        if len(tools) == 1:
            return f"Single Tool: {tools[0]}"

        # Extract common prefix/suffix
        first_tool = tools[0].replace("_", " ").title()
        last_tool = tools[-1].replace("_", " ").title()

        if len(tools) == 2:
            return f"{first_tool} to {last_tool}"

        return f"{first_tool} → ... → {last_tool} ({len(tools)} steps)"

    def _hash_sequence(self, tool_sequence: list[str]) -> str:
        """Generate SHA256 hash for a tool sequence.

        Args:
            tool_sequence: List of tool names

        Returns:
            SHA256 hex digest (64 characters)
        """
        sequence_str = ",".join(tool_sequence)
        return hashlib.sha256(sequence_str.encode()).hexdigest()

    async def get_pattern_statistics(
        self,
        namespace: str,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Get pattern detection statistics.

        Args:
            namespace: Namespace for P0-1 isolation
            since: Statistics since this time

        Returns:
            Statistics dictionary
        """
        since = since or (datetime.utcnow() - timedelta(days=30))

        # Count by state
        state_counts = {}
        for state in self.VALID_TRANSITIONS:
            result = await self.session.execute(
                select(func.count(DetectedPattern.id)).where(
                    and_(
                        DetectedPattern.namespace == namespace,
                        DetectedPattern.state == state,
                        DetectedPattern.created_at >= since,
                    )
                )
            )
            state_counts[state] = result.scalar() or 0

        # Total patterns
        total = sum(state_counts.values())

        # Average frequency
        avg_freq_result = await self.session.execute(
            select(func.avg(DetectedPattern.frequency)).where(
                and_(
                    DetectedPattern.namespace == namespace,
                    DetectedPattern.created_at >= since,
                )
            )
        )
        avg_frequency = avg_freq_result.scalar() or 0

        # Patterns promoted to skills
        promoted_result = await self.session.execute(
            select(func.count(DetectedPattern.id)).where(
                and_(
                    DetectedPattern.namespace == namespace,
                    DetectedPattern.state == "SKILL_CREATED",
                    DetectedPattern.created_at >= since,
                )
            )
        )
        promoted_count = promoted_result.scalar() or 0

        return {
            "total_patterns": total,
            "by_state": state_counts,
            "avg_frequency": float(avg_frequency),
            "promoted_to_skills": promoted_count,
            "promotion_rate": promoted_count / total if total > 0 else 0,
            "namespace": namespace,
            "since": since.isoformat(),
        }

    async def link_pattern_to_skill(
        self,
        pattern_id: str | UUID,
        skill_id: str,
        namespace: str,
    ) -> DetectedPattern:
        """Link a pattern to a created skill.

        Args:
            pattern_id: Pattern UUID
            skill_id: Skill UUID
            namespace: Namespace for P0-1 validation

        Returns:
            Updated DetectedPattern

        Raises:
            NotFoundError: If pattern not found
            ValidationError: If pattern not in APPROVED state
        """
        pattern = await self.get_pattern_by_id(pattern_id, namespace)

        if pattern.state != "APPROVED":
            raise ValidationError(
                f"Pattern must be in APPROVED state to link to skill. "
                f"Current state: {pattern.state}"
            )

        pattern.skill_id = skill_id
        pattern.state = "SKILL_CREATED"

        await self.session.flush()

        logger.info(f"Linked pattern {pattern_id} to skill {skill_id} in namespace {namespace}")

        return pattern

    async def cleanup_rejected_patterns(
        self,
        namespace: str,
        older_than_days: int = 30,
        batch_size: int = 100,
    ) -> int:
        """Clean up old rejected patterns.

        Args:
            namespace: Namespace for P0-1 isolation
            older_than_days: Delete patterns older than this
            batch_size: Maximum patterns to delete per batch

        Returns:
            Number of patterns deleted
        """
        cutoff = datetime.utcnow() - timedelta(days=older_than_days)

        # Find patterns to delete
        result = await self.session.execute(
            select(DetectedPattern.id)
            .where(
                and_(
                    DetectedPattern.namespace == namespace,
                    DetectedPattern.state == "REJECTED",
                    DetectedPattern.created_at < cutoff,
                )
            )
            .limit(batch_size)
        )

        pattern_ids = [row[0] for row in result.all()]

        if not pattern_ids:
            return 0

        # Delete patterns
        from sqlalchemy import delete

        await self.session.execute(
            delete(DetectedPattern).where(DetectedPattern.id.in_(pattern_ids))
        )

        logger.info(f"Cleaned up {len(pattern_ids)} rejected patterns in namespace {namespace}")

        return len(pattern_ids)
