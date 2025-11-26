"""Learning service for TMWS v2.0 - Universal Multi-Agent Platform.
Implements comprehensive learning pattern management with optimization.
"""

import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import and_, cast, desc, func, or_, select, text

from ..core.database import get_db_session
from ..core.exceptions import NotFoundError, PermissionError, ValidationError
from ..models.learning_pattern import LearningPattern, PatternUsageHistory
from ..security.validators import sanitize_input, validate_agent_id

logger = logging.getLogger(__name__)


class LearningService:
    """Enhanced learning service with agent-centric pattern management.

    Features:
    - Agent-based pattern isolation and sharing
    - Performance-optimized pattern retrieval
    - Advanced analytics and recommendation engine
    - Batch processing for high-throughput operations
    - Learning pattern evolution and versioning
    """

    def __init__(self):
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_cleanup = datetime.now()

    def _cleanup_cache(self) -> None:
        """Clean up expired cache entries."""
        now = datetime.now()
        if (now - self._last_cache_cleanup).seconds > 60:  # Cleanup every minute
            expired_keys = [
                key
                for key, (data, timestamp) in self._cache.items()
                if (now - timestamp).seconds > self._cache_ttl
            ]
            for key in expired_keys:
                del self._cache[key]
            self._last_cache_cleanup = now

    def _cache_key(self, operation: str, **kwargs) -> str:
        """Generate cache key for operation."""
        key_parts = [operation]
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}:{v}")
        return ":".join(key_parts)

    def _get_cached(self, key: str) -> Any | None:
        """Get cached value if not expired."""
        self._cleanup_cache()
        if key in self._cache:
            data, timestamp = self._cache[key]
            if (datetime.now() - timestamp).seconds < self._cache_ttl:
                return data
        return None

    def _set_cache(self, key: str, data: Any) -> None:
        """Set cached value with timestamp."""
        self._cache[key] = (data, datetime.now())

    async def create_pattern(
        self,
        pattern_name: str,
        category: str,
        pattern_data: dict[str, Any],
        agent_id: str | None = None,
        namespace: str = "default",
        subcategory: str | None = None,
        access_level: str = "private",
        learning_weight: float = 1.0,
        complexity_score: float | None = None,
    ) -> LearningPattern:
        """Create a new learning pattern with comprehensive validation.

        Args:
            pattern_name: Unique pattern name
            category: Pattern category
            pattern_data: Pattern data structure
            agent_id: Owner agent ID (optional for system patterns)
            namespace: Pattern namespace for organization
            subcategory: Optional subcategory
            access_level: Access level (private, shared, public, system)
            learning_weight: Initial learning weight
            complexity_score: Pattern complexity score

        Returns:
            Created LearningPattern instance

        Raises:
            ValidationError: If validation fails
            PermissionError: If access denied

        """
        # Validate inputs
        if agent_id:
            validate_agent_id(agent_id)

        pattern_name = sanitize_input(pattern_name)
        category = sanitize_input(category)
        namespace = sanitize_input(namespace)

        if not pattern_name or len(pattern_name) > 255:
            raise ValidationError("Pattern name must be 1-255 characters")

        if not category or len(category) > 100:
            raise ValidationError("Category must be 1-100 characters")

        if access_level not in ["private", "shared", "public", "system"]:
            raise ValidationError("Invalid access level")

        if not 0.0 <= learning_weight <= 10.0:
            raise ValidationError("Learning weight must be between 0.0 and 10.0")

        if complexity_score is not None and not 0.0 <= complexity_score <= 1.0:
            raise ValidationError("Complexity score must be between 0.0 and 1.0")

        # Create pattern
        async with get_db_session() as session:
            # Check for existing pattern
            existing = await session.execute(
                select(LearningPattern).where(
                    and_(
                        LearningPattern.pattern_name == pattern_name,
                        LearningPattern.namespace == namespace,
                        LearningPattern.agent_id == agent_id,
                    ),
                ),
            )

            if existing.scalar_one_or_none():
                raise ValidationError("Pattern with this name already exists in namespace")

            # Create new pattern
            pattern = LearningPattern(
                pattern_name=pattern_name,
                agent_id=agent_id,
                namespace=namespace,
                category=category,
                subcategory=subcategory,
                access_level=access_level,
                pattern_data=pattern_data,
                learning_weight=learning_weight,
                complexity_score=complexity_score,
            )

            session.add(pattern)
            await session.flush()
            await session.refresh(pattern)

            logger.info(f"Created learning pattern: {pattern_name} for agent: {agent_id}")
            return pattern

    async def get_pattern(
        self, pattern_id: UUID, requesting_agent_id: str | None = None,
    ) -> LearningPattern | None:
        """Get learning pattern by ID with access control.

        Args:
            pattern_id: Pattern UUID
            requesting_agent_id: ID of requesting agent

        Returns:
            LearningPattern if found and accessible, None otherwise

        Raises:
            PermissionError: If access denied

        """
        async with get_db_session() as session:
            result = await session.execute(
                select(LearningPattern).where(LearningPattern.id == pattern_id),
            )
            pattern = result.scalar_one_or_none()

            if not pattern:
                return None

            if not pattern.can_access(requesting_agent_id):
                raise PermissionError("Access denied to this learning pattern")

            return pattern

    async def get_patterns_by_agent(
        self,
        agent_id: str,
        namespace: str | None = None,
        category: str | None = None,
        access_level: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[LearningPattern]:
        """Get learning patterns owned by an agent.

        Args:
            agent_id: Agent ID
            namespace: Optional namespace filter
            category: Optional category filter
            access_level: Optional access level filter
            limit: Result limit
            offset: Result offset

        Returns:
            List of accessible learning patterns

        """
        cache_key = self._cache_key(
            "get_patterns_by_agent",
            agent_id=agent_id,
            namespace=namespace,
            category=category,
            access_level=access_level,
            limit=limit,
            offset=offset,
        )

        cached = self._get_cached(cache_key)
        if cached:
            return cached

        async with get_db_session() as session:
            query = select(LearningPattern).where(LearningPattern.agent_id == agent_id)

            if namespace:
                query = query.where(LearningPattern.namespace == namespace)
            if category:
                query = query.where(LearningPattern.category == category)
            if access_level:
                query = query.where(LearningPattern.access_level == access_level)

            query = query.order_by(desc(LearningPattern.last_used_at)).limit(limit).offset(offset)

            result = await session.execute(query)
            patterns = result.scalars().all()

            self._set_cache(cache_key, patterns)
            return patterns

    async def search_patterns(
        self,
        query_text: str | None = None,
        category: str | None = None,
        subcategory: str | None = None,
        namespace: str | None = None,
        access_levels: list[str] | None = None,
        requesting_agent_id: str | None = None,
        min_success_rate: float = 0.0,
        min_usage_count: int = 0,
        limit: int = 50,
        offset: int = 0,
    ) -> list[LearningPattern]:
        """Search learning patterns with advanced filtering.

        Args:
            query_text: Text search in pattern name and data
            category: Category filter
            subcategory: Subcategory filter
            namespace: Namespace filter
            access_levels: List of access levels to include
            requesting_agent_id: ID of requesting agent for access control
            min_success_rate: Minimum success rate filter
            min_usage_count: Minimum usage count filter
            limit: Result limit
            offset: Result offset

        Returns:
            List of matching learning patterns

        """
        cache_key = self._cache_key(
            "search_patterns",
            query_text=query_text,
            category=category,
            subcategory=subcategory,
            namespace=namespace,
            access_levels=",".join(access_levels or []),
            requesting_agent_id=requesting_agent_id,
            min_success_rate=min_success_rate,
            min_usage_count=min_usage_count,
            limit=limit,
            offset=offset,
        )

        cached = self._get_cached(cache_key)
        if cached:
            return cached

        async with get_db_session() as session:
            query = select(LearningPattern)

            # Access control filter
            if requesting_agent_id:
                # SQLite-compatible access filter (v2.2.6+)
                # For shared access, check if requesting_agent_id is in shared_with_agents JSON array
                access_filter = or_(
                    LearningPattern.access_level == "public",
                    LearningPattern.access_level == "system",
                    and_(
                        LearningPattern.access_level == "private",
                        LearningPattern.agent_id == requesting_agent_id,
                    ),
                    and_(
                        LearningPattern.access_level == "shared",
                        or_(
                            LearningPattern.agent_id == requesting_agent_id,
                            # SQLite JSON array containment check (Parameterized - SQL Injection Safe)
                            # SECURITY FIX (2025-11-08): Use bindparams() to prevent SQL injection (CVSS 9.8)
                            # Previous vulnerable code: f"WHERE value = '{requesting_agent_id}'"
                            # Attack vector: requesting_agent_id = "'; DROP TABLE learning_patterns; --"
                            text(
                                "EXISTS (SELECT 1 FROM json_each(learning_patterns.shared_with_agents) "
                                "WHERE value = :requesting_agent_id)"
                            ).bindparams(requesting_agent_id=requesting_agent_id),
                        ),
                    ),
                )
                query = query.where(access_filter)
            else:
                # No agent specified, only public and system patterns
                query = query.where(
                    or_(
                        LearningPattern.access_level == "public",
                        LearningPattern.access_level == "system",
                    ),
                )

            # Text search (SQLite-compatible v2.2.6+)
            if query_text:
                # V-3 MITIGATION: Escape wildcards to prevent DoS
                from src.security.query_builder import SecureQueryBuilder

                escaped_query, escape_char = SecureQueryBuilder.safe_like_pattern(query_text)
                escaped_query_lower, _ = SecureQueryBuilder.safe_like_pattern(query_text.lower())

                # Search in pattern name or JSON data (simple text search in JSON)
                search_filter = or_(
                    LearningPattern.pattern_name.ilike(f"%{escaped_query}%", escape=escape_char),
                    # SQLite: Search for text within JSON field (stored as text)
                    # This is less sophisticated than PostgreSQL jsonb_path_exists
                    # but works for basic text matching
                    func.lower(cast(LearningPattern.pattern_data, sa.String)).like(
                        f"%{escaped_query_lower}%", escape=escape_char
                    ),
                )
                query = query.where(search_filter)

            # Category filters
            if category:
                query = query.where(LearningPattern.category == category)
            if subcategory:
                query = query.where(LearningPattern.subcategory == subcategory)
            if namespace:
                query = query.where(LearningPattern.namespace == namespace)

            # Access level filter
            if access_levels:
                query = query.where(LearningPattern.access_level.in_(access_levels))

            # Performance filters
            if min_success_rate > 0:
                query = query.where(LearningPattern.success_rate >= min_success_rate)
            if min_usage_count > 0:
                query = query.where(LearningPattern.usage_count >= min_usage_count)

            # Order by relevance (usage count * success rate * confidence score)
            query = (
                query.order_by(
                    desc(
                        LearningPattern.usage_count
                        * LearningPattern.success_rate
                        * LearningPattern.confidence_score,
                    ),
                )
                .limit(limit)
                .offset(offset)
            )

            result = await session.execute(query)
            patterns = result.scalars().all()

            self._set_cache(cache_key, patterns)
            return patterns

    async def use_pattern(
        self,
        pattern_id: UUID,
        using_agent_id: str | None = None,
        execution_time: float | None = None,
        success: bool | None = None,
        context_data: dict[str, Any] | None = None,
    ) -> LearningPattern:
        """Record pattern usage and update analytics.

        Args:
            pattern_id: Pattern UUID
            using_agent_id: ID of agent using the pattern
            execution_time: Execution time in seconds
            success: Whether the usage was successful
            context_data: Additional context information

        Returns:
            Updated LearningPattern

        Raises:
            NotFoundError: If pattern not found
            PermissionError: If access denied

        """
        async with get_db_session() as session:
            # Get pattern with write lock
            result = await session.execute(
                select(LearningPattern).where(LearningPattern.id == pattern_id).with_for_update(),
            )
            pattern = result.scalar_one_or_none()

            if not pattern:
                raise NotFoundError("LearningPattern", str(pattern_id))

            if not pattern.can_access(using_agent_id):
                raise PermissionError("Access denied to this learning pattern")

            # Update pattern usage
            by_owner = pattern.agent_id == using_agent_id
            pattern.increment_usage(by_owner=by_owner, execution_time=execution_time)

            if success is not None:
                pattern.update_success_rate(success, by_owner=by_owner)

            # Record usage history
            usage_record = PatternUsageHistory(
                pattern_id=pattern_id,
                agent_id=using_agent_id,
                execution_time=execution_time,
                success=success,
                context_data=context_data,
            )
            session.add(usage_record)

            await session.flush()
            await session.refresh(pattern)

            logger.info(f"Pattern {pattern.pattern_name} used by agent {using_agent_id}")
            return pattern

    async def update_pattern(
        self,
        pattern_id: UUID,
        updating_agent_id: str,
        pattern_data: dict[str, Any] | None = None,
        learning_weight: float | None = None,
        complexity_score: float | None = None,
        access_level: str | None = None,
        shared_with_agents: list[str] | None = None,
    ) -> LearningPattern:
        """Update learning pattern with validation.

        Args:
            pattern_id: Pattern UUID
            updating_agent_id: ID of agent updating the pattern
            pattern_data: New pattern data
            learning_weight: New learning weight
            complexity_score: New complexity score
            access_level: New access level
            shared_with_agents: List of agents to share with

        Returns:
            Updated LearningPattern

        Raises:
            NotFoundError: If pattern not found
            PermissionError: If access denied
            ValidationError: If validation fails

        """
        async with get_db_session() as session:
            result = await session.execute(
                select(LearningPattern).where(LearningPattern.id == pattern_id).with_for_update(),
            )
            pattern = result.scalar_one_or_none()

            if not pattern:
                raise NotFoundError("LearningPattern", str(pattern_id))

            # Only owner can update pattern
            if pattern.agent_id != updating_agent_id:
                raise PermissionError("Only pattern owner can update")

            # Update fields
            if pattern_data is not None:
                pattern.pattern_data = pattern_data

            if learning_weight is not None:
                if not 0.0 <= learning_weight <= 10.0:
                    raise ValidationError("Learning weight must be between 0.0 and 10.0")
                pattern.learning_weight = learning_weight

            if complexity_score is not None:
                if not 0.0 <= complexity_score <= 1.0:
                    raise ValidationError("Complexity score must be between 0.0 and 1.0")
                pattern.complexity_score = complexity_score

            if access_level is not None:
                if access_level not in ["private", "shared", "public", "system"]:
                    raise ValidationError("Invalid access level")
                pattern.access_level = access_level

            if shared_with_agents is not None:
                pattern.shared_with_agents = shared_with_agents

            await session.flush()
            await session.refresh(pattern)

            logger.info(f"Pattern {pattern.pattern_name} updated by agent {updating_agent_id}")
            return pattern

    async def delete_pattern(self, pattern_id: UUID, deleting_agent_id: str) -> bool:
        """Delete learning pattern with access control.

        Args:
            pattern_id: Pattern UUID
            deleting_agent_id: ID of agent deleting the pattern

        Returns:
            True if deleted successfully

        Raises:
            NotFoundError: If pattern not found
            PermissionError: If access denied

        """
        async with get_db_session() as session:
            result = await session.execute(
                select(LearningPattern).where(LearningPattern.id == pattern_id),
            )
            pattern = result.scalar_one_or_none()

            if not pattern:
                raise NotFoundError("LearningPattern", str(pattern_id))

            # Only owner can delete pattern
            if pattern.agent_id != deleting_agent_id:
                raise PermissionError("Only pattern owner can delete")

            await session.delete(pattern)

            logger.info(f"Pattern {pattern.pattern_name} deleted by agent {deleting_agent_id}")
            return True

    async def get_pattern_analytics(
        self, agent_id: str | None = None, namespace: str | None = None, days: int = 30,
    ) -> dict[str, Any]:
        """Get comprehensive pattern analytics.

        Args:
            agent_id: Optional agent filter
            namespace: Optional namespace filter
            days: Number of days to analyze

        Returns:
            Dictionary with analytics data

        """
        cache_key = self._cache_key(
            "get_pattern_analytics", agent_id=agent_id, namespace=namespace, days=days,
        )

        cached = self._get_cached(cache_key)
        if cached:
            return cached

        since_date = datetime.now() - timedelta(days=days)

        async with get_db_session() as session:
            # Base query
            base_query = select(LearningPattern)

            if agent_id:
                base_query = base_query.where(LearningPattern.agent_id == agent_id)
            if namespace:
                base_query = base_query.where(LearningPattern.namespace == namespace)

            # Total patterns
            total_patterns = await session.scalar(
                select(func.count()).select_from(base_query.subquery()),
            )

            # Category distribution - consume immediately
            category_dist_result = await session.execute(
                select(LearningPattern.category, func.count().label("count")).group_by(
                    LearningPattern.category,
                ),
            )
            category_dist = category_dist_result.all()

            # Top patterns by usage - consume immediately
            top_patterns_result = await session.execute(
                base_query.order_by(desc(LearningPattern.usage_count)).limit(10),
            )
            top_patterns = top_patterns_result.scalars().all()

            # Usage over time (recent usage) - SQLite-compatible v2.2.6+
            # SQLite: Use date() function instead of PostgreSQL's date_trunc()
            recent_usage_result = await session.execute(
                select(
                    func.date(PatternUsageHistory.used_at).label("day"),
                    func.count().label("usage_count"),
                )
                .where(PatternUsageHistory.used_at >= since_date)
                .group_by(func.date(PatternUsageHistory.used_at))
                .order_by("day"),
            )
            recent_usage = recent_usage_result.all()

            # Success rate statistics (SQLite-compatible v2.2.6+)
            # Note: SQLite doesn't have stddev() - removed for compatibility
            success_stats_result = await session.execute(
                select(
                    func.avg(LearningPattern.success_rate).label("avg_success_rate"),
                    func.min(LearningPattern.success_rate).label("min_success_rate"),
                    func.max(LearningPattern.success_rate).label("max_success_rate"),
                ).select_from(base_query.subquery()),
            )
            success_stats = success_stats_result.first()

            analytics = {
                "total_patterns": total_patterns or 0,
                "category_distribution": [
                    {"category": row.category, "count": row.count} for row in category_dist
                ],
                "top_patterns": [
                    {
                        "id": str(pattern.id),
                        "name": pattern.pattern_name,
                        "usage_count": pattern.usage_count,
                        "success_rate": pattern.success_rate,
                        "confidence_score": pattern.confidence_score,
                    }
                    for pattern in top_patterns
                ],
                # SQLite date() returns string (YYYY-MM-DD), not datetime
                "recent_usage": [
                    {"day": row.day, "usage_count": row.usage_count}
                    for row in recent_usage
                ],
                "success_statistics": dict(success_stats._asdict())
                if success_stats
                else {},
            }

            self._set_cache(cache_key, analytics)
            return analytics

    async def recommend_patterns(
        self,
        agent_id: str,
        category: str | None = None,
        context_data: dict[str, Any] | None = None,
        limit: int = 10,
    ) -> list[tuple[LearningPattern, float]]:
        """Recommend patterns for an agent based on usage history and context.

        Args:
            agent_id: Agent ID requesting recommendations
            category: Optional category filter
            context_data: Context information for better recommendations
            limit: Number of recommendations

        Returns:
            List of tuples (pattern, relevance_score)

        """
        async with get_db_session() as session:
            # Get agent's usage history
            agent_history = await session.execute(
                select(
                    PatternUsageHistory.pattern_id,
                    func.count().label("usage_count"),
                    func.avg(func.coalesce(PatternUsageHistory.success, 0.5)).label("avg_success"),
                )
                .where(PatternUsageHistory.agent_id == agent_id)
                .group_by(PatternUsageHistory.pattern_id),
            )

            used_patterns = {
                str(row.pattern_id): {
                    "usage_count": row.usage_count,
                    "avg_success": float(row.avg_success),
                }
                for row in agent_history
            }

            # Get candidate patterns (not owned by agent, accessible)
            query = select(LearningPattern).where(
                and_(
                    LearningPattern.agent_id != agent_id,
                    or_(
                        LearningPattern.access_level == "public",
                        LearningPattern.access_level == "system",
                        and_(
                            LearningPattern.access_level == "shared",
                            # SQLite JSON array containment check (Parameterized - SQL Injection Safe)
                            # SECURITY FIX (2025-11-08): Use bindparams() to prevent SQL injection (CVSS 9.8)
                            # Previous vulnerable code: f"WHERE value = '{agent_id}'"
                            # Attack vector: agent_id = "'; DROP TABLE learning_patterns; --"
                            text(
                                "EXISTS (SELECT 1 FROM json_each(learning_patterns.shared_with_agents) "
                                "WHERE value = :agent_id)"
                            ).bindparams(agent_id=agent_id),
                        ),
                    ),
                ),
            )

            if category:
                query = query.where(LearningPattern.category == category)

            candidates = await session.execute(query)

            recommendations = []
            for pattern in candidates.scalars().all():
                # Calculate relevance score
                base_score = (
                    pattern.success_rate * 0.4
                    + min(pattern.usage_count / 10.0, 1.0) * 0.3
                    + pattern.confidence_score * 0.3
                )

                # Boost score if similar patterns were used successfully
                similarity_boost = 0.0
                pattern_id_str = str(pattern.id)

                if pattern_id_str in used_patterns:
                    history = used_patterns[pattern_id_str]
                    similarity_boost = history["avg_success"] * 0.2

                # Context-based adjustments (simplified)
                context_boost = 0.0
                if context_data and pattern.pattern_data:
                    # Simple keyword matching for context relevance
                    context_keywords = set(str(context_data).lower().split())
                    pattern_keywords = set(str(pattern.pattern_data).lower().split())
                    overlap = len(context_keywords & pattern_keywords)
                    context_boost = min(overlap / max(len(context_keywords), 1), 0.2)

                final_score = base_score + similarity_boost + context_boost
                recommendations.append((pattern, final_score))

            # Sort by relevance score and limit results
            recommendations.sort(key=lambda x: x[1], reverse=True)
            return recommendations[:limit]

    async def batch_create_patterns(
        self, patterns_data: list[dict[str, Any]], agent_id: str | None = None,
    ) -> list[LearningPattern]:
        """Create multiple patterns in a batch for optimal performance.

        Args:
            patterns_data: List of pattern creation data
            agent_id: Default agent ID for patterns

        Returns:
            List of created LearningPattern instances

        """
        created_patterns = []

        async with get_db_session() as session:
            for pattern_data in patterns_data:
                try:
                    # Use provided agent_id or default
                    pattern_agent_id = pattern_data.get("agent_id", agent_id)

                    pattern = LearningPattern(
                        pattern_name=pattern_data["pattern_name"],
                        agent_id=pattern_agent_id,
                        namespace=pattern_data.get("namespace", "default"),
                        category=pattern_data["category"],
                        subcategory=pattern_data.get("subcategory"),
                        access_level=pattern_data.get("access_level", "private"),
                        pattern_data=pattern_data["pattern_data"],
                        learning_weight=pattern_data.get("learning_weight", 1.0),
                        complexity_score=pattern_data.get("complexity_score"),
                    )

                    session.add(pattern)
                    created_patterns.append(pattern)

                except Exception as e:
                    logger.error(
                        f"Failed to create pattern {pattern_data.get('pattern_name', 'unknown')}: {e}",
                    )
                    continue

            # Commit all at once for better performance
            await session.flush()

            # Refresh all patterns
            for pattern in created_patterns:
                await session.refresh(pattern)

            logger.info(f"Batch created {len(created_patterns)} patterns")
            return created_patterns
