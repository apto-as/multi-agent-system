"""Adaptive Tool Ranking Service for TMWS.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 4.1 - Learning Integration

Integrates with Learning system to provide personalized tool ranking based on:
- Historical usage patterns (from LearningService)
- Success rate by agent (from LearningService)
- Context similarity (from embeddings)
- Tool trust score (from verification system)

Performance: < 10ms ranking overhead on P95

Author: Artemis (Implementation) + Aurora (Research)
Created: 2025-12-05
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from ..models.tool_search import ToolSearchResult, ToolSourceType

# Security constants
MAX_AGENT_ID_LENGTH = 64
MAX_QUERY_LENGTH = 1000
MAX_TOOL_NAME_LENGTH = 128
MAX_SERVER_ID_LENGTH = 128
VALID_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

logger = logging.getLogger(__name__)


def validate_agent_id(agent_id: str) -> str:
    """Validate and sanitize agent ID.

    Args:
        agent_id: Agent identifier to validate

    Returns:
        Sanitized agent ID

    Raises:
        ValueError: If agent_id is invalid
    """
    if not agent_id:
        raise ValueError("agent_id cannot be empty")

    if not isinstance(agent_id, str):
        raise ValueError("agent_id must be a string")

    agent_id = agent_id.strip()

    if len(agent_id) > MAX_AGENT_ID_LENGTH:
        raise ValueError(f"agent_id exceeds maximum length of {MAX_AGENT_ID_LENGTH}")

    if not VALID_ID_PATTERN.match(agent_id):
        raise ValueError("agent_id contains invalid characters (allowed: alphanumeric, dash, underscore)")

    return agent_id


def validate_tool_name(tool_name: str) -> str:
    """Validate and sanitize tool name.

    Args:
        tool_name: Tool name to validate

    Returns:
        Sanitized tool name

    Raises:
        ValueError: If tool_name is invalid
    """
    if not tool_name:
        raise ValueError("tool_name cannot be empty")

    tool_name = tool_name.strip()

    if len(tool_name) > MAX_TOOL_NAME_LENGTH:
        raise ValueError(f"tool_name exceeds maximum length of {MAX_TOOL_NAME_LENGTH}")

    if not VALID_ID_PATTERN.match(tool_name):
        raise ValueError("tool_name contains invalid characters")

    return tool_name


def validate_server_id(server_id: str) -> str:
    """Validate and sanitize server ID.

    Args:
        server_id: Server ID to validate

    Returns:
        Sanitized server ID

    Raises:
        ValueError: If server_id is invalid
    """
    if not server_id:
        raise ValueError("server_id cannot be empty")

    server_id = server_id.strip()

    if len(server_id) > MAX_SERVER_ID_LENGTH:
        raise ValueError(f"server_id exceeds maximum length of {MAX_SERVER_ID_LENGTH}")

    if not VALID_ID_PATTERN.match(server_id):
        raise ValueError("server_id contains invalid characters")

    return server_id


def validate_query(query: str) -> str:
    """Validate and sanitize query string.

    Args:
        query: Query to validate

    Returns:
        Sanitized query

    Raises:
        ValueError: If query is invalid
    """
    if not query:
        return ""

    query = query.strip()

    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"query exceeds maximum length of {MAX_QUERY_LENGTH}")

    return query


class ToolOutcome(str, Enum):
    """Outcome of a tool execution."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    ABANDONED = "abandoned"


@dataclass
class ToolUsagePattern:
    """Represents a tool usage pattern for adaptive ranking."""

    tool_name: str
    server_id: str
    agent_id: str
    usage_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_latency_ms: float = 0.0
    last_used: datetime | None = None
    query_contexts: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.usage_count == 0:
            return 0.0
        return self.success_count / self.usage_count

    @property
    def average_latency_ms(self) -> float:
        """Calculate average latency."""
        if self.usage_count == 0:
            return 0.0
        return self.total_latency_ms / self.usage_count


@dataclass
class ToolRecommendation:
    """A tool recommendation with reasoning."""

    tool_name: str
    server_id: str
    confidence: float
    reason: str
    based_on_patterns: int = 0


@dataclass
class AdaptiveRankingConfig:
    """Configuration for adaptive ranking."""

    # Boost factors
    success_rate_boost: float = 0.2  # Max boost from success rate
    frequency_boost: float = 0.1  # Max boost from usage frequency
    recency_boost: float = 0.1  # Max boost from recent usage
    context_boost: float = 0.15  # Max boost from context similarity

    # Decay factors
    recency_decay_days: float = 30.0  # Days after which recency boost is 0

    # Thresholds
    min_usage_for_personalization: int = 3  # Min usage to apply personalization
    max_patterns_to_consider: int = 100  # Max patterns to retrieve

    # Learning pattern category
    pattern_category: str = "tool-usage"


class AdaptiveRanker:
    """Adaptive ranking engine for tool search results.

    Features:
    - Per-agent personalization based on usage history
    - Context-aware ranking using query similarity
    - Learning pattern integration with LearningService
    - Performance-optimized (< 10ms overhead)

    Integration with 4th Core Feature (Learning):
    - Records tool outcomes via LearningService
    - Retrieves patterns for personalized ranking
    - Supports pattern evolution over time
    """

    def __init__(
        self,
        config: AdaptiveRankingConfig | None = None,
        learning_service: Any = None,
    ):
        """Initialize Adaptive Ranker.

        Args:
            config: Ranking configuration
            learning_service: LearningService instance for pattern management
        """
        self.config = config or AdaptiveRankingConfig()
        self._learning_service = learning_service

        # In-memory cache for agent patterns (hot cache)
        self._agent_patterns: dict[str, dict[str, ToolUsagePattern]] = {}
        self._cache_ttl_seconds: float = 300.0  # 5 minutes
        self._cache_timestamps: dict[str, float] = {}

        logger.info("AdaptiveRanker initialized")

    def set_learning_service(self, learning_service: Any) -> None:
        """Set or update the learning service.

        Args:
            learning_service: LearningService instance
        """
        self._learning_service = learning_service

    async def rank_for_agent(
        self,
        results: list[ToolSearchResult],
        agent_id: str,
        query_context: dict[str, Any] | None = None,
    ) -> list[ToolSearchResult]:
        """Apply personalized ranking to search results.

        Args:
            results: Base search results
            agent_id: Agent requesting the ranking
            query_context: Optional context for context-aware boosting

        Returns:
            Re-ranked results with personalization applied

        Raises:
            ValueError: If agent_id is invalid
        """
        if not results:
            return results

        # H-1 Security Fix: Validate agent_id
        agent_id = validate_agent_id(agent_id)

        # Get agent's usage patterns
        patterns = await self._get_agent_patterns(agent_id)

        if len(patterns) < self.config.min_usage_for_personalization:
            # Not enough data for personalization, return original order
            logger.debug(f"Insufficient patterns for agent {agent_id}, skipping personalization")
            return results

        # Calculate personalized boost for each result
        boosted_results = []
        for result in results:
            boost = self._calculate_boost(result, patterns, query_context)
            # Create a new result with boosted score
            boosted_result = ToolSearchResult(
                tool_name=result.tool_name,
                server_id=result.server_id,
                description=result.description,
                relevance_score=result.relevance_score,
                source_type=result.source_type,
                tags=result.tags,
                input_schema=result.input_schema,
                # Apply boost to weighted score
                _personalization_boost=boost,
            )
            boosted_results.append((boosted_result, result.weighted_score * (1.0 + boost)))

        # Sort by boosted score
        boosted_results.sort(key=lambda x: x[1], reverse=True)

        logger.debug(f"Applied adaptive ranking for agent {agent_id}: {len(results)} results")
        return [r for r, _ in boosted_results]

    async def record_outcome(
        self,
        agent_id: str,
        tool_name: str,
        server_id: str,
        query: str,
        outcome: ToolOutcome,
        latency_ms: float = 0.0,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Record tool usage outcome for learning.

        Args:
            agent_id: Agent that used the tool
            tool_name: Name of the tool
            server_id: Server ID the tool belongs to
            query: Original search query
            outcome: Outcome of the tool execution
            latency_ms: Execution latency in milliseconds
            context: Additional context data

        Raises:
            ValueError: If any input parameter is invalid
        """
        # H-1 Security Fix: Validate all inputs
        agent_id = validate_agent_id(agent_id)
        tool_name = validate_tool_name(tool_name)
        server_id = validate_server_id(server_id)
        query = validate_query(query)

        # Update local cache immediately
        await self._update_local_pattern(
            agent_id=agent_id,
            tool_name=tool_name,
            server_id=server_id,
            query=query,
            outcome=outcome,
            latency_ms=latency_ms,
        )

        # Store in LearningService for persistence
        if self._learning_service:
            await self._store_pattern_in_learning(
                agent_id=agent_id,
                tool_name=tool_name,
                server_id=server_id,
                query=query,
                outcome=outcome,
                latency_ms=latency_ms,
                context=context,
            )

        logger.debug(f"Recorded tool outcome: {tool_name} = {outcome.value} for agent {agent_id}")

    async def get_recommendations(
        self,
        agent_id: str,
        category: str | None = None,
        limit: int = 5,
    ) -> list[ToolRecommendation]:
        """Get proactive tool recommendations for an agent.

        Args:
            agent_id: Agent to get recommendations for
            category: Optional category filter
            limit: Maximum recommendations to return

        Returns:
            List of tool recommendations
        """
        patterns = await self._get_agent_patterns(agent_id)

        if not patterns:
            return []

        # Rank patterns by success rate and frequency
        scored_patterns: list[tuple[ToolUsagePattern, float]] = []
        for pattern in patterns.values():
            if pattern.usage_count < 2:
                continue

            # Score based on success rate and frequency
            score = pattern.success_rate * 0.7 + min(pattern.usage_count / 100, 1.0) * 0.3
            scored_patterns.append((pattern, score))

        # Sort and create recommendations
        scored_patterns.sort(key=lambda x: x[1], reverse=True)

        recommendations = []
        for pattern, score in scored_patterns[:limit]:
            recommendations.append(
                ToolRecommendation(
                    tool_name=pattern.tool_name,
                    server_id=pattern.server_id,
                    confidence=score,
                    reason=f"Used {pattern.usage_count} times with {pattern.success_rate:.0%} success rate",
                    based_on_patterns=pattern.usage_count,
                )
            )

        return recommendations

    async def get_agent_stats(self, agent_id: str) -> dict[str, Any]:
        """Get usage statistics for an agent.

        Args:
            agent_id: Agent to get stats for

        Returns:
            Dictionary with usage statistics
        """
        patterns = await self._get_agent_patterns(agent_id)

        if not patterns:
            return {
                "agent_id": agent_id,
                "total_tools_used": 0,
                "total_usage_count": 0,
                "overall_success_rate": 0.0,
                "top_tools": [],
            }

        total_usage = sum(p.usage_count for p in patterns.values())
        total_success = sum(p.success_count for p in patterns.values())

        # Get top 5 most used tools
        sorted_patterns = sorted(patterns.values(), key=lambda p: p.usage_count, reverse=True)
        top_tools = [
            {"tool_name": p.tool_name, "usage_count": p.usage_count, "success_rate": p.success_rate}
            for p in sorted_patterns[:5]
        ]

        return {
            "agent_id": agent_id,
            "total_tools_used": len(patterns),
            "total_usage_count": total_usage,
            "overall_success_rate": total_success / total_usage if total_usage > 0 else 0.0,
            "top_tools": top_tools,
        }

    # Private methods

    def _calculate_boost(
        self,
        result: ToolSearchResult,
        patterns: dict[str, ToolUsagePattern],
        query_context: dict[str, Any] | None,
    ) -> float:
        """Calculate personalization boost for a result.

        Args:
            result: Search result to boost
            patterns: Agent's usage patterns
            query_context: Optional query context

        Returns:
            Boost factor (0.0 - 0.5 typically)
        """
        pattern_key = f"{result.server_id}:{result.tool_name}"
        pattern = patterns.get(pattern_key)

        if not pattern:
            return 0.0

        boost = 0.0

        # Success rate boost
        boost += pattern.success_rate * self.config.success_rate_boost

        # Frequency boost (logarithmic scale)
        import math

        if pattern.usage_count > 0:
            frequency_factor = min(math.log10(pattern.usage_count + 1) / 2, 1.0)
            boost += frequency_factor * self.config.frequency_boost

        # Recency boost
        if pattern.last_used:
            days_ago = (datetime.now() - pattern.last_used).days
            if days_ago < self.config.recency_decay_days:
                recency_factor = 1.0 - (days_ago / self.config.recency_decay_days)
                boost += recency_factor * self.config.recency_boost

        # Context similarity boost
        if query_context and pattern.query_contexts:
            context_similarity = self._calculate_context_similarity(
                query_context.get("query", ""), pattern.query_contexts
            )
            boost += context_similarity * self.config.context_boost

        return boost

    def _calculate_context_similarity(self, query: str, past_queries: list[str]) -> float:
        """Calculate simple context similarity.

        Args:
            query: Current query
            past_queries: Past queries for this tool

        Returns:
            Similarity score (0.0 - 1.0)
        """
        if not query or not past_queries:
            return 0.0

        # Simple word overlap for fast computation
        query_words = set(query.lower().split())
        max_similarity = 0.0

        for past_query in past_queries[-10:]:  # Only check last 10 queries
            past_words = set(past_query.lower().split())
            if query_words and past_words:
                intersection = query_words & past_words
                union = query_words | past_words
                similarity = len(intersection) / len(union) if union else 0.0
                max_similarity = max(max_similarity, similarity)

        return max_similarity

    async def _get_agent_patterns(self, agent_id: str) -> dict[str, ToolUsagePattern]:
        """Get cached patterns for an agent.

        Args:
            agent_id: Agent ID

        Returns:
            Dictionary of patterns keyed by "server_id:tool_name"
        """
        import time

        now = time.time()

        # Check cache validity
        if agent_id in self._agent_patterns:
            cache_time = self._cache_timestamps.get(agent_id, 0)
            if now - cache_time < self._cache_ttl_seconds:
                return self._agent_patterns[agent_id]

        # Load from LearningService if available
        if self._learning_service:
            patterns = await self._load_patterns_from_learning(agent_id)
            self._agent_patterns[agent_id] = patterns
            self._cache_timestamps[agent_id] = now
            return patterns

        # Return cached or empty
        return self._agent_patterns.get(agent_id, {})

    async def _load_patterns_from_learning(self, agent_id: str) -> dict[str, ToolUsagePattern]:
        """Load patterns from LearningService.

        Args:
            agent_id: Agent ID

        Returns:
            Dictionary of patterns
        """
        patterns: dict[str, ToolUsagePattern] = {}

        try:
            # Get patterns from LearningService
            learning_patterns = await self._learning_service.search_patterns(
                category=self.config.pattern_category,
                requesting_agent_id=agent_id,
                limit=self.config.max_patterns_to_consider,
            )

            for lp in learning_patterns:
                content = lp.get("content", {})
                if isinstance(content, str):
                    continue

                tool_name = content.get("tool_name", "")
                server_id = content.get("server_id", "")

                if not tool_name:
                    continue

                pattern_key = f"{server_id}:{tool_name}"
                if pattern_key not in patterns:
                    patterns[pattern_key] = ToolUsagePattern(
                        tool_name=tool_name,
                        server_id=server_id,
                        agent_id=agent_id,
                    )

                pattern = patterns[pattern_key]
                pattern.usage_count += 1

                if content.get("outcome") == "success":
                    pattern.success_count += 1
                elif content.get("outcome") == "error":
                    pattern.error_count += 1

                if content.get("latency_ms"):
                    pattern.total_latency_ms += content["latency_ms"]

                if content.get("query"):
                    pattern.query_contexts.append(content["query"])

                # Track last used
                created_at = lp.get("created_at")
                if created_at and isinstance(created_at, datetime):
                    if not pattern.last_used or created_at > pattern.last_used:
                        pattern.last_used = created_at

        except Exception as e:
            logger.warning(f"Failed to load patterns from LearningService: {e}")

        return patterns

    async def _update_local_pattern(
        self,
        agent_id: str,
        tool_name: str,
        server_id: str,
        query: str,
        outcome: ToolOutcome,
        latency_ms: float,
    ) -> None:
        """Update local pattern cache.

        Args:
            agent_id: Agent ID
            tool_name: Tool name
            server_id: Server ID
            query: Search query
            outcome: Execution outcome
            latency_ms: Execution latency
        """
        if agent_id not in self._agent_patterns:
            self._agent_patterns[agent_id] = {}

        pattern_key = f"{server_id}:{tool_name}"
        if pattern_key not in self._agent_patterns[agent_id]:
            self._agent_patterns[agent_id][pattern_key] = ToolUsagePattern(
                tool_name=tool_name,
                server_id=server_id,
                agent_id=agent_id,
            )

        pattern = self._agent_patterns[agent_id][pattern_key]
        pattern.usage_count += 1
        pattern.total_latency_ms += latency_ms
        pattern.last_used = datetime.now()

        if outcome == ToolOutcome.SUCCESS:
            pattern.success_count += 1
        elif outcome in (ToolOutcome.ERROR, ToolOutcome.TIMEOUT):
            pattern.error_count += 1

        if query:
            pattern.query_contexts.append(query)
            # Keep only last 50 queries
            pattern.query_contexts = pattern.query_contexts[-50:]

    async def _store_pattern_in_learning(
        self,
        agent_id: str,
        tool_name: str,
        server_id: str,
        query: str,
        outcome: ToolOutcome,
        latency_ms: float,
        context: dict[str, Any] | None,
    ) -> None:
        """Store pattern in LearningService.

        Args:
            agent_id: Agent ID
            tool_name: Tool name
            server_id: Server ID
            query: Search query
            outcome: Execution outcome
            latency_ms: Execution latency
            context: Additional context
        """
        try:
            pattern_content = {
                "tool_name": tool_name,
                "server_id": server_id,
                "query": query,
                "outcome": outcome.value,
                "latency_ms": latency_ms,
                "timestamp": datetime.now().isoformat(),
            }

            if context:
                pattern_content["context"] = context

            await self._learning_service.create_pattern(
                name=f"Tool Usage: {tool_name}",
                category=self.config.pattern_category,
                content=pattern_content,
                creator_agent_id=agent_id,
                sharing_level="agent_only",
            )

        except Exception as e:
            logger.warning(f"Failed to store pattern in LearningService: {e}")
