"""ProactiveContextService - Layer 4 of Autonomous Learning System.

This service provides proactive skill suggestion injection at orchestration start.
It uses ChromaDB semantic search to find relevant skills based on task context
and tracks suggestion effectiveness for continuous learning improvement.

Architecture:
    Layer 1: SkillService (CRUD operations)
    Layer 2: PatternDetectionService (pattern detection)
    Layer 3: LearningLoopService (continuous improvement)
    Layer 4: ProactiveContextService (skill injection) ← THIS SERVICE

Performance Targets:
    - Skill suggestion: <100ms P95
    - Context injection: <50ms P95
    - Batch suggestion (10 skills): <200ms P95

Security Requirements:
    - P0-1: Namespace isolation (verified from DB)
    - Skill visibility (PUBLIC/SHARED only for suggestions)
    - No cross-namespace data leakage
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import log_and_raise
from src.models.execution_trace import SkillSuggestion
from src.models.skill import AccessLevel, Skill

if TYPE_CHECKING:
    from src.services.skill_service import SkillService
    from src.services.vector_search_service import VectorSearchService

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class SuggestedSkill:
    """A skill suggested for the current context."""

    skill_id: str
    skill_name: str
    display_name: str | None
    description: str | None
    relevance_score: float
    suggestion_reason: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "skill_id": self.skill_id,
            "skill_name": self.skill_name,
            "display_name": self.display_name,
            "description": self.description,
            "relevance_score": self.relevance_score,
            "suggestion_reason": self.suggestion_reason,
            "tags": self.tags,
        }


@dataclass
class ContextInjectionResult:
    """Result of context injection operation."""

    orchestration_id: str
    agent_id: str
    namespace: str
    suggested_skills: list[SuggestedSkill]
    suggestion_ids: list[str]
    total_candidates: int
    injection_time_ms: float
    context_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "orchestration_id": self.orchestration_id,
            "agent_id": self.agent_id,
            "namespace": self.namespace,
            "suggested_skills": [s.to_dict() for s in self.suggested_skills],
            "suggestion_ids": self.suggestion_ids,
            "total_candidates": self.total_candidates,
            "injection_time_ms": self.injection_time_ms,
            "context_summary": self.context_summary,
        }


@dataclass
class SuggestionFeedback:
    """Feedback on a skill suggestion."""

    suggestion_id: str
    was_activated: bool
    was_helpful: bool | None = None


@dataclass
class EffectivenessReport:
    """Report on skill suggestion effectiveness."""

    namespace: str
    period_days: int
    total_suggestions: int
    activated_count: int
    helpful_count: int
    unhelpful_count: int
    no_feedback_count: int
    activation_rate: float
    helpfulness_rate: float
    top_effective_skills: list[dict[str, Any]]
    low_performing_skills: list[dict[str, Any]]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "namespace": self.namespace,
            "period_days": self.period_days,
            "total_suggestions": self.total_suggestions,
            "activated_count": self.activated_count,
            "helpful_count": self.helpful_count,
            "unhelpful_count": self.unhelpful_count,
            "no_feedback_count": self.no_feedback_count,
            "activation_rate": self.activation_rate,
            "helpfulness_rate": self.helpfulness_rate,
            "top_effective_skills": self.top_effective_skills,
            "low_performing_skills": self.low_performing_skills,
            "recommendations": self.recommendations,
        }


# =============================================================================
# Service Implementation
# =============================================================================


class ProactiveContextService:
    """Service for proactive skill suggestion and context injection (Layer 4).

    This service provides intelligent skill suggestions at orchestration start
    by analyzing task context and finding semantically relevant skills.

    Features:
        - Semantic skill matching via ChromaDB
        - Context-aware suggestion ranking
        - Suggestion tracking and effectiveness analysis
        - Feedback-based learning integration

    Security:
        - P0-1: Namespace isolation enforced
        - Only PUBLIC/SHARED skills suggested
        - No cross-namespace data leakage

    Performance:
        - skill_suggestion: <100ms P95
        - context_injection: <50ms P95
        - batch_suggestion: <200ms P95
    """

    # Configuration constants
    MIN_RELEVANCE_SCORE = 0.7  # Minimum score for suggestion (0.7 = 70% similar)
    MAX_SUGGESTIONS_PER_INJECTION = 5  # Maximum skills to suggest per orchestration
    DEFAULT_TOP_K = 20  # Initial search limit for filtering
    SUGGESTION_COOLDOWN_HOURS = 2  # Avoid re-suggesting same skill too soon
    EFFECTIVENESS_PERIOD_DAYS = 30  # Default period for effectiveness analysis

    # Low-performing threshold
    LOW_ACTIVATION_THRESHOLD = 0.2  # Skills with <20% activation rate are low-performing
    HIGH_EFFECTIVENESS_THRESHOLD = 0.8  # Skills with >80% helpfulness are highly effective

    def __init__(
        self,
        session: AsyncSession,
        skill_service: SkillService | None = None,
        vector_search_service: VectorSearchService | None = None,
        embedding_service: Any | None = None,
    ) -> None:
        """Initialize ProactiveContextService.

        Args:
            session: Async database session
            skill_service: Optional SkillService instance (lazy-loaded if not provided)
            vector_search_service: Optional VectorSearchService instance
            embedding_service: Optional embedding service for query encoding
        """
        self.session = session
        self._skill_service = skill_service
        self._vector_search_service = vector_search_service
        self._embedding_service = embedding_service

        # Lock for suggestion tracking (prevents duplicate suggestions)
        self._suggestion_lock = asyncio.Lock()

    # =========================================================================
    # Lazy-loaded Dependencies
    # =========================================================================

    @property
    def skill_service(self) -> SkillService:
        """Lazy-load SkillService."""
        if self._skill_service is None:
            from src.services.skill_service import SkillService

            self._skill_service = SkillService(session=self.session)
        return self._skill_service

    @property
    def vector_search_service(self) -> VectorSearchService:
        """Lazy-load VectorSearchService."""
        if self._vector_search_service is None:
            from src.services.vector_search_service import get_vector_search_service

            self._vector_search_service = get_vector_search_service()
        return self._vector_search_service

    @property
    def embedding_service(self) -> Any:
        """Lazy-load embedding service."""
        if self._embedding_service is None:
            from src.services.ollama_embedding_service import get_ollama_embedding_service

            self._embedding_service = get_ollama_embedding_service()
        return self._embedding_service

    # =========================================================================
    # Core Methods
    # =========================================================================

    async def suggest_skills(
        self,
        task_context: str,
        namespace: str,
        agent_id: str,
        *,
        max_suggestions: int | None = None,
        min_relevance: float | None = None,
        exclude_skill_ids: list[str] | None = None,
    ) -> list[SuggestedSkill]:
        """Suggest relevant skills based on task context.

        Args:
            task_context: Description of the current task/context
            namespace: Agent's namespace (P0-1: verified from DB)
            agent_id: Agent requesting suggestions
            max_suggestions: Maximum number of suggestions (default: 5)
            min_relevance: Minimum relevance score (default: 0.7)
            exclude_skill_ids: Skill IDs to exclude from suggestions

        Returns:
            List of suggested skills sorted by relevance

        Performance Target: <100ms P95
        """
        start_time = asyncio.get_event_loop().time()

        max_suggestions = max_suggestions or self.MAX_SUGGESTIONS_PER_INJECTION
        min_relevance = min_relevance or self.MIN_RELEVANCE_SCORE
        exclude_skill_ids = exclude_skill_ids or []

        logger.debug(
            f"🎯 Suggesting skills for namespace={namespace}, agent={agent_id}, "
            f"context_len={len(task_context)}"
        )

        try:
            # 1. Generate embedding for task context
            query_embedding = await self._generate_embedding(task_context)

            # 2. Search for similar skills via ChromaDB
            search_results = await self._search_skills(
                query_embedding=query_embedding,
                namespace=namespace,
                top_k=self.DEFAULT_TOP_K,
                min_similarity=min_relevance,
            )

            # 3. Filter and rank candidates
            candidates = await self._filter_candidates(
                search_results=search_results,
                namespace=namespace,
                agent_id=agent_id,
                exclude_skill_ids=exclude_skill_ids,
            )

            # 4. Select top suggestions
            suggestions = candidates[:max_suggestions]

            elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            logger.info(
                f"✅ Suggested {len(suggestions)} skills in {elapsed_ms:.2f}ms "
                f"(from {len(search_results)} candidates)"
            )

            return suggestions

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(f"❌ Skill suggestion failed: {e}")
            log_and_raise(
                RuntimeError,
                "Failed to suggest skills",
                original_exception=e,
                details={
                    "namespace": namespace,
                    "agent_id": agent_id,
                    "context_length": len(task_context),
                },
            )

    async def inject_context(
        self,
        orchestration_id: str,
        task_context: str,
        namespace: str,
        agent_id: str,
        *,
        max_suggestions: int | None = None,
        min_relevance: float | None = None,
    ) -> ContextInjectionResult:
        """Inject skill suggestions into orchestration context.

        This method combines skill suggestion with tracking, recording
        all suggestions in the database for effectiveness analysis.

        Args:
            orchestration_id: Unique orchestration identifier
            task_context: Description of the current task/context
            namespace: Agent's namespace (P0-1: verified from DB)
            agent_id: Agent receiving suggestions
            max_suggestions: Maximum number of suggestions
            min_relevance: Minimum relevance score

        Returns:
            ContextInjectionResult with suggestions and tracking IDs

        Performance Target: <50ms P95 (excluding suggestion generation)
        """
        start_time = asyncio.get_event_loop().time()

        # 1. Get skill suggestions
        suggestions = await self.suggest_skills(
            task_context=task_context,
            namespace=namespace,
            agent_id=agent_id,
            max_suggestions=max_suggestions,
            min_relevance=min_relevance,
        )

        # 2. Record suggestions for tracking
        suggestion_ids = await self._record_suggestions(
            orchestration_id=orchestration_id,
            agent_id=agent_id,
            namespace=namespace,
            suggestions=suggestions,
        )

        elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000

        logger.info(
            f"🚀 Injected {len(suggestions)} skills for orchestration={orchestration_id} "
            f"in {elapsed_ms:.2f}ms"
        )

        return ContextInjectionResult(
            orchestration_id=orchestration_id,
            agent_id=agent_id,
            namespace=namespace,
            suggested_skills=suggestions,
            suggestion_ids=suggestion_ids,
            total_candidates=len(suggestions),
            injection_time_ms=elapsed_ms,
            context_summary=task_context[:200] if task_context else None,
        )

    async def record_feedback(
        self,
        suggestion_id: str,
        *,
        was_activated: bool = False,
        was_helpful: bool | None = None,
    ) -> bool:
        """Record feedback on a skill suggestion.

        Args:
            suggestion_id: ID of the suggestion to update
            was_activated: Whether the skill was activated
            was_helpful: Whether the suggestion was helpful (optional)

        Returns:
            True if feedback was recorded successfully
        """
        try:
            # Validate UUID format, but query with string (SQLite uses String(36) for UUIDs)
            suggestion_uuid = UUID(suggestion_id)
            result = await self.session.execute(
                select(SkillSuggestion).where(SkillSuggestion.id == str(suggestion_uuid))
            )
            suggestion = result.scalar_one_or_none()

            if suggestion is None:
                logger.warning(f"⚠️ Suggestion not found: {suggestion_id}")
                return False

            # Update suggestion
            if was_activated:
                suggestion.mark_activated()
            if was_helpful is not None:
                suggestion.provide_feedback(was_helpful)

            await self.session.commit()

            logger.debug(
                f"📝 Recorded feedback for suggestion={suggestion_id}: "
                f"activated={was_activated}, helpful={was_helpful}"
            )
            return True

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            logger.error(f"❌ Failed to record feedback: {e}")
            await self.session.rollback()
            return False

    async def get_effectiveness_report(
        self,
        namespace: str,
        *,
        days: int | None = None,
    ) -> EffectivenessReport:
        """Generate effectiveness report for skill suggestions.

        Args:
            namespace: Namespace to analyze
            days: Analysis period in days (default: 30)

        Returns:
            EffectivenessReport with metrics and recommendations
        """
        days = days or self.EFFECTIVENESS_PERIOD_DAYS
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        # 1. Get overall statistics
        stats = await self._get_suggestion_stats(namespace, cutoff_date)

        # 2. Get top effective skills
        top_skills = await self._get_top_effective_skills(namespace, cutoff_date, limit=5)

        # 3. Get low-performing skills
        low_skills = await self._get_low_performing_skills(namespace, cutoff_date, limit=5)

        # 4. Generate recommendations
        recommendations = self._generate_recommendations(
            stats=stats,
            top_skills=top_skills,
            low_skills=low_skills,
        )

        return EffectivenessReport(
            namespace=namespace,
            period_days=days,
            total_suggestions=stats["total"],
            activated_count=stats["activated"],
            helpful_count=stats["helpful"],
            unhelpful_count=stats["unhelpful"],
            no_feedback_count=stats["no_feedback"],
            activation_rate=stats["activation_rate"],
            helpfulness_rate=stats["helpfulness_rate"],
            top_effective_skills=top_skills,
            low_performing_skills=low_skills,
            recommendations=recommendations,
        )

    async def get_recent_suggestions(
        self,
        orchestration_id: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        """Get suggestions for a specific orchestration.

        Args:
            orchestration_id: Orchestration to query
            namespace: Namespace for P0-1 validation

        Returns:
            List of suggestion records
        """
        result = await self.session.execute(
            select(SkillSuggestion)
            .where(
                and_(
                    SkillSuggestion.orchestration_id == orchestration_id,
                    SkillSuggestion.namespace == namespace,  # P0-1
                )
            )
            .order_by(SkillSuggestion.relevance_score.desc())
        )
        suggestions = result.scalars().all()

        return [s.to_dict() for s in suggestions]

    # =========================================================================
    # Private Methods
    # =========================================================================

    async def _generate_embedding(self, text: str) -> list[float]:
        """Generate embedding for text.

        Args:
            text: Text to encode

        Returns:
            1024-dimensional embedding vector
        """
        embedding = await asyncio.to_thread(self.embedding_service.embed_text, text)
        return embedding

    async def _search_skills(
        self,
        query_embedding: list[float],
        namespace: str,
        top_k: int,
        min_similarity: float,
    ) -> list[dict[str, Any]]:
        """Search for similar skills via vector search.

        Note: This searches ChromaDB for skill content embeddings.
        Skills must be indexed in the vector store for this to work.

        Args:
            query_embedding: Query embedding vector
            namespace: Namespace for filtering
            top_k: Maximum results
            min_similarity: Minimum similarity threshold

        Returns:
            List of search results with skill metadata
        """
        # First, get accessible skill IDs from database
        accessible_skills = await self._get_accessible_skill_ids(namespace)

        if not accessible_skills:
            logger.debug("No accessible skills found for namespace")
            return []

        # Search via vector search service
        # Note: We filter by namespace to ensure P0-1 isolation
        results = await self.vector_search_service.search(
            query_embedding=query_embedding,
            top_k=top_k,
            filters={"namespace": namespace, "type": "skill"},
            min_similarity=min_similarity,
        )

        return results

    async def _get_accessible_skill_ids(self, namespace: str) -> list[str]:
        """Get IDs of skills accessible to the namespace.

        Skills are accessible if:
        - They are PUBLIC (visible to all)
        - They are in the same namespace
        - They are SHARED with the namespace

        Args:
            namespace: Target namespace

        Returns:
            List of accessible skill IDs
        """
        # Query for accessible skills
        # Note: Skill.is_deleted is the only status field - there's no is_active
        # Skills with active_version >= 1 are considered "active"
        result = await self.session.execute(
            select(Skill.id).where(
                and_(
                    Skill.is_deleted == False,  # noqa: E712 - Not deleted
                    Skill.active_version >= 1,  # Has at least one active version
                    # Access control: PUBLIC or same namespace
                    (Skill.access_level == AccessLevel.PUBLIC) | (Skill.namespace == namespace),
                )
            )
        )

        skill_ids = [str(row[0]) for row in result.fetchall()]
        return skill_ids

    async def _filter_candidates(
        self,
        search_results: list[dict[str, Any]],
        namespace: str,
        agent_id: str,
        exclude_skill_ids: list[str],
    ) -> list[SuggestedSkill]:
        """Filter and rank skill candidates.

        Args:
            search_results: Raw search results from vector store
            namespace: Target namespace
            agent_id: Agent receiving suggestions
            exclude_skill_ids: Skills to exclude

        Returns:
            Filtered and ranked list of suggested skills
        """
        suggestions: list[SuggestedSkill] = []
        seen_skill_ids: set[str] = set()

        # Get recently suggested skill IDs to avoid repetition
        recent_suggestions = await self._get_recent_skill_ids(namespace, agent_id)

        for result in search_results:
            skill_id = result.get("metadata", {}).get("skill_id")

            if not skill_id:
                continue

            # Skip excluded skills
            if skill_id in exclude_skill_ids:
                continue

            # Skip duplicates
            if skill_id in seen_skill_ids:
                continue

            # Skip recently suggested
            if skill_id in recent_suggestions:
                continue

            seen_skill_ids.add(skill_id)

            # Fetch skill details
            skill_info = await self._get_skill_info(skill_id)
            if skill_info is None:
                continue

            suggestions.append(
                SuggestedSkill(
                    skill_id=skill_id,
                    skill_name=skill_info["name"],
                    display_name=skill_info.get("display_name"),
                    description=skill_info.get("description"),
                    relevance_score=result.get("similarity", 0.0),
                    suggestion_reason=f"Semantic similarity: {result.get('similarity', 0.0):.2%}",
                    tags=skill_info.get("tags", []),
                )
            )

        # Sort by relevance score descending
        suggestions.sort(key=lambda s: s.relevance_score, reverse=True)

        return suggestions

    async def _get_recent_skill_ids(
        self,
        namespace: str,
        agent_id: str,
    ) -> set[str]:
        """Get skill IDs recently suggested to this agent.

        Args:
            namespace: Target namespace
            agent_id: Target agent

        Returns:
            Set of recently suggested skill IDs
        """
        cooldown_cutoff = datetime.now(timezone.utc) - timedelta(
            hours=self.SUGGESTION_COOLDOWN_HOURS
        )

        result = await self.session.execute(
            select(SkillSuggestion.skill_id).where(
                and_(
                    SkillSuggestion.namespace == namespace,
                    SkillSuggestion.agent_id == agent_id,
                    SkillSuggestion.created_at >= cooldown_cutoff,
                )
            )
        )

        return {row[0] for row in result.fetchall()}

    async def _get_skill_info(self, skill_id: str) -> dict[str, Any] | None:
        """Get skill information from database.

        Args:
            skill_id: Skill ID to fetch

        Returns:
            Skill info dictionary or None if not found
        """
        try:
            skill_uuid = UUID(skill_id)
            result = await self.session.execute(
                select(Skill).where(
                    and_(
                        Skill.id == skill_uuid,
                        Skill.is_deleted == False,  # noqa: E712
                    )
                )
            )
            skill = result.scalar_one_or_none()

            if skill is None:
                return None

            return {
                "name": skill.name,
                "display_name": skill.display_name,
                "description": skill.description,
                "tags": skill.tags or [],
            }

        except (ValueError, TypeError):
            return None

    async def _record_suggestions(
        self,
        orchestration_id: str,
        agent_id: str,
        namespace: str,
        suggestions: list[SuggestedSkill],
    ) -> list[str]:
        """Record suggestions in database for tracking.

        Args:
            orchestration_id: Orchestration identifier
            agent_id: Agent receiving suggestions
            namespace: Target namespace
            suggestions: List of suggestions to record

        Returns:
            List of created suggestion IDs
        """
        async with self._suggestion_lock:
            suggestion_ids: list[str] = []

            for suggestion in suggestions:
                record = SkillSuggestion(
                    orchestration_id=orchestration_id,
                    skill_id=suggestion.skill_id,
                    agent_id=agent_id,
                    namespace=namespace,
                    relevance_score=suggestion.relevance_score,
                    suggestion_reason=suggestion.suggestion_reason,
                )
                self.session.add(record)
                await self.session.flush()
                suggestion_ids.append(str(record.id))

            await self.session.commit()

            logger.debug(f"📝 Recorded {len(suggestion_ids)} suggestions")
            return suggestion_ids

    async def _get_suggestion_stats(
        self,
        namespace: str,
        cutoff_date: datetime,
    ) -> dict[str, Any]:
        """Get overall suggestion statistics.

        Args:
            namespace: Target namespace
            cutoff_date: Start date for analysis

        Returns:
            Statistics dictionary
        """
        # Use case() for conditional aggregation (SQLAlchemy-compatible)
        result = await self.session.execute(
            select(
                func.count(SkillSuggestion.id).label("total"),
                func.sum(
                    case(
                        (SkillSuggestion.was_activated == True, 1),  # noqa: E712
                        else_=0,
                    )
                ).label("activated"),
                func.sum(
                    case(
                        (SkillSuggestion.was_helpful == True, 1),  # noqa: E712
                        else_=0,
                    )
                ).label("helpful"),
                func.sum(
                    case(
                        (SkillSuggestion.was_helpful == False, 1),  # noqa: E712
                        else_=0,
                    )
                ).label("unhelpful"),
            ).where(
                and_(
                    SkillSuggestion.namespace == namespace,
                    SkillSuggestion.created_at >= cutoff_date,
                )
            )
        )

        row = result.fetchone()

        total = row[0] or 0
        activated = row[1] or 0
        helpful = row[2] or 0
        unhelpful = row[3] or 0
        no_feedback = total - helpful - unhelpful

        return {
            "total": total,
            "activated": activated,
            "helpful": helpful,
            "unhelpful": unhelpful,
            "no_feedback": no_feedback,
            "activation_rate": activated / total if total > 0 else 0.0,
            "helpfulness_rate": helpful / (helpful + unhelpful)
            if (helpful + unhelpful) > 0
            else 0.0,
        }

    async def _get_top_effective_skills(
        self,
        namespace: str,
        cutoff_date: datetime,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get top effective skills by helpfulness rate.

        Args:
            namespace: Target namespace
            cutoff_date: Start date for analysis
            limit: Maximum results

        Returns:
            List of skill effectiveness data
        """
        # Use case() for conditional aggregation (SQLAlchemy-compatible)
        activated_sum = func.sum(case((SkillSuggestion.was_activated == True, 1), else_=0))  # noqa: E712
        helpful_sum = func.sum(case((SkillSuggestion.was_helpful == True, 1), else_=0))  # noqa: E712

        result = await self.session.execute(
            select(
                SkillSuggestion.skill_id,
                func.count(SkillSuggestion.id).label("total"),
                activated_sum.label("activated"),
                helpful_sum.label("helpful"),
            )
            .where(
                and_(
                    SkillSuggestion.namespace == namespace,
                    SkillSuggestion.created_at >= cutoff_date,
                )
            )
            .group_by(SkillSuggestion.skill_id)
            .having(func.count(SkillSuggestion.id) >= 3)  # Minimum sample size
            .order_by((helpful_sum / func.count(SkillSuggestion.id)).desc())
            .limit(limit)
        )

        top_skills = []
        for row in result.fetchall():
            total = row[1] or 0
            activated = row[2] or 0
            helpful = row[3] or 0

            top_skills.append(
                {
                    "skill_id": row[0],
                    "total_suggestions": total,
                    "activation_rate": activated / total if total > 0 else 0.0,
                    "helpfulness_rate": helpful / total if total > 0 else 0.0,
                }
            )

        return top_skills

    async def _get_low_performing_skills(
        self,
        namespace: str,
        cutoff_date: datetime,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get low-performing skills by activation rate.

        Args:
            namespace: Target namespace
            cutoff_date: Start date for analysis
            limit: Maximum results

        Returns:
            List of skill performance data
        """
        # Use case() for conditional aggregation (SQLAlchemy-compatible)
        activated_sum = func.sum(case((SkillSuggestion.was_activated == True, 1), else_=0))  # noqa: E712

        result = await self.session.execute(
            select(
                SkillSuggestion.skill_id,
                func.count(SkillSuggestion.id).label("total"),
                activated_sum.label("activated"),
            )
            .where(
                and_(
                    SkillSuggestion.namespace == namespace,
                    SkillSuggestion.created_at >= cutoff_date,
                )
            )
            .group_by(SkillSuggestion.skill_id)
            .having(func.count(SkillSuggestion.id) >= 5)  # Minimum sample size
            .order_by((activated_sum / func.count(SkillSuggestion.id)).asc())
            .limit(limit)
        )

        low_skills = []
        for row in result.fetchall():
            total = row[1] or 0
            activated = row[2] or 0
            activation_rate = activated / total if total > 0 else 0.0

            if activation_rate < self.LOW_ACTIVATION_THRESHOLD:
                low_skills.append(
                    {
                        "skill_id": row[0],
                        "total_suggestions": total,
                        "activation_rate": activation_rate,
                    }
                )

        return low_skills

    def _generate_recommendations(
        self,
        stats: dict[str, Any],
        top_skills: list[dict[str, Any]],
        low_skills: list[dict[str, Any]],
    ) -> list[str]:
        """Generate recommendations based on effectiveness data.

        Args:
            stats: Overall statistics
            top_skills: Top effective skills
            low_skills: Low-performing skills

        Returns:
            List of recommendation strings
        """
        recommendations: list[str] = []

        # Activation rate recommendations
        if stats["activation_rate"] < 0.3:
            recommendations.append(
                "Low activation rate (<30%). Consider improving skill relevance "
                "matching or reducing suggestion frequency."
            )
        elif stats["activation_rate"] > 0.7:
            recommendations.append(
                "High activation rate (>70%). Skill suggestions are well-targeted."
            )

        # Helpfulness recommendations
        if stats["helpfulness_rate"] < 0.5:
            recommendations.append(
                "Low helpfulness rate (<50%). Review skill content quality "
                "and relevance matching algorithm."
            )

        # Low-performing skill recommendations
        if low_skills:
            recommendations.append(
                f"Consider reviewing {len(low_skills)} low-performing skills "
                f"with <{self.LOW_ACTIVATION_THRESHOLD:.0%} activation rate."
            )

        # High-performing skill recommendations
        if top_skills and any(
            s["helpfulness_rate"] >= self.HIGH_EFFECTIVENESS_THRESHOLD for s in top_skills
        ):
            recommendations.append(
                "Some skills show >80% helpfulness. Consider promoting them "
                "or using them as templates for new skills."
            )

        # Feedback rate recommendation
        feedback_rate = 1 - (stats["no_feedback"] / stats["total"]) if stats["total"] > 0 else 0
        if feedback_rate < 0.5:
            recommendations.append(
                f"Low feedback rate ({feedback_rate:.0%}). Encourage users to "
                "provide feedback on suggestions to improve the system."
            )

        return recommendations
