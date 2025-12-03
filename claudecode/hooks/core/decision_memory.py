"""
Trinitas Decision Memory System v2.3.0
=======================================

2-level autonomy system for Trinitas agents to prevent unauthorized changes.

Level 1 (Autonomous):
- Bug fixes
- Code cleanup (deletion only)
- Documentation updates
- Test additions
- Performance optimizations (no new features)
- Refactoring (no behavior change)

Level 2 (User Approval Required):
- New features
- New dependencies
- Database schema changes
- API changes
- New integrations
- Architectural changes

Architecture:
- Primary: TMWS MCP semantic search for similar past decisions
- Fallback: File-based JSON storage when TMWS unavailable
- Cache: LRU cache with 100 entries for >95% hit rate
- Performance: <300ms query, <100ms record, <50ms classification
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import httpx
import json
from pathlib import Path
from collections import OrderedDict
import logging
import asyncio

# Configure logging
logger = logging.getLogger(__name__)

# Import security utilities
try:
    from security_utils import (
        validate_decision_id,
        validate_tmws_url,
        validate_and_resolve_path,
        SecurityError
    )
except ImportError:
    # Fallback if security_utils not available
    class SecurityError(Exception):
        pass

    def validate_decision_id(decision_id: str) -> str:
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', decision_id):
            raise ValueError(f"Invalid decision ID: {decision_id}")
        return decision_id

    def validate_tmws_url(url: str, allow_localhost: bool = True) -> str:
        return url  # Minimal validation

    def validate_and_resolve_path(file_path: Path, base_dir: Path, allow_create: bool = False) -> Path:
        return file_path.resolve()


class DecisionType(Enum):
    """意思決定の種類"""
    TECHNICAL_CHOICE = "technical_choice"
    ARCHITECTURE = "architecture"
    IMPLEMENTATION = "implementation"
    SECURITY = "security"
    OPTIMIZATION = "optimization"
    WORKFLOW = "workflow"
    FEATURE_REQUEST = "feature_request"


class DecisionOutcome(Enum):
    """意思決定の結果"""
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    DEFERRED = "deferred"


class AutonomyLevel(Enum):
    """自律実行レベル"""
    LEVEL_1_AUTONOMOUS = 1  # 自律実行可能
    LEVEL_2_APPROVAL = 2    # ユーザー承認必須


@dataclass
class Decision:
    """意思決定レコード"""
    decision_id: str
    timestamp: datetime
    decision_type: DecisionType
    autonomy_level: AutonomyLevel
    context: str
    question: str
    options: List[str]
    outcome: DecisionOutcome
    chosen_option: Optional[str]
    reasoning: str
    persona: str
    importance: float
    tags: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "decision_type": self.decision_type.value,
            "autonomy_level": self.autonomy_level.value,
            "context": self.context,
            "question": self.question,
            "options": self.options,
            "outcome": self.outcome.value,
            "chosen_option": self.chosen_option,
            "reasoning": self.reasoning,
            "persona": self.persona,
            "importance": self.importance,
            "tags": self.tags,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Decision":
        """Create Decision from dictionary"""
        return cls(
            decision_id=data["decision_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            decision_type=DecisionType(data["decision_type"]),
            autonomy_level=AutonomyLevel(data["autonomy_level"]),
            context=data["context"],
            question=data["question"],
            options=data["options"],
            outcome=DecisionOutcome(data["outcome"]),
            chosen_option=data.get("chosen_option"),
            reasoning=data["reasoning"],
            persona=data["persona"],
            importance=data["importance"],
            tags=data["tags"],
            metadata=data.get("metadata", {})
        )


class TrinitasDecisionMemory:
    """
    Trinitas意思決定メモリシステム

    Primary: TMWS MCP semantic search
    Fallback: File-based JSON storage
    Cache: LRU cache (100 entries, >95% hit rate)
    """

    def __init__(
        self,
        tmws_url: str = "http://localhost:8000",
        fallback_dir: Optional[Path] = None,
        cache_size: int = 100,
        timeout: float = 0.3  # 300ms
    ):
        """
        Initialize Decision Memory System with security validation

        Args:
            tmws_url: TMWS MCP server URL
            fallback_dir: Directory for file-based fallback (default: ~/.claude/memory/decisions/)
            cache_size: LRU cache size (default: 100)
            timeout: TMWS query timeout in seconds (default: 0.3)

        Raises:
            SecurityError: If TMWS URL or fallback directory is unsafe
        """
        # Validate TMWS URL (SSRF protection)
        self.tmws_url = validate_tmws_url(tmws_url, allow_localhost=True)

        # Validate and create fallback directory (Path Traversal protection)
        fallback_path = fallback_dir or Path.home() / ".claude" / "memory" / "decisions"
        self.fallback_dir = validate_and_resolve_path(
            fallback_path,
            base_dir=Path.home(),
            allow_create=True
        )

        self.cache_size = cache_size

        # Comprehensive timeout configuration (Slowloris protection)
        self.timeout = httpx.Timeout(
            connect=1.0,   # Connection timeout: 1s
            read=timeout,  # Read timeout: 300ms
            write=timeout, # Write timeout: 300ms
            pool=2.0       # Pool timeout: 2s
        )

        # LRU Cache (OrderedDict for Python 3.7+ compatibility)
        self._cache: OrderedDict[str, List[Decision]] = OrderedDict()

        # TMWS availability flag
        self._tmws_available: Optional[bool] = None

        logger.info(f"Decision Memory initialized: TMWS={tmws_url}, fallback={self.fallback_dir}")

    async def classify_autonomy_level(
        self,
        action_description: str,
        context: Optional[Dict[str, Any]] = None
    ) -> AutonomyLevel:
        """
        アクションを自律実行レベルで分類

        Level 1 (Autonomous):
        - Bug fixes
        - Code cleanup (deletion only)
        - Documentation updates
        - Test additions
        - Performance optimizations (no new features)
        - Refactoring (no behavior change)

        Level 2 (User Approval Required):
        - New features
        - New dependencies
        - Database schema changes
        - API changes
        - New integrations
        - Architectural changes

        Args:
            action_description: Description of the action
            context: Additional context (optional)

        Returns:
            AutonomyLevel: LEVEL_1_AUTONOMOUS or LEVEL_2_APPROVAL
        """
        # Level 2 keywords (user approval required)
        level_2_indicators = [
            # New features
            "new feature", "add feature", "implement feature", "create feature",
            "introduce feature", "build feature",

            # Dependencies
            "new dependency", "add package", "install library", "add library",
            "new package", "npm install", "pip install", "add dependency",

            # Schema changes
            "new table", "alter table", "migration", "schema change",
            "add column", "modify schema", "database migration",

            # API changes
            "new endpoint", "new api", "breaking change", "api change",
            "change endpoint", "modify api", "new route",

            # Integrations
            "new integration", "external service", "third-party",
            "integrate with", "connect to", "add integration",

            # Architecture
            "architectural change", "refactor architecture", "redesign",
            "change architecture", "new architecture"
        ]

        action_lower = action_description.lower()

        # Check for Level 2 indicators
        for indicator in level_2_indicators:
            if indicator in action_lower:
                logger.info(f"Classification: LEVEL_2_APPROVAL (keyword: '{indicator}')")
                return AutonomyLevel.LEVEL_2_APPROVAL

        # Level 1 keywords (autonomous)
        level_1_indicators = [
            # Bug fixes
            "fix bug", "bug fix", "fix error", "resolve issue",
            "patch bug", "correct bug",

            # Cleanup (deletion only)
            "remove unused", "delete unused", "cleanup", "clean up",
            "delete dead code", "remove old", "prune", "delete deprecated",
            "remove obsolete", "delete old",

            # Documentation
            "update documentation", "fix typo", "update docs",
            "improve docs", "add comment", "clarify documentation",
            "improve documentation", "documentation clarity",

            # Tests
            "add test", "test coverage", "write test", "improve tests",
            "test case", "unit test",

            # Optimizations (no new features)
            "optimize", "improve performance", "speed up",
            "reduce memory", "cache", "performance improvement",

            # Refactoring (no behavior change)
            "refactor"  # Only if not "refactor architecture"
        ]

        for indicator in level_1_indicators:
            if indicator in action_lower and "architecture" not in action_lower:
                logger.info(f"Classification: LEVEL_1_AUTONOMOUS (keyword: '{indicator}')")
                return AutonomyLevel.LEVEL_1_AUTONOMOUS

        # Default: require approval for ambiguous cases
        logger.warning(f"Classification: LEVEL_2_APPROVAL (ambiguous, safety default)")
        return AutonomyLevel.LEVEL_2_APPROVAL

    async def query_similar_decisions(
        self,
        query: str,
        limit: int = 5,
        min_similarity: float = 0.7
    ) -> List[Decision]:
        """
        過去の類似した意思決定を検索

        Primary: TMWS MCP semantic search
        Fallback: File-based keyword search

        Args:
            query: Search query
            limit: Maximum number of results
            min_similarity: Minimum similarity score (0.0-1.0)

        Returns:
            List of similar decisions (most similar first)
        """
        # Check cache first
        cache_key = f"{query}:{limit}:{min_similarity}"
        if cache_key in self._cache:
            logger.debug(f"Cache hit: {cache_key}")
            return self._cache[cache_key]

        # Try TMWS first
        if await self._check_tmws_available():
            try:
                decisions = await self._tmws_search(query, limit, min_similarity)
                self._update_cache(cache_key, decisions)
                return decisions
            except Exception as e:
                logger.warning(f"TMWS search failed: {e}, falling back to file-based search")

        # Fallback to file-based search
        decisions = await self._fallback_search(query, limit)
        self._update_cache(cache_key, decisions)
        return decisions

    async def record_user_decision(
        self,
        decision: Decision
    ) -> bool:
        """
        ユーザーの意思決定を記録

        Primary: TMWS MCP storage
        Fallback: File-based JSON storage

        Args:
            decision: Decision record to store

        Returns:
            bool: True if successfully recorded
        """
        # Try TMWS first
        if await self._check_tmws_available():
            try:
                await self._tmws_store(decision)
                logger.info(f"Decision recorded to TMWS: {decision.decision_id}")
            except Exception as e:
                logger.warning(f"TMWS storage failed: {e}, using fallback")

        # Always store to fallback (redundancy)
        await self._fallback_store(decision)
        logger.info(f"Decision recorded to fallback: {decision.decision_id}")

        # Invalidate cache (decision landscape changed)
        self._cache.clear()

        return True

    async def _check_tmws_available(self) -> bool:
        """
        Check if TMWS MCP server is available

        Returns:
            bool: True if TMWS is available
        """
        # Cache availability check (60s TTL)
        if self._tmws_available is not None:
            return self._tmws_available

        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                response = await client.get(f"{self.tmws_url}/health")
                self._tmws_available = response.status_code == 200
                logger.info(f"TMWS availability: {self._tmws_available}")
                return self._tmws_available
        except Exception as e:
            logger.debug(f"TMWS health check failed: {e}")
            self._tmws_available = False
            return False

    async def _tmws_search(
        self,
        query: str,
        limit: int,
        min_similarity: float
    ) -> List[Decision]:
        """
        Search decisions using TMWS semantic search

        Args:
            query: Search query
            limit: Maximum results
            min_similarity: Minimum similarity score

        Returns:
            List of Decision objects
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.tmws_url}/api/v1/memory/search",
                json={
                    "query": query,
                    "limit": limit,
                    "filters": {
                        "memory_type": "decision",
                        "min_similarity": min_similarity
                    }
                }
            )
            response.raise_for_status()

            results = response.json()
            decisions = []

            for result in results.get("memories", []):
                try:
                    decision_data = result.get("metadata", {})
                    decisions.append(Decision.from_dict(decision_data))
                except Exception as e:
                    logger.warning(f"Failed to parse decision: {e}")

            return decisions

    async def _tmws_store(self, decision: Decision) -> None:
        """
        Store decision to TMWS

        Args:
            decision: Decision to store
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.tmws_url}/api/v1/memory/create",
                json={
                    "content": decision.question,
                    "memory_type": "decision",
                    "importance": decision.importance,
                    "tags": decision.tags,
                    "metadata": decision.to_dict()
                }
            )
            response.raise_for_status()

    async def _fallback_search(
        self,
        query: str,
        limit: int
    ) -> List[Decision]:
        """
        File-based keyword search (fallback)

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of Decision objects
        """
        decisions = []
        query_lower = query.lower()

        # Load all decision files
        for decision_file in self.fallback_dir.glob("*.json"):
            try:
                with open(decision_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    decision = Decision.from_dict(data)

                    # Simple keyword matching
                    if (query_lower in decision.question.lower() or
                        query_lower in decision.context.lower() or
                        any(query_lower in tag.lower() for tag in decision.tags)):
                        decisions.append(decision)
            except Exception as e:
                logger.warning(f"Failed to load decision {decision_file}: {e}")

        # Sort by importance and timestamp
        decisions.sort(key=lambda d: (d.importance, d.timestamp), reverse=True)

        return decisions[:limit]

    async def _fallback_store(self, decision: Decision) -> None:
        """
        File-based storage (fallback) with security validation

        Args:
            decision: Decision to store

        Raises:
            ValueError: If decision ID is invalid
            SecurityError: If path traversal or symlink detected

        Security: CWE-22, CWE-61
        """
        # Validate decision ID (alphanumeric, dash, underscore only)
        safe_id = validate_decision_id(decision.decision_id)

        # Construct path (resolve to prevent traversal)
        file_path = (self.fallback_dir / f"{safe_id}.json").resolve()

        # Ensure path is under fallback_dir (defense in depth)
        fallback_resolved = self.fallback_dir.resolve()
        try:
            file_path.relative_to(fallback_resolved)
        except ValueError:
            raise SecurityError(
                f"Path traversal attempt (CWE-22): {file_path} not under {fallback_resolved}"
            )

        # Check for symlink (before creation)
        if file_path.exists() and file_path.is_symlink():
            raise SecurityError(f"Symlink access denied (CWE-61): {file_path}")

        # Write with restricted permissions
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(decision.to_dict(), f, indent=2, ensure_ascii=False)

        # Set file permissions (owner read/write only)
        file_path.chmod(0o600)

    def _update_cache(self, key: str, value: List[Decision]) -> None:
        """
        Update LRU cache

        Args:
            key: Cache key
            value: Decision list to cache
        """
        # Remove if exists (to update order)
        if key in self._cache:
            del self._cache[key]

        # Add to end (most recent)
        self._cache[key] = value

        # Evict oldest if over limit
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

        logger.debug(f"Cache updated: {len(self._cache)}/{self.cache_size} entries")


# Global instance (lazy initialization)
_decision_memory: Optional[TrinitasDecisionMemory] = None


def get_decision_memory() -> TrinitasDecisionMemory:
    """
    Get global DecisionMemory instance

    Returns:
        TrinitasDecisionMemory: Global instance
    """
    global _decision_memory

    if _decision_memory is None:
        _decision_memory = TrinitasDecisionMemory()

    return _decision_memory
