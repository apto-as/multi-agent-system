# TMWS Forgetting Feature: Implementation Roadmap

**Date**: 2025-11-04
**Status**: Planning Phase
**Based on**: Competitive Analysis of 8 Major Memory Systems

---

## Executive Summary

この実装ロードマップは、競合分析の結果に基づき、TMWSに「忘れる」機能を段階的に実装するための詳細計画を提供します。

**アプローチ**: Hybrid Forgetting Strategy
- **Layer 1**: Score-based Soft Forgetting (Generative Agents方式)
- **Layer 2**: Dynamic Importance Adjustment (MongoDB AI Memory方式)
- **Layer 3**: Capacity-based Hard Forgetting (MongoDB AI Memory方式)
- **Layer 4**: Optional Expiration Date (Mem0方式)
- **Layer 5**: Temporal Invalidation (Zep方式、将来)

**差別化要因**: 業界で初めて、全ての主要アプローチを統合したハイブリッド実装

---

## Phase 1: Core Implementation (v2.3.0) - P0 Priority

**Target Date**: 2025-11-15 (2週間)
**Status**: 🟡 Planning
**Risk Level**: Low
**Dependencies**: None

### 1.1 Database Schema Changes

#### Add Fields to Memory Model

```python
# src/models/memory.py

class Memory(Base):
    __tablename__ = "memories"

    # NEW: Importance scoring (1-10 scale)
    importance: Mapped[float] = mapped_column(
        Float,
        default=5.0,  # Medium importance
        nullable=False,
        comment="LLM-generated importance score (1=mundane, 10=poignant)",
        index=True  # For pruning queries
    )

    # NEW: Access tracking
    access_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of times this memory has been accessed"
    )

    last_accessed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Last time this memory was retrieved",
        index=True  # For recency calculations
    )

    # EXISTING: created_at (already exists)
    # EXISTING: updated_at (already exists)
```

#### Migration Script

```bash
# Create migration
alembic revision --autogenerate -m "p0_add_forgetting_features"

# Expected changes:
# - Add importance column (Float, default=5.0, index=True)
# - Add access_count column (Integer, default=0)
# - Add last_accessed column (DateTime, default=now(), index=True)
# - Create index on importance for pruning
# - Create index on last_accessed for recency

# Apply migration
alembic upgrade head
```

**Time Estimate**: 2-3 hours
**Test Coverage**: 100% (migration up/down, data integrity)

---

### 1.2 Importance Scoring Service

#### Implementation

```python
# src/services/importance_scoring_service.py

from typing import Optional
from src.services.llm_service import LLMService
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)


class ImportanceScoringService:
    """LLM-assisted importance scoring for memories (1-10 scale)"""

    def __init__(self, llm_service: Optional[LLMService] = None):
        self.llm_service = llm_service or LLMService()
        self.cache = {}  # Simple cache for repeated content

    async def score_importance(self, content: str) -> float:
        """
        Score memory importance using LLM (1-10 scale)

        Inspired by: Generative Agents (Stanford/Google, UIST 2023)
        Paper: https://arxiv.org/abs/2304.03442

        Args:
            content: Memory content to evaluate

        Returns:
            float: Importance score in [1.0, 10.0]
                   1-3: Mundane, routine information
                   4-6: Moderately important
                   7-9: Very important
                   10: Critically important, life-changing
        """

        # Cache check
        cache_key = hash(content)
        if cache_key in self.cache:
            return self.cache[cache_key]

        prompt = self._build_scoring_prompt(content)

        try:
            response = await self.llm_service.generate(
                prompt,
                temperature=0.3,  # Low temperature for consistent scoring
                max_tokens=10      # Just need a number
            )

            score = self._parse_score(response)
            self.cache[cache_key] = score  # Cache result

            logger.info(f"Importance scored: {score:.1f} for content: {content[:50]}...")
            return score

        except Exception as e:
            logger.warning(f"Importance scoring failed: {e}. Using default: 5.0")
            return 5.0  # Default to medium importance

    def _build_scoring_prompt(self, content: str) -> str:
        """Build the importance scoring prompt"""

        return f"""Rate the importance of this memory on a scale from 1 to 10.

Memory content: "{content}"

Importance Scale:
1-3: Mundane, routine information (e.g., "I ate breakfast", "The weather is nice")
4-6: Moderately important (e.g., "I learned a new skill", "I had an interesting conversation")
7-9: Very important (e.g., "I made a significant decision", "I discovered a crucial insight")
10: Critically important, life-changing (e.g., "I had a major breakthrough", "This changed my understanding")

Instructions:
- Consider the uniqueness, impact, and long-term relevance of this memory
- Be consistent: similar content should get similar scores
- Respond with ONLY a single number from 1 to 10 (integer or decimal)

Your score:"""

    def _parse_score(self, response: str) -> float:
        """Parse LLM response to extract score"""

        # Clean response
        cleaned = response.strip()

        # Try to extract number
        try:
            score = float(cleaned)
            # Clamp to valid range
            return max(1.0, min(10.0, score))
        except ValueError:
            # Try to find first number in response
            import re
            match = re.search(r'(\d+\.?\d*)', cleaned)
            if match:
                score = float(match.group(1))
                return max(1.0, min(10.0, score))

            # Failed to parse
            logger.warning(f"Failed to parse importance score: '{response}'. Using default: 5.0")
            return 5.0

    async def batch_score(self, contents: list[str]) -> list[float]:
        """Score multiple memories in batch (future optimization)"""
        # TODO: Implement batch scoring for efficiency
        return [await self.score_importance(c) for c in contents]
```

**Time Estimate**: 6-8 hours
**Test Coverage**: 90%+
- Test valid scores (1-10)
- Test edge cases (empty, very long content)
- Test LLM failure handling
- Test cache behavior

---

### 1.3 Memory Retrieval with Scoring

#### Implementation

```python
# src/services/memory_retrieval_service.py

from datetime import datetime, timezone
from typing import Optional
import numpy as np
from src.models.memory import Memory
from src.services.vector_search_service import VectorSearchService
import logging

logger = logging.getLogger(__name__)


class MemoryRetrievalService:
    """
    Multi-factor memory retrieval with forgetting mechanism

    Inspired by:
    - Generative Agents (Stanford/Google): 3-factor scoring
    - MongoDB AI Memory: Dynamic importance adjustment
    """

    def __init__(
        self,
        vector_service: VectorSearchService,
        decay_factor: float = 0.995,  # Stanford paper value
        weights: Optional[dict[str, float]] = None
    ):
        self.vector_service = vector_service
        self.decay_factor = decay_factor

        # Default weights (can be tuned)
        self.weights = weights or {
            'relevance': 0.50,   # Semantic similarity
            'recency': 0.30,     # Time decay
            'importance': 0.20   # LLM-generated importance
        }

        # Validate weights sum to 1.0
        total = sum(self.weights.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Weights must sum to 1.0, got {total}")

    async def search_with_forgetting(
        self,
        query_embedding: list[float],
        namespace: str,
        limit: int = 10,
        filters: Optional[dict] = None
    ) -> list[tuple[Memory, float]]:
        """
        Search memories with multi-factor scoring and forgetting

        Args:
            query_embedding: Query vector
            namespace: Memory namespace
            limit: Number of results to return
            filters: Additional metadata filters

        Returns:
            List of (memory, score) tuples, sorted by score descending
        """

        # Step 1: Vector similarity search (get more candidates)
        candidates = await self.vector_service.search(
            query_embedding=query_embedding,
            namespace=namespace,
            top_k=limit * 3,  # Retrieve 3x for rescoring
            filters=filters
        )

        # Step 2: Calculate multi-factor scores
        scored_memories = []
        current_time = datetime.now(timezone.utc)

        for memory, vector_score in candidates:
            # Calculate individual components
            relevance = vector_score  # Already [0, 1] from cosine similarity
            recency = self._calculate_recency(memory, current_time)
            importance = self._normalize_importance(memory.importance)

            # Weighted combination
            final_score = (
                self.weights['relevance'] * relevance +
                self.weights['recency'] * recency +
                self.weights['importance'] * importance
            )

            scored_memories.append((memory, final_score))

        # Step 3: Sort by final score and return top-k
        scored_memories.sort(key=lambda x: x[1], reverse=True)

        return scored_memories[:limit]

    def _calculate_recency(self, memory: Memory, current_time: datetime) -> float:
        """
        Calculate recency score using exponential decay

        Formula: recency = decay_factor ^ hours_elapsed

        From Generative Agents paper:
        - decay_factor = 0.995 (per hour)
        - Exponential decay over sandbox game hours
        """

        time_delta = current_time - memory.last_accessed
        hours_elapsed = time_delta.total_seconds() / 3600.0

        # Exponential decay
        recency_score = self.decay_factor ** hours_elapsed

        return recency_score

    def _normalize_importance(self, importance: float) -> float:
        """
        Normalize importance from [1, 10] to [0, 1]

        Args:
            importance: Raw importance score (1-10 scale)

        Returns:
            Normalized score in [0, 1]
        """
        return (importance - 1.0) / 9.0

    async def update_access_stats(self, memory: Memory):
        """
        Update memory access statistics

        Called whenever a memory is retrieved.
        Part of reinforcement learning mechanism (MongoDB AI Memory approach).
        """

        memory.access_count += 1
        memory.last_accessed = datetime.now(timezone.utc)

        logger.debug(
            f"Memory {memory.id} accessed "
            f"(count={memory.access_count}, importance={memory.importance:.1f})"
        )

    def set_weights(self, weights: dict[str, float]):
        """Update scoring weights (for tuning)"""

        total = sum(weights.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Weights must sum to 1.0, got {total}")

        self.weights = weights
        logger.info(f"Updated scoring weights: {weights}")

    def set_decay_factor(self, decay_factor: float):
        """Update decay factor (for tuning)"""

        if not (0.9 <= decay_factor <= 1.0):
            raise ValueError(f"Decay factor must be in [0.9, 1.0], got {decay_factor}")

        self.decay_factor = decay_factor
        logger.info(f"Updated decay factor: {decay_factor}")
```

**Time Estimate**: 8-10 hours
**Test Coverage**: 95%+
- Test multi-factor scoring
- Test recency calculation (various time deltas)
- Test importance normalization
- Test weight validation
- Test access stats update

---

### 1.4 Integration with Memory Service

#### Update Memory Service

```python
# src/services/memory_service.py

class MemoryService:
    def __init__(self, ...):
        # Existing services...
        self.importance_scorer = ImportanceScoringService()
        self.retrieval_service = MemoryRetrievalService(
            vector_service=self.vector_service
        )

    async def create_memory(self, ...):
        """Create memory with importance scoring"""

        # Existing embedding generation...

        # NEW: Score importance
        importance = await self.importance_scorer.score_importance(content)

        # Create memory with importance
        memory = Memory(
            content=content,
            importance=importance,  # NEW
            access_count=0,          # NEW
            last_accessed=datetime.now(timezone.utc),  # NEW
            ...
        )

        # Save to database and vector store...

    async def search_memories(self, query: str, ...):
        """Search with multi-factor scoring"""

        # Generate query embedding...

        # NEW: Use retrieval service with forgetting
        results = await self.retrieval_service.search_with_forgetting(
            query_embedding=query_embedding,
            namespace=namespace,
            limit=limit
        )

        # Update access stats for retrieved memories
        for memory, score in results:
            await self.retrieval_service.update_access_stats(memory)

        return results
```

**Time Estimate**: 4-6 hours
**Test Coverage**: 90%+

---

### 1.5 API Updates

#### Add Importance to Memory Schema

```python
# src/api/schemas/memory.py

class MemoryResponse(BaseModel):
    id: UUID
    content: str
    importance: float  # NEW: 1-10 scale
    access_count: int  # NEW
    last_accessed: datetime  # NEW
    created_at: datetime
    # ... existing fields
```

**Time Estimate**: 2 hours

---

### 1.6 Testing & Validation

#### Unit Tests
```python
# tests/unit/test_importance_scoring.py
# tests/unit/test_memory_retrieval.py
```

#### Integration Tests
```python
# tests/integration/test_forgetting_mechanism.py
```

#### Performance Tests
```python
# tests/performance/test_scoring_latency.py
# Target: <5ms P95 for score calculation
```

**Time Estimate**: 8-10 hours

---

### Phase 1 Summary

**Total Time Estimate**: 30-40 hours (1-2 weeks with 1 developer)

**Deliverables**:
- ✅ Database schema with importance, access_count, last_accessed
- ✅ ImportanceScoringService (LLM-assisted, 1-10 scale)
- ✅ MemoryRetrievalService (3-factor scoring)
- ✅ Exponential decay (0.995^t)
- ✅ API updates with new fields
- ✅ Comprehensive test suite (90%+ coverage)
- ✅ Documentation

**Acceptance Criteria**:
1. All tests pass (100%)
2. Score calculation: <5ms P95
3. Importance scoring: <500ms P95 (LLM call)
4. Memory search: <20ms P95 (excluding LLM)
5. No regression in existing functionality

---

## Phase 2: Dynamic Adjustment (v2.4.0) - P1 Priority

**Target Date**: 2025-12-01 (2週間)
**Status**: 🔴 Not Started
**Risk Level**: Medium
**Dependencies**: Phase 1 complete

### 2.1 Reinforcement Learning Service

#### Implementation

```python
# src/services/memory_reinforcement_service.py

class MemoryReinforcementService:
    """
    Dynamic importance adjustment based on access patterns

    Inspired by: MongoDB AI Memory Service
    """

    def __init__(
        self,
        reinforcement_factor: float = 0.5,
        decay_factor: float = 0.98,
        frequent_threshold: int = 10,
        moderate_threshold: int = 5
    ):
        self.reinforcement_factor = reinforcement_factor
        self.decay_factor = decay_factor
        self.frequent_threshold = frequent_threshold
        self.moderate_threshold = moderate_threshold

    async def on_memory_accessed(
        self,
        memory: Memory,
        was_relevant: bool = True
    ):
        """
        Reinforce importance when memory is accessed

        Args:
            memory: Memory that was accessed
            was_relevant: Whether memory was relevant to query
        """

        if not was_relevant:
            return  # Don't reinforce irrelevant memories

        # Update access stats (already done by retrieval service)
        # memory.access_count += 1
        # memory.last_accessed = now()

        # Reinforce importance based on access frequency
        if memory.access_count > self.frequent_threshold:
            # Frequently accessed → high reinforcement
            boost = self.reinforcement_factor
        elif memory.access_count > self.moderate_threshold:
            # Moderately accessed → medium reinforcement
            boost = self.reinforcement_factor * 0.5
        else:
            # Rarely accessed → small reinforcement
            boost = self.reinforcement_factor * 0.2

        # Apply boost (capped at 10.0)
        old_importance = memory.importance
        memory.importance = min(10.0, memory.importance + boost)

        logger.info(
            f"Memory {memory.id} reinforced: "
            f"{old_importance:.2f} → {memory.importance:.2f} "
            f"(access_count={memory.access_count})"
        )

    async def apply_background_decay(
        self,
        namespace: str,
        cutoff_hours: int = 24
    ):
        """
        Apply decay to memories that haven't been accessed recently

        Args:
            namespace: Memory namespace to process
            cutoff_hours: Hours since last access to apply decay
        """

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)

        # Find memories not accessed in cutoff period
        unaccessed = await self.find_unaccessed_memories(
            namespace=namespace,
            since=cutoff_time
        )

        for memory in unaccessed:
            old_importance = memory.importance
            memory.importance *= self.decay_factor

            logger.debug(
                f"Memory {memory.id} decayed: "
                f"{old_importance:.2f} → {memory.importance:.2f}"
            )

        logger.info(
            f"Applied decay to {len(unaccessed)} memories in {namespace}"
        )
```

**Time Estimate**: 8-10 hours

---

### 2.2 Automatic Pruning Service

#### Implementation

```python
# src/services/memory_pruning_service.py

class MemoryPruningService:
    """
    Automatic pruning of least important memories

    Inspired by: MongoDB AI Memory Service
    """

    def __init__(
        self,
        max_memory_limit: int = 100000,  # Per namespace
        prune_percentage: float = 0.10,  # Prune 10% when limit reached
        min_importance_threshold: float = 2.0  # Never prune above this
    ):
        self.max_memory_limit = max_memory_limit
        self.prune_percentage = prune_percentage
        self.min_importance_threshold = min_importance_threshold

    async def prune_if_necessary(
        self,
        namespace: str,
        force: bool = False
    ) -> int:
        """
        Prune least important memories if capacity exceeded

        Args:
            namespace: Memory namespace to prune
            force: Force pruning even if under limit

        Returns:
            Number of memories pruned
        """

        memory_count = await self.count_memories(namespace)

        if not force and memory_count <= self.max_memory_limit:
            return 0  # No pruning needed

        # Calculate prune count
        if force:
            excess = int(memory_count * self.prune_percentage)
        else:
            excess = memory_count - self.max_memory_limit
            prune_count = max(1, int(excess * (1 + self.prune_percentage)))

        # Find least important memories
        candidates = await self.find_least_important(
            namespace=namespace,
            limit=prune_count,
            min_importance=self.min_importance_threshold
        )

        if not candidates:
            logger.warning(
                f"No candidates for pruning in {namespace} "
                f"(all above threshold {self.min_importance_threshold})"
            )
            return 0

        # Archive or delete
        pruned_count = 0
        for memory in candidates:
            await self.archive_or_delete(memory)
            pruned_count += 1

        logger.warning(
            f"Pruned {pruned_count} memories from {namespace} "
            f"(was {memory_count}, now {memory_count - pruned_count})"
        )

        return pruned_count

    async def archive_or_delete(self, memory: Memory):
        """Archive to long-term storage or delete permanently"""

        # Option 1: Archive to separate table (recommended)
        await self.archive_memory(memory)

        # Option 2: Delete permanently
        # await self.delete_memory(memory)
```

**Time Estimate**: 10-12 hours

---

### 2.3 Background Task Scheduler

#### Implementation

```python
# src/tasks/memory_maintenance.py

from apscheduler.schedulers.asyncio import AsyncIOScheduler

class MemoryMaintenanceTasks:
    """Background tasks for memory maintenance"""

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.reinforcement_service = MemoryReinforcementService()
        self.pruning_service = MemoryPruningService()

    def start(self):
        """Start background tasks"""

        # Task 1: Apply decay daily
        self.scheduler.add_job(
            self._apply_decay_to_all_namespaces,
            trigger='cron',
            hour=3,  # 3 AM daily
            minute=0
        )

        # Task 2: Check pruning hourly
        self.scheduler.add_job(
            self._check_pruning_all_namespaces,
            trigger='interval',
            hours=1
        )

        self.scheduler.start()
        logger.info("Memory maintenance tasks started")

    async def _apply_decay_to_all_namespaces(self):
        """Apply decay to all namespaces"""
        namespaces = await self.get_all_namespaces()
        for ns in namespaces:
            await self.reinforcement_service.apply_background_decay(ns)

    async def _check_pruning_all_namespaces(self):
        """Check if pruning needed in any namespace"""
        namespaces = await self.get_all_namespaces()
        for ns in namespaces:
            await self.pruning_service.prune_if_necessary(ns)
```

**Time Estimate**: 6-8 hours

---

### Phase 2 Summary

**Total Time Estimate**: 30-40 hours (1-2 weeks with 1 developer)

**Deliverables**:
- ✅ MemoryReinforcementService (access-based adjustment)
- ✅ MemoryPruningService (automatic capacity management)
- ✅ Background task scheduler
- ✅ Monitoring and logging
- ✅ Test suite (90%+ coverage)
- ✅ Documentation

**Acceptance Criteria**:
1. Importance adjusts automatically based on access
2. Pruning triggers when capacity exceeded
3. Background tasks run without errors
4. No performance degradation
5. Monitoring dashboards updated

---

## Phase 3: Advanced Features (v2.5.0+) - P2 Priority

**Target Date**: 2026-01-15 (3-4週間)
**Status**: 🔴 Not Started
**Risk Level**: High
**Dependencies**: Phase 1 & 2 complete

### 3.1 Expiration Date Feature

#### Schema Update

```python
class Memory(Base):
    expiration_date: Mapped[Optional[date]] = mapped_column(
        Date,
        nullable=True,
        comment="Optional expiration date for temporary memories"
    )
```

**Time Estimate**: 8 hours

---

### 3.2 Adaptive Decay Rates

#### Implementation

```python
class AdaptiveDecayService:
    """Context-aware decay factor adjustment"""

    def calculate_decay_factor(self, memory: Memory) -> float:
        """Adjust decay based on memory importance"""

        if memory.importance >= 8:
            return 0.998  # Slower decay for important
        elif memory.importance <= 3:
            return 0.990  # Faster decay for mundane

        return 0.995  # Default
```

**Time Estimate**: 12 hours

---

### 3.3 Temporal Invalidation (Knowledge Graph)

#### Implementation

```python
class TemporalEdge:
    """Graphiti-style temporal edges for knowledge graphs"""

    t_created: datetime  # System creation time
    t_expired: Optional[datetime]  # System expiration time
    t_valid: datetime  # Fact became true
    t_invalid: Optional[datetime]  # Fact became false

    def invalidate(self, when: datetime):
        """Mark edge as invalid without deletion"""
        self.t_invalid = when
```

**Time Estimate**: 20-30 hours (complex)

---

### Phase 3 Summary

**Total Time Estimate**: 40-50 hours (3-4 weeks with 1 developer)

---

## Testing Strategy

### Unit Tests (>90% coverage)

```bash
tests/unit/
  ├── test_importance_scoring.py
  ├── test_memory_retrieval.py
  ├── test_memory_reinforcement.py
  ├── test_memory_pruning.py
  └── test_adaptive_decay.py
```

### Integration Tests

```bash
tests/integration/
  ├── test_forgetting_end_to_end.py
  ├── test_background_tasks.py
  └── test_memory_lifecycle.py
```

### Performance Tests

```bash
tests/performance/
  ├── test_scoring_latency.py        # Target: <5ms P95
  ├── test_pruning_performance.py     # Target: <100ms P95
  └── test_concurrent_access.py      # Target: 100 concurrent users
```

---

## Monitoring & Observability

### Metrics to Track

```python
# Prometheus metrics

# Importance distribution
memory_importance_histogram = Histogram(
    'tmws_memory_importance',
    'Distribution of memory importance scores',
    buckets=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
)

# Access patterns
memory_access_counter = Counter(
    'tmws_memory_accesses_total',
    'Total memory accesses',
    ['namespace']
)

# Pruning events
memory_pruned_counter = Counter(
    'tmws_memories_pruned_total',
    'Total memories pruned',
    ['namespace', 'reason']
)

# Scoring latency
scoring_latency = Histogram(
    'tmws_scoring_latency_seconds',
    'Memory scoring latency',
    ['component']  # 'relevance', 'recency', 'importance', 'total'
)
```

### Dashboards

**Grafana Dashboard**: Memory Forgetting Overview
- Importance distribution (histogram)
- Access frequency (time series)
- Pruning events (time series)
- Scoring latency (P50, P95, P99)
- Memory count per namespace

---

## Risk Mitigation

### Risk 1: LLM Importance Scoring Latency

**Risk**: LLM calls for importance scoring may be slow (>1s)

**Mitigation**:
1. ✅ Use async/await for non-blocking calls
2. ✅ Implement caching for repeated content
3. ✅ Batch scoring for bulk operations (Phase 2)
4. ⚠️ Fallback to heuristic scoring if LLM unavailable

### Risk 2: Incorrect Pruning

**Risk**: Accidentally delete important memories

**Mitigation**:
1. ✅ Archive before delete (soft delete)
2. ✅ Minimum importance threshold (never prune >2.0)
3. ✅ User confirmation for manual pruning
4. ✅ Audit log for all pruning events

### Risk 3: Performance Degradation

**Risk**: Multi-factor scoring may slow down search

**Mitigation**:
1. ✅ Target: <5ms P95 for scoring
2. ✅ Pre-calculate when possible
3. ✅ Index optimization (importance, last_accessed)
4. ✅ Performance tests in CI/CD

### Risk 4: User Experience Impact

**Risk**: Users may notice relevant memories "forgotten"

**Mitigation**:
1. ✅ Transparent scoring (show importance in UI)
2. ✅ User feedback mechanism
3. ✅ Adjustable weights per user/namespace
4. ✅ Ability to "pin" important memories

---

## Success Metrics

### Functional Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Retrieval Accuracy | >90% | Relevance of top-10 results |
| Importance Accuracy | >85% | User feedback on scores |
| Pruning Precision | >95% | % correctly pruned |
| Decay Appropriateness | >85% | User feedback on relevance over time |

### Performance Metrics

| Metric | Target | Current (v2.2.6) |
|--------|--------|------------------|
| Score Calculation | <5ms P95 | N/A (not implemented) |
| Importance Scoring (LLM) | <500ms P95 | N/A |
| Pruning Operation | <100ms P95 | N/A |
| Memory Search | <20ms P95 | <20ms ✅ |

### Business Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Memory Efficiency | <100MB / 10K memories | Storage usage |
| User Satisfaction | >4.0/5.0 | User surveys |
| API Error Rate | <0.1% | Error logs |
| System Availability | >99.9% | Uptime monitoring |

---

## Rollout Plan

### Phase 1: Internal Testing (v2.3.0-alpha)

**Duration**: 1 week
**Participants**: Development team
**Scope**: Feature complete, alpha quality

**Actions**:
1. Deploy to staging environment
2. Run automated tests
3. Manual exploratory testing
4. Performance benchmarking
5. Fix critical bugs

### Phase 2: Beta Testing (v2.3.0-beta)

**Duration**: 2 weeks
**Participants**: 10-20 early adopters
**Scope**: Beta quality, feature complete

**Actions**:
1. Deploy to beta environment
2. Collect user feedback
3. Monitor metrics (importance, pruning, latency)
4. Iterate based on feedback
5. Prepare documentation

### Phase 3: Production Release (v2.3.0)

**Duration**: Rolling release over 1 week
**Participants**: All users
**Scope**: Production quality

**Actions**:
1. Feature flag rollout (10% → 50% → 100%)
2. Monitor error rates and latency
3. A/B testing (with/without forgetting)
4. Rollback plan prepared
5. Post-release review

---

## Documentation

### User Documentation

```
docs/user/
  ├── FORGETTING_FEATURE_GUIDE.md
  ├── IMPORTANCE_SCORING_FAQ.md
  └── MEMORY_MANAGEMENT_BEST_PRACTICES.md
```

### Developer Documentation

```
docs/dev/
  ├── FORGETTING_ARCHITECTURE.md
  ├── SCORING_ALGORITHM_DETAILS.md
  ├── PRUNING_STRATEGY_GUIDE.md
  └── PERFORMANCE_TUNING.md
```

### API Documentation

```
docs/api/
  ├── MEMORY_ENDPOINTS.md (updated)
  ├── IMPORTANCE_SCORING_API.md
  └── MEMORY_RETRIEVAL_API.md
```

---

## Conclusion

この実装ロードマップは、競合分析に基づき、TMWSに業界最先端の「忘れる」機能を段階的に実装するための詳細計画を提供します。

**Key Differentiators**:
1. ✅ **Multi-factor Scoring**: Stanford研究に基づく3要素スコアリング
2. ✅ **Dynamic Adjustment**: アクセスパターンによる自動重要度調整
3. ✅ **Hybrid Strategy**: Soft + Hard forgetting の統合
4. ✅ **Production-ready**: エンタープライズグレードの実装

**Timeline Summary**:
- **Phase 1 (P0)**: v2.3.0 - 2週間 - Core implementation
- **Phase 2 (P1)**: v2.4.0 - 2週間 - Dynamic adjustment
- **Phase 3 (P2)**: v2.5.0+ - 3-4週間 - Advanced features

**Total Effort**: 100-130 hours (2.5-3 months with 1 developer)

---

**Document Version**: 1.0
**Last Updated**: 2025-11-04
**Author**: Muses (Knowledge Architect)
**Status**: ✅ Ready for Review
