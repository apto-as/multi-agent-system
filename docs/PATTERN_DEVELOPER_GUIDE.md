# Pattern Execution Service - Developer Guide

**TMWS v2.2.0** | **Technical Implementation Guide**

## Table of Contents

1. [Quick Start](#quick-start)
2. [Pattern Definition Tutorial](#pattern-definition-tutorial)
3. [API Reference](#api-reference)
4. [Best Practices](#best-practices)
5. [Code Examples](#code-examples)
6. [Testing](#testing)
7. [Performance Tuning](#performance-tuning)

## Quick Start

### Installation

The Pattern Execution Service is included in TMWS v2.2.0. No additional installation needed.

### 5-Minute Quickstart

```python
import asyncio
from src.services.pattern_execution_service import (
    create_pattern_execution_engine,
    ExecutionMode,
    PatternDefinition,
    PatternType
)

async def quickstart():
    # 1. Create engine
    engine = await create_pattern_execution_engine()

    # 2. Execute a query
    result = await engine.execute("recall security patterns")

    # 3. Check results
    print(f"✓ Pattern: {result.pattern_name}")
    print(f"✓ Time: {result.execution_time_ms:.2f}ms")
    print(f"✓ Tokens: {result.tokens_used}")
    print(f"✓ Success: {result.success}")

    # 4. Get statistics
    stats = engine.get_stats()
    print(f"✓ Total executions: {stats['total_executions']}")
    print(f"✓ Cache hit rate: {stats['cache_hit_rate']:.1f}%")

# Run it
asyncio.run(quickstart())
```

**Expected output**:
```
✓ Pattern: recall_memory
✓ Time: 52.34ms
✓ Tokens: 100
✓ Success: True
✓ Total executions: 1
✓ Cache hit rate: 0.0%
```

## Pattern Definition Tutorial

### Understanding Patterns

A pattern is a template that matches user queries and defines how to execute them.

**Three components**:
1. **Trigger** - Regex that matches queries
2. **Type** - Execution strategy (infrastructure/memory/hybrid)
3. **Cost** - Token usage estimate

### Pattern Types Explained

#### 1. Infrastructure Patterns
**Purpose**: Fast, lightweight operations that don't need database access

**When to use**:
- Health checks
- Simple calculations
- System commands
- MCP tool calls

**Performance**: <50ms target

**Example**:
```python
{
    'name': 'health_check',
    'pattern_type': 'infrastructure',
    'trigger_pattern': r'(check|test)\s+(health|status)',
    'cost_tokens': 30,
    'priority': 10,
    'cache_ttl': 60  # Short TTL for real-time data
}
```

**Matches**:
- "check health"
- "test status"
- "check service status"

#### 2. Memory Patterns
**Purpose**: Database queries with optimization

**When to use**:
- Retrieving memories
- Searching by tags
- Filtering by criteria
- Historical data

**Performance**: <100ms target

**Example**:
```python
{
    'name': 'recall_by_tag',
    'pattern_type': 'memory',
    'trigger_pattern': r'(recall|find|get)\s+.*\s+(tagged|tag)\s+(\w+)',
    'cost_tokens': 90,
    'priority': 9,
    'cache_ttl': 300  # Longer TTL for stable data
}
```

**Matches**:
- "recall items tagged security"
- "find memories tagged performance"
- "get all tagged optimization"

#### 3. Hybrid Patterns
**Purpose**: Comprehensive analysis combining infrastructure + memory

**When to use**:
- Semantic search
- Complex analysis
- Comparison operations
- Multi-source aggregation

**Performance**: <200ms target

**Example**:
```python
{
    'name': 'semantic_analysis',
    'pattern_type': 'hybrid',
    'trigger_pattern': r'(analyze|examine|investigate)\s+.*\s+(pattern|system|performance)',
    'cost_tokens': 180,
    'priority': 8,
    'cache_ttl': 600  # Long TTL for expensive operations
}
```

**Matches**:
- "analyze performance patterns"
- "examine system behavior"
- "investigate pattern anomalies"

### Creating Custom Patterns

#### Step 1: Define Requirements

**Questions to ask**:
- What queries should this match?
- Does it need database access?
- How much does it cost in tokens?
- How often will it be queried?

#### Step 2: Write Pattern Configuration

```python
custom_pattern = {
    'name': 'database_optimization',  # Unique identifier
    'pattern_type': 'memory',  # infrastructure, memory, or hybrid
    'trigger_pattern': r'optimize\s+(database|query|index)',  # Regex
    'cost_tokens': 120,  # Token estimate
    'priority': 10,  # Higher = checked first
    'cache_ttl': 300,  # Cache duration in seconds
    'metadata': {
        'category': 'optimization',
        'description': 'Database optimization pattern',
        'author': 'artemis',
        'version': '1.0'
    }
}
```

#### Step 3: Create Pattern Definition

```python
from src.services.pattern_execution_service import PatternDefinition

# Create from config
pattern = PatternDefinition.from_config(custom_pattern)

# Or create directly
pattern = PatternDefinition(
    name='database_optimization',
    pattern_type=PatternType.MEMORY,
    trigger_regex=re.compile(r'optimize\s+(database|query|index)', re.IGNORECASE),
    cost_tokens=120,
    priority=10,
    cache_ttl=300,
    metadata={'category': 'optimization'}
)
```

#### Step 4: Register Pattern

```python
# Create engine
engine = await create_pattern_execution_engine()

# Register single pattern
engine.registry.register(pattern)

# Or batch register
patterns = [pattern1, pattern2, pattern3]
engine.registry.register_batch(patterns)
```

#### Step 5: Test Pattern

```python
# Test pattern matching
test_queries = [
    "optimize database performance",
    "optimize query execution",
    "optimize index usage"
]

for query in test_queries:
    result = await engine.execute(query)
    assert result.pattern_name == 'database_optimization'
    assert result.success
    print(f"✓ Matched: {query}")
```

### Pattern Design Best Practices

#### 1. Trigger Pattern Design

**✓ Good patterns** (specific, efficient):
```python
# Good: Specific keywords
r'(recall|retrieve)\s+(memory|memories)'

# Good: Required structure
r'find\s+similar\s+to\s+\w+'

# Good: Optional parts with ?
r'analyze\s+(system\s+)?performance'
```

**✗ Bad patterns** (too broad, inefficient):
```python
# Bad: Matches too much
r'.*'

# Bad: Too complex
r'(a|the|this|that)\s+(is|was|will be)\s+.*'

# Bad: No structure
r'\w+\s+\w+'
```

#### 2. Priority Assignment

```python
# Higher priority = checked first
{
    'name': 'critical_security',
    'priority': 10  # Highest - checked first
}

{
    'name': 'general_query',
    'priority': 5   # Medium
}

{
    'name': 'fallback',
    'priority': 1   # Lowest - checked last
}
```

#### 3. Cache TTL Selection

```python
# Short TTL for real-time data
{
    'name': 'health_check',
    'cache_ttl': 60  # 1 minute
}

# Medium TTL for semi-static data
{
    'name': 'recall_memory',
    'cache_ttl': 300  # 5 minutes
}

# Long TTL for expensive operations
{
    'name': 'deep_analysis',
    'cache_ttl': 600  # 10 minutes
}

# No cache for write operations
{
    'name': 'store_memory',
    'cache_ttl': 0  # Don't cache writes
}
```

## API Reference

### Core Classes

#### PatternExecutionEngine

```python
class PatternExecutionEngine:
    """Main execution engine with hybrid routing"""

    async def execute(
        self,
        query: str,
        execution_mode: ExecutionMode = ExecutionMode.BALANCED,
        context: Optional[Dict[str, Any]] = None,
        use_cache: bool = True
    ) -> ExecutionResult:
        """
        Execute query with pattern matching

        Args:
            query: Natural language query
            execution_mode: FAST, BALANCED, or COMPREHENSIVE
            context: Additional context dict
            use_cache: Whether to use caching

        Returns:
            ExecutionResult with results and metrics
        """
```

#### PatternRegistry

```python
class PatternRegistry:
    """High-performance pattern matching registry"""

    def register(self, pattern: PatternDefinition) -> None:
        """Register a single pattern"""

    def register_batch(self, patterns: List[PatternDefinition]) -> None:
        """Register multiple patterns efficiently"""

    def find_matching_pattern(
        self,
        query: str,
        pattern_type_filter: Optional[PatternType] = None
    ) -> Optional[PatternDefinition]:
        """Find best matching pattern for query"""
```

#### HybridDecisionRouter

```python
class HybridDecisionRouter:
    """Intelligent routing between execution paths"""

    async def route(
        self,
        query: str,
        execution_mode: ExecutionMode = ExecutionMode.BALANCED,
        context: Optional[Dict[str, Any]] = None
    ) -> RoutingDecision:
        """
        Route query to optimal execution path

        Args:
            query: Query to route
            execution_mode: Execution mode
            context: Additional context

        Returns:
            RoutingDecision with type, confidence, reasoning
        """
```

### Data Classes

#### ExecutionResult

```python
@dataclass
class ExecutionResult:
    pattern_name: str           # Matched pattern name
    success: bool              # Execution succeeded
    result: Any                # Execution result
    execution_time_ms: float   # Time in milliseconds
    tokens_used: int           # Tokens consumed
    cache_hit: bool            # From cache?
    error: Optional[str]       # Error message if failed
    metadata: Dict[str, Any]   # Additional metadata
```

#### RoutingDecision

```python
@dataclass
class RoutingDecision:
    pattern_type: PatternType      # Chosen route
    confidence: float              # Confidence (0-1)
    reasoning: str                 # Why this route
    estimated_cost: int            # Token estimate
    alternative_routes: List[PatternType]  # Alternatives
```

### Execution Modes

```python
class ExecutionMode(str, Enum):
    FAST = "fast"              # Infrastructure only (<50ms)
    BALANCED = "balanced"       # Smart routing (default)
    COMPREHENSIVE = "comprehensive"  # Full hybrid (<200ms)
```

## Best Practices

### 1. Engine Initialization

**✓ Best**: Singleton pattern
```python
# global_state.py
_engine = None

async def get_engine():
    global _engine
    if _engine is None:
        _engine = await create_pattern_execution_engine()
    return _engine

# usage.py
engine = await get_engine()
```

**✗ Avoid**: Creating multiple instances
```python
# Bad - creates new instance each time
async def do_query():
    engine = await create_pattern_execution_engine()
    return await engine.execute(query)
```

### 2. Error Handling

**✓ Best**: Comprehensive error handling
```python
from src.core.exceptions import NotFoundError, ValidationError

async def safe_execute(query: str) -> ExecutionResult:
    try:
        result = await engine.execute(query)
        if not result.success:
            logger.warning(f"Execution failed: {result.error}")
            return fallback_result()
        return result

    except NotFoundError:
        logger.warning(f"No pattern for: {query}")
        return default_result()

    except ValidationError as e:
        logger.error(f"Invalid query: {e}")
        raise

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return error_result(e)
```

### 3. Context Usage

**✓ Best**: Structured context
```python
result = await engine.execute(
    query,
    context={
        'agent_id': 'artemis',
        'session_id': session_id,
        'priority': 'high',
        'workflow': 'optimization',
        'timestamp': datetime.utcnow().isoformat()
    }
)
```

**✗ Avoid**: Unstructured context
```python
# Bad - no structure
result = await engine.execute(
    query,
    context={'everything': massive_dict}
)
```

### 4. Caching Strategy

**✓ Best**: Selective caching
```python
# Cache reads
result = await engine.execute(
    "recall memories",
    use_cache=True
)

# Don't cache writes
result = await engine.execute(
    "store new memory",
    use_cache=False
)

# Don't cache real-time data
result = await engine.execute(
    "check current status",
    use_cache=False
)
```

### 5. Performance Monitoring

**✓ Best**: Regular statistics
```python
import time

async def execute_with_monitoring(query: str):
    start = time.perf_counter()

    result = await engine.execute(query)

    duration = time.perf_counter() - start

    # Log metrics
    metrics.record_execution(
        pattern=result.pattern_name,
        duration=duration,
        tokens=result.tokens_used,
        cache_hit=result.cache_hit,
        success=result.success
    )

    # Alert on slow queries
    if duration > 0.2:  # 200ms
        logger.warning(f"Slow query ({duration:.0f}ms): {query}")

    return result
```

## Code Examples

### Example 1: Basic Integration

```python
from src.services.pattern_execution_service import create_pattern_execution_engine

class MyService:
    def __init__(self):
        self.engine = None

    async def initialize(self):
        """Initialize pattern engine"""
        self.engine = await create_pattern_execution_engine()

    async def find_similar(self, query: str):
        """Find similar items"""
        result = await self.engine.execute(
            f"find similar to {query}",
            execution_mode=ExecutionMode.HYBRID
        )

        if result.success:
            return result.result
        else:
            raise Exception(result.error)
```

### Example 2: Custom Patterns

```python
async def register_custom_patterns():
    """Register project-specific patterns"""
    engine = await create_pattern_execution_engine()

    # Define custom patterns
    patterns = [
        {
            'name': 'performance_alert',
            'pattern_type': 'infrastructure',
            'trigger_pattern': r'alert.*performance.*degradation',
            'cost_tokens': 40,
            'priority': 10,
            'metadata': {'category': 'monitoring'}
        },
        {
            'name': 'audit_report',
            'pattern_type': 'memory',
            'trigger_pattern': r'generate\s+audit\s+report',
            'cost_tokens': 120,
            'priority': 8,
            'metadata': {'category': 'compliance'}
        }
    ]

    # Create and register
    pattern_defs = [
        PatternDefinition.from_config(p) for p in patterns
    ]
    engine.registry.register_batch(pattern_defs)

    return engine
```

### Example 3: Batch Processing

```python
async def batch_analyze(queries: List[str]):
    """Analyze multiple queries in parallel"""
    engine = await create_pattern_execution_engine()

    # Execute all in parallel
    tasks = [
        engine.execute(q, execution_mode=ExecutionMode.BALANCED)
        for q in queries
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    successful = []
    failed = []

    for query, result in zip(queries, results):
        if isinstance(result, Exception):
            failed.append((query, str(result)))
        elif result.success:
            successful.append(result)
        else:
            failed.append((query, result.error))

    return {
        'successful': successful,
        'failed': failed,
        'success_rate': len(successful) / len(queries)
    }
```

### Example 4: Trinitas Agent Integration

```python
class ArtemisOptimizer:
    """Artemis agent using pattern service"""

    def __init__(self):
        self.engine = None

    async def initialize(self):
        self.engine = await create_pattern_execution_engine()

        # Register Artemis-specific patterns
        artemis_patterns = [
            {
                'name': 'code_optimization',
                'pattern_type': 'hybrid',
                'trigger_pattern': r'optimize\s+(code|function|algorithm)',
                'cost_tokens': 180,
                'priority': 10
            },
            {
                'name': 'performance_analysis',
                'pattern_type': 'hybrid',
                'trigger_pattern': r'analyze\s+performance',
                'cost_tokens': 200,
                'priority': 9
            }
        ]

        patterns = [
            PatternDefinition.from_config(p)
            for p in artemis_patterns
        ]
        self.engine.registry.register_batch(patterns)

    async def optimize_component(self, component: str):
        """Optimize a component using pattern service"""
        # Step 1: Recall past optimizations
        past = await self.engine.execute(
            f"recall optimization patterns for {component}",
            context={'agent': 'artemis', 'component': component}
        )

        # Step 2: Analyze current state
        current = await self.engine.execute(
            f"analyze current {component} performance",
            execution_mode=ExecutionMode.HYBRID,
            context={'agent': 'artemis', 'component': component}
        )

        # Step 3: Find similar cases
        similar = await self.engine.execute(
            f"find similar optimization cases",
            execution_mode=ExecutionMode.HYBRID,
            context={'agent': 'artemis', 'component': component}
        )

        # Create optimization plan
        plan = self._create_optimization_plan(
            past.result,
            current.result,
            similar.result
        )

        # Step 4: Store result
        await self.engine.execute(
            f"store optimization result for {component}",
            context={
                'agent': 'artemis',
                'component': component,
                'plan': plan
            }
        )

        return plan

    def _create_optimization_plan(self, past, current, similar):
        """Create optimization plan from analysis"""
        # Implementation
        pass
```

### Example 5: FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Global engine
_engine = None

async def get_engine():
    global _engine
    if _engine is None:
        _engine = await create_pattern_execution_engine()
    return _engine

class QueryRequest(BaseModel):
    query: str
    mode: str = "balanced"
    use_cache: bool = True

class QueryResponse(BaseModel):
    pattern: str
    success: bool
    execution_time_ms: float
    tokens_used: int
    cache_hit: bool
    result: dict

@app.post("/api/v1/pattern/execute", response_model=QueryResponse)
async def execute_pattern(
    request: QueryRequest,
    engine = Depends(get_engine)
):
    """Execute pattern query"""
    try:
        result = await engine.execute(
            request.query,
            execution_mode=ExecutionMode(request.mode),
            use_cache=request.use_cache
        )

        if not result.success:
            raise HTTPException(status_code=400, detail=result.error)

        return QueryResponse(
            pattern=result.pattern_name,
            success=result.success,
            execution_time_ms=result.execution_time_ms,
            tokens_used=result.tokens_used,
            cache_hit=result.cache_hit,
            result=result.result
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/pattern/stats")
async def get_stats(engine = Depends(get_engine)):
    """Get execution statistics"""
    return engine.get_stats()
```

## Testing

### Unit Testing Patterns

```python
import pytest
from src.services.pattern_execution_service import (
    PatternExecutionEngine,
    PatternDefinition,
    PatternType,
    ExecutionMode
)

@pytest.fixture
async def engine():
    """Create test engine"""
    engine = await create_pattern_execution_engine()
    yield engine

@pytest.mark.asyncio
async def test_infrastructure_pattern(engine):
    """Test infrastructure pattern execution"""
    result = await engine.execute(
        "check database health",
        execution_mode=ExecutionMode.FAST
    )

    assert result.success
    assert result.execution_time_ms < 50  # Fast
    assert result.tokens_used <= 50
    assert result.metadata['pattern_type'] == 'infrastructure'

@pytest.mark.asyncio
async def test_memory_pattern(engine):
    """Test memory pattern execution"""
    result = await engine.execute(
        "recall security patterns",
        execution_mode=ExecutionMode.BALANCED
    )

    assert result.success
    assert result.execution_time_ms < 100  # Medium
    assert result.tokens_used <= 100
    assert result.metadata['pattern_type'] == 'memory'

@pytest.mark.asyncio
async def test_hybrid_pattern(engine):
    """Test hybrid pattern execution"""
    result = await engine.execute(
        "analyze system performance",
        execution_mode=ExecutionMode.COMPREHENSIVE
    )

    assert result.success
    assert result.execution_time_ms < 200  # Comprehensive
    assert result.tokens_used <= 200
    assert result.metadata['pattern_type'] == 'hybrid'

@pytest.mark.asyncio
async def test_caching(engine):
    """Test caching functionality"""
    query = "recall test pattern"

    # First execution - cache miss
    result1 = await engine.execute(query)
    assert not result1.cache_hit
    time1 = result1.execution_time_ms

    # Second execution - cache hit
    result2 = await engine.execute(query)
    assert result2.cache_hit
    time2 = result2.execution_time_ms

    # Cache should be much faster
    assert time2 < time1 * 0.1  # At least 10x faster

@pytest.mark.asyncio
async def test_custom_pattern_registration(engine):
    """Test custom pattern registration"""
    custom = PatternDefinition.from_config({
        'name': 'test_pattern',
        'pattern_type': 'infrastructure',
        'trigger_pattern': r'test\s+custom\s+pattern',
        'cost_tokens': 50,
        'priority': 10
    })

    engine.registry.register(custom)

    result = await engine.execute("test custom pattern")
    assert result.pattern_name == 'test_pattern'
    assert result.success
```

### Integration Testing

```python
@pytest.mark.integration
class TestPatternIntegration:
    """Integration tests with real database"""

    @pytest.fixture(autouse=True)
    async def setup(self, db_session):
        """Setup test data"""
        self.engine = await create_pattern_execution_engine()
        # Insert test data

    async def test_end_to_end_workflow(self):
        """Test complete workflow"""
        # Store memory
        store = await self.engine.execute(
            "store test optimization pattern",
            use_cache=False
        )
        assert store.success

        # Recall memory
        recall = await self.engine.execute(
            "recall test optimization pattern"
        )
        assert recall.success
        assert len(recall.result['memories']) > 0

        # Analyze
        analyze = await self.engine.execute(
            "analyze optimization patterns",
            execution_mode=ExecutionMode.HYBRID
        )
        assert analyze.success
```

### Performance Testing

```python
@pytest.mark.performance
class TestPatternPerformance:
    """Performance benchmarks"""

    async def test_infrastructure_performance(self, engine):
        """Test infrastructure pattern meets targets"""
        times = []

        for _ in range(100):
            result = await engine.execute(
                "check health",
                execution_mode=ExecutionMode.FAST,
                use_cache=False  # No cache for benchmark
            )
            times.append(result.execution_time_ms)

        p50 = sorted(times)[50]
        p95 = sorted(times)[95]

        assert p50 < 25, f"P50 ({p50}ms) exceeds 25ms target"
        assert p95 < 50, f"P95 ({p95}ms) exceeds 50ms target"

    async def test_cache_effectiveness(self, engine):
        """Test cache hit rate"""
        # Execute same query 100 times
        query = "recall test pattern"

        for _ in range(100):
            await engine.execute(query)

        stats = engine.get_stats()

        # Should have >80% cache hit rate
        assert stats['cache_hit_rate'] > 80
```

## Performance Tuning

### Database Optimization

```python
# Use index hints for large datasets
from sqlalchemy import text

stmt = select(Memory).where(
    Memory.content.ilike(f"%{query}%")
).order_by(
    Memory.importance.desc()
).limit(10).execution_options(
    postgresql_use_index='idx_memory_content'
)
```

### Connection Pooling

```python
# Optimize pool size
settings = get_settings()
settings.database_pool_size = 20
settings.database_max_overflow = 10
settings.database_pool_pre_ping = True
```

### Caching Configuration

```python
# Tune cache settings
cache_manager = CacheManager(
    redis_url=settings.redis_url,
    local_ttl=60,        # Local cache: 60s
    redis_ttl=300,       # Redis cache: 5min
    max_local_size=1000  # Max 1000 entries
)
```

---

**Next Steps**:
- Review [API Documentation](PATTERN_SERVICE_API.md) for complete reference
- Check [Examples](../examples/pattern_execution_examples.py) for more code samples
- See [Operations Guide](PATTERN_OPERATIONS_GUIDE.md) for deployment

For questions: Review the [User Guide](PATTERN_USER_GUIDE.md) or check existing tests.
