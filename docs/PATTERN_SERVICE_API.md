# Pattern Execution Service - API Documentation

**Version**: TMWS v2.2.0
**Date**: 2025-01-09

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Classes](#core-classes)
3. [API Reference](#api-reference)
4. [Integration Examples](#integration-examples)
5. [Configuration](#configuration)

## Quick Start

### Installation

```python
from src.services.pattern_execution_service import (
    PatternExecutionEngine,
    ExecutionMode,
    create_pattern_execution_engine
)

# Create engine (async)
engine = await create_pattern_execution_engine()
```

### Basic Usage

```python
# Execute a query
result = await engine.execute("recall security patterns")

print(f"Pattern: {result.pattern_name}")
print(f"Success: {result.success}")
print(f"Time: {result.execution_time_ms:.2f}ms")
print(f"Tokens: {result.tokens_used}")
```

## Core Classes

### PatternExecutionEngine

Main orchestrator for pattern execution with hybrid routing.

```python
class PatternExecutionEngine:
    """
    Core pattern execution engine

    Attributes:
        session: AsyncSession for database operations
        cache_manager: CacheManager for caching
        registry: PatternRegistry for pattern matching
        router: HybridDecisionRouter for intelligent routing
    """
```

### PatternType (Enum)

```python
class PatternType(str, Enum):
    INFRASTRUCTURE = "infrastructure"  # Fast: <50ms
    MEMORY = "memory"                  # Medium: <100ms
    HYBRID = "hybrid"                  # Comprehensive: <200ms
```

### ExecutionMode (Enum)

```python
class ExecutionMode(str, Enum):
    FAST = "fast"              # Infrastructure-only
    BALANCED = "balanced"       # Smart routing (default)
    COMPREHENSIVE = "comprehensive"  # Full hybrid
```

## API Reference

### PatternExecutionEngine.execute()

Execute a query with pattern matching and caching.

```python
async def execute(
    query: str,
    execution_mode: ExecutionMode = ExecutionMode.BALANCED,
    context: Optional[Dict[str, Any]] = None,
    use_cache: bool = True
) -> ExecutionResult
```

**Parameters**:
- `query` (str): Query to execute
- `execution_mode` (ExecutionMode): Execution strategy
- `context` (dict, optional): Additional context for execution
- `use_cache` (bool): Whether to use caching

**Returns**: `ExecutionResult` with execution details

**Example**:
```python
result = await engine.execute(
    "find optimization patterns",
    execution_mode=ExecutionMode.BALANCED,
    context={"agent": "artemis", "priority": "high"}
)
```

**Performance**:
- Infrastructure: <50ms (95th percentile)
- Memory: <100ms (95th percentile)
- Hybrid: <200ms (95th percentile)

### PatternRegistry.register()

Register a new pattern definition.

```python
def register(pattern: PatternDefinition) -> None
```

**Parameters**:
- `pattern` (PatternDefinition): Pattern to register

**Example**:
```python
pattern = PatternDefinition.from_config({
    'name': 'custom_pattern',
    'pattern_type': 'memory',
    'trigger_pattern': r'custom\s+query',
    'cost_tokens': 100,
    'priority': 8
})

engine.registry.register(pattern)
```

### PatternRegistry.register_batch()

Register multiple patterns efficiently.

```python
def register_batch(patterns: List[PatternDefinition]) -> None
```

**Parameters**:
- `patterns` (List[PatternDefinition]): List of patterns to register

**Example**:
```python
patterns = [
    PatternDefinition.from_config(config1),
    PatternDefinition.from_config(config2),
]

engine.registry.register_batch(patterns)
```

**Performance**: Single cache invalidation for all patterns

### HybridDecisionRouter.route()

Get routing decision for a query.

```python
async def route(
    query: str,
    execution_mode: ExecutionMode = ExecutionMode.BALANCED,
    context: Optional[Dict[str, Any]] = None
) -> RoutingDecision
```

**Parameters**:
- `query` (str): Query to route
- `execution_mode` (ExecutionMode): Execution mode
- `context` (dict, optional): Additional context

**Returns**: `RoutingDecision` with routing details

**Example**:
```python
decision = await engine.router.route(
    "analyze security patterns",
    execution_mode=ExecutionMode.BALANCED
)

print(f"Route to: {decision.pattern_type}")
print(f"Confidence: {decision.confidence:.1%}")
print(f"Reasoning: {decision.reasoning}")
```

### PatternExecutionEngine.get_stats()

Get comprehensive execution statistics.

```python
def get_stats() -> Dict[str, Any]
```

**Returns**: Dictionary with execution statistics

**Example**:
```python
stats = engine.get_stats()

print(f"Total executions: {stats['total_executions']}")
print(f"Success rate: {stats['success_rate']:.1f}%")
print(f"Cache hit rate: {stats['cache_hit_rate']:.1f}%")
print(f"Average time: {stats['avg_execution_time_ms']:.2f}ms")
```

**Response format**:
```json
{
  "total_executions": 1000,
  "successful_executions": 980,
  "failed_executions": 20,
  "cache_hits": 850,
  "avg_execution_time_ms": 45.2,
  "total_tokens_used": 82000,
  "success_rate": 98.0,
  "cache_hit_rate": 85.0,
  "registry_stats": {
    "total_patterns": 12,
    "cache_hit_rate": 90.5
  },
  "router_stats": {
    "total_routes": 1000,
    "route_distribution": {
      "infrastructure": 45.0,
      "memory": 30.0,
      "hybrid": 25.0
    }
  }
}
```

## Data Classes

### ExecutionResult

```python
@dataclass
class ExecutionResult:
    pattern_name: str           # Name of matched pattern
    success: bool              # Whether execution succeeded
    result: Any                # Execution result
    execution_time_ms: float   # Time taken in milliseconds
    tokens_used: int           # Tokens consumed
    cache_hit: bool = False    # Whether result was cached
    error: Optional[str] = None  # Error message if failed
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### RoutingDecision

```python
@dataclass
class RoutingDecision:
    pattern_type: PatternType      # Chosen pattern type
    confidence: float              # Confidence score (0-1)
    reasoning: str                 # Explanation of decision
    estimated_cost: int            # Estimated token cost
    alternative_routes: List[PatternType]  # Alternative routes
```

### PatternDefinition

```python
@dataclass
class PatternDefinition:
    name: str                    # Unique pattern name
    pattern_type: PatternType    # Pattern type
    trigger_regex: Pattern       # Pre-compiled regex
    cost_tokens: int            # Token cost
    priority: int = 0           # Priority (higher = checked first)
    cache_ttl: int = 300        # Cache TTL in seconds
    metadata: Dict[str, Any] = field(default_factory=dict)
```

## Integration Examples

### Example 1: FastAPI Integration

```python
from fastapi import FastAPI, Depends
from src.services.pattern_execution_service import create_pattern_execution_engine

app = FastAPI()

# Dependency injection
async def get_engine():
    return await create_pattern_execution_engine()

@app.post("/api/v1/execute")
async def execute_pattern(
    query: str,
    execution_mode: str = "balanced",
    engine = Depends(get_engine)
):
    """Execute pattern with query"""
    result = await engine.execute(
        query,
        execution_mode=ExecutionMode(execution_mode)
    )

    return {
        "pattern": result.pattern_name,
        "success": result.success,
        "execution_time_ms": result.execution_time_ms,
        "tokens_used": result.tokens_used,
        "result": result.result
    }
```

### Example 2: Trinitas Agent Integration

```python
class ArtemisOptimizer:
    """Artemis optimizer agent using pattern service"""

    def __init__(self):
        self.engine = None

    async def initialize(self):
        """Initialize pattern engine"""
        self.engine = await create_pattern_execution_engine()

    async def optimize(self, target: str):
        """Optimize a target component"""
        # Step 1: Recall past optimizations
        past = await self.engine.execute(
            f"recall optimization patterns for {target}",
            execution_mode=ExecutionMode.BALANCED,
            context={"agent": "artemis", "target": target}
        )

        # Step 2: Analyze current state
        current = await self.engine.execute(
            f"analyze current {target} performance",
            execution_mode=ExecutionMode.HYBRID,
            context={"agent": "artemis", "target": target}
        )

        # Step 3: Find similar cases
        similar = await self.engine.execute(
            f"find similar optimization cases",
            execution_mode=ExecutionMode.HYBRID,
            context={"agent": "artemis", "target": target}
        )

        # Process results
        optimization_plan = self._create_plan(past, current, similar)

        # Step 4: Store new pattern
        await self.engine.execute(
            f"store optimization plan for {target}",
            execution_mode=ExecutionMode.FAST,
            context={
                "agent": "artemis",
                "plan": optimization_plan
            }
        )

        return optimization_plan

    def _create_plan(self, past, current, similar):
        """Create optimization plan from results"""
        # Implementation details
        pass
```

### Example 3: Background Task Processing

```python
import asyncio
from src.services.pattern_execution_service import create_pattern_execution_engine

async def background_pattern_processor():
    """Process patterns in background"""
    engine = await create_pattern_execution_engine()

    # Queue of patterns to process
    pattern_queue = asyncio.Queue()

    async def worker():
        """Process patterns from queue"""
        while True:
            query, context = await pattern_queue.get()

            try:
                result = await engine.execute(
                    query,
                    execution_mode=ExecutionMode.BALANCED,
                    context=context
                )

                # Process result
                await process_result(result)

            except Exception as e:
                logger.error(f"Pattern processing failed: {e}")

            finally:
                pattern_queue.task_done()

    # Start workers
    workers = [asyncio.create_task(worker()) for _ in range(5)]

    # Add patterns to queue
    await pattern_queue.put(("recall memories", {"priority": "high"}))

    # Wait for completion
    await pattern_queue.join()

    # Cancel workers
    for w in workers:
        w.cancel()
```

### Example 4: Batch Processing

```python
async def batch_pattern_execution(queries: List[str]):
    """Execute multiple patterns efficiently"""
    engine = await create_pattern_execution_engine()

    # Execute all queries in parallel
    tasks = [
        engine.execute(query, execution_mode=ExecutionMode.BALANCED)
        for query in queries
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    successful = [r for r in results if not isinstance(r, Exception)]
    failed = [r for r in results if isinstance(r, Exception)]

    print(f"Successful: {len(successful)}/{len(queries)}")
    print(f"Failed: {len(failed)}/{len(queries)}")

    return successful, failed
```

## Configuration

### Pattern Configuration (YAML)

```yaml
# config/patterns.yaml

infrastructure_patterns:
  - name: execute_tool
    pattern_type: infrastructure
    trigger_pattern: '(run|execute)\s+tool'
    cost_tokens: 50
    priority: 10
    cache_ttl: 300
    metadata:
      category: tool_execution

memory_patterns:
  - name: recall_memory
    pattern_type: memory
    trigger_pattern: 'recall\s+memory'
    cost_tokens: 100
    priority: 9
    cache_ttl: 300
    metadata:
      category: memory_retrieval

hybrid_patterns:
  - name: semantic_search
    pattern_type: hybrid
    trigger_pattern: 'find\s+similar'
    cost_tokens: 150
    priority: 10
    cache_ttl: 300
    metadata:
      category: semantic_search
```

### Environment Configuration

```bash
# .env

# Redis for caching
TMWS_REDIS_URL=redis://localhost:6379/0

# Database
TMWS_DATABASE_URL=postgresql://user:pass@localhost:5432/tmws

# Cache configuration
TMWS_CACHE_TTL=300
TMWS_CACHE_MAX_SIZE=1000

# Performance tuning
TMWS_DB_MAX_CONNECTIONS=20
TMWS_DB_POOL_PRE_PING=true
```

### Loading Custom Patterns

```python
import yaml
from src.services.pattern_execution_service import PatternDefinition

# Load patterns from YAML
with open('config/patterns.yaml') as f:
    config = yaml.safe_load(f)

# Register patterns
engine = await create_pattern_execution_engine()

for pattern_config in config['infrastructure_patterns']:
    pattern = PatternDefinition.from_config(pattern_config)
    engine.registry.register(pattern)

for pattern_config in config['memory_patterns']:
    pattern = PatternDefinition.from_config(pattern_config)
    engine.registry.register(pattern)

for pattern_config in config['hybrid_patterns']:
    pattern = PatternDefinition.from_config(pattern_config)
    engine.registry.register(pattern)
```

## Error Handling

### Common Errors

```python
from src.core.exceptions import NotFoundError, ValidationError

try:
    result = await engine.execute(query)
except NotFoundError as e:
    # No matching pattern found
    logger.warning(f"Pattern not found: {e}")
except ValidationError as e:
    # Invalid query or configuration
    logger.error(f"Validation error: {e}")
except Exception as e:
    # Other errors
    logger.error(f"Execution failed: {e}")
```

### Graceful Degradation

```python
async def safe_execute(query: str) -> ExecutionResult:
    """Execute with fallback to simpler mode"""
    try:
        # Try comprehensive mode
        return await engine.execute(
            query,
            execution_mode=ExecutionMode.COMPREHENSIVE
        )
    except Exception as e:
        logger.warning(f"Comprehensive mode failed: {e}, falling back")

        try:
            # Fallback to balanced mode
            return await engine.execute(
                query,
                execution_mode=ExecutionMode.BALANCED
            )
        except Exception as e:
            logger.warning(f"Balanced mode failed: {e}, falling back")

            # Last resort: fast mode
            return await engine.execute(
                query,
                execution_mode=ExecutionMode.FAST
            )
```

## Performance Monitoring

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram

# Define metrics
pattern_executions = Counter(
    'tmws_pattern_executions_total',
    'Total pattern executions',
    ['pattern_type', 'success']
)

execution_duration = Histogram(
    'tmws_pattern_execution_duration_seconds',
    'Pattern execution duration',
    ['pattern_type'],
    buckets=[0.01, 0.05, 0.1, 0.2, 0.5, 1.0]
)

# Record metrics
async def execute_with_metrics(query: str):
    start = time.perf_counter()

    result = await engine.execute(query)

    duration = time.perf_counter() - start
    pattern_type = result.metadata.get('pattern_type', 'unknown')

    pattern_executions.labels(
        pattern_type=pattern_type,
        success=str(result.success)
    ).inc()

    execution_duration.labels(
        pattern_type=pattern_type
    ).observe(duration)

    return result
```

## Best Practices

### 1. Initialization

✅ **DO**: Initialize once and reuse
```python
# Good: Single instance
engine = await create_pattern_execution_engine()
await engine.execute(query1)
await engine.execute(query2)
```

❌ **DON'T**: Create new instance per query
```python
# Bad: Multiple instances
engine1 = await create_pattern_execution_engine()
await engine1.execute(query1)

engine2 = await create_pattern_execution_engine()
await engine2.execute(query2)
```

### 2. Caching

✅ **DO**: Use caching for read operations
```python
result = await engine.execute(query, use_cache=True)
```

❌ **DON'T**: Cache write operations
```python
result = await engine.execute("store memory", use_cache=False)
```

### 3. Error Handling

✅ **DO**: Handle errors gracefully
```python
try:
    result = await engine.execute(query)
except Exception as e:
    logger.error(f"Execution failed: {e}")
    return default_result()
```

❌ **DON'T**: Let errors propagate uncaught
```python
result = await engine.execute(query)  # May crash
```

### 4. Context

✅ **DO**: Provide useful context
```python
result = await engine.execute(
    query,
    context={"agent": "artemis", "priority": "high"}
)
```

❌ **DON'T**: Overload context
```python
result = await engine.execute(
    query,
    context={"everything": huge_dict}  # Too much
)
```

## Troubleshooting

See [PATTERN_EXECUTION_OPTIMIZATION.md](PATTERN_EXECUTION_OPTIMIZATION.md#troubleshooting) for detailed troubleshooting guide.

---

**For more information**:
- [Optimization Guide](PATTERN_EXECUTION_OPTIMIZATION.md)
- [Examples](../examples/pattern_execution_examples.py)
- [Pattern Definitions](../config/patterns.yaml)
