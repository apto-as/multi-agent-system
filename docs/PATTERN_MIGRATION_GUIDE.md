# Pattern Execution Service - Migration Guide

**TMWS v2.0 → v2.2** | **Existing Users**

## Overview

This guide helps you migrate from TMWS v2.0 (or earlier) to v2.2.0 with the new Pattern Execution Service.

**Migration benefits**:
- 50% faster execution times
- 45% lower token usage
- 85% cache hit rate
- Automatic query optimization
- Backward compatible API

## Migration Steps

### Step 1: Pre-Migration Assessment

#### Check Current Version

```bash
# Check TMWS version
python -c "
from src.core.config import get_settings
print(f'TMWS version: {get_settings().version}')
"
```

#### Inventory Current Usage

```bash
# Analyze current query patterns
python scripts/analyze_query_patterns.py > migration_report.txt

# Review report
cat migration_report.txt
```

**Sample output**:
```
Query Analysis Report
=====================
Total queries analyzed: 10,000
Average execution time: 150ms
Average tokens: 150

Query types:
- Memory queries: 60% (6,000)
- Infrastructure queries: 25% (2,500)
- Complex queries: 15% (1,500)

Potential improvements:
- 60% queries can use MEMORY path (50% faster)
- 25% queries can use INFRASTRUCTURE path (6x faster)
- Cache potential: 85% (8,500 queries cacheable)
```

### Step 2: Backup Current System

#### Database Backup

```bash
# Full backup
pg_dump -h localhost -U tmws_user tmws_production > backup_pre_migration.sql

# Verify backup
pg_restore --list backup_pre_migration.sql | head -20
```

#### Configuration Backup

```bash
# Backup all configs
cp -r /opt/tmws/config /opt/tmws/config.backup.$(date +%Y%m%d)

# Backup environment
cp /opt/tmws/.env /opt/tmws/.env.backup.$(date +%Y%m%d)
```

### Step 3: Install Pattern Service

#### Update Dependencies

```bash
cd /opt/tmws

# Pull latest code
git fetch origin
git checkout v2.2.0

# Update Python dependencies
pip install -r requirements.txt --upgrade

# Install new dependencies
pip install redis aioredis
```

#### Update Database Schema

```bash
# Run migrations
python -m alembic upgrade head

# Verify schema
python -c "
from sqlalchemy import inspect
from src.core.database import engine

inspector = inspect(engine)
tables = inspector.get_table_names()
print('Tables:', tables)
assert 'learning_patterns_v2' in tables
print('✓ Migration successful')
"
```

#### Initialize Pattern Service

```bash
# Initialize default patterns
python scripts/initialize_patterns.py

# Verify initialization
python -c "
from src.services.pattern_execution_service import create_pattern_execution_engine
import asyncio

async def verify():
    engine = await create_pattern_execution_engine()
    stats = engine.registry.get_stats()
    print(f'Patterns loaded: {stats[\"total_patterns\"]}')
    assert stats['total_patterns'] > 0
    print('✓ Pattern service initialized')

asyncio.run(verify())
"
```

### Step 4: Update Application Code

#### Before (v2.0)

```python
# Old direct database queries
from src.services.memory_service import MemoryService

memory_service = MemoryService(session)

# Manual query
results = await memory_service.search(
    query="optimization patterns",
    limit=10
)
```

#### After (v2.2)

```python
# New pattern-based queries
from src.services.pattern_execution_service import create_pattern_execution_engine

engine = await create_pattern_execution_engine()

# Automatic optimization
result = await engine.execute(
    "recall optimization patterns"
)

results = result.result  # Same format as before
```

#### Migration Helper

```python
# migration_helper.py
class PatternServiceMigrationHelper:
    """Helper to gradually migrate from v2.0 to v2.2"""

    def __init__(self):
        self.engine = None
        self.fallback_service = None

    async def initialize(self):
        """Initialize both old and new services"""
        self.engine = await create_pattern_execution_engine()
        self.fallback_service = MemoryService(session)

    async def execute_with_fallback(self, query: str):
        """
        Try new pattern service, fallback to old service
        Use during migration period
        """
        try:
            # Try pattern service
            result = await self.engine.execute(query)
            if result.success:
                return result.result
        except Exception as e:
            logger.warning(f"Pattern service failed: {e}, using fallback")

        # Fallback to old service
        return await self.fallback_service.search(query)
```

### Step 5: Pattern Conversion

#### Converting Existing Queries

| v2.0 Query | v2.2 Pattern |
|------------|--------------|
| `memory_service.search("security")` | `engine.execute("recall security patterns")` |
| `memory_service.get_recent(limit=10)` | `engine.execute("get recent memories")` |
| `memory_service.filter_by_tag("important")` | `engine.execute("find memories tagged important")` |
| `analysis_service.analyze(data)` | `engine.execute("analyze system performance")` |

#### Custom Pattern Creation

For queries not covered by default patterns:

```python
# Custom migration pattern
custom_pattern = {
    'name': 'legacy_search',
    'pattern_type': 'memory',
    'trigger_pattern': r'search\s+\w+',  # Matches old search queries
    'cost_tokens': 100,
    'priority': 5,
    'metadata': {'migrated_from': 'v2.0'}
}

from src.services.pattern_execution_service import PatternDefinition
pattern = PatternDefinition.from_config(custom_pattern)
engine.registry.register(pattern)
```

### Step 6: Gradual Rollout

#### Phase 1: Testing (Week 1)

```python
# Enable pattern service for 10% of traffic
import random

async def execute_query(query: str):
    if random.random() < 0.1:  # 10% traffic
        result = await engine.execute(query)
        return result.result
    else:
        return await old_service.search(query)
```

**Monitor**:
- Error rates
- Response times
- Token usage
- Cache hit rates

#### Phase 2: Expansion (Week 2)

```python
# Increase to 50% traffic
async def execute_query(query: str):
    if random.random() < 0.5:  # 50% traffic
        result = await engine.execute(query)
        return result.result
    else:
        return await old_service.search(query)
```

**Metrics to watch**:
- P50, P95, P99 latencies
- Success rates
- Cache effectiveness

#### Phase 3: Full Migration (Week 3)

```python
# 100% traffic on pattern service
async def execute_query(query: str):
    result = await engine.execute(query)
    return result.result
```

**Final validation**:
- All queries using patterns
- Performance targets met
- No increase in errors

### Step 7: Verification

#### Functional Testing

```bash
# Run test suite
pytest tests/integration/test_pattern_migration.py -v

# Expected output:
# test_pattern_compatibility ... PASSED
# test_performance_improvement ... PASSED
# test_cache_effectiveness ... PASSED
# test_error_handling ... PASSED
```

#### Performance Benchmarking

```python
# benchmark_migration.py
import asyncio
import time
from statistics import mean, median

async def benchmark_comparison():
    """Compare v2.0 vs v2.2 performance"""

    # Old service
    old_times = []
    for _ in range(100):
        start = time.perf_counter()
        await old_service.search("test query")
        old_times.append((time.perf_counter() - start) * 1000)

    # New pattern service
    new_times = []
    for _ in range(100):
        start = time.perf_counter()
        result = await engine.execute("recall test query")
        new_times.append((time.perf_counter() - start) * 1000)

    print(f"Old service - Mean: {mean(old_times):.2f}ms, Median: {median(old_times):.2f}ms")
    print(f"New service - Mean: {mean(new_times):.2f}ms, Median: {median(new_times):.2f}ms")
    print(f"Improvement: {(1 - mean(new_times)/mean(old_times)) * 100:.1f}%")

asyncio.run(benchmark_comparison())
```

**Expected results**:
```
Old service - Mean: 150.00ms, Median: 145.00ms
New service - Mean: 75.00ms, Median: 50.00ms
Improvement: 50.0%
```

## Backward Compatibility

### API Compatibility

The Pattern Execution Service maintains backward compatibility with v2.0 APIs:

```python
# v2.0 API still works
from src.services.memory_service import MemoryService

memory_service = MemoryService(session)
results = await memory_service.search(query)  # Still supported

# But v2.2 is preferred
from src.services.pattern_execution_service import create_pattern_execution_engine

engine = await create_pattern_execution_engine()
result = await engine.execute(query)  # Faster, optimized
```

### Data Format Compatibility

Response formats remain compatible:

```python
# v2.0 response
{
    'results': [...],
    'count': 10,
    'execution_time': 150
}

# v2.2 response (same structure + extra fields)
{
    'results': [...],
    'count': 10,
    'execution_time': 50,  # Faster!
    'pattern_name': 'recall_memory',  # New
    'cache_hit': True  # New
}
```

## Pattern Conversion Examples

### Example 1: Simple Memory Search

**Before (v2.0)**:
```python
results = await memory_service.search(
    query="security vulnerabilities",
    limit=20,
    order_by="importance DESC"
)
```

**After (v2.2)**:
```python
result = await engine.execute(
    "recall important security vulnerabilities"
)
# Automatically optimized with same results
```

### Example 2: Tagged Search

**Before (v2.0)**:
```python
results = await memory_service.filter_by_tags(
    tags=["performance", "optimization"],
    limit=10
)
```

**After (v2.2)**:
```python
result = await engine.execute(
    "find memories tagged performance and optimization"
)
```

### Example 3: Complex Analysis

**Before (v2.0)**:
```python
# Multiple steps
memories = await memory_service.search("database")
analysis = await analysis_service.analyze(memories)
similar = await memory_service.find_similar(analysis.key_points)

# Combine results manually
final_result = combine_results(memories, analysis, similar)
```

**After (v2.2)**:
```python
# Single optimized query with parallel execution
result = await engine.execute(
    "analyze database patterns and find similar cases",
    execution_mode=ExecutionMode.HYBRID
)
# Automatically parallelized and optimized
```

## Rollback Procedures

### If Migration Fails

#### Quick Rollback

```bash
# Stop new service
sudo systemctl stop tmws

# Restore v2.0 code
git checkout v2.0

# Restore database
psql tmws_production < backup_pre_migration.sql

# Restore config
cp /opt/tmws/config.backup.*/* /opt/tmws/config/

# Start old service
sudo systemctl start tmws
```

#### Partial Rollback

```python
# Revert to old service for specific query types
async def execute_query(query: str):
    # Use pattern service for simple queries
    if is_simple_query(query):
        result = await engine.execute(query)
        return result.result
    else:
        # Fallback for complex queries
        return await old_service.search(query)
```

## Common Migration Issues

### Issue 1: Pattern Not Found

**Symptom**: `NotFoundError: No matching pattern found`

**Solution**: Create custom pattern for your query

```python
# Register missing pattern
custom = PatternDefinition.from_config({
    'name': 'my_custom_query',
    'pattern_type': 'memory',
    'trigger_pattern': r'your\s+query\s+pattern',
    'cost_tokens': 100,
    'priority': 5
})
engine.registry.register(custom)
```

### Issue 2: Different Results

**Symptom**: Pattern service returns different results than v2.0

**Cause**: Different optimization paths

**Solution**: Use COMPREHENSIVE mode for exact v2.0 behavior

```python
result = await engine.execute(
    query,
    execution_mode=ExecutionMode.COMPREHENSIVE  # More thorough
)
```

### Issue 3: Performance Regression

**Symptom**: Some queries slower than v2.0

**Diagnosis**:
```python
result = await engine.execute(query)
print(f"Execution time: {result.execution_time_ms}ms")
print(f"Pattern: {result.pattern_name}")
print(f"Cache hit: {result.cache_hit}")
```

**Solutions**:
1. Check cache is working (should have 85%+ hit rate)
2. Verify Redis is running
3. Use FAST mode for simple queries
4. Check database indexes

## Post-Migration Optimization

### Tune Cache Settings

```python
# After migration, optimize cache based on usage patterns
stats = engine.get_stats()

if stats['cache_hit_rate'] < 80:
    # Increase cache size and TTL
    cache_manager.max_local_size = 2000
    cache_manager.redis_ttl = 600
```

### Add Custom Patterns

```python
# Analyze frequent queries
query_analysis = analyze_query_logs()

# Create patterns for top queries
for query_type, count in query_analysis.items():
    if count > 100:  # Frequently used
        register_custom_pattern(query_type)
```

### Monitor and Adjust

```python
# Set up monitoring
from prometheus_client import start_http_server

# Expose metrics
start_http_server(8001)

# Check metrics regularly
curl http://localhost:8001/metrics | grep tmws_pattern
```

## Migration Checklist

### Pre-Migration

- [ ] Backup database
- [ ] Backup configuration
- [ ] Document current query patterns
- [ ] Review performance baselines
- [ ] Test migration in staging

### During Migration

- [ ] Update code repository
- [ ] Run database migrations
- [ ] Initialize pattern service
- [ ] Deploy to testing environment
- [ ] Verify functionality
- [ ] Gradual rollout (10% → 50% → 100%)

### Post-Migration

- [ ] Verify all queries working
- [ ] Check performance improvements
- [ ] Monitor cache hit rates
- [ ] Document custom patterns
- [ ] Train team on new service
- [ ] Archive v2.0 code

### Rollback Plan

- [ ] Backup rollback procedure documented
- [ ] Rollback tested in staging
- [ ] Team trained on rollback process
- [ ] Monitoring alerts configured
- [ ] Escalation path defined

## Timeline

**Recommended migration timeline**:

| Week | Phase | Activities |
|------|-------|-----------|
| Week 1 | Preparation | Backup, testing, team training |
| Week 2 | Testing | 10% traffic, monitor, fix issues |
| Week 3 | Expansion | 50% traffic, performance validation |
| Week 4 | Full Migration | 100% traffic, final optimization |
| Week 5 | Stabilization | Monitoring, custom patterns, documentation |

## Success Criteria

Migration is successful when:

✅ All queries execute without errors
✅ Performance improved by >40%
✅ Token usage reduced by >40%
✅ Cache hit rate >80%
✅ P95 latency <200ms
✅ No increase in error rates
✅ Team trained and comfortable

## Support

### Getting Help

1. **Check documentation**: [Pattern Service README](PATTERN_SERVICE_README.md)
2. **Review examples**: [Examples Directory](../examples/)
3. **Test cases**: [Test Suite](../tests/unit/test_pattern_execution_service.py)
4. **Migration issues**: Create ticket with:
   - Query that failed
   - Error message
   - Expected vs actual behavior
   - Environment details

### Additional Resources

- [Developer Guide](PATTERN_DEVELOPER_GUIDE.md) - Technical details
- [Operations Guide](PATTERN_OPERATIONS_GUIDE.md) - Deployment
- [User Guide](PATTERN_USER_GUIDE.md) - End-user documentation
- [API Reference](PATTERN_SERVICE_API.md) - Complete API docs

---

**Questions?** Contact the TMWS development team or open an issue in the repository.

**Feedback?** Share your migration experience to help improve this guide!
