# Performance Optimization Context v2.2.1

**Load Condition**: `coding` or `full` context profile
**Estimated Size**: ~2k tokens
**Primary Agent**: Artemis (with Hera resource management)

---

## Quick Reference

### Performance Hierarchy
1. **Algorithm Optimization** (highest priority) - O(n) complexity improvements
2. **Database Optimization** - Query tuning, indexing, connection pooling
3. **Caching Strategy** - Multi-tier caching (memory → Redis → CDN)
4. **Parallelization** - Async operations, concurrent processing
5. **Frontend Optimization** - Bundle size, lazy loading, rendering

---

## Algorithm Optimization (Level 1 - Critical)

### Time Complexity Improvements

**Common Patterns**:
```python
# Bad: O(n²) nested loops
def find_duplicates_slow(arr):
    duplicates = []
    for i in range(len(arr)):
        for j in range(i+1, len(arr)):
            if arr[i] == arr[j]:
                duplicates.append(arr[i])
    return duplicates

# Good: O(n) using set
def find_duplicates_fast(arr):
    seen = set()
    duplicates = set()
    for item in arr:
        if item in seen:
            duplicates.add(item)
        seen.add(item)
    return list(duplicates)
```

**Data Structure Selection**:
- **Lookup**: `dict` (O(1)) > `set` (O(1)) > `list` (O(n))
- **Insertion**: `deque` (O(1)) > `list.append` (O(1) amortized)
- **Range Queries**: `bisect` (O(log n)) > linear search (O(n))
- **Priority**: `heapq` (O(log n)) > sorted list (O(n log n))

---

## Database Optimization (Level 2)

### Query Optimization

**N+1 Problem Solution**:
```python
# Bad: N+1 queries
users = User.query.all()
for user in users:
    posts = Post.query.filter_by(user_id=user.id).all()  # N queries!

# Good: Single JOIN
users_with_posts = db.session.query(User).join(Post).all()
```

**Index Strategy**:
```sql
-- Single column index
CREATE INDEX idx_users_email ON users(email);

-- Composite index (order matters!)
CREATE INDEX idx_posts_user_created ON posts(user_id, created_at DESC);

-- Partial index (PostgreSQL)
CREATE INDEX idx_active_users ON users(email) WHERE deleted_at IS NULL;

-- Covering index
CREATE INDEX idx_posts_cover ON posts(user_id, created_at) INCLUDE (title, content);
```

**Connection Pooling** (TMWS Default):
```python
# Unified database pool configuration
pool_config = {
    "pool_size": 10,        # Base connections
    "max_overflow": 20,     # Additional connections
    "pool_recycle": 3600,   # Recycle after 1 hour
    "pool_pre_ping": True   # Verify before use
}
```

---

## Caching Strategy (Level 3)

### Multi-Tier Caching

**Layer 1: Application Memory** (Fastest)
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def expensive_computation(x):
    # Heavy calculation
    return result
```

**Layer 2: Redis** (Distributed)
```python
import redis
import json

redis_client = redis.Redis(host='localhost', port=6379, db=0)

async def get_cached_data(key):
    # Try cache first
    cached = await redis_client.get(key)
    if cached:
        return json.loads(cached)

    # Compute and cache
    data = await expensive_operation()
    await redis_client.setex(key, 300, json.dumps(data))  # 5 min TTL
    return data
```

**Layer 3: CDN** (Static Content)
- Images, CSS, JavaScript
- Cloudflare, CloudFront, Fastly
- Long TTL (days/months)

**Cache Invalidation Strategies**:
```python
# Tag-based invalidation
cache_tags = ["user:123", "posts", "recent"]
await cache.invalidate_by_tags(["user:123"])

# Time-based invalidation
cache.set(key, value, ttl=300)  # 5 minutes

# Event-based invalidation
@event.on("user_updated")
async def invalidate_user_cache(user_id):
    await cache.delete(f"user:{user_id}")
```

---

## Parallelization (Level 4)

### Async/Await Patterns

**Parallel I/O Operations**:
```python
import asyncio

# Bad: Sequential
result1 = await fetch_user_data()
result2 = await fetch_posts_data()
result3 = await fetch_comments_data()

# Good: Parallel
results = await asyncio.gather(
    fetch_user_data(),
    fetch_posts_data(),
    fetch_comments_data()
)
```

**Background Task Processing**:
```python
from celery import Celery

# Heavy work in background
@celery.task
def process_large_file(file_path):
    # Time-consuming processing
    return result

# Immediate response
@app.post("/upload")
async def upload_handler(file):
    task = process_large_file.delay(file.path)
    return {"task_id": task.id, "status": "processing"}
```

**Worker Pool Management**:
```python
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# I/O bound: Thread pool
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(api_call, url) for url in urls]
    results = [f.result() for f in futures]

# CPU bound: Process pool
with ProcessPoolExecutor(max_workers=4) as executor:
    results = executor.map(compute_heavy, data_chunks)
```

---

## Frontend Optimization (Level 5)

### Bundle Size Reduction

**Code Splitting** (React/Next.js):
```javascript
// Dynamic imports
const HeavyComponent = lazy(() => import('./HeavyComponent'));

// Route-based splitting
const Dashboard = lazy(() => import('./pages/Dashboard'));
```

**Tree Shaking**:
```javascript
// Bad: Import everything
import _ from 'lodash';

// Good: Import specific function
import { debounce } from 'lodash-es';
```

### Rendering Optimization

**React Memoization**:
```javascript
import { memo, useMemo, useCallback } from 'react';

// Memoized component
const ExpensiveComponent = memo(({ data }) => {
    const processed = useMemo(() => heavyComputation(data), [data]);
    return <div>{processed}</div>;
});

// Memoized callback
const handleClick = useCallback(() => {
    doSomething(id);
}, [id]);
```

**Virtual Scrolling** (Large Lists):
```javascript
import { FixedSizeList } from 'react-window';

<FixedSizeList
    height={600}
    itemCount={10000}
    itemSize={50}
    width="100%"
>
    {Row}
</FixedSizeList>
```

---

## Performance Monitoring

### Metrics to Track

**Response Time**:
- **Target**: <200ms (API), <2s (Page Load)
- **P50, P95, P99**: Track percentiles, not just averages
- **Measurement**: Application Performance Monitoring (APM)

**Resource Utilization**:
- **CPU**: Target <70% average
- **Memory**: Monitor for leaks, set limits
- **Database**: Connection pool usage, query time
- **Cache**: Hit ratio >80%

### Profiling Tools

**Python**:
```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()
# Code to profile
profiler.disable()

stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # Top 20 functions
```

**JavaScript**:
```javascript
// Chrome DevTools Performance API
performance.mark('start');
// Code to measure
performance.mark('end');
performance.measure('myOperation', 'start', 'end');
```

---

## Performance Testing

### Load Testing

**Artillery** (API Load Testing):
```yaml
config:
  target: 'https://api.example.com'
  phases:
    - duration: 60
      arrivalRate: 10
      rampTo: 100
scenarios:
  - name: "API Load Test"
    flow:
      - get:
          url: "/api/users"
```

**k6** (Programmable Load Testing):
```javascript
import http from 'k6/http';
import { check } from 'k6';

export let options = {
    vus: 100,
    duration: '30s',
};

export default function() {
    let res = http.get('https://api.example.com');
    check(res, {
        'status is 200': (r) => r.status === 200,
        'response time < 200ms': (r) => r.timings.duration < 200,
    });
}
```

---

## Artemis Performance Checklist

When optimizing, Artemis follows this systematic approach:

- [ ] **Measure baseline**: Establish current performance metrics
- [ ] **Identify bottleneck**: Profile to find actual slowdown
- [ ] **Algorithm first**: Check for O(n²) → O(n log n) opportunities
- [ ] **Database queries**: Eliminate N+1, add indexes
- [ ] **Caching**: Implement appropriate tier for access pattern
- [ ] **Async operations**: Parallelize independent I/O
- [ ] **Frontend**: Code splitting, lazy loading
- [ ] **Measure improvement**: Verify with benchmarks
- [ ] **Security check**: Validate with Hestia (no new vulnerabilities)
- [ ] **Document**: Record optimization for Muses

---

## Integration with TMWS

TMWS provides performance optimization support:

```python
# Learn optimization pattern
await tmws.learn_pattern(
    pattern_name="query_optimization",
    description="Added composite index for 90% improvement",
    result="Response time: 500ms → 50ms",
    context={"technique": "btree_index", "table": "posts"}
)

# Apply pattern to similar queries
await tmws.apply_pattern(
    pattern_name="query_optimization",
    target="comments_table_slow_query"
)
```

---

**Performance Optimization v2.2.1**
*Artemis-led optimization with Hera resource management*
*Reference: @artemis-optimizer.md for detailed patterns*
