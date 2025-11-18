# Performance Optimization Guidelines

## Algorithm Optimization Priority
1. O(n²) → O(n log n) improvements
2. Database query optimization
3. Caching strategy implementation
4. Parallel processing utilization
5. Frontend bundle optimization

## Performance Targets
| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| API Response | < 200ms | > 500ms | > 1000ms |
| DB Query | < 50ms | > 100ms | > 500ms |
| Page Load | < 2s | > 3s | > 5s |
| Memory | < 256MB | > 512MB | > 1GB |
| CPU Usage | < 60% | > 80% | > 90% |

## Optimization Checklist
- [ ] Profile before optimizing
- [ ] Measure improvements
- [ ] Consider caching early
- [ ] Use async operations
- [ ] Minimize network calls

## Code Patterns
```javascript
// Bad: Sequential execution
const a = await fetchA();
const b = await fetchB();
const c = await fetchC();

// Good: Parallel execution
const [a, b, c] = await Promise.all([
  fetchA(),
  fetchB(),
  fetchC()
]);
```

## Database Optimization
```sql
-- Add appropriate indexes
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_posts_user_created ON posts(user_id, created_at DESC);

-- Use EXPLAIN ANALYZE
EXPLAIN ANALYZE SELECT * FROM posts WHERE user_id = 123;
```