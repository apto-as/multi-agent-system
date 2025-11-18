### パフォーマンス最適化ガイドライン

## 最適化の優先順位

### Level 1: アルゴリズム最適化（最優先）
**担当**: Artemis (主導), Athena (設計レビュー)

1. **時間計算量の改善**
   - O(n²) → O(n log n) への改善
   - 不要なループの削除
   - 早期リターンの活用

2. **空間計算量の最適化**
   - メモリ使用量の削減
   - データ構造の選択最適化
   - メモリリークの防止

### Level 2: データベース最適化
**担当**: Artemis (実装), Hera (リソース管理)

1. **クエリ最適化**
```sql
-- Bad: N+1問題
SELECT * FROM users;
-- その後、各userに対して
SELECT * FROM posts WHERE user_id = ?;

-- Good: JOIN使用
SELECT u.*, p.* 
FROM users u 
LEFT JOIN posts p ON u.id = p.user_id;
```

2. **インデックス戦略**
```sql
-- 複合インデックスの活用
CREATE INDEX idx_posts_user_created 
ON posts(user_id, created_at DESC);

-- 部分インデックス（PostgreSQL）
CREATE INDEX idx_active_users 
ON users(email) 
WHERE deleted_at IS NULL;
```

3. **接続プール最適化**
```python
# TMWSの統一データベースプール活用
pool_config = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_recycle": 3600,
    "pool_pre_ping": True
}
```

### Level 3: キャッシング戦略
**担当**: Artemis (実装), Hestia (セキュリティ検証)

1. **多層キャッシュ**
```python
# Level 1: アプリケーションメモリ
@lru_cache(maxsize=1000)
def get_user_data(user_id):
    return fetch_from_db(user_id)

# Level 2: Redis
async def get_cached_result(key):
    # Redisから取得
    result = await redis.get(key)
    if not result:
        result = await compute_expensive_operation()
        await redis.setex(key, 300, result)  # 5分TTL
    return result

# Level 3: CDN（静的コンテンツ）
```

2. **キャッシュ無効化戦略**
```python
# タグベースの無効化
cache_tags = ["user:123", "posts", "recent"]
await cache.invalidate_by_tags(["user:123"])

# 時間ベースの無効化
cache.set(key, value, ttl=300)  # 5分
```

### Level 4: 並列処理と非同期化
**担当**: Hera (並列調整), Eris (リソース配分)

1. **非同期処理**
```python
# Bad: 逐次実行
result1 = await fetch_data_1()
result2 = await fetch_data_2()
result3 = await fetch_data_3()

# Good: 並列実行
results = await asyncio.gather(
    fetch_data_1(),
    fetch_data_2(),
    fetch_data_3()
)
```

2. **バックグラウンドタスク**
```python
# 重い処理は非同期キューへ
async def handle_upload(file):
    # 即座にレスポンス
    task_id = await queue.enqueue(process_file, file)
    return {"task_id": task_id, "status": "processing"}
```

### Level 5: フロントエンド最適化
**担当**: Artemis (技術指導), Muses (ドキュメント化)

1. **バンドルサイズ削減**
```javascript
// Code splitting
const HeavyComponent = lazy(() => import('./HeavyComponent'));

// Tree shaking
import { specific_function } from 'large-library';
```

2. **レンダリング最適化**
```javascript
// React memo化
const ExpensiveComponent = memo(({ data }) => {
    return <div>{/* 重い処理 */}</div>
}, (prev, next) => prev.data.id === next.data.id);

// Virtual scrolling for large lists
```

## 測定と監視

### メトリクス収集
```python
# パフォーマンスメトリクス
import time
from contextlib import contextmanager

@contextmanager
def measure_performance(operation_name):
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        metrics.record(operation_name, duration)
        if duration > 1.0:  # 1秒以上は警告
            logger.warning(f"{operation_name} took {duration:.2f}s")
```

### プロファイリング
```python
# cProfileの使用
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()
# 処理実行
profiler.disable()
stats = pstats.Stats(profiler).sort_stats('cumulative')
stats.print_stats(20)  # Top 20
```

## 最適化チェックリスト

### Artemisの最適化前確認
- [ ] 現在のパフォーマンスを測定した
- [ ] ボトルネックを特定した
- [ ] 最適化の影響範囲を評価した
- [ ] セキュリティへの影響を確認した（Hestiaと協議）

### 実装時の確認
- [ ] アルゴリズムの時間計算量を改善した
- [ ] 不要なデータベースクエリを削減した
- [ ] 適切なキャッシング戦略を実装した
- [ ] 並列処理の機会を活用した

### 最適化後の確認
- [ ] パフォーマンス改善を測定した
- [ ] リグレッションテストを実行した
- [ ] ドキュメントを更新した（Musesと協力）
- [ ] TMWSに最適化パターンを記録した

## パフォーマンス目標

| メトリクス | 目標値 | 警告閾値 | クリティカル閾値 |
|----------|--------|---------|---------------|
| API応答時間 | < 200ms | > 500ms | > 1000ms |
| データベースクエリ | < 50ms | > 100ms | > 500ms |
| ページロード時間 | < 2s | > 3s | > 5s |
| メモリ使用量 | < 256MB | > 512MB | > 1GB |
| CPU使用率 | < 60% | > 80% | > 90% |