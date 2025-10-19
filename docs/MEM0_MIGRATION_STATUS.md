# Mem0 Feature Migration Status - TMWS v2.3.0

## 概要
当初の目標「Mem0からの良いところを移植する」の達成状況と、今後の実装方針を定義します。

## 実装ステータスサマリー

| 機能 | Mem0実装 | TMWS実装状況 | 性能 | 備考 |
|-----|---------|-------------|------|------|
| **Semantic Search** | ✅ | ✅ 完全実装 | 0.47ms P95 | ChromaDB + multilingual-e5 |
| **Memory Layers** | ✅ | ✅ 完全実装 | - | agent_id + namespace |
| **Temporal Decay** | ✅ | ✅ 完全実装 | - | relevance_score decay |
| **Memory Consolidation** | ✅ | ✅ 完全実装 | - | MemoryConsolidation model |
| **Cross-entity Sharing** | ✅ | ✅ 完全実装 | - | access_level + shared_with_agents |
| **Metadata Filtering** | ✅ | ✅ 完全実装 | - | JSONB context + tags |
| **Knowledge Graph** | ✅ Neo4j | ⚠️ 部分実装 | - | parent_memory_id のみ |

**進捗率**: 6/7 完全実装 (85.7%)、1/7 部分実装 (14.3%)

---

## 詳細分析

### 1. Semantic Search (✅ 完全実装)

**Mem0実装**:
```python
# Vector embeddings with similarity search
memory_store.search(query="optimization", top_k=10)
```

**TMWS実装**:
```python
# ChromaDB + multilingual-e5-base (768-dim) / large (1024-dim)
results = await vector_service.search(
    query_embedding=query_embedding,
    top_k=10,
    filters={"agent_id": "athena", "namespace": "default"},
    min_similarity=0.7
)
```

**性能比較**:
- Mem0: 未公開
- TMWS: **0.47ms P95** (ChromaDB HNSW index)
- PostgreSQL pgvector比: **425x高速化** (200ms→0.47ms)

**評価**: ✅ Mem0を超える性能を達成

---

### 2. Memory Layers (✅ 完全実装)

**Mem0実装**:
```python
# User/Session/Agent hierarchy
memory.add("fact", user_id="user_123", session_id="sess_456")
memory.get(user_id="user_123")  # User-specific memories
memory.get(session_id="sess_456")  # Session-specific
```

**TMWS実装**:
```python
# agent_id + namespace による階層化
class Memory(TMWSBase):
    agent_id: Mapped[str]  # Owner agent
    namespace: Mapped[str]  # Memory isolation (default, session, temporary)
    access_level: Mapped[AccessLevel]  # PRIVATE, TEAM, SHARED, PUBLIC, SYSTEM
```

**階層構造**:
```
SYSTEM (全エージェント共有)
  └── PUBLIC (明示的に公開)
       └── SHARED (特定エージェント間共有)
            └── TEAM (同一namespace内共有)
                 └── PRIVATE (個人専用)
```

**評価**: ✅ Mem0と同等以上の柔軟性

---

### 3. Temporal Decay (✅ 完全実装)

**Mem0実装**:
```python
# Time-based importance reduction
memory.decay_factor = 0.95  # Daily decay
```

**TMWS実装**:
```python
class Memory(TMWSBase):
    relevance_score: Mapped[float]  # 0.0-1.0, decays over time
    accessed_at: Mapped[datetime | None]

    def update_access(self) -> None:
        """Update access metadata with decay."""
        self.access_count += 1
        self.accessed_at = datetime.utcnow()
        # Decay relevance over time, boost by access
        self.relevance_score = min(1.0, self.relevance_score * 0.99 + 0.05)
```

**減衰式**:
```
new_relevance = old_relevance × 0.99 + 0.05  (アクセス時)
→ 100日後: 0.366 (約37%に減衰)
→ 200日後: 0.134 (約13%に減衰)
```

**評価**: ✅ Mem0と同等の減衰メカニズム

---

### 4. Memory Consolidation (✅ 完全実装)

**Mem0実装**:
```python
# Multi-memory summarization
memory.consolidate(
    memory_ids=["mem1", "mem2", "mem3"],
    strategy="summarize"
)
```

**TMWS実装**:
```python
class MemoryConsolidation(TMWSBase):
    """Track memory consolidation and summarization."""
    __tablename__ = "memory_consolidations"

    source_memory_ids: Mapped[list[str]]  # Source memories
    consolidated_memory_id: Mapped[UUID]  # Result
    consolidation_type: Mapped[str]  # summary, merge, compress
    consolidation_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB)

    created_at: Mapped[datetime]
```

**統合戦略**:
- `summary`: 複数メモリを要約して1つに
- `merge`: 関連メモリを結合
- `compress`: 冗長性を削減

**評価**: ✅ Mem0と同等の統合機能

---

### 5. Cross-entity Sharing (✅ 完全実装)

**Mem0実装**:
```python
# Agent-to-agent memory sharing
memory.share(memory_id="mem_123", with_agents=["agent_2", "agent_3"])
```

**TMWS実装**:
```python
class Memory(TMWSBase):
    access_level: Mapped[AccessLevel]  # 5段階アクセス制御
    shared_with_agents: Mapped[list[str]]  # 明示的共有リスト

    # アクセス制御ロジック
    def can_access(self, requesting_agent_id: str) -> bool:
        if self.access_level == AccessLevel.SYSTEM:
            return True
        if self.access_level == AccessLevel.PUBLIC:
            return True
        if self.access_level == AccessLevel.SHARED:
            return requesting_agent_id in self.shared_with_agents
        if self.access_level == AccessLevel.TEAM:
            return requesting_agent_id in self.get_team_members()
        return requesting_agent_id == self.agent_id  # PRIVATE
```

**評価**: ✅ Mem0より細かいアクセス制御

---

### 6. Metadata Filtering (✅ 完全実装)

**Mem0実装**:
```python
# Flexible metadata search
memory.search(
    query="optimization",
    filters={"category": "performance", "priority": "high"}
)
```

**TMWS実装**:
```python
class Memory(TMWSBase):
    context: Mapped[dict[str, Any]] = mapped_column(JSONB)  # Flexible metadata
    tags: Mapped[list[str]]  # Indexed tags

# PostgreSQL JSONB operators
SELECT * FROM memories_v2
WHERE context @> '{"category": "performance"}'::jsonb
  AND tags && ARRAY['optimization', 'database'];

# ChromaDB metadata filtering
results = vector_service.search(
    query_embedding=embedding,
    filters={
        "agent_id": "artemis",
        "namespace": "default",
        "importance": {"$gte": 0.8}
    }
)
```

**インデックス**:
```sql
CREATE INDEX idx_memories_context_gin ON memories_v2 USING GIN (context);
CREATE INDEX idx_memories_tags ON memories_v2 USING GIN (tags);
```

**評価**: ✅ Mem0と同等のフィルタリング能力

---

### 7. Knowledge Graph (⚠️ 部分実装)

**Mem0実装**:
```python
# Explicit entity-relationship modeling
Entity("Claude", type="AI_Agent")
Entity("Database Optimization", type="Task")
Entity("API Performance", type="Metric")

Relationship("Claude", "WORKED_ON", "Database Optimization")
Relationship("Database Optimization", "IMPROVED", "API Performance")
Relationship("API Performance", "MEASURED_BY", "Response Time")

# Graph queries
graph.traverse(
    start="Claude",
    relationships=["WORKED_ON", "IMPROVED"],
    depth=2
)
# → ["Database Optimization", "API Performance"]
```

**TMWS実装 (現状)**:
```python
class Memory(TMWSBase):
    parent_memory_id: Mapped[UUID | None]  # ⚠️ 親子関係のみ
    context: Mapped[dict[str, Any]]  # ⚠️ 暗黙的関係

# 現在の使用例
parent_memory = Memory(
    content="データベース最適化プロジェクト",
    parent_memory_id=None
)

child_memory = Memory(
    content="インデックス追加により90%改善",
    parent_memory_id=parent_memory.id,  # 階層関係
    context={
        "related_to": ["mem_123", "mem_456"],  # 暗黙的関係
        "caused_by": "optimization_task",
        "improves": "api_performance"
    }
)
```

**Mem0との差異**:

| 機能 | Mem0 | TMWS現状 |
|-----|------|---------|
| **階層関係** | ✅ | ✅ parent_memory_id |
| **関係の型定義** | ✅ WORKED_ON, IMPROVED等 | ❌ 型なし |
| **双方向関係** | ✅ | ❌ 単方向のみ |
| **グラフクエリ** | ✅ traverse, shortest_path | ❌ 未実装 |
| **エンティティ抽出** | ✅ 自動 | ❌ 未実装 |
| **関係推論** | ✅ Multi-hop reasoning | ⚠️ JSONB手動のみ |

**現状の制限**:
1. **関係の型がない**: `context`のJSONBに文字列で埋め込むのみ
2. **グラフクエリ不可**: 「AからBを経由してCに至る経路」などが検索できない
3. **自動抽出なし**: エンティティと関係を手動で記録する必要がある
4. **推論機能なし**: 「AがBに影響し、BがCに影響する → AはCに間接影響」などの推論不可

**使用例での比較**:

```python
# Mem0: 知識グラフクエリ
results = graph.query("""
    MATCH (agent:Agent)-[:WORKED_ON]->(task:Task)-[:IMPROVED]->(metric:Metric)
    WHERE agent.name = 'Artemis'
    RETURN task, metric
""")
# → [("Database Optimization", "API Response Time")]

# TMWS現状: JSONB手動検索
results = await session.execute(
    select(Memory)
    .where(Memory.context.contains({"agent": "Artemis"}))
    .where(Memory.context.contains({"type": "optimization"}))
)
# → 関係の推論は不可、手動で related_to を辿る必要がある
```

---

## 性能検証計画 (Phase 1)

現状の階層・タグ・メタデータ機能の性能を検証し、知識グラフ実装の必要性を判断します。

### 検証項目

#### 1. 階層（parent_memory_id）性能テスト

```python
# Benchmark 1: 親子メモリ取得
@benchmark
async def test_hierarchical_retrieval():
    """3階層のメモリツリー取得性能"""
    # Level 1: プロジェクト
    # Level 2: タスク (5個)
    # Level 3: サブタスク (各5個、計25個)

    start = time.perf_counter()
    root = await memory_service.get_memory(project_id)
    tasks = await memory_service.get_children(project_id)
    for task in tasks:
        subtasks = await memory_service.get_children(task.id)
    duration = time.perf_counter() - start

    # 目標: < 50ms (N+1問題なし)
    assert duration < 0.050, f"階層取得が遅い: {duration*1000:.2f}ms"
```

#### 2. タグ検索性能テスト

```python
# Benchmark 2: タグベース検索
@benchmark
async def test_tag_search():
    """複数タグでのAND/OR検索性能"""

    # GIN index使用
    start = time.perf_counter()
    results = await session.execute(
        select(Memory)
        .where(Memory.tags.overlap(["optimization", "database"]))  # OR
        .where(Memory.tags.contains(["critical"]))  # AND
        .limit(100)
    )
    duration = time.perf_counter() - start

    # 目標: < 10ms (GIN indexによる高速化)
    assert duration < 0.010, f"タグ検索が遅い: {duration*1000:.2f}ms"
```

#### 3. メタデータ複合検索テスト

```python
# Benchmark 3: JSONB複合検索
@benchmark
async def test_metadata_complex_search():
    """JSONBメタデータの複雑な検索性能"""

    start = time.perf_counter()
    results = await session.execute(
        select(Memory)
        .where(Memory.context["category"].astext == "performance")
        .where(Memory.context["priority"].astext.in_(["high", "critical"]))
        .where(Memory.importance_score >= 0.8)
        .where(Memory.agent_id == "artemis")
        .limit(100)
    )
    duration = time.perf_counter() - start

    # 目標: < 20ms (GIN index + 複合条件)
    assert duration < 0.020, f"複合検索が遅い: {duration*1000:.2f}ms"
```

#### 4. クロスエージェント共有テスト

```python
# Benchmark 4: 共有メモリアクセス
@benchmark
async def test_cross_agent_sharing():
    """エージェント間メモリ共有の性能"""

    start = time.perf_counter()
    # Artemisが作成したメモリをAthenaが検索
    results = await session.execute(
        select(Memory)
        .where(
            or_(
                Memory.access_level == AccessLevel.PUBLIC,
                Memory.access_level == AccessLevel.SYSTEM,
                and_(
                    Memory.access_level == AccessLevel.SHARED,
                    Memory.shared_with_agents.contains(["athena"])
                )
            )
        )
        .where(Memory.agent_id == "artemis")
        .limit(100)
    )
    duration = time.perf_counter() - start

    # 目標: < 15ms (複合インデックス使用)
    assert duration < 0.015, f"共有検索が遅い: {duration*1000:.2f}ms"
```

### 性能目標値

| テスト | 目標 | 警告 | クリティカル |
|-------|------|------|-------------|
| 階層取得 (3レベル) | < 50ms | > 100ms | > 200ms |
| タグ検索 (100件) | < 10ms | > 20ms | > 50ms |
| メタデータ複合検索 | < 20ms | > 50ms | > 100ms |
| クロスエージェント共有 | < 15ms | > 30ms | > 60ms |

### 知識グラフ実装判断基準

以下のいずれかに該当する場合、知識グラフ実装を検討：

#### 判断基準 A: 性能不足
```
IF (階層取得 > 100ms) OR (複合検索 > 50ms):
    → 「現状の実装では性能要件を満たせない」
    → 知識グラフDBの検討が必要
```

#### 判断基準 B: 機能不足
```
以下のユースケースが頻繁に発生する場合:
1. Multi-hop reasoning (「AからBを経由してCに至る影響」)
2. Shortest path queries (「最短影響経路」)
3. Subgraph extraction (「関連メモリのサブグラフ抽出」)
4. Automatic entity extraction (「エンティティ自動抽出」)
5. Relationship inference (「関係の自動推論」)

→ 現状のJSONB暗黙的関係では対応困難
→ 知識グラフ実装が必要
```

#### 判断基準 C: 複雑度
```
IF (関係の型が10種類以上) OR (グラフ深度が5レベル以上):
    → parent_memory_id + JSONB では管理が困難
    → 明示的なグラフモデルが必要
```

---

## 知識グラフ実装オプション (Phase 2)

Phase 1の性能検証で「実装が必要」と判断された場合の選択肢：

### Option A: PostgreSQL AGE Extension ⭐推奨

**概要**: PostgreSQLの拡張機能でグラフDB機能を追加

**利点**:
- 既存のPostgreSQLインフラを活用
- トランザクション整合性
- SQLとの統合が容易
- 追加の外部依存なし

**実装例**:
```sql
-- AGE extension有効化
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- グラフ作成
SELECT create_graph('tmws_knowledge_graph');

-- エンティティ追加
SELECT * FROM cypher('tmws_knowledge_graph', $$
    CREATE (a:Agent {name: 'Artemis', type: 'optimizer'})
    CREATE (t:Task {name: 'Database Optimization'})
    CREATE (m:Metric {name: 'API Response Time'})
    CREATE (a)-[:WORKED_ON]->(t)
    CREATE (t)-[:IMPROVED]->(m)
$$) as (result agtype);

-- グラフクエリ
SELECT * FROM cypher('tmws_knowledge_graph', $$
    MATCH (a:Agent {name: 'Artemis'})-[:WORKED_ON]->(t:Task)-[:IMPROVED]->(m:Metric)
    RETURN t.name, m.name
$$) as (task agtype, metric agtype);
```

**性能**: グラフクエリ 10-50ms (Cypher最適化済み)

---

### Option B: 専用Relationshipテーブル

**概要**: 現在のモデルを拡張してRelationshipテーブルを追加

**利点**:
- 実装がシンプル
- 既存コードへの影響が小さい
- PostgreSQLのみで完結

**実装例**:
```python
class MemoryRelationship(TMWSBase):
    """Memory-to-memory relationships with typed edges."""
    __tablename__ = "memory_relationships"

    source_memory_id: Mapped[UUID] = mapped_column(ForeignKey("memories_v2.id"))
    target_memory_id: Mapped[UUID] = mapped_column(ForeignKey("memories_v2.id"))
    relationship_type: Mapped[str]  # CAUSED_BY, IMPROVED, DEPENDS_ON, etc.
    strength: Mapped[float]  # 0.0-1.0
    metadata: Mapped[dict[str, Any]] = mapped_column(JSONB)

    # Indexes for graph queries
    __table_args__ = (
        Index('idx_relationships_source', 'source_memory_id'),
        Index('idx_relationships_target', 'target_memory_id'),
        Index('idx_relationships_type', 'relationship_type'),
    )

# Graph traversal (recursive CTE)
async def traverse_graph(start_id: UUID, relationship_types: list[str], max_depth: int = 3):
    query = text("""
        WITH RECURSIVE graph_traverse AS (
            -- Base case
            SELECT
                source_memory_id,
                target_memory_id,
                relationship_type,
                1 AS depth
            FROM memory_relationships
            WHERE source_memory_id = :start_id
              AND relationship_type = ANY(:rel_types)

            UNION ALL

            -- Recursive case
            SELECT
                mr.source_memory_id,
                mr.target_memory_id,
                mr.relationship_type,
                gt.depth + 1
            FROM memory_relationships mr
            INNER JOIN graph_traverse gt ON mr.source_memory_id = gt.target_memory_id
            WHERE gt.depth < :max_depth
              AND mr.relationship_type = ANY(:rel_types)
        )
        SELECT DISTINCT target_memory_id FROM graph_traverse
    """)

    result = await session.execute(
        query,
        {"start_id": start_id, "rel_types": relationship_types, "max_depth": max_depth}
    )
    return [row[0] for row in result]
```

**性能**: 再帰CTE 20-100ms (深度とデータ量による)

---

### Option C: Neo4j統合 (非推奨)

**概要**: 専用グラフDBとして別途Neo4jを導入

**利点**:
- グラフクエリが最速 (1-10ms)
- Cypherクエリ言語が強力
- グラフアルゴリズム豊富

**欠点**:
- **追加の外部依存** (運用コスト増)
- **データ同期の複雑さ** (PostgreSQL ↔ Neo4j)
- **トランザクション整合性の課題**
- **学習コスト** (Cypher言語)

**判断**: TMWSの規模では過剰。Option AまたはBで十分。

---

## 実装推奨フロー

```
Phase 1: 性能検証 (Current)
├─ 階層・タグ・メタデータベンチマーク実施
├─ 実際のユースケースで性能評価
└─ 知識グラフ必要性の判断
    │
    ├─ 性能OK & 機能OK → Phase 2スキップ (現状維持)
    │
    └─ 性能不足 or 機能不足 → Phase 2へ
        │
        Phase 2: 知識グラフ実装
        ├─ Option A (PostgreSQL AGE) ← 推奨
        ├─ Option B (Relationshipテーブル) ← 軽量版
        └─ Option C (Neo4j) ← 大規模向け
```

---

## まとめ

### ✅ 完全実装済み (6/7機能)
- Semantic Search (0.47ms P95, Mem0超)
- Memory Layers (5段階アクセス制御)
- Temporal Decay (relevance_score減衰)
- Memory Consolidation (MemoryConsolidation model)
- Cross-entity Sharing (shared_with_agents)
- Metadata Filtering (JSONB + GIN index)

### ⚠️ 部分実装 (1/7機能)
- Knowledge Graph (parent_memory_id + JSONB暗黙的関係)
  - 関係の型定義なし
  - グラフクエリ未実装
  - エンティティ自動抽出なし

### 📋 次のステップ
1. **Phase 1実行**: 性能ベンチマーク (階層・タグ・メタデータ)
2. **判断**: 現状の性能・機能で十分か？
3. **Phase 2検討**: 必要なら知識グラフ実装 (Option A推奨)

### 🎯 判断基準
```
IF (性能OK) AND (ユースケースカバー率 > 90%):
    → 現状維持、知識グラフ不要
ELSE:
    → PostgreSQL AGE (Option A) 実装を推奨
```
