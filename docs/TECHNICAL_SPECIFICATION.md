# TMWS ハイブリッドクラウド技術仕様書 v1.0

## 1. システム要件仕様

### 1.1 機能要件

#### FR-001: メモリスコープ分類
- **優先度**: 必須
- **説明**: メモリを4つのスコープに自動分類
- **入力**: メモリコンテンツ、メタデータ
- **出力**: スコープ（GLOBAL/SHARED/PROJECT/PRIVATE）、分類詳細
- **制約**:
  - 機密情報は必ずPRIVATEに分類
  - ユーザーオーバーライド可能（安全性検証付き）

#### FR-002: マルチデータベース管理
- **優先度**: 必須
- **説明**: クラウド（PostgreSQL）とローカル（SQLite）の並行管理
- **入力**: スコープ、操作タイプ
- **出力**: 適切なDB接続
- **制約**:
  - GLOBAL/SHARED → クラウドDB
  - PROJECT/PRIVATE → ローカルDB
  - クラウド障害時はローカルフォールバック

#### FR-003: 機密情報自動検出
- **優先度**: 必須
- **説明**: 20+パターンで機密情報を検出
- **入力**: テキストコンテンツ
- **出力**: 検出結果（True/False）、検出タイプリスト
- **制約**:
  - False Negative = 0%（機密情報の見逃しなし）
  - False Positive < 5%

#### FR-004: 同期機構（Phase 3）
- **優先度**: 高
- **説明**: クラウド・ローカル間のデータ同期
- **入力**: 同期対象メモリ
- **出力**: 同期ステータス
- **制約**:
  - 双方向同期
  - Conflict Resolution実装
  - オフライン対応（Write-Ahead Log）

#### FR-005: E2EE暗号化（Phase 4）
- **優先度**: 高
- **説明**: SHAREDスコープのエンドツーエンド暗号化
- **入力**: 平文コンテンツ、チームID
- **出力**: 暗号化データ（AES-256-GCM）
- **制約**:
  - クライアント側暗号化
  - サーバーは暗号文のみ保持
  - チーム公開鍵で鍵配布

### 1.2 非機能要件

#### NFR-001: パフォーマンス
- API応答時間: < 200ms (90パーセンタイル)
- ベクトル検索: < 500ms (クラウド), < 50ms (ローカル)
- 同期遅延: < 5秒

#### NFR-002: 可用性
- システム稼働率: > 99.9%
- クラウドDB障害時のフォールバック: < 1秒
- 平均復旧時間 (MTTR): < 1時間

#### NFR-003: セキュリティ
- TLS 1.3以上（クラウド接続）
- 保存時暗号化（AES-256）
- Row-Level Security (RLS)
- 監査ログ保持期間: 1年

#### NFR-004: スケーラビリティ
- 同時接続数: 1,000ユーザー
- メモリ登録数: 100万件（クラウド）、10万件（ローカル）
- ベクトル次元: 384次元（MiniLM-L6-v2）

---

## 2. データベーススキーマ設計

### 2.1 クラウドDB（PostgreSQL + pgvector）

```sql
-- ============================================
-- Cloud Memories Table
-- ============================================
CREATE TABLE memories_cloud (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content TEXT NOT NULL,
    embedding vector(384),  -- pgvector
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('GLOBAL', 'SHARED')),

    -- Classification metadata
    auto_classified BOOLEAN DEFAULT true,
    classification_details JSONB,

    -- Encryption for SHARED scope
    encrypted_content BYTEA,  -- NULL for GLOBAL, populated for SHARED
    encryption_metadata JSONB,  -- nonce, tag, encrypted_key

    -- Ownership & access control
    owner_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    team_id UUID,  -- NULL for GLOBAL, required for SHARED

    -- Metadata
    tags TEXT[],
    metadata JSONB,
    importance FLOAT DEFAULT 0.5 CHECK (importance >= 0 AND importance <= 1),

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Soft delete
    deleted_at TIMESTAMP,

    -- Indexes
    CONSTRAINT scope_team_check CHECK (
        (scope = 'GLOBAL' AND team_id IS NULL) OR
        (scope = 'SHARED' AND team_id IS NOT NULL)
    )
);

-- Vector similarity search index
CREATE INDEX idx_memories_cloud_embedding ON memories_cloud
USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Scope & tenant index
CREATE INDEX idx_memories_cloud_scope_tenant ON memories_cloud(scope, tenant_id);

-- Tags GIN index
CREATE INDEX idx_memories_cloud_tags ON memories_cloud USING gin(tags);

-- Metadata GIN index
CREATE INDEX idx_memories_cloud_metadata ON memories_cloud USING gin(metadata jsonb_path_ops);

-- Row-Level Security
ALTER TABLE memories_cloud ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON memories_cloud
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY scope_access ON memories_cloud
    USING (
        CASE scope
            WHEN 'GLOBAL' THEN true
            WHEN 'SHARED' THEN tenant_id = current_setting('app.current_tenant', true)::uuid
            ELSE false
        END
    );

-- ============================================
-- Sync Events Table
-- ============================================
CREATE TABLE sync_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(20) NOT NULL CHECK (event_type IN ('CREATE', 'UPDATE', 'DELETE')),
    memory_id UUID NOT NULL,
    source VARCHAR(10) NOT NULL CHECK (source IN ('CLOUD', 'LOCAL')),
    data JSONB NOT NULL,
    synced BOOLEAN DEFAULT false,
    sync_attempts INTEGER DEFAULT 0,
    last_sync_attempt TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sync_events_synced ON sync_events(synced, created_at);
CREATE INDEX idx_sync_events_memory ON sync_events(memory_id);
```

### 2.2 ローカルDB（SQLite）

```sql
-- ============================================
-- Local Memories Table
-- ============================================
CREATE TABLE memories_local (
    id TEXT PRIMARY KEY,  -- UUID as text
    content TEXT NOT NULL,
    embedding BLOB,  -- Vector stored as blob (sqlite-vec)
    scope TEXT NOT NULL CHECK (scope IN ('PROJECT', 'PRIVATE')),

    -- Classification metadata
    auto_classified INTEGER DEFAULT 1,  -- SQLite boolean
    classification_details TEXT,  -- JSON string

    -- Encryption for PRIVATE scope
    encrypted_content BLOB,
    encryption_key_ref TEXT,  -- Reference to local keychain

    -- Metadata
    tags TEXT,  -- JSON array as string
    metadata TEXT,  -- JSON object as string
    importance REAL DEFAULT 0.5 CHECK (importance >= 0 AND importance <= 1),

    -- Timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),

    -- Sync metadata
    synced_to_cloud INTEGER DEFAULT 0,
    cloud_memory_id TEXT,
    last_sync_at TEXT
);

-- Indexes
CREATE INDEX idx_memories_local_scope ON memories_local(scope);
CREATE INDEX idx_memories_local_created ON memories_local(created_at DESC);

-- Virtual table for FTS (Full-Text Search)
CREATE VIRTUAL TABLE memories_local_fts USING fts5(
    content,
    content='memories_local',
    content_rowid='rowid'
);

-- Triggers for FTS sync
CREATE TRIGGER memories_local_ai AFTER INSERT ON memories_local BEGIN
    INSERT INTO memories_local_fts(rowid, content) VALUES (new.rowid, new.content);
END;

CREATE TRIGGER memories_local_ad AFTER DELETE ON memories_local BEGIN
    DELETE FROM memories_local_fts WHERE rowid = old.rowid;
END;

CREATE TRIGGER memories_local_au AFTER UPDATE ON memories_local BEGIN
    UPDATE memories_local_fts SET content = new.content WHERE rowid = new.rowid;
END;

-- ============================================
-- Local Cache Table
-- ============================================
CREATE TABLE memory_cache (
    cloud_memory_id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding BLOB,
    scope TEXT NOT NULL,
    cached_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    access_count INTEGER DEFAULT 0,
    last_accessed_at TEXT
);

CREATE INDEX idx_memory_cache_expires ON memory_cache(expires_at);
```

---

## 3. API仕様

### 3.1 メモリ作成API

**Endpoint**: `POST /api/v1/memories`

**Request**:
```json
{
  "content": "React Query v5の最適化パターン: useQueryでstaleTime設定",
  "metadata": {
    "tags": ["react", "performance", "caching"],
    "source": "artemis-optimizer",
    "project_id": "abc-123"
  },
  "importance": 0.8,
  "scope_hint": "GLOBAL",  // Optional user hint
  "force_scope": false  // If true, skip auto-classification
}
```

**Response** (Success):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "GLOBAL",
  "storage_location": "cloud",
  "classification_details": {
    "auto_classified": true,
    "detected_sensitive": false,
    "knowledge_type": "universal",
    "project_specific": false
  },
  "created_at": "2025-01-06T10:30:00Z"
}
```

**Response** (Security Override):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "scope": "PRIVATE",
  "storage_location": "local",
  "classification_details": {
    "auto_classified": true,
    "user_hint": "GLOBAL",
    "detected_sensitive": true,
    "sensitive_types": ["API_KEY", "PASSWORD"],
    "override_reason": "Security: Sensitive data detected, forced to PRIVATE"
  },
  "warning": "Sensitive data detected. Memory stored locally only.",
  "created_at": "2025-01-06T10:30:00Z"
}
```

### 3.2 ハイブリッド検索API

**Endpoint**: `POST /api/v1/memories/search`

**Request**:
```json
{
  "query": "データベース最適化の方法",
  "limit": 10,
  "min_similarity": 0.7,
  "scopes": ["GLOBAL", "PROJECT"],  // Optional filter
  "search_strategy": "hybrid"  // local_first, cloud_first, or hybrid
}
```

**Response**:
```json
{
  "results": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "content": "インデックス追加により応答時間90%改善",
      "scope": "GLOBAL",
      "storage_location": "cloud",
      "similarity": 0.92,
      "metadata": {
        "tags": ["database", "optimization", "performance"],
        "source": "artemis-optimizer"
      }
    },
    {
      "id": "local-123",
      "content": "プロジェクトXのDB最適化: users テーブルに複合インデックス",
      "scope": "PROJECT",
      "storage_location": "local",
      "similarity": 0.85,
      "metadata": {
        "tags": ["project-x", "database"],
        "project_id": "project-x"
      }
    }
  ],
  "search_metadata": {
    "total_results": 2,
    "cloud_results": 1,
    "local_results": 1,
    "search_time_ms": 245
  }
}
```

### 3.3 同期ステータスAPI（Phase 3）

**Endpoint**: `GET /api/v1/sync/status`

**Response**:
```json
{
  "sync_enabled": true,
  "last_sync": "2025-01-06T10:25:00Z",
  "pending_events": 3,
  "sync_health": "healthy",
  "cloud_connection": "connected",
  "offline_mode": false,
  "stats": {
    "total_synced_today": 150,
    "sync_success_rate": 0.998,
    "avg_sync_time_ms": 120
  }
}
```

**Endpoint**: `POST /api/v1/sync/trigger`

**Request**:
```json
{
  "sync_type": "full",  // full or incremental
  "scopes": ["GLOBAL", "SHARED"]
}
```

---

## 4. モジュール構成

### 4.1 ディレクトリ構造

```
src/
├── core/
│   ├── memory_scope.py           # ✅ Scope definitions
│   ├── database_router.py        # ✅ Multi-DB routing
│   ├── config.py                 # ✅ Configuration (updated)
│   └── exceptions.py             # Error handling
│
├── services/
│   ├── scope_classifier.py       # ✅ Auto-classification
│   ├── memory_service.py         # Memory CRUD operations
│   ├── sync_engine.py            # 🔄 Sync mechanism (Phase 3)
│   ├── encryption_service.py     # 🔒 E2EE service (Phase 4)
│   └── cache_manager.py          # Cache optimization
│
├── models/
│   ├── memory_cloud.py           # Cloud memory model
│   ├── memory_local.py           # Local memory model
│   └── sync_event.py             # Sync event model
│
├── api/
│   ├── routes_memory.py          # Memory endpoints
│   ├── routes_sync.py            # Sync endpoints (Phase 3)
│   └── dependencies_hybrid.py    # Hybrid DB dependencies
│
├── security/
│   ├── e2ee.py                   # E2EE implementation (Phase 4)
│   ├── rls_manager.py            # RLS policy management
│   └── audit_logger.py           # Security audit logging
│
└── utils/
    ├── vector_utils.py           # Vector operations
    └── migration_helpers.py      # Schema migration utils
```

### 4.2 主要クラス図

```
┌─────────────────────┐
│  DatabaseRouter     │
├─────────────────────┤
│ +get_session()      │
│ +get_cloud_engine() │
│ +get_local_engine() │
└──────────┬──────────┘
           │ uses
           ▼
┌─────────────────────┐
│  MemoryScope (Enum) │
├─────────────────────┤
│ GLOBAL              │
│ SHARED              │
│ PROJECT             │
│ PRIVATE             │
└─────────────────────┘
           ▲
           │ classifies
┌──────────┴──────────┐
│  ScopeClassifier    │
├─────────────────────┤
│ +classify()         │
│ +validate_safety()  │
│ -detect_sensitive() │
└─────────────────────┘
           │ uses
           ▼
┌─────────────────────┐
│ SensitiveDetector   │
├─────────────────────┤
│ PATTERNS[]          │
│ +detect()           │
└─────────────────────┘
```

---

## 5. 実装優先順位

### Priority 1: 即座実装（Week 1-2）
- [x] MemoryScope enum
- [x] DatabaseRouter
- [x] ScopeClassifier
- [ ] Cloud/Local Memory models
- [ ] Basic CRUD APIs

### Priority 2: Phase 3（Week 3-9）
- [ ] SyncEngine
- [ ] ConflictResolver
- [ ] OfflineManager
- [ ] Write-Ahead Log

### Priority 3: Phase 4（Week 10-12）
- [ ] E2EEManager
- [ ] RLS policies implementation
- [ ] Certificate pinning
- [ ] KMS integration

### Priority 4: 最適化（Week 13+）
- [ ] CacheManager optimization
- [ ] ML classifier training
- [ ] Performance monitoring
- [ ] Cost optimization

---

## 6. 依存パッケージ

### 6.1 Python Dependencies

```toml
# pyproject.toml

[project.dependencies]
# Existing
fastapi = "^0.104.0"
sqlalchemy = "^2.0.23"
asyncpg = "^0.29.0"  # PostgreSQL async driver
aiosqlite = "^0.19.0"  # SQLite async driver
pgvector = "^0.2.3"  # PostgreSQL vector extension

# New for hybrid architecture
cryptography = "^41.0.7"  # E2EE encryption
pydantic = "^2.5.0"  # Already in use
redis = "^5.0.1"  # Caching (optional)

# Sync & conflict resolution
python-dateutil = "^2.8.2"
pytz = "^2023.3"

[project.optional-dependencies]
# Vector support for SQLite
sqlite-vec = ["sqlite-vec>=0.0.1"]

# Cloud providers
supabase = ["supabase>=2.0.0"]  # If using Supabase
```

### 6.2 システム要件

- Python 3.11+
- PostgreSQL 15+ with pgvector extension (クラウド)
- SQLite 3.35+ (ローカル)
- Redis 6+ (オプション: キャッシング)

---

## 7. エラーハンドリング

### 7.1 カスタム例外

```python
# src/core/exceptions.py

class HybridMemoryException(TMWSException):
    """Base exception for hybrid memory operations."""
    pass

class ScopeClassificationError(HybridMemoryException):
    """Scope classification failed."""
    pass

class SensitiveDataViolation(HybridMemoryException):
    """Attempted to store sensitive data in cloud."""
    pass

class SyncConflictError(HybridMemoryException):
    """Sync conflict detected."""
    def __init__(self, local_version, cloud_version):
        self.local_version = local_version
        self.cloud_version = cloud_version
        super().__init__("Sync conflict requires resolution")

class CloudConnectionError(HybridMemoryException):
    """Cannot connect to cloud database."""
    pass
```

### 7.2 エラーレスポンス

```json
{
  "error": {
    "code": "SENSITIVE_DATA_VIOLATION",
    "message": "Cannot store sensitive data in cloud scope",
    "details": {
      "detected_types": ["PASSWORD", "API_KEY"],
      "suggested_scope": "PRIVATE"
    },
    "timestamp": "2025-01-06T10:30:00Z"
  }
}
```

---

**承認**:
- **技術リード**: Artemis
- **セキュリティ**: Hestia
- **文書化**: Muses

**バージョン**: 1.0
**作成日**: 2025-01-06
