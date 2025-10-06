# TMWS ハイブリッドクラウド テスト仕様書 v1.0

## 1. テスト戦略

### 1.1 テストピラミッド

```
        /\
       /  \  E2Eテスト (5%)
      /────\
     /      \ 統合テスト (25%)
    /────────\
   /          \ 単体テスト (70%)
  /────────────\
```

### 1.2 テストレベル

| レベル | カバレッジ目標 | 実行頻度 | 実行時間目標 |
|-------|--------------|---------|-----------|
| Unit Tests | 85%以上 | 各コミット | < 30秒 |
| Integration Tests | 70%以上 | 各PR | < 5分 |
| E2E Tests | 主要フロー100% | 毎日 | < 15分 |
| Security Tests | 100% | 各PR | < 10分 |
| Performance Tests | - | 週次 | < 30分 |

---

## 2. 単体テスト仕様

### 2.1 ScopeClassifier テスト

**ファイル**: `tests/unit/test_scope_classifier.py`

#### Test Suite: 機密情報検出

```python
class TestSensitiveDetection:
    """Test sensitive data detection patterns."""

    @pytest.mark.parametrize("content,expected_types", [
        ("password: secret123", ["PASSWORD"]),
        ("api_key = sk-abc123xyz", ["API_KEY"]),
        ("Bearer eyJhbGci...", ["BEARER_TOKEN"]),
        ("-----BEGIN PRIVATE KEY-----", ["PEM_KEY"]),
        ("user@example.com", ["EMAIL"]),
        ("+1-555-1234", ["PHONE"]),
        ("123-45-6789", ["SSN"]),
        ("1234567812345678", ["CREDIT_CARD"]),
        ("postgresql://user:pass@host/db", ["DB_CREDENTIALS"]),
        ("AKIA1234567890ABCDEF", ["AWS_ACCESS_KEY"]),
    ])
    def test_detect_sensitive_patterns(self, content, expected_types):
        """Should detect all sensitive data patterns."""
        detector = SensitiveDataDetector()
        has_sensitive, detected_types = detector.detect(content)

        assert has_sensitive is True
        assert all(t in detected_types for t in expected_types)

    def test_no_false_positives(self):
        """Should not flag normal content as sensitive."""
        detector = SensitiveDataDetector()
        normal_contents = [
            "React Query optimization pattern",
            "Database indexing best practices",
            "Here is how to implement caching"
        ]

        for content in normal_contents:
            has_sensitive, _ = detector.detect(content)
            assert has_sensitive is False

    def test_combined_sensitive_data(self):
        """Should detect multiple sensitive types."""
        content = """
        Database config:
        password: secret123
        api_key: sk-abc123
        email: admin@example.com
        """
        detector = SensitiveDataDetector()
        has_sensitive, types = detector.detect(content)

        assert has_sensitive is True
        assert "PASSWORD" in types
        assert "API_KEY" in types
        assert "EMAIL" in types
```

#### Test Suite: スコープ分類

```python
class TestScopeClassification:
    """Test scope classification logic."""

    def test_private_scope_for_sensitive_data(self):
        """Sensitive data must be classified as PRIVATE."""
        classifier = ScopeClassifier()
        content = "database password: secret123"

        scope, details = classifier.classify(content)

        assert scope == MemoryScope.PRIVATE
        assert details["detected_sensitive"] is True
        assert "PASSWORD" in details["sensitive_types"]

    def test_project_scope_for_code(self):
        """Code snippets should be PROJECT scope."""
        classifier = ScopeClassifier()
        content = """
        def calculate_total(items):
            return sum(item.price for item in items)
        """

        scope, details = classifier.classify(content)

        assert scope == MemoryScope.PROJECT
        assert details["project_specific"] is True

    def test_global_scope_for_best_practices(self):
        """Best practices should be GLOBAL scope."""
        classifier = ScopeClassifier()
        content = "Best practice: Always use parameterized queries to prevent SQL injection"

        scope, details = classifier.classify(content)

        assert scope == MemoryScope.GLOBAL
        assert details["knowledge_type"] == "universal"

    def test_shared_scope_for_team_guidelines(self):
        """Team guidelines should be SHARED scope."""
        classifier = ScopeClassifier()
        content = "Our team's coding standard: Use 2 spaces for indentation"

        scope, details = classifier.classify(content)

        assert scope == MemoryScope.SHARED
        assert details["knowledge_type"] == "team"

    def test_user_override_validation(self):
        """User can override but sensitive data blocks cloud."""
        classifier = ScopeClassifier()
        content = "api_key: sk-123456"

        # User wants GLOBAL but has sensitive data
        scope, details = classifier.classify(
            content,
            user_hint=MemoryScope.GLOBAL
        )

        # Should be forced to PRIVATE
        assert scope == MemoryScope.PRIVATE
        assert details["user_hint"] == "GLOBAL"

        # Validate safety check
        is_safe = classifier.validate_scope_safety(MemoryScope.GLOBAL, content)
        assert is_safe is False
```

### 2.2 DatabaseRouter テスト

**ファイル**: `tests/unit/test_database_router.py`

```python
class TestDatabaseRouter:
    """Test multi-database routing logic."""

    @pytest.mark.asyncio
    async def test_cloud_routing_for_global_scope(self):
        """GLOBAL scope should route to cloud database."""
        router = DatabaseRouter()

        async with router.get_session(scope=MemoryScope.GLOBAL) as session:
            # Verify it's a cloud session
            assert "postgresql" in str(session.bind.url)

    @pytest.mark.asyncio
    async def test_local_routing_for_private_scope(self):
        """PRIVATE scope should route to local database."""
        router = DatabaseRouter()

        async with router.get_session(scope=MemoryScope.PRIVATE) as session:
            # Verify it's a local session
            assert "sqlite" in str(session.bind.url)

    @pytest.mark.asyncio
    async def test_fallback_to_local_on_cloud_failure(self, monkeypatch):
        """Should fallback to local if cloud unavailable."""
        router = DatabaseRouter()

        # Simulate cloud failure
        def mock_cloud_engine():
            raise CloudConnectionError("Cloud DB unreachable")

        monkeypatch.setattr(router, "get_cloud_engine", mock_cloud_engine)

        # Should fallback to local
        async with router.get_session(scope=MemoryScope.GLOBAL) as session:
            assert "sqlite" in str(session.bind.url)

    @pytest.mark.asyncio
    async def test_multi_session_for_sync(self):
        """Multi-session should provide both cloud and local."""
        router = DatabaseRouter()

        async with router.get_multi_session() as (cloud, local):
            assert "postgresql" in str(cloud.bind.url)
            assert "sqlite" in str(local.bind.url)
```

---

## 3. 統合テスト仕様

### 3.1 ハイブリッドメモリ統合テスト

**ファイル**: `tests/integration/test_hybrid_memory.py`

```python
class TestHybridMemoryIntegration:
    """Test end-to-end hybrid memory operations."""

    @pytest.mark.asyncio
    async def test_create_global_memory_in_cloud(self, db_session):
        """GLOBAL memory should be stored in cloud."""
        memory_service = MemoryService()

        memory = await memory_service.create_memory(
            content="React Query caching best practices",
            scope=MemoryScope.GLOBAL,
            metadata={"tags": ["react", "caching"]}
        )

        # Verify cloud storage
        cloud_memory = await memory_service.get_from_cloud(memory.id)
        assert cloud_memory is not None
        assert cloud_memory.scope == MemoryScope.GLOBAL

        # Verify NOT in local
        local_memory = await memory_service.get_from_local(memory.id)
        assert local_memory is None

    @pytest.mark.asyncio
    async def test_create_private_memory_local_only(self, db_session):
        """PRIVATE memory should never reach cloud."""
        memory_service = MemoryService()

        memory = await memory_service.create_memory(
            content="Production API key: sk-prod-12345",
            metadata={"tags": ["credentials"]}
        )

        # Should be auto-classified as PRIVATE
        assert memory.scope == MemoryScope.PRIVATE

        # Verify local storage
        local_memory = await memory_service.get_from_local(memory.id)
        assert local_memory is not None

        # Verify NOT in cloud
        cloud_memory = await memory_service.get_from_cloud(memory.id)
        assert cloud_memory is None

    @pytest.mark.asyncio
    async def test_hybrid_search(self, db_session):
        """Hybrid search should query both cloud and local."""
        memory_service = MemoryService()

        # Create GLOBAL memory (cloud)
        await memory_service.create_memory(
            content="Universal optimization: Add database indexes",
            scope=MemoryScope.GLOBAL
        )

        # Create PROJECT memory (local)
        await memory_service.create_memory(
            content="Project-X optimization: Add index on users.email",
            scope=MemoryScope.PROJECT
        )

        # Hybrid search
        results = await memory_service.hybrid_search(
            query="database optimization",
            scopes=[MemoryScope.GLOBAL, MemoryScope.PROJECT]
        )

        assert len(results) == 2
        scopes = {r.scope for r in results}
        assert MemoryScope.GLOBAL in scopes
        assert MemoryScope.PROJECT in scopes
```

### 3.2 同期テスト（Phase 3）

**ファイル**: `tests/integration/test_sync_engine.py`

```python
class TestSyncEngine:
    """Test synchronization between cloud and local."""

    @pytest.mark.asyncio
    async def test_sync_local_to_cloud(self):
        """Local GLOBAL memory should sync to cloud."""
        sync_engine = SyncEngine()

        # Create GLOBAL memory locally (offline scenario)
        local_memory = await create_local_memory(
            content="New best practice discovered",
            scope=MemoryScope.GLOBAL
        )

        # Trigger sync
        await sync_engine.sync_to_cloud(local_memory)

        # Verify in cloud
        cloud_memory = await get_cloud_memory(local_memory.id)
        assert cloud_memory is not None
        assert cloud_memory.content == local_memory.content

    @pytest.mark.asyncio
    async def test_conflict_resolution_last_write_wins(self):
        """Conflicts should resolve with Last-Write-Wins."""
        sync_engine = SyncEngine()
        resolver = ConflictResolver()

        # Create conflicting versions
        local_version = Memory(
            id=uuid4(),
            content="Local version",
            updated_at=datetime(2025, 1, 6, 10, 0, 0)
        )

        cloud_version = Memory(
            id=local_version.id,
            content="Cloud version",
            updated_at=datetime(2025, 1, 6, 10, 5, 0)  # 5 min later
        )

        # Resolve conflict
        winner = await resolver.resolve_conflict(local_version, cloud_version)

        # Cloud version should win (later timestamp)
        assert winner.content == "Cloud version"
        assert winner.updated_at == cloud_version.updated_at

    @pytest.mark.asyncio
    async def test_offline_mode_queues_sync_events(self):
        """Offline mode should queue sync events."""
        sync_engine = SyncEngine()

        # Enable offline mode
        await sync_engine.enable_offline_mode()

        # Create memories (should be queued)
        memory1 = await create_memory(scope=MemoryScope.GLOBAL)
        memory2 = await create_memory(scope=MemoryScope.SHARED)

        # Check queue
        pending = await sync_engine.get_pending_events()
        assert len(pending) == 2

        # Go online and sync
        await sync_engine.disable_offline_mode()
        await sync_engine.sync_pending_events()

        # Queue should be empty
        pending = await sync_engine.get_pending_events()
        assert len(pending) == 0
```

---

## 4. セキュリティテスト仕様

### 4.1 機密情報保護テスト

**ファイル**: `tests/security/test_sensitive_protection.py`

```python
class TestSensitiveDataProtection:
    """Test that sensitive data is always protected."""

    @pytest.mark.parametrize("sensitive_content", [
        "password: secret123",
        "api_key: sk-abc123",
        "Bearer token: eyJhbGci...",
        "email: user@company.com and password: pass123"
    ])
    @pytest.mark.asyncio
    async def test_sensitive_never_reaches_cloud(self, sensitive_content):
        """Sensitive data must never be stored in cloud."""
        memory_service = MemoryService()

        # Attempt to create with GLOBAL hint
        memory = await memory_service.create_memory(
            content=sensitive_content,
            scope_hint=MemoryScope.GLOBAL  # User wants cloud
        )

        # Should be forced to PRIVATE
        assert memory.scope == MemoryScope.PRIVATE

        # Verify NOT in cloud
        cloud_check = await memory_service.get_from_cloud(memory.id)
        assert cloud_check is None

        # Verify in local
        local_check = await memory_service.get_from_local(memory.id)
        assert local_check is not None

    @pytest.mark.asyncio
    async def test_security_audit_log_for_violations(self):
        """Security violations should be logged."""
        memory_service = MemoryService()
        audit_logger = SecurityAuditLogger()

        # Attempt unsafe operation
        with pytest.raises(SensitiveDataViolation):
            await memory_service.force_create_cloud_memory(
                content="password: secret",
                scope=MemoryScope.GLOBAL
            )

        # Check audit log
        logs = await audit_logger.get_recent_logs(limit=1)
        assert len(logs) == 1
        assert logs[0].event_type == "SECURITY_VIOLATION"
        assert "SENSITIVE_DATA" in logs[0].details
```

### 4.2 E2EE暗号化テスト（Phase 4）

**ファイル**: `tests/security/test_e2ee.py`

```python
class TestEndToEndEncryption:
    """Test E2EE for SHARED scope."""

    @pytest.mark.asyncio
    async def test_shared_memory_encrypted_at_rest(self):
        """SHARED memories should be encrypted in cloud."""
        e2ee_manager = E2EEManager()
        memory_service = MemoryService()

        # Create SHARED memory
        plaintext = "Team secret: Our deployment process"
        memory = await memory_service.create_memory(
            content=plaintext,
            scope=MemoryScope.SHARED,
            team_id=uuid4()
        )

        # Fetch from cloud (should be encrypted)
        cloud_memory = await get_raw_cloud_memory(memory.id)
        assert cloud_memory.encrypted_content is not None
        assert cloud_memory.content != plaintext  # Not plaintext

        # Decrypt and verify
        decrypted = await e2ee_manager.decrypt_for_team(
            cloud_memory.encrypted_content,
            team_id=memory.team_id
        )
        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_e2ee_key_rotation(self):
        """Key rotation should not break existing memories."""
        e2ee_manager = E2EEManager()
        team_id = uuid4()

        # Create memory with key v1
        memory = await create_shared_memory("Secret data", team_id)

        # Rotate team key
        await e2ee_manager.rotate_team_key(team_id)

        # Should still decrypt with old key
        decrypted = await e2ee_manager.decrypt_for_team(
            memory.encrypted_content,
            team_id=team_id
        )
        assert decrypted == "Secret data"
```

---

## 5. パフォーマンステスト仕様

### 5.1 レスポンスタイム

**ファイル**: `tests/performance/test_response_time.py`

```python
@pytest.mark.performance
class TestResponseTime:
    """Test API response time requirements."""

    @pytest.mark.asyncio
    async def test_memory_creation_under_200ms(self, benchmark):
        """Memory creation should complete in < 200ms."""
        memory_service = MemoryService()

        async def create():
            return await memory_service.create_memory(
                content="Test memory",
                scope=MemoryScope.PROJECT
            )

        # Benchmark
        result = await benchmark(create)
        assert benchmark.stats.mean < 0.2  # 200ms

    @pytest.mark.asyncio
    async def test_hybrid_search_under_500ms(self, benchmark):
        """Hybrid search should complete in < 500ms."""
        memory_service = MemoryService()

        async def search():
            return await memory_service.hybrid_search(
                query="optimization patterns",
                limit=10
            )

        result = await benchmark(search)
        assert benchmark.stats.mean < 0.5  # 500ms
```

### 5.2 スケーラビリティ

```python
@pytest.mark.performance
class TestScalability:
    """Test system scalability."""

    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """System should handle 100 concurrent requests."""
        memory_service = MemoryService()

        async def create_memory(i):
            return await memory_service.create_memory(
                content=f"Memory {i}",
                scope=MemoryScope.GLOBAL
            )

        # 100 concurrent requests
        tasks = [create_memory(i) for i in range(100)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should succeed
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(errors) == 0
```

---

## 6. テスト実行コマンド

### 6.1 ローカル開発

```bash
# 全テスト実行
pytest tests/ -v

# 単体テストのみ
pytest tests/unit/ -v --cov=src --cov-report=term-missing

# 統合テストのみ
pytest tests/integration/ -v

# セキュリティテストのみ
pytest tests/security/ -v -m security

# パフォーマンステスト（スキップ推奨）
pytest tests/performance/ -v -m performance
```

### 6.2 CI/CD

```yaml
# .github/workflows/test-suite.yml

- name: Run Unit Tests
  run: pytest tests/unit/ -v --cov=src --cov-report=xml

- name: Run Integration Tests
  run: pytest tests/integration/ -v

- name: Run Security Tests
  run: pytest tests/security/ -v

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

---

## 7. テストカバレッジ目標

| モジュール | 目標カバレッジ | 現状 | 優先度 |
|----------|--------------|------|--------|
| scope_classifier.py | 90% | ✅ 92% | P0 |
| database_router.py | 85% | ✅ 88% | P0 |
| memory_service.py | 85% | 🔄 60% | P1 |
| sync_engine.py | 80% | ❌ 0% | P2 |
| e2ee.py | 95% | ❌ 0% | P2 |

---

**承認**:
- **QA Lead**: Hestia
- **Technical**: Artemis
- **Documentation**: Muses

**バージョン**: 1.0
**作成日**: 2025-01-06
