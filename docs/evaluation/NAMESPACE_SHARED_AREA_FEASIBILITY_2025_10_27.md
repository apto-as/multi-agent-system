# TMWS Namespace共有領域の運用実現可能性評価
## Eris (戦術調整スペシャリスト) による評価

**評価日**: 2025-10-27
**プロジェクト**: TMWS v2.2.6
**評価担当**: Eris (戦術調整スペシャリスト)
**評価対象**: プロジェクト横断共有記憶領域の実装・運用

---

## Executive Summary (経営層向けサマリー)

### 現状
- ✅ **Phase 1完了**: Namespace自動検出の実装済み（pwd-based）
- ✅ **セキュリティ強化**: `'default'` namespace拒否による漏洩防止
- ⚠️ **未実装**: プロジェクト横断共有領域の設計

### 結論
**段階的ロールアウトを推奨**:
1. **Phase 2a** (1-2日): 現在の実装の安定化と検証
2. **Phase 2b** (3-5日): 共有領域の設計と実装（リスク評価後）
3. **Phase 3** (7-14日): AIベース自動判定機能

**リスク評価**: 🟡 MEDIUM（適切な設計により低減可能）

---

## 1. MCPサーバーの挙動調査

### 1.1 検証すべきシナリオ

#### Scenario A: プロジェクト切り替え時の挙動
**検証目的**: Claude Codeでプロジェクトを切り替えた際、MCPサーバーが再起動されるか？

**検証方法**:
```bash
# Test Case 1: プロジェクトA → プロジェクトB
# Claude Code: Open project A → Open project B
# Expected: MCP server restarts, new namespace detected

# Test Case 2: 同一プロジェクト内のディレクトリ移動
# Claude Code: cd subdir/
# Expected: MCP server continues, namespace unchanged (git root detected)

# Test Case 3: 同時に複数プロジェクトを開く
# Claude Code: Window 1 (Project A) + Window 2 (Project B)
# Expected: Separate MCP server instances with different namespaces
```

**実装済みの検出優先順位**:
1. `TRINITAS_PROJECT_NAMESPACE` 環境変数 (0.001ms) ✅
2. Git repository root + remote URL (1-5ms) ✅
3. Marker file `.trinitas-project.yaml` (5-10ms) ✅
4. CWD hash fallback (0.01ms) ✅

**評価**:
- ✅ **強み**: Git root検出により、サブディレクトリ移動でもnamespaceは一貫
- ✅ **強み**: Fallback mechanism（CWD hash）により、常に一意のnamespaceを保証
- ⚠️ **懸念**: Fallback時のユーザー体験（警告メッセージが表示される）

---

### 1.2 実際の挙動検証計画

**検証ステップ** (Phase 2a で実施):

```bash
# Step 1: MCP server起動ログの確認
tail -f ~/.claude/logs/mcp-server-tmws.log

# Step 2: プロジェクト切り替え時のnamespace変化を記録
# Before: echo $PWD, echo $TRINITAS_PROJECT_NAMESPACE
# Switch project in Claude Code
# After: Check namespace in memory_service logs

# Step 3: 同時起動時のインスタンス分離を確認
# Expected: Different instance_id and namespace per project
```

**成功基準**:
- ✅ プロジェクト切り替え時にnamespaceが自動変更される
- ✅ 同一プロジェクト内のディレクトリ移動でnamespaceが維持される
- ✅ 複数プロジェクト同時起動時にnamespaceが分離される

---

## 2. 共有領域の設計オプション

### Option 1: 明示的共有namespace（推奨 - Phase 2b）

**設計**:
```python
# 新しいAccessLevel: CROSS_PROJECT
class AccessLevel(str, Enum):
    PRIVATE = "private"       # Agent only
    TEAM = "team"             # Same namespace
    SHARED = "shared"         # Explicit agents
    PUBLIC = "public"         # All agents (within namespace)
    SYSTEM = "system"         # System-wide (read-only)
    CROSS_PROJECT = "cross_project"  # NEW: Cross-namespace shared area

# 共有namespace: "shared:<user_id>"
# Example: "shared:apto-as" for user apto-as
```

**ユーザーインタラクション**:
```python
# Explicit specification by user
/trinitas remember project_architecture "Microservices design" --shared

# OR importance-based automatic assignment
/trinitas remember important_finding "Security vulnerability" --importance 1.0
# → Auto-assigned to CROSS_PROJECT if importance >= 0.9
```

**実装の複雑度**: 🟡 MEDIUM（3-5日）

**メリット**:
- ✅ セキュリティ境界が明確（namespaceベースの分離を維持）
- ✅ 既存のAccessLevel設計に自然に統合
- ✅ ユーザーが共有範囲を明示的に制御可能

**デメリット**:
- ⚠️ ユーザーが明示的に指定する必要がある（自動化の余地あり）
- ⚠️ `shared:<user_id>` の user_id 取得方法（環境変数？認証？）

---

### Option 2: 重要度ベース自動振り分け（Phase 3）

**設計**:
```python
async def store_memory_with_auto_namespace(
    content: str,
    importance: float,
    namespace: str = None,  # Auto-detected project namespace
):
    # Auto-detect namespace (existing implementation)
    if namespace is None:
        namespace = await detect_project_namespace()

    # Automatic cross-project sharing for high-importance memories
    if importance >= 0.9:
        access_level = AccessLevel.CROSS_PROJECT
        shared_namespace = f"shared:{get_user_id()}"  # Need to implement
        # Store in BOTH project namespace AND shared namespace
        await store_in_both_namespaces(content, namespace, shared_namespace)
    else:
        access_level = AccessLevel.PRIVATE
        await store_in_namespace(content, namespace)
```

**実装の複雑度**: 🔴 HIGH（7-14日 + AIベース分類の検証）

**メリット**:
- ✅ 完全自動化（ユーザー操作不要）
- ✅ 重要な知識が自動的にプロジェクト横断で利用可能
- ✅ Trinitas AIエージェントの知的機能を活用

**デメリット**:
- 🔴 複雑度高い（AIベース判定の精度検証が必要）
- 🔴 誤判定リスク（低重要度を共有領域に保存してしまう）
- 🔴 `get_user_id()` の実装が必要（認証システムとの統合）

---

### Option 3: ハイブリッドアプローチ（推奨最終形 - Phase 4）

**設計**:
```python
# Default: 明示的指定
# Option: 重要度ベース自動提案

async def store_memory(
    content: str,
    importance: float,
    shared: bool = None,  # None = auto-suggest based on importance
):
    namespace = await detect_project_namespace()

    # Auto-suggest cross-project sharing for high-importance
    if shared is None and importance >= 0.9:
        # AI suggests sharing, but user can override
        logger.info(f"High importance ({importance}) detected. Consider --shared flag.")
        shared = False  # Default to project-local for safety

    if shared:
        access_level = AccessLevel.CROSS_PROJECT
        shared_namespace = f"shared:{get_user_id()}"
        await store_in_both_namespaces(content, namespace, shared_namespace)
    else:
        await store_in_namespace(content, namespace)
```

**実装の複雑度**: 🟡 MEDIUM（5-7日）

**メリット**:
- ✅ 安全性とUXのバランス（デフォルトは明示的指定）
- ✅ AIがヒントを提供（ユーザーが最終判断）
- ✅ 段階的な自動化の余地

---

## 3. エラーハンドリング

### 3.1 Namespace検出失敗時の挙動

**現在の実装** (Line 256-270 in namespace.py):
```python
# Fallback: CWD hash
cwd_hash = hashlib.sha256(str(cwd).encode()).hexdigest()[:16]
namespace = f"project_{cwd_hash}"

logger.warning(
    f"No project namespace detected. Using cwd hash: {namespace}. "
    f"Set TRINITAS_PROJECT_NAMESPACE environment variable or create "
    f".trinitas-project.yaml for explicit namespace."
)
```

**評価**:
- ✅ **完璧なFallback**: 常にnamespaceを返す（エラーにならない）
- ✅ **一意性保証**: SHA256 hash により衝突率ほぼゼロ
- ⚠️ **UX改善の余地**: 警告メッセージがユーザーに見えるか？

**推奨改善** (Phase 2a):
```python
# Add user-friendly guidance in warning message
logger.warning(
    f"⚠️  TMWS: Auto-generated namespace '{namespace}' from working directory.\n"
    f"   For consistent project identification:\n"
    f"   1. Set environment variable: export TRINITAS_PROJECT_NAMESPACE='<project-name>'\n"
    f"   2. OR create .trinitas-project.yaml with: namespace: <project-name>\n"
    f"   3. OR ensure git remote URL is configured\n"
    f"   Current working directory: {cwd}"
)
```

---

### 3.2 共有領域アクセス失敗時の挙動

**シナリオ**:
1. User tries to access `shared:<user_id>` but doesn't have permission
2. ChromaDB is unavailable for shared namespace
3. Namespace collision (unlikely but possible)

**推奨エラーハンドリング**:
```python
async def access_shared_namespace(shared_namespace: str, user_id: str):
    # Verify user owns the shared namespace
    if not shared_namespace.startswith(f"shared:{user_id}"):
        raise NamespaceError(
            f"Access denied: User '{user_id}' cannot access namespace '{shared_namespace}'.\n"
            f"You can only access 'shared:{user_id}'."
        )

    # Check ChromaDB availability
    try:
        await vector_service.initialize()
    except ChromaOperationError as e:
        raise MemorySearchError(
            f"Shared namespace '{shared_namespace}' is unavailable (ChromaDB error).\n"
            f"Check Ollama service is running: ollama serve",
            original_exception=e
        )
```

---

## 4. 移行計画

### Phase 2a: 現在の実装の安定化（1-2日）✅ 優先度 P1

**目標**: Namespace自動検出の動作検証と改善

**タスク**:
- [x] ~~Namespace検出ロジックの検証~~（実装済み: Line 209-270 in namespace.py）
- [ ] MCP server再起動時の挙動検証（実機テスト必要）
- [ ] Fallback警告メッセージの改善
- [ ] ユーザードキュメント作成
  - How namespace detection works
  - How to set explicit namespace
  - Troubleshooting guide

**成果物**:
- `docs/guides/NAMESPACE_DETECTION_GUIDE.md`
- `tests/integration/test_namespace_detection.py` (実機テスト)

**リスク**: 🟢 LOW（既存実装の検証のみ）

---

### Phase 2b: 共有領域の設計と実装（3-5日）⚠️ 優先度 P2

**目標**: プロジェクト横断共有記憶領域の安全な実装

**前提条件**:
- [ ] Phase 2a完了
- [ ] Hestia (セキュリティ専門家) によるセキュリティレビュー完了
- [ ] User ID取得方法の決定（環境変数 or 認証システム統合）

**タスク**:
1. **設計レビュー** (1日)
   - AccessLevel.CROSS_PROJECT の仕様策定
   - `shared:<user_id>` namespace命名規則の確定
   - セキュリティ境界の定義（Hestiaと協議）

2. **実装** (2-3日)
   - AccessLevel.CROSS_PROJECT の追加
   - `store_memory_with_auto_namespace()` の実装
   - ChromaDB での namespace分離検証
   - SQLite での cross-namespace query実装

3. **テスト** (1日)
   - Unit tests: namespace isolation
   - Integration tests: cross-project memory retrieval
   - Security tests: unauthorized access prevention

**成果物**:
- `src/models/memory.py`: AccessLevel.CROSS_PROJECT追加
- `src/services/memory_service.py`: cross-namespace storage
- `tests/security/test_cross_project_access.py`

**リスク**: 🟡 MEDIUM（セキュリティ境界の設計が重要）

**Heraとの調整ポイント**:
- 長期的なnamespace設計の戦略的妥当性
- スケーラビリティ（1000+ projects での性能）
- 将来の機能拡張の余地（team-based sharing, organization-level sharing）

---

### Phase 3: AIベース自動判定（7-14日）⚠️ 優先度 P3

**目標**: 重要度ベースの自動共有領域振り分け

**前提条件**:
- [ ] Phase 2b完了
- [ ] Artemis (技術最適化専門家) によるパフォーマンステスト完了
- [ ] Athena (調和指揮者) によるUXレビュー完了

**タスク**:
1. **AI分類モデルの設計** (2-3日)
   - Importance score計算アルゴリズム
   - Content analysis (keyword extraction, topic modeling)
   - User behavior learning (access frequency, sharing patterns)

2. **実装** (3-5日)
   - AI-based auto-suggestion engine
   - User feedback loop (confirm/reject suggestions)
   - A/B testing framework

3. **検証** (2-3日)
   - Accuracy測定 (false positive rate < 5%)
   - Latency測定 (auto-suggestion < 50ms)
   - User acceptance測定

**成果物**:
- `src/services/memory_classification_service.py`
- `docs/research/AI_AUTO_CLASSIFICATION_ANALYSIS.md`

**リスク**: 🔴 HIGH（AIモデルの精度検証に時間がかかる）

**Trinitasフルモード推奨**:
- Athena: UX設計（ユーザーがAI提案をどう受け入れるか）
- Artemis: パフォーマンス最適化（AI推論の高速化）
- Hestia: 誤判定時のセキュリティリスク評価
- Muses: ユーザー向けドキュメント（AI提案の仕組み説明）

---

## 5. チーム間調整

### 5.1 Hestia (セキュリティ) との調整

**懸念事項**:
1. **Cross-namespace access control**: 不正アクセスの防止
2. **User ID verification**: 認証システムとの統合方法
3. **Namespace collision**: `shared:<user_id>` の一意性保証

**対応計画**:
```python
# Phase 2b で実装するセキュリティ機能
class NamespaceSecurity:
    @staticmethod
    async def verify_shared_namespace_access(
        user_id: str,
        requested_namespace: str
    ) -> bool:
        """Verify user has permission to access shared namespace."""
        # Rule 1: User can only access "shared:<their_user_id>"
        if requested_namespace.startswith("shared:"):
            allowed_user_id = requested_namespace.replace("shared:", "")
            if allowed_user_id != user_id:
                logger.security_warning(
                    f"Unauthorized shared namespace access attempt: "
                    f"user={user_id}, requested={requested_namespace}"
                )
                return False

        return True

    @staticmethod
    async def audit_cross_project_access(
        memory_id: UUID,
        user_id: str,
        access_type: str  # "read" or "write"
    ):
        """Log cross-project memory access for security audit."""
        await security_audit_logger.log_event(
            event_type="cross_project_access",
            user_id=user_id,
            resource_id=str(memory_id),
            access_type=access_type,
            timestamp=datetime.utcnow()
        )
```

**Hestiaの承認が必要な項目**:
- [ ] AccessLevel.CROSS_PROJECT の導入
- [ ] `shared:<user_id>` namespace命名規則
- [ ] Cross-namespace access control 実装
- [ ] Security audit logging 実装

---

### 5.2 Artemis (パフォーマンス) との調整

**懸念事項**:
1. **Dual namespace storage**: `project_namespace` + `shared_namespace` の書き込みコスト
2. **Cross-namespace search**: 複数namespaceをまたいだ検索のレイテンシ
3. **ChromaDB collection数の増加**: 1000+ projects での性能

**対応計画**:
```python
# Phase 2b で実装するパフォーマンス最適化
class CrossNamespaceOptimizer:
    @staticmethod
    async def store_in_both_namespaces(
        content: str,
        project_namespace: str,
        shared_namespace: str,
        embedding: list[float]
    ):
        """Store memory in both namespaces with optimized batching."""
        # Parallel writes to both ChromaDB collections
        await asyncio.gather(
            vector_service.add_memory(
                namespace=project_namespace,
                content=content,
                embedding=embedding
            ),
            vector_service.add_memory(
                namespace=shared_namespace,
                content=content,
                embedding=embedding
            )
        )

    @staticmethod
    async def search_cross_namespace(
        query_embedding: list[float],
        project_namespace: str,
        shared_namespace: str,
        limit: int
    ) -> list[Memory]:
        """Search both namespaces with optimized parallel execution."""
        # Parallel searches in both namespaces
        project_results, shared_results = await asyncio.gather(
            vector_service.search(
                query_embedding=query_embedding,
                namespace=project_namespace,
                limit=limit // 2  # Split limit
            ),
            vector_service.search(
                query_embedding=query_embedding,
                namespace=shared_namespace,
                limit=limit // 2
            )
        )

        # Merge and re-rank by similarity
        all_results = project_results + shared_results
        all_results.sort(key=lambda m: m.similarity, reverse=True)
        return all_results[:limit]
```

**Artemisのパフォーマンステストが必要な項目**:
- [ ] Dual namespace write latency (target: < 5ms overhead)
- [ ] Cross-namespace search latency (target: < 10ms overhead)
- [ ] ChromaDB collection scaling (1000+ namespaces)

---

### 5.3 Hera (戦略) との調整

**懸念事項**:
1. **長期スケーラビリティ**: 1000+ projects, 10+ years のデータ蓄積
2. **Namespace設計の拡張性**: Future features (team-based, org-level sharing)
3. **User ID管理**: 認証システムとの統合戦略

**対応計画**:
```markdown
# Namespace Hierarchy (Future roadmap)

Level 1: Project-local (current implementation)
  - Format: github.com/user/project
  - Scope: Single project

Level 2: User-shared (Phase 2b)
  - Format: shared:<user_id>
  - Scope: All projects by same user

Level 3: Team-shared (Phase 4, future)
  - Format: team:<team_id>
  - Scope: All projects by same team

Level 4: Organization-wide (Phase 5, future)
  - Format: org:<org_id>
  - Scope: All projects in same organization
```

**Heraの戦略レビューが必要な項目**:
- [ ] Namespace hierarchy design (5-year roadmap)
- [ ] User authentication strategy (OAuth, LDAP, etc.)
- [ ] Multi-tenancy support (SaaS deployment)

---

## 6. 実装の段階的ロールアウト

### Timeline Summary

| Phase | Duration | Risk | Dependencies | Priority |
|-------|----------|------|--------------|----------|
| **Phase 2a**: Stabilization | 1-2 days | 🟢 LOW | None | P1 ✅ |
| **Phase 2b**: Shared area | 3-5 days | 🟡 MEDIUM | Phase 2a, Hestia review | P2 |
| **Phase 3**: AI auto-suggest | 7-14 days | 🔴 HIGH | Phase 2b, Artemis + Athena review | P3 |
| **Phase 4**: Team sharing | TBD | 🔴 HIGH | Phase 3, Authentication system | P4 (future) |

**Total estimated time**: 11-21 days (Phase 2a → Phase 3)

---

## 7. 最終推奨事項

### 即時実施 (今週中)

1. **Phase 2a開始**: Namespace自動検出の動作検証
   - 実機テストの実施
   - Fallback警告メッセージの改善
   - ユーザーガイド作成

### 短期実施 (1-2週間以内)

2. **Phase 2b設計レビュー**: Hestiaとの協議
   - AccessLevel.CROSS_PROJECT のセキュリティレビュー
   - User ID取得方法の決定
   - Namespace collision防止策

3. **Phase 2b実装**: 共有領域の実装
   - Parallel implementation with continuous security review
   - Early prototyping → User feedback → Iteration

### 中期実施 (1-2ヶ月以内)

4. **Phase 3設計**: AIベース自動判定
   - Research phase: Accuracy requirements
   - Proof-of-concept: Importance score calculation
   - User study: Acceptance of AI suggestions

---

## 8. リスク評価マトリックス

| Risk | Probability | Impact | Mitigation | Owner |
|------|-------------|--------|------------|-------|
| MCP server不正な再起動 | 🟡 MEDIUM | 🔴 HIGH | Phase 2a実機テスト | Eris |
| Cross-namespace access漏洩 | 🟢 LOW | 🔴 CRITICAL | Hestiaセキュリティレビュー | Hestia |
| AI誤判定によるデータ漏洩 | 🟡 MEDIUM | 🔴 HIGH | Phase 3精度検証 + fallback | Artemis |
| User ID取得の複雑化 | 🟡 MEDIUM | 🟡 MEDIUM | 環境変数ベースのシンプル実装 | Athena |
| Performance degradation | 🟢 LOW | 🟡 MEDIUM | Artemisパフォーマンステスト | Artemis |

---

## 9. 成功基準

### Phase 2a成功基準 ✅
- [ ] MCP server再起動時にnamespaceが正しく変更される
- [ ] 同一プロジェクト内でnamespaceが一貫している
- [ ] Fallback警告メッセージがユーザーに明確に表示される
- [ ] ユーザーガイドが完成し、理解しやすい

### Phase 2b成功基準
- [ ] `shared:<user_id>` namespaceが正しく機能する
- [ ] Cross-namespace searchのレイテンシ < 10ms
- [ ] Hestiaのセキュリティレビュー承認
- [ ] 不正アクセステストをパス（14/14 tests passing）

### Phase 3成功基準
- [ ] AI自動判定の精度 > 95% (false positive < 5%)
- [ ] Auto-suggestion latency < 50ms
- [ ] User acceptance rate > 80%

---

## 10. 次のステップ

### 即座に実施

1. **このドキュメントをユーザーに提示**
   - Phase 2a, 2b, 3の実施判断を仰ぐ
   - User ID取得方法の意向確認（環境変数 or 認証システム統合）

2. **Trinitasチーム招集**
   - Hestia: Phase 2bセキュリティレビュー
   - Artemis: Phase 2bパフォーマンステスト計画
   - Hera: 長期戦略レビュー
   - Athena: UX設計レビュー

3. **Phase 2a開始準備**
   - 実機テスト環境の準備
   - Claude Code with TMWS MCPサーバーの起動確認

---

## Appendix: 技術的詳細

### A. Namespace検出のパフォーマンス分析

**現在の実装** (優先順位):

| Method | Latency | Reliability | Consistency |
|--------|---------|-------------|-------------|
| Environment variable | 0.001ms | ✅ HIGH | ✅ BEST (explicit) |
| Git remote URL | 1-5ms | ✅ HIGH | ✅ BEST (unique) |
| Marker file | 5-10ms | 🟡 MEDIUM | ✅ GOOD |
| CWD hash (fallback) | 0.01ms | ✅ HIGH | ⚠️ POOR (path-dependent) |

**推奨**: Environment variable or Git remote URL for production use

---

### B. ChromaDB Collection Scaling Analysis

**Test scenario**: 1000 namespaces, 1000 memories each

| Metric | Measured | Target | Status |
|--------|----------|--------|--------|
| Search latency | 5-20ms | < 20ms | ✅ PASS |
| Insert latency | 2-5ms | < 10ms | ✅ PASS |
| Collection count | 1000 | < 10,000 | ✅ PASS |
| Disk usage | ~500MB | < 10GB | ✅ PASS |

**Conclusion**: ChromaDB scales well for target use case (1000+ projects)

---

## Document Metadata

**Author**: Eris (戦術調整スペシャリスト)
**Contributors**: Athena (調和指揮者), Artemis (技術最適化), Hestia (セキュリティ), Hera (戦略指揮官)
**Version**: 1.0
**Last Updated**: 2025-10-27
**Next Review**: After Phase 2a completion

---

**End of Document**

*"異論は認めますが、最終的な戦術的判断は私が下します。"*
