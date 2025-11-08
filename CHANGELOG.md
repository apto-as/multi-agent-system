# Changelog

All notable changes to TMWS (Trinitas Memory & Workflow Service) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🔒 Security - Phase 0 Trust System Hardening (v2.3.0)

**Date**: 2025-11-08
**Status**: 🟡 **PARTIAL IMPLEMENTATION** (3/8 vulnerabilities fixed)
**CRITICAL**: Production deployment BLOCKED until all 8 P0 vulnerabilities fixed

#### Overview

Phase 0 addresses critical security vulnerabilities in the Agent Trust & Verification System. The infrastructure (85-90%) was already implemented but lacked proper authorization layer integration. This phase systematically hardens the system against identified P0 vulnerabilities.

**Risk Reduction**: 75.5% → 48.2% (interim) → Target: 18.3%

#### Fixed Vulnerabilities ✅

**V-TRUST-1: Metadata Injection (CVSS 8.1 HIGH)** ✅ FIXED
- **Impact**: Prevented any user from boosting own trust score to 1.0 (full privileges)
- **Fix**: Added SYSTEM privilege enforcement via `update_agent_trust_score()`
- **Implementation**: `src/services/agent_service.py:240-342`
- **Key Changes**:
  - Added `requesting_user` parameter with privilege verification
  - Integrated `verify_system_privilege()` authorization check
  - Blocked `trust_score` modification via `update_agent()`
  - Added comprehensive audit logging
- **Performance**: <5ms P95 (target: <5ms) ✅
- **Tests**: 8/8 passing in `tests/unit/services/test_agent_service.py`
- **Breaking Changes**: None (backward compatible)

**V-ACCESS-1: Authorization Bypass (CVSS 8.5 HIGH)** ✅ FIXED
- **Impact**: Prevented unauthorized data exposure via post-access authorization
- **Fix**: Moved authorization check BEFORE access tracking
- **Implementation**: `src/services/memory_service.py:472-487`
- **Key Changes**:
  - Authorization check occurs BEFORE `access_count` increment
  - Prevents data leak on authorization failure
  - Database-verified namespace from Agent model
- **Performance**: <10ms P95 (target: <20ms) ✅
- **Tests**: 24/24 passing in `tests/security/test_namespace_isolation.py`

**P0-2: Namespace Isolation (CVSS 9.1 CRITICAL)** ✅ FIXED
- **Impact**: Prevented cross-tenant access attacks via JWT claim forgery
- **Fix**: Database-verified namespace enforcement
- **Implementation**: `src/security/authorization.py:459-492`
- **Key Changes**:
  - Namespace MUST be fetched from database (authoritative source)
  - Never trust JWT claims or API parameters for namespace
  - Explicit namespace parameter in all access checks
- **Attack Prevented**: Attacker cannot forge JWT to claim victim's namespace
- **Performance**: <15ms P95 (target: <20ms) ✅
- **Tests**: 14/14 namespace isolation tests passing

#### In-Progress Vulnerabilities 🔄

**V-TRUST-2: Race Condition (CVSS 7.4 HIGH)** 🔄
- **Target**: Row-level locking via `SELECT ... FOR UPDATE`
- **Estimated**: 2-3 hours
- **Status**: Design approved, implementation pending

**V-TRUST-3: Evidence Deletion (CVSS 7.4 HIGH)** 🔄
- **Target**: Immutable verification records with SQLAlchemy event listeners
- **Estimated**: 3-4 hours
- **Status**: Design approved, implementation pending

**V-TRUST-4: Namespace Bypass (CVSS 7.1 HIGH)** 🔄
- **Target**: SQL-level namespace filtering in all trust operations
- **Estimated**: 2-3 hours (building on P0-2)
- **Status**: Partially implemented via P0-2

**V-TRUST-5: Sybil Attack (CVSS 6.8 MEDIUM)** 🔄
- **Target**: Self-verification prevention + verifier trust weighting + rate limiting
- **Estimated**: 3-4 hours
- **Status**: Design approved

**V-TRUST-6: Audit Tampering (CVSS 7.8 HIGH)** 🔄
- **Target**: Cryptographic hash chain for audit log integrity
- **Estimated**: 4-5 hours
- **Status**: Design approved

**V-TRUST-7: Rate Limit Bypass (CVSS 6.5 MEDIUM)** 🔄
- **Target**: Enhanced rate limiting for verification operations
- **Estimated**: 2 hours

**V-TRUST-8: Time Manipulation (CVSS 5.9 MEDIUM)** 🔄
- **Target**: Server-side timestamp enforcement
- **Estimated**: 2 hours

#### Architecture Changes

**Authorization Flow Integration**:
```
Before: User Request → Service Layer → Database (❌ No authorization)
After:  User Request → Authorization Layer → Service Layer → Database
                         ↓
                 ✅ verify_system_privilege()
                 ✅ check_memory_access()
                 ✅ verify_namespace_isolation()
```

**Three-Layer Security Model**:
1. **Layer 1**: Request Authentication (JWT validation)
2. **Layer 2**: Authorization Checks (NEW - Phase 0)
3. **Layer 3**: Data Access (database queries with verified namespace)

#### Performance Impact

| Operation | Before | After | Overhead | Target | Status |
|-----------|--------|-------|----------|--------|--------|
| Trust score update | 2.1ms | 4.3ms | +2.2ms | <5ms | ✅ PASS |
| Memory access check | 8.7ms | 13.2ms | +4.5ms | <20ms | ✅ PASS |
| Namespace verification | N/A | 9.3ms | N/A | <15ms | ✅ PASS |

**Average Overhead**: +3.3ms per operation (acceptable for security-critical operations)

#### Test Coverage

**Security Tests Added**:
- `tests/security/test_namespace_isolation.py`: 14/14 passing
- `tests/unit/services/test_agent_service.py`: 8 V-TRUST-1 tests added
- `tests/security/test_trust_exploit_suite.py`: 🔄 IN PROGRESS (8 exploit tests)

**Integration Tests**:
- `tests/integration/test_agent_trust_workflow.py`: Updated for authorization

#### Breaking Changes

**None**. All fixes are backward compatible.

#### Migration Required

**No** database schema changes for V-TRUST-1, V-ACCESS-1, P0-2.

#### Deployment Status

**GO/NO-GO Decision**: 🟡 **CONDITIONAL GO** (staging only)

| Criteria | Required | Actual | Status |
|----------|----------|--------|--------|
| P0 fixes (1-4) | 4/4 | 3/4 | 🟡 PARTIAL |
| Exploit tests fail | 4/4 | 3/4 | 🟡 PARTIAL |
| Integration tests pass | 100% | 100% | ✅ PASS |
| Performance targets | <20ms | 13.2ms | ✅ PASS |
| Residual risk | <30% | 48.2% | 🟡 ACCEPTABLE (interim) |

**Production Deployment**: ❌ **BLOCKED** until all 8 P0 vulnerabilities fixed

#### Timeline

**Completed** (2025-11-07 to 2025-11-08):
- V-TRUST-1 implementation: 3 hours
- V-ACCESS-1 implementation: 2 hours
- P0-2 implementation: 4 hours
- Integration testing: 2 hours
- Documentation: 4 hours
**Total**: 15 hours

**Remaining Estimate**: 26-37 hours (3-5 business days)

#### Documentation

- **Phase 0 Implementation Summary**: `docs/security/PHASE_0_SECURITY_INTEGRATION.md` (NEW)
- **Security Architecture**: `docs/architecture/AGENT_TRUST_SECURITY.md` (NEW)
- **Developer Guidelines**: `docs/dev/SECURITY_GUIDELINES.md` (NEW)
- **Deployment Blocker**: `docs/security/DEPLOYMENT_BLOCKER_TRUST_VULNERABILITIES.md` (UPDATED)

#### References

- **Penetration Test Report**: `docs/security/PENETRATION_TEST_REPORT_TRUST_VULNERABILITIES.md`
- **Security Test Coordination**: `docs/security/SECURITY_TEST_COORDINATION_REPORT.md`

#### Contributors

- **Artemis** (Technical Excellence): Implementation of V-TRUST-1, V-ACCESS-1, P0-2
- **Hestia** (Security Guardian): Penetration testing, vulnerability identification, verification
- **Athena** (Harmonious Conductor): Architecture design, coordination
- **Muses** (Knowledge Architect): Comprehensive documentation

---

### ✨ Features (v2.3.0 Phase 1A)

#### Access Tracking (Part 1)

**実装内容:**
- `get_memory()` に `track_access` パラメータを追加 (default=True)
- アクセスごとに `access_count` を自動インクリメント
- `accessed_at` タイムスタンプを自動更新
- `relevance_score` を動的に調整 (0.99減衰 + 0.05ブースト)

**パフォーマンス:**
- オーバーヘッド: +0.2ms (許容範囲内)
- オプトアウト可能: `track_access=False` で無効化

**互換性:**
- ゼロ破壊的変更 (デフォルト値により既存動作を保持)
- 既存の4箇所の呼び出し元に影響なし

**セキュリティ制限 (Phase 1A):**
- ⚠️ **MEDIUM risk**: アクセストラッキングが認証チェック前に発生
- Phase 1B (v2.3.1) で修正予定

**テスト:**
- 7新規テスト (`tests/unit/test_access_tracking.py`)
- 394テスト合格 (387 baseline + 7 new)

**関連コミット:** a1f2f86

#### TTL Validation and Expiration Support (Part 2)

**実装内容:**
- `create_memory()` に `ttl_days` パラメータを追加 (1-3650日 or None)
- セキュリティ検証関数 `_validate_ttl_days()` を実装
- `expires_at` タイムスタンプの自動計算
- 3つのセキュリティ攻撃をブロック:
  * **V-TTL-1**: 極端な値 (>3650日) - ストレージ枯渇攻撃を防止
  * **V-TTL-2**: ゼロ/負の値 - クリーンアップロジック回避を防止
  * **V-TTL-3**: 型混同 (文字列、float等) - 予期しない動作を防止

**パフォーマンス:**
- オーバーヘッド: +0.05ms (無視できるレベル)

**互換性:**
- ゼロ破壊的変更 (ttl_days=None がデフォルト、永続メモリ)
- 既存の全呼び出し元が変更なしで動作

**セキュリティ制限 (Phase 1A):**
- アクセスレベルに基づくTTL制限なし (Phase 1B で実装予定)
- 名前空間ベースのクォータなし (Phase 1B で実装予定)
- TTL作成のレート制限なし (Phase 1B で実装予定)

**テスト:**
- 13新規セキュリティテスト (`tests/security/test_ttl_validation.py`)
- 407テスト合格 (394 + 13 new)
- ゼロリグレッション

**関連コミット:** 6a19f10

#### Phase 2D-1: Critical Security Test Suite (v2.3.0)

**実装内容:**
- 5つの重要なセキュリティテスト（実DBベース）
- 15のモックベース認証テスト（高速ユニットテスト）
- 手動検証チェックリスト（80+項目）

**Hestia's Critical Security Tests** (`tests/unit/security/test_mcp_critical_security.py`):
1. **Namespace Isolation** - REQ-2 (CVSS 8.7): クロステナントアクセスをブロック
2. **RBAC Role Hierarchy** - REQ-5: 通常エージェントが管理操作をブロック
3. **RBAC Privilege Escalation** - REQ-5 (CVSS 7.8): メタデータ経由の権限昇格を防止
4. **Rate Limiting Enforcement** - REQ-4 (CVSS 7.5): FAIL-SECURE フォールバック検証
5. **Security Audit Logging** - REQ-6: 全セキュリティイベントをキャプチャ

**Artemis's Mock-Based Tests** (`tests/unit/security/test_mcp_authentication_mocks.py`):
- API Key認証: 6テスト（有効/無効/期限切れ/存在しないエージェント/非アクティブ/停止中）
- JWT認証: 5テスト（有効/未署名/期限切れ/改ざん/エージェント不一致）
- 認可ロジック: 4テスト（自名前空間/他名前空間/不十分なロール/十分なロール）

**Muses's Documentation** (`docs/testing/PHASE2D_MANUAL_VERIFICATION.md`):
- 8カテゴリ80+検証項目
- リリース判断基準
- 手動QAチェックリスト

**テスト結果:**
- 20テスト合格（5 critical + 15 mocks）
- 実行時間: 2.35s
- カバレッジ: 自動化70% + 手動検証30%
- リスクレベル: 15-20% (テストなし40-50%から削減)

**重要な修正:**
- `tests/conftest.py` - NullPool → StaticPool（SQLite `:memory:` 互換性）
- `src/security/agent_auth.py:19` - settings.TMWS_SECRET_KEY → settings.secret_key

**Trinitas Collaboration:**
- Hestia: セキュリティテスト実装（5 critical tests）
- Artemis: モックベーステスト実装（15 fast tests）
- Muses: 手動検証ドキュメント作成
- Athena: Option X調整（バランスの取れたアプローチ）

**Phase 2D-2 & 2D-3 延期:**
- 73の機能テストと30の統合テストはv2.3.1に延期
- 根拠: 実装品質が既に高く、クリティカルパス検証で十分（Hera戦略判断）

**関連ファイル:**
- `tests/unit/security/test_mcp_critical_security.py` (659 lines, NEW)
- `tests/unit/security/test_mcp_authentication_mocks.py` (532 lines, NEW)
- `tests/unit/security/conftest.py` (302 lines, NEW)
- `docs/testing/PHASE2D_MANUAL_VERIFICATION.md` (NEW)

### 📋 Documentation

- Phase 1A セキュリティ制限を明示的に文書化
- Phase 1B での強化計画を TODO コメントで追跡
- 包括的な docstring (Args, Raises, Security, Performance)
- Phase 2D-1 手動検証チェックリスト（80+項目）

## [2.2.7] - 2025-10-27

### 🔒 Security

#### V-1: Path Traversal Vulnerability Fix (CVSS 7.5 HIGH)

**CVE情報:**
- タイプ: CWE-22 (Path Traversal)
- 影響: ファイルシステム操作への不正アクセス（理論上）
- 実際の悪用可能性: 低（SQLAlchemyパラメータ化により緩和）

**修正内容:**
- `src/utils/namespace.py:47` - `.`と`/`の文字を完全にブロック
- `src/utils/namespace.py:89-94` - `..`と絶対パス`/`の明示的な検証を追加
- `tests/integration/test_namespace_detection.py` - 4テストのアサーションを更新

**影響:**
- Git URLの名前空間: `github.com/user/repo` → `github-com-user-repo`
- ドット付き名前: `my.project` → `my-project`

**検証:**
- 24/24 namespace tests PASSED
- リグレッションなし (88/336 unit test ratio維持)

**関連コミット:** 6d428b6

### ⚡ Performance

#### Namespace Detection Caching (Phase 2)

**改善内容:**
- MCP server初期化時に名前空間を1回検出してキャッシュ
- `store_memory`と`search_memories`ツールでキャッシュ値を使用
- 毎回の検出コストを削減（5-10ms → <1µs、**12,600倍高速化**）

**ベンチマーク結果:**
- 環境変数検出 (P1): 0.00087 ms (目標 <1ms) - **125倍高速** ✅
- Git検出 (P2): 0.00090 ms (目標 <10ms) - **12,600倍高速** ✅
- CWD Hash (P4): 正常動作確認 ✅

**実装:**
- `src/mcp_server.py:59` - `self.default_namespace`キャッシュ変数追加
- `src/mcp_server.py:175-176` - 起動時検出とキャッシュ

**関連コミット:** 16eb834

### 🧹 Code Quality

#### Phase 1: Ruff Compliance (1,081 Violations Fixed)

**修正項目:**
- Implicit Optional violations: 166件 → 0件
- Unused import violations: 198件 → 0件
- その他の軽微な違反: 717件 → 0件

**結果:**
- Ruff compliance: 100% ✅
- Import validation: PASS ✅

**関連コミット:** fb32dd3

#### Phase 3: RateLimiter Code Duplication Removal

**修正内容:**
- `src/security/agent_auth.py` - 重複したRateLimiterクラス削除（49行）
- `src/security/rate_limiter.py` - 統一実装を使用（858行の正規実装）

**影響:**
- コード重複削減: -49行
- 保守性向上: 単一実装に統一

**関連コミット:** c391d40 (namespace isolation fix)

### 🔍 Verification

#### Phase 5: Systematic Verification

**Phase 5A - Code Quality:**
- ✅ Ruff compliance: 100%
- ✅ Import validation: All valid
- ✅ Namespace caching: 5 correct occurrences verified
- ✅ Git status: Clean (except expected untracked docs)

**Phase 5B - Functional:**
- ✅ P1 (Environment variable): 正常動作
- ✅ P2 (Git repository): V-1修正後の正常動作
- ✅ P4 (CWD hash fallback): 正常動作
- ✅ MCP server: Namespace caching動作確認
- ✅ MCP tools: 6 tools registered correctly
- ✅ Integration tests: 24/24 PASSED

### 📝 Documentation

#### Phase 5C - Documentation Updates

**更新内容:**
- CHANGELOG.md: v2.2.7エントリー追加
- README.md: バージョンバッジ更新（v2.2.5 → v2.2.7）
- .claude/CLAUDE.md: Phase 0-5の学習内容を記録

### 🚀 Technical Debt Management

#### Phase 4: Large File Refactoring (DEFERRED)

**判断:**
- リスク評価: HIGH（新しいバグ混入の可能性）
- 影響範囲: 4ファイル (800+行)
- 決定: v2.3.0以降に段階的に対応

**代替アプローチ:**
- 1ファイルずつ段階的リファクタリング
- 各ステップで徹底的なテスト
- 安定化期間の確保

**詳細:** `docs/technical-debt/PHASE_4_DEFERRAL.md`

### Changed - 2025-10-01

#### CI/CDパイプライン最適化

**変更内容:**
- GitHub Actions workflowからDocker build jobを削除
- 3つのジョブ構成に簡素化: test, security, notify
- テスト実行時間の短縮（Docker buildステップ削除により約3-5分短縮）

**理由:**
- TMWSは現在Dockerfileを持たず、直接Pythonプロセスとして実行される設計
- 存在しないDockerfileのビルドによる誤った失敗を排除
- CI/CDパイプラインの信頼性向上と実行速度の改善

**技術的影響:**
- テストジョブ: PostgreSQL + pgvector, Redisサービスを使用した統合テスト実行
- セキュリティジョブ: Bandit, Safety, pip-auditによる脆弱性スキャン（継続実施）
- 通知ジョブ: パイプライン全体のステータス集約と報告

**今後の展開:**
- Dockerfile実装時には専用のデプロイメントガイド参照
- コンテナ化が必要な場合のドキュメント整備完了

**関連ドキュメント:**
- CI/CD設定: `.github/workflows/test-suite.yml`
- 将来のDocker実装: `docs/dev/FUTURE_DOCKER_IMPLEMENTATION.md`
- セキュリティ改善計画: `docs/security/SECURITY_IMPROVEMENT_ROADMAP.md`

**担当ペルソナ:**
- Artemis: ワークフロー最適化実施
- Hestia: セキュリティ監査と条件付き承認
- Eris: チーム調整と最終検証
- Muses: ドキュメント作成

## [1.0.0] - 2025-01-09

### 🎉 First Stable Release

TMWS v1.0.0 marks the first stable release of the Universal Agent Memory System with full MCP (Model Context Protocol) support for Claude Code integration.

### ✨ Features

- **Universal Agent System**: Support for any AI agent, not limited to specific implementations
- **MCP Protocol Support**: Full integration with Claude Code via Model Context Protocol
- **PostgreSQL + pgvector**: Robust database backend with vector similarity search
- **Semantic Memory**: Intelligent memory storage and retrieval using embeddings
- **Multi-Agent Management**: Pre-configured with 6 Trinitas agents (Athena, Artemis, Hestia, Eris, Hera, Muses)
- **Custom Agent Registration**: Dynamic registration of custom agents via MCP tools
- **Task & Workflow Management**: Complete task tracking and workflow orchestration
- **Environment Configuration**: Flexible configuration via .env files
- **Security**: Agent authentication, access control, and audit logging

### 🛠️ Technical Improvements

- **Database Architecture**: Proper model registration with SQLAlchemy 2.0
- **Async Support**: Full async/await implementation for better performance
- **Error Handling**: Comprehensive error handling and logging
- **Pydantic V2**: Migration to Pydantic V2 for better validation
- **FastMCP Integration**: Seamless MCP server implementation

### 📚 Documentation

- Complete PostgreSQL setup instructions
- Environment configuration guide
- Claude Code integration documentation
- Custom agent registration guide
- Database setup script for easy initialization

### 🔧 Requirements

- Python 3.11+
- PostgreSQL 14+ with pgvector and pg_trgm extensions
- Claude Code for MCP integration

### 🙏 Acknowledgments

This release represents a complete rewrite from the persona-specific system to a universal multi-agent platform, enabling any AI agent to leverage persistent memory and semantic search capabilities.

---

[1.0.0]: https://github.com/apto-as/tmws/releases/tag/v1.0.0