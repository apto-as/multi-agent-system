# Tool Search + MCP Hub System Specification v1.0.0

---
title: "Tool Search + MCP Hub System Specification"
version: "1.0.0"
status: "approved"
created: "2025-12-04"
last_updated: "2025-12-04"
owners: ["athena-conductor", "hera-strategist"]
reviewers: ["artemis-optimizer", "hestia-auditor", "eris-coordinator"]
tmws_memory_namespace: "tmws-core"
serena_memory: "tool_search_mcp_hub_spec"
---

## 1. Executive Summary

### 1.1 Strategic Objectives

TMWSに**Tool Search**と**MCP Hub**機能を統合し、複数のMCPサーバーを統一的に管理する。

**Primary Goals:**
- セマンティック検索による動的ツール発見（10,000+ ツール対応）
- 外部MCPサーバーの統一ハブ管理
- Claude Code / OpenCode 両プラットフォーム対応
- **TMWSの4つの核心特徴を完全に維持・強化**

### 1.2 TMWS 4つの核心特徴 (絶対維持)

| 特徴 | 影響 | 詳細 |
|------|------|------|
| **記憶 (Memory)** | ✅ PRESERVED | ChromaDB分離コレクション (`tmws_memories` / `tmws_tools`) |
| **ナラティブ (Narrative)** | ✅ PRESERVED | 変更なし、ツールコンテキストで強化 |
| **スキル (Skills)** | ✨ ENHANCED | Tool → Skill昇格、Progressive Disclosure |
| **学習 (Learning)** | ✨ ENHANCED | ツール使用パターン追跡、適応的ランキング |

### 1.3 成功指標

| Metric | Target | Priority |
|--------|--------|----------|
| ツール検索レイテンシ | < 100ms P95 | P0 |
| 外部MCP接続成功率 | > 95% | P0 |
| セキュリティテスト合格率 | 100% (P0) | P0 |
| キャッシュヒット率 | > 95% | P1 |
| 4特徴回帰テスト | 100% PASS | P0 |

---

## 2. Architecture Overview

### 2.1 System Architecture (2-Container Hybrid)

```
┌─────────────────────────────────────────────────────────────┐
│ Claude Code / OpenCode (Platform Adapters)                  │
└───────────────────────────┬─────────────────────────────────┘
                            │ stdio / HTTP
┌───────────────────────────▼─────────────────────────────────┐
│ TMWS Container (既存 + 拡張)                                 │
├─────────────────────────────────────────────────────────────┤
│ [PRESERVED] Memory System (ChromaDB: tmws_memories)         │
│ [PRESERVED] Narrative System                                 │
│ [PRESERVED] Skills System                                    │
│ [PRESERVED] Learning System                                  │
│ [NEW] Tool Discovery Engine                                  │
│ [NEW] MCP Hub Manager                                        │
└───────────────────────────┬─────────────────────────────────┘
                            │ Unix Socket (HMAC認証)
┌───────────────────────────▼─────────────────────────────────┐
│ MCP Hub Container (新規)                                     │
├─────────────────────────────────────────────────────────────┤
│ [NEW] Tool Registry (ChromaDB: tmws_tools)                  │
│ [NEW] External MCP Proxy                                     │
│ [NEW] Skill Execution Engine (Sandbox)                       │
│ [NEW] Platform Adapters                                      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ External MCP Servers                                         │
│ context7 | serena | playwright | chrome-devtools | gdrive   │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Design Decisions (Eris Tactical)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| MCP Hub Implementation | Hybrid (2コンテナ) | セキュリティ分離 + 障害隔離 |
| Tool Search Integration | TMWS tool + Protocol | UX優先 + 標準準拠 |
| OpenCode Compatibility | Platform Adapters | 単一バックエンド、二重メンテ回避 |
| Container Communication | Unix Socket + HMAC | 低レイテンシ + セキュア |

---

## 3. Component Specifications

### 3.1 Tool Discovery Engine

**Location:** `src/tools/tool_search.py`

```python
@mcp_tool
async def search_tools(
    query: str,
    source: Literal["all", "skills", "mcp_servers", "registry"] = "all",
    limit: int = 10,
    filters: dict | None = None
) -> list[ToolSearchResult]:
    """
    セマンティック検索で利用可能なツールを発見。

    Priority Order:
    1. TMWS Skills (weight: 2.0) - 第3特徴「スキル」優先
    2. Connected MCP servers (weight: 1.5)
    3. External Tool Registry (weight: 1.0)

    Performance:
    - P95 latency: < 100ms
    - ChromaDB vector search
    - BM25 hybrid ranking

    Integration with 4 Features:
    - 記憶: ツール使用履歴をMemoryに保存
    - スキル: Skillsを最優先でランキング
    - 学習: 使用パターンで適応的ランキング
    """
    pass
```

**Data Models:**

```python
@dataclass
class ToolSearchResult:
    tool_name: str
    server_id: str              # "tmws" for internal, "mcp__xxx" for external
    description: str
    relevance_score: float      # 0.0-1.0
    source_type: str            # "skill" | "internal" | "external"
    input_schema: dict
    tags: list[str]
    trust_score: float          # From Learning system
    usage_count: int            # From Memory system

@dataclass
class MCPServerMetadata:
    server_id: str
    name: str
    description: str
    transport: str              # "stdio" | "http" | "sse"
    command: list[str] | None   # For STDIO
    url: str | None             # For HTTP/SSE
    tools: list[ToolMetadata]
    trust_score: float
    auto_connect: bool
    last_connected: datetime | None
```

### 3.2 MCP Hub Manager

**Location:** `src/infrastructure/mcp/hub_manager.py`

```python
class MCPHubManager:
    """
    統一MCPサーバー管理ハブ。

    Responsibilities:
    - 外部MCPサーバーの接続管理
    - ツール呼び出しのプロキシ
    - ツールメタデータの集約
    - 動的ツール登録

    Security:
    - Preset-only接続 (任意コマンド実行禁止)
    - 最大10接続
    - Unix Socket HMAC認証
    """

    MAX_CONNECTIONS = 10

    async def connect_server(self, server_id: str) -> MCPConnection:
        """外部MCPサーバーに接続（lazy initialization）"""
        pass

    async def proxy_tool_call(
        self,
        server_id: str,
        tool_name: str,
        arguments: dict
    ) -> ToolResult:
        """ツール呼び出しを外部サーバーにプロキシ"""
        pass

    async def expose_external_tools(self) -> list[ToolMetadata]:
        """外部ツールをTMWSツールとして公開"""
        pass
```

### 3.3 Platform Adapters

**Claude Code Adapter:** `src/infrastructure/platform/claude_adapter.py`
**OpenCode Adapter:** `src/infrastructure/platform/opencode_adapter.py`

```python
class PlatformAdapter(Protocol):
    """プラットフォーム抽象化インターフェース"""

    def detect_platform(self) -> str:
        """現在のプラットフォームを検出"""
        pass

    def load_config(self) -> dict:
        """プラットフォーム固有の設定を読み込み"""
        pass

    def format_response(self, result: Any) -> Any:
        """プラットフォーム向けにレスポンスを整形"""
        pass
```

---

## 4. Security Requirements (Hestia Approved)

### 4.1 P0 必須 (実装前ブロッカー)

| ID | Requirement | Implementation | Test |
|----|-------------|----------------|------|
| S-P0-1 | Unix Socket HMAC認証 | `hmac_sha256(message, shared_secret)` | `test_socket_auth.py` |
| S-P0-2 | コンテナCapability Drop | `cap_drop: ALL` in docker-compose | Manual audit |
| S-P0-3 | 入力バリデーション | JSON Schema enforcement | `test_input_validation.py` |
| S-P0-4 | Skill Sandboxing | AST分析 + リソース制限 | `test_sandbox.py` |
| S-P0-5 | 外部MCP許可リスト | Preset-only, no auto-discovery | `test_allowlist.py` |
| S-P0-6 | レスポンスサイズ制限 | 10MB max | `test_response_limits.py` |
| S-P0-7 | タイムアウト強制 | 30s default | `test_timeouts.py` |
| S-P0-8 | 監査ログ | 全セキュリティイベント記録 | `test_audit_log.py` |

### 4.2 P1 高優先度 (v1.0内)

| ID | Requirement | Target Date |
|----|-------------|-------------|
| S-P1-1 | レート制限 (10 req/s/server) | Week 2 |
| S-P1-2 | Circuit Breaker | Week 2 |
| S-P1-3 | データ漏洩防止 (ログサニタイズ) | Week 3 |
| S-P1-4 | 異常検知 | Week 4 |

### 4.3 Container Security Configuration

```yaml
# docker-compose.yml 必須設定
services:
  tmws:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,nodev

  mcp-hub:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    network_mode: none  # Unix socketのみ
    read_only: true
```

---

## 5. Integration with TMWS 4 Core Features

### 5.1 記憶 (Memory) Integration

```python
# ツール使用履歴をMemoryに保存
await tmws.store_memory(
    namespace="mcp_hub:usage",
    content={
        "tool_name": tool_name,
        "server_id": server_id,
        "success": True,
        "latency_ms": 145,
        "timestamp": datetime.now().isoformat()
    },
    importance=0.5,
    tags=["tool-usage", server_id]
)

# ユーザー設定をMemoryに保存
await tmws.store_memory(
    namespace="mcp_hub:preferences",
    content={
        "server_id": server_id,
        "approved": True,
        "trust_override": 0.9
    },
    importance=0.7,
    tags=["user-preference", server_id]
)
```

**ChromaDB Collection Separation:**
- `tmws_memories` - 既存、変更なし
- `tmws_tools` - 新規、ツールメタデータ専用

### 5.2 ナラティブ (Narrative) Integration

```python
# ツール発見コンテキストをNarrativeに提供
narrative_context = {
    "phase": "tool_discovery",
    "agent": "athena",
    "message": f"Found {len(results)} tools for '{query}'",
    "context": {
        "search_query": query,
        "top_result": results[0].tool_name,
        "source_breakdown": {
            "skills": skills_count,
            "external": external_count
        }
    }
}
```

### 5.3 スキル (Skills) Integration

**Skills優先ランキング:**
```python
# search_tools内のランキング
def calculate_score(result: ToolSearchResult) -> float:
    base_score = result.relevance_score

    # Skills get 2x boost (第3特徴優先)
    if result.source_type == "skill":
        return base_score * 2.0
    elif result.source_type == "internal":
        return base_score * 1.5
    else:
        return base_score * 1.0
```

**Tool → Skill Promotion:**
```python
# 高使用率ツールをSkillに昇格
async def promote_to_skill(tool: ToolMetadata, usage_stats: dict):
    if usage_stats["count"] > 100 and usage_stats["success_rate"] > 0.95:
        await skill_service.create_skill(
            name=f"Promoted: {tool.name}",
            description=tool.description,
            source_tool=tool,
            promoted_at=datetime.now()
        )
```

### 5.4 学習 (Learning) Integration

**Adaptive Ranking:**
```python
class AdaptiveToolRanker:
    """ツール使用パターンから適応的にランキングを調整"""

    async def record_outcome(
        self,
        query: str,
        selected_tool: str,
        outcome: str  # "success" | "error" | "abandoned"
    ):
        # Learningシステムにパターン記録
        await learning_service.record_pattern(
            pattern_type="tool_usage",
            query=query,
            tool=selected_tool,
            outcome=outcome,
            timestamp=datetime.now()
        )

    async def get_personalized_ranking(
        self,
        query: str,
        base_results: list[ToolSearchResult]
    ) -> list[ToolSearchResult]:
        # 過去のパターンからランキングを調整
        patterns = await learning_service.get_patterns(
            pattern_type="tool_usage",
            similar_to=query
        )
        return self._apply_learned_weights(base_results, patterns)
```

---

## 6. API Specifications

### 6.1 New MCP Tools

```python
# Tool Search
@mcp_tool
async def search_tools(
    query: str,
    source: str = "all",
    limit: int = 10
) -> list[dict]:
    """ツールをセマンティック検索"""

# MCP Server Management
@mcp_tool
async def connect_mcp_server(server_id: str) -> dict:
    """外部MCPサーバーに接続"""

@mcp_tool
async def disconnect_mcp_server(server_id: str) -> dict:
    """外部MCPサーバーから切断"""

@mcp_tool
async def list_mcp_servers() -> list[dict]:
    """接続可能なMCPサーバー一覧"""

@mcp_tool
async def get_mcp_status() -> dict:
    """MCPハブの状態を取得"""

# Tool Forwarding (動的登録)
# 外部ツールは mcp__{server}__{tool} の形式で自動登録
# 例: mcp__context7__resolve_library_id
```

### 6.2 Configuration Schema

```yaml
# ~/.tmws/mcp_hub.yaml
mcp_hub:
  enabled: true

  servers:
    context7:
      type: stdio
      command: ["npx", "-y", "@upstash/context7-mcp"]
      auto_connect: true
      trust_level: high

    serena:
      type: stdio
      command: ["uvx", "--from", "serena-mcp-server", "serena"]
      auto_connect: true
      trust_level: medium

    playwright:
      type: stdio
      command: ["npx", "-y", "@anthropic/mcp-playwright"]
      auto_connect: false
      trust_level: medium

  security:
    max_connections: 10
    timeout_seconds: 30
    require_approval: true
    audit_logging: true

  search:
    skills_weight: 2.0
    internal_weight: 1.5
    external_weight: 1.0
    cache_ttl_seconds: 3600
```

---

## 7. Implementation Phases

### Phase 1: Foundation (Week 1-2)
**Lead:** Artemis | **Support:** Metis

- [ ] Tool Discovery Engine (search_tools)
- [ ] ChromaDB collection for tools (tmws_tools)
- [ ] Basic MCP Hub Manager
- [ ] Unix socket communication setup
- [ ] Unit tests (>80% coverage)

**Gate 1 Criteria:**
- search_tools returns results from skills + internal tools
- Unit tests pass
- No regression in existing TMWS tests

### Phase 2: MCP Hub + Security (Week 3-4)
**Lead:** Artemis | **Review:** Hestia

- [ ] External MCP server connections
- [ ] Tool forwarding proxy
- [ ] P0 security controls implementation
- [ ] HMAC socket authentication
- [ ] Integration tests

**Gate 2 Criteria:**
- External tools callable via TMWS
- All P0 security tests pass
- Hestia security audit approval

### Phase 3: Platform Adapters (Week 5-6)
**Lead:** Metis | **Review:** Aphrodite

- [ ] Claude Code adapter
- [ ] OpenCode adapter
- [ ] Platform detection logic
- [ ] Configuration sync
- [ ] E2E tests both platforms

**Gate 3 Criteria:**
- Both platforms work identically
- Configuration sync verified
- UX consistency confirmed

### Phase 4: Learning Integration + Polish (Week 7-8)
**Lead:** Artemis | **Support:** Aurora

- [ ] Adaptive ranking implementation
- [ ] Tool → Skill promotion
- [ ] Performance optimization
- [ ] Documentation (Muses)
- [ ] Final security audit (Hestia)

**Final Gate Criteria:**
- All tests pass
- Performance targets met
- 4 core features verified intact
- Production deployment approved

---

## 8. Testing Requirements

### 8.1 Unit Tests

```
tests/unit/
├── test_tool_search.py
├── test_mcp_hub_manager.py
├── test_platform_adapters.py
└── test_security.py
```

### 8.2 Integration Tests

```
tests/integration/
├── test_tool_search_integration.py
├── test_external_mcp_connection.py
├── test_tool_forwarding.py
└── test_four_features_regression.py  # 4特徴回帰テスト
```

### 8.3 Security Tests

```
tests/security/
├── test_socket_auth.py
├── test_input_validation.py
├── test_sandbox.py
├── test_injection_prevention.py
└── test_audit_logging.py
```

### 8.4 Critical Test: 4 Features Regression

```python
# test_four_features_regression.py
"""
TMWSの4つの核心特徴が維持されていることを検証。
このテストは全フェーズで実行必須。
"""

async def test_memory_feature_preserved():
    """第1特徴: 記憶が正常に動作"""
    # 既存のメモリ操作が影響を受けていないことを確認
    result = await tmws.store_memory(...)
    assert result.success

    search = await tmws.search_memories(...)
    assert len(search) > 0

async def test_narrative_feature_preserved():
    """第2特徴: ナラティブが正常に動作"""
    # エージェントのナラティブ機能が維持されていることを確認
    pass

async def test_skills_feature_enhanced():
    """第3特徴: スキルが強化されている"""
    # スキルがsearch_toolsで優先されることを確認
    results = await search_tools("test query")
    skill_results = [r for r in results if r.source_type == "skill"]
    # スキルが最上位にランキングされている
    assert results[0].source_type == "skill" or len(skill_results) == 0

async def test_learning_feature_enhanced():
    """第4特徴: 学習が強化されている"""
    # ツール使用パターンが学習されることを確認
    await record_tool_usage(...)
    patterns = await learning_service.get_patterns(...)
    assert len(patterns) > 0
```

---

## 9. Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| 4特徴回帰 | Low | Critical | 全フェーズで回帰テスト実行 |
| 外部MCP不安定 | Medium | Medium | Circuit breaker + fallback |
| パフォーマンス劣化 | Medium | High | キャッシュ + 並列化 |
| セキュリティ脆弱性 | Low | Critical | Hestia監査 + P0必須実装 |
| プラットフォーム差異 | Medium | Medium | 抽象化レイヤー + 同等テスト |

---

## 10. Approval Status

| Agent | Role | Status | Date | Notes |
|-------|------|--------|------|-------|
| Hera | Strategic Design | ✅ Approved | 2025-12-04 | 3層アーキテクチャ承認 |
| Athena | Coordination | ✅ Approved | 2025-12-04 | リソース計画承認 |
| Eris | Tactical Decision | ✅ Approved | 2025-12-04 | Hybrid実装承認 |
| Hestia | Security Review | 🟡 Conditional | 2025-12-04 | P0必須、3-5日ハードニング |
| Artemis | Technical Review | Pending | - | Phase 1開始前にレビュー |
| Muses | Documentation | Pending | - | Phase 4で最終化 |

---

## Appendix A: Related Documents

- `docs/specifications/tool-search-mcp-hub/SECURITY_ANALYSIS.md`
- `docs/specifications/tool-search-mcp-hub/IMPLEMENTATION_CHECKLIST.md`
- `.serena/memories/tool_search_mcp_hub_spec.md`
- TMWS Memory: namespace `tmws-core`, tags `["tool-search", "mcp-hub"]`

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| MCP | Model Context Protocol |
| Tool Search | セマンティック検索によるツール発見機能 |
| MCP Hub | 複数MCPサーバーの統一管理ハブ |
| 4特徴 | TMWS核心: 記憶・ナラティブ・スキル・学習 |
| P0/P1/P2 | 優先度 (P0=必須, P1=高優先, P2=推奨) |

---

**Document Version:** 1.0.0
**Status:** Approved with Security Conditions
**Next Review:** After Phase 1 completion
