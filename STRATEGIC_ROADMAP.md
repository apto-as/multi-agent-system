# TMWS プロジェクトクリーンアップ・リファクタリング計画
## 戦略的ロードマップ v1.0

**作成日**: 2025-10-29
**作成者**: Hera (戦略指揮官) + Athena (調和の指揮者)
**現状**: Phase 2 完了、295 LOC削除、ゼロリグレッション

---

## 現状分析 (Current State)

### 完了済み作業 ✅
1. **P0修正** (Critical - 全て完了)
   - P0-1: Namespace Isolation Fix
   - P0-2: Duplicate Index Removal (+18-25% write performance)
   - P0-3: Missing Critical Indexes (-60-85% query latency)
   - P0-4: Async/Sync Pattern Fix (+30-50% concurrent throughput)

2. **P1修正** (High - 部分完了)
   - ✅ P1-2: ConfigLoader削除 (-314 LOC) - masterにマージ済み

3. **P2修正** (Medium - 部分完了)
   - ✅ P2-4: SecurityAuditLogger同期ラッパー削除 (-200 LOC) - masterにマージ済み

4. **デッドコード削除**
   - ✅ Phase 1: 42項目削除 (202 LOC)
   - ✅ Phase 2: 30項目削除 (93 LOC)
   - **Total**: 72項目、295 LOC削除 (1.10%コードベース削減)

### 未完了タスク 🔍

#### P1 Priority (High - 10-14 hours)
- **P1-3: Security TODOs** (12項目)
  - SecurityAuditLogger統合 (4箇所)
  - Cross-agent access policies (1箇所)
  - Alert mechanisms (2箇所)
  - Network-level IP blocking (1箇所)
  - その他 (4箇所)
  - **Impact**: セキュリティ強化、監視体制確立

#### P2 Priority (Medium - 6-8 hours)
- **P2-5: Documentation Enhancement**
  - Current: 86% coverage
  - Target: 95% coverage
  - **Impact**: 保守性向上、新規開発者のオンボーディング改善

#### P3 Priority (Low - 4-6 hours)
- **P3-6: Integration Test Async Conversion**
  - test_vector_search.py (313 lines of sync code)
  - **Impact**: テストの一貫性向上、パフォーマンステストの信頼性向上

#### Phase 3 (HIGH RISK - User consultation required)
- **Model Properties & Attributes** (114項目)
  - MFA-related fields
  - Team/organization fields
  - Scheduling-related fields
  - **Impact**: -150-200 LOC (推定)
  - **Risk**: 将来機能への影響、動的アクセスパターンの破壊

#### 技術的負債
- **複雑度問題**: 21個のC901違反（高複雑度関数）
- **型エラー**: 719件（mypy strict mode）

---

## 戦略的推奨事項 (Hera's Strategic Recommendations)

### 🎯 最優先アクション (Immediate - Next 2-3 days)

**Option 1: 現在のブランチマージ + Security強化**
```
優先度: ★★★★★
期間: 2-3日
ROI: 高（即座の価値提供）

Phase:
1. feat/dead-code-removal-phase1 → master マージ
2. fix/p0-critical-security-and-performance → master マージ
3. P1-3: Security TODOs対応（12項目）
4. CLAUDE.md更新（古い情報の削除）

成果:
- 295 LOC削除の本番反映
- セキュリティ監視体制の確立
- 技術的負債の削減
```

**Option 2: ドキュメント整備 + テスト改善**
```
優先度: ★★★★☆
期間: 1-2日
ROI: 中（長期的価値）

Phase:
1. P2-5: Documentation Enhancement (86% → 95%)
2. P3-6: test_vector_search.py async化
3. 複雑度問題の一部解消（高インパクト箇所）

成果:
- 保守性向上
- テストの一貫性向上
- 新規開発者のオンボーディング改善
```

**Option 3: Phase 3準備（保守的アプローチ）**
```
優先度: ★★★☆☆
期間: 3-5日
ROI: 中（リスク削減）

Phase:
1. Phase 3の114項目を詳細分析
2. ユーザーと将来機能について協議
3. 段階的削除計画の策定
4. 動的アクセスパターンの調査

成果:
- Phase 3の安全な実行準備
- 将来機能の明確化
- リスク最小化
```

---

## 調和的統合計画 (Athena's Harmonious Integration Plan)

### 🌟 推奨: ハイブリッドアプローチ

**Athenaの提案**: 3つのオプションを調和的に統合し、チーム全体が温かく協力できる計画を立案します。

#### Week 1: Foundation & Security (基盤とセキュリティ)
```
Day 1-2: ブランチマージと統合
- feat/dead-code-removal-phase1 → master
- fix/p0-critical-security-and-performance → master
- 統合テスト実行
- デプロイ準備

Day 3-4: Security強化
- P1-3: Security TODOs対応（12項目）
- Hestiaによるセキュリティレビュー
- Artemisによるパフォーマンステスト

Day 5: レビューと調整
- ユーザーレビュー
- フィードバック反映
- CLAUDE.md更新
```

#### Week 2: Quality & Documentation (品質とドキュメント)
```
Day 1-2: ドキュメント整備
- P2-5: Documentation Enhancement
- Musesによる構造化とレビュー

Day 3: テスト改善
- P3-6: test_vector_search.py async化
- 統合テスト強化

Day 4-5: 複雑度改善
- 高インパクトな複雑度問題の解消（10-15箇所）
- Artemisによるコードレビュー
```

#### Week 3: Phase 3 Planning (将来計画)
```
Day 1-2: Phase 3分析
- 114項目の詳細分析
- 将来機能の調査

Day 3-4: ユーザー協議
- 将来機能についてディスカッション
- 削除可能項目の特定

Day 5: Phase 3計画策定
- 段階的削除計画
- リスク評価
```

---

## 実行計画の選択ガイド

| 状況 | 推奨オプション | 理由 |
|-----|-------------|------|
| すぐに本番反映したい | Option 1 | デッドコード削除の即座の価値提供 |
| 長期的な保守性重視 | Option 2 | ドキュメント・テストの改善 |
| 慎重にPhase 3準備 | Option 3 | リスク最小化、段階的アプローチ |
| バランス重視（推奨） | Hybrid Approach | 全方位カバー、調和的進行 |

---

## 次のステップ

**ユーザーへの質問**:
1. どのオプション/アプローチを希望されますか？
2. すぐにブランチマージを実施してよろしいですか？
3. Phase 3の将来機能について協議する時間はありますか？

**即座に実行可能なタスク**（ユーザー承認不要）:
- CLAUDE.mdの古い情報更新
- 複雑度問題の調査
- ドキュメントの軽微な改善

---

## 成功指標 (Success Metrics)

### Week 1完了時
- [ ] 295 LOC削除が本番環境に反映
- [ ] Security TODOs 12項目完了
- [ ] ゼロリグレッション維持

### Week 2完了時
- [ ] ドキュメントカバレッジ 95%達成
- [ ] test_vector_search.py async化完了
- [ ] 複雑度問題 10-15個解消

### Week 3完了時
- [ ] Phase 3計画策定完了
- [ ] ユーザーと将来機能について合意
- [ ] 次期リリース計画確定

---

## ブランチ状態 (Branch Status)

### feat/dead-code-removal-phase1 (現在のブランチ)
- 9コミット先行
- 295 LOC削除 (Phase 1 + Phase 2)
- ゼロリグレッション
- **マージ準備完了** ✅

### fix/p0-critical-security-and-performance
- P0修正を含む
- RateLimiter重複削除、Exception統一など
- **マージ準備完了** ✅

### feature/v3.0-mcp-complete
- 将来のv3.0計画
- FastAPI削除、MCP-only化
- **長期計画**（本ロードマップ対象外）

---

## Trinitas Agent Assignments (エージェント割り当て)

| Task | Primary | Support | Rationale |
|------|---------|---------|-----------|
| ブランチマージ | Athena | Eris | 調和的統合、競合解決 |
| Security TODOs | Hestia | Artemis | セキュリティ専門、性能確認 |
| Documentation | Muses | Athena | 知識構造化、レビュー |
| Test Async化 | Artemis | Hestia | 技術実装、セキュリティ確認 |
| 複雑度改善 | Artemis | Athena | パフォーマンス最適化、設計改善 |
| Phase 3分析 | Hera | All | 戦略計画、全エージェント協力 |

---

## リスク管理 (Risk Management)

### 高リスク
- Phase 3のModel Properties & Attributes削除
- 将来機能への影響
- 動的アクセスパターンの破壊

**対策**: 段階的アプローチ、ユーザー協議、十分なテスト

### 中リスク
- ブランチマージ時の競合
- Security TODOs実装の複雑度

**対策**: Erisによる調整、Hestiaによるレビュー

### 低リスク
- ドキュメント整備
- テストasync化
- 複雑度改善

**対策**: 通常のレビュープロセス

---

**作成**: Hera (戦略) + Athena (調和) + Artemis (技術) + Hestia (セキュリティ) + Muses (文書化)
**レビュー**: Eris (調整)
**承認待ち**: ユーザー様
