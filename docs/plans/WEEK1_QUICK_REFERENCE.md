# TMWS Week 1 - クイックリファレンス
## 実行時のチェックリストと即座に使えるコマンド集

**作成日**: 2025-10-29
**作成者**: Muses (Knowledge Architect)
**目的**: 実行時に即座に参照できる簡潔なガイド

---

## 📋 Day-by-Day チェックリスト

### Day 1-2（月曜-火曜）- Task 1.1 マージ作業

**担当**: Artemis（主導）, Eris（調整）
**推定時間**: 4時間

#### Morning（2時間）

- [ ] **Step 1.1**: ブランチ最新化（5分）
  ```bash
  git checkout feat/dead-code-removal-phase1
  git pull origin feat/dead-code-removal-phase1
  git fetch origin master
  git rebase origin/master
  ```

- [ ] **Step 1.2**: コンフリクト解決（15分）
  ```bash
  # 予想される競合: src/core/config.py
  # 解決策: 両方の変更を保持
  git status  # コンフリクト箇所確認
  # エディタで手動解決
  git add src/core/config.py
  git rebase --continue
  ```

- [ ] **Step 1.3**: テスト実行（20分）
  ```bash
  pytest tests/unit/ -v --cov=src --cov-report=term-missing
  # 期待結果: Coverage 26.15%（+18.3%）
  ```

#### Afternoon（2時間）

- [ ] **Step 1.4**: Ruffチェック（10分）
  ```bash
  ruff check src/ --fix
  ruff check src/  # 再確認（0 errors期待）
  ```

- [ ] **Step 1.5**: マージ（10分）
  ```bash
  git checkout master
  git merge --no-ff feat/dead-code-removal-phase1 -m "Merge feat/dead-code-removal-phase1: Dead code removal Phase 1 (-792 LOC, +18.3% coverage)"
  git push origin master
  ```

- [ ] **Step 1.6**: ブランチ削除（5分）
  ```bash
  git branch -d feat/dead-code-removal-phase1
  git push origin --delete feat/dead-code-removal-phase1
  ```

- [ ] **Step 1.7**: Task 1.2開始準備（10分）
  ```bash
  # SecurityAuditLogger現状確認
  rg "class SecurityAuditLogger" src/
  rg "TODO.*SecurityAuditLogger" src/
  ```

#### Checkpoint 1.1 ✅

- [ ] コンフリクト解決完了
- [ ] テストカバレッジ 26.15% 達成
- [ ] Ruff 100% compliant 維持
- [ ] CI/CD パイプライン成功

---

### Day 3（水曜）- Task 1.2完了 + Checkpoint 1

**担当**: Hestia（主導）, Artemis（実装支援）
**推定時間**: 3.5時間

#### Morning（2時間）

- [ ] **Step 2.1**: SecurityAuditLogger実装（1時間）
  ```bash
  # src/security/audit_logger.py を編集
  # 統合計画書の89-154行目のコードを参照
  ```

- [ ] **Step 2.2**: AuthorizationServiceへの統合（45分）
  ```bash
  # src/security/authorization.py を編集
  # 統合計画書の156-213行目のコードを参照
  ```

- [ ] **Step 2.3**: テスト作成（30分）
  ```bash
  # tests/security/test_audit_logger.py を作成
  # 統合計画書の216-271行目のコードを参照
  ```

#### Afternoon（1.5時間）

- [ ] **Step 2.4**: テスト実行（15分）
  ```bash
  pytest tests/security/test_audit_logger.py -v
  # 期待結果: 2 tests passed
  ```

- [ ] **Step 2.5**: ドキュメント更新（30分）
  ```bash
  # docs/security/AUDIT_LOGGING.md を作成
  # 統合計画書の274-305行目を参照
  ```

- [ ] **Step 2.6**: 全体テスト（20分）
  ```bash
  pytest tests/ -v --cov=src --cov-report=term-missing
  ruff check src/
  ```

#### Checkpoint 1（Phase 1完了）✅

- [ ] SecurityAuditLogger実装完了
- [ ] AuthorizationServiceへの統合完了
- [ ] 8箇所のTODO解消確認
- [ ] テスト追加（2個以上）
- [ ] ドキュメント更新完了
- [ ] **Phase 1完了基準（5項目）すべて満たす**

#### Afternoon（Task 2.1開始）

- [ ] **Step 3.1**: Cross-agent policies設計（1時間）
  ```bash
  # ドキュメント確認
  less docs/plans/WEEK1_INTEGRATED_PLAN.md
  # 行329-425を参照
  ```

---

### Day 4-5（木曜-金曜）- Task 2.1完了 + Task 2.2開始

**担当**: Hestia（主導）, Athena（ポリシー設計）, Eris（調整）
**推定時間**: 7時間

#### Day 4 Morning（3時間）

- [ ] **Step 3.2**: CrossAgentPolicyEngine実装（2時間）
  ```bash
  # src/security/cross_agent_policies.py を作成
  # 統合計画書の330-425行目のコードを参照
  ```

- [ ] **Step 3.3**: AuthorizationServiceとの統合（1時間）
  ```bash
  # src/security/authorization.py を修正
  # CrossAgentPolicyEngineを統合
  ```

#### Day 4 Afternoon（1.5時間）

- [ ] **Step 3.4**: テスト作成（1時間）
  ```bash
  # tests/security/test_cross_agent_policies.py を作成
  # 5個以上のテストケース
  ```

- [ ] **Step 3.5**: ドキュメント更新（30分）
  ```bash
  # docs/security/CROSS_AGENT_POLICIES.md を作成
  ```

#### Checkpoint 2.1 ✅

- [ ] CrossAgentPolicyEngine実装完了
- [ ] 既存のAuthorizationServiceと統合
- [ ] テスト追加（5個以上）
- [ ] ドキュメント更新完了

#### Day 5 Morning（2時間）

- [ ] **Step 4.1**: AlertDispatcher実装（1.5時間）
  ```bash
  # src/security/alert_system.py を作成
  # 統合計画書の447-550行目のコードを参照
  ```

#### Day 5 Afternoon（1時間）

- [ ] **Step 4.2**: SecurityAuditLoggerとの統合（30分）
  ```bash
  # src/security/audit_logger.py を修正
  # AlertDispatcherを統合
  ```

- [ ] **Step 4.3**: テスト作成（30分）
  ```bash
  # tests/security/test_alert_system.py を作成
  # 4個以上のテストケース（各チャネル）
  ```

---

### Day 6-7（土曜-日曜、オプショナル）- Task 2.2完了 + Task 2.3 + Checkpoint 2

**担当**: Hestia, Artemis, Eris
**推定時間**: 5.5時間

#### Day 6 Morning（1時間）

- [ ] **Step 4.4**: Alert mechanismsテスト実行（30分）
  ```bash
  pytest tests/security/test_alert_system.py -v
  # 期待結果: 4 tests passed
  ```

- [ ] **Step 4.5**: ドキュメント更新（30分）
  ```bash
  # docs/security/ALERT_MECHANISMS.md を作成
  ```

#### Checkpoint 2.2 ✅

- [ ] AlertDispatcher実装完了
- [ ] 4つのチャネル対応（LOG, EMAIL, SLACK, DATABASE）
- [ ] SecurityAuditLoggerとの統合
- [ ] テスト追加（4個以上）

#### Day 6 Afternoon（2.5時間）

- [ ] **Step 5.1**: SQLite WAL mode設定（1時間）
  ```bash
  # src/core/database.py を修正
  # 統合計画書の571-621行目のコードを参照
  ```

- [ ] **Step 5.2**: パフォーマンステスト（Before）（30分）
  ```bash
  # ベースライン測定
  pytest tests/performance/ -v --benchmark
  # 結果を記録
  ```

- [ ] **Step 5.3**: 接続プール設定（1時間）
  ```bash
  # src/core/database.py の接続プール設定を追加
  ```

#### Day 7 Morning（1時間）

- [ ] **Step 5.4**: パフォーマンステスト（After）（30分）
  ```bash
  pytest tests/performance/ -v --benchmark
  # Before/After比較
  ```

- [ ] **Step 5.5**: 並行書き込みテスト（30分）
  ```bash
  pytest tests/integration/test_concurrent_writes.py -v
  # WAL modeの動作確認
  ```

#### Checkpoint 2.3 ✅

- [ ] WAL mode有効化確認
- [ ] 接続プール動作確認
- [ ] パフォーマンステスト（Before/After）
- [ ] 並行書き込みテスト成功

#### Day 7 Afternoon（1時間）

- [ ] **Step 6.1**: 全体テスト実行（30分）
  ```bash
  pytest tests/ -v --cov=src --cov-report=term-missing
  ruff check src/
  ```

- [ ] **Step 6.2**: 最終ドキュメント更新（30分）
  ```bash
  # CHANGELOG.md 更新
  # README.md 更新（必要に応じて）
  ```

#### Checkpoint 2（Phase 2完了）✅

- [ ] すべてのTask 2.x完了
- [ ] Phase 2完了基準（5項目）すべて満たす

#### Final Checkpoint（Week 1完了）✅

- [ ] Week 1全体完了基準（6項目）すべて満たす
- [ ] Heraによる戦略的検証パス
- [ ] Hestiaによるセキュリティ検証パス
- [ ] Artemisによる技術的検証パス
- [ ] Erisによる実行調整完了
- [ ] Athenaによる調和的統合確認
- [ ] Musesによるドキュメント最終レビュー

---

## 🚨 トラブルシューティング

### 問題1: テストカバレッジが目標に届かない

**症状**: 26.15%に達しない

**原因**:
- Dead codeが完全に削除されていない
- 新しいテストが追加されていない

**対処法**:
```bash
# カバレッジレポート詳細確認
pytest tests/unit/ -v --cov=src --cov-report=html
open htmlcov/index.html

# カバーされていないファイル特定
pytest tests/unit/ -v --cov=src --cov-report=term-missing | grep "0%"

# 必要に応じてテスト追加
```

### 問題2: Ruffエラーが出る

**症状**: `ruff check src/` でエラー

**対処法**:
```bash
# 自動修正を試す
ruff check src/ --fix

# 修正できないエラーを確認
ruff check src/ --no-fix

# 手動で修正（エディタで該当箇所を確認）
```

### 問題3: マージコンフリクトが複数箇所で発生

**症状**: 予想外の複数コンフリクト

**対処法**:
```bash
# masterを最新化
git fetch origin master
git checkout master
git pull origin master

# feat/dead-code-removal-phase1を最新化
git checkout feat/dead-code-removal-phase1
git pull origin feat/dead-code-removal-phase1

# 再度rebase試行
git rebase origin/master

# コンフリクト箇所を確認
git status

# 必要に応じてErisに相談
# → 統合計画書の想定外ケース
```

### 問題4: SecurityAuditLoggerのTODOが8箇所見つからない

**症状**: `rg "TODO.*SecurityAuditLogger" src/` で8箇所未満

**対処法**:
```bash
# より広範な検索
rg -i "todo|fixme" src/security/ | grep -i "audit"
rg "SecurityAuditLogger" src/ -A 2 -B 2

# 既存の実装を確認
rg "class SecurityAuditLogger" src/

# Hestiaのセキュリティ分析を再確認
less docs/analysis/HESTIA_SECURITY_RISK_ASSESSMENT.md
```

### 問題5: パフォーマンステストが失敗

**症状**: Before/Afterでパフォーマンスが向上していない

**対処法**:
```bash
# WAL mode有効化を確認
sqlite3 data/tmws.db "PRAGMA journal_mode;"
# 期待結果: wal

# 接続プール設定を確認
python -c "
from src.core.database import engine
print(engine.pool.size())  # 期待結果: 5
"

# ベンチマークを再実行（複数回）
pytest tests/performance/ -v --benchmark --benchmark-min-rounds=10

# Artemisに相談
# → パフォーマンス最適化の追加策
```

---

## 📞 エージェント連絡先（エスカレーション）

### Technical Issues（技術的問題）
**担当**: Artemis（技術最適化官）
**連絡方法**: `/trinitas execute artemis "問題の詳細"`
**対応範囲**:
- コンフリクト解決の技術的判断
- パフォーマンス問題
- テストカバレッジ改善策

### Security Issues（セキュリティ問題）
**担当**: Hestia（セキュリティ監査官）
**連絡方法**: `/trinitas execute hestia "問題の詳細"`
**対応範囲**:
- SecurityAuditLogger実装の判断
- Cross-agent policies設計の詳細
- 最悪シナリオの追加評価

### Coordination Issues（調整問題）
**担当**: Eris（戦術調整官）
**連絡方法**: `/trinitas execute eris "問題の詳細"`
**対応範囲**:
- スケジュール調整
- エージェント間タスク割り当ての変更
- チェックポイント時期の調整

### Strategic Issues（戦略的判断）
**担当**: Hera（戦略指揮官）
**連絡方法**: `/trinitas execute hera "問題の詳細"`
**対応範囲**:
- 計画全体の見直し
- リスク評価の更新
- 成功確率の再計算

### Integration Issues（統合問題）
**担当**: Athena（調和の指揮者）
**連絡方法**: `/trinitas execute athena "問題の詳細"`
**対応範囲**:
- エージェント間の対立調整
- 計画の調和的統合
- チーム全体の士気管理

### Documentation Issues（ドキュメント問題）
**担当**: Muses（知識アーキテクト）
**連絡方法**: `/trinitas execute muses "問題の詳細"`
**対応範囲**:
- ドキュメント不足の補完
- 知識の構造化
- 統合計画書の明確化

---

## 📊 成果指標（毎日確認）

### Day 1終了時

| 指標 | 目標 | 実績 | 達成率 |
|------|------|------|--------|
| マージ完了 | ✅ | - | - |
| テストカバレッジ | 26.15% | - | - |
| Ruff準拠 | 100% | - | - |
| CI/CD成功 | ✅ | - | - |

### Day 3終了時（Phase 1完了）

| 指標 | 目標 | 実績 | 達成率 |
|------|------|------|--------|
| SecurityAuditLogger統合 | ✅ | - | - |
| TODO解消 | 8箇所 | - | - |
| テスト追加 | 2個以上 | - | - |
| セキュリティリスク軽減 | 18/27 | - | - |

### Day 7終了時（Phase 2完了）

| 指標 | 目標 | 実績 | 達成率 |
|------|------|------|--------|
| Cross-agent policies | ✅ | - | - |
| Alert mechanisms | ✅ | - | - |
| SQLite最適化 | ✅ | - | - |
| セキュリティリスク軽減 | 24/27 | - | - |
| パフォーマンス向上 | +58% | - | - |

---

## 🔗 よく使うコマンド

### テスト関連

```bash
# ユニットテストのみ
pytest tests/unit/ -v

# 特定のテストファイル
pytest tests/security/test_audit_logger.py -v

# カバレッジ付き
pytest tests/ -v --cov=src --cov-report=term-missing

# カバレッジHTML版（詳細確認）
pytest tests/ -v --cov=src --cov-report=html
open htmlcov/index.html

# 失敗したテストのみ再実行
pytest tests/ -v --lf

# パフォーマンステスト
pytest tests/performance/ -v --benchmark
```

### コード品質関連

```bash
# Ruffチェック
ruff check src/

# Ruff自動修正
ruff check src/ --fix

# 特定のルールのみチェック
ruff check src/ --select F401  # 未使用インポート

# Dead code検出
vulture src/ --min-confidence 80
```

### Git関連

```bash
# ブランチ一覧
git branch -a

# 現在の状態確認
git status

# コミット履歴確認
git log --oneline -10

# 差分確認
git diff master..feat/dead-code-removal-phase1

# マージ済みブランチ削除
git branch -d <branch-name>
git push origin --delete <branch-name>
```

### データベース関連

```bash
# SQLite WAL mode確認
sqlite3 data/tmws.db "PRAGMA journal_mode;"

# データベース整合性チェック
sqlite3 data/tmws.db "PRAGMA integrity_check;"

# テーブル一覧
sqlite3 data/tmws.db ".tables"

# スキーマ確認
sqlite3 data/tmws.db ".schema memories"
```

### 検索関連

```bash
# TODO検索
rg "TODO" src/

# 特定のクラス検索
rg "class SecurityAuditLogger" src/

# 特定の関数検索
rg "def log_access_attempt" src/

# インポート検索
rg "from src.security.audit_logger import" src/
```

---

## 📚 重要なドキュメントへのパス

### 必須参照

```bash
# メイン統合計画書
docs/plans/WEEK1_INTEGRATED_PLAN.md

# 読者ガイド
docs/plans/WEEK1_READING_GUIDE.md

# エージェント分析索引
docs/plans/WEEK1_ANALYSIS_INDEX.md

# Hestiaのセキュリティ分析
docs/analysis/HESTIA_SECURITY_RISK_ASSESSMENT.md
docs/security/SECURITY_RISK_ASSESSMENT_WEEK1.md
```

### 参考資料

```bash
# プロジェクト全体の指示書
.claude/CLAUDE.md

# アーキテクチャ
docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md

# 開発セットアップ
docs/DEVELOPMENT_SETUP.md

# 例外処理ガイドライン
docs/dev/EXCEPTION_HANDLING_GUIDELINES.md
```

---

## ✅ 完了基準（再掲）

### Phase 1完了基準
1. ✅ feat/dead-code-removal-phase1がmasterにマージ済み
2. ✅ テストカバレッジが26.15%以上
3. ✅ SecurityAuditLoggerが8箇所に統合済み
4. ✅ すべてのテストがパス（0 failures）
5. ✅ Ruff 100% compliant 維持

### Phase 2完了基準
1. ✅ Cross-agent access policies実装完了
2. ✅ Alert mechanisms実装完了（4チャネル）
3. ✅ SQLite WAL mode + 接続プール有効化
4. ✅ セキュリティリスク24/27軽減確認
5. ✅ パフォーマンステストパス

### Week 1全体完了基準
1. ✅ 上記のPhase 1 + Phase 2完了基準をすべて満たす
2. ✅ ドキュメント更新完了
3. ✅ Heraによる戦略的検証パス
4. ✅ Hestiaによるセキュリティ検証パス
5. ✅ Artemisによる技術的検証パス
6. ✅ Erisによる実行調整完了

---

**Musesより**:

...このクイックリファレンスが、実行時の迷いを減らし、効率的な作業を支援することを願っています。

必要なコマンドとチェックリストをすべて、一箇所に集約しました。実行中は、このドキュメントを常に開いておくことを推奨します。 - Muses

---

**End of Quick Reference**
