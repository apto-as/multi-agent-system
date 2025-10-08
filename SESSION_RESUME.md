# セッション再開ガイド - プロジェクトクリーンアップ継続

**作成日**: 2025-01-10
**前回セッション**: Phase A部分完了（ARGエラー修正）
**最終コミット**: `be12375` - refactor: Phase A partial - Fix ARG errors in routers and websocket (159→87)

---

## 📊 現在の進捗状況

### ✅ 完了した作業（Phase A - 部分完了）

1. **Ruff自動修正実行**
   - 220件のエラーを自動修正
   - import順序、未使用import、コード簡略化など

2. **ARGエラー削減**: 159件 → 87件（72件削減）
   - `src/api/routers/security.py`: `current_agent`使用箇所を全て修正
   - `src/api/routers/agent.py`: 未使用`current_user`を`_current_user`に変更（3箇所）
   - `src/api/websocket_mcp.py`: 未使用`params`/`session`引数を修正（10箇所）
   - `src/tools/*.py`: `session`引数を一括で`_session`に変更

3. **変更ファイル**: 36ファイル（+215, -253行）

### 📋 残作業の詳細

#### Phase A: 自動修正実行（Priority 1）- 継続
```bash
# 現在のエラー統計
ARG001: 69件（未使用関数引数）
ARG002: 18件（未使用メソッド引数）
合計: 87件

# その他のRuffエラー（推定100件）
SIM117: 12件（複数with文の統合可能）
SIM102: 10件（ネストif文の簡略化可能）
F821: 7件（未定義名の参照）
E402: 5件（importが先頭にない）
E722: 1件（bare except）
```

**主な残存箇所**:
- `src/tools/*.py`: 38件（services引数など）
- `src/services/*.py`: pattern_execution_service.py（4件）
- `src/core/database.py`: 4件
- `src/api/routers/security.py`: 4件

#### Phase B: 重複コード統合（Priority 2）
1. **sanitize関数の統合**（4箇所に散在）
   - `src/api/routers/memory.py`
   - `src/security/html_sanitizer.py`
   - `src/security/pattern_validator.py`
   - `src/security/validators.py`
   → 統合先: `src/security/validators.py`

2. **Service層の統一**（16個のServiceクラス）
   - 一部は`BaseService`継承、一部は独立
   → 全て`BaseService`継承に統一

3. **重複ファイルの整理**
   - `security.py` × 3箇所
   - `memory.py` × 2箇所
   - `agent.py` × 2箇所

#### Phase C: アーキテクチャ改善（Priority 3）
1. TODO/FIXME実装または削除（12件、全て`src/security/`配下）
2. 不要ファイル削除
   - 検証スクリプト: 2件
   - WIP/TODOドキュメント: 10件
3. ServiceManager重複の解消

#### Phase D: コミット・テスト
- 全テストスイート実行
- CI/CDパイプライン確認

---

## 🚀 新しいセッションでの開始手順

### 1. 状況確認コマンド

```bash
# 現在のブランチとコミット確認
git log --oneline -5

# 最新のエラー統計
ruff check src/ --select ARG001,ARG002 --statistics

# 全エラー確認
ruff check src/ --statistics

# 変更状況（クリーンであることを確認）
git status
```

### 2. 次のセッションで最初に伝えること

```
前回セッション（be12375）からプロジェクトクリーンアップの続きを行います。
SESSION_RESUME.mdを読み、Phase Aの残り87件のARGエラーから継続してください。

優先順位:
1. Phase A残り（ARGエラー87件 + その他Ruffエラー100件）
2. Phase B（重複コード統合）
3. Phase C（アーキテクチャ改善）
4. Phase D（テスト・コミット）

Trinitasフルモードで慎重に進めてください。
```

### 3. 推奨する作業フロー

#### Step 1: ARGエラーの残り修正
```bash
# tools配下の残りエラー確認
ruff check src/tools/ --select ARG001,ARG002

# services配下の確認
ruff check src/services/pattern_execution_service.py --select ARG001,ARG002

# database.pyの確認
ruff check src/core/database.py --select ARG001,ARG002
```

**注意点**:
- FastAPI依存性注入の引数は、認証のために必要だが使用しない場合がある
- 実際にコード内で参照しているかを必ず確認してから`_`プレフィックスを付ける
- 一括sedは危険（前回の教訓）- 個別に確認すること

#### Step 2: その他Ruffエラー修正
```bash
# SIM117（複数with文）の確認
ruff check src/ --select SIM117

# SIM102（ネストif）の確認
ruff check src/ --select SIM102

# F821（未定義名）の確認（最優先）
ruff check src/ --select F821
```

#### Step 3: 重複コード統合
```bash
# sanitize関数の検索
grep -rn "def sanitize" src/

# BaseService継承の確認
grep -rn "class.*Service" src/services/ | grep -v "BaseService"
```

---

## 📝 重要な教訓（次のセッションで注意）

### ❌ 避けるべきこと
1. **一括sed変更の危険性**
   ```bash
   # これは危険！実際に使用している箇所も変更される
   sed -i '' 's/current_agent:/_current_agent:/g'
   ```

2. **未確認での変更**
   - 引数名を変更する前に、関数内で使用しているか必ず確認
   - `grep -n "変数名\." ファイル名` で使用箇所を検索

### ✅ 推奨するアプローチ
1. **個別確認**
   ```bash
   # エラー箇所を特定
   ruff check ファイル名 --select ARG001

   # 使用箇所を確認
   grep -n "引数名" ファイル名

   # 使用していなければ Edit ツールで個別修正
   ```

2. **段階的コミット**
   - ファイル種別ごとにコミット（routers/, tools/, services/）
   - 各段階でテストを実行

---

## 🔍 クイックリファレンス

### Ruffエラーコード
- **ARG001**: 未使用関数引数
- **ARG002**: 未使用メソッド引数
- **SIM117**: 複数with文を統合可能
- **SIM102**: ネストif文を簡略化可能
- **F821**: 未定義名の参照
- **F401**: 未使用import
- **E722**: bare except
- **E402**: importが先頭にない

### 便利なコマンド
```bash
# 特定エラーコードのみ表示
ruff check src/ --select ARG001,ARG002

# 自動修正（安全なもののみ）
ruff check src/ --fix

# 自動修正（unsafe含む）
ruff check src/ --fix --unsafe-fixes

# ファイル別統計
ruff check src/ --statistics

# 詳細表示
ruff check src/ --show-source
```

---

## 📞 問題が発生した場合

### Git操作でのロールバック
```bash
# 最後のコミットを取り消し（変更は保持）
git reset --soft HEAD^

# 特定ファイルを前のコミットに戻す
git checkout HEAD -- ファイル名

# 全変更を破棄して前のコミットに戻る
git reset --hard HEAD
```

### テスト実行
```bash
# 全テスト
pytest tests/ -v

# 特定テスト
pytest tests/unit/test_api_router_functions.py -v

# カバレッジ付き
pytest tests/ -v --cov=src --cov-report=term
```

---

## ✨ 期待される最終状態（Phase A~C完了時）

- [ ] Ruffエラー: 0件（ARG, SIM, F821, E722等すべて解消）
- [ ] 重複コード: 統合完了
- [ ] TODO/FIXME: 実装完了または削除
- [ ] 不要ファイル: 削除完了
- [ ] Service層: 全て`BaseService`継承
- [ ] テスト: 全て通過
- [ ] コミット: 機能別に整理されたコミット履歴

---

**次のセッションで成功を祈ります！ 🚀**
