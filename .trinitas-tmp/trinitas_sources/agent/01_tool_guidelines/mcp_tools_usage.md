### MCP Tools使用ガイドライン

## 優先順位と使い分け

### 1. context7 (ドキュメント取得)
**用途**: ライブラリ・フレームワークの最新ドキュメント取得

**優先使用場面**:
- 新しいライブラリの使用方法調査
- API仕様の確認
- バージョン固有の機能確認
- ベストプラクティスの調査

**ペルソナ別推奨使用方法**:

```bash
# Athena: アーキテクチャ設計時の技術選定
/trinitas execute athena "Next.js 14の新機能を調査してプロジェクトへの適用可能性を評価"
→ context7で最新ドキュメントを取得し、戦略的判断

# Artemis: 実装前の仕様確認
/trinitas execute artemis "React Query v5の最適なキャッシング戦略を調査"
→ context7でパフォーマンス関連のドキュメントを重点的に確認

# Muses: ドキュメント作成時の正確な情報収集
/trinitas execute muses "プロジェクトで使用しているライブラリのバージョンと機能をドキュメント化"
→ context7で各ライブラリの公式ドキュメントを参照
```

### 2. markitdown (コンテンツ変換)
**用途**: Web/PDFコンテンツのMarkdown変換

**優先使用場面**:
- 外部技術文書の取り込み
- PDFレポートの構造化
- Web記事のアーカイブ
- 仕様書の解析と整理

**ペルソナ別推奨使用方法**:

```bash
# Muses: ドキュメント統合
/trinitas execute muses "外部の技術仕様書PDFをプロジェクトドキュメントに統合"
→ markitdownでPDFをMarkdownに変換後、構造化

# Athena: 外部仕様の分析
/trinitas execute athena "競合製品の公開仕様書を分析して比較表を作成"
→ markitdownで仕様書を変換し、戦略的分析
```

### 3. playwright (ブラウザ自動化)
**用途**: Webアプリケーションのテストと操作自動化

**優先使用場面**:
- E2Eテストの実行と検証
- UI動作確認とスクリーンショット取得
- フォーム入力の自動化
- 動的コンテンツの取得

**ペルソナ別推奨使用方法**:

```bash
# Hestia: セキュリティテスト
/trinitas execute hestia "ログインフォームのセキュリティテスト実施"
→ playwrightでXSS、SQLインジェクションなどをテスト

# Artemis: パフォーマンステスト
/trinitas execute artemis "ページロード時間とレンダリング性能を測定"
→ playwrightで各ページのパフォーマンスメトリクスを収集

# Eris: 統合テストの調整
/trinitas execute eris "複数ブラウザでのクロスブラウザテストを実施"
→ playwrightで並列テスト実行を調整
```

**Playwright実行例**:
```python
# スクリーンショット取得
await page.screenshot(path="dashboard.png", full_page=True)

# フォーム操作
await page.fill('input[name="email"]', 'test@example.com')
await page.fill('input[name="password"]', 'secure_password')
await page.click('button[type="submit"]')

# 要素の待機と確認
await page.wait_for_selector('.success-message')
assert await page.text_content('.user-name') == 'Test User'
```

### 4. serena (コードベース解析)
**用途**: 大規模コードベースの効率的な解析

**優先使用場面**:
- シンボル検索（関数、クラス、変数）
- 依存関係の分析
- リファクタリング影響調査
- コード構造の理解
- 参照箇所の特定

**ペルソナ別推奨使用方法**:

```bash
# Artemis: コード品質分析
/trinitas execute artemis "未使用コードと循環依存を特定して削除"
→ serenaでdead codeとimport cyclesを検出

# Athena: アーキテクチャ理解
/trinitas execute athena "システムの主要コンポーネントと依存関係を分析"
→ serenaでクラス階層と依存グラフを構築

# Hestia: セキュリティ監査
/trinitas execute hestia "ユーザー入力を処理する全ての箇所を特定"
→ serenaで危険な関数の使用箇所を検索

# Hera: 並列タスクの依存関係把握
/trinitas execute hera "並列実行可能なテストを特定して最適化"
→ serenaでテスト間の依存関係を分析
```

**Serena使用例**:
```python
# シンボル検索
find_symbol("UserController", depth=2)  # クラスとそのメソッドを取得

# 参照検索
find_referencing_symbols("deprecated_function")  # 使用箇所を特定

# パターン検索
search_for_pattern(r"exec\(|eval\(", restrict_to_code=True)  # 危険な関数
```

## 統合使用パターン

### Pattern A: 新技術導入時
```bash
# Step 1: ドキュメント調査
context7.get_library_docs("next.js/v14")  # Athena

# Step 2: 既存コードへの影響調査
serena.find_symbol("pages/*")  # Artemis

# Step 3: 移行計画の文書化
markitdown.convert(migration_plan_url)  # Muses

# Step 4: 動作確認テスト
playwright.test_migration()  # Hestia
```

### Pattern B: セキュリティ監査
```bash
# Step 1: 脆弱性パターン検索
serena.search_for_pattern("password|secret|token")  # Hestia

# Step 2: 動的テスト実行
playwright.security_test()  # Hestia

# Step 3: ベストプラクティス確認
context7.get_library_docs("owasp/security-guide")  # Hestia

# Step 4: 報告書作成
markitdown.convert(audit_report)  # Muses
```

### Pattern C: パフォーマンス最適化
```bash
# Step 1: ボトルネック特定
serena.find_symbol("*Query*", include_body=True)  # Artemis

# Step 2: 最適化手法の調査
context7.get_library_docs("database/optimization")  # Artemis

# Step 3: ベンチマーク実行
playwright.performance_test()  # Artemis

# Step 4: 結果文書化
markitdown.convert(benchmark_results)  # Muses
```

### Pattern D: ドキュメント生成
```bash
# Step 1: コード構造の把握
serena.get_symbols_overview()  # Muses

# Step 2: 外部仕様の確認
context7.get_library_docs(dependencies)  # Muses

# Step 3: 外部資料の統合
markitdown.convert(external_docs)  # Muses

# Step 4: インタラクティブデモの作成
playwright.create_demo_screenshots()  # Muses
```

## ツール選択の判断基準

| 状況 | 推奨ツール | 理由 |
|-----|-----------|------|
| ライブラリの使い方がわからない | context7 | 最新の公式ドキュメントが必要 |
| コードの影響範囲を調べたい | serena | シンボル解析と依存関係追跡 |
| Webアプリの動作を確認したい | playwright | 実際のブラウザ操作が必要 |
| PDF/Web記事を取り込みたい | markitdown | 構造化されたMarkdown変換 |
| セキュリティテストを実施 | playwright + serena | 静的+動的解析の組み合わせ |
| API仕様を調査 | context7 | バージョン固有の情報取得 |
| リファクタリング影響調査 | serena | 参照箇所の完全な特定 |
| 外部ドキュメント統合 | markitdown | フォーマット変換と整形 |

## エラーハンドリング

```python
# context7エラー処理
try:
    docs = context7.get_library_docs("library/version")
except LibraryNotFoundError:
    # フォールバック: Web検索や他のソースを試す
    pass

# serenaエラー処理
try:
    symbols = serena.find_symbol("ClassName")
except SymbolNotFoundError:
    # より広範な検索パターンを試す
    symbols = serena.search_for_pattern("Class.*")

# playwrightエラー処理
try:
    await page.click("button")
except TimeoutError:
    # 要素の待機時間を延長または別のセレクタを試す
    await page.wait_for_selector("button", timeout=30000)
```