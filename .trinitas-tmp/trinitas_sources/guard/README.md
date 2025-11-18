# Trinitas Quality Guardian Framework v2.0

Quality Guardian（品質守護）は、Trinitasシステムに統合された多言語対応品質保証フレームワークです。
Vibe Coding時代の開発品質を維持・向上させるためのツールとガイドラインを提供します。

## 🌟 新機能 (v2.0)

- **多言語対応**: Python, JavaScript/TypeScript, Go, Rustを完全サポート
- **強制実行モード**: 開発コマンド (`git`, `npm`, `cargo`, `go`) に品質チェックを自動統合
- **インテリジェントな言語検出**: プロジェクトタイプを自動判別
- **柔軟な設定**: warn/block/fixモードで動作制御可能

## 概要

Quality Guardianは、以下の原則に基づいて設計されています：

1. **予防的品質管理**: 問題が発生する前に防ぐ
2. **自動化優先**: 人間のミスを減らし、一貫性を保つ
3. **段階的採用**: プロジェクトの成熟度に応じて導入できる
4. **エージェント連携**: 各Trinitasエージェントが品質向上に貢献

## サポート言語とツール

| 言語 | Linter/Formatter | テスト | セキュリティ |
|------|-----------------|--------|-------------|
| **Python** | Ruff | pytest | bandit |
| **JavaScript/TypeScript** | ESLint, Prettier | Jest | ESLint Security |
| **Go** | golangci-lint, gofmt | go test | gosec |
| **Rust** | rustfmt, clippy | cargo test | cargo-audit |

## インストール

### 基本インストール
```bash
./install_trinitas_config.sh --with-guardian
```

### 強制実行モード付きインストール（推奨）
```bash
./install_trinitas_config.sh --enforce
```

これにより以下が追加されます：
- `cd`, `git`, `npm`, `cargo`, `go` コマンドの自動品質チェック
- シェル起動時の自動ロード
- 環境変数による動作制御

## 使用方法

### 手動品質チェック
```bash
# 現在のプロジェクトをチェック
trinitas-guard check

# 自動修正
trinitas-guard fix

# 状態確認
trinitas-guard status
```

### 自動品質チェック（強制実行モード）

強制実行モードでは、以下のコマンドが自動的に品質チェックを実行：

```bash
# Git commit時
git commit -m "feat: new feature"  # 自動で品質チェック

# npm/yarn実行時 (JavaScript/TypeScript)
npm run build  # 自動で品質チェック

# Cargo実行時 (Rust)
cargo build  # 自動で品質チェック

# Go実行時
go build  # 自動で品質チェック

# ディレクトリ移動時（プロジェクト検出）
cd my-project  # プロジェクトタイプを自動検出して通知
```

## 環境設定

### 動作モード制御
```bash
# 警告のみ（デフォルト）
export TRINITAS_GUARD_MODE=warn

# 品質問題がある場合はブロック
export TRINITAS_GUARD_MODE=block

# 自動修正
export TRINITAS_GUARD_MODE=fix

# 一時的に無効化
export TRINITAS_GUARD_ENABLED=false
```

### コマンド一覧
```bash
trinitas-guard check      # 品質チェック実行
trinitas-guard fix        # 自動修正
trinitas-guard enable     # Guardian有効化
trinitas-guard disable    # Guardian無効化
trinitas-guard mode <m>   # モード変更 (warn/block/fix)
trinitas-guard status     # 現在の状態表示
```

## コンポーネント構造

```
guard/
├── core/               # コア機能
│   └── detector.sh    # 言語自動検出
├── languages/         # 言語別設定
│   ├── javascript/    # JS/TS設定
│   ├── go/           # Go設定
│   ├── python/       # Python設定（レガシー）
│   └── rust/         # Rust設定
├── hooks/            # シェル統合
│   └── guard_enforcer.sh  # 強制実行メカニズム
├── templates/        # 設定テンプレート
├── scripts/          # ユーティリティ
└── docs/            # ドキュメント
```

## エージェント責任分担

| エージェント | 責任範囲 | 主要タスク |
|------------|---------|-----------|
| **Artemis** | 技術的品質 | 各言語のLinter/Formatter設定、コード品質チェック |
| **Hestia** | セキュリティ | 脆弱性スキャン、セキュリティルール、依存関係監査 |
| **Athena** | 全体設計 | フレームワーク統合、多言語対応設計 |
| **Muses** | ドキュメント | テンプレート作成、使用ガイド、言語別ドキュメント |
| **Hera** | 自動化 | CI/CD設計、ワークフロー最適化、並列実行 |
| **Eris** | 統合調整 | インストーラー統合、競合解決、強制実行メカニズム |

## プロジェクト初期設定

### Python プロジェクト
```bash
trinitas-guard init
# pyproject.toml, pytest.ini, .pre-commit-config.yaml が生成されます
```

### JavaScript/TypeScript プロジェクト
```bash
trinitas-guard init
# eslint.config.js, prettier.config.js, jest.config.js が生成されます
```

### Go プロジェクト
```bash
trinitas-guard init
# .golangci.yml, Makefile が生成されます
make help  # 利用可能なタスクを表示
```

### Rust プロジェクト
```bash
trinitas-guard init
# clippy.toml, rustfmt.toml, cargo_make.toml が生成されます
cargo make help  # 利用可能なタスクを表示
```

## CI/CD統合

### GitHub Actions
```bash
trinitas-guard setup-ci
# .github/workflows/quality-guardian.yml が生成されます
```

### Pre-commit hooks
```bash
trinitas-guard install-hooks
# Git commit時の自動チェックが有効になります
```

## 品質メトリクス

Quality Guardianは以下のメトリクスを追跡します：

### 言語共通
- コードカバレッジ率
- 循環的複雑度
- 技術的負債指標

### 言語固有
- **Python**: Ruffルール遵守率、テストカバレッジ
- **JavaScript**: ESLintエラー/警告数、Prettierフォーマット適合
- **Go**: golangci-lintスコア、gosec脆弱性数
- **Rust**: Clippy警告数、cargo-audit脆弱性

## トラブルシューティング

### 言語が正しく検出されない
```bash
# 手動で言語を指定
export TRINITAS_GUARD_LANGUAGE=javascript
```

### 特定のコマンドで強制実行を無効化
```bash
# 一時的に無効化
TRINITAS_GUARD_ENABLED=false git commit -m "emergency fix"
```

### パフォーマンスの問題
```bash
# 大規模プロジェクトでは警告モードを推奨
export TRINITAS_GUARD_MODE=warn
```

## ベストプラクティス

1. **段階的導入**
   - まず `warn` モードで開始
   - チームに慣れたら `block` モードへ
   - CI/CDでは常に `block` モード

2. **言語別最適化**
   - 各言語の標準的な設定ファイルを使用
   - プロジェクト固有のカスタマイズは最小限に

3. **チーム全体での採用**
   - READMEに設定方法を記載
   - 新規メンバー向けのオンボーディングに含める

## 貢献ガイド

Quality Guardian Frameworkの改善に貢献する方法：

1. 新しい言語サポートの追加
2. 品質チェックルールの改善
3. パフォーマンス最適化
4. ドキュメントの充実

## 今後の予定

- Ruby/Rails サポート
- Java/Kotlin サポート
- C/C++ サポート
- カスタムルール定義機能
- Web UIダッシュボード

## ライセンス

Trinitasシステムのライセンスに準拠します。