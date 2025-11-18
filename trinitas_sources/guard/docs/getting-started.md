# Trinitas Quality Guardian - Getting Started Guide

## 概要

Trinitas Quality Guardian Framework は、Vibe Coding 時代のソフトウェア開発において、高品質なコードを維持するための包括的な品質保証システムです。

## インストール

### 1. Trinitasシステムと一緒にインストール

```bash
./install_trinitas_config.sh --with-guardian
```

これにより以下がインストールされます：
- Quality Guardian ツール一式
- 設定テンプレート（Ruff, pytest, pre-commit, GitHub Actions）
- 品質チェックスクリプト
- `trinitas-guard` コマンド

### 2. PATHの設定

インストール後、以下をシェル設定（`.bashrc`、`.zshrc`など）に追加してください：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## プロジェクトでの使用開始

### Step 1: 初期化

プロジェクトディレクトリで以下を実行：

```bash
trinitas-guard init
```

これにより以下が作成されます：
- `pyproject.toml` - Ruff設定
- `pytest.ini` - テスト設定
- `.pre-commit-config.yaml` - Pre-commitフック
- `.github/workflows/quality-guardian.yml` - CI/CD設定

### Step 2: 品質チェック

現在のコード品質を確認：

```bash
trinitas-guard check
```

詳細な結果を表示：

```bash
trinitas-guard check -v
```

### Step 3: 自動修正

修正可能な問題を自動的に修正：

```bash
trinitas-guard fix
```

### Step 4: Pre-commit Hooks の設定

コミット時の自動チェックを有効化：

```bash
# pre-commitのインストール（必要な場合）
pip install pre-commit

# フックのインストール
trinitas-guard install-hooks
```

### Step 5: CI/CD の設定

GitHub Actions を設定：

```bash
trinitas-guard setup-ci
```

その後、生成された `setup_branch_protection.sh` を実行してブランチ保護を有効化：

```bash
./setup_branch_protection.sh
```

## 設定のカスタマイズ

### Ruff 設定のカスタマイズ

`pyproject.toml` を編集して、プロジェクトに応じた設定を調整：

```toml
[tool.ruff.lint]
# プロジェクト固有のルールを追加
select = ["F", "E", "W", "I"]  # 必要なルールのみ選択
ignore = ["E501"]  # 特定のルールを無視

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]  # テストではassertを許可
```

### pytest 設定のカスタマイズ

`pytest.ini` を編集：

```ini
[tool:pytest]
# カバレッジ閾値を調整
addopts = --cov-fail-under=70  # 70%に設定

# カスタムマーカーを追加
markers =
    slow: 時間のかかるテスト
    integration: 統合テスト
```

## トラブルシューティング

### Ruff が見つからない

```bash
pip install ruff
```

### Pre-commit が動作しない

```bash
pre-commit install
pre-commit run --all-files
```

### GitHub Actions が失敗する

1. ログを確認
2. ローカルで同じコマンドを実行
3. 依存関係を確認

## 段階的導入のロードマップ

### Phase 1: 基本（1週目）
- [x] Ruff によるコードフォーマット
- [x] 基本的なテスト構造
- [x] README.md の作成

### Phase 2: 自動化（2週目）
- [ ] Pre-commit hooks の設定
- [ ] GitHub Actions CI/CD
- [ ] カバレッジレポート

### Phase 3: 高度な品質管理（3週目以降）
- [ ] ミューテーションテスト
- [ ] セキュリティスキャン
- [ ] パフォーマンスベンチマーク

## ベストプラクティス

1. **段階的導入**: すべてを一度に適用しない
2. **チーム合意**: ルールはチーム全体で決める
3. **継続的改善**: 定期的に設定を見直す
4. **自動化優先**: 手動チェックを最小限に
5. **教育重視**: チームメンバーへの説明を怠らない

## サポート

問題が発生した場合：
1. `trinitas-guard help` でヘルプを参照
2. プロジェクトのIssueを作成
3. Trinitas コミュニティに相談

## 次のステップ

- [詳細設定ガイド](./advanced-configuration.md)
- [TDD/BDD実践ガイド](./tdd-bdd-guide.md)
- [CI/CD最適化](./ci-cd-optimization.md)