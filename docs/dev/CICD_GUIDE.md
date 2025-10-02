# CI/CD パイプラインガイド

## 概要

TMWSのCI/CDパイプラインは、GitHub Actionsを使用して、コードの品質、セキュリティ、機能を自動的に検証します。

**最終更新**: 2025-10-01
**バージョン**: 1.1.0 (Docker build job削除後)

## パイプライン構成

### 実行トリガー

```yaml
on:
  push:
    branches: [ master, main, develop ]
  pull_request:
    branches: [ master, main, develop ]
  workflow_dispatch:  # 手動実行
```

### 環境変数

```yaml
env:
  # 環境設定
  TMWS_ENVIRONMENT: test
  TMWS_SECRET_KEY: "test_secret_key_for_ci_pipeline_at_least_32_characters_long"
  TMWS_AUTH_ENABLED: "false"  # テスト時は認証無効化

  # データベース
  TMWS_DATABASE_URL: "postgresql://postgres:postgres@localhost:5432/tmws_test"
  TEST_USE_POSTGRESQL: "true"

  # Redis
  TMWS_REDIS_URL: "redis://localhost:6379/0"

  # Python
  PYTHON_VERSION: "3.11"
```

## ジョブ詳細

### 1. Test Job (テストスイート)

**実行時間**: 約5-7分

#### サービスコンテナ

```yaml
services:
  postgres:
    image: pgvector/pgvector:0.8.1-pg17
    env:
      POSTGRES_DB: tmws_test
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - 5432:5432

  redis:
    image: redis:7-alpine
    ports:
      - 6379:6379
```

#### 実行ステップ

1. **環境セットアップ**
   - Pythonインストール
   - 依存関係のキャッシュ利用
   - システム依存関係インストール

2. **PostgreSQL拡張機能セットアップ**
   ```sql
   CREATE EXTENSION IF NOT EXISTS pgvector;
   CREATE EXTENSION IF NOT EXISTS uuid-ossp;
   CREATE EXTENSION IF NOT EXISTS pg_trgm;
   ```

3. **依存関係インストール**
   ```bash
   pip install -e ".[dev]"
   ```

4. **データベースマイグレーション**
   ```bash
   alembic upgrade head
   ```

5. **コード品質チェック**
   - Ruff linting (continue-on-error)
   - Ruff formatting check (continue-on-error)
   - mypy型チェック (continue-on-error)

6. **テスト実行**
   - ユニットテスト
   - 統合テスト
   - カバレッジ計測

7. **結果アップロード**
   - Codecovへのカバレッジレポート
   - テスト結果アーティファクト

### 2. Security Job (セキュリティスキャン)

**実行時間**: 約2-3分

#### 実行ツール

1. **Bandit**: Pythonセキュリティ脆弱性スキャン
   ```bash
   bandit -r src/ -f json -o bandit-report.json
   ```

2. **Safety**: 既知の脆弱性を持つ依存関係チェック
   ```bash
   safety check --json
   ```

3. **pip-audit**: 依存関係の脆弱性監査
   ```bash
   pip-audit
   ```

**注意**: すべてのセキュリティチェックは `continue-on-error: true` で実行され、ビルドを失敗させません。

### 3. Notify Job (ステータス通知)

**実行時間**: 約30秒

前のジョブ（test, security）の結果を集約し、GitHub Step Summaryに表示します。

```yaml
needs: [test, security]
if: always()
```

#### 出力例

```markdown
## Pipeline Status
- Test Status: success
- Security Status: success

✅ All tests passed!
```

## ローカルでのテスト実行

### 1. 環境セットアップ

```bash
# PostgreSQL + pgvectorのセットアップ
docker run -d \
  --name tmws-test-db \
  -e POSTGRES_DB=tmws_test \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  pgvector/pgvector:0.8.1-pg17

# Redisのセットアップ
docker run -d \
  --name tmws-test-redis \
  -p 6379:6379 \
  redis:7-alpine
```

### 2. 拡張機能インストール

```bash
PGPASSWORD=postgres psql -h localhost -U postgres -d tmws_test << EOF
CREATE EXTENSION IF NOT EXISTS pgvector;
CREATE EXTENSION IF NOT EXISTS uuid-ossp;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
EOF
```

### 3. 依存関係インストール

```bash
pip install -e ".[dev]"
```

### 4. 環境変数設定

```bash
export TMWS_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/tmws_test"
export TMWS_ENVIRONMENT="test"
export TMWS_AUTH_ENABLED="false"
export TEST_USE_POSTGRESQL="true"
```

### 5. マイグレーション実行

```bash
alembic upgrade head
```

### 6. テスト実行

```bash
# ユニットテストのみ
pytest tests/unit/ -v

# 統合テストのみ
pytest tests/integration/ -v

# 全テスト + カバレッジ
pytest tests/ -v --cov=src --cov-report=html

# 特定のテストファイル
pytest tests/unit/test_auth_service.py -v
```

### 7. セキュリティスキャン

```bash
# Bandit
bandit -r src/ -f json -o bandit-report.json

# Safety
safety check

# pip-audit
pip-audit
```

## トラブルシューティング

### PostgreSQL接続エラー

```bash
# サービスが起動しているか確認
docker ps | grep tmws-test-db

# ログ確認
docker logs tmws-test-db

# 接続テスト
PGPASSWORD=postgres psql -h localhost -U postgres -d tmws_test -c "SELECT version();"
```

### Redis接続エラー

```bash
# サービス確認
docker ps | grep tmws-test-redis

# 接続テスト
redis-cli ping
```

### テスト失敗時

```bash
# 詳細ログ出力
pytest tests/ -vv -s

# 失敗したテストのみ再実行
pytest tests/ --lf

# 特定のテストをデバッグ
pytest tests/unit/test_auth_service.py::test_create_access_token -vv -s
```

## ベストプラクティス

### 1. コミット前チェック

```bash
# コード品質チェック
ruff check . --fix
ruff format .

# 型チェック
mypy src --ignore-missing-imports

# テスト実行
pytest tests/unit/ -v
```

### 2. プルリクエスト前

```bash
# 全テスト実行
pytest tests/ -v --cov=src

# セキュリティスキャン
bandit -r src/
safety check
```

### 3. CI/CD最適化

- キャッシュの有効活用
- 依存関係の最小化
- テストの並列実行
- 不要なステップのスキップ

## パフォーマンスメトリクス

| ジョブ | 平均実行時間 | 最適化後 |
|-------|------------|---------|
| Test | 7分 | 5分 (Docker build削除) |
| Security | 3分 | 2分 |
| Notify | 30秒 | 30秒 |
| **合計** | **10分30秒** | **7分30秒** |

## 今後の改善予定

詳細は `docs/security/SECURITY_IMPROVEMENT_ROADMAP.md` を参照してください。

### Phase 1 (24時間以内)
- Critical security findings対応
- 必須環境変数の検証強化

### Phase 2 (1週間以内)
- テストカバレッジ90%達成
- E2Eテストの追加

### Phase 3 (1ヶ月以内)
- パフォーマンステストの自動化
- デプロイメント自動化

## 関連ドキュメント

- [テストスイートガイド](TEST_SUITE_GUIDE.md)
- [セキュリティ改善ロードマップ](../security/SECURITY_IMPROVEMENT_ROADMAP.md)
- [Docker実装ガイド](FUTURE_DOCKER_IMPLEMENTATION.md)
- [デプロイメントガイド](../deployment/DEPLOYMENT_GUIDE_v2.2.0.md)

## 変更履歴

| 日付 | バージョン | 変更内容 | 担当 |
|-----|-----------|---------|------|
| 2025-10-01 | 1.1.0 | Docker build job削除、ドキュメント作成 | Muses |
| 2025-01-09 | 1.0.0 | 初版リリース | Artemis |
