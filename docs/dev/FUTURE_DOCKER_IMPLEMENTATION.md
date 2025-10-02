# 将来のDocker実装ガイド

## 概要

TMWSは現在、Dockerfileを持たず直接Pythonプロセスとして実行される設計ですが、将来的にコンテナ化が必要になった場合のための実装ガイドです。

**作成日**: 2025-10-01
**対象バージョン**: TMWS v2.x以降
**担当**: Muses (Knowledge Architect)

## 現在の状況

### なぜDockerfileが存在しないのか

1. **開発の柔軟性**
   - ローカル開発環境での迅速な変更とテスト
   - Python仮想環境での直接実行によるデバッグの容易さ

2. **CI/CDの簡素化**
   - GitHub Actionsでの直接テスト実行
   - ビルドステップの削減による高速化

3. **リソース効率**
   - 小規模デプロイメントではオーバーヘッドが不要
   - メモリとCPUの効率的な使用

### Docker化が必要になるケース

以下のいずれかに該当する場合、Docker化を検討してください:

1. **本番環境要件**
   - マルチテナント環境での分離
   - スケーラビリティの向上（Kubernetes等）
   - 環境の完全な再現性

2. **デプロイメント要件**
   - CI/CDパイプラインでのコンテナビルド
   - コンテナレジストリの使用
   - オーケストレーション（Docker Compose, K8s）

3. **チーム開発要件**
   - 開発環境の統一
   - 依存関係の完全な分離
   - 複数バージョンの並列運用

## Dockerfile テンプレート

### マルチステージビルド版

```dockerfile
# ========================================
# Builder Stage
# ========================================
FROM python:3.11-slim as builder

LABEL maintainer="TMWS Team"
LABEL description="Trinitas Memory & Workflow Service - Builder"

# 環境変数
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 作業ディレクトリ
WORKDIR /build

# システム依存関係
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Python依存関係のインストール
COPY pyproject.toml .
COPY README.md .

RUN pip install --user --no-warn-script-location \
    -e ".[production]"

# ========================================
# Runtime Stage
# ========================================
FROM python:3.11-slim

LABEL maintainer="TMWS Team"
LABEL description="Trinitas Memory & Workflow Service"
LABEL version="2.2.0"

# 非rootユーザー作成
RUN groupadd -r tmws && useradd -r -g tmws tmws

# 環境変数
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/tmws/.local/bin:$PATH" \
    TMWS_HOME=/app

# ランタイム依存関係
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 作業ディレクトリ
WORKDIR ${TMWS_HOME}

# Pythonパッケージをbuilderからコピー
COPY --from=builder /root/.local /home/tmws/.local

# アプリケーションコードコピー
COPY --chown=tmws:tmws . .

# 権限設定
RUN chown -R tmws:tmws ${TMWS_HOME}

# ヘルスチェック
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# 非rootユーザーに切り替え
USER tmws

# ポート公開
EXPOSE 8000

# エントリーポイント
ENTRYPOINT ["python", "-m", "src.main"]
```

### 開発用 Dockerfile

```dockerfile
# Dockerfile.dev
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# システム依存関係
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    postgresql-client \
    git \
    && rm -rf /var/lib/apt/lists/*

# Python依存関係
COPY pyproject.toml .
RUN pip install -e ".[dev]"

# アプリケーションコード（ボリュームマウント前提）
COPY . .

# 開発サーバー起動
CMD ["python", "-m", "src.main", "--reload"]
```

## Docker Compose 設定

### 開発環境用

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  tmws:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: tmws-dev
    ports:
      - "8000:8000"
    volumes:
      - .:/app
      - tmws-cache:/app/.cache
    environment:
      - TMWS_ENVIRONMENT=development
      - TMWS_DATABASE_URL=postgresql://tmws:tmws_dev_password@postgres:5432/tmws_dev
      - TMWS_REDIS_URL=redis://redis:6379/0
      - TMWS_AUTH_ENABLED=false
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - tmws-network

  postgres:
    image: pgvector/pgvector:0.8.1-pg17
    container_name: tmws-postgres
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=tmws_dev
      - POSTGRES_USER=tmws
      - POSTGRES_PASSWORD=tmws_dev_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./scripts/init-db.sh:/docker-entrypoint-initdb.d/init-db.sh
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U tmws"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - tmws-network

  redis:
    image: redis:7-alpine
    container_name: tmws-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - tmws-network

volumes:
  postgres-data:
  redis-data:
  tmws-cache:

networks:
  tmws-network:
    driver: bridge
```

### 本番環境用

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  tmws:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: tmws-prod
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - TMWS_ENVIRONMENT=production
      - TMWS_DATABASE_URL=${TMWS_DATABASE_URL}
      - TMWS_REDIS_URL=${TMWS_REDIS_URL}
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}
      - TMWS_AUTH_ENABLED=true
    env_file:
      - .env.production
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - tmws-network

  postgres:
    image: pgvector/pgvector:0.8.1-pg17
    container_name: tmws-postgres-prod
    restart: unless-stopped
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres-data-prod:/var/lib/postgresql/data
      - ./backups:/backups
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - tmws-network

  redis:
    image: redis:7-alpine
    container_name: tmws-redis-prod
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data-prod:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - tmws-network

volumes:
  postgres-data-prod:
  redis-data-prod:

networks:
  tmws-network:
    driver: bridge
```

## GitHub Actions への統合

### Docker Build Jobの追加方法

```yaml
# .github/workflows/test-suite.yml に追加

jobs:
  # 既存のtest, security jobの後に追加

  docker-build:
    name: "Docker Build & Push"
    runs-on: ubuntu-latest
    needs: [test, security]
    if: github.event_name == 'push' && (github.ref == 'refs/heads/master' || github.ref == 'refs/heads/main')

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: |
            your-org/tmws
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          platforms: linux/amd64,linux/arm64

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: your-org/tmws:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

## ベストプラクティス

### 1. イメージサイズの最小化

```dockerfile
# マルチステージビルドを使用
# alpine baseイメージは互換性問題があるため、slimを推奨

# 不要なファイルを除外
# .dockerignore
.git
.github
__pycache__
*.pyc
*.pyo
*.pyd
.pytest_cache
htmlcov
.coverage
*.log
.env
.env.*
!.env.example
```

### 2. セキュリティ

```dockerfile
# 非rootユーザーで実行
USER tmws

# 秘密情報をARGで渡さない（ビルド履歴に残る）
# 環境変数または secrets を使用

# 定期的な脆弱性スキャン
# Trivyまたは Snyk を使用
```

### 3. キャッシュ最適化

```dockerfile
# 変更の少ないレイヤーを先に配置
COPY pyproject.toml .
RUN pip install ...

# 変更の多いレイヤーを後に配置
COPY . .
```

## ローカルでのテスト

### ビルド

```bash
# 開発用
docker build -f Dockerfile.dev -t tmws:dev .

# 本番用
docker build -t tmws:latest .
```

### 実行

```bash
# 開発環境
docker-compose -f docker-compose.dev.yml up

# 本番環境
docker-compose -f docker-compose.prod.yml up -d
```

### デバッグ

```bash
# コンテナに入る
docker exec -it tmws-dev bash

# ログ確認
docker logs -f tmws-dev

# データベース接続確認
docker exec -it tmws-postgres psql -U tmws -d tmws_dev
```

## トラブルシューティング

### よくある問題

1. **ビルドが遅い**
   - Buildxとキャッシュを使用
   - .dockerignoreを適切に設定

2. **コンテナが起動しない**
   - ログを確認: `docker logs tmws`
   - ヘルスチェックを確認: `docker inspect tmws`

3. **データベース接続エラー**
   - ネットワーク設定を確認
   - サービス起動順序を確認（depends_on）

## チェックリスト

Docker実装前の確認事項:

- [ ] Dockerfileを作成
- [ ] docker-compose.yml（開発/本番）を作成
- [ ] .dockerignoreを作成
- [ ] ヘルスチェックエンドポイント実装
- [ ] 環境変数の整理
- [ ] セキュリティスキャン設定
- [ ] ドキュメント更新
- [ ] CI/CDへの統合
- [ ] ローカルテスト実施
- [ ] 本番環境での検証

## 関連ドキュメント

- [CI/CDガイド](CICD_GUIDE.md)
- [デプロイメントガイド](../deployment/DEPLOYMENT_GUIDE_v2.2.0.md)
- [セキュリティロードマップ](../security/SECURITY_IMPROVEMENT_ROADMAP.md)
- [Docker公式ドキュメント](https://docs.docker.com/)

## 参考リンク

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [Docker Compose](https://docs.docker.com/compose/)
- [GitHub Actions - Docker](https://docs.github.com/en/actions/publishing-packages/publishing-docker-images)

## 変更履歴

| 日付 | バージョン | 変更内容 | 担当 |
|-----|-----------|---------|------|
| 2025-10-01 | 1.0.0 | 初版作成、テンプレート整備 | Muses |
