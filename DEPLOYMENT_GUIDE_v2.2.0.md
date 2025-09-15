# 🚀 TMWS v2.2.0 デプロイメントガイド

## 📋 目次
1. [前提条件](#前提条件)
2. [クイックスタート](#クイックスタート)
3. [本番環境デプロイ](#本番環境デプロイ)
4. [Docker デプロイ](#docker-デプロイ)
5. [検証手順](#検証手順)
6. [トラブルシューティング](#トラブルシューティング)

---

## 前提条件

### システム要件
- **OS**: Ubuntu 22.04 LTS または macOS 13+
- **Python**: 3.11以上
- **PostgreSQL**: 15以上（pgvector拡張必須）
- **Redis**: 7.0以上
- **RAM**: 最小2GB、推奨4GB以上
- **ディスク**: 10GB以上の空き容量

### 必要なツール
```bash
# 確認コマンド
python --version  # Python 3.11+
psql --version    # PostgreSQL 15+
redis-cli --version  # Redis 7.0+
docker --version  # Docker 24+ (Dockerデプロイの場合)
```

---

## クイックスタート

### 1. リポジトリのクローン
```bash
# v2.2.0タグを指定してクローン
git clone --branch v2.2.0 https://github.com/apto-as/tmws.git
cd tmws
```

### 2. 環境設定
```bash
# 本番環境設定ファイルをコピー
cp config/production.env.template .env

# .envファイルを編集
vim .env
```

**重要な環境変数の設定:**
```bash
# データベース設定
TMWS_DATABASE_URL=postgresql://tmws_user:secure_password@localhost:5432/tmws

# セキュリティ設定（必ず変更してください）
TMWS_SECRET_KEY=your-super-secure-secret-key-at-least-32-chars
TMWS_JWT_SECRET=another-secure-jwt-secret-key

# 環境設定
TMWS_ENVIRONMENT=production
TMWS_AUTH_ENABLED=true

# Redis設定
TMWS_REDIS_URL=redis://localhost:6379/0

# API設定
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000
```

### 3. データベースセットアップ
```bash
# PostgreSQLユーザーとデータベース作成
sudo -u postgres psql << EOF
CREATE USER tmws_user WITH PASSWORD 'secure_password';
CREATE DATABASE tmws OWNER tmws_user;
\c tmws
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
GRANT ALL PRIVILEGES ON DATABASE tmws TO tmws_user;
EOF

# マイグレーション実行
python -m alembic upgrade head
```

### 4. インストールと起動
```bash
# 依存関係インストール
pip install -e .

# サーバー起動
python -m src.main
```

---

## 本番環境デプロイ

### 方法1: スクリプトによる自動デプロイ
```bash
# 実行権限付与
chmod +x scripts/deploy.sh

# デプロイ実行
./scripts/deploy.sh production
```

### 方法2: 手動デプロイ

#### Step 1: システム準備
```bash
# セキュリティ強化スクリプト実行
sudo ./scripts/security_hardening.sh

# SSL証明書取得（Let's Encrypt）
sudo ./scripts/ssl-automation.sh yourdomain.com
```

#### Step 2: Nginx設定
```bash
# Nginx設定ファイルをコピー
sudo cp config/nginx/nginx.conf /etc/nginx/nginx.conf
sudo cp config/nginx/conf.d/default.conf /etc/nginx/conf.d/tmws.conf

# ドメイン名を更新
sudo sed -i 's/yourdomain.com/実際のドメイン名/g' /etc/nginx/conf.d/tmws.conf

# Nginx再起動
sudo nginx -t && sudo systemctl reload nginx
```

#### Step 3: Systemdサービス作成
```bash
# サービスファイル作成
sudo tee /etc/systemd/system/tmws.service << EOF
[Unit]
Description=TMWS v2.2.0 - Trinitas Memory & Workflow Service
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=tmws
Group=tmws
WorkingDirectory=/opt/tmws
Environment="PATH=/opt/tmws/venv/bin"
ExecStart=/opt/tmws/venv/bin/python -m src.main
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID
Restart=on-failure
RestartSec=5s

# セキュリティ設定
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/tmws/logs /opt/tmws/data

[Install]
WantedBy=multi-user.target
EOF

# サービス有効化と起動
sudo systemctl daemon-reload
sudo systemctl enable tmws
sudo systemctl start tmws
```

---

## Docker デプロイ

### 1. Dockerイメージビルド
```bash
# マルチステージビルド
docker build -t tmws:v2.2.0 .

# または、ビルドスクリプト使用
./scripts/build.sh v2.2.0
```

### 2. Docker Compose起動
```bash
# docker-compose.ymlを使用
docker-compose up -d

# ログ確認
docker-compose logs -f tmws
```

### 3. Kubernetesデプロイ（オプション）
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tmws
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tmws
  template:
    metadata:
      labels:
        app: tmws
        version: v2.2.0
    spec:
      containers:
      - name: tmws
        image: tmws:v2.2.0
        ports:
        - containerPort: 8000
        env:
        - name: TMWS_ENVIRONMENT
          value: "production"
        - name: TMWS_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: tmws-secrets
              key: database-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

```bash
# デプロイ
kubectl apply -f k8s/
```

---

## 検証手順

### 1. ヘルスチェック
```bash
# APIヘルスチェック
curl http://localhost:8000/health

# 期待されるレスポンス
{
  "status": "healthy",
  "version": "2.2.0",
  "database": "connected",
  "redis": "connected",
  "vector_search": "operational"
}
```

### 2. パフォーマンステスト
```bash
# 簡易パフォーマンステスト
python scripts/test-runner.py --performance

# ベンチマーク実行
ab -n 1000 -c 10 http://localhost:8000/api/v1/memory/search
```

### 3. セキュリティ検証
```bash
# セキュリティテスト実行
python scripts/test-security.sh

# レート制限テスト
for i in {1..120}; do curl http://localhost:8000/api/v1/tasks; done
```

---

## トラブルシューティング

### よくある問題と解決方法

#### 1. pgvector拡張が見つからない
```bash
# 解決方法
sudo apt-get install postgresql-15-pgvector
sudo -u postgres psql -d tmws -c "CREATE EXTENSION vector;"
```

#### 2. Redis接続エラー
```bash
# Redis状態確認
sudo systemctl status redis
redis-cli ping

# Redis再起動
sudo systemctl restart redis
```

#### 3. ポート8000が使用中
```bash
# 使用中のプロセス確認
sudo lsof -i :8000

# 別のポートを使用
export TMWS_API_PORT=8001
```

#### 4. メモリ不足エラー
```bash
# Swapファイル追加（2GB）
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### 5. SSL証明書エラー
```bash
# Let's Encrypt証明書の再取得
sudo certbot renew --force-renewal
sudo systemctl reload nginx
```

### ログ確認
```bash
# アプリケーションログ
tail -f logs/tmws.log

# Nginxログ
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# PostgreSQLログ
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Systemdログ
sudo journalctl -u tmws -f
```

---

## 監視とメンテナンス

### Prometheusメトリクス設定
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'tmws'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

### バックアップ設定
```bash
# データベースバックアップ（daily cron）
0 2 * * * pg_dump -U tmws_user tmws | gzip > /backup/tmws_$(date +\%Y\%m\%d).sql.gz

# Redisバックアップ
0 3 * * * redis-cli BGSAVE
```

### アップデート手順
```bash
# 新バージョンへのアップデート
git fetch --tags
git checkout v2.3.0  # 新バージョン
pip install -e . --upgrade
python -m alembic upgrade head
sudo systemctl restart tmws
```

---

## サポート

### リソース
- 📚 [公式ドキュメント](https://github.com/apto-as/tmws/docs)
- 🐛 [Issue Tracker](https://github.com/apto-as/tmws/issues)
- 💬 [Discord](https://discord.gg/tmws)

### 緊急時の連絡先
- **Email**: support@tmws.dev
- **緊急ホットライン**: +81-XX-XXXX-XXXX（営業時間内）

---

## ライセンス

TMWS v2.2.0 is released under the MIT License.

---

*Last Updated: 2025-01-15*
*Version: 2.2.0*