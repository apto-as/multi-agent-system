# TMWS クイックスタート（5分で起動）

## 1. インストール

```bash
# PostgreSQL 17をインストール（未インストールの場合）
brew install postgresql@17

# 自動セットアップ（約10分）
chmod +x setup.sh
./setup.sh
```

## 2. サーバー起動

```bash
source .venv/bin/activate
python -m src.main
```

## 3. 動作確認

別ターミナルで:

```bash
# ヘルスチェック
curl http://localhost:8000/health

# メモリ作成テスト
curl -X POST http://localhost:8000/api/v1/memory \
  -H "Content-Type: application/json" \
  -d '{
    "content": "TMWS起動成功！",
    "importance": 0.9,
    "tags": ["quickstart"]
  }'
```

ブラウザで確認:
- **Swagger UI**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 4. 次のステップ

- [詳細なインストールガイド](INSTALL.md)
- [API認証ドキュメント](docs/API_AUTHENTICATION.md)
- [Trinitas統合ガイド](docs/TRINITAS_INTEGRATION.md)

## トラブルシューティング

### PostgreSQLが起動しない
```bash
brew services start postgresql@17
```

### ポート8000が使用中
```bash
export TMWS_API_PORT=8001
python -m src.main
```

### 依存パッケージのインストールエラー
```bash
pip install --upgrade pip
pip install -e ".[dev]" --no-cache-dir
```

詳細は [INSTALL.md](INSTALL.md) の「トラブルシューティング」を参照してください。
