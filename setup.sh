#!/bin/bash
# ========================================
# ⚠️  DEPRECATED - DO NOT USE
# ========================================
# This script is for TMWS v2.2.0 (PostgreSQL + pgvector architecture)
# which has been replaced by SQLite + ChromaDB architecture in v2.4.0+
#
# For current installation, use Docker:
#   docker-compose up -d
#
# Or see README.md for Quick Start instructions.
#
# This file is kept for historical reference only.
# ========================================

echo ""
echo "⚠️  =========================================="
echo "⚠️  DEPRECATED: This script is outdated"
echo "⚠️  =========================================="
echo ""
echo "TMWS v2.4.8 uses SQLite + ChromaDB architecture."
echo "PostgreSQL is no longer required."
echo ""
echo "Please use Docker instead:"
echo "  docker-compose up -d"
echo ""
echo "Or follow the Quick Start in README.md:"
echo "  https://github.com/apto-as/tmws#quick-start-docker"
echo ""
exit 1

# ========================================
# ORIGINAL SCRIPT BELOW (for reference)
# ========================================
# TMWS v2.2.0 自動セットアップスクリプト

set -e  # エラーで停止

echo "🚀 TMWS v2.2.0 セットアップを開始します..."

# 色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: PostgreSQLの確認
echo ""
echo "📦 Step 1: PostgreSQL 17の確認..."
if ! command -v /opt/homebrew/opt/postgresql@17/bin/psql &> /dev/null; then
    echo -e "${RED}❌ PostgreSQL 17が見つかりません${NC}"
    echo "インストールコマンド:"
    echo "  brew install postgresql@17"
    exit 1
fi
echo -e "${GREEN}✅ PostgreSQL 17 インストール済み${NC}"

# Step 2: PostgreSQLの起動
echo ""
echo "🔧 Step 2: PostgreSQLサービスの起動..."
brew services start postgresql@17 2>/dev/null || true
sleep 2
echo -e "${GREEN}✅ PostgreSQL起動完了${NC}"

# Step 3: データベースの作成
echo ""
echo "💾 Step 3: データベースとユーザーの作成..."

# データベースが存在するか確認
if /opt/homebrew/opt/postgresql@17/bin/psql postgres -tAc "SELECT 1 FROM pg_database WHERE datname='tmws_db'" | grep -q 1; then
    echo -e "${YELLOW}⚠️  tmws_db は既に存在します（スキップ）${NC}"
else
    /opt/homebrew/opt/postgresql@17/bin/psql postgres -c "CREATE USER tmws_user WITH PASSWORD 'tmws_password';" 2>/dev/null || echo "User already exists"
    /opt/homebrew/opt/postgresql@17/bin/psql postgres -c "CREATE DATABASE tmws_db OWNER tmws_user;"
    echo -e "${GREEN}✅ データベース作成完了${NC}"
fi

# pgvector拡張を有効化
/opt/homebrew/opt/postgresql@17/bin/psql tmws_db -c "CREATE EXTENSION IF NOT EXISTS vector;"
echo -e "${GREEN}✅ pgvector拡張を有効化${NC}"

# Step 4: Python仮想環境の作成
echo ""
echo "🐍 Step 4: Python仮想環境のセットアップ..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${GREEN}✅ 仮想環境を作成${NC}"
else
    echo -e "${YELLOW}⚠️  .venv は既に存在します（スキップ）${NC}"
fi

# 仮想環境を有効化
source .venv/bin/activate

# pipのアップグレード
echo "📦 pipをアップグレード中..."
pip install --upgrade pip -q

# Step 5: 依存パッケージのインストール
echo ""
echo "📚 Step 5: 依存パッケージのインストール（約3-5分）..."
echo "   以下のパッケージをインストール中:"
echo "   - FastAPI, SQLAlchemy, Alembic"
echo "   - ChromaDB (ベクトルストレージ)"
echo "   - pytest, ruff, mypy (開発ツール)"
echo "   ⚠️ 注意: Ollamaは別途インストールが必要です (https://ollama.ai/download)"
echo ""
pip install -e ".[dev]"
echo ""
echo -e "${GREEN}✅ 依存パッケージのインストール完了${NC}"

# Step 6: 環境変数ファイルの作成
echo ""
echo "⚙️  Step 6: 環境変数ファイルの作成..."
if [ ! -f ".env" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    cat > .env << EOF
# Database Configuration
TMWS_DATABASE_URL=postgresql://tmws_user:tmws_password@localhost:5432/tmws_db

# Security
TMWS_SECRET_KEY=${SECRET_KEY}
TMWS_AUTH_ENABLED=false

# Environment
TMWS_ENVIRONMENT=development

# API Configuration
TMWS_API_HOST=0.0.0.0
TMWS_API_PORT=8000

# Embeddings
TMWS_EMBEDDING_MODEL=all-MiniLM-L6-v2
TMWS_VECTOR_DIMENSION=384
EOF
    echo -e "${GREEN}✅ .env ファイルを作成${NC}"
else
    echo -e "${YELLOW}⚠️  .env は既に存在します（スキップ）${NC}"
fi

# Step 7: データベースマイグレーション
echo ""
echo "🔄 Step 7: データベースマイグレーション..."
alembic upgrade head
echo -e "${GREEN}✅ マイグレーション完了${NC}"

# Step 8: 完了メッセージ
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎉 TMWS v2.2.0 セットアップ完了！${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "次のステップ:"
echo ""
echo "1. 仮想環境を有効化:"
echo -e "   ${YELLOW}source .venv/bin/activate${NC}"
echo ""
echo "2. TMWSサーバーを起動:"
echo -e "   ${YELLOW}python -m src.main${NC}"
echo ""
echo "3. ブラウザでアクセス:"
echo "   - REST API: http://localhost:8000"
echo "   - Swagger UI: http://localhost:8000/docs"
echo "   - Health Check: http://localhost:8000/health"
echo ""
echo "4. Claude Desktop統合:"
echo "   詳細は INSTALL.md の「Claude Desktop統合」を参照"
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
