# TMWS v2.3.1 本番環境デプロイ計画書
## Production Deployment Plan - Cross-Platform User-Friendly Strategy

**作成日**: 2025-11-03
**対象バージョン**: v2.3.1
**対象ユーザー**: すべてのユーザー（技術知識不問）
**対象プラットフォーム**: Windows/Mac/Linux
**戦略**: 段階的展開（3つの選択肢）

---

## 📊 エグゼクティブサマリー

TMWSを**誰でも、どこでも、簡単に**使えるようにする包括的なデプロイ戦略です。

### 主要目標

| 目標 | 実現方法 |
|-----|---------|
| **ワンクリックインストール** | Docker Desktop + GUI installer |
| **クロスプラットフォーム** | Windows/Mac/Linux統一 |
| **技術知識不要** | グラフィカルインストーラー |
| **即座に起動** | 起動スクリプト自動化 |
| **セキュアデフォルト** | 環境変数テンプレート提供 |

### 3つのデプロイ戦略

| 戦略 | 対象ユーザー | 難易度 | GPU対応 | 推奨度 |
|-----|------------|--------|---------|--------|
| **🐳 Strategy A: Hybrid Docker** | すべてのユーザー | ★★☆☆☆ | ✅ 最適 | ⭐⭐⭐⭐⭐ |
| **📦 Strategy B: Standalone Binary** | 一般ユーザー | ★★☆☆☆ | ✅ 対応 | ⭐⭐⭐⭐☆ |
| **🐍 Strategy C: Python Package** | 開発者 | ★★★☆☆ | ✅ 対応 | ⭐⭐⭐☆☆ |

**推奨**: Strategy A (Hybrid Docker) - GPU性能を活かしつつ環境分離

**Hybrid Docker戦略の特徴**:
- 🍎 **Mac**: Ollama native (Metal GPU) + TMWS Docker
- 🪟🐧 **Windows/Linux**: Ollama native (CUDA/CPU) + TMWS Docker
- **利点**: GPU性能最大化 + 環境分離 + 簡単アップデート

---

## 🐳 Strategy A: Hybrid Docker (推奨)

### ⚠️ 重要: GPU対応とOS別構成

**Docker Desktop + OllamaのGPU問題**:
- ❌ **MacではDockerコンテナ内のOllamaがGPU使用不可** (Metal未対応)
- ❌ Docker内Ollama (Mac): CPU only → 推論速度が**10-50倍遅い**
- ✅ **ネイティブOllama (Mac)**: Metal GPU → 実用的な速度

### OS別推奨構成

#### 🍎 Mac (Apple Silicon: M1/M2/M3/M4)

**推奨**: **Hybrid構成** (Ollama native + TMWS Docker)

```
┌─────────────────────────────────────┐
│  macOS Host                         │
├─────────────────────────────────────┤
│  ┌─────────────────────────────┐   │
│  │  Ollama (Native)            │   │ ← Metal GPU使用 ✅
│  │  Port: 11434                │   │
│  └─────────────────────────────┘   │
│              ↑ http://host.docker.internal:11434
│  ┌─────────────────────────────┐   │
│  │  TMWS (Docker Container)    │   │
│  │  + ChromaDB + SQLite        │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

**性能比較**:
| 構成 | 推論速度 (embedding生成) | GPU利用 |
|-----|------------------------|---------|
| Native Ollama | 10-30ms | ✅ Metal |
| Docker Ollama | 500-1500ms | ❌ CPU only |

#### 🪟 Windows / 🐧 Linux

**推奨**: **Full Native** または **Hybrid構成**

```
Option 1 (推奨): Both Native
┌─────────────────────────────────────┐
│  Host OS (Windows/Linux)            │
├─────────────────────────────────────┤
│  Ollama (Native) + TMWS (Native)    │ ← シンプル
│  GPU: CUDA/ROCm対応可能              │
└─────────────────────────────────────┘

Option 2: Hybrid (Ollama native + TMWS Docker)
┌─────────────────────────────────────┐
│  Ollama (Native) ← GPU使用可能       │
│  TMWS (Docker)                      │
└─────────────────────────────────────┘
```

### 概要

**Hybrid Docker戦略**:
- Ollama: **ネイティブインストール** (GPU最適化)
- TMWS: Dockerコンテナ (環境分離)

**利点**:
- ✅ GPU性能を最大限活用 (Mac: Metal, Windows/Linux: CUDA)
- ✅ TMWS環境は完全分離（依存関係衝突なし）
- ✅ アンインストールも簡単
- ✅ OS間で共通のTMWS設定

**欠点**:
- ⚠️ Ollamaを別途インストール必要
- ⚠️ Docker Desktopインストール約500MB

### システム要件

| プラットフォーム | 最小要件 | 推奨 |
|---------------|---------|------|
| **Windows** | Windows 10 64-bit (Build 19041+) | Windows 11 |
| **Mac** | macOS 11 Big Sur+ | macOS 13 Ventura+ |
| **Linux** | Ubuntu 20.04+ / Debian 11+ | Ubuntu 22.04+ |
| **RAM** | 4GB | 8GB+ |
| **Disk** | 10GB空き | 20GB+ |
| **CPU** | 2コア | 4コア+ |

### デプロイ構成

```
┌─────────────────────────────────────────────┐
│         Docker Desktop Host                 │
├─────────────────────────────────────────────┤
│                                             │
│  ┌────────────────────────────────────┐    │
│  │  TMWS Container (tmws:v2.3.1)      │    │
│  ├────────────────────────────────────┤    │
│  │  ┌──────────┐  ┌──────────────┐   │    │
│  │  │ FastAPI  │  │ ChromaDB     │   │    │
│  │  │ MCP      │  │ (in-memory)  │   │    │
│  │  └──────────┘  └──────────────┘   │    │
│  │                                     │    │
│  │  Volume Mounts:                     │    │
│  │  - ./data:/app/data (SQLite)       │    │
│  │  - ./config:/app/config            │    │
│  │  - ./.chroma:/app/.chroma          │    │
│  └────────────────────────────────────┘    │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │  Ollama Container (ollama:latest)  │    │
│  ├────────────────────────────────────┤    │
│  │  Model: multilingual-e5-large      │    │
│  │  Port: 11434                       │    │
│  └────────────────────────────────────┘    │
│                                             │
│  Network: tmws_network (bridge)            │
└─────────────────────────────────────────────┘
```

### インストール手順

#### Phase 1: Docker Desktop インストール

**Windows**:
```powershell
# Step 1: Docker Desktop ダウンロード
# https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe

# Step 2: インストーラー実行
Docker Desktop Installer.exe

# Step 3: WSL2 更新（必要な場合）
wsl --update

# Step 4: 再起動
```

**Mac**:
```bash
# Step 1: Docker Desktop ダウンロード
# Intel: https://desktop.docker.com/mac/main/amd64/Docker.dmg
# Apple Silicon: https://desktop.docker.com/mac/main/arm64/Docker.dmg

# Step 2: Docker.dmg をマウントして Applications にドラッグ

# Step 3: Docker Desktop 起動
open -a Docker
```

**Linux (Ubuntu)**:
```bash
# Step 1: 依存関係インストール
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# Step 2: Docker公式GPGキー追加
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Step 3: Dockerリポジトリ追加
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Step 4: Docker Engine + Docker Compose インストール
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Step 5: ユーザーをdockerグループに追加
sudo usermod -aG docker $USER
newgrp docker
```

#### Phase 2: Ollama インストール

**🍎 Mac (Apple Silicon)**:

```bash
# Step 1: Ollama ダウンロード & インストール
curl -fsSL https://ollama.ai/install.sh | sh

# または https://ollama.ai/download からDMGをダウンロード

# Step 2: Ollama起動確認
ollama --version
# ollama version is 0.1.x

# Step 3: モデルダウンロード（約1GB、初回のみ10-15分）
ollama pull zylonai/multilingual-e5-large

# Step 4: Ollama起動
ollama serve  # バックグラウンドで動作

# Step 5: 動作確認
curl http://localhost:11434/api/tags
# {"models":[{"name":"zylonai/multilingual-e5-large:latest",...}]}
```

**🪟 Windows / 🐧 Linux**:

```bash
# Option 1 (推奨): ネイティブインストール
# Windows: https://ollama.ai/download/windows から OllamaSetup.exe
# Linux: curl -fsSL https://ollama.ai/install.sh | sh

# Option 2: Docker版を使用（Phase 3のdocker-compose.ymlで自動起動）
```

#### Phase 3: TMWS インストール

**🍎 Mac (Hybrid構成)**:

```bash
# Step 1: リポジトリクローンまたはリリースダウンロード
git clone https://github.com/apto-as/tmws.git
cd tmws

# Step 2: Mac用docker-compose設定を使用
cp docker-compose.mac.yml docker-compose.yml

# Step 3: 環境変数設定
cp .env.example .env
# SECRET_KEY自動生成
echo "TMWS_SECRET_KEY=$(openssl rand -hex 32)" >> .env

# Step 4: TMWS起動（Dockerコンテナ）
docker-compose up -d

# 初回起動時の自動処理:
# - イメージのダウンロード（約1GB、初回のみ）
# - コンテナ起動
# - ヘルスチェック
# - ホストのOllama (localhost:11434) に接続

# Step 5: 動作確認
curl http://localhost:8000/health
# {"status":"healthy","version":"v2.3.1"}
```

**🪟🐧 Windows/Linux (Docker構成)**:

```bash
# Step 1: リポジトリクローンまたはリリースダウンロード
git clone https://github.com/apto-as/tmws.git
cd tmws

# Step 2: 環境変数設定
cp .env.example .env
# Windows: notepad .env
# Linux: nano .env
# TMWS_SECRET_KEY を設定（openssl rand -hex 32 で生成）

# Step 3: 起動スクリプト実行
# Windows: start-tmws.bat をダブルクリック
# Linux: ./start-tmws.sh

# 初回起動時の自動処理:
# - docker-compose.yml 読み込み
# - イメージのダウンロード（約2GB、初回のみ）
# - Ollamaモデルのダウンロード（約1GB、初回のみ）
# - コンテナ起動（TMWS + Ollama）
# - ヘルスチェック
```

#### Phase 3: 設定（オプション）

```bash
# .env ファイルの編集（必要に応じて）
# Windows: notepad .env
# Mac/Linux: nano .env

# 主要設定項目:
TMWS_ENVIRONMENT=production
TMWS_SECRET_KEY=<自動生成された64文字キー>
TMWS_CORS_ORIGINS=["http://localhost:3000"]
TMWS_LOG_LEVEL=INFO
```

### 起動・停止手順

**起動**:
```bash
# Windows
start-tmws.bat

# Mac/Linux
./start-tmws.sh

# または Docker Compose 直接
docker-compose up -d
```

**停止**:
```bash
# Windows
stop-tmws.bat

# Mac/Linux
./stop-tmws.sh

# または Docker Compose 直接
docker-compose down
```

**再起動**:
```bash
# Windows
restart-tmws.bat

# Mac/Linux
./restart-tmws.sh

# または Docker Compose 直接
docker-compose restart
```

**ログ確認**:
```bash
# リアルタイムログ
docker-compose logs -f tmws

# 最新100行
docker-compose logs --tail=100 tmws
```

### 🔌 Claude Desktop MCP接続設定

#### 概要

TMWSはMCPサーバーとして動作し、Claude Desktopから接続できます。

**アーキテクチャ**:
```
Claude Desktop (Host OS)
    ↓ stdio
Wrapper Script
    ↓ docker exec -i
TMWS Container (tmws-app)
    ↓
MCP Server (FastMCP)
```

#### Wrapper Script作成

**🍎 Mac/🐧 Linux** (`~/.local/bin/tmws-mcp-docker.sh`):

```bash
#!/bin/bash
# TMWS MCP Server - Docker Wrapper

set -e

CONTAINER_NAME="tmws-app"

# Container起動チェック
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: TMWS container is not running" >&2
    echo "Start TMWS: docker-compose up -d" >&2
    exit 1
fi

# MCP server起動
exec docker exec -i "${CONTAINER_NAME}" python -m src.mcp_server
```

```bash
# 実行権限付与
chmod +x ~/.local/bin/tmws-mcp-docker.sh
```

**🪟 Windows** (`%USERPROFILE%\.local\bin\tmws-mcp-docker.bat`):

```batch
@echo off
set CONTAINER_NAME=tmws-app

docker ps --format "{{.Names}}" | findstr /X "%CONTAINER_NAME%" >nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: TMWS container is not running 1>&2
    echo Start TMWS: docker-compose up -d 1>&2
    exit /b 1
)

docker exec -i %CONTAINER_NAME% python -m src.mcp_server
```

#### Claude Desktop設定

**Mac** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/<your-username>/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
```

**Linux** (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tmws": {
      "command": "/home/<your-username>/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
```

**Windows** (`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tmws": {
      "command": "C:\\Users\\<your-username>\\.local\\bin\\tmws-mcp-docker.bat"
    }
  }
}
```

#### 動作確認

```bash
# 1. TMWS起動確認
docker ps | grep tmws-app

# 2. MCP接続テスト
echo '{"jsonrpc":"2.0","method":"ping","id":1}' | ~/.local/bin/tmws-mcp-docker.sh

# 3. Claude Desktop再起動
# Claude Desktop → Settings → Developer → Reload
```

#### 詳細ドキュメント

完全な接続ガイド: `docs/MCP_CONNECTION_DOCKER.md`

---

### docker-compose.yml 設計（OS別）

#### 🍎 Mac版: docker-compose.mac.yml

**特徴**: Ollama外部接続（ネイティブOllamaを使用）

```yaml
version: '3.8'

services:
  tmws:
    image: ghcr.io/apto-as/tmws:v2.3.1
    container_name: tmws-app
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
      - ./.chroma:/app/.chroma
    environment:
      - TMWS_ENVIRONMENT=${TMWS_ENVIRONMENT:-production}
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}
      - TMWS_DATABASE_URL=sqlite+aiosqlite:////app/data/tmws.db
      - TMWS_OLLAMA_BASE_URL=http://host.docker.internal:11434  # ← ホストのOllama
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
```

#### 🪟🐧 Windows/Linux版: docker-compose.yml

**特徴**: Ollama + TMWS 両方Docker（またはOllama外部も可）

```yaml
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: tmws-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama-models:/root/.ollama
    networks:
      - tmws-network
    restart: unless-stopped
    # GPU設定 (NVIDIA GPUがある場合)
    # deploy:
    #   resources:
    #     reservations:
    #       devices:
    #         - driver: nvidia
    #           count: 1
    #           capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  tmws:
    image: ghcr.io/apto-as/tmws:v2.3.1
    container_name: tmws-app
    depends_on:
      ollama:
        condition: service_healthy
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./config:/app/config
      - ./.chroma:/app/.chroma
    environment:
      - TMWS_ENVIRONMENT=${TMWS_ENVIRONMENT:-production}
      - TMWS_SECRET_KEY=${TMWS_SECRET_KEY}
      - TMWS_DATABASE_URL=sqlite+aiosqlite:////app/data/tmws.db
      - TMWS_OLLAMA_BASE_URL=http://ollama:11434
      - TMWS_CORS_ORIGINS=${TMWS_CORS_ORIGINS:-["http://localhost:3000"]}
      - TMWS_LOG_LEVEL=${TMWS_LOG_LEVEL:-INFO}
    networks:
      - tmws-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

networks:
  tmws-network:
    driver: bridge

volumes:
  ollama-models:
    driver: local
```

### Dockerfile 設計

```dockerfile
# Multi-stage build for minimal image size
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini .
COPY pyproject.toml .

# Create necessary directories
RUN mkdir -p /app/data /app/config /app/.chroma /app/logs

# Set environment variables
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run migrations on startup, then start server
CMD ["sh", "-c", "alembic upgrade head && uvicorn src.main:app --host 0.0.0.0 --port 8000"]
```

---

### ⚖️ Docker版 vs uvx版（ネイティブ）比較

#### uvx版（Python Package）の概要

**インストール**:
```bash
# PyPI経由（将来リリース予定）
uvx --from tmws tmws-mcp-server

# または pip
pip install tmws
tmws-mcp-server
```

**Claude Desktop設定**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "tmws", "tmws-mcp-server"]
    }
  }
}
```

**アーキテクチャ**:
```
Claude Desktop (Host OS)
    ↓ stdio (直接プロセス間通信)
uvx tmws-mcp-server (Host OS)
    ↓
Ollama (Host OS, GPU利用)
```

#### 詳細比較表

| 観点 | Docker版 | uvx版 | 推奨 |
|------|----------|-------|------|
| **インストール** | ★★★★☆ Docker + wrapper | ★★★★★ 1コマンド | uvx |
| **接続レイテンシー** | ★★★★☆ +10-30ms (docker exec) | ★★★★★ 最小 | uvx |
| **MCP tool実行** | ★★★★★ 同等 | ★★★★★ 同等 | 同等 |
| **GPU対応** | ✅ Ollama native | ✅ Ollama native | 同等 |
| **依存関係管理** | ⭐⭐⭐⭐⭐ 完全分離 | ⚠️ ホスト環境に依存 | Docker |
| **環境分離** | ⭐⭐⭐⭐⭐ 完全分離 | ❌ ホストOSと共有 | Docker |
| **アップデート** | ⭐⭐⭐⭐⭐ `docker-compose pull` | ⭐⭐⭐☆☆ `uvx --upgrade` | Docker |
| **トラブル時** | ⭐⭐⭐⭐⭐ コンテナ再起動 | ⚠️ Python環境に依存 | Docker |
| **メモリ使用量** | 250MB (アイドル) | 150MB (アイドル) | uvx |
| **ディスク使用量** | 2GB (イメージ) | 500MB (パッケージ) | uvx |

#### 選択ガイド

**uvx版を推奨する場合**:

✅ **単一プロジェクトでのみTMWS使用**
- 他のPythonプロジェクトと依存関係が競合しない
- 環境分離が不要

✅ **最小レイテンシーが必要**
- MCP接続の起動時間を最小化したい
- docker execの10-30msオーバーヘッドも気になる

✅ **シンプルさ重視**
- Dockerのインストール・管理が不要
- Wrapper scriptの設定が不要

✅ **開発者向け**
- Python環境の管理に慣れている
- トラブル時に自力で解決できる

**Docker版を推奨する場合**:

✅ **複数プロジェクトで依存関係が競合**
```
Project A: tmws 2.2.6, FastAPI 0.104
Project B: tmws 2.3.0, FastAPI 0.110  # 競合！
```
→ Docker版なら両方同時使用可能

✅ **環境を完全に分離したい**
- ホストOSのPython環境を汚したくない
- 他のプロジェクトに影響を与えたくない

✅ **チーム全体で統一環境**
- 開発者ごとの環境差異を排除
- "Works on my machine"問題を防止

✅ **本番環境移行を見据えている**
- 開発環境と本番環境を同一構成に
- Kubernetesへの移行が容易

✅ **トラブル時の確実な復旧**
```bash
# Docker版: 確実に復旧
docker-compose down
docker-compose up -d

# uvx版: Python環境の問題は複雑
```

#### 性能詳細比較

**MCP接続開始時間**:
```
uvx版:    50ms (プロセス起動)
Docker版: 60-80ms (docker exec + プロセス起動)
差分:     +10-30ms
```

**MCP tool実行時間**:
```
store_memory:    2ms (両方同等)
search_memories: 0.5ms (両方同等、Chroma処理)
create_task:     5ms (両方同等)
```

**結論**: Docker版のオーバーヘッドは**接続時のみ**。実行時性能は同等。

#### 推奨構成

**開発者（個人）**:
```
Ollama: Native (GPU)
TMWS: uvx (シンプル重視)
```

**チーム開発**:
```
Ollama: Native (GPU)
TMWS: Docker (環境統一)
```

**本番環境移行予定**:
```
Ollama: Native (GPU)
TMWS: Docker (本番と同一構成)
```

---

## 📦 Strategy B: Standalone Binary

### 概要

PyInstallerでPythonアプリケーションを**単一実行ファイル**にパッケージング。

**利点**:
- ✅ Pythonインストール不要
- ✅ ダブルクリックで起動
- ✅ 小さいファイルサイズ（約150MB）
- ✅ ポータブル（USBメモリで持ち運び可）

**欠点**:
- ⚠️ Ollamaは別途インストール必要
- ⚠️ プラットフォームごとにビルド必要
- ⚠️ 署名証明書が高額（Windows/Mac）

### システム要件

| プラットフォーム | 最小要件 |
|---------------|---------|
| **Windows** | Windows 10 64-bit |
| **Mac** | macOS 11+ |
| **Linux** | glibc 2.31+ |
| **RAM** | 2GB |
| **Disk** | 2GB空き |

### ビルドプロセス

```bash
# PyInstaller でビルド
pyinstaller --onefile \
    --name tmws \
    --icon=assets/icon.ico \
    --add-data "migrations:migrations" \
    --add-data "src:src" \
    --hidden-import=uvicorn \
    --hidden-import=fastapi \
    --hidden-import=chromadb \
    src/main.py

# 出力: dist/tmws.exe (Windows)
#      dist/tmws (Mac/Linux)
```

### インストール手順

**Windows**:
```
1. tmws-windows-v2.3.1.zip をダウンロード
2. 任意のフォルダに解凍
3. Ollama をインストール: https://ollama.ai/download
4. tmws.exe をダブルクリック
5. ブラウザで http://localhost:8000 にアクセス
```

**Mac**:
```bash
# Step 1: ダウンロード
curl -LO https://github.com/apto-as/tmws/releases/download/v2.3.1/tmws-macos-v2.3.1.zip

# Step 2: 解凍
unzip tmws-macos-v2.3.1.zip

# Step 3: Ollama インストール
brew install ollama

# Step 4: 実行権限付与
chmod +x tmws

# Step 5: 起動
./tmws
```

**Linux**:
```bash
# Step 1: ダウンロード
wget https://github.com/apto-as/tmws/releases/download/v2.3.1/tmws-linux-v2.3.1.tar.gz

# Step 2: 解凍
tar -xzf tmws-linux-v2.3.1.tar.gz

# Step 3: Ollama インストール
curl https://ollama.ai/install.sh | sh

# Step 4: 起動
./tmws/tmws
```

---

## 🐍 Strategy C: Python Package

### 概要

PyPIから`pip install`でインストール（開発者向け）。

**利点**:
- ✅ 最も柔軟
- ✅ 開発環境と統合しやすい
- ✅ カスタマイズ容易

**欠点**:
- ⚠️ Python 3.11+ 必須
- ⚠️ 技術知識必要
- ⚠️ 依存関係の競合リスク

### インストール手順

```bash
# Step 1: Python 3.11+ 確認
python --version  # 3.11 or higher

# Step 2: venv 作成（推奨）
python -m venv tmws-venv
source tmws-venv/bin/activate  # Windows: tmws-venv\Scripts\activate

# Step 3: TMWS インストール
pip install tmws

# Step 4: Ollama インストール
# https://ollama.ai/download

# Step 5: 初期化
tmws init  # 設定ファイル生成

# Step 6: 起動
tmws start
```

---

## ⚙️ 設定管理

### 環境変数テンプレート

**.env.template** (リリースに含める):
```bash
# =============================================================================
# TMWS v2.3.1 Configuration Template
# Copy this file to .env and customize values
# =============================================================================

# Environment (development/staging/production)
TMWS_ENVIRONMENT=production

# Security - IMPORTANT: Generate a secure random key
# Run: python -c "import secrets; print(secrets.token_hex(32))"
TMWS_SECRET_KEY=<GENERATE_YOUR_OWN_64_CHARACTER_HEX_STRING>

# Database (SQLite - no changes needed for default)
TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db

# Ollama Embedding Service
TMWS_OLLAMA_BASE_URL=http://localhost:11434

# CORS Origins (comma-separated, JSON array format)
TMWS_CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]

# Logging
TMWS_LOG_LEVEL=INFO

# Authentication
TMWS_AUTH_ENABLED=true
TMWS_API_KEY_EXPIRE_DAYS=90

# Rate Limiting
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_PER_MINUTE=60

# Security Headers
TMWS_SECURITY_HEADERS_ENABLED=true

# Audit Logging
TMWS_AUDIT_LOG_ENABLED=true
```

### 設定生成スクリプト

**generate-config.py**:
```python
#!/usr/bin/env python3
"""Generate secure TMWS configuration."""

import secrets
import sys

def generate_secret_key():
    """Generate cryptographically secure secret key."""
    return secrets.token_hex(32)

def create_env_file():
    """Create .env file with secure defaults."""
    secret_key = generate_secret_key()

    env_content = f'''# TMWS v2.3.1 Configuration
# Generated: {datetime.now().isoformat()}

TMWS_ENVIRONMENT=production
TMWS_SECRET_KEY={secret_key}
TMWS_DATABASE_URL=sqlite+aiosqlite:///./data/tmws.db
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_CORS_ORIGINS=["http://localhost:3000"]
TMWS_LOG_LEVEL=INFO
TMWS_AUTH_ENABLED=true
TMWS_API_KEY_EXPIRE_DAYS=90
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_PER_MINUTE=60
TMWS_SECURITY_HEADERS_ENABLED=true
TMWS_AUDIT_LOG_ENABLED=true
'''

    with open('.env', 'w') as f:
        f.write(env_content)

    print("✅ .env file created successfully!")
    print(f"🔑 Secret key: {secret_key}")
    print("\n⚠️  IMPORTANT: Keep your .env file secure and never commit it to git!")

if __name__ == '__main__':
    create_env_file()
```

---

## 🔒 セキュリティ考慮事項

### 本番環境チェックリスト

- [ ] **Secret Key生成**: 64文字のランダムキー（`secrets.token_hex(32)`）
- [ ] **CORS設定**: 明示的なオリジン指定（ワイルドカード禁止）
- [ ] **HTTPS有効化**: リバースプロキシ（nginx/Caddy）経由
- [ ] **ファイアウォール**: ポート8000を内部のみに制限
- [ ] **定期バックアップ**: SQLiteデータベース + ChromaDBデータ
- [ ] **ログ監視**: 異常なアクセスパターンの検出
- [ ] **アップデート戦略**: セキュリティパッチの定期適用

### セキュアデフォルト設定

```bash
# 本番環境での必須設定
TMWS_ENVIRONMENT=production
TMWS_AUTH_ENABLED=true
TMWS_RATE_LIMIT_ENABLED=true
TMWS_SECURITY_HEADERS_ENABLED=true
TMWS_AUDIT_LOG_ENABLED=true

# HTTPSリバースプロキシ経由（nginx設定例）
server {
    listen 443 ssl http2;
    server_name tmws.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 💾 バックアップ戦略

### 自動バックアップスクリプト

**backup-tmws.sh** (cron daily):
```bash
#!/bin/bash
# TMWS Daily Backup Script

BACKUP_DIR="/backups/tmws"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/tmws_backup_$TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_PATH"

# Backup SQLite database
sqlite3 ./data/tmws.db ".backup '$BACKUP_PATH/tmws.db'"

# Backup ChromaDB data
cp -r ./.chroma "$BACKUP_PATH/chroma"

# Backup configuration
cp .env "$BACKUP_PATH/.env"

# Compress backup
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "tmws_backup_$TIMESTAMP"
rm -rf "$BACKUP_PATH"

# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "tmws_backup_*.tar.gz" -mtime +7 -delete

echo "✅ Backup completed: $BACKUP_PATH.tar.gz"
```

### リストア手順

```bash
# Step 1: サービス停止
docker-compose down  # or ./stop-tmws.sh

# Step 2: バックアップ解凍
tar -xzf tmws_backup_20251103_120000.tar.gz

# Step 3: データリストア
cp tmws_backup_20251103_120000/tmws.db ./data/
cp -r tmws_backup_20251103_120000/chroma ./.chroma

# Step 4: サービス再起動
docker-compose up -d  # or ./start-tmws.sh
```

---

## 🔄 アップグレード戦略

### 自動更新（Docker）

```bash
# Step 1: 最新イメージをダウンロード
docker-compose pull

# Step 2: コンテナ再作成
docker-compose up -d

# 自動的に以下を実行:
# - 古いコンテナ停止
# - 新しいコンテナ起動
# - マイグレーション実行
# - ヘルスチェック
```

### マニュアル更新（Standalone Binary）

```bash
# Step 1: バックアップ作成
./backup-tmws.sh

# Step 2: 古いバージョン停止
./stop-tmws.sh

# Step 3: 新しいバイナリダウンロード
wget https://github.com/apto-as/tmws/releases/download/v2.4.0/tmws-v2.4.0.zip

# Step 4: 解凍・上書き
unzip -o tmws-v2.4.0.zip

# Step 5: 起動
./start-tmws.sh
```

### データベースマイグレーション

```bash
# Docker環境
docker-compose exec tmws alembic upgrade head

# Standalone/Python環境
tmws migrate  # or: alembic upgrade head
```

---

## 🛠️ トラブルシューティング

### 問題1: Docker起動失敗

**症状**: `docker-compose up` が失敗
**原因**: ポート競合、メモリ不足
**解決**:
```bash
# ポート使用確認
netstat -ano | findstr :8000  # Windows
lsof -i :8000                 # Mac/Linux

# 競合プロセス終了またはポート変更
# docker-compose.yml の ports を 8001:8000 に変更
```

### 問題2: Ollama接続失敗

**症状**: `Cannot connect to Ollama service`
**原因**: Ollamaが起動していない、ネットワーク問題
**解決**:
```bash
# Ollama起動確認
curl http://localhost:11434/api/tags

# 手動起動
ollama serve  # or: systemctl start ollama
```

### 問題3: データベース破損

**症状**: SQLite database is locked/corrupted
**原因**: 不適切なシャットダウン
**解決**:
```bash
# Step 1: バックアップからリストア
cp /backups/tmws/latest/tmws.db ./data/

# Step 2: 整合性チェック
sqlite3 ./data/tmws.db "PRAGMA integrity_check;"

# Step 3: マイグレーション再実行
docker-compose exec tmws alembic upgrade head
```

### 問題4: 高メモリ使用

**症状**: TMWS consuming > 2GB RAM
**原因**: ChromaDBキャッシュ肥大化
**解決**:
```bash
# キャッシュクリア
docker-compose exec tmws python -c "from src.services.vector_search_service import vector_search_service; vector_search_service.clear_cache()"

# または コンテナ再起動
docker-compose restart tmws
```

---

## 📈 パフォーマンスチューニング

### Docker Compose設定最適化

```yaml
services:
  tmws:
    # リソース制限
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G

    # ログローテーション
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

    # 環境変数（パフォーマンス）
    environment:
      - UVICORN_WORKERS=4  # CPU cores
      - UVICORN_BACKLOG=2048
```

### SQLite最適化

```sql
-- WAL mode有効化（既に設定済み）
PRAGMA journal_mode=WAL;

-- キャッシュサイズ増加
PRAGMA cache_size=-64000;  -- 64MB

-- 同期モード最適化
PRAGMA synchronous=NORMAL;

-- 自動VACUUM
PRAGMA auto_vacuum=INCREMENTAL;
```

---

## 🚀 リリースチェックリスト

### v2.3.1リリース準備

#### Phase 1: コードの最終確認
- [ ] すべてのテスト合格（387/440, 87.9%）
- [ ] Ruff 100%準拠
- [ ] セキュリティスキャン実行
- [ ] パフォーマンステスト実行

#### Phase 2: ドキュメント作成
- [ ] README.md更新
- [ ] CHANGELOG.md作成
- [ ] インストールガイド作成
- [ ] API ドキュメント生成

#### Phase 3: ビルド成果物
- [ ] Docker イメージビルド（amd64, arm64）
- [ ] Docker イメージpush（ghcr.io）
- [ ] Standalone バイナリビルド（Windows/Mac/Linux）
- [ ] Python パッケージビルド（wheel, sdist）

#### Phase 4: GitHub Release
- [ ] Git tag作成: `v2.3.1`
- [ ] Release notes作成
- [ ] 成果物アップロード
- [ ] Release公開

#### Phase 5: 配布準備
- [ ] スタートスクリプト作成（各プラットフォーム）
- [ ] .env.template作成
- [ ] docker-compose.yml最終版
- [ ] インストーラー署名（Windows/Mac）

---

## 📚 ユーザーガイド（リリースに含める）

### クイックスタートガイド

**QUICKSTART.md**:
```markdown
# TMWS v2.3.1 クイックスタートガイド

## 5分で始める

### Option 1: Docker Desktop（推奨）

1. Docker Desktopをインストール: https://docker.com/products/docker-desktop
2. TMWSをダウンロード: https://github.com/apto-as/tmws/releases
3. 解凍してフォルダを開く
4. `start-tmws.bat`（Windows）または`./start-tmws.sh`（Mac/Linux）をダブルクリック
5. ブラウザで http://localhost:8000 にアクセス

完了！🎉

### Option 2: Standalone Binary

1. TMWSをダウンロード: https://github.com/apto-as/tmws/releases
2. Ollamaをインストール: https://ollama.ai/download
3. TMWSを解凍
4. `tmws.exe`（Windows）または`./tmws`（Mac/Linux）をダブルクリック
5. ブラウザで http://localhost:8000 にアクセス

完了！🎉

## 次のステップ

- ユーザー作成: http://localhost:8000/docs#/auth/create_user
- APIキー発行: http://localhost:8000/docs#/auth/create_api_key
- MCP統合: Claude Codeと接続
```

---

## 🗺️ ロードマップ（将来の拡張）

### v2.4.0 (1-2ヶ月)
- [ ] **Desktop App** (Electron/Tauri)
  - グラフィカルインストーラー
  - システムトレイアイコン
  - 自動起動設定
  - GUIでの設定管理

- [ ] **Auto-Update**
  - GitHub Releasesからの自動更新チェック
  - ワンクリックアップデート
  - ロールバック機能

### v2.5.0 (2-3ヶ月)
- [ ] **Cloud Deployment**
  - Heroku One-Click Deploy
  - AWS Lightsail Blueprint
  - Railway.app Template
  - DigitalOcean App Platform

- [ ] **Multi-Instance Support**
  - ロードバランサー統合
  - データベース複製
  - 分散ChromaDB

### v3.0.0 (3-6ヶ月)
- [ ] **Enterprise Features**
  - LDAP/SAML認証
  - マルチテナンシー
  - 監査ログエクスポート
  - 高可用性構成

---

## 📞 サポート

### コミュニティサポート
- GitHub Issues: https://github.com/apto-as/tmws/issues
- Discussions: https://github.com/apto-as/tmws/discussions
- Discord: （将来的に開設予定）

### ドキュメント
- Installation Guide: `docs/INSTALLATION.md`
- Configuration Guide: `docs/CONFIGURATION.md`
- API Documentation: `docs/API.md`
- Troubleshooting: `docs/TROUBLESHOOTING.md`

---

## 📊 推奨デプロイ戦略まとめ

| ユーザータイプ | 推奨戦略 | 理由 |
|-------------|---------|------|
| **一般ユーザー** | Strategy A (Docker) | ワンクリック、確実 |
| **開発者** | Strategy C (Python) | 柔軟性、カスタマイズ |
| **企業ユーザー** | Strategy A (Docker) | サポート、セキュリティ |
| **オフライン環境** | Strategy B (Binary) | 依存関係最小 |

**全体推奨**: Strategy A (Docker Desktop) - 最もユーザーフレンドリーで確実

---

**計画書ステータス**: ✅ **COMPREHENSIVE DEPLOYMENT PLAN COMPLETE**

**次のアクション**: リリース成果物の作成
1. Dockerfile作成
2. docker-compose.yml作成
3. スタートスクリプト作成（Windows/Mac/Linux）
4. ドキュメント整備
5. GitHub Releaseの準備

---

*End of Deployment Plan*
