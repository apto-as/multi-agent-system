# TMWS MCP Server - Docker版接続ガイド
## Docker Container Integration with Claude Desktop

**作成日**: 2025-11-03
**対象**: Docker版TMWSのMCPサーバー接続

---

## 📋 接続アーキテクチャの比較

### uvx版（ネイティブ）

```
┌─────────────────────────────────────────┐
│  Claude Desktop                         │
│  ┌─────────────────────────────────┐   │
│  │  MCP Client                     │   │
│  │  (stdio transport)              │   │
│  └──────────────┬──────────────────┘   │
│                 │ stdin/stdout          │
│                 ↓                       │
│  ┌─────────────────────────────────┐   │
│  │  uvx tmws-mcp-server            │   │ ← ホストOS上で直接実行
│  │  (Python process)               │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**特徴**:
- ✅ シンプルな直接接続
- ✅ レイテンシー最小（プロセス間通信のみ）
- ✅ 設定が簡単

### Docker版

```
┌─────────────────────────────────────────┐
│  Claude Desktop (Host OS)               │
│  ┌─────────────────────────────────┐   │
│  │  MCP Client                     │   │
│  │  (stdio transport)              │   │
│  └──────────────┬──────────────────┘   │
│                 │ stdin/stdout          │
│                 ↓                       │
│  ┌─────────────────────────────────┐   │
│  │  docker exec wrapper            │   │ ← Wrapper script
│  └──────────────┬──────────────────┘   │
└─────────────────┼───────────────────────┘
                  │ docker exec -i
                  ↓
┌─────────────────────────────────────────┐
│  Docker Container (tmws-app)            │
│  ┌─────────────────────────────────┐   │
│  │  tmws-mcp-server                │   │
│  │  (Python process)               │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**特徴**:
- ⚠️ Wrapper scriptが必要
- ⚠️ 若干のオーバーヘッド（docker execコスト）
- ✅ 環境完全分離
- ✅ 依存関係の衝突なし

---

## 🔧 接続設定（3つの方法）

### Option 1: docker exec wrapper（推奨）

**Step 1: Wrapper script作成**

**Mac/Linux** (`~/.local/bin/tmws-mcp-docker.sh`):
```bash
#!/bin/bash
# TMWS MCP Server - Docker Wrapper
# Claude Desktop -> docker exec -> TMWS Container

set -e

# Container name (docker-compose.yml参照)
CONTAINER_NAME="tmws-app"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: TMWS container '${CONTAINER_NAME}' is not running" >&2
    echo "Please start TMWS: docker-compose up -d" >&2
    exit 1
fi

# Execute MCP server in container
# -i: Keep stdin open (required for MCP stdio transport)
exec docker exec -i "${CONTAINER_NAME}" python -m src.mcp_server
```

**Windows** (`%USERPROFILE%\.local\bin\tmws-mcp-docker.bat`):
```batch
@echo off
REM TMWS MCP Server - Docker Wrapper for Windows

set CONTAINER_NAME=tmws-app

REM Check if container is running
docker ps --format "{{.Names}}" | findstr /X "%CONTAINER_NAME%" >nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: TMWS container '%CONTAINER_NAME%' is not running 1>&2
    echo Please start TMWS: docker-compose up -d 1>&2
    exit /b 1
)

REM Execute MCP server in container
docker exec -i %CONTAINER_NAME% python -m src.mcp_server
```

**Step 2: 実行権限付与**

```bash
# Mac/Linux
chmod +x ~/.local/bin/tmws-mcp-docker.sh

# Windows: 不要（.batは自動実行可能）
```

**Step 3: Claude Desktop設定**

**Mac/Linux** (`~/Library/Application Support/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/<your-username>/.local/bin/tmws-mcp-docker.sh"
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

---

### Option 2: docker exec直接（シンプル版）

**Claude Desktop設定**:

```json
{
  "mcpServers": {
    "tmws": {
      "command": "docker",
      "args": ["exec", "-i", "tmws-app", "python", "-m", "src.mcp_server"]
    }
  }
}
```

**利点**:
- ✅ Wrapper script不要
- ✅ 最もシンプル

**欠点**:
- ❌ コンテナ起動チェックなし（エラーメッセージ不親切）
- ❌ 環境変数の柔軟な設定が困難

---

### Option 3: SSE transport（将来実装）

**アーキテクチャ**:

```
Claude Desktop → HTTP (SSE) → TMWS Container (port 8000)
```

**docker-compose.yml**:
```yaml
services:
  tmws:
    ports:
      - "8000:8000"  # MCP SSE endpoint
```

**Claude Desktop設定**:
```json
{
  "mcpServers": {
    "tmws": {
      "url": "http://localhost:8000/mcp/sse"
    }
  }
}
```

**Status**: ⚠️ 未実装（FastMCPはSSE対応だが、TMWS側の実装が必要）

---

## 🔄 uvx版との差別化

### uvx版（ネイティブ実行）

**インストール**:
```bash
# PyPIからインストール
uvx --from tmws tmws-mcp-server

# または pip
pip install tmws
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

**特徴**:
| 観点 | 評価 | 詳細 |
|------|------|------|
| **インストール** | ⭐⭐⭐⭐⭐ | `uvx --from tmws tmws-mcp-server` 1コマンド |
| **接続レイテンシー** | ⭐⭐⭐⭐⭐ | 最小（プロセス間通信のみ） |
| **GPU対応** | ✅ | ネイティブOllama使用（Metal/CUDA） |
| **依存関係管理** | ⚠️ | ホストPython環境に依存 |
| **環境分離** | ❌ | ホストOSと共有 |
| **アップデート** | ⭐⭐⭐☆☆ | `uvx --upgrade tmws` |
| **トラブル時** | ⚠️ | Python環境の問題に影響される |

**適用場面**:
- ✅ 単一プロジェクトでのみTMWSを使用
- ✅ Python環境が整っている開発者
- ✅ 最小レイテンシーが必要
- ✅ GPU性能を最大限活用したい

### Docker版（コンテナ実行）

**インストール**:
```bash
# docker-compose起動
docker-compose up -d

# Wrapper script設定（1回のみ）
chmod +x ~/.local/bin/tmws-mcp-docker.sh
```

**Claude Desktop設定**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/<username>/.local/bin/tmws-mcp-docker.sh"
    }
  }
}
```

**特徴**:
| 観点 | 評価 | 詳細 |
|------|------|------|
| **インストール** | ⭐⭐⭐⭐☆ | Docker + wrapper script |
| **接続レイテンシー** | ⭐⭐⭐⭐☆ | docker execオーバーヘッド（~10-20ms） |
| **GPU対応** | ✅ | ネイティブOllama使用（Hybrid構成） |
| **依存関係管理** | ⭐⭐⭐⭐⭐ | 完全分離、衝突なし |
| **環境分離** | ⭐⭐⭐⭐⭐ | 完全分離 |
| **アップデート** | ⭐⭐⭐⭐⭐ | `docker-compose pull && docker-compose up -d` |
| **トラブル時** | ⭐⭐⭐⭐⭐ | コンテナ再起動で解決 |

**適用場面**:
- ✅ 複数プロジェクトでPython依存関係が競合
- ✅ 環境を完全に分離したい
- ✅ チーム全体で統一環境を維持したい
- ✅ 本番環境への移行を見据えている

---

## 📊 性能比較

### レイテンシー測定

| 操作 | uvx版 | Docker版 | 差分 |
|------|-------|----------|------|
| MCP接続開始 | 50ms | 60-80ms | +10-30ms (docker exec) |
| store_memory | 2ms | 2ms | 同等（コンテナ内処理） |
| search_memories | 0.5ms | 0.5ms | 同等（Chroma処理） |
| create_task | 5ms | 5ms | 同等 |

**結論**: Docker版のオーバーヘッドは**接続時のみ**（10-30ms）。実際のMCP tool実行は同等。

### メモリ使用量

| 構成 | 起動時 | アイドル時 | ピーク時 |
|------|--------|-----------|---------|
| uvx版 | 120MB | 150MB | 400MB |
| Docker版 | 200MB | 250MB | 500MB |

**Docker版の追加メモリ**: 約100MB（Dockerオーバーヘッド）

---

## 🔍 トラブルシューティング

### 1. "Container not running" エラー

**症状**:
```
Error: TMWS container 'tmws-app' is not running
```

**解決**:
```bash
# コンテナ起動確認
docker ps | grep tmws

# 起動していない場合
docker-compose up -d

# ログ確認
docker-compose logs -f tmws
```

### 2. "Connection refused" エラー

**症状**:
```
Error: Cannot connect to Ollama at http://host.docker.internal:11434
```

**解決（Mac Hybrid構成）**:
```bash
# Ollama起動確認
curl http://localhost:11434/api/tags

# 起動していない場合
ollama serve

# モデル確認
ollama list | grep multilingual-e5-large
```

### 3. 高レイテンシー（>100ms）

**症状**: MCP tool実行が遅い

**診断**:
```bash
# docker exec時間測定
time docker exec tmws-app echo "test"
# 期待値: <50ms

# コンテナリソース確認
docker stats tmws-app
```

**解決**:
```bash
# Docker Desktop設定
# Preferences > Resources > Memory: 4GB以上推奨

# コンテナ再起動
docker-compose restart tmws
```

---

## 🎯 推奨構成まとめ

### 開発者（シンプル重視）

```
Ollama: Native (GPU)
TMWS: uvx (ネイティブ)
```

**理由**: 最小レイテンシー、シンプル設定

### チーム開発（環境統一重視）

```
Ollama: Native (GPU)
TMWS: Docker (Hybrid構成)
```

**理由**: 環境分離、依存関係管理、統一環境

### 本番環境移行予定

```
Ollama: Native (GPU)
TMWS: Docker (Hybrid構成)
```

**理由**: 本番環境と同一構成、スケーラビリティ

---

## 📚 関連ドキュメント

- **MCP Tools Reference**: `docs/MCP_TOOLS_REFERENCE.md`
- **Production Deployment**: `PRODUCTION_DEPLOYMENT_PLAN.md`
- **Development Setup**: `docs/DEVELOPMENT_SETUP.md`

---

**End of Document**
