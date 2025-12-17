# Trinitas Multi-Agent System v2.4.22 導入手順書

## 対象環境

| 環境 | OS | 前提条件 |
|------|----|---------|
| Linux | Ubuntu 22.04+ / Debian 12+ | conda仮想環境構築済み |
| macOS | macOS 13+ (Ventura以降) | conda仮想環境構築済み |

## 目次

1. [前提条件の確認](#1-前提条件の確認)
2. [Claude Code のインストール](#2-claude-code-のインストール)
3. [Ollama のインストール](#3-ollama-のインストール)
4. [Docker のインストール](#4-docker-のインストール)
5. [Trinitas のインストール](#5-trinitas-のインストール)
6. [動作確認](#6-動作確認)
7. [トラブルシューティング](#7-トラブルシューティング)

---

## 1. 前提条件の確認

### 1.1 conda環境の確認

```bash
# condaがインストールされていることを確認
conda --version
# 出力例: conda 24.x.x

# 現在の環境を確認
conda info --envs
```

### 1.2 必要なシステム要件

| 要件 | 最小スペック | 推奨スペック |
|------|-------------|-------------|
| RAM | 8GB | 16GB以上 |
| ディスク | 20GB空き | 50GB以上空き |
| CPU | 4コア | 8コア以上 |
| GPU | 不要 | NVIDIA GPU (オプション) |

### 1.3 ネットワーク要件

以下のポートが使用されます:

| ポート | 用途 |
|--------|------|
| 8000 | TMWS REST API |
| 8892 | TMWS MCP Server |
| 11434 | Ollama API |

---

## 2. Claude Code のインストール

### 2.1 Linux (Ubuntu/Debian)

```bash
# Node.js がインストールされていない場合
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# npm のバージョン確認
npm --version

# Claude Code をグローバルインストール
npm install -g @anthropic-ai/claude-code

# インストール確認
claude --version
```

### 2.2 macOS

```bash
# Homebrew で Node.js をインストール（未インストールの場合）
brew install node

# Claude Code をグローバルインストール
npm install -g @anthropic-ai/claude-code

# インストール確認
claude --version
```

### 2.3 PATH設定（コマンドが見つからない場合）

```bash
# npmのグローバルbin パスを確認
npm root -g

# ~/.bashrc または ~/.zshrc に追加
echo 'export PATH="$PATH:$(npm root -g)/.bin"' >> ~/.zshrc
source ~/.zshrc

# 再確認
claude --version
```

### 2.4 Claude Code の初回認証

```bash
# Claude Code を起動して認証
claude

# ブラウザが開き、Anthropic アカウントでログイン
# API キーの設定は自動で行われます
```

---

## 3. Ollama のインストール

Ollama は TMWS のベクトル埋め込み生成に必要です。

### 3.1 Linux (Ubuntu/Debian)

```bash
# Ollama インストール（systemd サービスも自動登録）
curl -fsSL https://ollama.ai/install.sh | sh

# サービス状態確認
sudo systemctl status ollama

# サービスが起動していない場合
sudo systemctl enable ollama
sudo systemctl start ollama

# 動作確認
curl http://localhost:11434/api/version
```

### 3.2 macOS

```bash
# Homebrew でインストール
brew install ollama

# Ollama サービスを起動
brew services start ollama

# または手動起動
ollama serve &

# 動作確認
curl http://localhost:11434/api/version
```

### 3.3 必須モデルのダウンロード

```bash
# TMWS が使用する多言語埋め込みモデルをダウンロード
ollama pull zylonai/multilingual-e5-large

# ダウンロード確認（約2GB）
ollama list
# 出力例:
# NAME                                    SIZE
# zylonai/multilingual-e5-large:latest    2.2 GB
```

### 3.4 SSH/リモートサーバーでの永続化

SSH接続が切断されてもOllamaが動作し続けるようにする:

```bash
# systemd サービスとして起動（推奨）
sudo systemctl enable ollama
sudo systemctl start ollama

# 自動起動の確認
systemctl is-enabled ollama
# 出力: enabled

# または tmux/screen を使用
tmux new -s ollama
ollama serve
# Ctrl+B, D でデタッチ
```

---

## 4. Docker のインストール

### 4.1 Linux (Ubuntu/Debian)

```bash
# 公式スクリプトでインストール
curl -fsSL https://get.docker.com | sudo sh

# 現在のユーザーを docker グループに追加（sudo なしで実行可能に）
sudo usermod -aG docker $USER

# グループ変更を反映（再ログインまたは以下を実行）
newgrp docker

# インストール確認
docker --version
docker compose version

# Docker が起動しているか確認
docker info
```

### 4.2 macOS

```bash
# Homebrew で Docker Desktop をインストール
brew install --cask docker

# Docker Desktop を起動（初回は手動起動が必要）
open -a Docker

# 起動を待つ（約30秒）
sleep 30

# インストール確認
docker --version
docker compose version
```

### 4.3 Docker 動作確認

```bash
# テストコンテナを実行
docker run --rm hello-world

# 出力に "Hello from Docker!" が含まれていれば成功
```

---

## 5. Trinitas のインストール

### 5.1 ワンコマンドインストール

すべての前提条件が満たされていれば、以下の1コマンドでインストール完了:

```bash
curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash
```

### 5.2 手動インストール（詳細確認したい場合）

```bash
# リポジトリをクローン
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system

# インストールスクリプトを確認
cat install.sh

# 実行
chmod +x install.sh
./install.sh
```

### 5.3 インストール中の対話

```
🚀 Trinitas Multi-Agent System Installer v2.4.22
================================================

Checking prerequisites...
✓ Docker is installed
✓ Git is installed
✓ Ollama is running
✓ Required model is available

Do you want to proceed with installation? [Y/n] Y

Installing TMWS container...
✓ Container started successfully

Installing Claude Code configuration...
✓ Agent configurations installed
✓ MCP server configured

Installation complete!
```

### 5.4 インストール後のディレクトリ構成

```
~/.trinitas/              # TMWS Docker Compose 設定
├── docker-compose.yml
├── .env
└── presets/              # MCP プリセット

~/.claude/                # Claude Code 設定
├── CLAUDE.md            # Clotho + Lachesis 設定
├── AGENTS.md            # エージェント協調プロトコル
├── SUBAGENT_EXECUTION_RULES.md
├── agents/              # 11 エージェント定義
│   ├── clotho-orchestrator.md
│   ├── lachesis-support.md
│   ├── hera-strategist.md
│   └── ... (9 specialists)
├── commands/
│   └── trinitas.md
└── settings.json        # MCP サーバー設定

~/.tmws/                  # TMWS データ
├── tmws.db              # SQLite データベース
├── vector_store/        # ChromaDB ベクトルストア
└── logs/                # ログファイル
```

---

## 6. 動作確認

### 6.1 TMWS コンテナの確認

```bash
# コンテナ状態確認
docker ps | grep tmws

# 出力例:
# abc123  aptoas/tmws:latest  ...  Up 5 minutes  tmws-app

# ログ確認
docker logs tmws-app | tail -20
```

### 6.2 MCP 接続テスト

```bash
# MCP サーバーの応答確認（約20-25秒かかる）
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
docker exec -i tmws-app tmws-mcp-server | head -1

# 正常応答例:
# {"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2024-11-05",...}}
```

### 6.3 REST API 確認

```bash
# ヘルスチェック
curl -s http://localhost:8000/health | jq .

# 出力例:
# {
#   "status": "healthy",
#   "version": "2.4.22",
#   "components": {
#     "database": "healthy",
#     "vector_store": "healthy",
#     "ollama": "healthy"
#   }
# }
```

### 6.4 Claude Code での確認

```bash
# 任意のプロジェクトディレクトリで Claude Code を起動
cd ~/your-project
claude

# Claude Code 内で以下を入力:
# /trinitas status

# または直接メモリをテスト:
# 「TMWSのメモリに "テスト記憶" を保存して」
```

### 6.5 ツール一覧の確認

Claude Code 内で:

```
TMWSで利用可能なツールを一覧表示して
```

期待される出力（42ツール）:

```
Memory Tools:
- store_memory
- search_memories
- get_memory_stats
...

Agent Tools:
- list_agents
- get_recommended_agents
...

Verification Tools:
- verify_and_record
- get_agent_trust_score
...
```

---

## 7. トラブルシューティング

### 7.1 Docker 関連

#### コンテナが起動しない

```bash
# ログを確認
docker logs tmws-app

# コンテナを再作成
cd ~/.trinitas
docker compose down
docker compose up -d

# イメージを再取得
docker compose pull
docker compose up -d
```

#### ポートが使用中

```bash
# 8000番ポートを使用しているプロセスを確認
lsof -i :8000
# または
sudo netstat -tlnp | grep 8000

# 必要に応じてプロセスを終了
kill -9 <PID>
```

### 7.2 Ollama 関連

#### Ollama が起動しない

```bash
# プロセス確認
pgrep -a ollama

# 手動起動
ollama serve

# ポート確認
curl http://localhost:11434/api/version
```

#### モデルがダウンロードされていない

```bash
# 利用可能なモデル確認
ollama list

# モデルを再ダウンロード
ollama pull zylonai/multilingual-e5-large
```

### 7.3 MCP 接続関連

#### Claude Code が TMWS に接続できない

```bash
# MCP 設定を確認
cat ~/.claude/settings.json

# 設定例:
# {
#   "mcpServers": {
#     "tmws": {
#       "command": "docker",
#       "args": ["exec", "-i", "tmws-app", "tmws-mcp-server"]
#     }
#   }
# }

# コンテナ名を確認
docker ps --format '{{.Names}}'
```

#### MCP ハンドシェイクがタイムアウト

```bash
# コンテナ内の初期化ログを確認
docker logs tmws-app 2>&1 | grep -E "(Started|Phase|MCP)"

# コンテナを再起動
docker restart tmws-app

# 20-30秒待ってから再接続
```

### 7.4 パーミッション関連

#### Docker 権限エラー

```bash
# ユーザーを docker グループに追加
sudo usermod -aG docker $USER

# ログアウト・ログインするか、以下を実行
newgrp docker
```

#### ファイル書き込みエラー

```bash
# ~/.tmws の権限を確認
ls -la ~/.tmws

# 権限を修正
chmod -R 755 ~/.tmws
```

---

## 環境別チェックリスト

### Linux

- [ ] Node.js v20+ インストール済み
- [ ] npm グローバルパスが PATH に含まれている
- [ ] Claude Code インストール済み (`claude --version`)
- [ ] Docker インストール済み (`docker --version`)
- [ ] 現在のユーザーが docker グループに所属
- [ ] Ollama インストール済み (`curl localhost:11434/api/version`)
- [ ] Ollama が systemd で起動している
- [ ] zylonai/multilingual-e5-large モデルがダウンロード済み
- [ ] Trinitas インストーラー実行済み
- [ ] tmws-app コンテナが起動中 (`docker ps`)

### macOS

- [ ] Node.js インストール済み (`node --version`)
- [ ] Claude Code インストール済み (`claude --version`)
- [ ] Docker Desktop インストール済み・起動中
- [ ] Ollama インストール済み・起動中
- [ ] zylonai/multilingual-e5-large モデルがダウンロード済み
- [ ] Trinitas インストーラー実行済み
- [ ] tmws-app コンテナが起動中

---

## バージョン情報

| コンポーネント | バージョン | 確認コマンド |
|---------------|-----------|-------------|
| TMWS | v2.4.22 | `docker logs tmws-app \| head -5` |
| Docker Image | aptoas/tmws:2.4.22 | `docker images aptoas/tmws` |
| Ollama Model | multilingual-e5-large | `ollama list` |
| Claude Code | Latest | `claude --version` |

---

## サポート

問題が解決しない場合:

1. GitHub Issues: https://github.com/apto-as/multi-agent-system/issues
2. TMWS Issues: https://github.com/apto-as/tmws/issues

---

*Trinitas Multi-Agent System v2.4.22*
*Last Updated: 2025-12-17*
