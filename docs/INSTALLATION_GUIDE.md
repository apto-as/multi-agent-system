# Trinitas Multi-Agent System v2.4.37 導入手順書

## 対象環境

| 環境 | OS | 前提条件 |
|------|----|---------|
| Linux | Ubuntu 22.04+ / Debian 12+ | Git, curl |
| macOS | macOS 13+ (Ventura以降) | Git, curl |
| WSL2 | Windows 10/11 + WSL2 | Ubuntu/Debian in WSL2 |

## 目次

1. [前提条件の確認](#1-前提条件の確認)
2. [Claude Code のインストール](#2-claude-code-のインストール)
3. [Ollama のインストール](#3-ollama-のインストール)
4. [Trinitas のインストール](#4-trinitas-のインストール)
5. [動作確認](#5-動作確認)
6. [トラブルシューティング](#6-トラブルシューティング)

> **Claude Desktop をお使いの方へ**: [Claude Desktop セットアップガイド](./CLAUDE_DESKTOP_SETUP.md) を参照してください。

---

## 1. 前提条件の確認

### 1.1 必要なシステム要件

| 要件 | 最小スペック | 推奨スペック |
|------|-------------|-------------|
| RAM | 8GB | 16GB以上 |
| ディスク | 10GB空き | 30GB以上空き |
| CPU | 4コア | 8コア以上 |
| GPU | 不要 | NVIDIA GPU (オプション) |

### 1.2 ネットワーク要件

以下のポートが使用されます:

| ポート | 用途 |
|--------|------|
| 33333 | TMWS REST API |
| 11434 | Ollama API |

### 1.3 必要なツールの確認

```bash
# Git
git --version
# 出力例: git version 2.x.x

# curl
curl --version
# 出力例: curl 8.x.x
```

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
# TMWS が使用する埋め込みモデルをダウンロード
ollama pull mxbai-embed-large

# ダウンロード確認（約600MB）
ollama list
# 出力例:
# NAME                       SIZE
# mxbai-embed-large:latest   669 MB
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

## 4. Trinitas のインストール

### 4.1 クイックセットアップ（`claude mcp add` 推奨）

最も簡単なセットアップ方法です:

```bash
# 1. ディレクトリ作成
mkdir -p ~/.tmws/bin ~/.tmws/db

# 2. TMWS-Go バイナリをダウンロード（プラットフォームに合わせて選択）
# macOS (Apple Silicon)
curl -L -o ~/.tmws/bin/tmws-mcp \
  https://github.com/apto-as/tmws_go/releases/latest/download/tmws-mcp-darwin-arm64

# macOS (Intel)
curl -L -o ~/.tmws/bin/tmws-mcp \
  https://github.com/apto-as/tmws_go/releases/latest/download/tmws-mcp-darwin-amd64

# Linux / WSL2 (x86_64)
curl -L -o ~/.tmws/bin/tmws-mcp \
  https://github.com/apto-as/tmws_go/releases/latest/download/tmws-mcp-linux-amd64

# 3. 実行権限を付与
chmod +x ~/.tmws/bin/tmws-mcp

# 4. 設定ファイルを作成
cat > ~/.tmws/config.yaml << 'EOF'
database:
  driver: "sqlite3"
  path: "~/.tmws/db/tmws.db"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m

vector:
  backend: "sqlite-vec"
  dimension: 1024
  distance: "cosine"

memory:
  default_ttl: 720h
  max_memories_per_namespace: 10000
  cleanup_interval: 1h

embedding:
  provider: "ollama"
  model: "mxbai-embed-large"
  dimension: 1024
  batch_size: 32
EOF

# 5. Claude Code に MCP サーバーとして追加
# 注意: 環境変数は通常不要（自動検出される）
claude mcp add tmws --scope user -- $HOME/.tmws/bin/tmws-mcp

# カスタム設定が必要な場合のみ:
# claude mcp add tmws \
#   -e TMWS_CONFIG_PATH=$HOME/.tmws/config.yaml \
#   -e TMWS_OLLAMA_URL=http://localhost:11434 \
#   --scope user \
#   -- $HOME/.tmws/bin/tmws-mcp

# 6. 確認
claude mcp list
```

**代替方法: JSON設定ファイルを直接編集（推奨）**

`claude mcp add` でエラーが発生する場合、`~/.claude.json` を直接編集:

```json
{
  "mcpServers": {
    "tmws": {
      "type": "stdio",
      "command": "/Users/YOUR_USERNAME/.tmws/bin/tmws-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

> **Note**: 環境変数は通常不要です。`~/.tmws/config.yaml` は自動検出され、Ollama はデフォルトで `localhost:11434` を使用します。

**カスタム設定が必要な場合のみ:**

| 環境変数 | デフォルト | 説明 |
|---------|-----------|------|
| `TMWS_CONFIG_PATH` | `~/.tmws/config.yaml` を自動検出 | カスタム設定ファイルパス |
| `TMWS_OLLAMA_URL` | `http://localhost:11434` | Ollama サーバー URL |

> **重要**: JSON設定では `~` や `$HOME` は展開されないため、絶対パスを使用してください。

### 4.2 ワンコマンドインストール（11エージェント完全版）

11エージェントのペルソナ設定を含む完全インストール:

```bash
curl -fsSL https://raw.githubusercontent.com/apto-as/multi-agent-system/main/install.sh | bash
```

### 4.3 手動インストール（詳細確認したい場合）

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

### 4.4 インストール後のディレクトリ構成

```
~/.tmws/                  # TMWS-Go 設定・データ
├── bin/
│   └── tmws-mcp         # TMWS-Go バイナリ
├── db/
│   └── tmws.db          # SQLite データベース
├── config.yaml          # TMWS 設定ファイル
└── logs/                # ログファイル

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
```

---

## 5. 動作確認

### 5.1 TMWS プロセスの確認

```bash
# MCP サーバーが正しく応答するか確認
echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
  TMWS_CONFIG_PATH=~/.tmws/config.yaml ~/.tmws/bin/tmws-mcp 2>/dev/null | head -1

# 正常応答例:
# {"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2024-11-05",...}}
```

### 5.2 REST API 確認

```bash
# ヘルスチェック（TMWS-Go は REST API も提供）
curl -s http://localhost:33333/health | jq .

# 出力例:
# {
#   "status": "healthy",
#   "version": "2.4.36",
#   "components": {
#     "database": "healthy",
#     "vector_store": "healthy",
#     "ollama": "healthy"
#   }
# }
```

### 5.3 Claude Code での確認

```bash
# 任意のプロジェクトディレクトリで Claude Code を起動
cd ~/your-project
claude

# Claude Code 内で以下を入力:
# /trinitas status

# または直接メモリをテスト:
# 「TMWSのメモリに "テスト記憶" を保存して」
```

### 5.4 MCP 接続一覧

```bash
# 登録されている MCP サーバーを確認
claude mcp list

# 出力例:
# tmws: ~/.tmws/bin/tmws-mcp
```

### 5.5 ツール一覧の確認

Claude Code 内で:

```
TMWSで利用可能なツールを一覧表示して
```

期待される出力（140+ ツール）:

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

## 6. トラブルシューティング

### 6.1 TMWS バイナリ関連

#### バイナリが見つからない

```bash
# バイナリが存在するか確認
ls -la ~/.tmws/bin/tmws-mcp

# 実行権限を確認・付与
chmod +x ~/.tmws/bin/tmws-mcp

# 手動でダウンロードし直す
curl -L -o ~/.tmws/bin/tmws-mcp \
  https://github.com/apto-as/tmws_go/releases/latest/download/tmws-mcp-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
chmod +x ~/.tmws/bin/tmws-mcp
```

#### 設定ファイルエラー

```bash
# 設定ファイルの確認
cat ~/.tmws/config.yaml

# 環境変数が設定されているか確認
echo $TMWS_CONFIG_PATH
```

### 6.2 Ollama 関連

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
ollama pull mxbai-embed-large
```

#### SSH/リモート環境でOllamaが停止する

```bash
# systemd サービスとして起動（推奨）
sudo systemctl enable ollama
sudo systemctl start ollama

# 状態確認
systemctl status ollama
```

### 6.3 MCP 接続関連

#### Claude Code が TMWS に接続できない

```bash
# MCP 設定を確認
cat ~/.claude/settings.json

# 最小構成の設定例:
# {
#   "mcpServers": {
#     "tmws": {
#       "command": "/Users/YOUR_USERNAME/.tmws/bin/tmws-mcp",
#       "args": [],
#       "env": {}
#     }
#   }
# }
#
# Note: 環境変数は通常不要。~/.tmws/config.yaml は自動検出されます。

# claude mcp add で再登録
claude mcp remove tmws
claude mcp add tmws --scope user -- $HOME/.tmws/bin/tmws-mcp
```

### 6.4 パーミッション関連

#### ファイル書き込みエラー

```bash
# ~/.tmws の権限を確認
ls -la ~/.tmws

# 権限を修正
chmod -R 755 ~/.tmws

# データベースファイルの権限
chmod 644 ~/.tmws/db/tmws.db
```

---

## 環境別チェックリスト

### Linux

- [ ] Node.js v20+ インストール済み
- [ ] npm グローバルパスが PATH に含まれている
- [ ] Claude Code インストール済み (`claude --version`)
- [ ] Ollama インストール済み (`curl localhost:11434/api/version`)
- [ ] Ollama が systemd で起動している
- [ ] mxbai-embed-large モデルがダウンロード済み
- [ ] TMWS-Go バイナリがインストール済み (`~/.tmws/bin/tmws-mcp`)
- [ ] TMWS 設定ファイルが存在 (`~/.tmws/config.yaml`)
- [ ] Claude Code に TMWS が登録済み (`claude mcp list`)

### macOS

- [ ] Node.js インストール済み (`node --version`)
- [ ] Claude Code インストール済み (`claude --version`)
- [ ] Ollama インストール済み・起動中
- [ ] mxbai-embed-large モデルがダウンロード済み
- [ ] TMWS-Go バイナリがインストール済み
- [ ] TMWS 設定ファイルが存在
- [ ] Claude Code に TMWS が登録済み

### WSL2 (Windows)

- [ ] WSL2 が有効化されている (`wsl --status`)
- [ ] Ubuntu/Debian がインストールされている
- [ ] 上記 Linux チェックリストを完了

---

## バージョン情報

| コンポーネント | バージョン | 確認コマンド |
|---------------|-----------|-------------|
| TMWS-Go | v2.4.37 | `~/.tmws/bin/tmws-mcp --version` |
| Ollama Model | mxbai-embed-large | `ollama list` |
| Claude Code | Latest | `claude --version` |

---

## サポート

問題が解決しない場合:

1. GitHub Issues: https://github.com/apto-as/multi-agent-system/issues
2. TMWS-Go Issues: https://github.com/apto-as/tmws_go/issues

---

*Trinitas Multi-Agent System v2.4.37*
*Powered by TMWS-Go Native Mode*
*Last Updated: 2026-01-11*
