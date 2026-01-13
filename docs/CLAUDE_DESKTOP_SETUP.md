# Claude Desktop で Trinitas を使用する方法

## 概要

Claude Desktop では Claude Code と異なり、`~/.claude/CLAUDE.md` が自動的に読み込まれません。
そのため、TMWS の MCP Prompts 機能を使用して Trinitas コンテキストを読み込みます。

## セットアップ手順

### Step 1: TMWS-MCP をインストール

```bash
# ディレクトリ作成
mkdir -p ~/.tmws/bin ~/.tmws/db

# バイナリをダウンロード (macOS Apple Silicon)
curl -L -o ~/.tmws/bin/tmws-mcp \
  https://github.com/apto-as/tmws/releases/latest/download/tmws-mcp-darwin-arm64

# macOS Intel の場合
# curl -L -o ~/.tmws/bin/tmws-mcp \
#   https://github.com/apto-as/tmws/releases/latest/download/tmws-mcp-darwin-amd64

# Linux の場合
# curl -L -o ~/.tmws/bin/tmws-mcp \
#   https://github.com/apto-as/tmws/releases/latest/download/tmws-mcp-linux-amd64

# 実行権限を付与
chmod +x ~/.tmws/bin/tmws-mcp
```

### Step 2: 設定ファイルを作成

```bash
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
```

### Step 3: Claude Desktop の設定ファイルを編集

**設定ファイルの場所:**

| OS | パス |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**設定内容 (macOS 例):**

```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/YOUR_USERNAME/.tmws/bin/tmws-mcp",
      "args": [],
      "env": {
        "TMWS_CONFIG_PATH": "/Users/YOUR_USERNAME/.tmws/config.yaml",
        "OLLAMA_HOST": "http://localhost:11434"
      }
    }
  }
}
```

> **重要**: `~` や `$HOME` は展開されないため、フルパスを使用してください。

### Step 4: Ollama をインストール・起動

```bash
# macOS
brew install ollama
brew services start ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh
sudo systemctl enable ollama
sudo systemctl start ollama

# 必須モデルをダウンロード
ollama pull mxbai-embed-large
```

### Step 5: Claude Desktop を再起動

完全に終了してから再起動してください。

---

## Trinitas コンテキストの読み込み方法

Claude Desktop で会話を開始したら、**最初に以下のコマンドを入力**します:

```
/mcp__tmws__trinitas
```

これにより Trinitas オーケストレーションシステム (Clotho & Lachesis + 9 specialist agents) が有効になります。

### 利用可能なプロンプト

| プロンプト | コマンド | 内容 |
|-----------|---------|------|
| Trinitas システム | `/mcp__tmws__trinitas` | 完全なシステムコンテキスト |
| エージェント情報 | `/mcp__tmws__trinitas-agents` | 9エージェントの階層と役割 |
| クイックスタート | `/mcp__tmws__trinitas-quick-start` | 新規ユーザー向けガイド |
| SubAgent ルール | `/mcp__tmws__trinitas-subagent-rules` | SubAgent実行ルール |

---

## 使用例

### 例1: シンプルな会話

```
あなた: /mcp__tmws__trinitas

[Trinitasコンテキストが読み込まれる]

あなた: このAPIのパフォーマンスを改善したい

Clotho: パフォーマンス改善ね。Artemis に任せましょう。
Lachesis: 姉さん、まずは現状のボトルネックを確認した方がいいわ。
```

### 例2: Trinitas Full Mode

```
あなた: /mcp__tmws__trinitas

あなた: Trinitas Full Mode でセキュリティ監査を実施して

Clotho: Full Mode で進めるわ。Phase 1 で Hera と Athena を並列起動するわね。
[Hera と Athena が戦略分析を実行]
```

---

## トラブルシューティング

### プロンプトが見つからない

```bash
# TMWS-MCP が正しく設定されているか確認
echo '{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{}}' | \
  TMWS_CONFIG_PATH=~/.tmws/config.yaml ~/.tmws/bin/tmws-mcp 2>/dev/null
```

期待される出力:

```json
{"jsonrpc":"2.0","id":1,"result":{"prompts":[{"name":"trinitas",...}]}}
```

### Claude Desktop が TMWS を認識しない

1. 設定ファイルのパスが正しいか確認
2. Claude Desktop を完全に再起動
3. ログファイルを確認:
   - macOS: `~/Library/Logs/Claude/mcp*.log`
   - Windows: `%APPDATA%\Claude\logs\mcp*.log`

### Ollama 接続エラー

```bash
# Ollama が起動しているか確認
curl http://localhost:11434/api/version

# 起動していない場合
ollama serve
```

---

## Claude Code との違い

| 機能 | Claude Code | Claude Desktop |
|------|-------------|----------------|
| CLAUDE.md 自動読み込み | ○ | × |
| MCP Prompts | ○ | ○ |
| MCP Tools | ○ | ○ |
| Task tool (SubAgent) | ○ | × |

> **注意**: Claude Desktop では Task tool (SubAgent の並列起動) は利用できません。
> 単一の会話として Trinitas のコンテキストを使用することは可能です。

---

## バージョン情報

| コンポーネント | バージョン |
|---------------|-----------|
| TMWS-MCP | v2.5.0+ |
| MCP Prompts | 4種類 |

---

*Trinitas Multi-Agent System - Claude Desktop Setup Guide*
*Last Updated: 2026-01-13*
