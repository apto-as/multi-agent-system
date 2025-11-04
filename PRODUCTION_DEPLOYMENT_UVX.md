# TMWS v2.3.1 本番デプロイ計画書（uvx版）
## Production Deployment Plan - Individual Developer Configuration

**作成日**: 2025-11-03
**対象バージョン**: v2.3.1
**対象構成**: 個人開発者（Ollama Native + TMWS uvx）
**対象プラットフォーム**: Mac/Linux

---

## 📊 エグゼクティブサマリー

**推奨構成**: Ollama Native (GPU) + TMWS uvx

```
┌──────────────────────────────────┐
│  Host OS (Mac/Linux)             │
├──────────────────────────────────┤
│  ┌────────────────────────────┐  │
│  │ Ollama (Native)            │  │ ← Metal/CUDA GPU使用
│  │ Port: 11434                │  │
│  └────────────────────────────┘  │
│                                  │
│  ┌────────────────────────────┐  │
│  │ TMWS (uvx/pip)             │  │
│  │ + SQLite                   │  │
│  │ + ChromaDB                 │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

**特徴**:
- ✅ シンプルな構成（最小レイテンシー）
- ✅ GPU性能最大化（Metal/CUDA）
- ✅ インストール1コマンド
- ✅ 環境変数で設定管理
- ✅ systemd/launchdで自動起動

---

## 🎯 デプロイ目標

| 目標 | 実現方法 |
|-----|---------|
| **GPU性能最大化** | Ollama native (Metal/CUDA) |
| **シンプルインストール** | uvx 1コマンド |
| **自動起動** | systemd (Linux) / launchd (Mac) |
| **簡単バックアップ** | SQLite + ChromaDB ファイルコピー |
| **迅速アップデート** | uvx --upgrade tmws |

---

## 📋 システム要件

### ハードウェア要件

| 項目 | 最小 | 推奨 |
|------|------|------|
| **CPU** | 2コア | 4コア以上 |
| **RAM** | 4GB | 8GB以上 |
| **Disk** | 10GB空き | 20GB以上 |
| **GPU** | なし（CPU可） | Metal (Mac) / CUDA (Linux) |

### ソフトウェア要件

| ソフトウェア | Mac | Linux |
|-------------|-----|-------|
| **OS** | macOS 11+ | Ubuntu 20.04+ |
| **Python** | 3.11+ | 3.11+ |
| **uv** | ✅ | ✅ |
| **Ollama** | ✅ Native | ✅ Native |
| **Claude Desktop** | ✅ | ✅ |

---

## 🚀 インストール手順

### Phase 1: 基本環境セットアップ

#### 🍎 Mac環境

```bash
# Step 1: Homebrewインストール（未インストールの場合）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Step 2: Python 3.11+確認
python3 --version
# Python 3.11.x 以上であることを確認

# 古い場合はインストール
brew install python@3.11

# Step 3: uvインストール
curl -LsSf https://astral.sh/uv/install.sh | sh

# パスを通す
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# 動作確認
uv --version
# uv 0.4.x
```

#### 🐧 Linux環境 (Ubuntu/Debian)

```bash
# Step 1: Python 3.11+インストール
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip

# Step 2: uvインストール
curl -LsSf https://astral.sh/uv/install.sh | sh

# パスを通す
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 動作確認
uv --version
```

### Phase 2: Ollamaインストール

#### 🍎 Mac環境

```bash
# Step 1: Ollama ダウンロード & インストール
curl -fsSL https://ollama.ai/install.sh | sh

# または公式サイトからDMG
# https://ollama.ai/download

# Step 2: Ollama起動確認
ollama --version
# ollama version is 0.1.x

# Step 3: モデルダウンロード（約1GB、10-15分）
ollama pull zylonai/multilingual-e5-large

# Step 4: Ollama起動（バックグラウンド）
ollama serve &

# または自動起動設定（後述）

# Step 5: 動作確認
curl http://localhost:11434/api/tags
# {"models":[{"name":"zylonai/multilingual-e5-large:latest",...}]}
```

#### 🐧 Linux環境

```bash
# Step 1: Ollamaインストール
curl -fsSL https://ollama.ai/install.sh | sh

# Step 2: GPU確認（NVIDIA GPUがある場合）
nvidia-smi
# GPU情報が表示されればOK

# Step 3: モデルダウンロード
ollama pull zylonai/multilingual-e5-large

# Step 4: Ollama起動
ollama serve &

# Step 5: 動作確認
curl http://localhost:11434/api/tags
```

### Phase 3: TMWS インストール

#### uvx経由インストール（推奨）

```bash
# Step 1: TMWSインストール（uvxが自動でvenv作成）
uvx --from tmws tmws-mcp-server --version
# tmws version 2.3.1

# これだけでインストール完了！
```

#### pip経由インストール（代替）

```bash
# Step 1: venv作成
python3.11 -m venv ~/.tmws-venv
source ~/.tmws-venv/bin/activate

# Step 2: TMWSインストール
pip install tmws

# Step 3: 動作確認
tmws-mcp-server --version
# tmws version 2.3.1
```

### Phase 4: TMWS 初期設定

```bash
# Step 1: データディレクトリ作成
mkdir -p ~/.tmws/data
mkdir -p ~/.tmws/config
mkdir -p ~/.tmws/.chroma

# Step 2: 環境変数設定
cat > ~/.tmws/.env << 'EOF'
# TMWS v2.3.1 Configuration
TMWS_ENVIRONMENT=production
TMWS_SECRET_KEY=$(openssl rand -hex 32)
TMWS_DATABASE_URL=sqlite+aiosqlite:///$HOME/.tmws/data/tmws.db
TMWS_OLLAMA_BASE_URL=http://localhost:11434
TMWS_LOG_LEVEL=INFO
TMWS_CORS_ORIGINS=["http://localhost:3000"]
TMWS_AUTH_ENABLED=true
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_PER_MINUTE=60
EOF

# SECRET_KEY生成
SECRET_KEY=$(openssl rand -hex 32)
sed -i.bak "s/\$(openssl rand -hex 32)/${SECRET_KEY}/" ~/.tmws/.env

# Step 3: 環境変数読み込み
export $(cat ~/.tmws/.env | xargs)

# Step 4: データベースマイグレーション
# （初回起動時に自動実行されるため、手動実行は不要）
```

### Phase 5: Claude Desktop MCP接続設定

```bash
# Step 1: Claude Desktop設定ファイル編集
# Mac:
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Linux:
nano ~/.config/claude/claude_desktop_config.json

# Step 2: 以下のJSON設定を追加
```

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "tmws", "tmws-mcp-server"],
      "env": {
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///~/.tmws/data/tmws.db",
        "TMWS_OLLAMA_BASE_URL": "http://localhost:11434"
      }
    }
  }
}
```

**pip版の場合**:
```json
{
  "mcpServers": {
    "tmws": {
      "command": "/Users/<username>/.tmws-venv/bin/tmws-mcp-server",
      "env": {
        "TMWS_DATABASE_URL": "sqlite+aiosqlite:///~/.tmws/data/tmws.db",
        "TMWS_OLLAMA_BASE_URL": "http://localhost:11434"
      }
    }
  }
}
```

```bash
# Step 3: Claude Desktop再起動
# Mac: Cmd+Q → 再起動
# Linux: killall claude-desktop && claude-desktop &

# Step 4: MCP接続確認
# Claude Desktop → Settings → Developer → MCP Servers
# "tmws" が表示され、緑色のステータスであることを確認
```

---

## 🔄 自動起動設定

### 🍎 Mac (launchd)

```bash
# Step 1: Ollama自動起動設定
cat > ~/Library/LaunchAgents/com.ollama.serve.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ollama.serve</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ollama</string>
        <string>serve</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ollama.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ollama.err</string>
</dict>
</plist>
EOF

# Step 2: launchdに登録
launchctl load ~/Library/LaunchAgents/com.ollama.serve.plist

# Step 3: 起動確認
launchctl list | grep ollama
# com.ollama.serve が表示されればOK

# Step 4: Ollama起動確認
curl http://localhost:11434/api/tags
```

**TMWS自動起動は不要**: Claude Desktopが起動時に自動的にMCPサーバーを起動します。

### 🐧 Linux (systemd)

```bash
# Step 1: Ollamaサービス作成
sudo tee /etc/systemd/system/ollama.service > /dev/null << 'EOF'
[Unit]
Description=Ollama Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# $USERを実際のユーザー名に置換
sudo sed -i "s/\$USER/$USER/" /etc/systemd/system/ollama.service

# Step 2: systemd再読み込み
sudo systemctl daemon-reload

# Step 3: Ollama起動 & 自動起動有効化
sudo systemctl enable ollama.service
sudo systemctl start ollama.service

# Step 4: 起動確認
sudo systemctl status ollama.service
# Active: active (running) であればOK

curl http://localhost:11434/api/tags
```

**TMWS自動起動は不要**: Claude Desktopが起動時に自動的にMCPサーバーを起動します。

---

## 💾 バックアップ戦略

### 自動バックアップスクリプト

```bash
# Step 1: バックアップスクリプト作成
cat > ~/.tmws/scripts/backup.sh << 'EOF'
#!/bin/bash
# TMWS Backup Script

BACKUP_DIR="$HOME/.tmws/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/tmws_backup_$TIMESTAMP"

# バックアップディレクトリ作成
mkdir -p "$BACKUP_PATH"

# SQLiteデータベースバックアップ
if [ -f "$HOME/.tmws/data/tmws.db" ]; then
    sqlite3 "$HOME/.tmws/data/tmws.db" ".backup '$BACKUP_PATH/tmws.db'"
    echo "✅ Database backed up"
fi

# ChromaDBデータバックアップ
if [ -d "$HOME/.tmws/.chroma" ]; then
    cp -r "$HOME/.tmws/.chroma" "$BACKUP_PATH/chroma"
    echo "✅ ChromaDB backed up"
fi

# 設定ファイルバックアップ
if [ -f "$HOME/.tmws/.env" ]; then
    cp "$HOME/.tmws/.env" "$BACKUP_PATH/.env"
    echo "✅ Config backed up"
fi

# 圧縮
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "tmws_backup_$TIMESTAMP"
rm -rf "$BACKUP_PATH"

# 7日以上古いバックアップを削除
find "$BACKUP_DIR" -name "tmws_backup_*.tar.gz" -mtime +7 -delete

echo "✅ Backup completed: $BACKUP_PATH.tar.gz"
EOF

# Step 2: 実行権限付与
chmod +x ~/.tmws/scripts/backup.sh

# Step 3: 手動実行テスト
~/.tmws/scripts/backup.sh
```

### Cron自動バックアップ設定

#### 🍎 Mac (cron)

```bash
# Step 1: crontab編集
crontab -e

# Step 2: 以下を追加（毎日午前2時にバックアップ）
0 2 * * * /Users/<your-username>/.tmws/scripts/backup.sh >> /tmp/tmws_backup.log 2>&1

# Step 3: cron確認
crontab -l
```

#### 🐧 Linux (cron)

```bash
# Step 1: crontab編集
crontab -e

# Step 2: 以下を追加（毎日午前2時にバックアップ）
0 2 * * * /home/<your-username>/.tmws/scripts/backup.sh >> /tmp/tmws_backup.log 2>&1

# Step 3: cron確認
crontab -l
```

### リストア手順

```bash
# Step 1: バックアップ一覧表示
ls -lh ~/.tmws/backups/

# Step 2: リストアするバックアップを選択
BACKUP_FILE=~/.tmws/backups/tmws_backup_20251103_020000.tar.gz

# Step 3: TMWS停止（Claude Desktopを終了）

# Step 4: 現在のデータを別名保存
mv ~/.tmws/data/tmws.db ~/.tmws/data/tmws.db.old
mv ~/.tmws/.chroma ~/.tmws/.chroma.old

# Step 5: バックアップを展開
tar -xzf "$BACKUP_FILE" -C ~/.tmws/backups/
BACKUP_DIR=$(basename "$BACKUP_FILE" .tar.gz)

# Step 6: データをリストア
cp ~/.tmws/backups/$BACKUP_DIR/tmws.db ~/.tmws/data/tmws.db
cp -r ~/.tmws/backups/$BACKUP_DIR/chroma ~/.tmws/.chroma

# Step 7: Claude Desktop再起動
# 動作確認後、.oldファイルを削除
# rm -rf ~/.tmws/data/tmws.db.old
# rm -rf ~/.tmws/.chroma.old
```

---

## 🔄 アップデート手順

### uvx版アップデート

```bash
# Step 1: 最新バージョン確認
uvx --from tmws tmws-mcp-server --version
# 現在: tmws version 2.3.1

# Step 2: バックアップ実行（念のため）
~/.tmws/scripts/backup.sh

# Step 3: Claude Desktop停止

# Step 4: アップデート実行
uvx --upgrade --from tmws tmws-mcp-server

# Step 5: バージョン確認
uvx --from tmws tmws-mcp-server --version
# 更新後: tmws version 2.3.2 (例)

# Step 6: データベースマイグレーション（必要に応じて）
# 通常は自動実行されるため不要

# Step 7: Claude Desktop再起動

# Step 8: 動作確認
# Claude Desktop → MCP Serversで"tmws"が緑色
```

### pip版アップデート

```bash
# Step 1: venv有効化
source ~/.tmws-venv/bin/activate

# Step 2: バックアップ実行
~/.tmws/scripts/backup.sh

# Step 3: Claude Desktop停止

# Step 4: アップデート実行
pip install --upgrade tmws

# Step 5: バージョン確認
tmws-mcp-server --version

# Step 6: Claude Desktop再起動
```

### メジャーバージョンアップグレード（例: v2.x → v3.x）

```bash
# Step 1: リリースノート確認
# https://github.com/apto-as/tmws/releases

# Step 2: 完全バックアップ
~/.tmws/scripts/backup.sh

# Step 3: データベースダンプ（念のため）
sqlite3 ~/.tmws/data/tmws.db .dump > ~/.tmws/backups/tmws_dump_$(date +%Y%m%d).sql

# Step 4: Claude Desktop停止

# Step 5: 既存環境削除（uvx版）
uvx --from tmws --version  # キャッシュクリア
rm -rf ~/.cache/uv/tmws*

# Step 6: 最新版インストール
uvx --from tmws tmws-mcp-server

# Step 7: マイグレーション実行（自動）
# 初回起動時に自動実行

# Step 8: Claude Desktop再起動

# Step 9: 動作確認
# MCP接続確認
# store_memory/search_memoriesテスト
```

---

## 🔍 トラブルシューティング

### 1. Ollama接続エラー

**症状**:
```
Error: Cannot connect to Ollama at http://localhost:11434
```

**診断**:
```bash
# Ollama起動確認
curl http://localhost:11434/api/tags

# Ollamaプロセス確認
ps aux | grep ollama

# Mac
launchctl list | grep ollama

# Linux
sudo systemctl status ollama
```

**解決**:
```bash
# Mac
launchctl start com.ollama.serve

# Linux
sudo systemctl start ollama.service

# 手動起動
ollama serve &
```

### 2. MCP接続エラー

**症状**: Claude Desktopで"tmws"が赤色表示

**診断**:
```bash
# MCP接続テスト
uvx --from tmws tmws-mcp-server --help

# 環境変数確認
echo $TMWS_DATABASE_URL
echo $TMWS_OLLAMA_BASE_URL

# データベースファイル確認
ls -lh ~/.tmws/data/tmws.db
```

**解決**:
```bash
# 1. データベース初期化（データ消失注意！）
rm ~/.tmws/data/tmws.db
# Claude Desktop再起動で自動作成

# 2. 権限確認
chmod 644 ~/.tmws/data/tmws.db
chmod 755 ~/.tmws/data/

# 3. Claude Desktop設定確認
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json
# uvx コマンドと引数が正しいか確認
```

### 3. パフォーマンス低下

**症状**: MCP tool実行が遅い (>1秒)

**診断**:
```bash
# データベースサイズ確認
du -sh ~/.tmws/data/tmws.db
du -sh ~/.tmws/.chroma/

# SQLiteインデックス確認
sqlite3 ~/.tmws/data/tmws.db "PRAGMA index_list;"

# メモリ使用量確認
ps aux | grep tmws-mcp-server
```

**解決**:
```bash
# 1. データベース最適化
sqlite3 ~/.tmws/data/tmws.db "VACUUM;"
sqlite3 ~/.tmws/data/tmws.db "ANALYZE;"

# 2. ChromaDB再構築（古いデータ削除）
# バックアップ取得後
rm -rf ~/.tmws/.chroma/
# Claude Desktop再起動で自動再構築

# 3. 古いメモリ削除（手動）
sqlite3 ~/.tmws/data/tmws.db << 'EOF'
DELETE FROM memories WHERE created_at < date('now', '-90 days');
VACUUM;
EOF
```

### 4. ディスク容量不足

**症状**:
```
Error: [Errno 28] No space left on device
```

**診断**:
```bash
# ディスク使用量確認
df -h ~

# TMWS使用量確認
du -sh ~/.tmws/
du -sh ~/.tmws/data/
du -sh ~/.tmws/.chroma/
du -sh ~/.tmws/backups/
```

**解決**:
```bash
# 1. 古いバックアップ削除
find ~/.tmws/backups/ -name "*.tar.gz" -mtime +30 -delete

# 2. ログファイル削除
find ~/.tmws/ -name "*.log" -delete

# 3. ChromaDB最適化
# （メモリ削除により自動的に縮小）
```

---

## 📊 監視とメンテナンス

### ヘルスチェックスクリプト

```bash
# ~/.tmws/scripts/health-check.sh
#!/bin/bash

echo "🔍 TMWS Health Check"
echo "===================="

# Ollama確認
if curl -s http://localhost:11434/api/tags > /dev/null; then
    echo "✅ Ollama: Running"
else
    echo "❌ Ollama: Not running"
fi

# データベース確認
if [ -f ~/.tmws/data/tmws.db ]; then
    SIZE=$(du -sh ~/.tmws/data/tmws.db | cut -f1)
    echo "✅ Database: $SIZE"
else
    echo "❌ Database: Not found"
fi

# ChromaDB確認
if [ -d ~/.tmws/.chroma ]; then
    SIZE=$(du -sh ~/.tmws/.chroma | cut -f1)
    echo "✅ ChromaDB: $SIZE"
else
    echo "❌ ChromaDB: Not found"
fi

# ディスク容量確認
DISK=$(df -h ~ | awk 'NR==2 {print $5}')
echo "💾 Disk usage: $DISK"

# メモリ数確認
MEMORIES=$(sqlite3 ~/.tmws/data/tmws.db "SELECT COUNT(*) FROM memories;" 2>/dev/null || echo "0")
echo "📝 Total memories: $MEMORIES"

echo "===================="
```

```bash
chmod +x ~/.tmws/scripts/health-check.sh

# 実行
~/.tmws/scripts/health-check.sh
```

### 定期メンテナンスタスク

**毎日**:
- ✅ 自動バックアップ（cron）

**毎週**:
```bash
# ヘルスチェック
~/.tmws/scripts/health-check.sh

# データベース最適化
sqlite3 ~/.tmws/data/tmws.db "VACUUM; ANALYZE;"
```

**毎月**:
```bash
# アップデート確認
uvx --upgrade --from tmws tmws-mcp-server

# 古いバックアップ削除
find ~/.tmws/backups/ -name "*.tar.gz" -mtime +30 -delete

# ディスク使用量確認
du -sh ~/.tmws/
```

---

## 🔐 セキュリティ強化

### 環境変数の保護

```bash
# .envファイルの権限設定
chmod 600 ~/.tmws/.env

# 所有者確認
ls -l ~/.tmws/.env
# -rw------- 1 <user> <group> ... .env
```

### データベース暗号化（オプション）

```bash
# SQLCipher使用（高度なセキュリティが必要な場合）
# https://www.zetetic.net/sqlcipher/

# 注意: 通常のSQLiteを暗号化SQLiteに移行するには
# 専用の手順が必要です（将来実装予定）
```

### ファイアウォール設定

```bash
# Mac (ファイアウォール有効化)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Linux (ufwでOllamaポート保護)
sudo ufw allow from 127.0.0.1 to any port 11434
sudo ufw deny 11434
```

---

## 📈 本番運用チェックリスト

### デプロイ前確認

- [ ] Python 3.11+インストール済み
- [ ] uvまたはpipインストール済み
- [ ] Ollamaインストール & モデルダウンロード済み
- [ ] TMWSインストール済み（uvx/pip）
- [ ] 環境変数設定完了（~/.tmws/.env）
- [ ] Claude Desktop MCP設定完了
- [ ] Ollama自動起動設定完了
- [ ] バックアップスクリプト設置完了
- [ ] Cron設定完了（自動バックアップ）

### 動作確認

- [ ] Ollama起動確認（curl http://localhost:11434/api/tags）
- [ ] TMWS起動確認（uvx --from tmws tmws-mcp-server --help）
- [ ] Claude Desktop MCP接続確認（緑色ステータス）
- [ ] store_memory動作確認
- [ ] search_memories動作確認
- [ ] create_task動作確認

### 運用開始後

- [ ] 毎日バックアップ実行確認
- [ ] 週次ヘルスチェック実施
- [ ] 月次アップデート確認
- [ ] ディスク容量監視
- [ ] パフォーマンス監視

---

## 🚀 次のステップ

### v2.3.1 → v2.4.0 移行（予定）

**新機能**:
- SSE transport対応（HTTP経由MCP接続）
- マルチエージェント協調強化
- パフォーマンスダッシュボード

**移行手順**: `UPGRADE_GUIDE.md`（リリース時に提供）

### スケーリング計画（将来）

**単一サーバーの限界**:
- 同時接続: ~100 MCPクライアント
- メモリ: ~1M memories
- スループット: ~100 req/s

**スケーリングオプション**:
1. **PostgreSQL移行** (>1M memories)
2. **Redis Queue** (>100 req/s)
3. **Load Balancer** (>100 clients)

詳細: `SCALING_GUIDE.md`（将来提供）

---

## 📚 関連ドキュメント

- **MCP Tools Reference**: `docs/MCP_TOOLS_REFERENCE.md`
- **Docker版デプロイ**: `PRODUCTION_DEPLOYMENT_PLAN.md`
- **MCP Docker接続**: `docs/MCP_CONNECTION_DOCKER.md`
- **Development Setup**: `docs/DEVELOPMENT_SETUP.md`
- **Architecture**: `docs/architecture/TMWS_v2.2.0_ARCHITECTURE.md`

---

**End of Document**

*"Simplicity is the ultimate sophistication." - Leonardo da Vinci*

**Status**: ✅ **PRODUCTION READY** (uvx版)
