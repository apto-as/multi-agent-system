#!/bin/bash
# TMWS: ~/.claude.json をuvx設定に戻すスクリプト
# 運用テスト完了後に実行してください

set -e

echo "🔄 TMWS Configuration: Restoring to uvx mode..."
echo ""

# バックアップ作成
BACKUP_FILE=~/.claude.json.backup-$(date +%Y%m%d-%H%M%S)
cp ~/.claude.json "$BACKUP_FILE"
echo "✅ Backup created: $BACKUP_FILE"

# uvx設定に戻す
jq '.mcpServers.tmws = {
  "type": "stdio",
  "command": "uvx",
  "args": ["tmws"],
  "env": {
    "TMWS_DATABASE_URL": "sqlite+aiosqlite:////Users/apto-as/.tmws/data/tmws.db",
    "TMWS_ENVIRONMENT": "development",
    "TMWS_SECRET_KEY": "aS43vOSSakVPN1hHwcKMwrbMUwdfMLSA2LHO__ihWbA",
    "TMWS_AGENT_ID": "trinitas-unified"
  }
}' ~/.claude.json > ~/.claude.json.tmp && mv ~/.claude.json.tmp ~/.claude.json

echo "✅ Configuration restored to uvx mode"
echo ""
echo "📋 Current TMWS configuration:"
jq '.mcpServers.tmws' ~/.claude.json
echo ""
echo "🔄 Please restart Claude Code to apply changes."
