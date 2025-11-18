#!/bin/bash

# Trinitas Configuration Split Script
# 設定ファイルを適切に分割し、最適化する
# Author: Artemis (Technical Optimization)

set -e

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# パス定義
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${PROJECT_ROOT}/.claude/config"
GLOBAL_CONFIG_DIR="${HOME}/.claude"
BACKUP_DIR="${PROJECT_ROOT}/.claude/backup"

# ロゴ表示
echo -e "${BLUE}"
echo "╔════════════════════════════════════════╗"
echo "║   Trinitas Config Splitter v1.0       ║"
echo "║   Optimizing Configuration Files      ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"

# バックアップディレクトリ作成
mkdir -p "${BACKUP_DIR}"
mkdir -p "${CONFIG_DIR}"

# 現在の設定をバックアップ
backup_configs() {
    echo -e "${YELLOW}📦 Creating backup...${NC}"
    timestamp=$(date +%Y%m%d_%H%M%S)
    
    if [ -f "${GLOBAL_CONFIG_DIR}/CLAUDE.md" ]; then
        cp "${GLOBAL_CONFIG_DIR}/CLAUDE.md" "${BACKUP_DIR}/CLAUDE_global_${timestamp}.md"
        echo -e "${GREEN}✓ Global config backed up${NC}"
    fi
    
    if [ -f "${PROJECT_ROOT}/.claude/CLAUDE.md" ]; then
        cp "${PROJECT_ROOT}/.claude/CLAUDE.md" "${BACKUP_DIR}/CLAUDE_project_${timestamp}.md"
        echo -e "${GREEN}✓ Project config backed up${NC}"
    fi
}

# グローバル設定の作成
create_global_config() {
    echo -e "${BLUE}🌐 Creating optimized global configuration...${NC}"
    
    cat > "${PROJECT_ROOT}/.claude/CLAUDE_GLOBAL_NEW.md" << 'EOF'
# Claude Code グローバル設定
# ~/.claude/CLAUDE.md として配置

## 🌍 システム基本設定
**応答言語**: 日本語で応答すること
**セッション維持**: コンテキスト圧縮後も日本語を維持
**作業制限**: プロジェクトディレクトリ内でのみ作業

## 🤖 Trinitas AI System v5.0

### コアペルソナ定義
| ペルソナ | 役割 | トリガー |
|---------|------|----------|
| **Athena** | 調和的指揮 | orchestration, workflow |
| **Artemis** | 技術最適化 | optimization, performance |
| **Hestia** | セキュリティ | security, audit |
| **Eris** | チーム調整 | coordinate, tactical |
| **Hera** | 戦略計画 | strategy, planning |
| **Muses** | 文書化 | documentation, knowledge |

### 基本コマンド
```bash
/trinitas execute <persona> "<task>"
/trinitas analyze "<task>" --personas all
```

### 重要度レベル
- 1.0: クリティカル
- 0.8-0.9: 高
- 0.5-0.7: 中
- 0.3-0.4: 低

---
*Trinitas Core System - Global Configuration*
EOF
    
    echo -e "${GREEN}✓ Global config created (3KB)${NC}"
}

# プロジェクト設定の作成
create_project_config() {
    echo -e "${BLUE}📁 Creating project-specific configuration...${NC}"
    
    cat > "${PROJECT_ROOT}/.claude/CLAUDE_PROJECT_NEW.md" << 'EOF'
# Trinitas Agents プロジェクト設定
# プロジェクト固有の設定

## 📂 プロジェクト情報
- **ルート**: trinitas-agents/
- **ブランチ**: feature/tmws-implementation
- **状態**: 開発中

## 🔧 プロジェクト構造
```
├── agents/          # ペルソナ定義
├── hooks/          # Claudeフック
├── scripts/        # ビルドツール
├── trinitas_sources/ # ドキュメント
└── .claude/        # 設定ファイル
```

## 📝 プロジェクトルール
1. agents/ディレクトリのmarkdownを編集してペルソナ更新
2. ./scripts/build_claude_md.sh でCLAUDE.md生成
3. git commitは明示的指示時のみ

## ⚙️ 開発コマンド
```bash
# ビルド
./scripts/build_claude_md.sh

# テスト
./scripts/test_config.sh

# 最適化
./scripts/optimize_loading.sh
```

---
*Project-specific configuration for trinitas-agents*
EOF
    
    echo -e "${GREEN}✓ Project config created (2KB)${NC}"
}

# モジュール設定の分割
split_modules() {
    echo -e "${BLUE}📋 Splitting configuration modules...${NC}"
    
    # コア設定
    cat > "${CONFIG_DIR}/core.md" << 'EOF'
# Core Configuration Module
## 必須読み込み設定

### システム基本
- 日本語応答
- 作業ディレクトリ制限
- セキュリティポリシー

### エラーハンドリング
- 日本語エラーメッセージ
- スタックトレース制御
EOF
    echo -e "${GREEN}✓ core.md created${NC}"
    
    # ペルソナ詳細
    cat > "${CONFIG_DIR}/personas.md" << 'EOF'
# Persona Definitions Module
## 詳細なペルソナ定義

### Athena - Harmonious Conductor
- 調和的なシステム統合
- ワークフロー管理
- チーム協調の促進

### Artemis - Technical Perfectionist
- パフォーマンス最適化
- コード品質向上
- 技術的卓越性の追求

### Hestia - Security Guardian
- セキュリティ監査
- 脆弱性評価
- リスク管理

### Eris - Tactical Coordinator
- 戦術的調整
- 競合解決
- リソース配分

### Hera - Strategic Commander
- 戦略立案
- 長期計画
- ROI分析

### Muses - Knowledge Architect
- ドキュメント作成
- 知識管理
- アーカイブ構築
EOF
    echo -e "${GREEN}✓ personas.md created${NC}"
    
    # TMWS統合設定
    cat > "${CONFIG_DIR}/tmws.md" << 'EOF'
# TMWS Integration Module
## オプショナル - 開発時のみ読み込み

### メモリシステム
- セマンティック検索
- ベクトルDB統合
- キャッシュ戦略

### ワークフロー
- タスク管理
- 並列実行
- 依存関係解決
EOF
    echo -e "${GREEN}✓ tmws.md created${NC}"
}

# 最適化設定の作成
create_optimized_loader() {
    echo -e "${BLUE}⚡ Creating optimized loader configuration...${NC}"
    
    cat > "${PROJECT_ROOT}/.claude/loader.json" << 'EOF'
{
  "version": "1.0.0",
  "load_strategy": "progressive",
  "modules": {
    "core": {
      "priority": 1,
      "required": true,
      "cache": true,
      "size": "2KB"
    },
    "personas": {
      "priority": 2,
      "required": true,
      "cache": true,
      "size": "3KB"
    },
    "tmws": {
      "priority": 3,
      "required": false,
      "lazy_load": true,
      "size": "4KB"
    }
  },
  "cache_settings": {
    "enabled": true,
    "ttl": 3600,
    "max_size": "10MB"
  },
  "performance_targets": {
    "load_time": "< 3s",
    "memory": "< 1.5MB"
  }
}
EOF
    
    echo -e "${GREEN}✓ Loader configuration created${NC}"
}

# サイズレポートの生成
generate_size_report() {
    echo -e "${BLUE}📊 Generating size report...${NC}"
    echo ""
    echo "Configuration Size Analysis:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -f "${GLOBAL_CONFIG_DIR}/CLAUDE.md" ]; then
        original_size=$(du -h "${GLOBAL_CONFIG_DIR}/CLAUDE.md" | cut -f1)
        echo -e "Original Global: ${RED}${original_size}${NC}"
    fi
    
    new_global_size=$(du -h "${PROJECT_ROOT}/.claude/CLAUDE_GLOBAL_NEW.md" | cut -f1)
    new_project_size=$(du -h "${PROJECT_ROOT}/.claude/CLAUDE_PROJECT_NEW.md" | cut -f1)
    
    echo -e "New Global:      ${GREEN}${new_global_size}${NC}"
    echo -e "New Project:     ${GREEN}${new_project_size}${NC}"
    echo ""
    
    # モジュールサイズ
    echo "Module Sizes:"
    for module in ${CONFIG_DIR}/*.md; do
        if [ -f "$module" ]; then
            size=$(du -h "$module" | cut -f1)
            name=$(basename "$module")
            echo -e "  - ${name}: ${BLUE}${size}${NC}"
        fi
    done
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✨ Optimization Complete!${NC}"
}

# メイン実行
main() {
    echo -e "${YELLOW}Starting configuration optimization...${NC}"
    echo ""
    
    # ステップ実行
    backup_configs
    create_global_config
    create_project_config
    split_modules
    create_optimized_loader
    generate_size_report
    
    echo ""
    echo -e "${GREEN}✅ Configuration split completed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review generated configurations in .claude/"
    echo "2. Test with: ./scripts/test_config.sh"
    echo "3. Deploy with: ./scripts/deploy_config.sh"
    echo ""
    echo -e "${BLUE}Athena:${NC} 'すべてのペルソナが調和して最適化を達成しました♪'"
}

# 実行
main "$@"