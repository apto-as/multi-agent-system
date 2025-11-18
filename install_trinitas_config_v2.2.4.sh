#!/bin/bash

# Trinitas Configuration Installer v2.2.4
# ユーザー環境にTrinitas最適化設定をインストール
# Author: Trinitas System (All Personas)
# Changes: File-based memory system (simple and private)

set -e

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# パス定義
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="${SCRIPT_DIR}/trinitas_sources/config"
GLOBAL_CONFIG_DIR="${HOME}/.claude"
BACKUP_DIR="${HOME}/.claude/backup"

# ロゴ表示
echo -e "${CYAN}"
echo "╔════════════════════════════════════════╗"
echo "║ Trinitas Configuration Installer v2.2.4║"
echo "║   File-Based Memory & Global Hooks    ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"

# 前提条件のチェック
check_prerequisites() {
    echo -e "${BLUE}📋 Checking prerequisites...${NC}"

    # .claudeディレクトリの確認
    if [ ! -d "${GLOBAL_CONFIG_DIR}" ]; then
        echo -e "${YELLOW}  Creating ~/.claude directory...${NC}"
        mkdir -p "${GLOBAL_CONFIG_DIR}"
    fi

    # テンプレートファイルの確認
    if [ ! -d "${TEMPLATES_DIR}" ]; then
        echo -e "${RED}❌ Error: Template files not found at ${TEMPLATES_DIR}${NC}"
        echo "Please run this script from the trinitas-agents project root."
        exit 1
    fi

    echo -e "${GREEN}✓ Prerequisites satisfied${NC}"
}


# Hook設定の生成（グローバル配置用）
setup_hook_settings() {
    echo -e "${BLUE}🔧 Configuring hooks...${NC}"

    # グローバル .claude ディレクトリ作成
    mkdir -p "${GLOBAL_CONFIG_DIR}"

    # グローバルインストール用テンプレートを使用
    TEMPLATE_FILE="${SCRIPT_DIR}/hooks/settings_global.template.json"
    SETTINGS_FILE="${GLOBAL_CONFIG_DIR}/settings.json"

    if [ -f "${TEMPLATE_FILE}" ]; then
        # {{GLOBAL_CONFIG_DIR}} を実際のパスに置換
        sed "s|{{GLOBAL_CONFIG_DIR}}|${GLOBAL_CONFIG_DIR}|g" "${TEMPLATE_FILE}" > "${SETTINGS_FILE}"
        echo -e "${GREEN}✓ Generated global hook settings${NC}"
        echo -e "${GREEN}✓ Saved to: ${SETTINGS_FILE}${NC}"
    else
        echo -e "${RED}❌ Global settings template not found: ${TEMPLATE_FILE}${NC}"
        echo -e "${YELLOW}⚠ Falling back to minimal settings${NC}"

        # フォールバック: 最小設定を作成
        cat > "${SETTINGS_FILE}" << 'EOF'
{
  "description": "Trinitas Minimal Configuration",
  "hooks": {}
}
EOF
    fi
}

# バックアップの作成
create_backup() {
    echo -e "${BLUE}💾 Creating comprehensive backup...${NC}"

    mkdir -p "${BACKUP_DIR}"
    timestamp=$(date +%Y%m%d_%H%M%S)
    backup_created=false

    # CLAUDE.md のバックアップ
    if [ -f "${GLOBAL_CONFIG_DIR}/CLAUDE.md" ]; then
        cp "${GLOBAL_CONFIG_DIR}/CLAUDE.md" "${BACKUP_DIR}/CLAUDE_${timestamp}.md"
        echo -e "${GREEN}  ✓ Existing CLAUDE.md backed up${NC}"
        backup_created=true
    fi

    # AGENTS.md のバックアップ
    if [ -f "${GLOBAL_CONFIG_DIR}/AGENTS.md" ]; then
        cp "${GLOBAL_CONFIG_DIR}/AGENTS.md" "${BACKUP_DIR}/AGENTS_${timestamp}.md"
        echo -e "${GREEN}  ✓ Existing AGENTS.md backed up${NC}"
        backup_created=true
    fi

    # agents/ ディレクトリのバックアップ
    if [ -d "${GLOBAL_CONFIG_DIR}/agents" ]; then
        mkdir -p "${BACKUP_DIR}/agents_${timestamp}"
        cp -r "${GLOBAL_CONFIG_DIR}/agents/"* "${BACKUP_DIR}/agents_${timestamp}/" 2>/dev/null || true
        if [ "$(ls -A ${BACKUP_DIR}/agents_${timestamp} 2>/dev/null)" ]; then
            echo -e "${GREEN}  ✓ Existing agents/ directory backed up${NC}"
            backup_created=true
        fi
    fi

    # hooks/ ディレクトリのバックアップ
    if [ -d "${GLOBAL_CONFIG_DIR}/hooks" ]; then
        mkdir -p "${BACKUP_DIR}/hooks_${timestamp}"
        cp -r "${GLOBAL_CONFIG_DIR}/hooks/"* "${BACKUP_DIR}/hooks_${timestamp}/" 2>/dev/null || true
        if [ "$(ls -A ${BACKUP_DIR}/hooks_${timestamp} 2>/dev/null)" ]; then
            echo -e "${GREEN}  ✓ Existing hooks/ directory backed up${NC}"
            backup_created=true
        fi
    fi

    # バックアップサマリー
    if [ "$backup_created" = true ]; then
        echo -e "${CYAN}  📁 Backup location: ${BACKUP_DIR}/${NC}"
        echo -e "${CYAN}  🕐 Backup timestamp: ${timestamp}${NC}"
    else
        echo -e "${YELLOW}  ℹ️  No existing files to backup (fresh installation)${NC}"
    fi
}

# エージェント定義のインストール
install_agents() {
    echo -e "${BLUE}📚 Installing agent definitions...${NC}"

    AGENTS_DIR="${GLOBAL_CONFIG_DIR}/agents"
    mkdir -p "${AGENTS_DIR}"

    # エージェントファイルのコピー
    AGENT_FILES=(
        "athena-conductor.md"
        "artemis-optimizer.md"
        "hestia-auditor.md"
        "eris-coordinator.md"
        "hera-strategist.md"
        "muses-documenter.md"
    )

    for agent_file in "${AGENT_FILES[@]}"; do
        if [ -f "${SCRIPT_DIR}/agents/${agent_file}" ]; then
            cp "${SCRIPT_DIR}/agents/${agent_file}" "${AGENTS_DIR}/"
            echo -e "${GREEN}  ✓ Installed: ${agent_file}${NC}"
        else
            echo -e "${YELLOW}  ⚠ Agent file not found: ${agent_file}${NC}"
        fi
    done
}

# Hooksのインストール
install_hooks() {
    echo -e "${BLUE}🔗 Installing hooks...${NC}"

    HOOKS_DIR="${GLOBAL_CONFIG_DIR}/hooks"
    mkdir -p "${HOOKS_DIR}/core"

    # protocol_injector.py のコピー（PreCompact hook）
    if [ -f "${SCRIPT_DIR}/hooks/core/protocol_injector.py" ]; then
        cp "${SCRIPT_DIR}/hooks/core/protocol_injector.py" "${HOOKS_DIR}/core/"
        echo -e "${GREEN}  ✓ Installed: protocol_injector.py (PreCompact hook)${NC}"
    else
        echo -e "${RED}  ❌ Critical: protocol_injector.py not found!${NC}"
    fi

    # dynamic_context_loader.py のコピー（UserPromptSubmit hook）
    if [ -f "${SCRIPT_DIR}/hooks/core/dynamic_context_loader.py" ]; then
        cp "${SCRIPT_DIR}/hooks/core/dynamic_context_loader.py" "${HOOKS_DIR}/core/"
        echo -e "${GREEN}  ✓ Installed: dynamic_context_loader.py (UserPromptSubmit hook)${NC}"
    else
        echo -e "${YELLOW}  ⚠ dynamic_context_loader.py not found (optional)${NC}"
    fi

    # 共有ユーティリティのコピー
    SHARED_UTILS_DIR="${GLOBAL_CONFIG_DIR}/shared/utils"
    mkdir -p "${SHARED_UTILS_DIR}"

    if [ -d "${SCRIPT_DIR}/shared/utils" ]; then
        cp -r "${SCRIPT_DIR}/shared/utils/"*.py "${SHARED_UTILS_DIR}/" 2>/dev/null || true
        echo -e "${GREEN}  ✓ Installed: shared utilities${NC}"
    else
        echo -e "${YELLOW}  ⚠ shared/utils directory not found (optional)${NC}"
    fi
}

# Memory Cookbookのインストール（v2.2.4: TMWS削除）
install_memory() {
    echo -e "${BLUE}🧠 Installing Memory Cookbook files (v2.2.4)...${NC}"

    MEMORY_DIR="${GLOBAL_CONFIG_DIR}/memory"
    mkdir -p "${MEMORY_DIR}/core"
    mkdir -p "${MEMORY_DIR}/contexts"

    # Core memory files
    if [ -d "${SCRIPT_DIR}/trinitas_sources/memory/core" ]; then
        cp "${SCRIPT_DIR}/trinitas_sources/memory/core/"*.md "${MEMORY_DIR}/core/" 2>/dev/null || true
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}  ✓ Installed core memory files (system, agents)${NC}"
        else
            echo -e "${YELLOW}  ⚠ Core memory files not found${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ Core memory source not found (optional feature)${NC}"
    fi

    # Context files (excluding TMWS)
    if [ -d "${SCRIPT_DIR}/trinitas_sources/memory/contexts" ]; then
        for context_file in "${SCRIPT_DIR}/trinitas_sources/memory/contexts/"*.md; do
            # Skip tmws.md
            if [[ "$(basename $context_file)" != "tmws.md" ]]; then
                cp "$context_file" "${MEMORY_DIR}/contexts/"
            fi
        done
        echo -e "${GREEN}  ✓ Installed context files (performance, security, mcp-tools, collaboration)${NC}"
        echo -e "${CYAN}  ℹ️  Note: TMWS context removed in v2.2.4${NC}"
    else
        echo -e "${YELLOW}  ⚠ Context source not found (optional feature)${NC}"
    fi

    # Verify installation
    CORE_COUNT=$(ls -1 "${MEMORY_DIR}/core/"*.md 2>/dev/null | wc -l)
    CONTEXT_COUNT=$(ls -1 "${MEMORY_DIR}/contexts/"*.md 2>/dev/null | wc -l)

    echo -e "${GREEN}  ✓ Memory Cookbook v2.2.4 installed${NC}"
    echo -e "${CYAN}  📊 Core: ${CORE_COUNT}/2, Contexts: ${CONTEXT_COUNT}/4${NC}"
}

# Quality Guardian機能のインストール
install_quality_guardian() {
    echo -e "${BLUE}🛡️ Installing Quality Guardian Framework...${NC}"

    # guardディレクトリのコピー
    if [ -d "${SCRIPT_DIR}/trinitas_sources/guard" ]; then
        echo -e "${CYAN}  📦 Installing Quality Guardian tools...${NC}"

        # guardディレクトリを全体コピー
        cp -r "${SCRIPT_DIR}/trinitas_sources/guard" "${GLOBAL_CONFIG_DIR}/"

        # 初回インストール日時を記録
        mkdir -p "${GLOBAL_CONFIG_DIR}/guard"
        date +%s > "${GLOBAL_CONFIG_DIR}/guard/.install_date"

        # guard コマンドのシンボリックリンクを作成
        GUARD_SCRIPT="${GLOBAL_CONFIG_DIR}/guard/scripts/guard_command.sh"
        if [ -f "$GUARD_SCRIPT" ]; then
            # ローカルbinディレクトリを作成
            mkdir -p "${HOME}/.local/bin"

            # シンボリックリンクを作成
            ln -sf "$GUARD_SCRIPT" "${HOME}/.local/bin/trinitas-guard"

            echo -e "${GREEN}  ✓ Quality Guardian installed${NC}"
            echo -e "${CYAN}  📝 Command: trinitas-guard${NC}"

            # PATHチェック
            if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
                echo -e "${YELLOW}  ⚠️  Please add ${HOME}/.local/bin to your PATH:${NC}"
                echo -e "${YELLOW}     export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
            fi
        fi

        echo -e "${GREEN}  ✓ Multi-language support: Python, JS/TS, Go, Rust${NC}"
        echo -e "${GREEN}  ✓ Quality check scripts installed${NC}"

        # ツールインストールの提案
        echo -e ""
        echo -e "${YELLOW}💡 Tip: To install language quality tools:${NC}"
        echo -e "  ${WHITE}~/.claude/guard/scripts/install_tools.sh auto${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Quality Guardian not found (optional feature)${NC}"
    fi
}

# グローバル設定のインストール
install_global_config() {
    echo -e "${BLUE}🌍 Installing global configuration (v2.2.4)...${NC}"

    # MINIMAL_MODEの場合はテンプレートのみ使用
    if [ "$MINIMAL_MODE" = "true" ]; then
        echo -e "${CYAN}  📦 Using minimal template (optimized for size)${NC}"
        if [ -f "${TEMPLATES_DIR}/global/CLAUDE_global_template.md" ]; then
            cp "${TEMPLATES_DIR}/global/CLAUDE_global_template.md" "${GLOBAL_CONFIG_DIR}/CLAUDE.md"
            echo -e "${GREEN}  ✓ Minimal CLAUDE.md installed (3KB)${NC}"
        else
            echo -e "${RED}  ❌ Template not found${NC}"
            return 1
        fi
    else
        # 動的ビルドモード (TMWS参照を削除)
        if [ -x "${SCRIPT_DIR}/scripts/build_claude_md.sh" ]; then
            echo -e "${CYAN}  🔨 Building CLAUDE.md from trinitas_sources/ (v2.2.4 - no TMWS)...${NC}"
            cd "${SCRIPT_DIR}"
            INCLUDE_TMWS=false ./scripts/build_claude_md.sh
            if [ -f "${SCRIPT_DIR}/CLAUDE.md" ]; then
                cp "${SCRIPT_DIR}/CLAUDE.md" "${GLOBAL_CONFIG_DIR}/CLAUDE.md"
                echo -e "${GREEN}  ✓ CLAUDE.md dynamically built and installed${NC}"
            else
                echo -e "${RED}  ❌ Failed to build CLAUDE.md${NC}"
                return 1
            fi
        # フォールバック：テンプレートを使用
        elif [ -f "${TEMPLATES_DIR}/global/CLAUDE_global_template.md" ]; then
            echo -e "${YELLOW}  ⚠️  Build script not found, using template fallback${NC}"
            cp "${TEMPLATES_DIR}/global/CLAUDE_global_template.md" "${GLOBAL_CONFIG_DIR}/CLAUDE.md"
            echo -e "${GREEN}  ✓ CLAUDE.md installed from template${NC}"
        else
            echo -e "${RED}  ❌ Neither build script nor template found${NC}"
            return 1
        fi

        # AGENTS.mdを動的にビルド（MINIMAL_MODEでない場合のみ）
        if [ -x "${SCRIPT_DIR}/scripts/build_agents_md.sh" ]; then
            echo -e "${CYAN}  🔨 Building AGENTS.md from trinitas_sources/...${NC}"
            cd "${SCRIPT_DIR}"
            ./scripts/build_agents_md.sh
            if [ -f "${SCRIPT_DIR}/AGENTS.md" ]; then
                cp "${SCRIPT_DIR}/AGENTS.md" "${GLOBAL_CONFIG_DIR}/AGENTS.md"
                echo -e "${GREEN}  ✓ AGENTS.md dynamically built and installed${NC}"
            fi
        fi
    fi

    # ファイルサイズ確認
    size=$(du -h "${GLOBAL_CONFIG_DIR}/CLAUDE.md" | cut -f1)
    echo -e "${CYAN}  📊 CLAUDE.md size: ${size}${NC}"

    if [ -f "${GLOBAL_CONFIG_DIR}/AGENTS.md" ]; then
        size_agents=$(du -h "${GLOBAL_CONFIG_DIR}/AGENTS.md" | cut -f1)
        echo -e "${CYAN}  📊 AGENTS.md size: ${size_agents}${NC}"
    fi
}

# パフォーマンステストの実行
performance_test() {
    echo -e "${BLUE}⚡ Running performance test...${NC}"

    # ファイルサイズ測定
    if [ -f "${GLOBAL_CONFIG_DIR}/CLAUDE.md" ]; then
        size_bytes=$(stat -f%z "${GLOBAL_CONFIG_DIR}/CLAUDE.md" 2>/dev/null || stat -c%s "${GLOBAL_CONFIG_DIR}/CLAUDE.md" 2>/dev/null)
        size_kb=$((size_bytes / 1024))

        echo -e "${CYAN}  📊 Configuration size: ${size_kb}KB${NC}"

        if [ ${size_kb} -le 5 ]; then
            echo -e "${GREEN}  ✅ Excellent: Hook loading will be very fast${NC}"
        elif [ ${size_kb} -le 10 ]; then
            echo -e "${YELLOW}  ⚠️  Good: Hook loading optimized${NC}"
        else
            echo -e "${RED}  ❌ Large: Consider further optimization${NC}"
        fi
    fi
}

# インストール結果の表示
show_installation_summary() {
    echo -e "${GREEN}✅ Installation completed successfully!${NC}"
    echo ""
    echo -e "${CYAN}📋 Summary (v2.2.4):${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✓ Global configuration installed${NC}"
    echo -e "${GREEN}✓ Backup created in ~/.claude/backup/${NC}"
    echo -e "${GREEN}✓ File-based memory system configured${NC}"
    echo -e "${GREEN}✓ Performance optimized${NC}"
    echo ""

    echo -e "${YELLOW}📚 What's included:${NC}"
    echo "  • 6 Trinitas AI Personas (Athena, Artemis, Hestia, Eris, Hera, Muses)"
    echo "  • File-Based Memory System (simple & private)"
    echo "  • Dynamic Context Loading (UserPromptSubmit hook)"
    echo "  • Japanese response enforcement"
    echo "  • Optimized Hook loading"
    echo "  • Basic command templates"
    if [[ "$WITH_GUARDIAN" != "false" ]]; then
        echo "  • Quality Guardian Framework (Multi-language)"
    fi
    echo ""

    echo -e "${BLUE}🚀 Next Steps:${NC}"
    echo "1. Restart Claude Code to load new configuration"
    echo "2. Test with: 'Trinitasシステムの動作確認'"
    echo "3. Test persona detection: 'optimize this code' (should detect Artemis)"
    if [[ "$WITH_GUARDIAN" != "false" ]]; then
        echo "4. Install quality tools: ~/.claude/guard/scripts/install_tools.sh"
        echo "5. Check code quality: trinitas-guard check"
    fi
    echo ""

    echo -e "${CYAN}💡 Tips:${NC}"
    echo "  • All data stays on your machine in ~/.claude/"
    echo "  • No external dependencies required"
    echo "  • Personas auto-detect from your prompts"
    echo ""

    echo -e "${MAGENTA}🎭 Trinitas Personas are ready!${NC}"
    echo -e "${GREEN}  Athena:${NC} 'ふふ、シンプルで美しいシステムですね♪'"
    echo -e "${CYAN}  Artemis:${NC} '完璧な設計...無駄のない実装です。'"
    echo -e "${RED}  Hestia:${NC} '...ローカル処理で安全性も確保されています...'"
}

# エラーハンドリング
handle_error() {
    echo -e "${RED}❌ Installation failed!${NC}"
    echo -e "${YELLOW}Attempting to restore from backup...${NC}"

    # 最新のバックアップを復元
    latest_backup=$(ls -t "${BACKUP_DIR}"/CLAUDE_*.md 2>/dev/null | head -n1)
    if [ -n "$latest_backup" ]; then
        cp "$latest_backup" "${GLOBAL_CONFIG_DIR}/CLAUDE.md"
        echo -e "${GREEN}✓ Configuration restored from backup${NC}"
    fi

    exit 1
}

# インタラクティブモードの確認
confirm_installation() {
    echo -e "${YELLOW}This will install Trinitas v2.2.4 optimized configuration to ~/.claude/${NC}"
    echo -e "${YELLOW}Current configuration will be backed up.${NC}"
    echo ""
    echo -e "${CYAN}New in v2.2.4:${NC}"
    echo "  • File-based memory system (simple & private)"
    echo "  • Dynamic context loading with persona detection"
    echo "  • Global hooks installation"
    echo "  • No external dependencies required"
    echo ""
    read -p "Continue with installation? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Installation cancelled.${NC}"
        exit 0
    fi
}

# メイン実行
main() {
    # エラートラップ
    trap handle_error ERR

    echo -e "${BLUE}Starting Trinitas v2.2.4 configuration installation...${NC}"
    echo ""

    # インタラクティブ確認（引数で無効化可能）
    if [[ "$1" != "--yes" && "$1" != "-y" ]]; then
        confirm_installation
    fi

    # インストール手順
    check_prerequisites
    create_backup

    install_global_config
    install_agents       # エージェント定義のインストール
    install_hooks        # Hooksのインストール
    install_memory       # Memory Cookbookのインストール
    setup_hook_settings  # Hook設定の生成

    # Quality Guardian機能のインストール (デフォルトで有効)
    if [[ "$WITH_GUARDIAN" != "false" ]]; then
        install_quality_guardian
    fi

    performance_test
    show_installation_summary

    echo ""
    echo -e "${CYAN}Trinitas System v2.2.4: File-Based Excellence${NC}"
}

# ヘルプの表示
show_help() {
    echo "Trinitas Configuration Installer v2.2.4"
    echo ""
    echo "Usage:"
    echo "  $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help         Show this help message"
    echo "  -y, --yes          Skip confirmation prompt"
    echo "  --minimal          Use minimal template only (fastest, smallest)"
    echo "  --with-guardian    Include Quality Guardian Framework (default: enabled)"
    echo "  --without-guardian Exclude Quality Guardian Framework"
    echo "  --backup-only      Create backup only, don't install"
    echo "  --uninstall        Restore from latest backup"
    echo ""
    echo "New in v2.2.4:"
    echo "  • File-based memory system (simple & private)"
    echo "  • Dynamic context loading with persona detection"
    echo "  • Global hooks installation to ~/.claude/"
    echo "  • No external dependencies required"
    echo ""
    echo "Examples:"
    echo "  $0                  # Interactive installation with Guardian"
    echo "  $0 --yes            # Silent installation with full features"
    echo "  $0 --minimal        # Minimal installation (no Guardian)"
    echo "  $0 --uninstall      # Restore previous configuration"
}

# アンインストール機能
uninstall_config() {
    echo -e "${YELLOW}Restoring previous configuration...${NC}"

    latest_backup=$(ls -t "${BACKUP_DIR}"/CLAUDE_*.md 2>/dev/null | head -n1)
    if [ -n "$latest_backup" ]; then
        cp "$latest_backup" "${GLOBAL_CONFIG_DIR}/CLAUDE.md"
        echo -e "${GREEN}✓ Previous configuration restored${NC}"
    else
        echo -e "${RED}❌ No backup found${NC}"
        exit 1
    fi
}

# コマンドライン引数の処理
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --backup-only)
        check_prerequisites
        create_backup
        echo -e "${GREEN}✓ Backup completed${NC}"
        exit 0
        ;;
    --uninstall)
        uninstall_config
        exit 0
        ;;
    --minimal)
        # 最小モード：テンプレートのみ使用、Guardianなし
        export MINIMAL_MODE=true
        export WITH_GUARDIAN=false
        main "$@"
        ;;
    --with-guardian)
        # Quality Guardian Framework を含める (明示的に有効)
        export WITH_GUARDIAN=true
        shift
        main "$@"
        ;;
    --without-guardian)
        # Quality Guardian Framework を無効化
        export WITH_GUARDIAN=false
        shift
        main "$@"
        ;;
    *)
        # デフォルト：Quality Guardian含む
        export WITH_GUARDIAN=true
        main "$@"
        ;;
esac
