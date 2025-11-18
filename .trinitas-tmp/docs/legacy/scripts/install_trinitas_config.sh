#!/bin/bash

# Trinitas Configuration Installer
# ユーザー環境にTrinitas最適化設定をインストール
# Author: Trinitas System (All Personas)

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
echo "║     Trinitas Configuration Installer   ║"
echo "║     System-wide Optimization Setup    ║"
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

# Hook設定の生成（実パスを埋め込み）
setup_hook_settings() {
    echo -e "${BLUE}🔧 Configuring hooks...${NC}"
    
    # プロジェクトの絶対パスを取得
    PROJECT_PATH="${SCRIPT_DIR}"
    
    # .claudeディレクトリ作成
    mkdir -p "${SCRIPT_DIR}/.claude"
    
    # テンプレートから設定ファイルを生成
    TEMPLATE_FILE="${SCRIPT_DIR}/hooks/settings_unix.template.json"
    SETTINGS_FILE="${SCRIPT_DIR}/.claude/settings.json"
    
    if [ -f "${TEMPLATE_FILE}" ]; then
        # {{PROJECT_PATH}}を実際のパスに置換
        sed "s|{{PROJECT_PATH}}|${PROJECT_PATH}|g" "${TEMPLATE_FILE}" > "${SETTINGS_FILE}"
        echo -e "${GREEN}✓ Generated hook settings with path: ${PROJECT_PATH}${NC}"
        echo -e "${GREEN}✓ Saved to: ${SETTINGS_FILE}${NC}"
    else
        # テンプレートがない場合は従来の設定を使用
        if [ -f "${SCRIPT_DIR}/hooks/settings_minimal.json" ]; then
            cp "${SCRIPT_DIR}/hooks/settings_minimal.json" "${SETTINGS_FILE}"
            echo -e "${YELLOW}⚠ Using legacy hook settings (with environment variable)${NC}"
        else
            echo -e "${RED}❌ No hook settings template found${NC}"
        fi
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

    # TRINITAS-CORE-PROTOCOL.md のバックアップ（存在する場合）
    if [ -f "${GLOBAL_CONFIG_DIR}/TRINITAS-CORE-PROTOCOL.md" ]; then
        cp "${GLOBAL_CONFIG_DIR}/TRINITAS-CORE-PROTOCOL.md" "${BACKUP_DIR}/TRINITAS-CORE-PROTOCOL_${timestamp}.md"
        echo -e "${GREEN}  ✓ Existing TRINITAS-CORE-PROTOCOL.md backed up${NC}"
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
        echo -e "${YELLOW}  ℹ️ No existing files to backup (fresh installation)${NC}"
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

    LOCAL_HOOKS_DIR="${SCRIPT_DIR}/.claude/hooks"
    mkdir -p "${LOCAL_HOOKS_DIR}/core"

    # protocol_injector.pyのコピー
    if [ -f "${SCRIPT_DIR}/hooks/core/protocol_injector.py" ]; then
        cp "${SCRIPT_DIR}/hooks/core/protocol_injector.py" "${LOCAL_HOOKS_DIR}/core/"
        echo -e "${GREEN}  ✓ Installed: protocol_injector.py${NC}"
    else
        echo -e "${RED}  ❌ Critical: protocol_injector.py not found!${NC}"
    fi
}

# Memory Cookbookのインストール
install_memory() {
    echo -e "${BLUE}🧠 Installing Memory Cookbook files...${NC}"

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

    # Context files
    if [ -d "${SCRIPT_DIR}/trinitas_sources/memory/contexts" ]; then
        cp "${SCRIPT_DIR}/trinitas_sources/memory/contexts/"*.md "${MEMORY_DIR}/contexts/" 2>/dev/null || true
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}  ✓ Installed context files (performance, security, tmws, mcp-tools, collaboration)${NC}"
        else
            echo -e "${YELLOW}  ⚠ Context files not found${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ Context source not found (optional feature)${NC}"
    fi

    # Verify installation
    CORE_COUNT=$(ls -1 "${MEMORY_DIR}/core/"*.md 2>/dev/null | wc -l)
    CONTEXT_COUNT=$(ls -1 "${MEMORY_DIR}/contexts/"*.md 2>/dev/null | wc -l)

    if [ ${CORE_COUNT} -eq 2 ] && [ ${CONTEXT_COUNT} -eq 5 ]; then
        echo -e "${GREEN}  ✓ Memory Cookbook v2.2.1 installed successfully${NC}"
        echo -e "${CYAN}  📊 Core: ${CORE_COUNT}/2, Contexts: ${CONTEXT_COUNT}/5${NC}"
    else
        echo -e "${YELLOW}  ⚠ Some memory files may be missing (Core: ${CORE_COUNT}/2, Contexts: ${CONTEXT_COUNT}/5)${NC}"
    fi
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

        # Enforcement mode installation
        if [ "${INSTALL_ENFORCER}" = "true" ]; then
            echo -e "${PURPLE}🔒 Installing enforcement mechanism...${NC}"

            # Add to shell RC files
            local shell_rc_files=("${HOME}/.bashrc" "${HOME}/.zshrc")
            local enforcer_source="source '${GLOBAL_CONFIG_DIR}/guard/hooks/guard_enforcer.sh'"

            for rc_file in "${shell_rc_files[@]}"; do
                if [ -f "$rc_file" ]; then
                    # Check if already installed
                    if ! grep -q "guard_enforcer.sh" "$rc_file"; then
                        echo "" >> "$rc_file"
                        echo "# Trinitas Quality Guardian Enforcer" >> "$rc_file"
                        echo "$enforcer_source" >> "$rc_file"
                        echo -e "${GREEN}  ✓ Added enforcer to $rc_file${NC}"
                    else
                        echo -e "${YELLOW}  ⚠️  Enforcer already in $rc_file${NC}"
                    fi
                fi
            done

            echo -e "${CYAN}Enforcement modes:${NC}"
            echo -e "  ${WHITE}TRINITAS_GUARD_MODE=warn${NC}  - Show warnings only (default)"
            echo -e "  ${WHITE}TRINITAS_GUARD_MODE=block${NC} - Block operations with issues"
            echo -e "  ${WHITE}TRINITAS_GUARD_MODE=fix${NC}   - Auto-fix issues"
            echo -e ""
            echo -e "${PURPLE}🔧 To install language tools, run:${NC}"
            echo -e "  ${WHITE}~/.claude/guard/scripts/install_tools.sh${NC}"
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
    echo -e "${BLUE}🌍 Installing global configuration...${NC}"
    
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
        # 動的ビルドモード
        if [ -x "${SCRIPT_DIR}/scripts/build_claude_md.sh" ]; then
            echo -e "${CYAN}  🔨 Building CLAUDE.md from trinitas_sources/...${NC}"
            cd "${SCRIPT_DIR}"
            INCLUDE_TMWS="${INCLUDE_TMWS:-true}" ./scripts/build_claude_md.sh
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

# プロジェクト設定テンプレートの案内
show_project_setup_guide() {
    echo -e "${BLUE}📁 Project configuration guide:${NC}"
    echo ""
    echo "For each project, create a .claude/CLAUDE.md file using:"
    echo ""
    echo -e "${YELLOW}  cp ${TEMPLATES_DIR}/project/CLAUDE_project_template.md \\${NC}"
    echo -e "${YELLOW}     /path/to/your/project/.claude/CLAUDE.md${NC}"
    echo ""
    echo "Then customize it with:"
    echo "  • Project name and root directory"
    echo "  • Project-specific commands"
    echo "  • Custom rules and constraints"
    echo ""
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
    echo -e "${CYAN}📋 Summary:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${GREEN}✓ Global configuration installed${NC}"
    echo -e "${GREEN}✓ Backup created in ~/.claude/backup/${NC}"
    echo -e "${GREEN}✓ Performance optimized${NC}"
    echo ""
    
    echo -e "${YELLOW}📚 What's included:${NC}"
    echo "  • 6 Trinitas AI Personas (Athena, Artemis, Hestia, Eris, Hera, Muses)"
    echo "  • Memory Cookbook v2.2.1 (Lazy loading context system)"
    echo "  • Japanese response enforcement"
    echo "  • Optimized Hook loading (3KB vs 44KB)"
    echo "  • Basic command templates"
    if [[ "$WITH_GUARDIAN" != "false" ]]; then
        echo "  • Quality Guardian Framework (Multi-language)"
        if [[ "$INSTALL_ENFORCER" == "true" ]]; then
            echo "  • Auto-enforcement on git/npm/cargo/go commands"
        fi
    fi
    echo ""
    
    echo -e "${BLUE}🚀 Next Steps:${NC}"
    echo "1. Restart Claude Code to load new configuration"
    echo "2. Test with: 'Trinitasシステムの動作確認'"
    echo "3. For projects: Copy project template from trinitas_sources/config/project/"
    if [[ "$WITH_GUARDIAN" != "false" ]]; then
        echo "4. Install quality tools: ~/.claude/guard/scripts/install_tools.sh"
        echo "5. Check code quality: trinitas-guard check"
    fi
    echo ""
    
    echo -e "${MAGENTA}🎭 Trinitas Personas are ready!${NC}"
    echo -e "${GREEN}  Athena:${NC} 'ふふ、最適化されたシステムで温かい協力を始めましょう♪'"
    echo -e "${CYAN}  Artemis:${NC} 'パフォーマンス向上は完璧よ。データが証明している。'"
    echo -e "${RED}  Hestia:${NC} '...セキュリティ設定も適切に分離されました...'"
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
    echo -e "${YELLOW}This will install Trinitas optimized configuration to ~/.claude/${NC}"
    echo -e "${YELLOW}Current configuration will be backed up.${NC}"
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

    echo -e "${BLUE}Starting Trinitas configuration installation...${NC}"
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
    show_project_setup_guide
    performance_test
    show_installation_summary
    
    echo ""
    echo -e "${CYAN}Trinitas System: Ready for Excellence${NC}"
}

# ヘルプの表示
show_help() {
    echo "Trinitas Configuration Installer"
    echo ""
    echo "Usage:"
    echo "  $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -y, --yes      Skip confirmation prompt"
    echo "  --optimize     Build from trinitas_sources/ with TMWS (default)"
    echo "  --minimal      Use minimal template only (fastest, smallest)"
    echo "  --with-guardian Include Quality Guardian Framework (default: enabled)"
    echo "  --without-guardian Exclude Quality Guardian Framework"
    echo "  --enforce      Enable auto-enforcement for git/npm/cargo/go"
    echo "  --backup-only  Create backup only, don't install"
    echo "  --uninstall    Restore from latest backup"
    echo ""
    echo "Build Modes:"
    echo "  Default:  Dynamic build from trinitas_sources/ with TMWS"
    echo "  Optimize: Force rebuild from sources (useful after updates)"
    echo "  Minimal:  Use pre-built template only (3KB, no TMWS)"
    echo ""
    echo "Examples:"
    echo "  $0              # Interactive installation (includes Guardian)"
    echo "  $0 --yes        # Silent installation with full features"
    echo "  $0 --minimal    # Minimal installation (no Guardian)"
    echo "  $0 --enforce    # Install with auto-enforcement"
    echo "  $0 --without-guardian # Install without Quality Guardian"
    echo "  $0 --uninstall  # Restore previous configuration"
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
    --optimize)
        # 最適化モード：trinitas_sources/から動的ビルド
        export OPTIMIZE_MODE=true
        export INCLUDE_TMWS=true
        main "$@"
        ;;
    --minimal)
        # 最小モード：テンプレートのみ使用、Guardianなし
        export MINIMAL_MODE=true
        export INCLUDE_TMWS=false
        export WITH_GUARDIAN=false
        main "$@"
        ;;
    --with-guardian)
        # Quality Guardian Framework を含める (明示的に有効)
        export WITH_GUARDIAN=true
        export INCLUDE_TMWS=true
        shift
        main "$@"
        ;;
    --without-guardian)
        # Quality Guardian Framework を無効化
        export WITH_GUARDIAN=false
        shift
        main "$@"
        ;;
    --enforce)
        # Quality Guardian Framework with enforcement
        export WITH_GUARDIAN=true
        export INSTALL_ENFORCER=true
        export INCLUDE_TMWS=true
        shift
        main "$@"
        ;;
    *)
        # デフォルト：動的ビルド + TMWS + Quality Guardian含む
        export INCLUDE_TMWS=true
        export WITH_GUARDIAN=true
        export INSTALL_ENFORCER=false  # 強制実行はオプトイン
        main "$@"
        ;;
esac