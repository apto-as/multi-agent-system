#!/bin/bash

# Build TRINITAS-CORE-PROTOCOL.md with conditional TMWS inclusion
# This script generates the protocol file for hook injection

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="$PROJECT_ROOT/TRINITAS-CORE-PROTOCOL.md"

echo -e "${BLUE}Building TRINITAS-CORE-PROTOCOL.md${NC}"
echo -e "${BLUE}TMWS Mode: ${INCLUDE_TMWS:-auto}${NC}"

# Create temporary file
TEMP_FILE=$(mktemp)

# Add header
{
    echo "# TRINITAS-CORE-PROTOCOL v5.0"
    echo "## Hook Injection Protocol for Claude Code"
    echo ""
    echo "---"
    echo "generated_at: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "tmws_included: ${INCLUDE_TMWS:-false}"
    echo "---"
    echo ""
} > "$TEMP_FILE"

# Section 1: Core Persona Information (Always included)
{
    echo "## 📌 Core Personas (Always Active)"
    echo ""
    echo "- **Athena**: Harmonious Conductor - orchestration, workflow"
    echo "- **Artemis**: Technical Perfectionist - optimization, performance"
    echo "- **Hestia**: Security Guardian - security, audit, risk"
    echo "- **Eris**: Tactical Coordinator - coordination, team"
    echo "- **Hera**: Strategic Commander - strategy, planning"
    echo "- **Muses**: Knowledge Architect - documentation, knowledge"
    echo ""
} >> "$TEMP_FILE"

# Section 2: MCP Tool Execution (Conditional TMWS)
if [ "$INCLUDE_TMWS" = "true" ] || [ "$INCLUDE_TMWS" = "dev" ]; then
    echo -e "${GREEN}Including TMWS MCP tools section${NC}"
    {
        echo "## 🎯 MCP Tool Execution Methods"
        echo ""
        if [ "$INCLUDE_TMWS" = "dev" ]; then
            echo "⚠️ **DEVELOPMENT VERSION** - API may change"
            echo ""
        fi
        echo "### TMWS エージェント操作"
        echo '```python'
        echo '# エージェント情報取得'
        echo 'get_agent_info()'
        echo ''
        echo '# エージェント切り替え'
        echo 'switch_agent(agent_id="athena-conductor")'
        echo ''
        echo '# カスタムエージェント登録'
        echo 'register_agent(agent_name="researcher", capabilities=["research", "analysis"])'
        echo '```'
        echo ""
        echo "### メモリ操作"
        echo '```python'
        echo '# メモリ作成'
        echo 'create_memory(content="重要な決定", tags=["decision"], importance=0.9)'
        echo ''
        echo '# メモリ検索'
        echo 'recall_memory(query="architecture", semantic=True, limit=5)'
        echo '```'
        echo ""
        echo "### パターン学習"
        echo '```python'
        echo '# パターン学習'
        echo 'learn_pattern(pattern_name="optimization", result="90% improvement")'
        echo ''
        echo '# パターン適用'
        echo 'apply_pattern(pattern_name="optimization", target="new_endpoint")'
        echo '```'
        echo ""
    } >> "$TEMP_FILE"
else
    echo -e "${YELLOW}Excluding TMWS MCP tools (using basic commands)${NC}"
    {
        echo "## 🎯 Basic Command Execution"
        echo ""
        echo "### Manual Persona Invocation"
        echo '```bash'
        echo '# Use Task tool for persona execution'
        echo 'Task tool with subagent_type parameter'
        echo '```'
        echo ""
        echo "### Local Memory Management"
        echo '```bash'
        echo '# Use Read/Write tools for persistence'
        echo 'Write memories to project .claude/ directory'
        echo '```'
        echo ""
    } >> "$TEMP_FILE"
fi

# Section 3: Security Checklist (Always included)
{
    echo "## 🛡️ Security Checklist (Critical)"
    echo ""
    echo "### Pre-Commit Checks"
    echo "- [ ] No passwords/API keys in code"
    echo "- [ ] .env files in .gitignore"
    echo "- [ ] Input validation implemented"
    echo "- [ ] SQL queries parameterized"
    echo "- [ ] Error messages sanitized"
    echo ""
    echo "### Emergency Response"
    echo "1. Vulnerability found → Immediate isolation"
    echo "2. Execute security audit persona"
    echo "3. Document in security log"
    echo ""
} >> "$TEMP_FILE"

# Section 4: Performance Thresholds (Always included)
{
    echo "## ⚡ Performance Guidelines"
    echo ""
    echo "### Optimization Triggers"
    echo "- Response > 1s → Consider caching"
    echo "- Memory > 80% → Garbage collection"
    echo "- CPU > 70% → Task distribution"
    echo ""
    echo "### Parallel Execution"
    echo "- Tasks ≥ 3 → Use parallel processing"
    echo "- API calls → Max 5 concurrent"
    echo "- Batch size → 100 items"
    echo ""
} >> "$TEMP_FILE"

# Section 5: PreCompact Instructions (Always included)
{
    echo "## 🔒 PreCompact Context Preservation"
    echo ""
    echo "### Must Preserve"
    echo "1. **Security decisions and findings**"
    echo "2. **Architecture decisions (ADRs)**"
    echo "3. **Unresolved issues and TODOs**"
    echo "4. **Project-specific patterns**"
    echo "5. **Successful persona combinations**"
    echo ""
    echo "### Session Summary Format"
    echo '```markdown'
    echo "- Used Personas: [list]"
    echo "- Key Decisions: [list]"
    echo "- Discovered Patterns: [list]"
    echo "- Remaining Tasks: [list]"
    echo '```'
    echo ""
} >> "$TEMP_FILE"

# Section 6: Error Recovery (Always included)
{
    echo "## 🔧 Error Recovery Flows"
    echo ""
    echo "### Common Error Handlers"
    echo "- **Connection Error**: 3 retries → fallback"
    echo "- **Timeout**: Split task → reduce parallelism"
    echo "- **Memory Error**: Clear cache → restart"
    echo "- **Auth Error**: Refresh token → retry"
    echo ""
} >> "$TEMP_FILE"

# Add dynamic sections if TMWS is enabled
if [ "$INCLUDE_TMWS" = "true" ] || [ "$INCLUDE_TMWS" = "dev" ]; then
    {
        echo "## 📊 TMWS Dynamic Sections"
        echo ""
        echo "### プロジェクトコンテキスト (TMWSから動的取得)"
        echo '```python'
        echo '# SessionStart時に取得'
        echo 'get_agent_info()  # 現在のエージェント情報'
        echo 'get_memory_stats()  # メモリ統計'
        echo 'get_system_stats()  # システム状態'
        echo '```'
        echo ""
        echo "### 学習済みパターン (TMWSから動的取得)"
        echo '```python'
        echo '# SessionStart時に取得'
        echo 'get_learning_history(limit=10)  # 最近の学習'
        echo 'search_patterns(query="optimization")  # パターン検索'
        echo '```'
        echo ""
    } >> "$TEMP_FILE"
fi

# Add footer
{
    echo "---"
    echo "# Metadata"
    echo "- Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "- Version: $(git describe --tags --always 2>/dev/null || echo 'dev')"
    echo "- TMWS Status: ${INCLUDE_TMWS:-not specified}"
    echo "---"
} >> "$TEMP_FILE"

# Move to final location
mv "$TEMP_FILE" "$OUTPUT_FILE"

echo -e "${GREEN}✓ TRINITAS-CORE-PROTOCOL.md successfully built${NC}"

# Show summary
FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
LINE_COUNT=$(wc -l < "$OUTPUT_FILE")

echo -e "${BLUE}File size: $FILE_SIZE${NC}"
echo -e "${BLUE}Line count: $LINE_COUNT${NC}"

if [ "$INCLUDE_TMWS" = "true" ]; then
    echo -e "${GREEN}TMWS integration: ENABLED${NC}"
elif [ "$INCLUDE_TMWS" = "dev" ]; then
    echo -e "${YELLOW}TMWS integration: DEVELOPMENT MODE${NC}"
else
    echo -e "${YELLOW}TMWS integration: DISABLED${NC}"
fi