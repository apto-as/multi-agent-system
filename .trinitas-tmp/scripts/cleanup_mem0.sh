#!/bin/bash
# cleanup_mem0.sh - Remove accidentally installed Mem0 components
# Trinitas v2.2.4 - Emergency cleanup script

set -e

echo "🧹 Trinitas Mem0 Cleanup Script"
echo "================================"
echo ""
echo "This script will remove Mem0 components that may have been"
echo "accidentally installed by the old installer version."
echo ""

CLEANED=0

# Remove Mem0 directory
if [ -d "$HOME/.trinitas/mem0" ]; then
    echo "📁 Found: ~/.trinitas/mem0/"
    read -p "   Remove this directory? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$HOME/.trinitas/mem0"
        echo "   ✓ Removed ~/.trinitas/mem0/"
        CLEANED=$((CLEANED + 1))
    else
        echo "   ⊘ Skipped"
    fi
else
    echo "✓ ~/.trinitas/mem0/ not found (already clean)"
fi

# Remove parent .trinitas directory if empty
if [ -d "$HOME/.trinitas" ] && [ -z "$(ls -A "$HOME/.trinitas")" ]; then
    echo "📁 Found empty: ~/.trinitas/"
    rmdir "$HOME/.trinitas"
    echo "   ✓ Removed empty ~/.trinitas/"
    CLEANED=$((CLEANED + 1))
fi

# Remove MCP config
if [ -f "$HOME/.claude/mcp/mem0.json" ]; then
    echo "📄 Found: ~/.claude/mcp/mem0.json"
    read -p "   Remove this file? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm "$HOME/.claude/mcp/mem0.json"
        echo "   ✓ Removed ~/.claude/mcp/mem0.json"
        CLEANED=$((CLEANED + 1))
    else
        echo "   ⊘ Skipped"
    fi
else
    echo "✓ ~/.claude/mcp/mem0.json not found (already clean)"
fi

# Check for Ollama (informational only - may be used by other projects)
echo ""
echo "🔍 Checking for Ollama installation..."
if command -v ollama &> /dev/null; then
    echo "⚠️  Ollama is installed on this system"
    echo ""
    echo "   Ollama may be used by other projects, so this script does NOT"
    echo "   automatically remove it. If you installed Ollama only for Mem0"
    echo "   and want to remove it, run manually:"
    echo ""
    echo "   macOS:   brew uninstall ollama"
    echo "   Linux:   sudo systemctl stop ollama && sudo rm /usr/local/bin/ollama"
    echo ""

    # Check for Mem0-related Ollama models
    if ollama list 2>/dev/null | grep -q "mxbai-embed-large\|llama2"; then
        echo "   📦 Ollama models detected (possibly from Mem0):"
        ollama list | grep -E "mxbai-embed-large|llama2" || true
        echo ""
        echo "   To remove: ollama rm <model-name>"
    fi
else
    echo "✓ Ollama not installed (already clean)"
fi

echo ""
echo "================================"
if [ $CLEANED -gt 0 ]; then
    echo "✅ Cleanup complete: $CLEANED item(s) removed"
else
    echo "✅ No Mem0 components found - system is clean"
fi
echo ""
echo "Trinitas now uses a simple file-based memory system in:"
echo "  • ~/.claude/memory/"
echo "  • ~/.config/opencode/ (if using OpenCode)"
