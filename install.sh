#!/bin/bash

# Trinitas System Installer for Linux/WSL/macOS v2.3.0
# Usage: bash install.sh
# This installer copies Trinitas agents, hooks, and configuration to ~/.claude/

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Trinitas System Installer v2.3.0${NC}"
echo -e "${CYAN}Linux/WSL/macOS${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# Determine target directory
if [ -n "$CLAUDE_HOME" ]; then
    TARGET_DIR="$CLAUDE_HOME"
else
    TARGET_DIR="$HOME/.claude"
fi

echo -e "${YELLOW}Target directory: $TARGET_DIR${NC}"
echo

# Create .claude directory if it doesn't exist
if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${NC}Creating .claude directory...${NC}"
    mkdir -p "$TARGET_DIR"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Directory created successfully.${NC}"
    else
        echo -e "${RED}Error: Failed to create .claude directory${NC}"
        exit 1
    fi
else
    echo -e "${NC}.claude directory already exists.${NC}"
fi

echo
echo -e "${YELLOW}Copying files...${NC}"
echo

# Files to copy
FILES=(
    "CLAUDE.md"
    "AGENTS.md"
    "TRINITAS-CORE-PROTOCOL.md"
    "settings.json"
)

# Copy files
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        printf "Copying %-30s" "$file..."
        cp "$file" "$TARGET_DIR/" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[OK]${NC}"
        else
            echo -e "${RED}[ERROR]${NC}"
            echo -e "${RED}  Error: Failed to copy $file${NC}"
            exit 1
        fi
    else
        printf "%-30s" "$file"
        echo -e "${YELLOW}[SKIP] (not found)${NC}"
    fi
done

echo
echo -e "${YELLOW}Copying directories...${NC}"
echo

# Directories to copy
DIRECTORIES=(
    "agents"
    "commands"
    "hooks"
    "config"
    "contexts"
    "shared"
)

# Copy directories
for dir in "${DIRECTORIES[@]}"; do
    if [ -d "$dir" ]; then
        printf "Copying %-30s" "$dir/ ..."
        # Remove target directory if it exists
        if [ -d "$TARGET_DIR/$dir" ]; then
            rm -rf "$TARGET_DIR/$dir"
        fi
        # Copy directory
        cp -r "$dir" "$TARGET_DIR/" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[OK]${NC}"
        else
            echo -e "${RED}[ERROR]${NC}"
            echo -e "${RED}  Error: Failed to copy $dir directory${NC}"
            exit 1
        fi
    else
        printf "%-30s" "$dir/"
        echo -e "${YELLOW}[SKIP] (not found)${NC}"
    fi
done

# Set permissions for hooks if they exist
if [ -d "$TARGET_DIR/hooks" ]; then
    echo
    echo -e "${YELLOW}Setting permissions...${NC}"
    find "$TARGET_DIR/hooks" -name "*.py" -exec chmod +x {} \; 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Permissions set for Python hooks.${NC}"
    fi
fi

echo
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${CYAN}========================================${NC}"
echo
echo -e "${YELLOW}Files have been copied to:${NC}"
echo -e "  ${NC}$TARGET_DIR${NC}"
echo
echo -e "${NC}To verify the installation, run:${NC}"
echo -e "  ${NC}ls -la \"$TARGET_DIR\"${NC}"
echo

# WSL-specific information
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo -e "${CYAN}WSL Detected!${NC}"
    echo -e "${YELLOW}Note for WSL users:${NC}"
    echo -e "  - Claude Desktop runs on Windows, not in WSL"
    echo -e "  - You may also want to run the Windows installer (install.ps1)"
    echo -e "  - Files in WSL can be accessed from Windows at:"
    echo -e "    ${NC}\\\\wsl$\\$(lsb_release -i -s 2>/dev/null || echo "Ubuntu")$TARGET_DIR${NC}"
    echo
fi

# Check if running in a container
if [ -f /.dockerenv ] || [ -n "$CONTAINER" ]; then
    echo -e "${CYAN}Container environment detected!${NC}"
    echo -e "${YELLOW}Note:${NC} Make sure to mount this directory when running Claude Desktop."
    echo
fi

echo -e "${GREEN}Installation complete!${NC}"