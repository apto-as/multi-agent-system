#!/bin/bash

# Build CLAUDE.md from trinitas_sources/common/
# This script combines all common configuration files into a single CLAUDE.md

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_DIR="$PROJECT_ROOT/trinitas_sources/common"
OUTPUT_FILE="$PROJECT_ROOT/CLAUDE.md"

# Default: Include TMWS for complete documentation
# Set INCLUDE_TMWS=false to generate minimal version for hooks
INCLUDE_TMWS="${INCLUDE_TMWS:-true}"

echo -e "${BLUE}Building CLAUDE.md from trinitas_sources/common/${NC}"

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${YELLOW}Warning: Source directory $SOURCE_DIR does not exist${NC}"
    exit 1
fi

# Create temporary file
TEMP_FILE=$(mktemp)

# Combine files in order
echo -e "${BLUE}Combining source files...${NC}"

# Process files in numerical order
for file in "$SOURCE_DIR"/*.md; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")

        # Skip TMWS files if not included
        if [[ "$filename" == *"tmws"* ]] && [ "$INCLUDE_TMWS" = "false" ]; then
            echo -e "${YELLOW}  - Skipping $filename (TMWS excluded)${NC}"
            continue
        fi

        echo -e "${GREEN}  + Adding $filename${NC}"

        # Add file content with separator
        echo "" >> "$TEMP_FILE"

        # Add warning for dev TMWS
        if [[ "$filename" == *"tmws"* ]] && [ "$INCLUDE_TMWS" = "dev" ]; then
            echo "<!-- ⚠️ DEVELOPMENT TMWS FEATURES - UNSTABLE -->" >> "$TEMP_FILE"
        fi

        cat "$file" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
    fi
done

# Add TMWS section if enabled (DEFAULT: YES)
if [ "$INCLUDE_TMWS" = "true" ] || [ "$INCLUDE_TMWS" = "dev" ]; then
    if [ -d "$PROJECT_ROOT/trinitas_sources/tmws" ]; then
        echo -e "${BLUE}Adding TMWS integration sections...${NC}"

        # Add TMWS header
        {
            echo ""
            echo "## TMWS Integration"
            echo ""
            if [ "$INCLUDE_TMWS" = "dev" ]; then
                echo "⚠️ **Development Version** - Features may be unstable"
                echo ""
            fi
        } >> "$TEMP_FILE"

        # Process TMWS specific files
        for file in "$PROJECT_ROOT/trinitas_sources/tmws"/*.md; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                echo -e "${GREEN}  + Adding TMWS: $filename${NC}"
                cat "$file" >> "$TEMP_FILE"
                echo "" >> "$TEMP_FILE"
            fi
        done
    fi
fi

# Add AGENTS.md reference for agent coordination patterns
{
    echo ""
    echo "---"
    echo ""
    echo "# Agent Coordination and Execution Patterns"
    echo "@AGENTS.md"
    echo ""
} >> "$TEMP_FILE"

# Add timestamp and version
{
    echo "---"
    echo "# Generated Information"
    echo "- Built: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "- Version: $(git describe --tags --always 2>/dev/null || echo 'dev')"
    echo "- Source: trinitas_sources/common/"
    echo "---"
} >> "$TEMP_FILE"

# Move to final location
mv "$TEMP_FILE" "$OUTPUT_FILE"

echo -e "${GREEN}✓ CLAUDE.md successfully built at $OUTPUT_FILE${NC}"

# Show file size
FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
echo -e "${BLUE}File size: $FILE_SIZE${NC}"

# Inform about configuration
if [ "$INCLUDE_TMWS" = "true" ]; then
    echo -e "${GREEN}✓ Full documentation with TMWS included${NC}"
elif [ "$INCLUDE_TMWS" = "false" ]; then
    echo -e "${YELLOW}⚠️ Minimal version without TMWS (for hooks)${NC}"
fi