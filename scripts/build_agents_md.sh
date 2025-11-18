#!/bin/bash

# Build AGENTS.md from trinitas_sources/agent/
# This script combines all agent configuration files into a single AGENTS.md

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_DIR="$PROJECT_ROOT/trinitas_sources/agent"
OUTPUT_FILE="$PROJECT_ROOT/AGENTS.md"

echo -e "${BLUE}Building AGENTS.md from trinitas_sources/agent/${NC}"

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${YELLOW}Warning: Source directory $SOURCE_DIR does not exist${NC}"
    exit 1
fi

# Create temporary file
TEMP_FILE=$(mktemp)

# Add header
{
    echo "# AGENTS.md - Trinitas Agent System Configuration"
    echo ""
    echo "This file defines the behavior and coordination patterns for all Trinitas agents."
    echo "Generated from trinitas_sources/agent/"
    echo ""
    echo "---"
    echo ""
} > "$TEMP_FILE"

# Process main files in order
echo -e "${BLUE}Processing agent configuration files...${NC}"

# Process numbered files first
for file in "$SOURCE_DIR"/*.md; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo -e "${GREEN}  + Adding $filename${NC}"
        
        # Add section header
        echo "## $(echo "$filename" | sed 's/^[0-9]*_//; s/.md$//; s/_/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
        
        # Add file content
        cat "$file" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
        echo "---" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
    fi
done

# Process subdirectories (like 01_tool_guidelines/)
for dir in "$SOURCE_DIR"/*/; do
    if [ -d "$dir" ]; then
        dirname=$(basename "$dir")
        echo -e "${BLUE}Processing subdirectory: $dirname${NC}"
        
        # Add section for subdirectory
        echo "## $(echo "$dirname" | sed 's/^[0-9]*_//; s/_/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
        
        # Process files in subdirectory
        for file in "$dir"/*.md; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                echo -e "${GREEN}    + Adding $dirname/$filename${NC}"
                
                # Add subsection header
                echo "### $(echo "$filename" | sed 's/.md$//; s/_/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')" >> "$TEMP_FILE"
                echo "" >> "$TEMP_FILE"
                
                # Add file content
                cat "$file" >> "$TEMP_FILE"
                echo "" >> "$TEMP_FILE"
            fi
        done
        
        echo "---" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
    fi
done

# Add Athena-Hera Discussion Flow if it exists
DISCUSSION_FLOW_FILE="$PROJECT_ROOT/ATHENA_HERA_DISCUSSION_FLOW.md"
if [ -f "$DISCUSSION_FLOW_FILE" ]; then
    echo -e "${BLUE}Adding Athena-Hera Discussion Flow...${NC}"
    {
        echo ""
        echo "---"
        echo ""
        echo "# Agent Discussion Protocol"
        echo ""
        cat "$DISCUSSION_FLOW_FILE"
        echo ""
    } >> "$TEMP_FILE"
    echo -e "${GREEN}  + Added ATHENA_HERA_DISCUSSION_FLOW.md${NC}"
else
    echo -e "${YELLOW}Note: ATHENA_HERA_DISCUSSION_FLOW.md not found, skipping${NC}"
fi

# Add timestamp and version
{
    echo ""
    echo "---"
    echo "# Generated Information"
    echo "- Built: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "- Version: $(git describe --tags --always 2>/dev/null || echo 'dev')"
    echo "- Source: trinitas_sources/agent/"
    echo "---"
} >> "$TEMP_FILE"

# Move to final location
mv "$TEMP_FILE" "$OUTPUT_FILE"

echo -e "${GREEN}✓ AGENTS.md successfully built at $OUTPUT_FILE${NC}"

# Show file size
FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
echo -e "${BLUE}File size: $FILE_SIZE${NC}"