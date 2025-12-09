"""Registry Builder for introspecting MCP servers and building sparse registry.

CLI tool for building/rebuilding the sparse registry from MCP presets.

Usage:
    # Build registry from default presets
    python -m src.infrastructure.mcp.registry_builder

    # Build from custom presets
    python -m src.infrastructure.mcp.registry_builder --presets /path/to/presets.json

    # Output to custom location
    python -m src.infrastructure.mcp.registry_builder --output /path/to/registry.json
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from src.infrastructure.mcp.preset_config import MCPServerPreset, load_presets
from src.models.registry import (
    ServerRegistryEntry,
    ToolRegistryEntry,
    RegistryMetadata,
    SparseRegistry,
    ToolCategory,
)

logger = logging.getLogger(__name__)


# Category keywords for auto-detection
CATEGORY_KEYWORDS = {
    ToolCategory.MEMORY: ["memory", "store", "recall", "remember", "knowledge"],
    ToolCategory.SEARCH: ["search", "find", "query", "lookup", "grep"],
    ToolCategory.BROWSER: ["browser", "navigate", "click", "page", "web"],
    ToolCategory.CODE: ["code", "symbol", "refactor", "edit", "ast"],
    ToolCategory.FILE: ["file", "read", "write", "directory", "path"],
    ToolCategory.DATA: ["data", "database", "sql", "spreadsheet", "csv"],
}


async def introspect_server(preset: MCPServerPreset) -> Dict[str, Any]:
    """Connect to server, extract tools, disconnect.

    Args:
        preset: MCP server preset configuration

    Returns:
        Dict with server_id, tools (list of dicts), and metadata

    Raises:
        RuntimeError: If server connection fails
    """
    logger.info(f"Introspecting server: {preset.id}")

    try:
        # Import here to avoid circular dependency
        from src.infrastructure.mcp.manager import MCPManager

        # Create temporary manager for introspection
        manager = MCPManager()
        await manager.initialize()

        # Connect to server
        logger.debug(f"Connecting to server: {preset.id}")
        await manager.connect_server(preset)

        # Get tools
        tools = await manager.list_tools(preset.id)
        logger.debug(f"Found {len(tools)} tools for {preset.id}")

        # Disconnect
        await manager.disconnect_server(preset.id)

        return {
            "server_id": preset.id,
            "tools": tools,
            "preset": preset,
        }

    except Exception as e:
        logger.error(f"Failed to introspect server {preset.id}: {e}")
        raise RuntimeError(f"Server introspection failed: {preset.id}") from e


def categorize_server(server_id: str, tools: List[Dict[str, Any]]) -> ToolCategory:
    """Auto-detect server category based on tool names and descriptions.

    Args:
        server_id: Server identifier
        tools: List of tool metadata dicts

    Returns:
        Detected category (defaults to OTHER if no match)
    """
    # Collect all text to analyze
    text_to_analyze = server_id.lower() + " "

    for tool in tools:
        text_to_analyze += tool.get("name", "").lower() + " "
        text_to_analyze += tool.get("description", "").lower() + " "

    # Count keyword matches per category
    category_scores = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_to_analyze)
        if score > 0:
            category_scores[category] = score

    # Return category with highest score
    if category_scores:
        return max(category_scores, key=category_scores.get)
    else:
        return ToolCategory.OTHER


def extract_keywords(tool_name: str, tool_description: str) -> List[str]:
    """Extract searchable keywords from tool name and description.

    Args:
        tool_name: Tool name
        tool_description: Tool description

    Returns:
        List of keywords (max 5)
    """
    # Extract words from name (split on underscore and camelCase)
    name_words = []
    for word in tool_name.replace("_", " ").split():
        # Split camelCase: "getMemory" -> ["get", "Memory"]
        import re

        name_words.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", word))

    # Extract important words from description (simple heuristic)
    desc_words = []
    if tool_description:
        # Split and take first 10 words
        words = tool_description.lower().split()[:10]
        # Filter out common words
        stopwords = {
            "a",
            "an",
            "the",
            "is",
            "are",
            "was",
            "were",
            "and",
            "or",
            "but",
            "for",
            "to",
            "of",
            "in",
            "on",
            "at",
        }
        desc_words = [w for w in words if w not in stopwords]

    # Combine and deduplicate
    all_keywords = list(dict.fromkeys(name_words + desc_words))

    # Return top 5
    return all_keywords[:5]


def truncate_description(description: str, max_length: int = 100) -> str:
    """Truncate description to max length, preserving word boundaries.

    Args:
        description: Original description
        max_length: Maximum length

    Returns:
        Truncated description
    """
    if len(description) <= max_length:
        return description

    # Find last space before max_length
    truncated = description[:max_length]
    last_space = truncated.rfind(" ")

    if last_space > 0:
        return truncated[:last_space] + "..."
    else:
        return truncated + "..."


def estimate_server_memory(tool_count: int, server_id: str) -> int:
    """Estimate server memory usage in MB.

    Args:
        tool_count: Number of tools
        server_id: Server identifier

    Returns:
        Estimated memory in MB
    """
    # Base memory: 30 MB
    base_memory = 30

    # Per-tool overhead: ~2 MB per tool
    tool_memory = tool_count * 2

    # Known servers with higher memory usage
    high_memory_servers = {"serena", "browser", "playwright"}
    if any(pattern in server_id.lower() for pattern in high_memory_servers):
        return base_memory + tool_memory + 50

    return base_memory + tool_memory


def estimate_cold_start_time(server_id: str, command: str) -> int:
    """Estimate server cold start time in milliseconds.

    Args:
        server_id: Server identifier
        command: Server command

    Returns:
        Estimated cold start time in ms
    """
    # Python servers: ~100ms
    if "python" in command.lower():
        return 100

    # Node.js servers: ~200ms
    if "node" in command.lower() or "npx" in command.lower():
        return 200

    # Native binaries: ~50ms
    return 50


async def build_sparse_registry(
    presets_path: Path, output_path: Path
) -> RegistryMetadata:
    """Build complete registry from all presets.

    Args:
        presets_path: Path to MCP presets JSON file
        output_path: Path to output registry JSON

    Returns:
        Registry metadata

    Raises:
        FileNotFoundError: If presets file not found
        RuntimeError: If registry building fails
    """
    logger.info(f"Building sparse registry from: {presets_path}")

    # Load presets
    if not presets_path.exists():
        raise FileNotFoundError(f"Presets file not found: {presets_path}")

    presets = load_presets(presets_path)
    logger.info(f"Loaded {len(presets)} preset servers")

    # Introspect all servers (sequentially to avoid resource exhaustion)
    introspection_results = []
    for preset in presets:
        try:
            result = await introspect_server(preset)
            introspection_results.append(result)
        except Exception as e:
            logger.warning(f"Skipping server {preset.id} due to error: {e}")
            continue

    # Build registry entries
    servers: Dict[str, ServerRegistryEntry] = {}
    tools: Dict[str, ToolRegistryEntry] = {}
    tool_by_server: Dict[str, List[str]] = {}

    for result in introspection_results:
        server_id = result["server_id"]
        preset = result["preset"]
        tool_list = result["tools"]

        # Categorize server
        category = categorize_server(server_id, tool_list)

        # Create server entry
        server_entry = ServerRegistryEntry(
            server_id=server_id,
            name=preset.name or server_id,
            command=preset.command,
            args=preset.args or [],
            env=preset.env,
            tool_count=len(tool_list),
            category=category,
            popularity_score=0.0,
            last_connected=None,
            estimated_memory_mb=estimate_server_memory(len(tool_list), server_id),
            cold_start_ms=estimate_cold_start_time(server_id, preset.command),
        )
        servers[server_id] = server_entry

        # Create tool entries
        tool_ids = []
        for tool_dict in tool_list:
            tool_name = tool_dict.get("name", "unknown")
            tool_id = f"{server_id}::{tool_name}"

            description = tool_dict.get("description", "")
            truncated_desc = truncate_description(description, max_length=100)

            keywords = extract_keywords(tool_name, description)

            tool_entry = ToolRegistryEntry(
                tool_id=tool_id,
                name=tool_name,
                server_id=server_id,
                category=category,
                description=truncated_desc,
                keywords=keywords,
            )
            tools[tool_id] = tool_entry
            tool_ids.append(tool_id)

        tool_by_server[server_id] = tool_ids

    # Create metadata
    metadata = RegistryMetadata(
        version="1.0.0",
        created_at=datetime.now(),
        server_count=len(servers),
        tool_count=len(tools),
        total_size_bytes=0,  # Will be updated on save
    )

    # Create registry
    registry = SparseRegistry(
        metadata=metadata,
        servers=servers,
        tools=tools,
        tool_by_server=tool_by_server,
    )

    # Save to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_str = registry.to_json(indent=2)
    metadata.total_size_bytes = len(json_str.encode("utf-8"))
    output_path.write_text(json_str)

    logger.info(f"Registry saved to: {output_path}")
    logger.info(f"Servers: {metadata.server_count}, Tools: {metadata.tool_count}")
    logger.info(f"Size: {metadata.total_size_bytes} bytes")

    return metadata


async def main_async(args: argparse.Namespace) -> int:
    """Async main function.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success)
    """
    # Setup logging
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    try:
        # Build registry
        metadata = await build_sparse_registry(args.presets, args.output)

        print(f"\n✅ Registry built successfully!")
        print(f"   Servers: {metadata.server_count}")
        print(f"   Tools: {metadata.tool_count}")
        print(f"   Size: {metadata.total_size_bytes} bytes")
        print(f"   Output: {args.output}")

        return 0

    except Exception as e:
        logger.error(f"Registry build failed: {e}", exc_info=True)
        print(f"\n❌ Registry build failed: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """CLI entry point.

    Returns:
        Exit code (0 for success)
    """
    parser = argparse.ArgumentParser(
        description="Build sparse registry from MCP presets"
    )

    parser.add_argument(
        "--presets",
        type=Path,
        default=Path("~/.tmws/config/mcp_presets.json").expanduser(),
        help="Path to MCP presets JSON file (default: ~/.tmws/config/mcp_presets.json)",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("~/.tmws/registry/index.json").expanduser(),
        help="Path to output registry JSON (default: ~/.tmws/registry/index.json)",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Run async main
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
