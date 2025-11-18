#!/usr/bin/env python3
"""
precompact_memory_injection.py - PreCompact Hook for TMWS Memory Integration
=============================================================================

Context compaction前に、以下を実行:
1. ローカルキャッシュの決定をTMWSにアップロード（Claude経由でMCPツール使用）
2. TMWSから関連する過去のメモリを検索・注入（Claude経由でMCPツール使用）

これにより、エージェントが過去の決定やパターンを思い出すことができる。

Performance Target: <100ms (プロンプト生成のみ、MCP実行はClaude側)

Architecture v2.4.0:
- MCP tools integration via prompt-based approach
- No direct HTTP client dependencies
- Lightweight file-based cache management
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent))
from security_utils import (
    sanitize_log_message,
    safe_json_parse,
    validate_and_resolve_path,
)


class PreCompactMemoryInjectionHook:
    """PreCompact Hook for uploading cached decisions and injecting relevant memories"""

    def __init__(self):
        """Initialize hook with cache directory"""
        # Validate and get cache directory
        cache_dir = Path.home() / ".claude" / "memory" / "decisions"
        self.cache_dir = validate_and_resolve_path(
            cache_dir,
            base_dir=Path.home(),
            allow_create=True
        )

    def process_hook(self, stdin_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main hook processing logic

        1. Upload cached decisions to TMWS (via MCP prompt)
        2. Search TMWS for relevant memories (via MCP prompt)
        3. Inject memories into context

        Args:
            stdin_data: JSON from stdin containing conversation data

        Returns:
            dict: {"addedContext": [...]} for stdout
        """
        try:
            # Step 1: Get cached decisions (not yet uploaded to TMWS)
            cached_decisions = self._load_cached_decisions()

            # Step 2: Extract conversation context for memory search
            conversation = stdin_data.get("conversation", {})
            messages = conversation.get("messages", [])
            recent_queries = self._extract_recent_queries(messages, limit=3)

            # Step 3: Generate MCP prompt for Claude
            mcp_prompt = self._generate_mcp_prompt(cached_decisions, recent_queries)

            if not mcp_prompt:
                return {"addedContext": []}

            return {
                "addedContext": [
                    {
                        "type": "text",
                        "text": mcp_prompt
                    }
                ]
            }

        except Exception as e:
            # Fail-safe: return empty context, don't block compaction
            print(f"[precompact_memory] Error: {sanitize_log_message(str(e))}", file=sys.stderr)
            return {"addedContext": []}

    def _load_cached_decisions(self) -> List[Dict[str, Any]]:
        """
        Load cached decisions from local file system

        These are decisions recorded by decision_check.py but not yet
        uploaded to TMWS.

        Returns:
            List[Dict]: List of cached decision data
        """
        decisions = []

        try:
            # Find all decision files in cache directory
            for decision_file in sorted(self.cache_dir.glob("decision-*.json")):
                try:
                    with open(decision_file, 'r', encoding='utf-8') as f:
                        decision_data = json.load(f)
                        decisions.append(decision_data)

                except Exception as e:
                    print(f"[precompact_memory] Failed to load {decision_file.name}: {sanitize_log_message(str(e))}", file=sys.stderr)
                    continue

        except Exception as e:
            print(f"[precompact_memory] Failed to scan cache directory: {sanitize_log_message(str(e))}", file=sys.stderr)

        return decisions

    def _extract_recent_queries(self, messages: List[Dict[str, Any]], limit: int = 3) -> List[str]:
        """
        Extract recent user queries from conversation

        Args:
            messages: List of conversation messages
            limit: Maximum number of queries to extract

        Returns:
            List[str]: Recent user query texts
        """
        queries = []

        # Iterate backwards through messages (most recent first)
        for message in reversed(messages):
            if len(queries) >= limit:
                break

            # Only extract user messages
            if message.get("role") == "user":
                content = message.get("content", "")
                if isinstance(content, str) and content.strip():
                    # Limit query length to avoid token bloat
                    query = content.strip()[:500]
                    queries.append(query)

        return queries

    def _generate_mcp_prompt(
        self,
        cached_decisions: List[Dict[str, Any]],
        recent_queries: List[str]
    ) -> str:
        """
        Generate prompt for Claude to use MCP tools

        This prompt instructs Claude to:
        1. Upload cached decisions to TMWS using mcp__tmws__store_memory
        2. Search TMWS for relevant memories using mcp__tmws__search_memories
        3. Inject top relevant memories into context

        Args:
            cached_decisions: List of cached decision data
            recent_queries: List of recent user queries

        Returns:
            str: MCP prompt for Claude
        """
        if not cached_decisions and not recent_queries:
            return ""

        prompt_parts = [
            "<system-reminder>",
            "📚 **TMWS Memory Integration** (Trinitas v2.4.0)",
            ""
        ]

        # Part 1: Upload cached decisions to TMWS
        if cached_decisions:
            prompt_parts.extend([
                "## Step 1: Upload Recent Decisions to TMWS",
                "",
                f"Found {len(cached_decisions)} cached decision(s) to upload to TMWS.",
                "Please use `mcp__tmws__store_memory` for each:",
                ""
            ])

            # Limit to last 5 decisions to avoid token bloat
            for decision in cached_decisions[-5:]:
                decision_id = decision.get("decision_id", "unknown")
                content = decision.get("context", "")
                importance = decision.get("importance", 0.5)
                tags = decision.get("tags", [])

                prompt_parts.extend([
                    f"### Decision: {decision_id}",
                    "```",
                    f"mcp__tmws__store_memory(",
                    f"  content: \"{content[:200]}...\",",
                    f"  importance: {importance},",
                    f"  tags: {tags},",
                    f"  namespace: \"trinitas-agents\"",
                    ")",
                    "```",
                    ""
                ])

                # After successful upload, delete the cache file
                prompt_parts.extend([
                    f"After upload, please note: Cache file `{decision_id}.json` should be deleted.",
                    ""
                ])

            prompt_parts.append("")

        # Part 2: Search TMWS for relevant memories
        if recent_queries:
            prompt_parts.extend([
                "## Step 2: Search TMWS for Relevant Memories",
                "",
                f"Recent conversation queries ({len(recent_queries)}):",
                ""
            ])

            for i, query in enumerate(recent_queries, 1):
                prompt_parts.append(f"{i}. \"{query[:200]}...\"")

            prompt_parts.extend([
                "",
                "Please use `mcp__tmws__search_memories` to find relevant past decisions:",
                "```",
                "mcp__tmws__search_memories(",
                f"  query: \"<combination of queries above>\",",
                "  limit: 5,",
                "  min_similarity: 0.7,",
                "  namespace: \"trinitas-agents\"",
                ")",
                "```",
                "",
                "**Instructions**:",
                "- Combine the recent queries into a single semantic search query",
                "- Return top 5 most relevant memories (similarity >= 0.7)",
                "- Format results as brief summary for context injection",
                ""
            ])

        prompt_parts.extend([
            "---",
            "*This is an automated TMWS integration prompt from precompact hook*",
            "</system-reminder>"
        ])

        return "\n".join(prompt_parts)


def main():
    """
    Main entry point for PreCompact hook

    Reads JSON from stdin, processes, writes JSON to stdout
    """
    try:
        # Read and parse stdin
        stdin_raw = sys.stdin.read()
        stdin_data = safe_json_parse(stdin_raw, max_size=50_000, max_depth=10)

        # Create hook instance
        hook = PreCompactMemoryInjectionHook()

        # Process hook (synchronous - no async needed)
        output = hook.process_hook(stdin_data)

        # Write stdout
        print(json.dumps(output, ensure_ascii=False))

        # Exit success
        sys.exit(0)

    except Exception as e:
        # Fail-safe: return empty context, exit success
        print(f"[precompact_memory] Fatal error: {sanitize_log_message(str(e))}", file=sys.stderr)
        print(json.dumps({"addedContext": []}, ensure_ascii=False))
        sys.exit(0)


if __name__ == "__main__":
    main()
