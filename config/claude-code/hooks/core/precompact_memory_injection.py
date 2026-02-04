#!/usr/bin/env python3
"""
precompact_memory_injection.py - PreCompact Hook for TMWS Memory Injection
============================================================================

Context compaction前に、TMWSから関連する過去のメモリを検索・注入する。
これにより、エージェントが過去の決定やパターンを思い出すことができる。

Performance Target: <250ms (including semantic search)
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, List
import asyncio

# decision_memory.pyをインポート
sys.path.insert(0, str(Path(__file__).parent))
from decision_memory import TrinitasDecisionMemory, Decision
from security_utils import (
    sanitize_log_message,
    safe_json_parse,
    validate_and_resolve_path,
)


class PreCompactMemoryInjectionHook:
    """PreCompact Hook for injecting relevant memories before context compaction"""

    def __init__(self):
        """Initialize hook with TMWS decision memory system"""
        # Validate and create fallback directory
        fallback_dir = Path.home() / ".claude" / "memory" / "decisions"
        safe_fallback_dir = validate_and_resolve_path(
            fallback_dir,
            base_dir=Path.home(),
            allow_create=True
        )

        self.decision_memory = TrinitasDecisionMemory(
            tmws_url="http://localhost:8000",
            fallback_dir=safe_fallback_dir,
            cache_size=100,
            timeout=0.3
        )

    async def process_hook(self, stdin_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main hook processing logic

        Searches TMWS for relevant past memories and injects them
        into the context before compaction.

        Args:
            stdin_data: JSON from stdin containing conversation data

        Returns:
            dict: {"addedContext": [...]} for stdout
        """
        try:
            # Extract conversation context
            conversation = stdin_data.get("conversation", {})
            messages = conversation.get("messages", [])

            # Get recent user queries (last 3 messages)
            recent_queries = self._extract_recent_queries(messages, limit=3)

            if not recent_queries:
                return {"addedContext": []}

            # Search TMWS for relevant past memories
            relevant_memories = await self._search_relevant_memories(recent_queries)

            if not relevant_memories:
                return {"addedContext": []}

            # Format memories for injection
            memory_context = self._format_memory_context(relevant_memories)

            return {
                "addedContext": [
                    {
                        "type": "text",
                        "text": memory_context
                    }
                ]
            }

        except Exception as e:
            # Fail-safe: return empty context, don't block compaction
            print(f"[precompact_memory] Error: {sanitize_log_message(str(e))}", file=sys.stderr)
            return {"addedContext": []}

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
                    queries.append(content.strip())

        return queries

    async def _search_relevant_memories(self, queries: List[str]) -> List[Decision]:
        """
        Search TMWS for memories relevant to recent queries

        Uses semantic search to find similar past decisions.

        Args:
            queries: List of recent user queries

        Returns:
            List[Decision]: Relevant past decisions
        """
        all_memories = []

        for query in queries:
            try:
                # Semantic search with min_similarity threshold
                memories = await self.decision_memory.query_similar_decisions(
                    query=query,
                    limit=5,
                    min_similarity=0.7  # Only high-relevance memories
                )
                all_memories.extend(memories)

            except Exception as e:
                # Continue if search fails for one query
                print(f"[precompact_memory] Search failed for query: {sanitize_log_message(str(e))}", file=sys.stderr)
                continue

        # Deduplicate by decision_id
        unique_memories = self._deduplicate_memories(all_memories)

        # Sort by importance (descending)
        unique_memories.sort(key=lambda m: m.importance, reverse=True)

        # Return top 10 most important
        return unique_memories[:10]

    def _deduplicate_memories(self, memories: List[Decision]) -> List[Decision]:
        """
        Remove duplicate memories by decision_id

        Args:
            memories: List of memories (may contain duplicates)

        Returns:
            List[Decision]: Unique memories
        """
        seen_ids = set()
        unique = []

        for memory in memories:
            if memory.decision_id not in seen_ids:
                seen_ids.add(memory.decision_id)
                unique.append(memory)

        return unique

    def _format_memory_context(self, memories: List[Decision]) -> str:
        """
        Format memories as context injection

        Creates a <system-reminder> block with formatted memories.

        Args:
            memories: List of relevant memories

        Returns:
            str: Formatted memory context
        """
        if not memories:
            return ""

        # Build context sections
        context_lines = [
            "<system-reminder>",
            "📚 **Relevant Past Memories** (from TMWS)",
            "",
            "The following past decisions and learnings may be relevant to the current conversation:",
            ""
        ]

        for i, memory in enumerate(memories, 1):
            # Format each memory
            context_lines.extend([
                f"### Memory {i}: {memory.decision_type.value}",
                f"**Persona**: {memory.persona}",
                f"**Context**: {memory.context[:150]}...",  # Truncate
                f"**Outcome**: {memory.outcome.value}",
                f"**Reasoning**: {memory.reasoning[:200]}...",  # Truncate
                f"**Importance**: {memory.importance:.2f}",
                f"**Tags**: {', '.join(memory.tags[:5])}",  # First 5 tags
                ""
            ])

        context_lines.extend([
            "---",
            f"*Total memories injected: {len(memories)}*",
            "</system-reminder>"
        ])

        return "\n".join(context_lines)


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

        # Process hook (async)
        output = asyncio.run(hook.process_hook(stdin_data))

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
