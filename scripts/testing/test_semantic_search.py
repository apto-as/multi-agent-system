#!/usr/bin/env python3
"""
TMWS Semantic Search Test Script
Tests semantic search functionality with Japanese queries
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.database import get_session
from src.services.memory_service import HybridMemoryService


async def test_semantic_search():
    """Test semantic search with various queries."""

    print("=" * 80)
    print("TMWS Semantic Search Test - Phase 2 (中級テスト)")
    print("=" * 80)
    print()

    # Test queries
    test_queries = [
        {
            "query": "Bug修正とMCP統合テストの完了状況",
            "description": "Bug fix and MCP integration test",
            "min_similarity": 0.7,
            "limit": 5
        },
        {
            "query": "データベースとChromaDBの設定",
            "description": "Database and ChromaDB configuration",
            "min_similarity": 0.6,
            "limit": 3
        },
        {
            "query": "async await の問題",
            "description": "Async/await issues",
            "min_similarity": 0.5,
            "limit": 5
        },
        {
            "query": "パフォーマンス最適化",
            "description": "Performance optimization",
            "min_similarity": 0.5,
            "limit": 3
        }
    ]

    async with get_session() as session:
        memory_service = HybridMemoryService(session)

        for i, test_case in enumerate(test_queries, 1):
            print(f"\n{'=' * 80}")
            print(f"Test {i}: {test_case['description']}")
            print(f"Query: {test_case['query']}")
            print(f"Min Similarity: {test_case['min_similarity']}, Limit: {test_case['limit']}")
            print(f"{'=' * 80}\n")

            try:
                # Search memories
                results = await memory_service.search_memories(
                    query=test_case['query'],
                    limit=test_case['limit'],
                    min_similarity=test_case['min_similarity'],
                    namespace="default"
                )

                if results:
                    print(f"✅ Found {len(results)} results:\n")

                    for j, memory in enumerate(results, 1):
                        print(f"  Result {j}:")
                        print(f"    ID: {memory.id}")
                        print(f"    Agent: {memory.agent_id}")
                        print(f"    Importance: {memory.importance_score}")
                        print(f"    Content Preview: {memory.content[:100]}...")
                        print(f"    Tags: {memory.tags}")
                        print(f"    Created: {memory.created_at}")
                        print()
                else:
                    print("⚠️  No results found (may need to adjust min_similarity)")

            except Exception as e:
                print(f"❌ Error: {type(e).__name__}: {str(e)}")
                import traceback
                traceback.print_exc()

            print()

    print("=" * 80)
    print("✅ Semantic Search Test Completed")
    print("=" * 80)


if __name__ == "__main__":
    # Set database URL to the actual MCP server database
    os.environ["TMWS_DATABASE_URL"] = "sqlite+aiosqlite:////Users/apto-as/.tmws/data/tmws.db"
    os.environ["TMWS_ENVIRONMENT"] = "development"
    os.environ["TMWS_SECRET_KEY"] = "test-secret-key"

    asyncio.run(test_semantic_search())
