#!/usr/bin/env python3
"""
ChromaDB Initialization Script for TMWS v2.3.0

Initializes ChromaDB collection with Multilingual-E5 embeddings (768-dim).
This script should be run once during installation.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    """Initialize ChromaDB collection."""
    print("\n" + "=" * 60)
    print("ChromaDB Initialization for TMWS v2.3.0")
    print("=" * 60 + "\n")

    try:
        from src.services.vector_search_service import get_vector_search_service
        from src.services.embedding_service import get_embedding_service

        # Initialize services
        print("Loading services...")
        vector_service = get_vector_search_service()
        embedding_service = get_embedding_service()

        # Initialize collection
        print("Initializing Chroma collection...")
        vector_service.initialize()

        # Display configuration
        print("\n✅ ChromaDB Initialized Successfully!\n")
        print(f"Collection: {vector_service.collection.name}")
        print(f"Embedding Model: {embedding_service.MODEL_NAME}")
        print(f"Embedding Dimension: {embedding_service.DIMENSION}")
        print(f"Distance Metric: cosine")
        print(f"Index Type: HNSW")
        print(f"Index Parameters: M=16, ef_construction=200")

        # Test embedding generation
        print("\nTesting embedding generation...")
        test_texts = [
            "This is a test document in English",
            "これは日本語のテスト文書です",
            "Database optimization improves query performance",
        ]

        for text in test_texts:
            embedding = embedding_service.encode_document(text)
            print(f"  ✅ Generated {len(embedding)}-dim embedding for: '{text[:50]}...'")

        # Get collection stats
        print("\nCollection Statistics:")
        count = vector_service.collection.count()
        print(f"  Total vectors: {count}")

        print("\n" + "=" * 60)
        print("✅ Initialization Complete!")
        print("=" * 60)
        print("\nNext Steps:")
        print("  1. Run TMWS: ./start_mcp.sh")
        print("  2. Test performance: ./run_benchmark.sh")
        print("  3. Populate cache: python scripts/rebuild_chroma_cache.py")
        print("")

    except Exception as e:
        print(f"\n❌ Initialization Failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
