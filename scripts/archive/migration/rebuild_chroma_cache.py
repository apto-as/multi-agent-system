#!/usr/bin/env python3
"""
ChromaDB Hot Cache Rebuild Script for TMWS v2.3.0

Synchronizes PostgreSQL memories to ChromaDB collection.
Useful for:
- Disaster recovery (rebuild Chroma if corrupted)
- Cache warming (populate Chroma on fresh install)
- Migration (populate Chroma when upgrading from v2.2.0)

Usage:
    python scripts/rebuild_chroma_cache.py [--limit N] [--batch-size N] [--min-importance FLOAT]
"""

import argparse
import asyncio
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


async def rebuild_chroma_cache(
    limit: Optional[int] = None,
    batch_size: int = 100,
    min_importance: float = 0.0,
):
    """Rebuild ChromaDB hot cache from PostgreSQL."""
    from sqlalchemy import select, func
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    import numpy as np

    from src.models.memory import Memory
    from src.services.vector_search_service import get_vector_search_service
    from src.services.embedding_service import get_embedding_service
    from src.core.config import settings

    print("\n" + "=" * 60)
    print("ChromaDB Hot Cache Rebuild for TMWS v2.3.0")
    print("=" * 60 + "\n")

    # Initialize services
    print("Initializing services...")
    vector_service = get_vector_search_service()
    embedding_service = get_embedding_service()
    print(f"✅ Embedding Model: {embedding_service.MODEL_NAME}")
    print(f"✅ Embedding Dimension: {embedding_service.DIMENSION}")
    print(f"✅ ChromaDB Collection: {vector_service.collection.name}")

    # Create database session
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # Query total count
        count_query = select(func.count(Memory.id)).where(
            Memory.importance >= min_importance
        )
        if limit:
            print(f"\nQuerying top {limit} memories (importance >= {min_importance})...")
        else:
            print(f"\nQuerying all memories (importance >= {min_importance})...")

        result = await session.execute(count_query)
        total_count = result.scalar()
        print(f"Total memories to sync: {total_count}")

        if total_count == 0:
            print("\n⚠️  No memories found in PostgreSQL. Nothing to rebuild.")
            return

        # Query memories ordered by importance (descending)
        query = (
            select(Memory)
            .where(Memory.importance >= min_importance)
            .order_by(Memory.importance.desc(), Memory.created_at.desc())
        )
        if limit:
            query = query.limit(limit)

        result = await session.execute(query)
        memories = result.scalars().all()

        # Process in batches
        print(f"\nProcessing {len(memories)} memories in batches of {batch_size}...")

        synced_count = 0
        error_count = 0
        skipped_count = 0

        for i in range(0, len(memories), batch_size):
            batch = memories[i : i + batch_size]
            batch_ids = []
            batch_embeddings = []
            batch_metadatas = []
            batch_documents = []

            for memory in batch:
                try:
                    # Get or generate embedding
                    if memory.embedding_v2 and len(memory.embedding_v2) == embedding_service.DIMENSION:
                        # Use existing embedding (v2.3.0 format)
                        embedding = np.array(memory.embedding_v2, dtype=np.float32)
                    elif memory.embedding and len(memory.embedding) == embedding_service.DIMENSION:
                        # Use legacy embedding if compatible
                        embedding = np.array(memory.embedding, dtype=np.float32)
                    else:
                        # Generate new embedding
                        embedding = embedding_service.encode_document(memory.content)

                    # Prepare for batch insertion
                    batch_ids.append(str(memory.id))
                    batch_embeddings.append(embedding.tolist())
                    batch_documents.append(memory.content)

                    metadata = {
                        "memory_type": memory.memory_type or "general",
                        "importance": float(memory.importance),
                        "persona_id": memory.persona_id or "unknown",
                        "namespace": memory.namespace or "default",
                        "created_at": memory.created_at.isoformat() if memory.created_at else None,
                    }

                    # Add tags if available
                    if memory.tags:
                        metadata["tags"] = ",".join(memory.tags)

                    # Add custom metadata if available
                    if memory.metadata:
                        for key, value in memory.metadata.items():
                            # Chroma only supports string, int, float, bool
                            if isinstance(value, (str, int, float, bool)):
                                metadata[f"custom_{key}"] = value

                    batch_metadatas.append(metadata)

                except Exception as e:
                    print(f"  ⚠️  Error processing memory {memory.id}: {e}")
                    error_count += 1

            # Batch insert to ChromaDB
            if batch_ids:
                try:
                    vector_service.collection.upsert(
                        ids=batch_ids,
                        embeddings=batch_embeddings,
                        documents=batch_documents,
                        metadatas=batch_metadatas,
                    )
                    synced_count += len(batch_ids)
                    print(
                        f"  ✅ Synced batch {i // batch_size + 1}: "
                        f"{synced_count}/{len(memories)} memories"
                    )
                except Exception as e:
                    print(f"  ❌ Error syncing batch {i // batch_size + 1}: {e}")
                    error_count += len(batch_ids)

        # Final statistics
        print("\n" + "=" * 60)
        print("Rebuild Complete!")
        print("=" * 60)
        print(f"\n📊 Statistics:")
        print(f"  Total memories: {total_count}")
        print(f"  Synced to ChromaDB: {synced_count}")
        print(f"  Errors: {error_count}")
        print(f"  Skipped: {skipped_count}")

        # Verify ChromaDB count
        chroma_count = vector_service.collection.count()
        print(f"\n✅ ChromaDB collection count: {chroma_count}")

        if chroma_count >= synced_count:
            print("✅ Sync verification passed!")
        else:
            print("⚠️  Warning: ChromaDB count mismatch. Some memories may not have synced.")

    await engine.dispose()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Rebuild ChromaDB hot cache from PostgreSQL"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of memories to sync (default: all)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for ChromaDB insertion (default: 100)",
    )
    parser.add_argument(
        "--min-importance",
        type=float,
        default=0.0,
        help="Minimum importance threshold (default: 0.0)",
    )

    args = parser.parse_args()

    try:
        asyncio.run(
            rebuild_chroma_cache(
                limit=args.limit,
                batch_size=args.batch_size,
                min_importance=args.min_importance,
            )
        )
        print("\n✅ ChromaDB hot cache rebuild completed successfully!\n")
    except KeyboardInterrupt:
        print("\n\n⚠️  Rebuild interrupted by user.\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Rebuild failed: {e}\n")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
