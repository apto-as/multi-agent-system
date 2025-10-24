#!/usr/bin/env python3
"""
ChromaDB Collection Migration Script
=====================================

Migrates vector embeddings from the old collection name (tmws_memories_v2)
to the new collection name (tmws_memories) as part of the _v2 suffix removal.

Features:
- Zero data loss migration
- Batch processing for large collections
- Progress tracking with tqdm
- Safety checks and confirmations
- Rollback support (keeps old collection unless explicitly deleted)

Usage:
    python scripts/migrate_chroma_collection.py

    Optional flags:
        --auto-delete    Automatically delete old collection after successful migration
        --batch-size N   Set custom batch size (default: 1000)
        --dry-run       Show what would be migrated without making changes

Requirements:
    - ChromaDB client installed
    - ChromaDB data directory at data/chroma/
    - Old collection (tmws_memories_v2) must exist

Author: Athena (Harmonious Conductor) + Artemis (Technical Perfectionist)
Date: 2025-10-24
"""

import argparse
import sys
from pathlib import Path

try:
    import chromadb
    from chromadb.config import Settings
except ImportError:
    print("❌ ChromaDB not installed. Please run: pip install chromadb")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("⚠️  tqdm not installed. Progress bar disabled. Install with: pip install tqdm")
    tqdm = None


def migrate_chroma_collection(
    old_name: str = "tmws_memories_v2",
    new_name: str = "tmws_memories",
    batch_size: int = 1000,
    auto_delete: bool = False,
    dry_run: bool = False,
) -> bool:
    """
    Migrate ChromaDB collection from old name to new name.

    Args:
        old_name: Source collection name
        new_name: Destination collection name
        batch_size: Number of vectors to migrate per batch
        auto_delete: Automatically delete old collection after migration
        dry_run: Show what would be migrated without making changes

    Returns:
        bool: True if migration successful, False otherwise
    """

    # Initialize ChromaDB client
    chroma_path = Path(__file__).parent.parent / "data" / "chroma"

    if not chroma_path.exists():
        print(f"❌ ChromaDB directory not found: {chroma_path}")
        print("   Please ensure the database has been initialized.")
        return False

    try:
        client = chromadb.PersistentClient(
            path=str(chroma_path), settings=Settings(anonymized_telemetry=False)
        )
    except Exception as e:
        print(f"❌ Failed to initialize ChromaDB client: {e}")
        return False

    print(f"\n🔄 ChromaDB Collection Migration")
    print(f"{'=' * 60}")
    print(f"Source:      {old_name}")
    print(f"Destination: {new_name}")
    print(f"Batch size:  {batch_size}")
    print(f"Mode:        {'DRY RUN' if dry_run else 'LIVE MIGRATION'}")
    print(f"{'=' * 60}\n")

    # Check if old collection exists
    try:
        old_collection = client.get_collection(old_name)
        old_count = old_collection.count()
        print(f"✅ Found source collection: {old_count:,} vectors")

        if old_count == 0:
            print("⚠️  Source collection is empty. Nothing to migrate.")
            return True

        # Show metadata
        print(f"   Metadata: {old_collection.metadata}")

    except Exception as e:
        print(f"❌ Source collection not found: {e}")
        print(f"   Looking for: {old_name}")
        print("\n   Available collections:")
        for col in client.list_collections():
            print(f"   - {col.name} ({col.count()} vectors)")
        return False

    # Check if new collection already exists
    collection_exists = False
    try:
        existing = client.get_collection(new_name)
        existing_count = existing.count()
        collection_exists = True
        print(f"\n⚠️  Destination collection already exists!")
        print(f"   Current vectors: {existing_count:,}")

        if dry_run:
            print("   [DRY RUN] Would delete and recreate collection")
        else:
            response = input("\n   Delete and recreate? (yes/no): ")
            if response.lower() != "yes":
                print("❌ Migration cancelled by user")
                return False

            client.delete_collection(new_name)
            print("   ✅ Old destination collection deleted")

    except Exception:
        pass  # Collection doesn't exist, which is fine

    if dry_run:
        print(f"\n[DRY RUN] Would migrate {old_count:,} vectors in batches of {batch_size}")
        print(f"[DRY RUN] Would create collection: {new_name}")
        return True

    # Create new collection with same configuration
    try:
        new_collection = client.create_collection(name=new_name, metadata=old_collection.metadata)
        print(f"\n✅ Created destination collection")
        print(f"   Metadata: {new_collection.metadata}")
    except Exception as e:
        print(f"❌ Failed to create destination collection: {e}")
        return False

    # Migrate all vectors in batches
    print(f"\n🔄 Migrating {old_count:,} vectors...")

    try:
        # Get all data from source collection
        all_data = old_collection.get(include=["embeddings", "metadatas", "documents"])

        total_ids = len(all_data["ids"])
        print(f"   Retrieved {total_ids:,} entries")

        # Create progress bar if tqdm available
        if tqdm:
            progress = tqdm(
                total=total_ids, desc="Migrating vectors", unit="vectors", unit_scale=True
            )
        else:
            progress = None

        # Migrate in batches
        migrated_count = 0
        for i in range(0, total_ids, batch_size):
            batch_end = min(i + batch_size, total_ids)

            batch_data = {
                "ids": all_data["ids"][i:batch_end],
                "embeddings": (
                    all_data["embeddings"][i:batch_end] if all_data["embeddings"] else None
                ),
                "metadatas": (
                    all_data["metadatas"][i:batch_end] if all_data["metadatas"] else None
                ),
                "documents": (
                    all_data["documents"][i:batch_end] if all_data["documents"] else None
                ),
            }

            new_collection.add(**batch_data)

            migrated_count += len(batch_data["ids"])

            if progress:
                progress.update(len(batch_data["ids"]))
            else:
                print(f"   Migrated: {migrated_count:,} / {total_ids:,} vectors")

        if progress:
            progress.close()

    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print("   Attempting cleanup...")
        try:
            client.delete_collection(new_name)
            print("   ✅ Cleaned up partial migration")
        except Exception:
            print("   ⚠️  Could not cleanup partial migration")
        return False

    # Verify migration
    print(f"\n🔍 Verifying migration...")
    new_count = new_collection.count()

    print(f"\n{'=' * 60}")
    print(f"Migration Summary")
    print(f"{'=' * 60}")
    print(f"Source vectors:      {old_count:,}")
    print(f"Destination vectors: {new_count:,}")
    print(f"Status:              ", end="")

    if new_count == old_count:
        print("✅ SUCCESS")
    else:
        print("❌ MISMATCH!")
        print(f"\n❌ ERROR: Vector count mismatch!")
        print(f"   Expected: {old_count:,}, Got: {new_count:,}")
        print(f"   Difference: {abs(new_count - old_count):,}")
        return False

    # Handle old collection deletion
    print(f"\n🗑️  Old Collection Cleanup")
    print(f"{'=' * 60}")

    if auto_delete:
        print(f"Auto-delete enabled. Removing {old_name}...")
        try:
            client.delete_collection(old_name)
            print(f"✅ Old collection deleted: {old_name}")
        except Exception as e:
            print(f"⚠️  Could not delete old collection: {e}")
            print(f"   You can manually delete it later.")
    else:
        response = input(f"\nDelete old collection '{old_name}'? (yes/no): ")
        if response.lower() == "yes":
            try:
                client.delete_collection(old_name)
                print(f"✅ Old collection deleted: {old_name}")
            except Exception as e:
                print(f"❌ Failed to delete old collection: {e}")
        else:
            print(f"⚠️  Old collection kept for safety: {old_name}")
            print(f"   You can manually delete it after verifying the migration:")
            print(f"   >>> client.delete_collection('{old_name}')")

    print(f"\n{'=' * 60}")
    print("✅ Migration complete!")
    print(f"{'=' * 60}\n")

    return True


def main():
    """Main entry point with CLI argument parsing."""

    parser = argparse.ArgumentParser(
        description="Migrate ChromaDB collection from _v2 to new naming convention",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--old-name",
        default="tmws_memories_v2",
        help="Source collection name (default: tmws_memories_v2)",
    )

    parser.add_argument(
        "--new-name",
        default="tmws_memories",
        help="Destination collection name (default: tmws_memories)",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Number of vectors per batch (default: 1000)",
    )

    parser.add_argument(
        "--auto-delete",
        action="store_true",
        help="Automatically delete old collection after successful migration",
    )

    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be migrated without making changes"
    )

    args = parser.parse_args()

    # Run migration
    success = migrate_chroma_collection(
        old_name=args.old_name,
        new_name=args.new_name,
        batch_size=args.batch_size,
        auto_delete=args.auto_delete,
        dry_run=args.dry_run,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
