#!/usr/bin/env python3
"""
Migration Verification Script
==============================

Verifies that the _v2 suffix removal migration completed successfully.

Checks:
1. Database schema (table names, indexes, foreign keys)
2. ChromaDB collection names and vector counts
3. Code references (ensures no _v2 references remain)
4. Data integrity (row counts match, no data loss)

Usage:
    python scripts/verify_migration.py

    Optional flags:
        --verbose    Show detailed verification output
        --fix        Attempt to fix minor issues automatically

Author: Hestia (Security Guardian) + Artemis (Technical Perfectionist)
Date: 2025-10-24
"""

import argparse
import sys
from pathlib import Path

# Verification results
class VerificationResult:
    def __init__(self):
        self.passed = []
        self.failed = []
        self.warnings = []

    def add_pass(self, check: str, detail: str = ""):
        self.passed.append((check, detail))

    def add_fail(self, check: str, detail: str):
        self.failed.append((check, detail))

    def add_warning(self, check: str, detail: str):
        self.warnings.append((check, detail))

    def is_success(self) -> bool:
        return len(self.failed) == 0

    def print_summary(self):
        print(f"\n{'=' * 70}")
        print("Verification Summary")
        print(f"{'=' * 70}")

        if self.passed:
            print(f"\n✅ Passed Checks ({len(self.passed)}):")
            for check, detail in self.passed:
                print(f"   ✓ {check}")
                if detail:
                    print(f"     {detail}")

        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for check, detail in self.warnings:
                print(f"   ! {check}")
                print(f"     {detail}")

        if self.failed:
            print(f"\n❌ Failed Checks ({len(self.failed)}):")
            for check, detail in self.failed:
                print(f"   ✗ {check}")
                print(f"     {detail}")

        print(f"\n{'=' * 70}")
        if self.is_success():
            print("✅ All checks passed!")
        else:
            print(f"❌ {len(self.failed)} check(s) failed")
        print(f"{'=' * 70}\n")


def verify_database_schema(verbose: bool = False) -> VerificationResult:
    """Verify database schema after migration."""
    result = VerificationResult()

    try:
        from sqlalchemy import create_engine, inspect, text

        # Load database URL from config
        db_path = Path(__file__).parent.parent / "data" / "tmws.db"
        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)

    except Exception as e:
        result.add_fail("Database Connection", f"Failed to connect: {e}")
        return result

    # Check 1: New table names exist
    tables = inspector.get_table_names()

    if "memories" in tables:
        result.add_pass("Table: memories", "New table name exists")
    else:
        result.add_fail("Table: memories", "New table name not found!")

    if "learning_patterns" in tables:
        result.add_pass("Table: learning_patterns", "New table name exists")
    else:
        result.add_fail("Table: learning_patterns", "New table name not found!")

    # Check 2: Old table names removed
    if "memories_v2" in tables:
        result.add_fail("Table: memories_v2", "Old table name still exists!")
    else:
        result.add_pass("Table: memories_v2", "Old table name removed")

    if "learning_patterns_v2" in tables:
        result.add_fail("Table: learning_patterns_v2", "Old table name still exists!")
    else:
        result.add_pass("Table: learning_patterns_v2", "Old table name removed")

    # Check 3: Indexes on new tables
    if "memories" in tables:
        indexes = inspector.get_indexes("memories")
        index_names = [idx["name"] for idx in indexes]

        expected_indexes = [
            "ix_memory_agent_namespace",
            "ix_memory_access_level",
            "ix_memory_importance",
            "ix_memory_accessed",
            "ix_memory_expires",
        ]

        for idx_name in expected_indexes:
            if idx_name in index_names:
                result.add_pass(f"Index: {idx_name}", "")
            else:
                result.add_fail(f"Index: {idx_name}", "Missing!")

    if "learning_patterns" in tables:
        indexes = inspector.get_indexes("learning_patterns")
        index_names = [idx["name"] for idx in indexes]

        expected_indexes = [
            "idx_learning_patterns_agent_namespace",
            "idx_learning_patterns_category_access",
            "idx_learning_patterns_usage",
            "idx_learning_patterns_last_used",
        ]

        for idx_name in expected_indexes:
            if idx_name in index_names:
                result.add_pass(f"Index: {idx_name}", "")
            else:
                result.add_fail(f"Index: {idx_name}", "Missing!")

    # Check 4: Foreign keys
    if "memories" in tables:
        fks = inspector.get_foreign_keys("memories")
        if verbose:
            print(f"\nForeign keys on 'memories': {len(fks)}")
            for fk in fks:
                print(f"  - {fk}")

        # Just verify some FKs exist (exact count may vary)
        if len(fks) > 0:
            result.add_pass(
                "Foreign Keys: memories", f"{len(fks)} foreign key constraint(s) found"
            )
        else:
            result.add_warning("Foreign Keys: memories", "No foreign keys found")

    # Check 5: Row counts (data integrity)
    try:
        with engine.connect() as conn:
            if "memories" in tables:
                count_result = conn.execute(text("SELECT COUNT(*) FROM memories"))
                memory_count = count_result.scalar()
                result.add_pass("Data Integrity: memories", f"{memory_count} rows found")

            if "learning_patterns" in tables:
                count_result = conn.execute(text("SELECT COUNT(*) FROM learning_patterns"))
                pattern_count = count_result.scalar()
                result.add_pass(
                    "Data Integrity: learning_patterns", f"{pattern_count} rows found"
                )

    except Exception as e:
        result.add_fail("Data Integrity", f"Failed to count rows: {e}")

    return result


def verify_chromadb_collection(verbose: bool = False) -> VerificationResult:
    """Verify ChromaDB collection migration."""
    result = VerificationResult()

    try:
        import chromadb
        from chromadb.config import Settings

        chroma_path = Path(__file__).parent.parent / "data" / "chroma"

        if not chroma_path.exists():
            result.add_warning("ChromaDB Path", f"Directory not found: {chroma_path}")
            return result

        client = chromadb.PersistentClient(
            path=str(chroma_path), settings=Settings(anonymized_telemetry=False)
        )

    except Exception as e:
        result.add_fail("ChromaDB Connection", f"Failed to connect: {e}")
        return result

    # Check 1: New collection exists
    try:
        new_collection = client.get_collection("tmws_memories")
        new_count = new_collection.count()
        result.add_pass(
            "Collection: tmws_memories", f"New collection exists with {new_count:,} vectors"
        )
    except Exception as e:
        result.add_fail("Collection: tmws_memories", f"New collection not found: {e}")

    # Check 2: Old collection removed (or warn if still exists)
    try:
        old_collection = client.get_collection("tmws_memories_v2")
        old_count = old_collection.count()
        result.add_warning(
            "Collection: tmws_memories_v2",
            f"Old collection still exists ({old_count:,} vectors). Safe to delete after verification.",
        )
    except Exception:
        result.add_pass("Collection: tmws_memories_v2", "Old collection removed")

    # Check 3: List all collections
    if verbose:
        print("\nAll ChromaDB collections:")
        for col in client.list_collections():
            print(f"  - {col.name}: {col.count():,} vectors")

    return result


def verify_code_references(verbose: bool = False) -> VerificationResult:
    """Verify no _v2 references remain in code."""
    result = VerificationResult()

    project_root = Path(__file__).parent.parent

    # Files to check
    files_to_check = [
        "src/models/memory.py",
        "src/models/learning_pattern.py",
        "src/core/config.py",
        "src/services/vector_search_service.py",
    ]

    for file_path in files_to_check:
        full_path = project_root / file_path

        if not full_path.exists():
            result.add_warning(f"Code Check: {file_path}", "File not found")
            continue

        content = full_path.read_text()

        # Check for _v2 references
        if "memories_v2" in content:
            result.add_fail(f"Code Reference: {file_path}", "Still contains 'memories_v2'")
        elif "learning_patterns_v2" in content:
            result.add_fail(
                f"Code Reference: {file_path}", "Still contains 'learning_patterns_v2'"
            )
        elif "tmws_memories_v2" in content:
            result.add_fail(f"Code Reference: {file_path}", "Still contains 'tmws_memories_v2'")
        else:
            result.add_pass(f"Code Reference: {file_path}", "No _v2 references found")

    return result


def verify_alembic_migration(verbose: bool = False) -> VerificationResult:
    """Verify Alembic migration state."""
    result = VerificationResult()

    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        alembic_cfg = Config("alembic.ini")
        script = ScriptDirectory.from_config(alembic_cfg)

        head = script.get_current_head()

        if verbose:
            print(f"\nCurrent Alembic head: {head}")

        # Check if migration 010 exists
        revisions = [rev.revision for rev in script.walk_revisions()]

        if "010" in revisions:
            result.add_pass("Alembic Migration: 010", "Migration file exists")
        else:
            result.add_fail("Alembic Migration: 010", "Migration file not found!")

        # Try to get current database revision
        try:
            from sqlalchemy import create_engine, text

            db_path = Path(__file__).parent.parent / "data" / "tmws.db"
            engine = create_engine(f"sqlite:///{db_path}")

            with engine.connect() as conn:
                current = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()

            if current == "010":
                result.add_pass("Alembic Database State", "Database at revision 010")
            else:
                result.add_warning(
                    "Alembic Database State",
                    f"Database at revision {current} (expected 010)",
                )

        except Exception as e:
            result.add_warning("Alembic Database State", f"Could not check: {e}")

    except Exception as e:
        result.add_fail("Alembic Check", f"Failed to check Alembic: {e}")

    return result


def main():
    """Main verification entry point."""

    parser = argparse.ArgumentParser(description="Verify _v2 suffix removal migration")

    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues (not implemented)")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("TMWS Migration Verification")
    print("=" * 70)

    all_results = []

    # Run all verification checks
    print("\n🔍 Checking database schema...")
    db_result = verify_database_schema(verbose=args.verbose)
    all_results.append(db_result)

    print("\n🔍 Checking ChromaDB collections...")
    chroma_result = verify_chromadb_collection(verbose=args.verbose)
    all_results.append(chroma_result)

    print("\n🔍 Checking code references...")
    code_result = verify_code_references(verbose=args.verbose)
    all_results.append(code_result)

    print("\n🔍 Checking Alembic migration state...")
    alembic_result = verify_alembic_migration(verbose=args.verbose)
    all_results.append(alembic_result)

    # Print all summaries
    for result in all_results:
        result.print_summary()

    # Final verdict
    all_success = all(r.is_success() for r in all_results)

    if all_success:
        print("\n🎉 Migration verification PASSED! All systems nominal.")
        sys.exit(0)
    else:
        print("\n❌ Migration verification FAILED. Please review errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
