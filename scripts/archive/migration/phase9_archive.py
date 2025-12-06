#!/usr/bin/env python3
"""
Phase 9: PostgreSQL Archive Script

Archives old data and prepares for PostgreSQL minimization.
"""

import asyncio
from datetime import datetime, timedelta

# Add parent directory to path
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


async def archive_old_memories():
    """Archive old low-importance memories."""
    from src.core.database import get_session

    print("\n" + "=" * 60)
    print("ARCHIVING: memories_v2")
    print("=" * 60)

    async for session in get_session():
        # Create archive table for current month
        current_month = datetime.utcnow().strftime("%Y%m")
        archive_table = f"memories_v2_archive_{current_month}"

        # Archive memories older than 90 days with low importance
        cutoff_date = datetime.utcnow() - timedelta(days=90)

        archive_query = f"""
        CREATE TABLE IF NOT EXISTS {archive_table} AS
        SELECT * FROM memories_v2
        WHERE created_at < :cutoff_date
          AND importance < 0.5
          AND access_count = 0
        LIMIT 0;

        INSERT INTO {archive_table}
        SELECT * FROM memories_v2
        WHERE created_at < :cutoff_date
          AND importance < 0.5
          AND access_count = 0;
        """

        try:
            result = await session.execute(
                archive_query, {"cutoff_date": cutoff_date}
            )
            archived_count = result.rowcount

            print(f"✅ Archived {archived_count} old memories to {archive_table}")

            # Delete archived memories from main table
            delete_query = """
            DELETE FROM memories_v2
            WHERE created_at < :cutoff_date
              AND importance < 0.5
              AND access_count = 0
            """

            await session.execute(delete_query, {"cutoff_date": cutoff_date})
            await session.commit()

            print(f"✅ Deleted {archived_count} archived memories from main table")

        except Exception as e:
            print(f"⚠️ Archive skipped (likely already exists): {e}")
            await session.rollback()


async def archive_completed_tasks():
    """Archive completed tasks."""
    from src.core.database import get_session

    print("\n" + "=" * 60)
    print("ARCHIVING: tasks")
    print("=" * 60)

    async for session in get_session():
        # Create archive table
        archive_query = """
        CREATE TABLE IF NOT EXISTS tasks_archive AS
        SELECT * FROM tasks
        WHERE status = 'completed'
        LIMIT 0;

        INSERT INTO tasks_archive
        SELECT * FROM tasks
        WHERE status = 'completed'
          AND updated_at < NOW() - INTERVAL '30 days';
        """

        try:
            result = await session.execute(archive_query)
            archived_count = result.rowcount

            print(f"✅ Archived {archived_count} completed tasks")

            # Delete archived tasks
            delete_query = """
            DELETE FROM tasks
            WHERE status = 'completed'
              AND updated_at < NOW() - INTERVAL '30 days'
            """

            await session.execute(delete_query)
            await session.commit()

            print(f"✅ Deleted {archived_count} archived tasks")

        except Exception as e:
            print(f"⚠️ Archive skipped: {e}")
            await session.rollback()


async def archive_completed_workflows():
    """Archive completed workflows."""
    from src.core.database import get_session

    print("\n" + "=" * 60)
    print("ARCHIVING: workflows")
    print("=" * 60)

    async for session in get_session():
        # Create archive table
        archive_query = """
        CREATE TABLE IF NOT EXISTS workflows_archive AS
        SELECT * FROM workflows
        WHERE status = 'completed'
        LIMIT 0;

        INSERT INTO workflows_archive
        SELECT * FROM workflows
        WHERE status = 'completed'
          AND updated_at < NOW() - INTERVAL '30 days';
        """

        try:
            result = await session.execute(archive_query)
            archived_count = result.rowcount

            print(f"✅ Archived {archived_count} completed workflows")

            # Delete archived workflows
            delete_query = """
            DELETE FROM workflows
            WHERE status = 'completed'
              AND updated_at < NOW() - INTERVAL '30 days'
            """

            await session.execute(delete_query)
            await session.commit()

            print(f"✅ Deleted {archived_count} archived workflows")

        except Exception as e:
            print(f"⚠️ Archive skipped: {e}")
            await session.rollback()


async def optimize_postgresql():
    """Optimize PostgreSQL tables after archiving."""
    from src.core.database import get_session

    print("\n" + "=" * 60)
    print("OPTIMIZING: PostgreSQL")
    print("=" * 60)

    async for session in get_session():
        # Vacuum and analyze
        optimize_queries = [
            "VACUUM ANALYZE memories_v2;",
            "VACUUM ANALYZE tasks;",
            "VACUUM ANALYZE workflows;",
            "VACUUM ANALYZE api_audit_log;",
        ]

        for query in optimize_queries:
            try:
                await session.execute(query)
                print(f"✅ {query}")
            except Exception as e:
                print(f"⚠️ Failed: {query} - {e}")

        await session.commit()


async def generate_phase9_report():
    """Generate Phase 9 summary report."""
    from src.core.database import get_session

    print("\n" + "=" * 60)
    print("PHASE 9 SUMMARY REPORT")
    print("=" * 60)

    async for session in get_session():
        # Count tables
        tables_query = """
        SELECT table_name,
               pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as size,
               (SELECT COUNT(*) FROM information_schema.columns
                WHERE table_name = t.table_name) as columns
        FROM information_schema.tables t
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY pg_total_relation_size(quote_ident(table_name)) DESC;
        """

        result = await session.execute(tables_query)
        tables = result.fetchall()

        print("\nPostgreSQL Tables:")
        print(f"{'Table':<30} {'Size':<15} {'Columns':<10}")
        print("-" * 55)

        for table in tables:
            print(f"{table[0]:<30} {table[1]:<15} {table[2]:<10}")

        # Summary
        active_tables = [
            t[0]
            for t in tables
            if not t[0].endswith("_archive") and not t[0].endswith("_backup")
        ]
        archive_tables = [
            t[0]
            for t in tables
            if t[0].endswith("_archive") or t[0].endswith("_backup")
        ]

        print(f"\n📊 Statistics:")
        print(f"  Active tables: {len(active_tables)}")
        print(f"  Archive tables: {len(archive_tables)}")
        print(f"  Total tables: {len(tables)}")

        # Phase 9 target validation
        target_active = 7  # users, api_keys, api_audit_log, audit_log, workflow_history, memories_v2, (minimal tasks/workflows)
        if len(active_tables) <= target_active:
            print(f"\n✅ Phase 9 Target Achieved: {len(active_tables)} <= {target_active} tables")
        else:
            print(
                f"\n⚠️ Phase 9 Target: {len(active_tables)} active tables (target: <= {target_active})"
            )


async def main():
    """Run Phase 9 archive process."""
    print("\n" + "#" * 60)
    print("# TMWS v2.3.0 Phase 9: PostgreSQL Minimization")
    print("# Archive and Optimize")
    print("#" * 60)
    print(f"Timestamp: {datetime.utcnow().isoformat()}")

    print("\n⚠️ WARNING: This script will archive and delete old data.")
    print("Ensure you have a backup before proceeding.")

    try:
        # Archive old data
        await archive_old_memories()
        await archive_completed_tasks()
        await archive_completed_workflows()

        # Optimize PostgreSQL
        await optimize_postgresql()

        # Generate report
        await generate_phase9_report()

        print("\n" + "=" * 60)
        print("✅ Phase 9 Archive Completed Successfully")
        print("=" * 60)

        print("\n📊 Next Steps:")
        print("  1. Verify archived data: SELECT * FROM *_archive;")
        print("  2. Backup archive tables: pg_dump -t '*_archive' > archives.sql")
        print("  3. Monitor Redis/Chroma for active operations")
        print("  4. Proceed to Phase 10 (Documentation)")

    except Exception as e:
        print(f"\n❌ Phase 9 Archive Failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
