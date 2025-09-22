#!/usr/bin/env python3
"""
TMWS Database Health Check Script v2.2.0

This script performs comprehensive health checks on the TMWS database
including connection, performance, and data integrity checks
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DatabaseHealthChecker:
    """Comprehensive database health checker for TMWS."""

    def __init__(self, database_url: str | None = None):
        """Initialize health checker."""
        self.database_url = database_url or os.getenv(
            'TMWS_DATABASE_URL',
            'postgresql://tmws_user:tmws_password@localhost:5432/tmws'
        )
        # Convert to async URL if needed
        if 'postgresql://' in self.database_url:
            self.async_database_url = self.database_url.replace(
                'postgresql://', 'postgresql+asyncpg://'
            )
        else:
            self.async_database_url = self.database_url

    async def check_connection(self) -> dict[str, Any]:
        """Check basic database connection."""
        result = {
            'status': 'unknown',
            'response_time_ms': None,
            'error': None
        }

        try:
            engine = create_async_engine(self.async_database_url)
            start_time = datetime.now()

            async with engine.begin() as conn:
                result_query = await conn.execute(text("SELECT 1"))
                response_time = (datetime.now() - start_time).total_seconds() * 1000

            await engine.dispose()

            result['status'] = 'connected'
            result['response_time_ms'] = round(response_time, 2)

        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)

        return result

    async def check_extensions(self) -> dict[str, Any]:
        """Check required PostgreSQL extensions."""
        required_extensions = ['vector', 'pgcrypto', 'pg_trgm', 'uuid-ossp']
        result = {
            'installed': [],
            'missing': [],
            'versions': {}
        }

        try:
            engine = create_async_engine(self.async_database_url)

            async with engine.begin() as conn:
                extensions = await conn.execute(
                    text("SELECT extname, extversion FROM pg_extension")
                )

                installed_ext = {row[0]: row[1] for row in extensions}

                for ext in required_extensions:
                    if ext in installed_ext:
                        result['installed'].append(ext)
                        result['versions'][ext] = installed_ext[ext]
                    else:
                        result['missing'].append(ext)

            await engine.dispose()

        except Exception as e:
            result['error'] = str(e)

        return result

    async def check_table_health(self) -> dict[str, Any]:
        """Check health of database tables."""
        result = {
            'tables': {},
            'total_size': '0 MB',
            'largest_table': None,
            'index_usage': {}
        }

        try:
            engine = create_async_engine(self.async_database_url)

            async with engine.begin() as conn:
                # Get table sizes
                table_sizes = await conn.execute(text("""
                    SELECT
                        schemaname,
                        tablename,
                        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total_size,
                        pg_total_relation_size(schemaname||'.'||tablename) AS size_bytes
                    FROM pg_tables
                    WHERE schemaname = 'public'
                    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                """))

                total_bytes = 0
                for row in table_sizes:
                    table_name = row[1]
                    result['tables'][table_name] = {
                        'size': row[2],
                        'size_bytes': row[3]
                    }
                    total_bytes += row[3]

                    if not result['largest_table']:
                        result['largest_table'] = f"{table_name} ({row[2]})"

                # Convert total size to human readable
                result['total_size'] = self._format_bytes(total_bytes)

                # Get row counts for main tables
                main_tables = ['tasks', 'memories', 'workflows', 'personas']
                for table in main_tables:
                    try:
                        count_result = await conn.execute(
                            text(f"SELECT COUNT(*) FROM {table}")
                        )
                        count = count_result.scalar()
                        if table in result['tables']:
                            result['tables'][table]['row_count'] = count
                    except:
                        pass

                # Check index usage
                index_usage = await conn.execute(text("""
                    SELECT
                        schemaname,
                        tablename,
                        indexname,
                        idx_scan,
                        idx_tup_read,
                        idx_tup_fetch
                    FROM pg_stat_user_indexes
                    WHERE idx_scan > 0
                    ORDER BY idx_scan DESC
                    LIMIT 10
                """))

                for row in index_usage:
                    result['index_usage'][row[2]] = {
                        'table': row[1],
                        'scans': row[3],
                        'rows_read': row[4],
                        'rows_fetched': row[5]
                    }

            await engine.dispose()

        except Exception as e:
            result['error'] = str(e)

        return result

    async def check_performance_metrics(self) -> dict[str, Any]:
        """Check database performance metrics."""
        result = {
            'cache_hit_ratio': 0,
            'connection_count': 0,
            'active_queries': 0,
            'slow_queries': [],
            'deadlocks': 0,
            'conflicts': 0
        }

        try:
            engine = create_async_engine(self.async_database_url)

            async with engine.begin() as conn:
                # Cache hit ratio
                cache_stats = await conn.execute(text("""
                    SELECT
                        sum(blks_hit) * 100.0 / NULLIF(sum(blks_hit) + sum(blks_read), 0) AS cache_hit_ratio
                    FROM pg_stat_database
                    WHERE datname = current_database()
                """))
                result['cache_hit_ratio'] = round(cache_stats.scalar() or 0, 2)

                # Connection count
                conn_count = await conn.execute(text("""
                    SELECT COUNT(*) FROM pg_stat_activity
                    WHERE datname = current_database()
                """))
                result['connection_count'] = conn_count.scalar()

                # Active queries
                active_queries = await conn.execute(text("""
                    SELECT COUNT(*) FROM pg_stat_activity
                    WHERE datname = current_database()
                    AND state = 'active'
                    AND query NOT LIKE '%pg_stat_activity%'
                """))
                result['active_queries'] = active_queries.scalar()

                # Slow queries (if pg_stat_statements is available)
                try:
                    slow_queries = await conn.execute(text("""
                        SELECT
                            query,
                            calls,
                            mean_exec_time,
                            total_exec_time
                        FROM pg_stat_statements
                        WHERE mean_exec_time > 100
                        ORDER BY mean_exec_time DESC
                        LIMIT 5
                    """))

                    for row in slow_queries:
                        result['slow_queries'].append({
                            'query': row[0][:100],  # Truncate for safety
                            'calls': row[1],
                            'mean_time_ms': round(row[2], 2),
                            'total_time_ms': round(row[3], 2)
                        })
                except:
                    # pg_stat_statements might not be available
                    pass

                # Deadlocks and conflicts
                db_stats = await conn.execute(text("""
                    SELECT
                        deadlocks,
                        conflicts
                    FROM pg_stat_database
                    WHERE datname = current_database()
                """))
                stats_row = db_stats.fetchone()
                if stats_row:
                    result['deadlocks'] = stats_row[0]
                    result['conflicts'] = stats_row[1]

            await engine.dispose()

        except Exception as e:
            result['error'] = str(e)

        return result

    async def check_vector_performance(self) -> dict[str, Any]:
        """Check pgvector performance and indexes."""
        result = {
            'vector_tables': [],
            'vector_indexes': [],
            'sample_search_time_ms': None,
            'vector_dimensions': {}
        }

        try:
            engine = create_async_engine(self.async_database_url)

            async with engine.begin() as conn:
                # Find tables with vector columns
                vector_cols = await conn.execute(text("""
                    SELECT
                        table_name,
                        column_name,
                        udt_name
                    FROM information_schema.columns
                    WHERE udt_name = 'vector'
                """))

                for row in vector_cols:
                    table_name = row[0]
                    column_name = row[1]
                    result['vector_tables'].append(f"{table_name}.{column_name}")

                    # Get vector dimensions
                    try:
                        dim_query = await conn.execute(
                            text(f"SELECT vector_dims({column_name}) FROM {table_name} LIMIT 1")
                        )
                        dim = dim_query.scalar()
                        if dim:
                            result['vector_dimensions'][f"{table_name}.{column_name}"] = dim
                    except:
                        pass

                # Find vector indexes
                vector_indexes = await conn.execute(text("""
                    SELECT
                        indexname,
                        tablename,
                        indexdef
                    FROM pg_indexes
                    WHERE indexdef LIKE '%vector%'
                """))

                for row in vector_indexes:
                    result['vector_indexes'].append({
                        'name': row[0],
                        'table': row[1],
                        'type': 'ivfflat' if 'ivfflat' in row[2] else 'hnsw' if 'hnsw' in row[2] else 'other'
                    })

                # Test vector search performance
                if 'memories' in [t.split('.')[0] for t in result['vector_tables']]:
                    # Generate random vector for testing
                    dim = result['vector_dimensions'].get('memories.embedding', 384)
                    test_vector = np.random.randn(dim).tolist()
                    vector_str = '[' + ','.join(map(str, test_vector)) + ']'

                    start_time = datetime.now()
                    search_result = await conn.execute(text(f"""
                        SELECT id FROM memories
                        ORDER BY embedding <=> '{vector_str}'::vector
                        LIMIT 10
                    """))
                    search_time = (datetime.now() - start_time).total_seconds() * 1000
                    result['sample_search_time_ms'] = round(search_time, 2)

            await engine.dispose()

        except Exception as e:
            result['error'] = str(e)

        return result

    async def check_data_integrity(self) -> dict[str, Any]:
        """Check data integrity and consistency."""
        result = {
            'orphaned_records': {},
            'invalid_foreign_keys': [],
            'duplicate_keys': [],
            'null_violations': []
        }

        try:
            engine = create_async_engine(self.async_database_url)

            async with engine.begin() as conn:
                # Check for orphaned task dependencies
                try:
                    orphaned_deps = await conn.execute(text("""
                        SELECT COUNT(*) FROM task_dependencies td
                        WHERE NOT EXISTS (
                            SELECT 1 FROM tasks t WHERE t.id = td.task_id
                        ) OR NOT EXISTS (
                            SELECT 1 FROM tasks t WHERE t.id = td.depends_on_id
                        )
                    """))
                    count = orphaned_deps.scalar()
                    if count > 0:
                        result['orphaned_records']['task_dependencies'] = count
                except:
                    pass

                # Check for invalid foreign keys
                fk_check = await conn.execute(text("""
                    SELECT
                        conname AS constraint_name,
                        conrelid::regclass AS table_name
                    FROM pg_constraint
                    WHERE contype = 'f'
                    AND NOT convalidated
                """))

                for row in fk_check:
                    result['invalid_foreign_keys'].append({
                        'constraint': row[0],
                        'table': row[1]
                    })

            await engine.dispose()

        except Exception as e:
            result['error'] = str(e)

        return result

    async def run_full_health_check(self) -> dict[str, Any]:
        """Run comprehensive health check."""
        logger.info("Starting comprehensive database health check...")

        results = {
            'timestamp': datetime.now().isoformat(),
            'database_url': self.database_url.split('@')[-1] if '@' in self.database_url else 'unknown',
            'checks': {}
        }

        # Run all checks
        checks = [
            ('connection', self.check_connection()),
            ('extensions', self.check_extensions()),
            ('table_health', self.check_table_health()),
            ('performance', self.check_performance_metrics()),
            ('vector_performance', self.check_vector_performance()),
            ('data_integrity', self.check_data_integrity())
        ]

        for name, check_coro in checks:
            logger.info(f"Running {name} check...")
            try:
                results['checks'][name] = await check_coro
            except Exception as e:
                results['checks'][name] = {'error': str(e)}

        # Calculate overall health score
        results['health_score'] = self._calculate_health_score(results['checks'])
        results['status'] = self._determine_status(results['health_score'])

        return results

    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"

    def _calculate_health_score(self, checks: dict[str, Any]) -> int:
        """Calculate overall health score (0-100)."""
        score = 100

        # Connection check
        if checks.get('connection', {}).get('status') != 'connected':
            score -= 50  # Critical issue

        # Extensions check
        missing_ext = len(checks.get('extensions', {}).get('missing', []))
        score -= missing_ext * 10

        # Performance checks
        perf = checks.get('performance', {})
        if perf.get('cache_hit_ratio', 0) < 90:
            score -= 10
        if perf.get('deadlocks', 0) > 0:
            score -= 15
        if len(perf.get('slow_queries', [])) > 3:
            score -= 10

        # Vector performance
        vector_perf = checks.get('vector_performance', {})
        if vector_perf.get('sample_search_time_ms', 0) > 100:
            score -= 10

        # Data integrity
        integrity = checks.get('data_integrity', {})
        if integrity.get('orphaned_records'):
            score -= 10
        if integrity.get('invalid_foreign_keys'):
            score -= 15

        return max(0, score)

    def _determine_status(self, health_score: int) -> str:
        """Determine status based on health score."""
        if health_score >= 90:
            return 'healthy'
        elif health_score >= 70:
            return 'warning'
        elif health_score >= 50:
            return 'degraded'
        else:
            return 'critical'


def print_health_report(results: dict[str, Any]):
    """Print formatted health report."""
    print("\n" + "=" * 60)
    print("   TMWS Database Health Report")
    print("=" * 60)
    print(f"Timestamp: {results['timestamp']}")
    print(f"Database: {results['database_url']}")
    print(f"Overall Status: {results['status'].upper()}")
    print(f"Health Score: {results['health_score']}/100")
    print("=" * 60)

    # Connection status
    conn = results['checks'].get('connection', {})
    print(f"\n📡 Connection Status: {conn.get('status', 'unknown').upper()}")
    if conn.get('response_time_ms'):
        print(f"   Response Time: {conn['response_time_ms']}ms")

    # Extensions
    ext = results['checks'].get('extensions', {})
    print("\n🔧 Extensions:")
    print(f"   Installed: {', '.join(ext.get('installed', []))}")
    if ext.get('missing'):
        print(f"   ⚠️  Missing: {', '.join(ext['missing'])}")

    # Table health
    tables = results['checks'].get('table_health', {})
    print(f"\n📊 Database Size: {tables.get('total_size', 'unknown')}")
    if tables.get('largest_table'):
        print(f"   Largest Table: {tables['largest_table']}")

    # Performance
    perf = results['checks'].get('performance', {})
    print("\n⚡ Performance Metrics:")
    print(f"   Cache Hit Ratio: {perf.get('cache_hit_ratio', 0)}%")
    print(f"   Active Connections: {perf.get('connection_count', 0)}")
    print(f"   Active Queries: {perf.get('active_queries', 0)}")
    if perf.get('deadlocks', 0) > 0:
        print(f"   ⚠️  Deadlocks: {perf['deadlocks']}")

    # Vector performance
    vector = results['checks'].get('vector_performance', {})
    if vector.get('vector_tables'):
        print("\n🔍 Vector Search:")
        print(f"   Vector Tables: {len(vector['vector_tables'])}")
        print(f"   Vector Indexes: {len(vector.get('vector_indexes', []))}")
        if vector.get('sample_search_time_ms'):
            print(f"   Sample Search Time: {vector['sample_search_time_ms']}ms")

    # Data integrity
    integrity = results['checks'].get('data_integrity', {})
    if integrity.get('orphaned_records') or integrity.get('invalid_foreign_keys'):
        print("\n⚠️  Data Integrity Issues:")
        if integrity.get('orphaned_records'):
            for table, count in integrity['orphaned_records'].items():
                print(f"   Orphaned records in {table}: {count}")

    print("\n" + "=" * 60)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='TMWS Database Health Check'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )

    parser.add_argument(
        '--database-url',
        help='Database URL (overrides environment variable)'
    )

    args = parser.parse_args()

    # Create health checker
    checker = DatabaseHealthChecker(database_url=args.database_url)

    # Run health check
    results = await checker.run_full_health_check()

    # Output results
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print_health_report(results)

    # Exit with appropriate code
    if results['status'] == 'healthy':
        sys.exit(0)
    elif results['status'] == 'warning':
        sys.exit(0)  # Still OK but with warnings
    else:
        sys.exit(1)  # Degraded or critical


if __name__ == '__main__':
    asyncio.run(main())
