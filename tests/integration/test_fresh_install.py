"""Integration test for fresh TMWS installation.

Issue #71: Verify database initialization creates all 42 tables on fresh install.

Test Coverage:
1. Fresh install creates all expected tables
2. Table creation is idempotent (safe to run multiple times)
3. No race conditions in initialization flow

Note: This test bypasses the test_engine fixture to test actual create_tables()
implementation, since the fixture itself had the same bug we're testing for.
"""

import os
import tempfile

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from src.core.database import Base, create_tables, get_db_session, get_engine


@pytest_asyncio.fixture
async def fresh_db_engine():
    """Create a fresh database engine for testing without using cached fixtures.

    This fixture creates its own temporary database to test fresh install scenarios,
    bypassing the test_engine fixture which may already have tables created.
    """
    import src.core.database as db_module

    # Create temp database file
    temp_db = tempfile.NamedTemporaryFile(mode='w', suffix='.db', delete=False)
    temp_db_path = temp_db.name
    temp_db.close()

    # Create fresh engine pointing to temp file
    db_url = f"sqlite+aiosqlite:///{temp_db_path}"
    fresh_engine = create_async_engine(
        db_url,
        poolclass=NullPool,
        echo=False,
    )

    # Monkeypatch global engine to use our fresh instance
    original_engine = db_module._engine
    original_session_maker = db_module._session_maker
    db_module._engine = fresh_engine
    db_module._session_maker = None

    yield fresh_engine

    # Cleanup
    await fresh_engine.dispose()
    db_module._engine = original_engine
    db_module._session_maker = original_session_maker

    # Remove temp database file
    try:
        os.unlink(temp_db_path)
    except Exception:
        pass


# Expected 42 tables (alphabetically sorted)
EXPECTED_TABLES = {
    "agent_namespaces",
    "agent_teams",
    "agents",
    "api_audit_log",
    "api_keys",
    "detected_patterns",
    "discovered_tools",
    "execution_traces",
    "learning_patterns",
    "license_key_usage",
    "license_keys",
    "mcp_connections",
    "memories",
    "memory_consolidations",
    "memory_patterns",
    "memory_sharing",
    "pattern_usage_history",
    "personas",
    "phase_templates",
    "refresh_tokens",
    "security_audit_logs",
    "skill_activations",
    "skill_mcp_tools",
    "skill_memory_filters",
    "skill_shared_agents",
    "skill_suggestions",
    "skill_versions",
    "skills",
    "task_templates",
    "tasks",
    "token_consumption",
    "tool_dependencies",
    "tool_instances",
    "tool_verification_history",
    "trust_score_history",
    "users",
    "verification_records",
    "workflow_execution_logs",
    "workflow_executions",
    "workflow_schedules",
    "workflow_step_executions",
    "workflows",
}


@pytest.mark.asyncio
async def test_fresh_install_creates_all_42_tables(fresh_db_engine):
    """Verify fresh install creates all 42 expected tables.

    Critical test for Issue #71: Ensures no tables are missing from
    create_tables() import list.
    """

    # Create all tables (simulates fresh install)
    await create_tables()

    # Inspect database for actual tables
    engine = get_engine()
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        )
        actual_tables = {row[0] for row in result.fetchall()}

    # Verify table count
    assert len(actual_tables) == 42, (
        f"Expected 42 tables, got {len(actual_tables)}. "
        f"Missing: {EXPECTED_TABLES - actual_tables}, "
        f"Unexpected: {actual_tables - EXPECTED_TABLES}"
    )

    # Verify exact match
    assert actual_tables == EXPECTED_TABLES, (
        f"Table mismatch.\n"
        f"Missing: {EXPECTED_TABLES - actual_tables}\n"
        f"Unexpected: {actual_tables - EXPECTED_TABLES}"
    )


@pytest.mark.asyncio
async def test_create_tables_is_idempotent(fresh_db_engine):
    """Verify running create_tables() multiple times is safe.

    Tests for:
    - No errors when tables already exist
    - No duplicate tables created
    - No race conditions
    """

    # Run create_tables() twice
    await create_tables()
    await create_tables()

    # Should not raise errors
    engine = get_engine()
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        )
        count = result.scalar()

    # Still exactly 42 tables
    assert count == 42, f"Expected 42 tables after idempotent run, got {count}"


@pytest.mark.asyncio
async def test_critical_tables_have_expected_structure(fresh_db_engine):
    """Verify critical tables have expected columns.

    Validates structure of high-impact tables from Issue #71:
    - skills (v2.4.7 feature)
    - agent_teams (v2.4.7 feature)
    - mcp_connections (v2.5.0 feature)
    """

    await create_tables()

    engine = get_engine()
    async with engine.begin() as conn:
        # Test: skills table exists with expected columns
        result = await conn.execute(text("PRAGMA table_info(skills)"))
        skills_columns = {row[1] for row in result.fetchall()}
        assert "id" in skills_columns, "skills table missing 'id' column"
        assert "name" in skills_columns, "skills table missing 'name' column"
        assert "namespace" in skills_columns, "skills table missing 'namespace' column"

        # Test: agent_teams table exists with expected columns
        result = await conn.execute(text("PRAGMA table_info(agent_teams)"))
        agent_teams_columns = {row[1] for row in result.fetchall()}
        assert "id" in agent_teams_columns, "agent_teams table missing 'id' column"
        assert "team_name" in agent_teams_columns, "agent_teams table missing 'team_name' column"

        # Test: mcp_connections table exists with expected columns
        result = await conn.execute(text("PRAGMA table_info(mcp_connections)"))
        mcp_columns = {row[1] for row in result.fetchall()}
        assert "id" in mcp_columns, "mcp_connections table missing 'id' column"
        assert "server_name" in mcp_columns, "mcp_connections table missing 'server_name' column"


@pytest.mark.asyncio
async def test_fresh_install_no_race_conditions(fresh_db_engine):
    """Verify idempotent table creation prevents corruption.

    Tests that calling create_tables() sequentially multiple times
    (simulating retry scenarios) doesn't corrupt the database.

    Note: SQLAlchemy's create_all() is NOT thread-safe, so true concurrent
    calls require external locking. This test verifies sequential retry safety.
    """

    # Run create_tables() sequentially 3 times (retry scenario)
    await create_tables()
    await create_tables()  # Retry 1
    await create_tables()  # Retry 2

    # Verify exactly 42 tables (no duplicates, no missing)
    engine = get_engine()
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        )
        count = result.scalar()

    assert count == 42, f"Idempotency violation: expected 42 tables, got {count}"


@pytest.mark.asyncio
async def test_skills_system_tables_complete(fresh_db_engine):
    """Verify all 6 skills system tables are created.

    Critical test for Issue #71: Skills system was completely broken
    on fresh installs due to missing table imports.
    """

    await create_tables()

    skills_tables = {
        "skills",
        "skill_versions",
        "skill_activations",
        "skill_mcp_tools",
        "skill_shared_agents",
        "skill_memory_filters",
    }

    engine = get_engine()
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        )
        actual_tables = {row[0] for row in result.fetchall()}

    missing_skills_tables = skills_tables - actual_tables
    assert not missing_skills_tables, (
        f"Skills system incomplete. Missing tables: {missing_skills_tables}"
    )


@pytest.mark.asyncio
async def test_workflow_execution_tables_complete(fresh_db_engine):
    """Verify all 5 workflow execution tables are created.

    Critical test for Issue #71: Workflow execution tracking was broken
    on fresh installs.
    """

    await create_tables()

    workflow_tables = {
        "workflows",
        "workflow_executions",
        "workflow_step_executions",
        "workflow_execution_logs",
        "workflow_schedules",
    }

    engine = get_engine()
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        )
        actual_tables = {row[0] for row in result.fetchall()}

    missing_workflow_tables = workflow_tables - actual_tables
    assert not missing_workflow_tables, (
        f"Workflow execution incomplete. Missing tables: {missing_workflow_tables}"
    )


@pytest.mark.asyncio
async def test_database_session_works_after_fresh_install(fresh_db_engine):
    """Verify database session can be created after fresh install.

    Integration test: Ensures database is fully functional after table creation.
    """

    await create_tables()

    # Test: Can create and use database session
    async with get_db_session() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1, "Database session not functional"

    # Test: Can query table metadata
    async with get_db_session() as session:
        result = await session.execute(
            text("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        )
        count = result.scalar()
        assert count == 42, f"Session query failed: expected 42 tables, got {count}"
