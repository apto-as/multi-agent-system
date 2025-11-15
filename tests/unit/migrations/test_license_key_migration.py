"""
License Key Migration Test Suite

Tests for Alembic migration: 096325207c82_add_license_key_system

Test Coverage:
- Schema creation (license_keys, license_key_usage tables)
- Index creation (3 for license_keys, 2 for license_key_usage)
- Constraint validation (CHECK, UNIQUE, FK)
- Agents.tier column addition
- Upgrade/downgrade idempotency
- Data integrity across migrations
- Performance requirements (<10ms P95)

Phase: 2B - Database Migration
Author: Artemis (Technical Perfectionist)
Created: 2025-11-15
"""

import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from src.core.config import get_settings


@pytest.fixture
def alembic_config(tmp_path):
    """Create Alembic configuration for testing."""
    settings = get_settings()

    # Use temporary database for migration tests
    test_db = tmp_path / "test_migration.db"
    sync_db_url = f"sqlite:///{test_db}"

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", sync_db_url)

    return config, sync_db_url


@pytest.fixture
def db_engine(alembic_config):
    """Create database engine for testing."""
    _, sync_db_url = alembic_config
    engine = create_engine(sync_db_url)

    yield engine

    engine.dispose()


@pytest.mark.migration
class TestLicenseKeyMigration:
    """Test suite for license key system migration."""

    def test_upgrade_creates_license_keys_table(self, alembic_config, db_engine):
        """Test that upgrade creates license_keys table with correct schema."""
        config, _ = alembic_config

        # Run migration
        command.upgrade(config, "096325207c82")

        # Force new connection to see schema changes
        with db_engine.connect() as conn:
            inspector = inspect(conn)

            # Verify table exists
            assert "license_keys" in inspector.get_table_names()

            # Verify columns
            columns = {col["name"]: col for col in inspector.get_columns("license_keys")}
            expected_columns = [
                "id", "agent_id", "tier", "license_key_hash",
                "issued_at", "expires_at", "is_active",
                "revoked_at", "revoked_reason"
            ]

            for col in expected_columns:
                assert col in columns, f"Column {col} missing from license_keys"

            # Verify primary key
            pk = inspector.get_pk_constraint("license_keys")
            assert pk["constrained_columns"] == ["id"]

    def test_upgrade_creates_license_keys_indexes(self, alembic_config, db_engine):
        """Test that upgrade creates all required indexes for license_keys."""
        config, _ = alembic_config

        # Run migration
        command.upgrade(config, "096325207c82")

        # Verify indexes
        inspector = inspect(db_engine)
        indexes = {idx["name"]: idx for idx in inspector.get_indexes("license_keys")}

        expected_indexes = [
            "idx_license_keys_hash_lookup",
            "idx_license_keys_expiration",
            "idx_license_keys_agent"
        ]

        for idx in expected_indexes:
            assert idx in indexes, f"Index {idx} missing from license_keys"

    def test_upgrade_creates_license_key_usage_table(self, alembic_config, db_engine):
        """Test that upgrade creates license_key_usage table."""
        config, _ = alembic_config

        # Run migration
        command.upgrade(config, "096325207c82")

        # Verify table exists
        inspector = inspect(db_engine)
        assert "license_key_usage" in inspector.get_table_names()

        # Verify columns
        columns = {col["name"]: col for col in inspector.get_columns("license_key_usage")}
        expected_columns = [
            "id", "license_key_id", "used_at",
            "feature_accessed", "usage_metadata"
        ]

        for col in expected_columns:
            assert col in columns, f"Column {col} missing from license_key_usage"

    def test_upgrade_creates_license_key_usage_indexes(self, alembic_config, db_engine):
        """Test that upgrade creates indexes for license_key_usage."""
        config, _ = alembic_config

        # Run migration
        command.upgrade(config, "096325207c82")

        # Verify indexes
        inspector = inspect(db_engine)
        indexes = {idx["name"]: idx for idx in inspector.get_indexes("license_key_usage")}

        expected_indexes = [
            "idx_license_key_usage_time",
            "idx_license_key_usage_feature"
        ]

        for idx in expected_indexes:
            assert idx in indexes, f"Index {idx} missing from license_key_usage"

    def test_upgrade_adds_tier_column_to_agents(self, alembic_config, db_engine):
        """Test that upgrade adds tier column to agents table."""
        config, _ = alembic_config

        # Run migration
        command.upgrade(config, "096325207c82")

        # Verify tier column exists
        inspector = inspect(db_engine)
        columns = {col["name"]: col for col in inspector.get_columns("agents")}

        assert "tier" in columns, "tier column missing from agents table"
        assert columns["tier"]["default"] == "'FREE'", "tier default value incorrect"

    def test_upgrade_creates_agents_tier_index(self, alembic_config, db_engine):
        """Test that upgrade creates index on agents.tier."""
        config, _ = alembic_config

        # Run migration
        command.upgrade(config, "096325207c82")

        # Verify index
        inspector = inspect(db_engine)
        indexes = {idx["name"]: idx for idx in inspector.get_indexes("agents")}

        assert "ix_agents_tier" in indexes, "ix_agents_tier index missing"

    def test_check_constraint_expiration_after_issuance(self, alembic_config, db_engine):
        """Test that CHECK constraint validates expires_at > issued_at."""
        config, _ = alembic_config

        # Ensure base schema exists first
        command.upgrade(config, "43ffdc09701d")  # Base schema
        command.upgrade(config, "096325207c82")  # License key migration

        with Session(db_engine) as session:
            # Create test agent
            agent_id = str(uuid4())
            session.execute(text(f"""
                INSERT INTO agents (id, agent_id, display_name, namespace, status, health_score, tier)
                VALUES ('{agent_id}', 'test-agent', 'Test Agent', 'default', 'active', 1.0, 'FREE')
            """))
            session.commit()

            # Try to insert license with expires_at < issued_at (should fail)
            now = datetime.now(timezone.utc)
            past = now - timedelta(days=1)

            with pytest.raises(Exception) as exc_info:
                session.execute(text(f"""
                    INSERT INTO license_keys (id, agent_id, tier, license_key_hash, issued_at, expires_at, is_active)
                    VALUES (
                        '{uuid4()}', '{agent_id}', 'FREE', 'test_hash_123',
                        '{now.isoformat()}', '{past.isoformat()}', 1
                    )
                """))
                session.commit()

            assert "check_expiration_after_issuance" in str(exc_info.value).lower()

    def test_foreign_key_cascade_delete(self, alembic_config, db_engine):
        """Test that deleting agent cascades to license_keys and license_key_usage."""
        config, _ = alembic_config

        # Ensure base schema exists first
        command.upgrade(config, "43ffdc09701d")  # Base schema
        command.upgrade(config, "096325207c82")  # License key migration

        with Session(db_engine) as session:
            # Create test agent
            agent_id = str(uuid4())
            session.execute(text(f"""
                INSERT INTO agents (id, agent_id, display_name, namespace, status, health_score, tier)
                VALUES ('{agent_id}', 'test-agent', 'Test Agent', 'default', 'active', 1.0, 'PRO')
            """))

            # Create license key
            license_id = str(uuid4())
            session.execute(text(f"""
                INSERT INTO license_keys (id, agent_id, tier, license_key_hash, issued_at, is_active)
                VALUES (
                    '{license_id}', '{agent_id}', 'PRO', 'test_hash_456',
                    '{datetime.now(timezone.utc).isoformat()}', 1
                )
            """))

            # Create usage record
            session.execute(text(f"""
                INSERT INTO license_key_usage (id, license_key_id, used_at)
                VALUES (
                    '{uuid4()}', '{license_id}', '{datetime.now(timezone.utc).isoformat()}'
                )
            """))
            session.commit()

            # Verify records exist
            assert session.execute(text(f"SELECT COUNT(*) FROM license_keys WHERE agent_id = '{agent_id}'")).scalar() == 1
            assert session.execute(text(f"SELECT COUNT(*) FROM license_key_usage WHERE license_key_id = '{license_id}'")).scalar() == 1

            # Delete agent
            session.execute(text(f"DELETE FROM agents WHERE id = '{agent_id}'"))
            session.commit()

            # Verify cascade delete
            assert session.execute(text(f"SELECT COUNT(*) FROM license_keys WHERE agent_id = '{agent_id}'")).scalar() == 0
            assert session.execute(text(f"SELECT COUNT(*) FROM license_key_usage WHERE license_key_id = '{license_id}'")).scalar() == 0

    def test_downgrade_removes_all_changes(self, alembic_config, db_engine):
        """Test that downgrade removes all migration changes."""
        config, _ = alembic_config

        # Run upgrade
        command.upgrade(config, "096325207c82")

        # Verify tables exist
        inspector = inspect(db_engine)
        assert "license_keys" in inspector.get_table_names()
        assert "license_key_usage" in inspector.get_table_names()

        # Run downgrade
        command.downgrade(config, "ff4b1a18d2f0")

        # Verify tables removed
        inspector = inspect(db_engine)
        assert "license_keys" not in inspector.get_table_names()
        assert "license_key_usage" not in inspector.get_table_names()

        # Verify tier column removed from agents
        if "agents" in inspector.get_table_names():
            columns = {col["name"]: col for col in inspector.get_columns("agents")}
            assert "tier" not in columns

    def test_upgrade_downgrade_idempotency(self, alembic_config, db_engine):
        """Test that multiple upgrade/downgrade cycles work correctly."""
        config, _ = alembic_config

        # First cycle
        command.upgrade(config, "096325207c82")
        command.downgrade(config, "ff4b1a18d2f0")

        # Second cycle
        command.upgrade(config, "096325207c82")
        command.downgrade(config, "ff4b1a18d2f0")

        # Third cycle (final upgrade)
        command.upgrade(config, "096325207c82")

        # Verify final state
        inspector = inspect(db_engine)
        assert "license_keys" in inspector.get_table_names()
        assert "license_key_usage" in inspector.get_table_names()

    def test_migration_performance(self, alembic_config):
        """Test that migration completes within performance target (<10ms P95)."""
        config, _ = alembic_config

        # Run multiple migrations and measure time
        times = []

        for _ in range(20):
            start = time.perf_counter()
            command.upgrade(config, "096325207c82")
            duration = (time.perf_counter() - start) * 1000  # Convert to ms
            times.append(duration)

            # Downgrade for next iteration
            command.downgrade(config, "ff4b1a18d2f0")

        # Calculate P95
        times_sorted = sorted(times)
        p95_index = int(len(times_sorted) * 0.95)
        p95_time = times_sorted[p95_index]

        # Assert P95 < 10ms
        assert p95_time < 10.0, f"Migration P95 time {p95_time:.2f}ms exceeds 10ms target"

    def test_data_integrity_across_upgrade_downgrade(self, alembic_config, db_engine):
        """Test that data is preserved across upgrade/downgrade cycles (where applicable)."""
        config, _ = alembic_config

        # Create base schema
        command.upgrade(config, "43ffdc09701d")

        with Session(db_engine) as session:
            # Create test agent
            agent_id = str(uuid4())
            session.execute(text(f"""
                INSERT INTO agents (id, agent_id, display_name, namespace, status, health_score)
                VALUES ('{agent_id}', 'test-agent', 'Test Agent', 'default', 'active', 1.0)
            """))
            session.commit()

            # Verify agent exists
            count_before = session.execute(text(f"SELECT COUNT(*) FROM agents WHERE id = '{agent_id}'")).scalar()
            assert count_before == 1

        # Run upgrade
        command.upgrade(config, "096325207c82")

        with Session(db_engine) as session:
            # Verify agent still exists with tier
            result = session.execute(text(f"SELECT tier FROM agents WHERE id = '{agent_id}'")).fetchone()
            assert result is not None
            assert result[0] == "FREE"  # Default value

        # Run downgrade
        command.downgrade(config, "ff4b1a18d2f0")

        with Session(db_engine) as session:
            # Verify agent still exists (tier column removed)
            count_after = session.execute(text(f"SELECT COUNT(*) FROM agents WHERE id = '{agent_id}'")).scalar()
            assert count_after == 1


# Performance benchmarks
@pytest.mark.benchmark
@pytest.mark.migration
class TestLicenseKeyMigrationPerformance:
    """Performance benchmarks for license key migration."""

    def test_license_keys_insert_performance(self, alembic_config, db_engine):
        """Test that inserting license keys meets performance target."""
        config, _ = alembic_config

        # Ensure base schema exists first
        command.upgrade(config, "43ffdc09701d")  # Base schema
        command.upgrade(config, "096325207c82")  # License key migration

        with Session(db_engine) as session:
            # Create test agent
            agent_id = str(uuid4())
            session.execute(text(f"""
                INSERT INTO agents (id, agent_id, display_name, namespace, status, health_score, tier)
                VALUES ('{agent_id}', 'test-agent', 'Test Agent', 'default', 'active', 1.0, 'PRO')
            """))
            session.commit()

            # Measure insert performance
            times = []

            for _ in range(100):
                start = time.perf_counter()

                license_id = str(uuid4())
                session.execute(text(f"""
                    INSERT INTO license_keys (id, agent_id, tier, license_key_hash, issued_at, is_active)
                    VALUES (
                        '{license_id}', '{agent_id}', 'PRO', '{uuid4().hex}',
                        '{datetime.now(timezone.utc).isoformat()}', 1
                    )
                """))
                session.commit()

                duration = (time.perf_counter() - start) * 1000  # ms
                times.append(duration)

            # Calculate P95
            times_sorted = sorted(times)
            p95_index = int(len(times_sorted) * 0.95)
            p95_time = times_sorted[p95_index]

            # Assert P95 < 10ms
            assert p95_time < 10.0, f"Insert P95 time {p95_time:.2f}ms exceeds 10ms target"
