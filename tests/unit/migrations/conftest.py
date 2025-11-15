"""
Fixtures for migration tests.

Author: Artemis (Technical Perfectionist)
Created: 2025-11-15
"""

import pytest
from alembic.config import Config
from sqlalchemy import create_engine


@pytest.fixture
def alembic_config(tmp_path):
    """Create Alembic configuration for testing."""
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
