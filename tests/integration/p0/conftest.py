"""
P0 Integration Tests - Shared Fixtures and Configuration.

This module provides fixtures specific to P0 critical integration tests.
These tests are production deployment blockers.
"""

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
def production_environment(monkeypatch):
    """Set up production-like environment for validation tests.

    This fixture temporarily switches to production mode for testing
    production security validations.
    """
    original_env = os.environ.copy()

    # Set production environment
    monkeypatch.setenv("TMWS_ENVIRONMENT", "production")
    monkeypatch.setenv("TMWS_DATABASE_URL", "sqlite+aiosqlite:///test_prod.db")
    monkeypatch.setenv("TMWS_SECRET_KEY", "production_secret_key_32_characters_min!")
    monkeypatch.setenv("TMWS_AUTH_ENABLED", "true")
    monkeypatch.setenv("TMWS_CORS_ORIGINS", '["https://app.example.com"]')

    yield

    # Restore original environment - handled by monkeypatch


@pytest.fixture
def development_environment(monkeypatch):
    """Set up development environment for comparison tests."""
    monkeypatch.setenv("TMWS_ENVIRONMENT", "development")
    monkeypatch.setenv("TMWS_AUTH_ENABLED", "false")
    yield


@pytest.fixture
def isolated_cors_environment(monkeypatch):
    """Isolated environment for CORS testing."""
    # Clear any existing CORS settings
    monkeypatch.delenv("TMWS_CORS_ORIGINS", raising=False)
    yield monkeypatch


@pytest_asyncio.fixture
async def test_agent_for_memory(test_session: AsyncSession):
    """Create a test agent for memory operations."""
    from uuid import uuid4
    from src.models.agent import Agent

    agent = Agent(
        id=str(uuid4()),
        agent_id="p0-test-agent",
        display_name="P0 Test Agent",
        namespace="p0-test-namespace",
        status="active",
        health_score=1.0,
        role="editor",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def test_agent_different_namespace(test_session: AsyncSession):
    """Create a test agent in a different namespace for isolation tests."""
    from uuid import uuid4
    from src.models.agent import Agent

    agent = Agent(
        id=str(uuid4()),
        agent_id="p0-other-agent",
        display_name="P0 Other Agent",
        namespace="other-namespace",
        status="active",
        health_score=1.0,
        role="editor",
    )
    test_session.add(agent)
    await test_session.commit()
    await test_session.refresh(agent)
    return agent


@pytest.fixture
def mock_embedding_service():
    """Mock embedding service for memory tests without Ollama dependency."""
    import numpy as np

    mock_service = AsyncMock()
    mock_service.encode_document = AsyncMock(
        return_value=np.random.rand(1024).tolist()
    )
    mock_service.encode_query = AsyncMock(
        return_value=np.random.rand(1024).tolist()
    )
    mock_service.get_model_info = MagicMock(return_value={
        "model_name": "test-model",
        "dimension": 1024,
        "provider": "mock",
    })
    return mock_service


@pytest.fixture
def mock_chromadb_client():
    """Mock ChromaDB client for vector search tests."""
    mock_client = MagicMock()
    mock_collection = MagicMock()

    # Mock collection methods
    mock_collection.add = MagicMock()
    mock_collection.query = MagicMock(return_value={
        "ids": [["test-id-1", "test-id-2"]],
        "distances": [[0.1, 0.2]],
        "metadatas": [[{"content": "test1"}, {"content": "test2"}]],
    })
    mock_collection.delete = MagicMock()
    mock_collection.update = MagicMock()
    mock_collection.get = MagicMock(return_value={
        "ids": ["test-id-1"],
        "metadatas": [{"content": "test1"}],
    })

    mock_client.get_or_create_collection = MagicMock(return_value=mock_collection)
    mock_client.get_collection = MagicMock(return_value=mock_collection)

    return mock_client


@pytest.fixture
def jwt_attack_vectors():
    """Known JWT attack vectors for security testing."""
    return {
        "none_algorithm": {
            "header": {"alg": "none", "typ": "JWT"},
            "description": "Algorithm 'none' attack",
        },
        "hs256_weak_secret": {
            "secret": "weak",
            "description": "Weak secret key attack",
        },
        "expired_token": {
            "exp_offset": -3600,  # 1 hour in the past
            "description": "Expired token attack",
        },
        "future_iat": {
            "iat_offset": 3600,  # 1 hour in the future
            "description": "Future issued-at attack",
        },
        "missing_claims": {
            "omit_claims": ["sub", "iss", "aud"],
            "description": "Missing required claims",
        },
    }


@pytest.fixture
def cors_attack_vectors():
    """CORS attack vectors for security testing."""
    return [
        {"origin": "*", "description": "Wildcard origin"},
        {"origin": "https://evil.com", "description": "Malicious origin"},
        {"origin": "null", "description": "Null origin (sandboxed iframe)"},
        {"origin": "http://localhost:3000/", "description": "Trailing slash"},
        {"origin": "ftp://example.com", "description": "Invalid scheme"},
        {"origin": "", "description": "Empty origin"},
    ]


@pytest.fixture
def production_security_requirements():
    """Production security requirements checklist."""
    return {
        "auth_enabled": True,
        "rate_limit_enabled": True,
        "security_headers_enabled": True,
        "session_cookie_secure": True,
        "cors_configured": True,
        "secret_key_strong": True,
        "db_echo_disabled": True,
        "api_reload_disabled": True,
        "debug_logging_disabled": True,
    }
