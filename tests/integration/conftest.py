"""
Integration test fixtures for TMWS v2.3.1.

This module imports and exposes fixtures from unit/security/conftest.py
for use in integration tests.
"""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

# Import all security fixtures for reuse in integration tests
from tests.unit.security.conftest import (
    mock_jwt_service,
    mock_rate_limiter,
    pwd_context,
    sample_admin_context,
    sample_mcp_auth_context,
    test_agent,
    test_agent_admin,
    test_agent_different_namespace,
    test_agent_suspended,
    test_api_key_for_agent,
    test_expired_api_key,
)

# Import for dependency override
from src.api.dependencies import User

# Import app and memory service dependency for override
from src.api.main import app  # noqa: E402
from src.api.routers.memory import get_memory_service  # noqa: E402


@pytest.fixture
def mock_user():
    """Create mock user for bypassing authentication in tests.

    Returns:
        User object with test agent credentials
    """
    return User(
        agent_id="test-agent-id",
        namespace="test-namespace",
        roles=["user", "admin"],
    )


@pytest.fixture
def auth_headers():
    """Create authorization headers for API requests.

    Returns:
        dict: Headers with mock Bearer token for authenticated requests

    Note:
        For rate limiting tests, we don't need real JWT validation.
        The mock authentication in test environment will accept any token.
    """
    # Use a mock token - test environment has auth disabled
    return {"Authorization": "Bearer mock-test-token"}


@pytest.fixture
def mock_hybrid_memory_service():
    """Mock HybridMemoryService for API testing.

    This fixture creates a mock service for FastAPI dependency override.
    NOTE: Must be used with async_client fixture which will apply the override.

    Returns:
        AsyncMock: Mocked memory service with cleanup, prune, and TTL methods
    """
    service_mock = AsyncMock()

    # Mock cleanup_namespace method
    service_mock.cleanup_namespace = AsyncMock(
        return_value={
            "deleted_count": 5,
            "dry_run": False,
            "namespace": "test-namespace",
            "criteria": {"days": 90, "min_importance": 0.3},
        },
    )

    # Mock prune_expired_memories method
    service_mock.prune_expired_memories = AsyncMock(
        return_value={
            "deleted_count": 3,
            "dry_run": False,
            "namespace": "test-namespace",
            "expired_count": 3,
        },
    )

    # Mock set_memory_ttl method - uses side_effect to return dynamic memory_id
    async def mock_set_ttl(memory_id, agent_id, ttl_days):
        return {
            "success": True,
            "memory_id": str(memory_id),  # Return the provided memory_id
            "expires_at": "2025-01-10T00:00:00Z",
            "ttl_days": ttl_days,
            "previous_ttl_days": None,
        }

    service_mock.set_memory_ttl = AsyncMock(side_effect=mock_set_ttl)

    return service_mock


@pytest_asyncio.fixture
async def async_client_with_mocked_memory(async_client, mock_hybrid_memory_service):
    """Async client with mocked memory service for rate limiting tests.

    This fixture combines the standard async_client with a mocked HybridMemoryService,
    bypassing Ollama dependency for integration tests.

    Args:
        async_client: Standard async HTTP client (from conftest.py)
        mock_hybrid_memory_service: Mocked memory service (from this file)

    Returns:
        AsyncClient with memory service override applied

    Note:
        This fixture automatically applies the get_memory_service override
        so tests don't need Ollama running.
    """
    # Apply memory service override
    app.dependency_overrides[get_memory_service] = lambda: mock_hybrid_memory_service

    yield async_client

    # Clean up memory service override (keep other overrides)
    if get_memory_service in app.dependency_overrides:
        del app.dependency_overrides[get_memory_service]


__all__ = [
    "test_agent",
    "test_agent_different_namespace",
    "test_agent_admin",
    "test_agent_suspended",
    "test_api_key_for_agent",
    "test_expired_api_key",
    "pwd_context",
    "mock_jwt_service",
    "sample_mcp_auth_context",
    "sample_admin_context",
    "mock_rate_limiter",
    "auth_headers",
    "mock_hybrid_memory_service",
]
