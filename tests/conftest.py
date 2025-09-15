"""
Comprehensive Test Configuration for TMWS Phase 1 Implementation.

This file provides shared fixtures, test database setup, and mock configurations
for the entire test suite. Organized by the Trinitas team for optimal coverage.

Team Responsibilities:
- Eris: Test structure and fixtures coordination
- Hestia: Security test fixtures and audit validation  
- Artemis: Performance test fixtures and service mocks
- Muses: Test documentation and reporting fixtures
- Athena: Overall test harmony and integration
- Hera: Strategic test validation and coverage requirements
"""

from dotenv import load_dotenv

load_dotenv() # Load .env file before anything else

import asyncio
import os
import pytest
import tempfile
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator, Dict, Any, List, Optional
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Import application components
from src.core.config import get_settings
from src.core.database import get_db_session, Base
from src.models.user import User, UserRole, UserStatus, APIKey, APIKeyScope, RefreshToken
from src.models.memory import Memory
from src.services.auth_service import AuthService, auth_service
from src.services.memory_service import MemoryService
from src.security.jwt_service import JWTService, jwt_service
from src.api.app import create_app


# Test Configuration Constants
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
TEST_SECRET_KEY = "test_secret_key_at_least_32_characters_long"
PERFORMANCE_TIMEOUT = 0.2  # 200ms requirement
SECURITY_TEST_ITERATIONS = 100


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine with proper configuration."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,  # Set to True for SQL debugging
        poolclass=StaticPool,
        connect_args={
            "check_same_thread": False,
        },
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine):
    """Create database session for tests."""
    async with AsyncSession(test_engine) as session:
        yield session


@pytest.fixture
async def test_app():
    """Create FastAPI test application."""
    # Override settings for testing
    os.environ.update({
        "TMWS_DATABASE_URL": TEST_DATABASE_URL,
        "TMWS_SECRET_KEY": TEST_SECRET_KEY,
        "TMWS_ENVIRONMENT": "test",
        "TMWS_AUTH_ENABLED": "true",
    })
    
    app = create_app()
    yield app


@pytest.fixture
async def async_client(test_app):
    """Create async HTTP client for API testing."""
    async with AsyncClient(app=test_app, base_url="http://test") as client:
        yield client


@pytest.fixture
def sync_client(test_app):
    """Create synchronous HTTP client for simple tests."""
    return TestClient(test_app)


# === SECURITY TEST FIXTURES (Hestia's Domain) ===

@pytest.fixture
async def test_user_data():
    """Test user data for authentication tests."""
    return {
        "username": "test_user",
        "email": "test@example.com",
        "password": "secure_password_123",
        "full_name": "Test User",
        "agent_namespace": "test_namespace"
    }


@pytest.fixture
async def test_user(db_session, test_user_data):
    """Create test user in database."""
    user = await auth_service.create_user(
        username=test_user_data["username"],
        email=test_user_data["email"],
        password=test_user_data["password"],
        full_name=test_user_data["full_name"],
        agent_namespace=test_user_data["agent_namespace"],
        roles=[UserRole.USER]
    )
    return user


@pytest.fixture
async def admin_user(db_session):
    """Create admin user for privilege testing."""
    return await auth_service.create_user(
        username="admin_user",
        email="admin@example.com", 
        password="admin_password_123",
        full_name="Admin User",
        roles=[UserRole.ADMIN, UserRole.USER]
    )


@pytest.fixture
async def locked_user(db_session):
    """Create locked user for security testing."""
    user = await auth_service.create_user(
        username="locked_user",
        email="locked@example.com",
        password="locked_password_123"
    )
    # Lock the account
    user.status = UserStatus.LOCKED
    user.failed_login_attempts = 5
    await db_session.commit()
    return user


@pytest.fixture
async def test_api_key(db_session, test_user):
    """Create test API key."""
    api_key, api_key_record = await auth_service.create_api_key(
        user_id=test_user.id,
        name="Test API Key",
        description="For testing purposes",
        scopes=[APIKeyScope.READ, APIKeyScope.WRITE],
        expires_days=30
    )
    return api_key, api_key_record


@pytest.fixture
async def expired_api_key(db_session, test_user):
    """Create expired API key for security testing."""
    api_key, api_key_record = await auth_service.create_api_key(
        user_id=test_user.id,
        name="Expired API Key",
        expires_days=-1  # Already expired
    )
    return api_key, api_key_record


# === PERFORMANCE TEST FIXTURES (Artemis's Domain) ===

@pytest.fixture
def performance_timer():
    """Timer fixture for performance testing."""
    class PerformanceTimer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = datetime.now()
        
        def stop(self):
            self.end_time = datetime.now()
            return self.elapsed_ms
        
        @property
        def elapsed_ms(self):
            if not (self.start_time and self.end_time):
                return 0
            return (self.end_time - self.start_time).total_seconds() * 1000
    
    return PerformanceTimer()


@pytest.fixture
async def memory_service():
    """Memory service instance for testing."""
    return MemoryService()


@pytest.fixture
async def large_dataset(db_session):
    """Create large dataset for performance testing.""" 
    memories = []
    for i in range(1000):
        memory = Memory(
            content=f"Test memory content {i}",
            embedding=[0.1] * 384,  # 384-dimensional vector
            importance=0.5,
            persona_id="test-persona",
            metadata={"test_id": i}
        )
        memories.append(memory)
    
    db_session.add_all(memories)
    await db_session.commit()
    return memories


# === MOCK DATA FIXTURES (Eris's Coordination) ===

@pytest.fixture
def mock_jwt_payload():
    """Mock JWT payload for testing."""
    return {
        "sub": str(uuid4()),
        "username": "test_user",
        "email": "test@example.com",
        "roles": ["user"],
        "agent_namespace": "test",
        "iat": datetime.now(timezone.utc).timestamp(),
        "exp": (datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp(),
        "jti": "test_jwt_id"
    }


@pytest.fixture
def security_test_vectors():
    """Security test vectors for vulnerability testing."""
    return {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--"
        ],
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ],
        "command_injection": [
            "; cat /etc/passwd",
            "| id",
            "&& whoami",
            "$(id)"
        ]
    }


@pytest.fixture
async def test_memory_data():
    """Test memory data for memory service testing."""
    return [
        {
            "content": "This is a test memory about authentication",
            "importance": 0.8,
            "tags": ["test", "auth"],
            "metadata": {"category": "security"}
        },
        {
            "content": "This is a test memory about performance",
            "importance": 0.9,
            "tags": ["test", "performance"],
            "metadata": {"category": "optimization"}
        },
        {
            "content": "This is a test memory about documentation",
            "importance": 0.7,
            "tags": ["test", "docs"],
            "metadata": {"category": "knowledge"}
        }
    ]


# === AUTHENTICATION HELPERS (Hestia & Artemis Collaboration) ===

@pytest.fixture
async def authenticated_client(async_client, test_user, test_user_data):
    """Create authenticated HTTP client."""
    # Login to get tokens
    login_response = await async_client.post("/auth/login", json={
        "username": test_user_data["username"],
        "password": test_user_data["password"]
    })
    
    assert login_response.status_code == 200
    tokens = login_response.json()
    
    # Set authorization header
    async_client.headers.update({
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    
    return async_client


@pytest.fixture
async def admin_authenticated_client(async_client, admin_user):
    """Create admin authenticated HTTP client."""
    login_response = await async_client.post("/auth/login", json={
        "username": "admin_user",
        "password": "admin_password_123"
    })
    
    assert login_response.status_code == 200
    tokens = login_response.json()
    
    async_client.headers.update({
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    
    return async_client


# === TEST DATA CLEANUP (Muses's Documentation) ===

@pytest.fixture(autouse=True)
async def cleanup_test_data(db_session):
    """Automatically cleanup test data after each test."""
    yield
    
    # Clean up any test data that might have been created
    await db_session.rollback()
    await db_session.close()


# === COVERAGE AND REPORTING (Muses & Hera Collaboration) ===

@pytest.fixture(scope="session")
def test_results_collector():
    """Collect test results for comprehensive reporting."""
    class TestResultsCollector:
        def __init__(self):
            self.results = {
                "security_tests": [],
                "performance_tests": [],
                "integration_tests": [],
                "unit_tests": []
            }
        
        def add_result(self, category: str, test_name: str, result: Dict[str, Any]):
            if category in self.results:
                self.results[category].append({
                    "test_name": test_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **result
                })
        
        def generate_report(self) -> Dict[str, Any]:
            total_tests = sum(len(tests) for tests in self.results.values())
            return {
                "total_tests": total_tests,
                "categories": self.results,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
    
    return TestResultsCollector()


# === ENVIRONMENT VALIDATION ===

@pytest.fixture(autouse=True, scope="session")
def validate_test_environment():
    """Validate test environment setup before running tests."""
    required_env_vars = [
        "TMWS_SECRET_KEY",
        "TMWS_ENVIRONMENT"
    ]
    
    for var in required_env_vars:
        if var not in os.environ:
            pytest.fail(f"Required environment variable {var} not set for testing")
    
    # Validate secret key length
    secret_key = os.environ.get("TMWS_SECRET_KEY", "")
    if len(secret_key) < 32:
        pytest.fail("TMWS_SECRET_KEY must be at least 32 characters long")


# === PYTEST CONFIGURATION ===

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "security: Security-related tests (Hestia)")
    config.addinivalue_line("markers", "performance: Performance tests (Artemis)")
    config.addinivalue_line("markers", "integration: Integration tests (Team)")
    config.addinivalue_line("markers", "unit: Unit tests (Artemis)")
    config.addinivalue_line("markers", "e2e: End-to-end tests (All)")
    config.addinivalue_line("markers", "slow: Slow tests that require special handling")


def pytest_collection_modifyitems(config, items):
    """Modify test collection for better organization."""
    for item in items:
        # Add markers based on test location
        if "test_security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        elif "test_performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        elif "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "test_unit" in item.nodeid:
            item.add_marker(pytest.mark.unit)
        elif "test_e2e" in item.nodeid:
            item.add_marker(pytest.mark.e2e)