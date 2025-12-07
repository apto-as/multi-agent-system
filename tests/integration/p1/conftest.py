"""
P1 Integration Tests - Shared Fixtures and Configuration.

This module provides fixtures specific to P1 high priority integration tests.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest
import pytest_asyncio


@pytest.fixture
def mock_skill():
    """Create a mock Skill object."""
    skill = Mock()
    skill.id = uuid4()
    skill.name = "test-skill"
    skill.description = "Test skill for testing"
    skill.category = "utility"
    skill.version = "1.0.0"
    skill.agent_id = "test-agent"
    skill.namespace = "test-namespace"
    skill.is_active = True
    skill.parameters = {"param1": "string"}
    skill.code = "def execute(): pass"
    skill.created_at = datetime.now(timezone.utc)
    skill.updated_at = datetime.now(timezone.utc)
    return skill


@pytest.fixture
def mock_skill_service():
    """Mock SkillService for testing."""
    service = AsyncMock()

    mock_skill = Mock()
    mock_skill.id = uuid4()
    mock_skill.name = "test-skill"
    mock_skill.is_active = True
    mock_skill.agent_id = "test-agent"

    service.create_skill = AsyncMock(return_value=mock_skill)
    service.get_skill = AsyncMock(return_value=mock_skill)
    service.list_skills = AsyncMock(return_value=[mock_skill])
    service.update_skill = AsyncMock(return_value=mock_skill)
    service.delete_skill = AsyncMock(return_value=True)
    service.activate_skill = AsyncMock(return_value=mock_skill)
    service.deactivate_skill = AsyncMock(return_value=mock_skill)
    service.share_skill = AsyncMock(return_value=mock_skill)

    return service


@pytest.fixture
def mock_agent():
    """Create a mock Agent object."""
    agent = Mock()
    agent.id = uuid4()
    agent.agent_id = "test-agent"
    agent.display_name = "Test Agent"
    agent.namespace = "test-namespace"
    agent.status = "active"
    agent.health_score = 1.0
    agent.role = "editor"
    agent.created_at = datetime.now(timezone.utc)
    return agent


@pytest.fixture
def mock_agent_service():
    """Mock AgentService for testing."""
    service = AsyncMock()

    mock_agent = Mock()
    mock_agent.id = uuid4()
    mock_agent.agent_id = "test-agent"
    mock_agent.status = "active"

    service.get_agent = AsyncMock(return_value=mock_agent)
    service.list_agents = AsyncMock(return_value=[mock_agent])
    service.update_agent = AsyncMock(return_value=mock_agent)

    return service


@pytest.fixture
def sql_injection_payloads():
    """Common SQL injection attack vectors for testing."""
    return [
        # Basic SQL injection
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' OR 1=1 --",
        "' UNION SELECT * FROM users --",
        # Blind SQL injection
        "' AND 1=1 --",
        "' AND 1=2 --",
        # Time-based blind injection
        "'; WAITFOR DELAY '0:0:5' --",
        "' OR SLEEP(5) --",
        # Encoded payloads
        "%27%20OR%20%271%27%3D%271",
        "&#39; OR &#39;1&#39;=&#39;1",
        # Comment-based injection
        "admin'/*",
        "*/OR/**/1=1/*",
        # Unicode bypass attempts
        "ʼ OR ʼ1ʼ=ʼ1",
        # Null byte injection
        "admin\x00' OR '1'='1",
    ]


@pytest.fixture
def xss_payloads():
    """Common XSS attack vectors for testing."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
        "'\"><script>alert('XSS')</script>",
        "<img src=\"javascript:alert('XSS')\">",
        "<div style=\"background:url('javascript:alert(1)')\">",
    ]


@pytest.fixture
def state_transition_matrix():
    """Valid state transitions for agents."""
    return {
        "pending": ["active", "failed"],
        "active": ["paused", "failed", "completed"],
        "paused": ["active", "failed", "completed"],
        "failed": ["pending", "active"],
        "completed": ["pending"],
    }
