"""
P2 Integration Tests - Shared Fixtures and Configuration.

This module provides fixtures specific to P2 coverage expansion tests.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest


@pytest.fixture
def performance_thresholds():
    """Performance thresholds for various operations."""
    return {
        "api_response_p95": 200,  # ms
        "api_response_p99": 500,  # ms
        "memory_search_p95": 100,  # ms
        "memory_create_p95": 50,  # ms
        "skill_execution_p95": 1000,  # ms
        "batch_operation_p95": 5000,  # ms
        "concurrent_connections": 100,
        "requests_per_second": 50,
    }


@pytest.fixture
def rbac_roles():
    """RBAC role definitions."""
    return {
        "admin": {
            "permissions": ["*"],
            "description": "Full system access",
        },
        "editor": {
            "permissions": [
                "memory:create",
                "memory:read",
                "memory:update",
                "memory:delete",
                "skill:create",
                "skill:read",
                "skill:update",
                "skill:delete",
                "agent:read",
            ],
            "description": "Can manage memories and skills",
        },
        "viewer": {
            "permissions": [
                "memory:read",
                "skill:read",
                "agent:read",
            ],
            "description": "Read-only access",
        },
        "agent": {
            "permissions": [
                "memory:create",
                "memory:read",
                "memory:update",
                "skill:read",
                "skill:execute",
            ],
            "description": "Agent operational access",
        },
    }


@pytest.fixture
def observability_config():
    """Observability configuration."""
    return {
        "log_levels": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        "required_fields": ["timestamp", "level", "message", "service", "trace_id"],
        "metrics": [
            "request_duration_seconds",
            "request_total",
            "error_total",
            "active_connections",
            "memory_operations_total",
            "skill_executions_total",
        ],
        "trace_sampling_rate": 0.1,  # 10% sampling in production
    }


@pytest.fixture
def mock_metrics_collector():
    """Mock metrics collector for observability tests."""
    collector = Mock()
    collector.metrics = {}

    def record_metric(name: str, value: float, labels: dict = None):
        if name not in collector.metrics:
            collector.metrics[name] = []
        collector.metrics[name].append({
            "value": value,
            "labels": labels or {},
            "timestamp": datetime.now(timezone.utc),
        })

    collector.record = Mock(side_effect=record_metric)
    collector.get_metric = Mock(side_effect=lambda name: collector.metrics.get(name, []))

    return collector


@pytest.fixture
def mock_logger():
    """Mock logger for observability tests."""
    logger = Mock()
    logger.logs = []

    def log(level: str, message: str, **kwargs):
        logger.logs.append({
            "level": level,
            "message": message,
            "timestamp": datetime.now(timezone.utc),
            "extra": kwargs,
        })

    logger.debug = Mock(side_effect=lambda msg, **kw: log("DEBUG", msg, **kw))
    logger.info = Mock(side_effect=lambda msg, **kw: log("INFO", msg, **kw))
    logger.warning = Mock(side_effect=lambda msg, **kw: log("WARNING", msg, **kw))
    logger.error = Mock(side_effect=lambda msg, **kw: log("ERROR", msg, **kw))
    logger.critical = Mock(side_effect=lambda msg, **kw: log("CRITICAL", msg, **kw))

    return logger


@pytest.fixture
def mock_rbac_service():
    """Mock RBAC service for access control tests."""
    service = Mock()

    def check_permission(user_id: str, permission: str, resource_id: str = None):
        # Simulate permission check based on user role
        admin_users = ["admin-user"]
        editor_users = ["editor-user"]
        viewer_users = ["viewer-user"]

        if user_id in admin_users:
            return True
        elif user_id in editor_users:
            return permission.split(":")[1] in ["create", "read", "update", "delete"]
        elif user_id in viewer_users:
            return permission.split(":")[1] == "read"
        return False

    service.check_permission = Mock(side_effect=check_permission)
    service.get_user_role = Mock(return_value="viewer")

    return service
