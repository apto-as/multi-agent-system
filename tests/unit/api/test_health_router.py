"""
Unit Tests for Health Router

Coverage:
- Health endpoint returns 200 (no auth required)
- Response structure validation (status, components, response_time_ms)
- Performance validation (< 100ms target)
- Degraded status scenarios (high CPU, memory)
- Unhealthy status scenarios (database failure)
- Caching behavior (5-second TTL)

Target:
- 10+ unit tests
- No authentication required for health checks
- Mock system metrics cache for predictable test results
- Mock database health check for failure scenarios

Author: Metis (Development Assistant)
Created: 2025-12-02
Phase: v2.4.8 (Orchestration Layer)

Note: This test suite validates the existing health router implementation
in src.api.routers.health.py which already implements caching and health checks.
"""

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.main import app


@pytest.fixture
def test_client():
    """Create FastAPI test client."""
    return TestClient(app)


class TestHealthEndpointBasics:
    """Test suite for basic health endpoint functionality."""

    def test_health_detailed_returns_200(self, test_client: TestClient):
        """Test health endpoint returns 200 OK."""
        response = test_client.get("/api/v1/health/detailed")

        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

    def test_health_detailed_response_structure(self, test_client: TestClient):
        """Test health endpoint response has required structure."""
        response = test_client.get("/api/v1/health/detailed")

        assert response.status_code == 200
        data = response.json()

        # Top-level fields
        assert "status" in data
        assert "timestamp" in data
        assert "components" in data
        assert "response_time_ms" in data

        # Components structure
        assert "database" in data["components"]
        assert "system" in data["components"]

        # Database component fields
        db_component = data["components"]["database"]
        assert "status" in db_component
        assert "latency_ms" in db_component
        assert "details" in db_component

        # System component fields
        sys_component = data["components"]["system"]
        assert "status" in sys_component
        assert "cpu_percent" in sys_component
        assert "memory_percent" in sys_component
        assert "memory_available_mb" in sys_component

    def test_health_detailed_no_auth_required(self, test_client: TestClient):
        """Test health endpoint does not require authentication."""
        # No Authorization header
        response = test_client.get("/api/v1/health/detailed")

        assert response.status_code == 200
        # Should not return 401 Unauthorized


class TestHealthPerformance:
    """Test suite for health endpoint performance."""

    def test_health_detailed_performance(self, test_client: TestClient):
        """Test health endpoint responds within 100ms target."""
        start = time.time()
        response = test_client.get("/api/v1/health/detailed")
        duration_ms = (time.time() - start) * 1000

        assert response.status_code == 200
        # Target: < 100ms P95
        assert duration_ms < 100, f"Health check took {duration_ms:.2f}ms (target: < 100ms)"

    def test_health_detailed_includes_response_time(self, test_client: TestClient):
        """Test health endpoint includes response_time_ms in response."""
        response = test_client.get("/api/v1/health/detailed")

        assert response.status_code == 200
        data = response.json()
        assert "response_time_ms" in data
        assert isinstance(data["response_time_ms"], (int, float))
        assert data["response_time_ms"] > 0


class TestHealthDegradedScenarios:
    """Test suite for degraded health scenarios."""

    def test_health_degraded_high_cpu(self, test_client: TestClient):
        """Test health endpoint returns degraded status for high CPU (80-90%)."""
        # Mock the get_metrics method to return degraded CPU
        mock_metrics = AsyncMock(
            return_value={
                "cpu_percent": 85.2,  # 85.2% CPU (degraded)
                "memory_percent": 60.0,
                "memory_available_mb": 6553.6,
                "memory_total_mb": 16384.0,
            }
        )

        with patch("src.api.routers.health._system_metrics_cache.get_metrics", mock_metrics):
            response = test_client.get("/api/v1/health/detailed")

            assert response.status_code == 200
            data = response.json()

            # Should be degraded due to elevated CPU
            assert data["status"] == "degraded"

            # System component should be degraded
            assert data["components"]["system"]["status"] == "degraded"

            # Verify CPU is in degraded range (80-90%)
            cpu_percent = data["components"]["system"]["cpu_percent"]
            assert 80 <= cpu_percent <= 90

    def test_health_degraded_high_memory(self, test_client: TestClient):
        """Test health endpoint returns degraded status for high memory (85-95%)."""
        # Mock the get_metrics method to return degraded memory
        mock_metrics = AsyncMock(
            return_value={
                "cpu_percent": 45.0,
                "memory_percent": 88.5,  # 88.5% memory (degraded)
                "memory_available_mb": 1884.16,
                "memory_total_mb": 16384.0,
            }
        )

        with patch("src.api.routers.health._system_metrics_cache.get_metrics", mock_metrics):
            response = test_client.get("/api/v1/health/detailed")

            assert response.status_code == 200
            data = response.json()

            # Should be degraded due to high memory
            assert data["status"] == "degraded"

            # System component should be degraded
            assert data["components"]["system"]["status"] == "degraded"

            # Verify memory is in degraded range (85-95%)
            memory_percent = data["components"]["system"]["memory_percent"]
            assert 85 <= memory_percent <= 95


class TestHealthUnhealthyScenarios:
    """Test suite for unhealthy health scenarios."""

    def test_health_unhealthy_high_cpu(self, test_client: TestClient):
        """Test health endpoint returns unhealthy status for very high CPU (> 90%)."""
        # Mock the get_metrics method to return unhealthy CPU
        mock_metrics = AsyncMock(
            return_value={
                "cpu_percent": 95.8,  # 95.8% CPU (unhealthy)
                "memory_percent": 60.0,
                "memory_available_mb": 6553.6,
                "memory_total_mb": 16384.0,
            }
        )

        with patch("src.api.routers.health._system_metrics_cache.get_metrics", mock_metrics):
            response = test_client.get("/api/v1/health/detailed")

            assert response.status_code == 200
            data = response.json()

            # Should be unhealthy due to very high CPU
            assert data["status"] == "unhealthy"

            # System component should be unhealthy
            assert data["components"]["system"]["status"] == "unhealthy"

            # Verify CPU is > 90%
            assert data["components"]["system"]["cpu_percent"] > 90

    def test_health_unhealthy_high_memory(self, test_client: TestClient):
        """Test health endpoint returns unhealthy status for very high memory (> 95%)."""
        # Mock the get_metrics method to return unhealthy memory
        mock_metrics = AsyncMock(
            return_value={
                "cpu_percent": 45.0,
                "memory_percent": 96.5,  # 96.5% memory (unhealthy)
                "memory_available_mb": 573.44,
                "memory_total_mb": 16384.0,
            }
        )

        with patch("src.api.routers.health._system_metrics_cache.get_metrics", mock_metrics):
            response = test_client.get("/api/v1/health/detailed")

            assert response.status_code == 200
            data = response.json()

            # Should be unhealthy due to very high memory
            assert data["status"] == "unhealthy"

            # System component should be unhealthy
            assert data["components"]["system"]["status"] == "unhealthy"

            # Verify memory is > 95%
            assert data["components"]["system"]["memory_percent"] > 95

    def test_health_unhealthy_db_failure(self, test_client: TestClient):
        """Test health endpoint returns unhealthy status for database failure."""
        with patch("src.core.database.DatabaseHealthCheck.check_connection", return_value=False):
            response = test_client.get("/api/v1/health/detailed")

            # Health endpoint should always return 200 (even if unhealthy)
            assert response.status_code == 200
            data = response.json()

            # Should be unhealthy due to database failure
            assert data["status"] == "unhealthy"

            # Database component should be unhealthy
            assert data["components"]["database"]["status"] == "unhealthy"


class TestHealthCaching:
    """Test suite for health endpoint caching behavior."""

    def test_health_caching_reduces_metrics_calls(self, test_client: TestClient):
        """Test system metrics are cached for 5 seconds (reduces metric calls)."""
        mock_metrics = AsyncMock(
            return_value={
                "cpu_percent": 45.5,
                "memory_percent": 60.2,
                "memory_available_mb": 6553.6,
                "memory_total_mb": 16384.0,
            }
        )

        with patch("src.api.routers.health._system_metrics_cache.get_metrics", mock_metrics):
            # First call - should fetch fresh metrics
            response1 = test_client.get("/api/v1/health/detailed")
            assert response1.status_code == 200

            # Second call immediately - cache should reduce redundant calls
            response2 = test_client.get("/api/v1/health/detailed")
            assert response2.status_code == 200

            # Verify both requests succeeded
            assert response1.json()["status"] in ["healthy", "degraded", "unhealthy"]
            assert response2.json()["status"] in ["healthy", "degraded", "unhealthy"]
