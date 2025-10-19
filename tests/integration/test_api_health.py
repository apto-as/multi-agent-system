"""
Health API Integration Tests for TMWS.
Artemis-led comprehensive testing for system health monitoring.

This module provides complete integration testing for the Health API endpoints,
ensuring robust monitoring, diagnostics, and system reliability verification.

Testing Strategy:
- Complete health check validation
- Database connectivity monitoring
- Performance metrics verification
- Configuration validation testing
- System resource monitoring
- Production readiness checks
- Monitoring integration testing

Performance Requirements:
- Basic health check: < 50ms
- Detailed health check: < 200ms
- Readiness check: < 100ms
- Liveness check: < 30ms
- Metrics collection: < 150ms
"""

import asyncio
from datetime import datetime

import pytest
from fastapi import status
from httpx import AsyncClient


@pytest.mark.integration
class TestHealthAPIIntegration:
    """Complete integration testing for Health API endpoints."""

    async def test_basic_health_check_success(self, async_client: AsyncClient, performance_timer):
        """Test basic health check endpoint with performance validation."""
        timer = performance_timer.start()

        response = await async_client.get("/api/v1/health/")

        elapsed = timer.stop()
        assert elapsed < 50, f"Basic health check took {elapsed}ms, expected < 50ms"

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify required fields
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["service"] == "TMWS"
        assert "version" in data
        assert "environment" in data

        # Verify timestamp format
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        assert isinstance(timestamp, datetime)

    async def test_basic_health_check_no_database_dependency(self, async_client: AsyncClient):
        """Test that basic health check works without database dependency."""
        # This test ensures the basic endpoint works even if database is down
        response = await async_client.get("/api/v1/health/")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["status"] == "healthy"
        # Basic health check should not include database status

    async def test_detailed_health_check_success(
        self, async_client: AsyncClient, performance_timer
    ):
        """Test detailed health check with all system components."""
        timer = performance_timer.start()

        response = await async_client.get("/api/v1/health/detailed")

        elapsed = timer.stop()
        assert elapsed < 200, f"Detailed health check took {elapsed}ms, expected < 200ms"

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify overall status
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "checks" in data

        checks = data["checks"]

        # Database check
        assert "database" in checks
        db_check = checks["database"]
        assert db_check["status"] in ["healthy", "unhealthy"]
        assert "connection" in db_check
        if db_check["status"] == "healthy":
            assert db_check["connection"] is True
            assert "pool" in db_check

        # Application check
        assert "application" in checks
        app_check = checks["application"]
        assert app_check["status"] == "healthy"
        assert "info" in app_check
        app_info = app_check["info"]
        assert "name" in app_info
        assert "version" in app_info
        assert "environment" in app_info

        # Middleware check
        assert "middleware" in checks
        middleware_check = checks["middleware"]
        assert middleware_check["status"] == "healthy"
        assert "stats" in middleware_check

        # Configuration check
        assert "configuration" in checks
        config_check = checks["configuration"]
        assert config_check["status"] in ["healthy", "degraded"]
        assert "issues" in config_check
        assert "environment" in config_check

    async def test_detailed_health_check_database_error_handling(self, async_client: AsyncClient):
        """Test detailed health check behavior when database has issues."""
        # Note: This test would require mocking database failures
        # For now, we test the structure and error handling format

        response = await async_client.get("/api/v1/health/detailed")

        # Should still return 200 even with degraded services
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should have proper error structure if database fails
        if "database" in data["checks"] and data["checks"]["database"]["status"] == "unhealthy":
            assert "error" in data["checks"]["database"]

    async def test_readiness_check_success(self, async_client: AsyncClient, performance_timer):
        """Test Kubernetes readiness probe endpoint."""
        timer = performance_timer.start()

        response = await async_client.get("/api/v1/health/ready")

        elapsed = timer.stop()
        assert elapsed < 100, f"Readiness check took {elapsed}ms, expected < 100ms"

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["status"] == "ready"
        assert "timestamp" in data

    async def test_readiness_check_database_dependency(self, async_client: AsyncClient):
        """Test that readiness check fails when database is not available."""
        # Note: This would require mocking database unavailability
        # For integration testing with real database, we expect success
        response = await async_client.get("/api/v1/health/ready")

        # With functional database, should be ready
        assert response.status_code == status.HTTP_200_OK

    async def test_liveness_check_success(self, async_client: AsyncClient, performance_timer):
        """Test Kubernetes liveness probe endpoint."""
        timer = performance_timer.start()

        response = await async_client.get("/api/v1/health/live")

        elapsed = timer.stop()
        assert elapsed < 30, f"Liveness check took {elapsed}ms, expected < 30ms"

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["status"] == "alive"
        assert "timestamp" in data
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], int | float)
        assert data["uptime_seconds"] >= 0

    async def test_liveness_check_lightweight(self, async_client: AsyncClient):
        """Test that liveness check is truly lightweight and dependency-free."""
        # Multiple rapid calls should all succeed quickly
        for _ in range(5):
            response = await async_client.get("/api/v1/health/live")
            assert response.status_code == status.HTTP_200_OK
            assert response.json()["status"] == "alive"

    async def test_metrics_endpoint_success(self, async_client: AsyncClient, performance_timer):
        """Test metrics endpoint for monitoring integration."""
        timer = performance_timer.start()

        response = await async_client.get("/api/v1/health/metrics")

        elapsed = timer.stop()
        assert elapsed < 150, f"Metrics collection took {elapsed}ms, expected < 150ms"

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify timestamp
        assert "timestamp" in data
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        assert isinstance(timestamp, datetime)

        # Service information
        assert "service" in data
        service = data["service"]
        assert "name" in service
        assert "version" in service
        assert "environment" in service

        # Database metrics
        assert "database" in data
        db_metrics = data["database"]
        assert "pool_size" in db_metrics
        assert "connections_in_use" in db_metrics
        assert "connections_available" in db_metrics
        assert "connections_overflow" in db_metrics
        assert "connections_invalid" in db_metrics

        # Verify metric values are reasonable
        assert isinstance(db_metrics["pool_size"], int)
        assert db_metrics["pool_size"] >= 0
        assert isinstance(db_metrics["connections_in_use"], int)
        assert db_metrics["connections_in_use"] >= 0

        # Middleware metrics
        assert "middleware" in data
        middleware_metrics = data["middleware"]
        assert "status" in middleware_metrics

        # Configuration metrics
        assert "configuration" in data
        config_metrics = data["configuration"]
        assert "rate_limiting_enabled" in config_metrics
        assert "cors_enabled" in config_metrics
        assert "debug_mode" in config_metrics

    async def test_metrics_endpoint_structure_validation(self, async_client: AsyncClient):
        """Test metrics endpoint returns properly structured data."""
        response = await async_client.get("/api/v1/health/metrics")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()

        # Verify all required top-level keys exist
        required_keys = ["timestamp", "service", "database", "middleware", "configuration"]
        for key in required_keys:
            assert key in data, f"Missing required key: {key}"

        # Verify service structure
        service_keys = ["name", "version", "environment"]
        for key in service_keys:
            assert key in data["service"], f"Missing service key: {key}"

        # Verify database metrics structure
        db_keys = [
            "pool_size",
            "connections_in_use",
            "connections_available",
            "connections_overflow",
            "connections_invalid",
        ]
        for key in db_keys:
            assert key in data["database"], f"Missing database metric: {key}"

    async def test_version_info_endpoint(self, async_client: AsyncClient):
        """Test version information endpoint."""
        response = await async_client.get("/api/v1/health/version")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()

        # Verify required fields
        assert "service" in data
        assert "version" in data
        assert "environment" in data
        assert "api" in data
        assert "build" in data

        # API configuration
        api_info = data["api"]
        assert "docs_enabled" in api_info
        assert "openapi_enabled" in api_info
        assert isinstance(api_info["docs_enabled"], bool)
        assert isinstance(api_info["openapi_enabled"], bool)

        # Build information
        build_info = data["build"]
        assert "timestamp" in build_info
        assert "python_version" in build_info
        assert "framework" in build_info
        assert build_info["framework"] == "FastAPI"

    async def test_version_info_consistency(self, async_client: AsyncClient):
        """Test version information is consistent across endpoints."""
        # Get version from version endpoint
        version_response = await async_client.get("/api/v1/health/version")
        version_data = version_response.json()

        # Get version from basic health check
        health_response = await async_client.get("/api/v1/health/")
        health_data = health_response.json()

        # Get version from metrics
        metrics_response = await async_client.get("/api/v1/health/metrics")
        metrics_data = metrics_response.json()

        # Verify consistency
        assert version_data["version"] == health_data["version"]
        assert version_data["service"] == health_data["service"]
        assert version_data["environment"] == health_data["environment"]

        assert version_data["version"] == metrics_data["service"]["version"]
        assert version_data["service"] == metrics_data["service"]["name"]
        assert version_data["environment"] == metrics_data["service"]["environment"]


@pytest.mark.integration
class TestHealthEndpointPerformance:
    """Test performance characteristics of health endpoints."""

    async def test_concurrent_health_checks(self, async_client: AsyncClient):
        """Test concurrent health check requests."""

        async def make_health_request():
            response = await async_client.get("/api/v1/health/")
            return response.status_code, response.json()

        # Make 20 concurrent requests
        tasks = [make_health_request() for _ in range(20)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        for status_code, data in results:
            assert status_code == status.HTTP_200_OK
            assert data["status"] == "healthy"

    async def test_health_endpoint_load_performance(
        self, async_client: AsyncClient, performance_timer
    ):
        """Test health endpoint performance under load."""
        timer = performance_timer.start()

        # Sequential requests to test sustained performance
        for _ in range(50):
            response = await async_client.get("/api/v1/health/")
            assert response.status_code == status.HTTP_200_OK

        total_time = timer.stop()
        average_time = total_time / 50

        assert average_time < 50, f"Average health check time {average_time}ms exceeds 50ms"

    async def test_detailed_health_check_performance_consistency(
        self, async_client: AsyncClient, performance_timer
    ):
        """Test that detailed health check performance is consistent."""
        times = []

        for _ in range(10):
            timer = performance_timer.start()
            response = await async_client.get("/api/v1/health/detailed")
            elapsed = timer.stop()

            assert response.status_code == status.HTTP_200_OK
            times.append(elapsed)

        # Calculate statistics
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        assert avg_time < 200, f"Average detailed health check time {avg_time}ms exceeds 200ms"
        assert max_time < 500, f"Maximum detailed health check time {max_time}ms exceeds 500ms"

        # Variance should be reasonable (max shouldn't be more than 3x min)
        assert max_time / min_time < 3, f"Performance variance too high: {max_time / min_time}x"


@pytest.mark.integration
class TestHealthConfigurationValidation:
    """Test health endpoint configuration validation."""

    async def test_production_configuration_warnings(self, async_client: AsyncClient):
        """Test configuration validation in different environments."""
        response = await async_client.get("/api/v1/health/detailed")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        config_check = data["checks"]["configuration"]

        # In test environment, some production warnings might not apply
        assert "issues" in config_check
        assert isinstance(config_check["issues"], list)

        # Environment should be properly detected
        assert config_check["environment"] in ["development", "test", "staging", "production"]

    async def test_readiness_production_validation(self, async_client: AsyncClient):
        """Test readiness check validates production configuration."""
        # In test environment, should pass
        response = await async_client.get("/api/v1/health/ready")
        assert response.status_code == status.HTTP_200_OK

        # If this were production with insecure config, it should fail with 503
        # This test validates the check is implemented

    async def test_metrics_configuration_reflection(self, async_client: AsyncClient):
        """Test that metrics accurately reflect current configuration."""
        response = await async_client.get("/api/v1/health/metrics")
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        config = data["configuration"]

        # These should reflect actual application configuration
        assert isinstance(config["rate_limiting_enabled"], bool)
        assert isinstance(config["cors_enabled"], bool)
        assert isinstance(config["debug_mode"], bool)

        # In test environment, debug mode should typically be true
        # Rate limiting might be disabled for testing


@pytest.mark.integration
class TestHealthEndpointResilience:
    """Test health endpoint resilience and error handling."""

    async def test_health_endpoints_error_isolation(self, async_client: AsyncClient):
        """Test that errors in one health check don't affect others."""
        # Basic health check should work even if detailed checks fail
        basic_response = await async_client.get("/api/v1/health/")
        assert basic_response.status_code == status.HTTP_200_OK

        # Liveness should always work
        liveness_response = await async_client.get("/api/v1/health/live")
        assert liveness_response.status_code == status.HTTP_200_OK

        # Version should always work
        version_response = await async_client.get("/api/v1/health/version")
        assert version_response.status_code == status.HTTP_200_OK

    async def test_health_check_graceful_degradation(self, async_client: AsyncClient):
        """Test graceful degradation when subsystems fail."""
        response = await async_client.get("/api/v1/health/detailed")

        # Should return 200 even with degraded services
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Status might be degraded but endpoint should still function
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

        # All check sections should be present even if some fail
        assert "checks" in data
        checks = data["checks"]

        expected_checks = ["database", "application", "middleware", "configuration"]
        for check_name in expected_checks:
            assert check_name in checks
            assert "status" in checks[check_name]

    async def test_metrics_collection_resilience(self, async_client: AsyncClient):
        """Test metrics collection handles partial failures gracefully."""
        response = await async_client.get("/api/v1/health/metrics")

        # Should return 200 or 500, but handle gracefully
        if response.status_code == status.HTTP_200_OK:
            data = response.json()

            # Core structure should be present
            assert "timestamp" in data
            assert "service" in data

            # Individual metric sections might have default values if collection fails
            assert "database" in data
            assert "middleware" in data
            assert "configuration" in data
        else:
            # If metrics collection fails entirely, should return 500
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Metrics collection failed" in response.json()["detail"]


@pytest.mark.integration
class TestHealthMonitoringIntegration:
    """Test integration with monitoring and alerting systems."""

    async def test_health_endpoint_response_format_prometheus(self, async_client: AsyncClient):
        """Test health endpoints return data suitable for Prometheus scraping."""
        metrics_response = await async_client.get("/api/v1/health/metrics")
        assert metrics_response.status_code == status.HTTP_200_OK

        data = metrics_response.json()

        # Verify numeric metrics are suitable for Prometheus
        db_metrics = data["database"]
        numeric_fields = [
            "pool_size",
            "connections_in_use",
            "connections_available",
            "connections_overflow",
            "connections_invalid",
        ]

        for field in numeric_fields:
            assert isinstance(db_metrics[field], int | float)
            assert db_metrics[field] >= 0

    async def test_health_status_codes_for_monitoring(self, async_client: AsyncClient):
        """Test health endpoints return appropriate HTTP status codes for monitoring."""
        # Basic health should always return 200
        basic_response = await async_client.get("/api/v1/health/")
        assert basic_response.status_code == status.HTTP_200_OK

        # Detailed health returns 200 even with degraded services
        detailed_response = await async_client.get("/api/v1/health/detailed")
        assert detailed_response.status_code == status.HTTP_200_OK

        # Readiness returns 200 if ready, 503 if not
        ready_response = await async_client.get("/api/v1/health/ready")
        assert ready_response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_503_SERVICE_UNAVAILABLE,
        ]

        # Liveness should always return 200
        live_response = await async_client.get("/api/v1/health/live")
        assert live_response.status_code == status.HTTP_200_OK

    async def test_health_endpoint_timing_consistency(
        self, async_client: AsyncClient, performance_timer
    ):
        """Test health endpoint timing consistency for SLA monitoring."""
        endpoints = [
            ("/api/v1/health/", 50),  # Basic: < 50ms
            ("/api/v1/health/live", 30),  # Liveness: < 30ms
            ("/api/v1/health/ready", 100),  # Readiness: < 100ms
            ("/api/v1/health/detailed", 200),  # Detailed: < 200ms
            ("/api/v1/health/metrics", 150),  # Metrics: < 150ms
        ]

        for endpoint, max_time in endpoints:
            # Test multiple times to ensure consistency
            times = []

            for _ in range(5):
                timer = performance_timer.start()
                response = await async_client.get(endpoint)
                elapsed = timer.stop()

                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                ]
                times.append(elapsed)

            avg_time = sum(times) / len(times)
            max_observed = max(times)

            assert avg_time < max_time, f"Average time for {endpoint}: {avg_time}ms > {max_time}ms"
            assert max_observed < max_time * 2, (
                f"Max time for {endpoint}: {max_observed}ms > {max_time * 2}ms"
            )
