"""Health Check FastAPI Router

This module provides detailed health check endpoint for monitoring.
No authentication required - public health status endpoint.

Endpoints:
- GET /api/v1/health/detailed - Comprehensive health check with component status

Design Principles:
1. Fast response time (<100ms, target 20-40ms)
2. Component-based health status (database, system)
3. Cached system metrics (5-second TTL)
4. No authentication required (public endpoint)
5. Overall status derived from component health
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Literal

import psutil
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.api.dependencies import check_rate_limit_health_detailed
from src.core.database import DatabaseHealthCheck

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/health", tags=["Health"])


# ============================================================================
# Response Models
# ============================================================================


class DatabaseComponentStatus(BaseModel):
    """Database component health status"""

    status: Literal["healthy", "unhealthy"]
    latency_ms: float = Field(..., description="Database query latency in milliseconds")
    details: dict = Field(default_factory=dict, description="Additional database metrics")


class SystemComponentStatus(BaseModel):
    """System component health status"""

    status: Literal["healthy", "degraded", "unhealthy"]
    cpu_percent: float = Field(..., description="CPU usage percentage")
    memory_percent: float = Field(..., description="Memory usage percentage")
    memory_available_mb: float = Field(..., description="Available memory in MB")


class ComponentsStatus(BaseModel):
    """All component statuses"""

    database: DatabaseComponentStatus
    system: SystemComponentStatus


class DetailedHealthResponse(BaseModel):
    """Detailed health check response"""

    status: Literal["healthy", "degraded", "unhealthy"]
    timestamp: str = Field(..., description="ISO8601 timestamp")
    components: ComponentsStatus
    response_time_ms: float = Field(..., description="Total health check latency")


# ============================================================================
# System Metrics Cache (5-second TTL)
# ============================================================================


class SystemMetricsCache:
    """Cache system metrics to avoid excessive psutil calls"""

    def __init__(self, ttl_seconds: float = 5.0):
        self._cache: dict | None = None
        self._last_update: float = 0.0
        self._ttl_seconds = ttl_seconds

    async def get_metrics(self) -> dict:
        """Get cached system metrics or fetch new ones if expired"""
        current_time = time.time()

        # Check if cache is valid
        if self._cache and (current_time - self._last_update < self._ttl_seconds):
            return self._cache

        # Fetch new metrics (use asyncio.to_thread for sync psutil calls)
        metrics = await asyncio.to_thread(self._fetch_metrics)

        # Update cache
        self._cache = metrics
        self._last_update = current_time

        return metrics

    @staticmethod
    def _fetch_metrics() -> dict:
        """Fetch system metrics using psutil (synchronous)"""
        # Get CPU usage (interval=0.1 for faster response)
        cpu_percent = psutil.cpu_percent(interval=0.1)

        # Get memory info
        memory = psutil.virtual_memory()

        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_mb": memory.available / (1024 * 1024),
            "memory_total_mb": memory.total / (1024 * 1024),
        }


# Global cache instance
_system_metrics_cache = SystemMetricsCache(ttl_seconds=5.0)


# ============================================================================
# Helper Functions
# ============================================================================


def determine_system_status(cpu_percent: float, memory_percent: float) -> Literal["healthy", "degraded", "unhealthy"]:
    """Determine system status based on CPU and memory usage

    Thresholds:
    - healthy: CPU < 80% AND Memory < 85%
    - degraded: CPU 80-90% OR Memory 85-95%
    - unhealthy: CPU > 90% OR Memory > 95%
    """
    if cpu_percent > 90 or memory_percent > 95:
        return "unhealthy"
    if cpu_percent > 80 or memory_percent > 85:
        return "degraded"
    return "healthy"


def determine_overall_status(
    db_status: Literal["healthy", "unhealthy"],
    system_status: Literal["healthy", "degraded", "unhealthy"],
) -> Literal["healthy", "degraded", "unhealthy"]:
    """Determine overall health status from component statuses

    Logic:
    - If database is unhealthy → overall unhealthy
    - If database is healthy and system is degraded → overall degraded
    - If both are healthy → overall healthy
    """
    if db_status == "unhealthy":
        return "unhealthy"
    if system_status == "unhealthy":
        return "unhealthy"
    if system_status == "degraded":
        return "degraded"
    return "healthy"


# ============================================================================
# Endpoint: GET /api/v1/health/detailed
# ============================================================================


@router.get(
    "/detailed",
    response_model=DetailedHealthResponse,
    dependencies=[Depends(check_rate_limit_health_detailed)],
)
async def detailed_health_check() -> DetailedHealthResponse:
    """Comprehensive health check with component-level status

    This endpoint provides detailed health information including:
    - Database connection health and latency
    - System resource usage (CPU, memory)
    - Overall service health status

    No authentication required - public monitoring endpoint.
    Rate limited: 60 req/min (production), 120 req/min (development).

    Performance:
    - Target response time: 20-40ms
    - Maximum response time: <100ms
    - System metrics cached for 5 seconds

    Security (Hestia Audit 2025-12-02):
    - Rate limiting applied to prevent DoS
    - No sensitive data exposed (generic system metrics only)

    Returns:
        DetailedHealthResponse with component statuses

    Example Response:
        {
            "status": "healthy",
            "timestamp": "2025-12-02T10:30:00Z",
            "components": {
                "database": {
                    "status": "healthy",
                    "latency_ms": 2.5,
                    "details": {}
                },
                "system": {
                    "status": "healthy",
                    "cpu_percent": 45.2,
                    "memory_percent": 62.8,
                    "memory_available_mb": 2048.5
                }
            },
            "response_time_ms": 35.2
        }
    """
    start_time = time.perf_counter()

    # Check database health and measure latency
    db_start = time.perf_counter()
    db_healthy = await DatabaseHealthCheck.check_connection()
    db_latency_ms = (time.perf_counter() - db_start) * 1000

    db_status = "healthy" if db_healthy else "unhealthy"

    # Get cached system metrics
    system_metrics = await _system_metrics_cache.get_metrics()
    system_status = determine_system_status(system_metrics["cpu_percent"], system_metrics["memory_percent"])

    # Determine overall status
    overall_status = determine_overall_status(db_status, system_status)

    # Calculate total response time
    response_time_ms = (time.perf_counter() - start_time) * 1000

    # Build response
    response = DetailedHealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        components=ComponentsStatus(
            database=DatabaseComponentStatus(
                status=db_status,
                latency_ms=round(db_latency_ms, 2),
                details={},
            ),
            system=SystemComponentStatus(
                status=system_status,
                cpu_percent=round(system_metrics["cpu_percent"], 1),
                memory_percent=round(system_metrics["memory_percent"], 1),
                memory_available_mb=round(system_metrics["memory_available_mb"], 1),
            ),
        ),
        response_time_ms=round(response_time_ms, 2),
    )

    # Log if response is slower than expected
    if response_time_ms > 100:
        logger.warning(
            f"Health check exceeded 100ms threshold: {response_time_ms:.2f}ms "
            f"(db: {db_latency_ms:.2f}ms, status: {overall_status})"
        )

    return response
