"""System Health Service for TMWS.

Provides system-level health metrics including:
- CPU and memory usage (via psutil)
- Database health checks
- Combined health status with caching

Performance:
- 5-second cache for system metrics (Athena's recommendation)
- < 50ms P95 target (async-first with psutil wrapped in asyncio.to_thread)

Phase: v2.4.8 (Orchestration Layer)
Author: Metis (Development Assistant)
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import DatabaseError, log_and_raise

logger = logging.getLogger(__name__)


class SystemHealthService:
    """System health monitoring service with caching.

    Provides efficient health metrics with 5-second cache to prevent
    excessive system calls. All psutil calls are wrapped in asyncio.to_thread
    to prevent event loop blocking.
    """

    def __init__(self, session: AsyncSession):
        """Initialize health service with database session.

        Args:
            session: Async database session for health checks
        """
        self.session = session

        # Cache configuration (Athena's recommendation)
        self._cache_ttl_seconds = 5
        self._metrics_cache: dict[str, Any] | None = None
        self._cache_timestamp: datetime | None = None

        logger.info("SystemHealthService initialized with 5-second cache")

    def _is_cache_valid(self) -> bool:
        """Check if metrics cache is still valid.

        Returns:
            True if cache exists and is within TTL window
        """
        if self._cache_timestamp is None or self._metrics_cache is None:
            return False

        age = datetime.now(timezone.utc) - self._cache_timestamp
        return age < timedelta(seconds=self._cache_ttl_seconds)

    async def get_system_metrics(self) -> dict[str, Any]:
        """Get system metrics (CPU, memory, disk) with caching.

        Metrics are cached for 5 seconds to prevent excessive system calls.
        All psutil operations are async-wrapped to avoid blocking event loop.

        Returns:
            Dictionary with system metrics:
            - cpu_percent: CPU usage percentage
            - memory_percent: Memory usage percentage
            - memory_total_gb: Total memory in GB
            - memory_available_gb: Available memory in GB
            - disk_percent: Disk usage percentage
            - disk_total_gb: Total disk space in GB
            - disk_free_gb: Free disk space in GB

        Performance:
            Target: < 50ms P95 (async psutil calls)
        """
        # Return cached metrics if valid
        if self._is_cache_valid():
            logger.debug("Returning cached system metrics")
            return self._metrics_cache  # type: ignore

        logger.debug("Fetching fresh system metrics")

        try:
            # Wrap all psutil calls in asyncio.to_thread to prevent blocking
            cpu_percent = await asyncio.to_thread(psutil.cpu_percent, interval=0.1)
            memory = await asyncio.to_thread(psutil.virtual_memory)
            disk = await asyncio.to_thread(psutil.disk_usage, "/")

            metrics = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_percent": disk.percent,
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "disk_free_gb": round(disk.free / (1024**3), 2),
            }

            # Update cache
            self._metrics_cache = metrics
            self._cache_timestamp = datetime.now(timezone.utc)

            logger.info(
                f"System metrics: CPU={cpu_percent}%, "
                f"Memory={memory.percent}%, Disk={disk.percent}%"
            )

            return metrics

        except Exception as e:
            log_and_raise(
                DatabaseError,
                f"Failed to fetch system metrics: {str(e)}",
                original_exception=e,
            )

    async def get_database_health(self) -> dict[str, Any]:
        """Check database connectivity and basic health.

        Executes a simple SELECT 1 query to verify database is responsive.

        Returns:
            Dictionary with database health status:
            - status: "healthy" or "unhealthy"
            - latency_ms: Query latency in milliseconds
            - error: Error message if unhealthy

        Performance:
            Target: < 20ms P95 (simple SELECT)
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Simple health check query
            result = await self.session.execute(text("SELECT 1"))
            result.scalar_one()

            latency = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            logger.debug(f"Database health check: OK (latency={latency:.2f}ms)")

            return {
                "status": "healthy",
                "latency_ms": round(latency, 2),
            }

        except Exception as e:
            latency = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            logger.error(
                f"Database health check failed: {str(e)} (latency={latency:.2f}ms)"
            )

            return {
                "status": "unhealthy",
                "latency_ms": round(latency, 2),
                "error": str(e),
            }

    async def get_detailed_health(self) -> dict[str, Any]:
        """Get comprehensive health status combining all metrics.

        Determines overall system health based on:
        - Database connectivity (critical)
        - CPU usage (warning if > 80%, degraded if > 90%)
        - Memory usage (warning if > 80%, degraded if > 90%)
        - Disk usage (warning if > 80%, degraded if > 90%)

        Returns:
            Dictionary with comprehensive health status:
            - status: "healthy", "degraded", or "unhealthy"
            - timestamp: ISO8601 timestamp
            - database: Database health metrics
            - system: System metrics
            - warnings: List of warning messages (if any)

        Performance:
            Target: < 100ms P95 (includes DB check + cached metrics)
        """
        timestamp = datetime.now(timezone.utc)

        # Fetch database health (always fresh, critical check)
        db_health = await self.get_database_health()

        # Fetch system metrics (may be cached)
        system_metrics = await self.get_system_metrics()

        # Determine overall status
        warnings: list[str] = []

        # Database is critical - if unhealthy, entire system is unhealthy
        if db_health["status"] == "unhealthy":
            status = "unhealthy"
            warnings.append(f"Database unhealthy: {db_health.get('error', 'Unknown error')}")
        else:
            status = "healthy"

        # Check CPU (degraded if > 90%, warning if > 80%)
        cpu_percent = system_metrics["cpu_percent"]
        if cpu_percent > 90:
            status = "degraded"
            warnings.append(f"High CPU usage: {cpu_percent}%")
        elif cpu_percent > 80:
            warnings.append(f"Elevated CPU usage: {cpu_percent}%")

        # Check Memory (degraded if > 90%, warning if > 80%)
        memory_percent = system_metrics["memory_percent"]
        if memory_percent > 90:
            status = "degraded"
            warnings.append(f"High memory usage: {memory_percent}%")
        elif memory_percent > 80:
            warnings.append(f"Elevated memory usage: {memory_percent}%")

        # Check Disk (degraded if > 90%, warning if > 80%)
        disk_percent = system_metrics["disk_percent"]
        if disk_percent > 90:
            status = "degraded"
            warnings.append(f"High disk usage: {disk_percent}%")
        elif disk_percent > 80:
            warnings.append(f"Elevated disk usage: {disk_percent}%")

        logger.info(
            f"Detailed health check: status={status}, "
            f"warnings={len(warnings)}"
        )

        return {
            "status": status,
            "timestamp": timestamp.isoformat(),
            "database": db_health,
            "system": system_metrics,
            "warnings": warnings,
        }
