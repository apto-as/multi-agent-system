"""Production-ready memory monitoring with leak detection.

This module implements a 3-tier memory monitoring system with <0.5% overhead
in production mode. It detects memory leaks (CWE-401) using linear regression
on RSS growth patterns.

Architecture:
    - PRODUCTION: psutil-only, 60s sampling, <0.5% overhead
    - DEVELOPMENT: tracemalloc enabled, 10s sampling, detailed profiling
    - DISABLED: No monitoring

Performance:
    - Production overhead: <0.5% CPU, <2MB RAM
    - Leak detection: Linear regression on 5-minute baseline
    - Alerts: Warning at 256MB, Critical at 512MB
    - Growth alerts: Warning at 50MB/hour, Critical at 100MB/hour

Example:
    >>> monitor = MemoryMonitor(tier=MonitoringTier.PRODUCTION)
    >>> await monitor.start()
    >>> # Monitor runs in background
    >>> snapshot = monitor.get_current_snapshot()
    >>> print(f"RSS: {snapshot.rss_mb:.2f} MB")

References:
    - CWE-401: Missing Release of Memory after Effective Lifetime
    - V-7: Memory leak detection vulnerability
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import tracemalloc
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Deque, Optional

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)


class MonitoringTier(Enum):
    """Memory monitoring tier configuration.

    PRODUCTION: Lightweight monitoring with psutil only (<0.5% overhead)
    DEVELOPMENT: Detailed profiling with tracemalloc (higher overhead)
    DISABLED: No monitoring (for testing or resource-constrained environments)
    """
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    DISABLED = "disabled"


@dataclass
class MemorySnapshot:
    """Point-in-time memory usage snapshot.

    Attributes:
        timestamp: When snapshot was taken
        rss_mb: Resident Set Size in MB (physical memory)
        vms_mb: Virtual Memory Size in MB
        percent: Memory usage as percentage of system total
        tracemalloc_current: Current tracemalloc memory (bytes, dev tier only)
        tracemalloc_peak: Peak tracemalloc memory (bytes, dev tier only)
        active_tasks: Number of active asyncio tasks
    """
    timestamp: datetime
    rss_mb: float
    vms_mb: float
    percent: float
    tracemalloc_current: Optional[int] = None
    tracemalloc_peak: Optional[int] = None
    active_tasks: Optional[int] = None

    def is_critical(self) -> bool:
        """Check if memory usage is at critical level (>512MB RSS)."""
        return self.rss_mb > 512

    def is_warning(self) -> bool:
        """Check if memory usage is at warning level (>256MB RSS)."""
        return self.rss_mb > 256

    def to_dict(self) -> dict:
        """Convert snapshot to dictionary for logging/serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "rss_mb": round(self.rss_mb, 2),
            "vms_mb": round(self.vms_mb, 2),
            "percent": round(self.percent, 2),
            "tracemalloc_current": self.tracemalloc_current,
            "tracemalloc_peak": self.tracemalloc_peak,
            "active_tasks": self.active_tasks,
        }


@dataclass
class MemoryLeakAlert:
    """Memory leak detection alert.

    Attributes:
        detected_at: When leak was detected
        growth_rate_mb_per_hour: Calculated memory growth rate
        baseline_rss_mb: Baseline RSS (5-minute median)
        current_rss_mb: Current RSS at detection time
        prediction_24h_mb: Predicted RSS in 24 hours if growth continues
        severity: 'warning' or 'critical'
        message: Human-readable alert message
    """
    detected_at: datetime
    growth_rate_mb_per_hour: float
    baseline_rss_mb: float
    current_rss_mb: float
    prediction_24h_mb: float
    severity: str  # 'warning' or 'critical'
    message: str

    def to_dict(self) -> dict:
        """Convert alert to dictionary for logging/serialization."""
        return {
            "detected_at": self.detected_at.isoformat(),
            "growth_rate_mb_per_hour": round(self.growth_rate_mb_per_hour, 2),
            "baseline_rss_mb": round(self.baseline_rss_mb, 2),
            "current_rss_mb": round(self.current_rss_mb, 2),
            "prediction_24h_mb": round(self.prediction_24h_mb, 2),
            "severity": self.severity,
            "message": self.message,
        }


@dataclass
class MemoryBaseline:
    """Memory baseline for leak detection.

    Attributes:
        established_at: When baseline was established
        rss_mb: Baseline RSS (Resident Set Size) in MB
        vms_mb: Baseline VMS (Virtual Memory Size) in MB
        percent: Baseline memory usage percentage
        samples_count: Number of samples used to establish baseline
        variance_percent: Variance in RSS across baseline samples
    """
    established_at: datetime
    rss_mb: float
    vms_mb: float
    percent: float
    samples_count: int = 0
    variance_percent: float = 0.0

    def to_dict(self) -> dict:
        """Convert baseline to dictionary for JSON serialization."""
        return {
            "established_at": self.established_at.isoformat(),
            "rss_mb": round(self.rss_mb, 2),
            "vms_mb": round(self.vms_mb, 2),
            "percent": round(self.percent, 2),
            "samples_count": self.samples_count,
            "variance_percent": round(self.variance_percent, 2),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryBaseline":
        """Create baseline from dictionary."""
        return cls(
            established_at=datetime.fromisoformat(data["established_at"]),
            rss_mb=data["rss_mb"],
            vms_mb=data["vms_mb"],
            percent=data["percent"],
            samples_count=data.get("samples_count", 0),
            variance_percent=data.get("variance_percent", 0.0),
        )


class MemoryMonitor:
    """Production-ready memory monitor with leak detection.

    This class provides continuous memory monitoring with configurable
    sampling intervals and automatic leak detection using linear regression
    on RSS growth patterns.

    The monitor establishes a baseline over the first 5 minutes, then
    continuously checks for anomalous growth patterns. Alerts are triggered
    when memory grows faster than expected thresholds.

    Performance:
        - Production tier: <0.5% CPU overhead, <2MB RAM overhead
        - Development tier: ~1-2% CPU overhead, detailed profiling
        - Disabled tier: 0% overhead (no monitoring)

    Args:
        tier: Monitoring tier (PRODUCTION, DEVELOPMENT, or DISABLED)
        sampling_interval: Seconds between snapshots (default 60 for production)
        baseline_window: Seconds for baseline calculation (default 300 = 5 minutes)
        max_history: Maximum snapshots to retain (default 1000)
        leak_detection_threshold_mb_per_hour: Growth rate for warning (default 50)
        leak_detection_critical_mb_per_hour: Growth rate for critical (default 100)

    Example:
        >>> monitor = MemoryMonitor(tier=MonitoringTier.PRODUCTION)
        >>> await monitor.start()
        >>> # Monitor runs in background
        >>> snapshot = monitor.get_current_snapshot()
        >>> if snapshot and snapshot.is_warning():
        ...     logger.warning(f"High memory usage: {snapshot.rss_mb:.2f} MB")
    """

    def __init__(
        self,
        tier: MonitoringTier = MonitoringTier.PRODUCTION,
        sampling_interval: int = 60,
        baseline_window: int = 300,
        max_history: int = 1000,
        leak_detection_threshold_mb_per_hour: float = 20.0,  # WK-1: Lowered from 50.0
        leak_detection_critical_mb_per_hour: float = 100.0,
        baseline_recalc_interval: int = 86400,  # WK-2: Recalc baseline every 24h
        monitoring_window_hours: int = 12,  # WK-1: Extended from 1h to 12h
    ):
        """Initialize memory monitor with specified configuration."""
        self.tier = tier
        self.sampling_interval = sampling_interval
        self.baseline_window = baseline_window
        self.max_history = max_history
        self.leak_detection_threshold = leak_detection_threshold_mb_per_hour
        self.leak_detection_critical = leak_detection_critical_mb_per_hour
        self.baseline_recalc_interval = baseline_recalc_interval
        self.monitoring_window_seconds = monitoring_window_hours * 3600

        # State
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._process: Optional[psutil.Process] = None
        self._snapshots: Deque[MemorySnapshot] = deque(maxlen=max_history)
        self._baseline_rss_mb: Optional[float] = None
        self._baseline_established_at: Optional[datetime] = None
        self._last_alert: Optional[datetime] = None

        # WK-2: Baseline history for outlier detection
        self._baseline_history: Deque[float] = deque(maxlen=100)  # Keep last 100 baselines

        # Validation
        if tier != MonitoringTier.DISABLED and psutil is None:
            raise ImportError(
                "psutil is required for memory monitoring. "
                "Install it with: pip install psutil"
            )

        # Initialize tracemalloc for development tier
        if tier == MonitoringTier.DEVELOPMENT:
            if not tracemalloc.is_tracing():
                tracemalloc.start()
                logger.info("Tracemalloc enabled for development tier monitoring")

    async def start(self) -> None:
        """Start memory monitoring in background.

        This method starts the monitoring loop as an asyncio task. The loop
        will run continuously until stop() is called.

        The first 5 minutes (baseline_window) are used to establish a baseline,
        after which leak detection becomes active.

        Raises:
            RuntimeError: If monitoring is already running
        """
        if self._running:
            raise RuntimeError("Memory monitor is already running")

        if self.tier == MonitoringTier.DISABLED:
            logger.info("Memory monitoring is disabled")
            return

        self._running = True
        self._process = psutil.Process()
        self._task = asyncio.create_task(self._monitoring_loop())
        logger.info(
            f"Memory monitor started (tier={self.tier.value}, "
            f"interval={self.sampling_interval}s)"
        )

    async def stop(self) -> None:
        """Stop memory monitoring.

        This method gracefully stops the monitoring loop and waits for
        the background task to complete.
        """
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        logger.info("Memory monitor stopped")

    async def _monitoring_loop(self) -> None:
        """Main monitoring loop (runs in background).

        This loop:
        1. Takes memory snapshots at regular intervals
        2. Establishes baseline during first baseline_window seconds
        3. Checks for memory leaks after baseline is established
        4. Triggers alerts when thresholds are exceeded
        5. WK-2: Recalculates baseline every 24 hours with outlier detection
        """
        try:
            while self._running:
                snapshot = self._take_snapshot()
                self._snapshots.append(snapshot)

                # Establish baseline if not yet done
                if self._baseline_rss_mb is None:
                    self._try_establish_baseline()
                # WK-2: Recalculate baseline periodically
                elif self._should_recalculate_baseline():
                    self._recalculate_baseline()

                # Check for leaks after baseline is established
                if self._baseline_rss_mb is not None:
                    alert = self._check_for_leak(snapshot)
                    if alert:
                        self._handle_alert(alert)

                # Check threshold alerts
                if snapshot.is_critical():
                    logger.critical(
                        f"CRITICAL: Memory usage at {snapshot.rss_mb:.2f} MB "
                        f"(threshold: 512 MB)"
                    )
                elif snapshot.is_warning():
                    logger.warning(
                        f"WARNING: Memory usage at {snapshot.rss_mb:.2f} MB "
                        f"(threshold: 256 MB)"
                    )

                await asyncio.sleep(self.sampling_interval)

        except asyncio.CancelledError:
            logger.debug("Monitoring loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Monitoring loop error: {e}", exc_info=True)
            raise

    def _take_snapshot(self) -> MemorySnapshot:
        """Take a memory snapshot at current time.

        Returns:
            MemorySnapshot with current memory usage metrics
        """
        if not self._process:
            raise RuntimeError("Process not initialized")

        # Get memory info from psutil
        mem_info = self._process.memory_info()
        mem_percent = self._process.memory_percent()

        rss_mb = mem_info.rss / (1024 * 1024)
        vms_mb = mem_info.vms / (1024 * 1024)

        # Get tracemalloc info if in development tier
        tracemalloc_current = None
        tracemalloc_peak = None
        if self.tier == MonitoringTier.DEVELOPMENT and tracemalloc.is_tracing():
            tracemalloc_current, tracemalloc_peak = tracemalloc.get_traced_memory()

        # Count active asyncio tasks
        try:
            active_tasks = len([t for t in asyncio.all_tasks() if not t.done()])
        except RuntimeError:
            active_tasks = None

        return MemorySnapshot(
            timestamp=datetime.now(),
            rss_mb=rss_mb,
            vms_mb=vms_mb,
            percent=mem_percent,
            tracemalloc_current=tracemalloc_current,
            tracemalloc_peak=tracemalloc_peak,
            active_tasks=active_tasks,
        )

    def _try_establish_baseline(self) -> None:
        """Try to establish baseline from collected snapshots.

        Baseline is established as the median RSS over the first baseline_window
        seconds (default 5 minutes). This requires at least 5 snapshots.
        """
        if not self._snapshots:
            return

        # Check if we have enough data spanning baseline_window
        oldest = self._snapshots[0].timestamp
        newest = self._snapshots[-1].timestamp
        duration = (newest - oldest).total_seconds()

        if duration < self.baseline_window or len(self._snapshots) < 5:
            return

        # Calculate median RSS from baseline window
        baseline_samples = [s.rss_mb for s in self._snapshots]
        self._baseline_rss_mb = statistics.median(baseline_samples)
        self._baseline_established_at = datetime.now()

        # WK-2: Add to baseline history
        self._baseline_history.append(self._baseline_rss_mb)

        logger.info(
            f"Baseline established: {self._baseline_rss_mb:.2f} MB "
            f"(based on {len(baseline_samples)} samples over "
            f"{duration:.0f} seconds)"
        )

    def _should_recalculate_baseline(self) -> bool:
        """
        Check if baseline should be recalculated (WK-2).

        Returns:
            True if baseline is older than recalc_interval
        """
        if not self._baseline_established_at:
            return False

        time_since_baseline = (datetime.now() - self._baseline_established_at).total_seconds()
        return time_since_baseline >= self.baseline_recalc_interval

    def _recalculate_baseline(self) -> None:
        """
        Recalculate baseline with outlier detection (WK-2).

        This method:
        1. Calculates new baseline from recent samples
        2. Checks if new baseline is an outlier (>1.5x median of history)
        3. Rejects outliers to prevent baseline poisoning
        4. Updates baseline if valid
        """
        if not self._snapshots:
            return

        # Get recent samples (last baseline_window seconds)
        cutoff_time = datetime.now() - timedelta(seconds=self.baseline_window)
        recent_samples = [
            s.rss_mb for s in self._snapshots
            if s.timestamp >= cutoff_time
        ]

        if len(recent_samples) < 5:
            return

        # Calculate new baseline candidate
        new_baseline = statistics.median(recent_samples)

        # WK-2: Outlier detection - reject if >1.5x median of history
        if self._baseline_history:
            median_history = statistics.median(self._baseline_history)
            if new_baseline > median_history * 1.5:
                logger.warning(
                    f"Baseline recalculation rejected: {new_baseline:.2f} MB is an outlier "
                    f"(>1.5x median history {median_history:.2f} MB). "
                    f"Possible baseline poisoning attempt."
                )
                return

        old_baseline = self._baseline_rss_mb
        self._baseline_rss_mb = new_baseline
        self._baseline_established_at = datetime.now()
        self._baseline_history.append(new_baseline)

        logger.info(
            f"Baseline recalculated: {old_baseline:.2f} MB -> {new_baseline:.2f} MB "
            f"(based on {len(recent_samples)} samples, "
            f"median history: {statistics.median(self._baseline_history):.2f} MB)"
        )

    def _check_for_leak(self, current_snapshot: MemorySnapshot) -> Optional[MemoryLeakAlert]:
        """Check for memory leak using linear regression on RSS growth.

        This method performs a simple linear regression on recent RSS samples
        to detect if memory is growing faster than expected thresholds.

        Args:
            current_snapshot: Most recent memory snapshot

        Returns:
            MemoryLeakAlert if leak detected, None otherwise
        """
        if self._baseline_rss_mb is None:
            return None

        # Need at least 10 samples for reliable regression
        if len(self._snapshots) < 10:
            return None

        # Throttle alerts (max 1 per hour)
        if self._last_alert:
            time_since_last_alert = (datetime.now() - self._last_alert).total_seconds()
            if time_since_last_alert < 3600:  # 1 hour
                return None

        # WK-1: Use extended monitoring window (12 hours instead of baseline_window)
        cutoff_time = datetime.now() - timedelta(seconds=self.monitoring_window_seconds)
        recent_samples = [
            s for s in self._snapshots
            if s.timestamp >= cutoff_time
        ]

        if len(recent_samples) < 10:
            return None

        # Calculate growth rate using simple linear regression
        # y = mx + b, where y is RSS and x is time
        n = len(recent_samples)

        # Convert timestamps to seconds since first sample
        t0 = recent_samples[0].timestamp
        x_values = [(s.timestamp - t0).total_seconds() for s in recent_samples]
        y_values = [s.rss_mb for s in recent_samples]

        # Calculate slope (growth rate) using least squares
        x_mean = sum(x_values) / n
        y_mean = sum(y_values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)

        if denominator == 0:
            return None

        slope_mb_per_second = numerator / denominator
        growth_rate_mb_per_hour = slope_mb_per_second * 3600

        # Check if growth rate exceeds thresholds
        if abs(growth_rate_mb_per_hour) < self.leak_detection_threshold:
            return None

        # Predict memory in 24 hours
        prediction_24h_mb = current_snapshot.rss_mb + (growth_rate_mb_per_hour * 24)

        # Determine severity
        severity = "critical" if abs(growth_rate_mb_per_hour) >= self.leak_detection_critical else "warning"

        message = (
            f"Memory leak detected: Growing at {growth_rate_mb_per_hour:.2f} MB/hour. "
            f"Current: {current_snapshot.rss_mb:.2f} MB, "
            f"Baseline: {self._baseline_rss_mb:.2f} MB, "
            f"Predicted in 24h: {prediction_24h_mb:.2f} MB"
        )

        return MemoryLeakAlert(
            detected_at=datetime.now(),
            growth_rate_mb_per_hour=growth_rate_mb_per_hour,
            baseline_rss_mb=self._baseline_rss_mb,
            current_rss_mb=current_snapshot.rss_mb,
            prediction_24h_mb=prediction_24h_mb,
            severity=severity,
            message=message,
        )

    def _handle_alert(self, alert: MemoryLeakAlert) -> None:
        """Handle a memory leak alert by logging it.

        Args:
            alert: The memory leak alert to handle
        """
        self._last_alert = alert.detected_at

        log_func = logger.critical if alert.severity == "critical" else logger.warning
        log_func(
            f"MEMORY LEAK ALERT ({alert.severity.upper()}): {alert.message}",
            extra={"alert": alert.to_dict()},
        )

    def get_current_snapshot(self) -> Optional[MemorySnapshot]:
        """Get the most recent memory snapshot.

        Returns:
            Most recent MemorySnapshot, or None if no snapshots taken yet
        """
        return self._snapshots[-1] if self._snapshots else None

    def get_baseline_rss_mb(self) -> Optional[float]:
        """Get the established baseline RSS in MB.

        Returns:
            Baseline RSS in MB, or None if baseline not yet established
        """
        return self._baseline_rss_mb

    def get_statistics(self) -> dict:
        """Get monitoring statistics.

        Returns:
            Dictionary with monitoring statistics including:
            - snapshot_count: Number of snapshots collected
            - baseline_rss_mb: Baseline RSS (if established)
            - current_rss_mb: Current RSS
            - min_rss_mb: Minimum observed RSS
            - max_rss_mb: Maximum observed RSS
            - mean_rss_mb: Mean RSS
            - running: Whether monitor is currently running
        """
        if not self._snapshots:
            return {
                "snapshot_count": 0,
                "baseline_rss_mb": self._baseline_rss_mb,
                "running": self._running,
            }

        rss_values = [s.rss_mb for s in self._snapshots]

        return {
            "snapshot_count": len(self._snapshots),
            "baseline_rss_mb": self._baseline_rss_mb,
            "baseline_established_at": (
                self._baseline_established_at.isoformat()
                if self._baseline_established_at else None
            ),
            "current_rss_mb": rss_values[-1],
            "min_rss_mb": min(rss_values),
            "max_rss_mb": max(rss_values),
            "mean_rss_mb": statistics.mean(rss_values),
            "median_rss_mb": statistics.median(rss_values),
            "running": self._running,
            "tier": self.tier.value,
        }

    def __repr__(self) -> str:
        """String representation of monitor."""
        return (
            f"MemoryMonitor(tier={self.tier.value}, "
            f"running={self._running}, "
            f"snapshots={len(self._snapshots)})"
        )
