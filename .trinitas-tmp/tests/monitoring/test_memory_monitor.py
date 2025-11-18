"""Tests for MemoryMonitor class.

This test suite validates the production-ready memory monitoring implementation
with <0.5% overhead and linear regression-based leak detection.

Test Categories:
    - Baseline establishment (5 tests)
    - Leak detection algorithm (6 tests)
    - Alert thresholds (5 tests)
    - Performance overhead (3 tests)
    - Async lifecycle (2 tests)

Total: 21 tests
"""

import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from shared.monitoring.memory_monitor import (
    MemoryLeakAlert,
    MemoryMonitor,
    MemorySnapshot,
    MonitoringTier,
)


# --- Baseline Establishment Tests (5 tests) ---

@pytest.mark.asyncio
async def test_baseline_establishment_requires_5_minutes():
    """Test that baseline requires 5-minute duration."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=10,  # 10 seconds for testing
    )

    await monitor.start()

    # Wait for less than baseline_window
    await asyncio.sleep(2)

    # Baseline should not be established yet
    assert monitor.get_baseline_rss_mb() is None

    # Wait for full baseline_window
    await asyncio.sleep(9)

    # Baseline should now be established
    baseline = monitor.get_baseline_rss_mb()
    assert baseline is not None
    assert baseline > 0

    await monitor.stop()


@pytest.mark.asyncio
async def test_baseline_uses_median_of_samples():
    """Test that baseline is calculated as median of samples."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=5,
    )

    # Manually add snapshots
    now = datetime.now()
    monitor._snapshots.extend([
        MemorySnapshot(timestamp=now, rss_mb=100.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now, rss_mb=150.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now, rss_mb=120.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=5), rss_mb=130.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=5), rss_mb=110.0, vms_mb=200.0, percent=10.0),
    ])

    # Manually trigger baseline establishment
    monitor._try_establish_baseline()

    # Median of [100, 150, 120, 130, 110] = 120
    baseline = monitor.get_baseline_rss_mb()
    assert baseline == 120.0


@pytest.mark.asyncio
async def test_baseline_requires_minimum_5_snapshots():
    """Test that baseline requires at least 5 snapshots."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=10,
    )

    # Add only 4 snapshots
    now = datetime.now()
    monitor._snapshots.extend([
        MemorySnapshot(timestamp=now, rss_mb=100.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=3), rss_mb=105.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=6), rss_mb=110.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=10), rss_mb=115.0, vms_mb=200.0, percent=10.0),
    ])

    # Try to establish baseline
    monitor._try_establish_baseline()

    # Should not be established (need 5+ snapshots)
    assert monitor.get_baseline_rss_mb() is None


@pytest.mark.asyncio
async def test_baseline_not_established_before_window():
    """Test that baseline is not established before baseline_window."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=20,
    )

    # Add snapshots within 10 seconds (less than 20-second window)
    now = datetime.now()
    monitor._snapshots.extend([
        MemorySnapshot(timestamp=now, rss_mb=100.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=2), rss_mb=105.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=4), rss_mb=110.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=6), rss_mb=115.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=10), rss_mb=120.0, vms_mb=200.0, percent=10.0),
    ])

    # Try to establish baseline
    monitor._try_establish_baseline()

    # Should not be established (duration < baseline_window)
    assert monitor.get_baseline_rss_mb() is None


@pytest.mark.asyncio
async def test_baseline_logs_establishment():
    """Test that baseline establishment is logged."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=5,
    )

    # Add sufficient snapshots
    now = datetime.now()
    monitor._snapshots.extend([
        MemorySnapshot(timestamp=now, rss_mb=100.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=1), rss_mb=105.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=2), rss_mb=110.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=3), rss_mb=115.0, vms_mb=200.0, percent=10.0),
        MemorySnapshot(timestamp=now + timedelta(seconds=5), rss_mb=120.0, vms_mb=200.0, percent=10.0),
    ])

    # Trigger baseline establishment
    with patch('shared.monitoring.memory_monitor.logger') as mock_logger:
        monitor._try_establish_baseline()

        # Verify logging
        mock_logger.info.assert_called_once()
        log_message = mock_logger.info.call_args[0][0]
        assert "Baseline established" in log_message
        assert "110.00 MB" in log_message  # Median value


# --- Leak Detection Algorithm Tests (6 tests) ---

@pytest.mark.asyncio
async def test_leak_detection_linear_regression():
    """Test leak detection using linear regression."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=10.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with linear growth (10 MB/hour)
    for i in range(15):
        timestamp = now + timedelta(seconds=i * 2)
        # 10 MB/hour = 0.166 MB/min = 0.00278 MB/sec
        rss_mb = 100.0 + (i * 2 * 0.00278)
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Should detect leak (growth rate >= 10 MB/hour)
    assert alert is not None
    assert alert.severity in ("warning", "critical")
    assert alert.growth_rate_mb_per_hour > 0


@pytest.mark.asyncio
async def test_leak_detection_requires_10_samples():
    """Test that leak detection requires at least 10 samples."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
    )

    # Establish baseline
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = datetime.now()

    # Add only 5 snapshots
    now = datetime.now()
    for i in range(5):
        monitor._snapshots.append(
            MemorySnapshot(
                timestamp=now + timedelta(seconds=i),
                rss_mb=100.0 + i * 10,  # Rapid growth
                vms_mb=200.0,
                percent=10.0
            )
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Should not detect leak (insufficient samples)
    assert alert is None


@pytest.mark.asyncio
async def test_leak_detection_throttles_alerts():
    """Test that alerts are throttled to max 1 per hour."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=10.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with high growth
    for i in range(15):
        monitor._snapshots.append(
            MemorySnapshot(
                timestamp=now + timedelta(seconds=i * 2),
                rss_mb=100.0 + i * 10,  # Rapid growth
                vms_mb=200.0,
                percent=10.0
            )
        )

    # First check - should alert
    current_snapshot = monitor._snapshots[-1]
    alert1 = monitor._check_for_leak(current_snapshot)
    assert alert1 is not None

    # Set last alert time
    monitor._last_alert = datetime.now()

    # Second check - should be throttled
    alert2 = monitor._check_for_leak(current_snapshot)
    assert alert2 is None


@pytest.mark.asyncio
async def test_leak_detection_growth_rate_calculation():
    """Test accuracy of growth rate calculation."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=60,
        leak_detection_threshold_mb_per_hour=50.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with known growth rate (100 MB/hour)
    # 100 MB/hour = 1.667 MB/min = 0.02778 MB/sec
    for i in range(20):
        timestamp = now + timedelta(seconds=i * 3)
        rss_mb = 100.0 + (i * 3 * 0.02778)
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Verify growth rate is approximately 100 MB/hour
    assert alert is not None
    assert 90 < alert.growth_rate_mb_per_hour < 110  # Allow 10% tolerance


@pytest.mark.asyncio
async def test_leak_detection_24h_prediction():
    """Test 24-hour memory prediction calculation."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=50.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with 100 MB/hour growth
    for i in range(15):
        timestamp = now + timedelta(seconds=i * 2)
        rss_mb = 100.0 + (i * 2 * 0.02778)  # 100 MB/hour
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # 24h prediction should be current + (100 MB/hour * 24 hours)
    assert alert is not None
    expected_24h = current_snapshot.rss_mb + (100 * 24)
    assert abs(alert.prediction_24h_mb - expected_24h) < 200  # Allow tolerance


@pytest.mark.asyncio
async def test_leak_detection_no_false_positives():
    """Test that stable memory doesn't trigger false positives."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=50.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with minimal/no growth (noise only)
    import random
    for i in range(20):
        timestamp = now + timedelta(seconds=i * 2)
        # Add small random noise (+/- 1 MB)
        rss_mb = 100.0 + random.uniform(-1.0, 1.0)
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Should not trigger alert for stable memory
    assert alert is None


# --- Alert Threshold Tests (5 tests) ---

@pytest.mark.asyncio
async def test_snapshot_warning_threshold_256mb():
    """Test warning alert at 256MB RSS threshold."""
    snapshot = MemorySnapshot(
        timestamp=datetime.now(),
        rss_mb=260.0,
        vms_mb=400.0,
        percent=25.0
    )

    assert snapshot.is_warning() is True
    assert snapshot.is_critical() is False


@pytest.mark.asyncio
async def test_snapshot_critical_threshold_512mb():
    """Test critical alert at 512MB RSS threshold."""
    snapshot = MemorySnapshot(
        timestamp=datetime.now(),
        rss_mb=520.0,
        vms_mb=800.0,
        percent=50.0
    )

    assert snapshot.is_critical() is True
    assert snapshot.is_warning() is True  # Critical is also warning


@pytest.mark.asyncio
async def test_growth_rate_warning_50mb_per_hour():
    """Test warning severity at 50 MB/hour growth rate."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=50.0,
        leak_detection_critical_mb_per_hour=100.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with 55 MB/hour growth (above warning, below critical)
    for i in range(15):
        timestamp = now + timedelta(seconds=i * 2)
        rss_mb = 100.0 + (i * 2 * 0.01528)  # 55 MB/hour
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Should be warning severity
    assert alert is not None
    assert alert.severity == "warning"


@pytest.mark.asyncio
async def test_growth_rate_critical_100mb_per_hour():
    """Test critical severity at 100 MB/hour growth rate."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=50.0,
        leak_detection_critical_mb_per_hour=100.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with 110 MB/hour growth (above critical)
    for i in range(15):
        timestamp = now + timedelta(seconds=i * 2)
        rss_mb = 100.0 + (i * 2 * 0.03056)  # 110 MB/hour
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Should be critical severity
    assert alert is not None
    assert alert.severity == "critical"


@pytest.mark.asyncio
async def test_alert_message_includes_key_metrics():
    """Test that alert messages include all key metrics."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
        baseline_window=30,
        leak_detection_threshold_mb_per_hour=50.0,
    )

    # Establish baseline
    now = datetime.now()
    monitor._baseline_rss_mb = 100.0
    monitor._baseline_established_at = now

    # Add snapshots with growth
    for i in range(15):
        timestamp = now + timedelta(seconds=i * 2)
        rss_mb = 100.0 + (i * 2 * 0.03056)  # 110 MB/hour
        monitor._snapshots.append(
            MemorySnapshot(timestamp=timestamp, rss_mb=rss_mb, vms_mb=200.0, percent=10.0)
        )

    # Check for leak
    current_snapshot = monitor._snapshots[-1]
    alert = monitor._check_for_leak(current_snapshot)

    # Verify alert message includes key metrics
    assert alert is not None
    assert "MB/hour" in alert.message
    assert "Current:" in alert.message
    assert "Baseline:" in alert.message
    assert "Predicted in 24h:" in alert.message


# --- Performance Overhead Tests (3 tests) ---

@pytest.mark.asyncio
async def test_production_tier_low_overhead():
    """Test that production tier has <0.5% CPU overhead."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=0.1,  # Fast sampling for test
    )

    # Measure baseline CPU usage
    import psutil
    process = psutil.Process()
    cpu_before = process.cpu_percent(interval=1.0)

    # Start monitoring
    await monitor.start()

    # Let it run for 5 seconds
    await asyncio.sleep(5)

    # Measure CPU usage during monitoring
    cpu_during = process.cpu_percent(interval=1.0)

    # Stop monitoring
    await monitor.stop()

    # CPU overhead should be minimal (<0.5% additional)
    overhead_percent = cpu_during - cpu_before
    assert overhead_percent < 0.5, f"CPU overhead too high: {overhead_percent}%"


@pytest.mark.asyncio
async def test_memory_overhead_under_2mb():
    """Test that monitor's own memory overhead is <2MB."""
    import psutil
    process = psutil.Process()

    # Measure baseline memory
    mem_before = process.memory_info().rss / (1024 * 1024)

    # Create monitor
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
    )

    # Start monitoring
    await monitor.start()
    await asyncio.sleep(5)

    # Measure memory after
    mem_after = process.memory_info().rss / (1024 * 1024)

    await monitor.stop()

    # Monitor overhead should be <2MB
    overhead_mb = mem_after - mem_before
    assert overhead_mb < 2.0, f"Memory overhead too high: {overhead_mb} MB"


@pytest.mark.asyncio
async def test_snapshot_collection_performance():
    """Test that snapshot collection is fast (<1ms)."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
    )

    await monitor.start()
    await asyncio.sleep(2)  # Let process initialize

    # Time 100 snapshot collections
    start_time = time.perf_counter()
    for _ in range(100):
        monitor._take_snapshot()
    end_time = time.perf_counter()

    await monitor.stop()

    # Average time per snapshot should be <1ms
    avg_time_ms = ((end_time - start_time) / 100) * 1000
    assert avg_time_ms < 1.0, f"Snapshot collection too slow: {avg_time_ms} ms"


# --- Async Lifecycle Tests (2 tests) ---

@pytest.mark.asyncio
async def test_start_stop_lifecycle():
    """Test proper start and stop lifecycle."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
    )

    # Initially not running
    assert monitor._running is False

    # Start monitoring
    await monitor.start()
    assert monitor._running is True
    assert monitor._task is not None

    # Stop monitoring
    await monitor.stop()
    assert monitor._running is False
    assert monitor._task is None


@pytest.mark.asyncio
async def test_double_start_raises_error():
    """Test that starting an already running monitor raises error."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.PRODUCTION,
        sampling_interval=1,
    )

    await monitor.start()

    # Try to start again - should raise RuntimeError
    with pytest.raises(RuntimeError, match="already running"):
        await monitor.start()

    await monitor.stop()


# --- Additional Tests ---

@pytest.mark.asyncio
async def test_disabled_tier_no_monitoring():
    """Test that DISABLED tier performs no monitoring."""
    monitor = MemoryMonitor(
        tier=MonitoringTier.DISABLED,
        sampling_interval=1,
    )

    # Start should complete but not actually monitor
    await monitor.start()
    await asyncio.sleep(2)

    # No snapshots should be collected
    assert len(monitor._snapshots) == 0

    await monitor.stop()


@pytest.mark.asyncio
async def test_development_tier_enables_tracemalloc():
    """Test that DEVELOPMENT tier enables tracemalloc."""
    import tracemalloc

    # Stop tracemalloc if running
    if tracemalloc.is_tracing():
        tracemalloc.stop()

    monitor = MemoryMonitor(
        tier=MonitoringTier.DEVELOPMENT,
        sampling_interval=1,
    )

    # Tracemalloc should be enabled
    assert tracemalloc.is_tracing() is True

    await monitor.start()
    await asyncio.sleep(2)

    # Snapshots should include tracemalloc data
    snapshot = monitor.get_current_snapshot()
    assert snapshot is not None
    assert snapshot.tracemalloc_current is not None
    assert snapshot.tracemalloc_peak is not None

    await monitor.stop()
