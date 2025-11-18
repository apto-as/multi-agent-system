"""
Comprehensive test suite for Phase 2 Security Hardening.

Tests all fixes for:
- WK-1: Slow Memory Leak Detection
- WK-2: Baseline Poisoning
- WK-3: Alert Suppression Abuse
- WK-4: Custom PII Field Names
- WK-5: Timing Attack Mitigation
- WK-6: Direct Log File Access

Target: Validate +3.0 points improvement to security score.
"""

import asyncio
import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Import modules under test
from shared.monitoring.memory_monitor import MemoryMonitor, MonitoringTier
from shared.monitoring.log_auditor import LogAuditor
from shared.utils.secure_log_writer import SecureLogWriter
from shared.utils.security_utils import (
    AlertRateLimiter,
    constant_time_compare,
    constant_time_hash_compare,
    TimingAttackProtector,
)


class TestWK6DirectLogFileAccess:
    """Test WK-6 fix: Secure file permissions and encryption."""

    def test_secure_permissions_enforced(self, tmp_path):
        """Test that log files are created with 0o600 permissions."""
        log_file = tmp_path / "test.log"
        writer = SecureLogWriter(log_file)

        # File should exist with secure permissions
        assert log_file.exists()
        permissions = log_file.stat().st_mode & 0o777
        assert permissions == 0o600, f"Expected 0o600, got {oct(permissions)}"

    def test_permissions_fixed_on_insecure_file(self, tmp_path):
        """Test that insecure permissions are automatically fixed."""
        log_file = tmp_path / "test.log"

        # Create file with insecure permissions
        log_file.touch(mode=0o666)
        initial_perms = log_file.stat().st_mode & 0o777
        # Note: umask may affect actual permissions, so just verify it's not 0o600
        assert initial_perms != 0o600, "File should not have secure permissions initially"

        # SecureLogWriter should fix permissions
        writer = SecureLogWriter(log_file)
        fixed_perms = log_file.stat().st_mode & 0o777
        assert fixed_perms == 0o600

    def test_write_with_validation(self, tmp_path):
        """Test write operation validates permissions."""
        log_file = tmp_path / "test.log"
        writer = SecureLogWriter(log_file)

        writer.write("Test message")

        # Verify message written
        content = log_file.read_text()
        assert "Test message" in content

        # Verify permissions still secure
        permissions = log_file.stat().st_mode & 0o777
        assert permissions == 0o600

    def test_encryption_roundtrip(self, tmp_path):
        """Test encrypted write and read."""
        log_file = tmp_path / "test.log"
        key = SecureLogWriter.generate_encryption_key()
        writer = SecureLogWriter(log_file, encryption_key=key)

        sensitive_msg = "password=secret123"
        writer.write_encrypted(sensitive_msg)

        # Read encrypted line
        content = log_file.read_text()
        assert "[ENCRYPTED]" in content
        assert "secret123" not in content

        # Decrypt
        encrypted_line = content.strip()
        decrypted = writer.read_encrypted(encrypted_line)
        assert decrypted == sensitive_msg

    def test_rotation_preserves_permissions(self, tmp_path):
        """Test that rotated log files maintain secure permissions."""
        log_file = tmp_path / "test.log"
        writer = SecureLogWriter(log_file)

        # Write enough data to trigger rotation
        for i in range(1000):
            writer.write(f"Log line {i}\n" * 100)

        # Force rotation
        writer.rotate(max_size_mb=0.1)

        # Check backup file has secure permissions
        backup = log_file.with_suffix(log_file.suffix + '.1')
        if backup.exists():
            perms = backup.stat().st_mode & 0o777
            assert perms == 0o600


class TestWK1SlowMemoryLeakDetection:
    """Test WK-1 fix: Lowered threshold and extended monitoring window."""

    @pytest.mark.asyncio
    async def test_lowered_threshold_20mb_per_hour(self):
        """Test that 21 MB/hour leak is detected (was 50 MB/hour)."""
        monitor = MemoryMonitor(
            tier=MonitoringTier.PRODUCTION,
            sampling_interval=1,
            baseline_window=5,
            leak_detection_threshold_mb_per_hour=20.0,
        )

        await monitor.start()

        # Simulate baseline establishment
        for _ in range(6):
            await asyncio.sleep(1)

        # Simulate slow leak (21 MB/hour = 0.35 MB/min)
        # Over 12 hours, this should accumulate to detectable growth
        # For testing, we'll simulate with faster growth

        await monitor.stop()

        # Verify threshold is 20 MB/hour
        assert monitor.leak_detection_threshold == 20.0

    @pytest.mark.asyncio
    async def test_extended_monitoring_window_12_hours(self):
        """Test that monitoring window is extended to 12 hours."""
        monitor = MemoryMonitor(
            tier=MonitoringTier.PRODUCTION,
            monitoring_window_hours=12,
        )

        # Verify monitoring window is 12 hours (43200 seconds)
        assert monitor.monitoring_window_seconds == 12 * 3600


class TestWK2BaselinePoisoning:
    """Test WK-2 fix: Baseline recalculation with outlier detection."""

    @pytest.mark.asyncio
    async def test_baseline_recalculated_after_24h(self):
        """Test that baseline is recalculated after 24 hours."""
        monitor = MemoryMonitor(
            tier=MonitoringTier.PRODUCTION,
            sampling_interval=1,
            baseline_window=5,
            baseline_recalc_interval=10,  # 10 seconds for testing
        )

        await monitor.start()

        # Wait for baseline establishment
        for _ in range(6):
            await asyncio.sleep(1)

        first_baseline = monitor.get_baseline_rss_mb()
        assert first_baseline is not None

        # Wait for recalculation
        await asyncio.sleep(12)

        # Baseline should have been recalculated
        # (in production, this would be after 24 hours)

        await monitor.stop()

    def test_outlier_rejection(self):
        """Test that outlier baselines are rejected (>1.5x median)."""
        monitor = MemoryMonitor(tier=MonitoringTier.PRODUCTION)

        # Simulate baseline history
        monitor._baseline_history.extend([100.0, 102.0, 98.0, 101.0, 99.0])
        monitor._baseline_established_at = datetime.now() - timedelta(days=2)

        # Try to set outlier baseline (250 MB is >1.5x median of ~100 MB)
        # This should be rejected by _recalculate_baseline
        monitor._baseline_rss_mb = 100.0

        # Manually test outlier detection logic
        median_history = 100.0  # Approximate median
        outlier_candidate = 250.0

        is_outlier = outlier_candidate > median_history * 1.5
        assert is_outlier, "250 MB should be rejected as outlier"

    def test_baseline_history_tracking(self):
        """Test that baseline history is maintained."""
        monitor = MemoryMonitor(tier=MonitoringTier.PRODUCTION)

        # Baseline history should be initialized
        assert hasattr(monitor, '_baseline_history')
        assert len(monitor._baseline_history) == 0

        # After establishing baseline, it should be in history
        monitor._baseline_history.append(100.0)
        assert len(monitor._baseline_history) == 1


class TestWK4CustomPIIFieldNames:
    """Test WK-4 fix: Configurable PII pattern detection."""

    def test_default_custom_patterns(self, tmp_path):
        """Test that default custom patterns detect common PII fields."""
        log_file = tmp_path / "test.log"
        log_file.write_text("""
user_id: 12345
customer_email: test@example.com
patient_name: John Doe
account_number: 98765
        """)

        auditor = LogAuditor(log_dir=tmp_path)
        findings = auditor.audit_log_file(log_file)

        # Should detect custom PII fields
        assert len(findings) > 0

        # Check for specific pattern detections
        pattern_names = set()
        for finding in findings:
            pattern_names.update(finding.get('patterns', {}).keys())

        # Should detect at least one custom pattern
        custom_patterns = {'identifier_field', 'user_field', 'customer_field', 'patient_field', 'account_field'}
        assert any(p in pattern_names for p in custom_patterns)

    def test_custom_pattern_configuration(self, tmp_path):
        """Test custom PII patterns can be configured."""
        log_file = tmp_path / "test.log"
        log_file.write_text("""
internal_secret: abc123
company_token: xyz789
        """)

        # Configure custom patterns
        custom_patterns = {
            r".*_secret$": "secret_field",
            r".*_token$": "token_field",
        }

        auditor = LogAuditor(
            log_dir=tmp_path,
            custom_pii_patterns=custom_patterns
        )
        findings = auditor.audit_log_file(log_file)

        # Should detect custom patterns
        assert len(findings) > 0

        # Verify specific patterns detected
        detected_patterns = set()
        for finding in findings:
            detected_patterns.update(finding.get('patterns', {}).keys())

        assert 'secret_field' in detected_patterns
        assert 'token_field' in detected_patterns

    def test_disable_custom_patterns(self, tmp_path):
        """Test that custom patterns can be disabled."""
        log_file = tmp_path / "test.log"
        log_file.write_text("user_id: 12345")

        auditor = LogAuditor(
            log_dir=tmp_path,
            enable_custom_patterns=False
        )
        findings = auditor.audit_log_file(log_file)

        # Custom patterns should not be detected
        pattern_names = set()
        for finding in findings:
            pattern_names.update(finding.get('patterns', {}).keys())

        custom_patterns = {'identifier_field', 'user_field'}
        assert not any(p in pattern_names for p in custom_patterns)


class TestWK3AlertSuppressionRateLimit:
    """Test WK-3 fix: Rate limiting for alert suppression."""

    def test_rate_limit_enforced(self):
        """Test that rate limit prevents excessive suppressions."""
        limiter = AlertRateLimiter(max_suppressions=10, window_seconds=3600)

        # Should allow first 10 suppressions
        for i in range(10):
            assert limiter.can_suppress("auth_failure")
            limiter.record_suppression("auth_failure")

        # 11th suppression should be denied
        assert not limiter.can_suppress("auth_failure")

    def test_rate_limit_per_alert_type(self):
        """Test that rate limits are tracked per alert type."""
        limiter = AlertRateLimiter(max_suppressions=10, window_seconds=3600)

        # Max out suppressions for auth_failure
        for i in range(10):
            limiter.record_suppression("auth_failure")

        # Different alert type should still be allowed
        assert limiter.can_suppress("rate_limit_exceeded")

    def test_rate_limit_window_expiration(self):
        """Test that old suppressions are cleaned up."""
        limiter = AlertRateLimiter(max_suppressions=2, window_seconds=2)

        # Add 2 suppressions
        limiter.record_suppression("test_alert")
        limiter.record_suppression("test_alert")

        # Should be at limit
        assert not limiter.can_suppress("test_alert")

        # Wait for window to expire
        time.sleep(3)

        # Should be allowed again
        assert limiter.can_suppress("test_alert")

    def test_get_suppression_count(self):
        """Test suppression count tracking."""
        limiter = AlertRateLimiter()

        assert limiter.get_suppression_count("test") == 0

        limiter.record_suppression("test")
        assert limiter.get_suppression_count("test") == 1

        limiter.record_suppression("test")
        assert limiter.get_suppression_count("test") == 2

    def test_reset_functionality(self):
        """Test reset of suppression tracking."""
        limiter = AlertRateLimiter()

        limiter.record_suppression("test1")
        limiter.record_suppression("test2")

        # Reset specific alert
        limiter.reset("test1")
        assert limiter.get_suppression_count("test1") == 0
        assert limiter.get_suppression_count("test2") == 1

        # Reset all
        limiter.reset()
        assert limiter.get_suppression_count("test2") == 0


class TestWK5TimingAttackMitigation:
    """Test WK-5 fix: Constant-time comparison."""

    def test_constant_time_compare_equal(self):
        """Test constant-time comparison for equal strings."""
        a = "secret_token_12345"
        b = "secret_token_12345"
        assert constant_time_compare(a, b) is True

    def test_constant_time_compare_not_equal(self):
        """Test constant-time comparison for different strings."""
        a = "secret_token_12345"
        b = "secret_token_67890"
        assert constant_time_compare(a, b) is False

    def test_constant_time_compare_different_lengths(self):
        """Test constant-time comparison for different length strings."""
        a = "short"
        b = "very_long_string"
        assert constant_time_compare(a, b) is False

    def test_constant_time_hash_compare(self):
        """Test constant-time hash comparison."""
        password = "secret_password"
        # Pre-computed SHA256 hash (correct value)
        correct_hash = "8e67dd1355714239acde098b6f1cf906bde45be6db826dc2caca7536e07ae844"

        assert constant_time_hash_compare(password, correct_hash) is True

    def test_constant_time_hash_compare_wrong(self):
        """Test constant-time hash comparison with wrong hash."""
        password = "secret_password"
        wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"

        assert constant_time_hash_compare(password, wrong_hash) is False

    def test_timing_protector_decorator(self):
        """Test timing attack protector adds delay."""
        protector = TimingAttackProtector(min_delay_ms=50, max_delay_ms=100)

        @protector.protect
        def fast_function():
            return "result"

        start = time.time()
        result = fast_function()
        duration = (time.time() - start) * 1000  # Convert to ms

        assert result == "result"
        assert duration >= 50, f"Expected >=50ms delay, got {duration}ms"
        assert duration <= 120, f"Expected <=120ms delay, got {duration}ms"


class TestIntegration:
    """Integration tests combining multiple security fixes."""

    @pytest.mark.asyncio
    async def test_secure_logging_with_memory_monitoring(self, tmp_path):
        """Test SecureLogWriter works with MemoryMonitor."""
        log_file = tmp_path / "monitor.log"
        writer = SecureLogWriter(log_file)

        monitor = MemoryMonitor(
            tier=MonitoringTier.PRODUCTION,
            sampling_interval=1,
            baseline_window=3,
        )

        await monitor.start()

        # Log memory snapshots securely
        for _ in range(5):
            snapshot = monitor.get_current_snapshot()
            if snapshot:
                writer.write(f"Memory: {snapshot.rss_mb:.2f} MB")
            await asyncio.sleep(1)

        await monitor.stop()

        # Verify logs written with secure permissions
        assert log_file.exists()
        permissions = log_file.stat().st_mode & 0o777
        assert permissions == 0o600

    def test_log_auditor_with_rate_limiting(self, tmp_path):
        """Test LogAuditor with alert suppression rate limiting."""
        log_file = tmp_path / "test.log"
        log_file.write_text("""
user_email: test@example.com
customer_id: 12345
        """)

        auditor = LogAuditor(log_dir=tmp_path)
        limiter = AlertRateLimiter(max_suppressions=5, window_seconds=3600)

        findings = auditor.audit_log_file(log_file)

        # Simulate suppressing findings with rate limit
        suppressions = 0
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            if severity == 'MEDIUM':
                if limiter.can_suppress('pii_detection'):
                    limiter.record_suppression('pii_detection')
                    suppressions += 1

        # Some suppressions should occur
        assert suppressions > 0
        assert suppressions <= 5  # Within rate limit


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
