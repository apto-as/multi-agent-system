"""
Tests for Log Auditor (CWE-532 Prevention).
"""
import pytest
from pathlib import Path
import tempfile
from shared.monitoring.log_auditor import LogAuditor


class TestLogAuditor:
    """Test suite for LogAuditor."""

    @pytest.fixture
    def temp_log_dir(self):
        """Create temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_detect_aws_access_key(self, temp_log_dir):
        """Test AWS access key detection (CRITICAL)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "aws_access_key" in findings[0]["patterns"]

    def test_detect_aws_secret_key(self, temp_log_dir):
        """Test AWS secret key detection (CRITICAL)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_detect_bearer_token(self, temp_log_dir):
        """Test Bearer token detection (HIGH)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert "bearer_token" in findings[0]["patterns"]

    def test_detect_database_password(self, temp_log_dir):
        """Test database password detection (CRITICAL)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("db_password=secret123\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_detect_connection_string(self, temp_log_dir):
        """Test database connection string detection (MEDIUM)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("DB: postgresql://user:pass@localhost/db\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert "connection_string" in findings[0]["patterns"]

    def test_detect_email(self, temp_log_dir):
        """Test email detection (MEDIUM)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("User: alice@example.com logged in\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert "email" in findings[0]["patterns"]

    def test_detect_phone_number(self, temp_log_dir):
        """Test phone number detection (MEDIUM)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("Contact: +1-555-123-4567\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    def test_detect_ip_address(self, temp_log_dir):
        """Test IP address detection (LOW)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("Request from 192.168.1.1\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "LOW"
        assert "ip_address" in findings[0]["patterns"]

    def test_detect_session_id(self, temp_log_dir):
        """Test session ID detection (HIGH)."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("session_id=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_audit_all_logs(self, temp_log_dir):
        """Test scanning all log files in directory."""
        # Create multiple log files
        (temp_log_dir / "app.log").write_text("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        (temp_log_dir / "error.log").write_text("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\n")
        (temp_log_dir / "debug.log").write_text("User alice@example.com logged in\n")

        auditor = LogAuditor(temp_log_dir)
        result = auditor.audit_all_logs()

        assert result["status"] == "success"
        assert result["total_files"] == 3
        assert result["total_findings"] == 3
        assert result["summary"]["CRITICAL"] == 1
        assert result["summary"]["HIGH"] == 1
        assert result["summary"]["MEDIUM"] == 1

    def test_empty_directory(self, temp_log_dir):
        """Test empty directory handling."""
        auditor = LogAuditor(temp_log_dir)
        result = auditor.audit_all_logs()

        assert result["status"] == "success"
        assert result["total_files"] == 0
        assert result["total_findings"] == 0

    def test_nonexistent_directory(self):
        """Test nonexistent directory error."""
        auditor = LogAuditor(Path("/nonexistent/path"))
        result = auditor.audit_all_logs()

        assert result["status"] == "error"
        assert "not found" in result["message"]

    def test_generate_report(self, temp_log_dir):
        """Test report generation."""
        (temp_log_dir / "test.log").write_text("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")

        auditor = LogAuditor(temp_log_dir)
        report = auditor.generate_report()

        assert "LOG SECURITY AUDIT REPORT" in report
        assert "CRITICAL" in report
        assert "aws_access_key" in report

    def test_multiple_patterns_same_line(self, temp_log_dir):
        """Test multiple sensitive patterns on same line."""
        log_file = temp_log_dir / "test.log"
        log_file.write_text("User alice@example.com with API key AKIAIOSFODNN7EXAMPLE\n")

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"  # Highest severity wins
        assert len(findings[0]["patterns"]) >= 2  # Both email and AWS key

    def test_severity_assessment(self, temp_log_dir):
        """Test severity assessment with mixed patterns."""
        log_file = temp_log_dir / "test.log"
        # Line 1: CRITICAL (AWS key)
        # Line 2: MEDIUM (email)
        # Line 3: LOW (IP)
        log_file.write_text(
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "User alice@example.com\n"
            "From 192.168.1.1\n"
        )

        auditor = LogAuditor(temp_log_dir)
        findings = auditor.audit_log_file(log_file)

        # Should have 3 findings with different severities
        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities
        assert "MEDIUM" in severities
        assert "LOW" in severities
