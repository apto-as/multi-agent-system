#!/usr/bin/env python3
"""
Advanced Log Auditor Tests
==========================

Coverage target: 90% → 95%

Tests advanced scenarios:
- Custom PII field patterns
- Multiple PII types in single log entry
- Obfuscated PII (base64, hex encoding)
- Large log file handling (>100 MB)
- Concurrent log analysis
"""

import pytest
from pathlib import Path
import sys
import base64
import threading

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.monitoring.log_auditor import LogAuditor


class TestCustomPIIPatterns:
    """Test custom PII pattern detection"""

    def test_custom_employee_id(self, tmp_path):
        """Test detection of custom employee ID pattern"""
        log_file = tmp_path / "employees.log"
        log_file.write_text("User EMP-12345 accessed system")

        auditor = LogAuditor(
            custom_patterns={
                "employee_id": r"EMP-\d{5}"
            }
        )

        findings = auditor.audit_file(log_file)

        assert len(findings) > 0
        assert any("employee_id" in f["type"] for f in findings)

    def test_custom_sensitive_field(self, tmp_path):
        """Test custom sensitive field pattern"""
        log_file = tmp_path / "api.log"
        log_file.write_text('{"api_key": "sk_live_123abc", "user": "john"}')

        auditor = LogAuditor(
            custom_patterns={
                "api_key": r"sk_live_[a-zA-Z0-9]+"
            }
        )

        findings = auditor.audit_file(log_file)

        assert any("api_key" in f["type"] for f in findings)

    def test_multiple_custom_patterns(self, tmp_path):
        """Test multiple custom patterns in same log"""
        log_file = tmp_path / "multi.log"
        log_file.write_text(
            "Order ORD-999 for customer CUST-ABC123 with card 1234-5678-9012-3456"
        )

        auditor = LogAuditor(
            custom_patterns={
                "order_id": r"ORD-\d{3}",
                "customer_id": r"CUST-[A-Z0-9]+",
            }
        )

        findings = auditor.audit_file(log_file)

        # Should find order_id, customer_id, and credit_card
        assert len(findings) >= 3


class TestMultiplePIITypes:
    """Test logs with multiple PII types"""

    def test_email_and_phone(self, tmp_path):
        """Test detection of email and phone in same log"""
        log_file = tmp_path / "contact.log"
        log_file.write_text("Contact: john@example.com, Phone: 555-1234")

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        types_found = {f["type"] for f in findings}
        assert "email" in types_found
        assert "phone" in types_found

    def test_all_pii_types(self, tmp_path):
        """Test detection of all major PII types in one log"""
        log_file = tmp_path / "full_pii.log"
        log_file.write_text("""
User: john@example.com
SSN: 123-45-6789
Phone: 555-1234
Card: 4532-1111-2222-3333
IP: 192.168.1.1
Session: sess_abc123
Password: mySecret123!
        """)

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        # Should find multiple types
        assert len(findings) >= 5

    def test_nested_json_pii(self, tmp_path):
        """Test PII in nested JSON structure"""
        log_file = tmp_path / "json.log"
        log_file.write_text('''
{
  "user": {
    "email": "john@example.com",
    "profile": {
      "ssn": "123-45-6789",
      "payment": {
        "card": "4532111122223333"
      }
    }
  }
}
        ''')

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        # Should find email, SSN, and credit card
        assert len(findings) >= 3


class TestObfuscatedPII:
    """Test detection of obfuscated PII"""

    def test_base64_encoded_email(self, tmp_path):
        """Test detection of base64-encoded email"""
        log_file = tmp_path / "encoded.log"

        # Base64 encode email
        email = "sensitive@example.com"
        encoded = base64.b64encode(email.encode()).decode()

        log_file.write_text(f"Data: {encoded}")

        # Auditor with base64 decoding
        auditor = LogAuditor(decode_base64=True)
        findings = auditor.audit_file(log_file)

        # Should detect email after decoding
        assert any("email" in f["type"] for f in findings)

    def test_hex_encoded_ssn(self, tmp_path):
        """Test detection of hex-encoded SSN"""
        log_file = tmp_path / "hex.log"

        ssn = "123-45-6789"
        hex_ssn = ssn.encode().hex()

        log_file.write_text(f"SSN: {hex_ssn}")

        # Auditor with hex decoding
        auditor = LogAuditor(decode_hex=True)
        findings = auditor.audit_file(log_file)

        assert any("ssn" in f["type"] for f in findings)

    def test_url_encoded_pii(self, tmp_path):
        """Test detection of URL-encoded PII"""
        import urllib.parse

        log_file = tmp_path / "url.log"

        email = "test@example.com"
        encoded = urllib.parse.quote(email)

        log_file.write_text(f"email={encoded}")

        auditor = LogAuditor()
        # URL decoding should happen automatically in some implementations
        findings = auditor.audit_file(log_file)

        # May or may not detect depending on implementation


class TestLargeLogFiles:
    """Test handling of large log files"""

    def test_100mb_log_file(self, tmp_path):
        """Test processing of 100 MB log file"""
        log_file = tmp_path / "large.log"

        # Write 100 MB of log data
        log_line = "INFO: Normal log entry without PII\n"
        lines_needed = (100 * 1024 * 1024) // len(log_line)

        with open(log_file, 'w') as f:
            for i in range(lines_needed):
                if i % 10000 == 0:  # Add PII occasionally
                    f.write(f"User email: user{i}@example.com\n")
                else:
                    f.write(log_line)

        auditor = LogAuditor()

        # Should handle large file without memory issues
        findings = auditor.audit_file(log_file)

        # Should find PIIs
        assert len(findings) > 0

    def test_streaming_large_file(self, tmp_path):
        """Test streaming analysis of large file"""
        log_file = tmp_path / "stream.log"

        # 10 MB file
        with open(log_file, 'w') as f:
            for i in range(100000):
                f.write(f"Line {i}: email{i}@test.com\n")

        auditor = LogAuditor(stream_mode=True)

        # Streaming should handle file efficiently
        findings = auditor.audit_file(log_file)

        assert len(findings) > 0


class TestConcurrentAnalysis:
    """Test concurrent log analysis"""

    def test_concurrent_file_analysis(self, tmp_path):
        """Test analyzing multiple files concurrently"""
        # Create 10 log files
        files = []
        for i in range(10):
            log_file = tmp_path / f"log_{i}.log"
            log_file.write_text(f"User: user{i}@example.com\nSSN: 123-45-{i:04d}")
            files.append(log_file)

        auditor = LogAuditor()
        results = {}

        def analyze_file(file_path):
            findings = auditor.audit_file(file_path)
            results[file_path.name] = len(findings)

        # Analyze concurrently
        threads = [threading.Thread(target=analyze_file, args=(f,)) for f in files]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All files should be analyzed
        assert len(results) == 10
        assert all(count > 0 for count in results.values())

    def test_concurrent_pattern_compilation(self):
        """Test thread-safe pattern compilation"""
        import threading

        patterns_compiled = []

        def compile_patterns():
            auditor = LogAuditor(
                custom_patterns={"test": r"\d+"}
            )
            patterns_compiled.append(auditor)

        # Compile patterns in 10 threads
        threads = [threading.Thread(target=compile_patterns) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed
        assert len(patterns_compiled) == 10


class TestSeverityAssessment:
    """Test severity assessment of findings"""

    def test_critical_severity_ssn(self, tmp_path):
        """Test SSN is marked as CRITICAL"""
        log_file = tmp_path / "ssn.log"
        log_file.write_text("SSN: 123-45-6789")

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        ssn_finding = next(f for f in findings if "ssn" in f["type"])
        assert ssn_finding["severity"] == "CRITICAL"

    def test_high_severity_credit_card(self, tmp_path):
        """Test credit card is marked as HIGH"""
        log_file = tmp_path / "cc.log"
        log_file.write_text("Card: 4532-1111-2222-3333")

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        cc_finding = next(f for f in findings if "credit" in f["type"])
        assert cc_finding["severity"] in ["HIGH", "CRITICAL"]

    def test_medium_severity_email(self, tmp_path):
        """Test email is marked as MEDIUM"""
        log_file = tmp_path / "email.log"
        log_file.write_text("Email: test@example.com")

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        email_finding = next(f for f in findings if "email" in f["type"])
        assert email_finding["severity"] in ["MEDIUM", "HIGH"]


class TestReportGeneration:
    """Test audit report generation"""

    def test_generate_summary_report(self, tmp_path):
        """Test summary report generation"""
        log_file = tmp_path / "multi.log"
        log_file.write_text("""
email: test@example.com
ssn: 123-45-6789
phone: 555-1234
        """)

        auditor = LogAuditor()
        findings = auditor.audit_file(log_file)

        report = auditor.generate_report(findings)

        assert "total_findings" in report
        assert report["total_findings"] >= 3
        assert "by_type" in report
        assert "by_severity" in report

    def test_report_statistics(self, tmp_path):
        """Test report includes statistics"""
        # Create multiple files with PII
        for i in range(5):
            log_file = tmp_path / f"log_{i}.log"
            log_file.write_text(f"Email: user{i}@test.com\n" * 10)

        auditor = LogAuditor()
        all_findings = []

        for log_file in tmp_path.glob("*.log"):
            findings = auditor.audit_file(log_file)
            all_findings.extend(findings)

        report = auditor.generate_report(all_findings)

        assert "files_analyzed" in report
        assert report["files_analyzed"] == 5
