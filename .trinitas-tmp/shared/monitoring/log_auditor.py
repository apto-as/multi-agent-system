"""
Log Audit Tool - Scan logs for sensitive data exposure (CWE-532).

This module provides automated scanning of log files to detect sensitive
data that should not be logged, including:
- AWS/Azure/GCP cloud credentials
- Database passwords and connection strings
- Session IDs and authentication tokens
- Personal Identifiable Information (PII)
- WK-4: Custom PII field patterns (configurable)

Security References:
- CWE-532: Insertion of Sensitive Information into Log File
- OWASP Logging Cheat Sheet
- WK-4: Custom PII Field Names weakness
"""
import re
from pathlib import Path
from typing import List, Dict, Optional, Pattern
from shared.utils.secure_logging import detect_sensitive_data


class LogAuditor:
    """Audit log files for sensitive data exposure with configurable PII patterns."""

    SEVERITY_MAP = {
        # Critical: Cloud credentials and secrets
        "aws_access_key": "CRITICAL",
        "aws_secret_key": "CRITICAL",
        "azure_key": "CRITICAL",
        "gcp_key": "CRITICAL",
        "password": "CRITICAL",
        "database_password": "CRITICAL",

        # High: Authentication tokens
        "bearer_token": "HIGH",
        "basic_auth": "HIGH",
        "jwt": "HIGH",
        "session_id": "HIGH",
        "csrf_token": "HIGH",
        "api_key": "HIGH",

        # Medium: PII and connection info
        "email": "MEDIUM",
        "phone": "MEDIUM",
        "ssn": "MEDIUM",
        "connection_string": "MEDIUM",
        "credit_card": "CRITICAL",  # Credit cards are critical

        # Low: Network information
        "ip_address": "LOW",

        # WK-4: Custom PII patterns (default severity: MEDIUM)
        "custom_pii": "MEDIUM",
    }

    # WK-4: Default custom PII field patterns
    DEFAULT_CUSTOM_PATTERNS = {
        r".*_id$": "identifier_field",  # user_id, customer_id, etc.
        r"user_.*": "user_field",  # user_email, user_phone, etc.
        r"customer_.*": "customer_field",  # customer_name, customer_address, etc.
        r"patient_.*": "patient_field",  # patient_name, patient_ssn, etc.
        r"account_.*": "account_field",  # account_number, account_balance, etc.
    }

    def __init__(
        self,
        log_dir: Optional[Path] = None,
        custom_pii_patterns: Optional[Dict[str, str]] = None,
        enable_custom_patterns: bool = True,
    ):
        """
        Initialize log auditor with configurable PII patterns (WK-4 fix).

        Args:
            log_dir: Directory containing log files (default: ./logs)
            custom_pii_patterns: Dict of regex patterns to pattern names
                                 Example: {r".*_token$": "token_field"}
            enable_custom_patterns: Whether to enable custom pattern detection

        Example:
            >>> auditor = LogAuditor(
            ...     custom_pii_patterns={
            ...         r".*_secret$": "secret_field",
            ...         r"patient_.*": "patient_data"
            ...     }
            ... )
        """
        self.log_dir = log_dir or Path("logs")
        self.findings = []
        self.enable_custom_patterns = enable_custom_patterns

        # WK-4: Compile custom PII patterns
        self.custom_patterns: Dict[Pattern, str] = {}
        if enable_custom_patterns:
            patterns_to_compile = custom_pii_patterns or self.DEFAULT_CUSTOM_PATTERNS
            for pattern_str, pattern_name in patterns_to_compile.items():
                try:
                    compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
                    self.custom_patterns[compiled_pattern] = pattern_name
                except re.error as e:
                    # Log error but continue with other patterns
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"Invalid custom pattern '{pattern_str}': {e}")

    def audit_log_file(self, log_file: Path) -> List[Dict]:
        """
        Scan single log file for sensitive data including custom PII patterns (WK-4).

        Args:
            log_file: Path to log file

        Returns:
            List of findings with file, line, patterns, and severity

        Example:
            >>> auditor = LogAuditor()
            >>> findings = auditor.audit_log_file(Path("app.log"))
            >>> print(findings[0])
            {
                "file": "app.log",
                "line": 42,
                "patterns": {"aws_access_key": ["AKIAIOSFODNN7EXAMPLE"]},
                "severity": "CRITICAL"
            }
        """
        findings = []
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    # Standard pattern detection
                    detected = detect_sensitive_data(line)

                    # WK-4: Custom PII pattern detection
                    if self.enable_custom_patterns:
                        custom_detected = self._detect_custom_pii(line)
                        if custom_detected:
                            detected.update(custom_detected)

                    if detected:
                        findings.append({
                            "file": str(log_file),
                            "line": line_num,
                            "patterns": detected,
                            "severity": self._assess_severity(detected),
                        })
        except Exception as e:
            findings.append({
                "file": str(log_file),
                "error": str(e),
                "severity": "ERROR"
            })
        return findings

    def _detect_custom_pii(self, line: str) -> Dict[str, List[str]]:
        """
        Detect custom PII field patterns in log line (WK-4).

        Args:
            line: Log line to scan

        Returns:
            Dictionary of pattern name to matches

        Example:
            >>> auditor = LogAuditor()
            >>> auditor._detect_custom_pii("user_email: john@example.com")
            {'user_field': ['user_email']}
        """
        findings = {}

        # Look for field assignments: field_name: value or field_name=value
        field_pattern = re.compile(r'(\w+)\s*[:=]\s*', re.IGNORECASE)
        field_matches = field_pattern.findall(line)

        for field_name in field_matches:
            # Check if field name matches any custom pattern
            for pattern, pattern_name in self.custom_patterns.items():
                if pattern.match(field_name):
                    if pattern_name not in findings:
                        findings[pattern_name] = []
                    findings[pattern_name].append(field_name)

        return findings

    def _assess_severity(self, detected: Dict[str, List[str]]) -> str:
        """
        Assess overall severity based on detected patterns.

        Args:
            detected: Dictionary of pattern name to matches

        Returns:
            Highest severity level found
        """
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        max_severity = "LOW"
        for pattern_name in detected.keys():
            severity = self.SEVERITY_MAP.get(pattern_name, "MEDIUM")
            if severities.index(severity) < severities.index(max_severity):
                max_severity = severity
        return max_severity

    def audit_all_logs(self) -> Dict:
        """
        Scan all log files in directory.

        Returns:
            Dictionary with status, total files, findings, and summary

        Example:
            >>> auditor = LogAuditor(Path("logs"))
            >>> result = auditor.audit_all_logs()
            >>> print(result["summary"])
            {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        """
        all_findings = []
        if not self.log_dir.exists():
            return {
                "status": "error",
                "message": f"Log directory not found: {self.log_dir}"
            }

        log_files = list(self.log_dir.glob("*.log"))
        for log_file in log_files:
            findings = self.audit_log_file(log_file)
            all_findings.extend(findings)

        return {
            "status": "success",
            "total_files": len(log_files),
            "total_findings": len(all_findings),
            "findings": all_findings,
            "summary": self._generate_summary(all_findings)
        }

    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """
        Generate summary statistics.

        Args:
            findings: List of audit findings

        Returns:
            Dictionary with severity counts
        """
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in summary:
                summary[severity] = summary.get(severity, 0) + 1
        return summary

    def generate_report(self, output_file: Optional[Path] = None) -> str:
        """
        Generate human-readable audit report.

        Args:
            output_file: Optional file path to write report

        Returns:
            Report text

        Example:
            >>> auditor = LogAuditor()
            >>> result = auditor.audit_all_logs()
            >>> report = auditor.generate_report()
            >>> print(report)
        """
        result = self.audit_all_logs()

        if result["status"] == "error":
            return f"Error: {result['message']}"

        report_lines = [
            "=" * 80,
            "LOG SECURITY AUDIT REPORT",
            "=" * 80,
            f"Total files scanned: {result['total_files']}",
            f"Total findings: {result['total_findings']}",
            "",
            "SEVERITY SUMMARY:",
            f"  CRITICAL: {result['summary']['CRITICAL']}",
            f"  HIGH:     {result['summary']['HIGH']}",
            f"  MEDIUM:   {result['summary']['MEDIUM']}",
            f"  LOW:      {result['summary']['LOW']}",
            "",
            "=" * 80,
            "DETAILED FINDINGS:",
            "=" * 80,
        ]

        # Sort by severity
        sorted_findings = sorted(
            result["findings"],
            key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.get("severity", "LOW"))
        )

        for finding in sorted_findings:
            if "error" in finding:
                report_lines.append(f"\n[ERROR] {finding['file']}: {finding['error']}")
                continue

            report_lines.append(f"\n[{finding['severity']}] {finding['file']}:{finding['line']}")
            for pattern_name, matches in finding["patterns"].items():
                report_lines.append(f"  - {pattern_name}: {len(matches)} matches")

        report = "\n".join(report_lines)

        if output_file:
            output_file.write_text(report, encoding='utf-8')

        return report
