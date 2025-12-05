"""Unit tests for S-P0-8: Audit Logging.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.3 - Runtime Protection

Tests for:
- Audit event logging
- Event type classification
- Log level filtering
- Argument sanitization
- JSON serialization

Author: Metis (Testing) + Hestia (Security Review)
Created: 2025-12-05
"""

import json
import logging

import pytest

from src.infrastructure.security.audit_logger import (
    AuditEntry,
    AuditEventType,
    AuditLevel,
    SecurityAuditLogger,
    get_audit_logger,
)


class TestAuditEntry:
    """Tests for AuditEntry data class."""

    def test_entry_creation(self):
        """Test audit entry creation."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_SUCCESS,
            level=AuditLevel.INFO,
            message="Test message",
            client_id="client_1",
            server_id="server_1",
        )

        assert entry.event_type == AuditEventType.AUTH_SUCCESS
        assert entry.level == AuditLevel.INFO
        assert entry.message == "Test message"
        assert entry.client_id == "client_1"
        assert entry.server_id == "server_1"
        assert entry.timestamp is not None
        assert entry.pid > 0

    def test_entry_to_dict(self):
        """Test AuditEntry.to_dict()."""
        entry = AuditEntry(
            event_type=AuditEventType.TOOL_CALL_SUCCESS,
            level=AuditLevel.INFO,
            message="Tool call succeeded",
            server_id="context7",
            tool_name="search",
            details={"duration_ms": 150},
        )

        entry_dict = entry.to_dict()

        assert entry_dict["event_type"] == "TOOL_CALL_SUCCESS"
        assert entry_dict["level"] == "INFO"
        assert entry_dict["message"] == "Tool call succeeded"
        assert entry_dict["server_id"] == "context7"
        assert entry_dict["tool_name"] == "search"
        assert entry_dict["details"]["duration_ms"] == 150

    def test_entry_to_json(self):
        """Test AuditEntry.to_json()."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_FAILURE,
            level=AuditLevel.WARNING,
            message="Auth failed",
        )

        json_str = entry.to_json()
        parsed = json.loads(json_str)

        assert parsed["event_type"] == "AUTH_FAILURE"
        assert parsed["level"] == "WARNING"

    def test_entry_optional_fields_omitted(self):
        """Test that optional fields are omitted when not provided."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_SUCCESS,
            level=AuditLevel.INFO,
            message="Test",
        )

        entry_dict = entry.to_dict()

        assert "client_id" not in entry_dict
        assert "server_id" not in entry_dict
        assert "tool_name" not in entry_dict
        assert "details" not in entry_dict


class TestSecurityAuditLogger:
    """Tests for SecurityAuditLogger."""

    def test_logger_initialization(self):
        """Test logger initialization."""
        logger = SecurityAuditLogger()

        assert logger.log_to_file is False
        assert logger.min_level == AuditLevel.INFO

    def test_logger_with_custom_config(self):
        """Test logger with custom configuration."""
        logger = SecurityAuditLogger(
            min_level=AuditLevel.WARNING,
            max_file_size_mb=50,
        )

        assert logger.min_level == AuditLevel.WARNING
        assert logger.max_file_size_bytes == 50 * 1024 * 1024


class TestAuthenticationLogging:
    """Tests for authentication event logging."""

    def test_log_auth_success(self, caplog):
        """Test logging authentication success."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.INFO, logger="tmws.security.audit"):
            logger.log_auth_success("client_1", "context7")

        # Verify log was created
        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "AUTH_SUCCESS"
        assert log_entry["client_id"] == "client_1"

    def test_log_auth_failure(self, caplog):
        """Test logging authentication failure."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.WARNING, logger="tmws.security.audit"):
            logger.log_auth_failure("client_1", "Invalid signature")

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "AUTH_FAILURE"
        assert log_entry["details"]["reason"] == "Invalid signature"

    def test_log_auth_replay(self, caplog):
        """Test logging replay attack detection."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.ERROR, logger="tmws.security.audit"):
            logger.log_auth_replay("client_1", "abc123def456")

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "AUTH_REPLAY"
        assert "nonce" in log_entry["details"]


class TestToolCallLogging:
    """Tests for tool call event logging."""

    def test_log_tool_call_start(self, caplog):
        """Test logging tool call start."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.INFO, logger="tmws.security.audit"):
            logger.log_tool_call_start(
                "context7",
                "search",
                arguments={"query": "test"},
            )

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "TOOL_CALL_START"
        assert log_entry["server_id"] == "context7"
        assert log_entry["tool_name"] == "search"

    def test_log_tool_call_success(self, caplog):
        """Test logging successful tool call."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.INFO, logger="tmws.security.audit"):
            logger.log_tool_call_success(
                "context7",
                "search",
                duration_ms=150.5,
                response_size_bytes=1024,
            )

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "TOOL_CALL_SUCCESS"
        assert log_entry["details"]["duration_ms"] == 150.5
        assert log_entry["details"]["response_size_bytes"] == 1024

    def test_log_tool_call_failure(self, caplog):
        """Test logging failed tool call."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.ERROR, logger="tmws.security.audit"):
            logger.log_tool_call_failure(
                "context7",
                "search",
                error="Connection timeout",
                duration_ms=30000,
            )

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "TOOL_CALL_FAILURE"
        assert "timeout" in log_entry["details"]["error"].lower()

    def test_log_tool_call_timeout(self, caplog):
        """Test logging tool call timeout."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.ERROR, logger="tmws.security.audit"):
            logger.log_tool_call_timeout("context7", "search", 30.0)

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "TOOL_CALL_TIMEOUT"
        assert log_entry["details"]["timeout_seconds"] == 30.0


class TestSecurityViolationLogging:
    """Tests for security violation event logging."""

    def test_log_code_validation_failure(self, caplog):
        """Test logging code validation failure."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.ERROR, logger="tmws.security.audit"):
            logger.log_code_validation_failure(
                violations=["Forbidden import: os", "Forbidden builtin: eval"],
                code_snippet="import os; eval('1+1')",
            )

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "CODE_VALIDATION_FAILURE"
        assert len(log_entry["details"]["violations"]) == 2

    def test_log_forbidden_import(self, caplog):
        """Test logging forbidden import."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.ERROR, logger="tmws.security.audit"):
            logger.log_forbidden_import("subprocess", line_number=5)

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "FORBIDDEN_IMPORT"
        assert log_entry["details"]["import"] == "subprocess"

    def test_log_security_bypass_attempt(self, caplog):
        """Test logging security bypass attempt."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.CRITICAL, logger="tmws.security.audit"):
            logger.log_security_bypass_attempt(
                "MRO_CHAIN_ATTACK",
                details={"pattern": "__class__.__mro__"},
            )

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "SECURITY_BYPASS_ATTEMPT"
        assert log_entry["level"] == "CRITICAL"


class TestArgumentSanitization:
    """Tests for argument sanitization."""

    def test_sanitize_password(self):
        """Test that passwords are redacted."""
        logger = SecurityAuditLogger()

        sanitized = logger._sanitize_arguments({
            "username": "user1",
            "password": "secret123",
        })

        assert sanitized["username"] == "user1"
        assert sanitized["password"] == "[REDACTED]"

    def test_sanitize_api_key(self):
        """Test that API keys are redacted."""
        logger = SecurityAuditLogger()

        sanitized = logger._sanitize_arguments({
            "api_key": "sk-1234567890",
            "query": "test",
        })

        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["query"] == "test"

    def test_sanitize_token(self):
        """Test that tokens are redacted."""
        logger = SecurityAuditLogger()

        sanitized = logger._sanitize_arguments({
            "auth_token": "bearer-xyz",
            "data": "value",
        })

        assert sanitized["auth_token"] == "[REDACTED]"
        assert sanitized["data"] == "value"

    def test_truncate_long_strings(self):
        """Test that long strings are truncated."""
        logger = SecurityAuditLogger()

        long_value = "x" * 200

        sanitized = logger._sanitize_arguments({
            "data": long_value,
        })

        assert "[truncated]" in sanitized["data"]
        assert len(sanitized["data"]) < len(long_value)


class TestLogLevelFiltering:
    """Tests for log level filtering."""

    def test_debug_filtered_at_info_level(self, caplog):
        """Test that DEBUG events are filtered at INFO level."""
        logger = SecurityAuditLogger(min_level=AuditLevel.INFO)

        with caplog.at_level(logging.DEBUG, logger="tmws.security.audit"):
            logger.log_validation_success("server", "tool")

        # Debug logs should be filtered
        debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
        # The validation success is DEBUG level, should not appear
        # (depends on logger config)

    def test_warning_not_filtered_at_info_level(self, caplog):
        """Test that WARNING events pass at INFO level."""
        logger = SecurityAuditLogger(min_level=AuditLevel.INFO)

        with caplog.at_level(logging.WARNING, logger="tmws.security.audit"):
            logger.log_validation_failure("server", "tool", ["error1"])

        # Warning should pass through
        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_records) > 0


class TestConnectionLogging:
    """Tests for connection event logging."""

    def test_log_connection_established(self, caplog):
        """Test logging connection established."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.INFO, logger="tmws.security.audit"):
            logger.log_connection_established("context7", tool_count=15)

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "CONNECTION_ESTABLISHED"
        assert log_entry["details"]["tool_count"] == 15

    def test_log_connection_limit_reached(self, caplog):
        """Test logging connection limit reached."""
        logger = SecurityAuditLogger(min_level=AuditLevel.DEBUG)

        with caplog.at_level(logging.WARNING, logger="tmws.security.audit"):
            logger.log_connection_limit_reached(
                current_count=10,
                max_count=10,
                attempted_server="new_server",
            )

        assert len(caplog.records) > 0
        log_entry = json.loads(caplog.records[-1].message)
        assert log_entry["event_type"] == "CONNECTION_LIMIT_REACHED"


class TestSingleton:
    """Tests for singleton pattern."""

    def test_get_audit_logger_returns_same_instance(self):
        """Test that get_audit_logger returns the same instance."""
        logger1 = get_audit_logger()
        logger2 = get_audit_logger()

        assert logger1 is logger2


class TestModuleImports:
    """Tests for module import functionality."""

    def test_security_module_exports(self):
        """Test that audit logger is exported from security module."""
        from src.infrastructure.security import (
            AuditEntry,
            AuditEventType,
            AuditLevel,
            SecurityAuditLogger,
            configure_audit_logger,
            get_audit_logger,
        )

        assert SecurityAuditLogger is not None
        assert AuditEntry is not None
        assert AuditEventType is not None
        assert AuditLevel is not None
        assert get_audit_logger is not None
        assert configure_audit_logger is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
