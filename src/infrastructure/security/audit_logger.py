"""Structured Audit Logging for MCP Hub.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.3 - Runtime Protection
Requirement: S-P0-8 - Audit Logging

Security Properties:
- Structured JSON logging for security events
- Separation of security logs from application logs
- Log rotation and size management
- Immutable log entries (append-only)

Event Types:
- AUTH: Authentication events (HMAC token verification)
- TOOL_CALL: Tool execution events
- VALIDATION: Input validation events
- RESPONSE: Response processing events
- SECURITY: Security violation events (code validation, size limits)

Usage:
    >>> logger = SecurityAuditLogger()
    >>> logger.log_auth_success("client_1", "context7")
    >>> logger.log_tool_call("context7", "search", {"query": "test"})
    >>> logger.log_security_violation("CODE_VALIDATION", ["import os blocked"])

Author: Metis (Implementation) + Hestia (Security Review)
Created: 2025-12-05
"""

import json
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# Configure audit logger
logger = logging.getLogger("tmws.security.audit")


class AuditEventType(Enum):
    """Types of security audit events."""

    # Authentication events
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_EXPIRED = "AUTH_EXPIRED"
    AUTH_REPLAY = "AUTH_REPLAY"

    # Tool execution events
    TOOL_CALL_START = "TOOL_CALL_START"
    TOOL_CALL_SUCCESS = "TOOL_CALL_SUCCESS"
    TOOL_CALL_FAILURE = "TOOL_CALL_FAILURE"
    TOOL_CALL_TIMEOUT = "TOOL_CALL_TIMEOUT"

    # Validation events
    VALIDATION_SUCCESS = "VALIDATION_SUCCESS"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"

    # Response events
    RESPONSE_OK = "RESPONSE_OK"
    RESPONSE_SIZE_WARNING = "RESPONSE_SIZE_WARNING"
    RESPONSE_SIZE_EXCEEDED = "RESPONSE_SIZE_EXCEEDED"
    RESPONSE_TRUNCATED = "RESPONSE_TRUNCATED"

    # Security violation events
    CODE_VALIDATION_FAILURE = "CODE_VALIDATION_FAILURE"
    FORBIDDEN_IMPORT = "FORBIDDEN_IMPORT"
    FORBIDDEN_BUILTIN = "FORBIDDEN_BUILTIN"
    SECURITY_BYPASS_ATTEMPT = "SECURITY_BYPASS_ATTEMPT"

    # Connection events
    CONNECTION_ESTABLISHED = "CONNECTION_ESTABLISHED"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"
    CONNECTION_LIMIT_REACHED = "CONNECTION_LIMIT_REACHED"


class AuditLevel(Enum):
    """Severity levels for audit events."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditEntry:
    """Immutable audit log entry.

    Contains all information for a security audit event.
    """

    def __init__(
        self,
        event_type: AuditEventType,
        level: AuditLevel,
        message: str,
        client_id: str | None = None,
        server_id: str | None = None,
        tool_name: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.event_type = event_type
        self.level = level
        self.message = message
        self.client_id = client_id
        self.server_id = server_id
        self.tool_name = tool_name
        self.details = details or {}

        # Add process info
        self.pid = os.getpid()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        entry = {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "level": self.level.value,
            "message": self.message,
            "pid": self.pid,
        }

        # Add optional fields if present
        if self.client_id:
            entry["client_id"] = self.client_id
        if self.server_id:
            entry["server_id"] = self.server_id
        if self.tool_name:
            entry["tool_name"] = self.tool_name
        if self.details:
            entry["details"] = self.details

        return entry

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class SecurityAuditLogger:
    """Structured audit logger for security events.

    Features:
    - JSON-structured logging
    - Separate audit log file (optional)
    - Log rotation support
    - Configurable log levels

    Configuration:
    - log_to_file: Enable file logging
    - log_file_path: Path to audit log file
    - max_file_size_mb: Maximum log file size before rotation
    - min_level: Minimum level to log
    """

    DEFAULT_LOG_PATH = Path("logs/security_audit.jsonl")
    DEFAULT_MAX_SIZE_MB = 100

    def __init__(
        self,
        log_to_file: bool = False,
        log_file_path: Path | str | None = None,
        max_file_size_mb: int | None = None,
        min_level: AuditLevel = AuditLevel.INFO,
    ):
        """Initialize audit logger.

        Args:
            log_to_file: Enable file logging
            log_file_path: Path to log file
            max_file_size_mb: Max size before rotation
            min_level: Minimum level to log
        """
        self.log_to_file = log_to_file
        self.log_file_path = Path(log_file_path) if log_file_path else self.DEFAULT_LOG_PATH
        self.max_file_size_bytes = (max_file_size_mb or self.DEFAULT_MAX_SIZE_MB) * 1024 * 1024
        self.min_level = min_level
        self._level_order = {
            AuditLevel.DEBUG: 0,
            AuditLevel.INFO: 1,
            AuditLevel.WARNING: 2,
            AuditLevel.ERROR: 3,
            AuditLevel.CRITICAL: 4,
        }

        # Setup file handler if enabled
        if self.log_to_file:
            self._setup_file_logging()

        logger.debug(f"SecurityAuditLogger initialized (file={log_to_file})")

    def _setup_file_logging(self) -> None:
        """Setup file logging with rotation."""
        # Create logs directory if needed
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Add file handler
        from logging.handlers import RotatingFileHandler

        handler = RotatingFileHandler(
            self.log_file_path,
            maxBytes=self.max_file_size_bytes,
            backupCount=5,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    def _should_log(self, level: AuditLevel) -> bool:
        """Check if event should be logged based on level."""
        return self._level_order[level] >= self._level_order[self.min_level]

    def _log_entry(self, entry: AuditEntry) -> None:
        """Log an audit entry."""
        if not self._should_log(entry.level):
            return

        # Map to Python logging level
        level_map = {
            AuditLevel.DEBUG: logging.DEBUG,
            AuditLevel.INFO: logging.INFO,
            AuditLevel.WARNING: logging.WARNING,
            AuditLevel.ERROR: logging.ERROR,
            AuditLevel.CRITICAL: logging.CRITICAL,
        }

        logger.log(level_map[entry.level], entry.to_json())

    # ========================================================================
    # Authentication Events
    # ========================================================================

    def log_auth_success(
        self,
        client_id: str,
        server_id: str | None = None,
    ) -> None:
        """Log successful authentication."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_SUCCESS,
            level=AuditLevel.INFO,
            message=f"Authentication successful for client: {client_id}",
            client_id=client_id,
            server_id=server_id,
        )
        self._log_entry(entry)

    def log_auth_failure(
        self,
        client_id: str | None,
        reason: str,
        server_id: str | None = None,
    ) -> None:
        """Log authentication failure."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_FAILURE,
            level=AuditLevel.WARNING,
            message=f"Authentication failed: {reason}",
            client_id=client_id,
            server_id=server_id,
            details={"reason": reason},
        )
        self._log_entry(entry)

    def log_auth_expired(
        self,
        client_id: str,
        expired_at: str,
    ) -> None:
        """Log expired token."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_EXPIRED,
            level=AuditLevel.WARNING,
            message=f"Token expired for client: {client_id}",
            client_id=client_id,
            details={"expired_at": expired_at},
        )
        self._log_entry(entry)

    def log_auth_replay(
        self,
        client_id: str,
        nonce: str,
    ) -> None:
        """Log replay attack attempt."""
        entry = AuditEntry(
            event_type=AuditEventType.AUTH_REPLAY,
            level=AuditLevel.ERROR,
            message=f"Replay attack detected for client: {client_id}",
            client_id=client_id,
            details={"nonce": nonce[:16] + "..."},  # Truncate for security
        )
        self._log_entry(entry)

    # ========================================================================
    # Tool Execution Events
    # ========================================================================

    def log_tool_call_start(
        self,
        server_id: str,
        tool_name: str,
        client_id: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> None:
        """Log tool call start."""
        # Sanitize arguments (don't log sensitive data)
        safe_args = self._sanitize_arguments(arguments) if arguments else None

        entry = AuditEntry(
            event_type=AuditEventType.TOOL_CALL_START,
            level=AuditLevel.INFO,
            message=f"Tool call started: {server_id}:{tool_name}",
            client_id=client_id,
            server_id=server_id,
            tool_name=tool_name,
            details={"arguments_keys": list(safe_args.keys()) if safe_args else []},
        )
        self._log_entry(entry)

    def log_tool_call_success(
        self,
        server_id: str,
        tool_name: str,
        duration_ms: float,
        response_size_bytes: int | None = None,
    ) -> None:
        """Log successful tool call."""
        entry = AuditEntry(
            event_type=AuditEventType.TOOL_CALL_SUCCESS,
            level=AuditLevel.INFO,
            message=f"Tool call succeeded: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
            details={
                "duration_ms": round(duration_ms, 2),
                "response_size_bytes": response_size_bytes,
            },
        )
        self._log_entry(entry)

    def log_tool_call_failure(
        self,
        server_id: str,
        tool_name: str,
        error: str,
        duration_ms: float | None = None,
    ) -> None:
        """Log failed tool call."""
        entry = AuditEntry(
            event_type=AuditEventType.TOOL_CALL_FAILURE,
            level=AuditLevel.ERROR,
            message=f"Tool call failed: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
            details={
                "error": error[:500],  # Truncate long errors
                "duration_ms": round(duration_ms, 2) if duration_ms else None,
            },
        )
        self._log_entry(entry)

    def log_tool_call_timeout(
        self,
        server_id: str,
        tool_name: str,
        timeout_seconds: float,
    ) -> None:
        """Log tool call timeout."""
        entry = AuditEntry(
            event_type=AuditEventType.TOOL_CALL_TIMEOUT,
            level=AuditLevel.ERROR,
            message=f"Tool call timeout: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
            details={"timeout_seconds": timeout_seconds},
        )
        self._log_entry(entry)

    # ========================================================================
    # Validation Events
    # ========================================================================

    def log_validation_success(
        self,
        server_id: str,
        tool_name: str,
    ) -> None:
        """Log successful validation."""
        entry = AuditEntry(
            event_type=AuditEventType.VALIDATION_SUCCESS,
            level=AuditLevel.DEBUG,
            message=f"Input validation passed: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
        )
        self._log_entry(entry)

    def log_validation_failure(
        self,
        server_id: str,
        tool_name: str,
        errors: list[str],
    ) -> None:
        """Log validation failure."""
        entry = AuditEntry(
            event_type=AuditEventType.VALIDATION_FAILURE,
            level=AuditLevel.WARNING,
            message=f"Input validation failed: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
            details={"errors": errors[:10]},  # Limit error count
        )
        self._log_entry(entry)

    # ========================================================================
    # Response Events
    # ========================================================================

    def log_response_size_warning(
        self,
        server_id: str,
        tool_name: str,
        size_bytes: int,
        limit_bytes: int,
    ) -> None:
        """Log response size warning."""
        entry = AuditEntry(
            event_type=AuditEventType.RESPONSE_SIZE_WARNING,
            level=AuditLevel.WARNING,
            message=f"Response size approaching limit: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
            details={
                "size_bytes": size_bytes,
                "limit_bytes": limit_bytes,
                "percentage": round(size_bytes / limit_bytes * 100, 1),
            },
        )
        self._log_entry(entry)

    def log_response_size_exceeded(
        self,
        server_id: str,
        tool_name: str,
        size_bytes: int,
        limit_bytes: int,
    ) -> None:
        """Log response size exceeded."""
        entry = AuditEntry(
            event_type=AuditEventType.RESPONSE_SIZE_EXCEEDED,
            level=AuditLevel.ERROR,
            message=f"Response size exceeded limit: {server_id}:{tool_name}",
            server_id=server_id,
            tool_name=tool_name,
            details={
                "size_bytes": size_bytes,
                "limit_bytes": limit_bytes,
            },
        )
        self._log_entry(entry)

    # ========================================================================
    # Security Violation Events
    # ========================================================================

    def log_code_validation_failure(
        self,
        violations: list[str],
        code_snippet: str | None = None,
    ) -> None:
        """Log code validation failure."""
        entry = AuditEntry(
            event_type=AuditEventType.CODE_VALIDATION_FAILURE,
            level=AuditLevel.ERROR,
            message=f"Code validation failed: {len(violations)} violation(s)",
            details={
                "violations": violations[:10],  # Limit count
                "code_preview": code_snippet[:100] if code_snippet else None,
            },
        )
        self._log_entry(entry)

    def log_forbidden_import(
        self,
        import_name: str,
        line_number: int | None = None,
    ) -> None:
        """Log forbidden import attempt."""
        entry = AuditEntry(
            event_type=AuditEventType.FORBIDDEN_IMPORT,
            level=AuditLevel.ERROR,
            message=f"Forbidden import detected: {import_name}",
            details={
                "import": import_name,
                "line": line_number,
            },
        )
        self._log_entry(entry)

    def log_forbidden_builtin(
        self,
        builtin_name: str,
        line_number: int | None = None,
    ) -> None:
        """Log forbidden builtin attempt."""
        entry = AuditEntry(
            event_type=AuditEventType.FORBIDDEN_BUILTIN,
            level=AuditLevel.ERROR,
            message=f"Forbidden builtin detected: {builtin_name}",
            details={
                "builtin": builtin_name,
                "line": line_number,
            },
        )
        self._log_entry(entry)

    def log_security_bypass_attempt(
        self,
        bypass_type: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log security bypass attempt."""
        entry = AuditEntry(
            event_type=AuditEventType.SECURITY_BYPASS_ATTEMPT,
            level=AuditLevel.CRITICAL,
            message=f"Security bypass attempt detected: {bypass_type}",
            details={"bypass_type": bypass_type, **(details or {})},
        )
        self._log_entry(entry)

    # ========================================================================
    # Connection Events
    # ========================================================================

    def log_connection_established(
        self,
        server_id: str,
        tool_count: int,
    ) -> None:
        """Log connection established."""
        entry = AuditEntry(
            event_type=AuditEventType.CONNECTION_ESTABLISHED,
            level=AuditLevel.INFO,
            message=f"Connection established: {server_id}",
            server_id=server_id,
            details={"tool_count": tool_count},
        )
        self._log_entry(entry)

    def log_connection_closed(
        self,
        server_id: str,
        reason: str | None = None,
    ) -> None:
        """Log connection closed."""
        entry = AuditEntry(
            event_type=AuditEventType.CONNECTION_CLOSED,
            level=AuditLevel.INFO,
            message=f"Connection closed: {server_id}",
            server_id=server_id,
            details={"reason": reason},
        )
        self._log_entry(entry)

    def log_connection_limit_reached(
        self,
        current_count: int,
        max_count: int,
        attempted_server: str,
    ) -> None:
        """Log connection limit reached."""
        entry = AuditEntry(
            event_type=AuditEventType.CONNECTION_LIMIT_REACHED,
            level=AuditLevel.WARNING,
            message=f"Connection limit reached ({current_count}/{max_count})",
            server_id=attempted_server,
            details={
                "current_count": current_count,
                "max_count": max_count,
            },
        )
        self._log_entry(entry)

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _sanitize_arguments(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Sanitize arguments for logging (remove sensitive data)."""
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "key",
            "auth",
            "credential",
            "api_key",
            "apikey",
            "private",
        }

        sanitized = {}
        for key, value in arguments.items():
            key_lower = key.lower()
            if any(s in key_lower for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 100:
                sanitized[key] = f"{value[:50]}...[truncated]"
            else:
                sanitized[key] = value

        return sanitized


# ============================================================================
# SINGLETON
# ============================================================================

_audit_logger: SecurityAuditLogger | None = None


def get_audit_logger() -> SecurityAuditLogger:
    """Get singleton SecurityAuditLogger instance.

    Returns:
        SecurityAuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = SecurityAuditLogger()
    return _audit_logger


def configure_audit_logger(
    log_to_file: bool = False,
    log_file_path: Path | str | None = None,
    max_file_size_mb: int | None = None,
    min_level: AuditLevel = AuditLevel.INFO,
) -> SecurityAuditLogger:
    """Configure and return the audit logger.

    Args:
        log_to_file: Enable file logging
        log_file_path: Path to log file
        max_file_size_mb: Max size before rotation
        min_level: Minimum level to log

    Returns:
        Configured SecurityAuditLogger
    """
    global _audit_logger
    _audit_logger = SecurityAuditLogger(
        log_to_file=log_to_file,
        log_file_path=log_file_path,
        max_file_size_mb=max_file_size_mb,
        min_level=min_level,
    )
    return _audit_logger
