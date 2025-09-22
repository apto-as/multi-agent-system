from enum import Enum

from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, Index, Integer, String

from ..core.database import Base


class SecurityEventType(Enum):
    """Types of security events to track."""

    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGIN_BLOCKED = "login_blocked"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"

    # Authorization Events
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Input Validation Events
    INPUT_VALIDATION_FAILED = "input_validation_failed"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    COMMAND_INJECTION_ATTEMPT = "command_injection_attempt"

    # Rate Limiting Events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    DDOS_DETECTED = "ddos_detected"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    IP_BLOCKED = "ip_blocked"

    # Data Security Events
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"
    DATA_EXPORT = "data_export"
    BULK_OPERATION = "bulk_operation"

    # System Security Events
    CONFIGURATION_CHANGE = "configuration_change"
    ADMIN_ACTION = "admin_action"
    SYSTEM_COMPROMISE = "system_compromise"
    MALWARE_DETECTED = "malware_detected"

    # API Security Events
    API_ABUSE = "api_abuse"
    UNUSUAL_API_PATTERN = "unusual_api_pattern"
    BOT_DETECTED = "bot_detected"

    # Vector Security Events
    VECTOR_INJECTION_ATTEMPT = "vector_injection_attempt"
    EMBEDDING_ABUSE = "embedding_abuse"
    UNUSUAL_VECTOR_PATTERN = "unusual_vector_pattern"


class SecurityEventSeverity(Enum):
    """Security event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAuditLog(Base):
    """Database model for security audit logs."""
    __tablename__ = 'security_audit_logs'

    id = Column(Integer, primary_key=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    client_ip = Column(String(45), nullable=False, index=True)
    user_id = Column(String(100), index=True)
    session_id = Column(String(100), index=True)
    endpoint = Column(String(255))
    method = Column(String(10))
    user_agent = Column(String(500))
    referer = Column(String(500))
    message = Column(String(1000))
    details = Column(JSON)
    location = Column(JSON)
    risk_score = Column(Integer, default=0, index=True)
    blocked = Column(Boolean, default=False)
    event_hash = Column(String(16), index=True)

    # Performance optimization indexes
    __table_args__ = (
        Index("idx_audit_logs_timestamp_severity", "timestamp", "severity"),
        Index("idx_audit_logs_event_type_timestamp", "event_type", "timestamp"),
        Index("idx_audit_logs_client_ip", "client_ip"),
    )
