"""
Ultra-Fast Secure Logging (V-8 Performance Optimized)
Target: <0.1% overhead through aggressive optimization

Optimization Strategy:
1. Fast Path: Early exit for non-sensitive messages (99% of logs)
2. Lazy Evaluation: Only compile expensive regexes if needed
3. Minimal Regex: Use simple string operations where possible
4. Caching: Pre-compiled patterns at module level
"""
import hashlib
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)


def mask_user_id(user_id: Any) -> str:
    """Mask user ID for GDPR/CCPA compliance (optimized)."""
    if user_id is None:
        return "[anonymous]"

    user_str = str(user_id)
    if not user_str or user_str.lower() in ("none", "null", ""):
        return "[anonymous]"

    hashed = hashlib.sha256(user_str.encode()).hexdigest()
    return f"user-{hashed[:8]}"


def mask_email(email: str) -> str:
    """Mask email address (optimized)."""
    if not email or '@' not in email:
        return "***@***"

    username, domain = email.split('@', 1)
    if len(username) <= 2:
        masked_user = "*" * max(3, len(username))
    elif len(username) <= 3:
        masked_user = username[0] + "*" * (len(username) - 1)
    else:
        masked_user = username[:2] + "*" * (len(username) - 3) + username[-1]

    return f"{masked_user}@{domain}"


def mask_api_key(key: str) -> str:
    """Mask API key (optimized)."""
    if not key or len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"


def safe_log_error(
    logger_instance: logging.Logger,
    message: str,
    exception: Exception | None = None,
):
    """Log error with environment-aware stack trace."""
    env = os.getenv("TRINITAS_ENV", "development")

    if env == "production" and exception:
        logger_instance.error(f"{message}: {type(exception).__name__}")
    else:
        logger_instance.error(message, exc_info=exception is not None)


# ULTRA-FAST OPTIMIZATION: Sentinel-based fast path
# Check for common indicators first before expensive regex
SENSITIVE_INDICATORS = {
    '@',  # Email
    'password', 'passwd', 'pwd',  # Password keywords
    'Bearer', 'Basic',  # Auth headers
    'AKIA',  # AWS key prefix
    '://',  # Connection strings
    'token', 'secret', 'key',  # Credential keywords
}


def has_potential_sensitive_data(text: str) -> bool:
    """
    Fast check if text might contain sensitive data.

    This is a O(n) scan for sentinel characters/keywords.
    99% of log messages will exit early here.

    Returns:
        True if message might have sensitive data (needs full scan)
        False if definitely safe (skip expensive regex)
    """
    if not text:
        return False

    text_lower = text.lower()

    # Check for common indicators
    for indicator in SENSITIVE_INDICATORS:
        if indicator in text or indicator in text_lower:
            return True

    # Check for numeric patterns (credit cards, SSN, IP addresses)
    digit_count = sum(c.isdigit() for c in text)
    if digit_count >= 7:  # Potential CC, SSN, or IP (lowered from 9 to catch IPs like 192.168.1.1)
        return True

    return False


# Compile patterns ONCE at module load (not per-call)
# Only the most critical patterns for production

# Critical patterns (MUST redact)
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
BEARER_PATTERN = re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE)
PASSWORD_PATTERN = re.compile(r'(password|passwd|pwd)\s*[:=]\s*[\'"]?(\S+)', re.IGNORECASE)
DATABASE_PASSWORD_PATTERN = re.compile(r'(db_password|database_password)\s*[:=]\s*[\'"]?(\S+)', re.IGNORECASE)

# AWS keys (high priority)
AWS_ACCESS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')
AWS_SECRET_KEY_PATTERN = re.compile(r'aws_secret[_\s]*(?:access_)?key\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})', re.IGNORECASE)

# Database connection strings
CONNECTION_STRING_PATTERN = re.compile(r'\b(?:postgresql|mysql|mongodb|redis)://[^\s]+', re.IGNORECASE)

# Phone numbers (international and US formats)
PHONE_PATTERN = re.compile(r'\+?1?[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}')

# IP addresses (IPv4)
IP_ADDRESS_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Session IDs (alphanumeric strings after session_id=, 32+ chars)
SESSION_ID_PATTERN = re.compile(r'session_id\s*=\s*([a-zA-Z0-9]{32,})', re.IGNORECASE)

# Credit card (simplified)
CREDIT_CARD_PATTERN = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b')


def sanitize_log_message_fast(message: str) -> str:
    """
    Ultra-fast sanitization with early exit optimization.

    Performance target: <0.001ms per call for clean messages (99%)
    Overhead target: <0.1%

    Strategy:
    1. Fast path: Early exit if no sensitive indicators (O(n) scan)
    2. Slow path: Apply only critical regexes if needed
    """
    if not message:
        return message

    # FAST PATH: Early exit for 99% of messages
    if not has_potential_sensitive_data(message):
        return message

    # SLOW PATH: Only reached for ~1% of messages
    sanitized = message

    # Apply critical patterns only
    # Important: Apply more specific patterns first to avoid false matches
    # Credit card must come before phone (to avoid matching last 10 digits as phone)
    sanitized = CREDIT_CARD_PATTERN.sub('[credit_card_redacted]', sanitized)
    sanitized = AWS_ACCESS_KEY_PATTERN.sub('[aws_key_redacted]', sanitized)
    sanitized = AWS_SECRET_KEY_PATTERN.sub(r'aws_secret_key: [secret_redacted]', sanitized)
    sanitized = SESSION_ID_PATTERN.sub('session_id=[session_redacted]', sanitized)
    sanitized = JWT_PATTERN.sub('[jwt_redacted]', sanitized)
    sanitized = BEARER_PATTERN.sub('[bearer_redacted]', sanitized)
    sanitized = CONNECTION_STRING_PATTERN.sub('[connection_string_redacted]', sanitized)
    sanitized = PASSWORD_PATTERN.sub(r'\1: [password_redacted]', sanitized)
    sanitized = DATABASE_PASSWORD_PATTERN.sub(r'\1: [password_redacted]', sanitized)
    sanitized = EMAIL_PATTERN.sub('[email_redacted]', sanitized)
    sanitized = PHONE_PATTERN.sub('[phone_redacted]', sanitized)
    sanitized = IP_ADDRESS_PATTERN.sub('[ip_redacted]', sanitized)

    return sanitized


# Backward compatibility alias
sanitize_log_message = sanitize_log_message_fast


def detect_sensitive_data(text: str) -> dict[str, list[str]]:
    """
    Detect sensitive data patterns (optimized).

    Only used for audit purposes, not in hot path.
    """
    if not has_potential_sensitive_data(text):
        return {}

    findings = {}

    # Check each critical pattern
    patterns = {
        'email': EMAIL_PATTERN,
        'jwt': JWT_PATTERN,
        'bearer_token': BEARER_PATTERN,
        'password': PASSWORD_PATTERN,
        'database_password': DATABASE_PASSWORD_PATTERN,
        'aws_access_key': AWS_ACCESS_KEY_PATTERN,
        'aws_secret_key': AWS_SECRET_KEY_PATTERN,
        'connection_string': CONNECTION_STRING_PATTERN,
        'phone': PHONE_PATTERN,
        'ip_address': IP_ADDRESS_PATTERN,
        'session_id': SESSION_ID_PATTERN,
        'credit_card': CREDIT_CARD_PATTERN,
    }

    for name, pattern in patterns.items():
        matches = pattern.findall(text)
        if matches:
            # Handle tuple matches from capture groups
            if matches and isinstance(matches[0], tuple):
                matches = [m[-1] for m in matches if m[-1]]
            findings[name] = matches

    return findings


def create_secure_logger(
    name: str,
    level: int = logging.INFO,
    sanitize: bool = True,
) -> logging.Logger:
    """Create a logger with automatic message sanitization (optimized)."""
    secure_logger = logging.getLogger(name)
    secure_logger.setLevel(level)

    if sanitize:
        class SanitizingFilter(logging.Filter):
            def filter(self, record):
                record.msg = sanitize_log_message(str(record.msg))
                return True

        secure_logger.addFilter(SanitizingFilter())

    return secure_logger


# Pre-configured secure logger for common use
secure_logger = create_secure_logger("trinitas.secure")
