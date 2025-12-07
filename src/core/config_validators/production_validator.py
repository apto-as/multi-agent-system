"""Production Validator - Production security checks.

This module handles production environment validation:
- Security configuration checks
- API configuration checks
- Session cookie checks
- Rate limiting checks

Security Patterns:
- 404 Security Standards compliance
- Zero tolerance for security issues in production
- Clear error messages for each violation
"""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def validate_production_settings(settings: Any) -> None:
    """Validate settings for production environment.

    404 Production Validation: Zero tolerance for security issues.

    Args:
        settings: Settings instance to validate

    Raises:
        ValueError: If any production security issue is detected
    """
    issues = []

    # Security validations
    issues.extend(_check_api_settings(settings))
    issues.extend(_check_security_settings(settings))
    issues.extend(_check_auth_settings(settings))
    issues.extend(_check_rate_limit_settings(settings))

    if issues:
        raise ValueError(f"PRODUCTION SECURITY ISSUES DETECTED: {'; '.join(issues)}")

    logger.info("Production security validation passed")


def _check_api_settings(settings: Any) -> list[str]:
    """Check API-related settings.

    Args:
        settings: Settings instance

    Returns:
        List of issues found
    """
    issues = []

    if settings.api_host == "0.0.0.0":
        issues.append("API host is 0.0.0.0 in production - security risk")

    if settings.db_echo_sql:
        issues.append("SQL echo is enabled in production - data exposure risk")

    if settings.api_reload:
        issues.append("API reload is enabled in production - instability risk")

    if not settings.cors_origins:
        issues.append("CORS origins not configured in production")

    if settings.log_level == "DEBUG":
        issues.append("Debug logging enabled in production - information disclosure")

    return issues


def _check_security_settings(settings: Any) -> list[str]:
    """Check security-related settings.

    Args:
        settings: Settings instance

    Returns:
        List of issues found
    """
    issues = []

    if not settings.session_cookie_secure:
        issues.append("Insecure session cookies in production")

    if settings.session_cookie_samesite != "strict":
        logger.warning("Session cookies not using 'strict' SameSite in production")

    if not settings.security_headers_enabled:
        issues.append("Security headers disabled in production")

    return issues


def _check_auth_settings(settings: Any) -> list[str]:
    """Check authentication settings.

    Args:
        settings: Settings instance

    Returns:
        List of issues found
    """
    issues = []

    if not settings.auth_enabled:
        issues.append("Authentication disabled in production - critical security risk")

    return issues


def _check_rate_limit_settings(settings: Any) -> list[str]:
    """Check rate limiting settings.

    Args:
        settings: Settings instance

    Returns:
        List of issues found
    """
    issues = []

    if not settings.rate_limit_enabled:
        issues.append("Rate limiting disabled in production")

    if settings.rate_limit_requests > 1000:
        logger.warning("High rate limit in production - consider lowering")

    return issues


def validate_staging_settings(settings: Any) -> None:
    """Validate settings for staging environment.

    Less strict than production, but still warns about potential issues.

    Args:
        settings: Settings instance to validate
    """
    warnings = []

    if settings.db_echo_sql:
        warnings.append("SQL echo enabled in staging")

    if settings.log_level == "DEBUG":
        warnings.append("Debug logging in staging")

    if warnings:
        logger.warning(f"Staging configuration warnings: {'; '.join(warnings)}")
