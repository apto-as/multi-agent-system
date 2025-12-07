"""
P0 Integration Tests: Production Security Checks
CRITICAL: These tests verify production-ready security configuration.

Test IDs:
- PROD-P0-001: API host 0.0.0.0 blocked
- PROD-P0-002: SQL echo disabled
- PROD-P0-003: API reload disabled
- PROD-P0-004: Authentication required
- PROD-P0-005: Security headers enabled
- PROD-P0-006: Rate limiting enabled
- PROD-P0-007: Secure cookies enforced
- PROD-P0-008: CORS origins configured
"""

import pytest


@pytest.mark.integration
@pytest.mark.security
class TestProductionAPIHost:
    """PROD-P0-001: API host security tests."""

    def test_production_warns_on_0_0_0_0_binding(self, caplog):
        """PROD-P0-001-T1: 0.0.0.0 binding raises security issue in production."""
        import logging
        from typing import Any

        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "0.0.0.0"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "0.0.0.0" in str(exc_info.value)
        assert "security" in str(exc_info.value).lower()

    def test_production_accepts_localhost_binding(self):
        """PROD-P0-001-T2: Localhost binding accepted in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        # Should not raise
        validate_production_settings(MockSettings())


@pytest.mark.integration
@pytest.mark.security
class TestProductionSQLEcho:
    """PROD-P0-002: SQL echo security tests."""

    def test_production_rejects_sql_echo(self):
        """PROD-P0-002-T1: SQL echo must be disabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = True  # Security risk
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "SQL echo" in str(exc_info.value)


@pytest.mark.integration
@pytest.mark.security
class TestProductionAPIReload:
    """PROD-P0-003: API reload security tests."""

    def test_production_rejects_api_reload(self):
        """PROD-P0-003-T1: API reload must be disabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = True  # Instability risk
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "reload" in str(exc_info.value).lower()


@pytest.mark.integration
@pytest.mark.security
class TestProductionAuthentication:
    """PROD-P0-004: Authentication requirement tests."""

    def test_production_requires_authentication(self):
        """PROD-P0-004-T1: Authentication must be enabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = False  # Critical security risk
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "Authentication" in str(exc_info.value)
        assert "critical" in str(exc_info.value).lower()


@pytest.mark.integration
@pytest.mark.security
class TestProductionSecurityHeaders:
    """PROD-P0-005: Security headers tests."""

    def test_production_requires_security_headers(self):
        """PROD-P0-005-T1: Security headers must be enabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = False  # Security risk
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "Security headers" in str(exc_info.value)


@pytest.mark.integration
@pytest.mark.security
class TestProductionRateLimiting:
    """PROD-P0-006: Rate limiting tests."""

    def test_production_requires_rate_limiting(self):
        """PROD-P0-006-T1: Rate limiting must be enabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = False  # DoS risk
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "Rate limiting" in str(exc_info.value)

    def test_production_warns_on_high_rate_limit(self, caplog):
        """PROD-P0-006-T2: High rate limit triggers warning."""
        import logging

        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 5000  # Very high

        with caplog.at_level(logging.WARNING):
            validate_production_settings(MockSettings())

        assert "rate limit" in caplog.text.lower()


@pytest.mark.integration
@pytest.mark.security
class TestProductionSecureCookies:
    """PROD-P0-007: Secure cookie tests."""

    def test_production_requires_secure_cookies(self):
        """PROD-P0-007-T1: Secure cookies must be enabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = False  # Security risk
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "cookie" in str(exc_info.value).lower()

    def test_production_warns_non_strict_samesite(self, caplog):
        """PROD-P0-007-T2: Non-strict SameSite triggers warning."""
        import logging

        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "lax"  # Not strict
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with caplog.at_level(logging.WARNING):
            validate_production_settings(MockSettings())

        assert "strict" in caplog.text.lower()


@pytest.mark.integration
@pytest.mark.security
class TestProductionCORSConfiguration:
    """PROD-P0-008: CORS configuration tests."""

    def test_production_requires_cors_origins(self):
        """PROD-P0-008-T1: CORS origins must be configured in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = []  # Empty - not configured
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "CORS" in str(exc_info.value)


@pytest.mark.integration
@pytest.mark.security
class TestProductionDebugLogging:
    """PROD-P0-009: Debug logging prevention tests."""

    def test_production_rejects_debug_logging(self):
        """PROD-P0-009-T1: Debug logging must be disabled in production."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://example.com"]
            log_level = "DEBUG"  # Information disclosure risk
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        with pytest.raises(ValueError) as exc_info:
            validate_production_settings(MockSettings())

        assert "Debug" in str(exc_info.value) or "logging" in str(exc_info.value).lower()


@pytest.mark.integration
@pytest.mark.security
class TestProductionFullValidation:
    """Combined production security validation tests."""

    def test_valid_production_configuration_passes(self):
        """Test that a properly configured production environment passes."""
        from src.core.config_validators.production_validator import (
            validate_production_settings,
        )

        class MockSettings:
            api_host = "127.0.0.1"
            db_echo_sql = False
            api_reload = False
            cors_origins = ["https://app.example.com"]
            log_level = "INFO"
            session_cookie_secure = True
            session_cookie_samesite = "strict"
            security_headers_enabled = True
            auth_enabled = True
            rate_limit_enabled = True
            rate_limit_requests = 100

        # Should not raise
        validate_production_settings(MockSettings())

    def test_staging_environment_less_strict(self, caplog):
        """Test that staging environment has less strict validation."""
        import logging

        from src.core.config_validators.production_validator import (
            validate_staging_settings,
        )

        class MockSettings:
            db_echo_sql = True  # Allowed in staging
            log_level = "DEBUG"  # Allowed in staging

        with caplog.at_level(logging.WARNING):
            validate_staging_settings(MockSettings())

        # Should warn but not raise
        assert "staging" in caplog.text.lower()
