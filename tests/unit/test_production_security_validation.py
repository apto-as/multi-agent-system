"""
Unit tests for production security validation.

Tests the security validation mechanisms that ensure production
environments have proper security configurations enabled.
"""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from src.core.config import Settings

# Common production environment base for tests
PRODUCTION_BASE_ENV = {
    "TMWS_ENVIRONMENT": "production",
    "TMWS_DATABASE_URL": "postgresql://user:pass@localhost/db",
    "TMWS_SECRET_KEY": "SecureProductionKey1234567890ABCDEF",
    "TMWS_AUTH_ENABLED": "true",
    "TMWS_RATE_LIMIT_ENABLED": "true",
    "TMWS_SECURITY_HEADERS_ENABLED": "true",
    "TMWS_AUDIT_LOG_ENABLED": "true",
    "TMWS_CORS_ORIGINS": '["https://example.com"]',
}


class TestProductionSecurityValidation:
    """Test production security enforcement."""

    def test_production_requires_auth_enabled(self):
        """Production environment must have authentication enabled."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_AUTH_ENABLED"] = "false"

        with patch.dict(os.environ, env, clear=True):
            settings = Settings()
            # Should be auto-enabled
            assert settings.auth_enabled is True
            assert settings.environment == "production"

    def test_production_requires_rate_limiting(self):
        """Production environment must have rate limiting enabled."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_RATE_LIMIT_ENABLED"] = "false"

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="Rate limiting MUST be enabled"):
                Settings()

    def test_production_requires_security_headers(self):
        """Production environment must have security headers enabled."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_SECURITY_HEADERS_ENABLED"] = "false"

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="Security headers MUST be enabled"):
                Settings()

    def test_production_requires_audit_logging(self):
        """Production environment must have audit logging enabled."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_AUDIT_LOG_ENABLED"] = "false"

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="Audit logging MUST be enabled"):
                Settings()

    def test_production_requires_strong_secret_key(self):
        """Production environment must have a strong SECRET_KEY."""
        # Too short
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_SECRET_KEY"] = "short"

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError, match="at least 32 characters"):
                Settings()

        # Weak key
        env["TMWS_SECRET_KEY"] = "development" * 5
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="Weak or default secret key"):
                Settings()

    def test_production_all_security_features_enabled(self):
        """Production with all security features properly configured should work."""
        with patch.dict(os.environ, PRODUCTION_BASE_ENV, clear=True):
            settings = Settings()
            assert settings.environment == "production"
            assert settings.auth_enabled is True
            assert settings.rate_limit_enabled is True
            assert settings.security_headers_enabled is True
            assert settings.audit_log_enabled is True

    def test_development_allows_disabled_auth(self):
        """Development environment can have authentication disabled."""
        with patch.dict(
            os.environ,
            {
                "TMWS_ENVIRONMENT": "development",
                "TMWS_DATABASE_URL": "sqlite:///./test.db",
                "TMWS_SECRET_KEY": "dev-key-at-least-32-characters-long!",
                "TMWS_AUTH_ENABLED": "false",
            },
            clear=True,
        ):
            settings = Settings()
            assert settings.environment == "development"
            assert settings.auth_enabled is False

    def test_staging_warns_disabled_auth(self):
        """Staging environment warns but allows disabled authentication."""
        with patch.dict(
            os.environ,
            {
                "TMWS_ENVIRONMENT": "staging",
                "TMWS_DATABASE_URL": "postgresql://user:pass@localhost/db",
                "TMWS_SECRET_KEY": "staging-key-at-least-32-characters-long!",
                "TMWS_AUTH_ENABLED": "false",
            },
            clear=True,
        ):
            # Should not raise, but will log warning
            settings = Settings()
            assert settings.environment == "staging"
            assert settings.auth_enabled is False


class TestSecretKeyValidation:
    """Test SECRET_KEY security validation."""

    def test_common_weak_keys_rejected(self):
        """Common weak SECRET_KEYs should be rejected in production."""
        weak_keys = [
            "change-this-in-production-to-a-secure-random-key-long-enough",
            "debug" * 10,
            "test" * 10,
            "development" * 5,
            "secret" * 8,
            "password" * 6,
            "admin" * 10,
        ]

        for weak_key in weak_keys:
            env = PRODUCTION_BASE_ENV.copy()
            env["TMWS_SECRET_KEY"] = weak_key

            with patch.dict(os.environ, env, clear=True):
                with pytest.raises(ValueError, match="Weak or default secret key"):
                    Settings()

    def test_entropy_check_passes_with_mixed_chars(self):
        """SECRET_KEY with mixed case and numbers should pass."""
        with patch.dict(os.environ, PRODUCTION_BASE_ENV, clear=True):
            settings = Settings()
            assert len(settings.secret_key) >= 32


class TestDatabaseURLValidation:
    """Test DATABASE_URL security validation."""

    def test_production_database_url_required(self):
        """Production environment requires a valid DATABASE_URL."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_DATABASE_URL"] = ""

        with patch.dict(os.environ, env, clear=True), pytest.raises(ValidationError):
            Settings()


class TestCORSValidation:
    """Test CORS security validation."""

    def test_production_requires_explicit_cors(self):
        """Production environment requires explicit CORS configuration."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_CORS_ORIGINS"] = ""

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="CORS origins must be explicitly configured"):
                Settings()

    def test_production_rejects_wildcard_cors(self):
        """Production environment rejects wildcard CORS."""
        env = PRODUCTION_BASE_ENV.copy()
        env["TMWS_CORS_ORIGINS"] = '["*"]'

        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="Wildcard CORS origins not allowed"):
                Settings()
