"""
P0 Integration Tests: CORS Security
CRITICAL: These tests verify CORS configuration security.

Test IDs:
- CORS-P0-001: Wildcard origin blocked in production
- CORS-P0-002: Invalid URL scheme rejection
- CORS-P0-003: Localhost warning in production
- CORS-P0-004: Trailing slash rejection
- CORS-P0-005: Mixed wildcard + specific origins blocked
- CORS-P0-006: Empty origin validation
"""

import os
import pytest


@pytest.mark.integration
@pytest.mark.security
class TestCORSWildcardBlocking:
    """CORS-P0-001: Wildcard origin blocking tests."""

    def test_production_rejects_wildcard_origin(self, monkeypatch):
        """CORS-P0-001-T1: Wildcard origin '*' blocked in production.

        Security Requirement:
        - Production environment MUST reject wildcard CORS origin
        - This prevents any website from making requests to the API
        """
        # Clear cached settings
        monkeypatch.setenv("TMWS_ENVIRONMENT", "production")
        monkeypatch.setenv("TMWS_DATABASE_URL", "sqlite+aiosqlite:///test.db")
        monkeypatch.setenv("TMWS_SECRET_KEY", "production_secret_key_32_chars_min!!")

        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(["*"], "production")

        assert "Wildcard" in str(exc_info.value)
        assert "production" in str(exc_info.value).lower()

    def test_development_allows_wildcard_origin(self, monkeypatch):
        """CORS-P0-001-T2: Wildcard allowed in development.

        Development mode should allow wildcard for convenience.
        """
        from src.core.config_validators.cors_validator import validate_cors_origins

        # Should NOT raise
        result = validate_cors_origins(["*"], "development")
        assert result == ["*"]


@pytest.mark.integration
@pytest.mark.security
class TestCORSURLSchemeValidation:
    """CORS-P0-002: URL scheme validation tests."""

    def test_rejects_ftp_scheme(self):
        """CORS-P0-002-T1: FTP scheme rejected."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(["ftp://example.com"], "development")

        assert "http://" in str(exc_info.value) or "https://" in str(exc_info.value)

    def test_rejects_file_scheme(self):
        """CORS-P0-002-T2: File scheme rejected."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(["file:///path/to/file"], "development")

        assert "http" in str(exc_info.value).lower()

    def test_rejects_javascript_scheme(self):
        """CORS-P0-002-T3: JavaScript scheme rejected (XSS vector)."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(["javascript:alert(1)"], "development")

        assert "http" in str(exc_info.value).lower()

    def test_accepts_http_scheme(self):
        """CORS-P0-002-T4: HTTP scheme accepted."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        result = validate_cors_origins(["http://localhost:3000"], "development")
        assert "http://localhost:3000" in result

    def test_accepts_https_scheme(self):
        """CORS-P0-002-T5: HTTPS scheme accepted."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        result = validate_cors_origins(["https://example.com"], "development")
        assert "https://example.com" in result


@pytest.mark.integration
@pytest.mark.security
class TestCORSLocalhostWarning:
    """CORS-P0-003: Localhost warning in production tests."""

    def test_localhost_warns_in_production(self, caplog):
        """CORS-P0-003-T1: Localhost origins trigger warning in production."""
        import logging

        from src.core.config_validators.cors_validator import validate_cors_origins

        with caplog.at_level(logging.WARNING):
            result = validate_cors_origins(
                ["http://localhost:3000", "https://app.example.com"],
                "production"
            )

        # Should allow but warn
        assert "http://localhost:3000" in result
        assert "localhost" in caplog.text.lower()

    def test_127_0_0_1_warns_in_production(self, caplog):
        """CORS-P0-003-T2: 127.0.0.1 origins trigger warning in production."""
        import logging

        from src.core.config_validators.cors_validator import validate_cors_origins

        with caplog.at_level(logging.WARNING):
            validate_cors_origins(
                ["http://127.0.0.1:8080"],
                "production"
            )

        assert "127.0.0.1" in caplog.text


@pytest.mark.integration
@pytest.mark.security
class TestCORSTrailingSlash:
    """CORS-P0-004: Trailing slash rejection tests."""

    def test_rejects_trailing_slash(self):
        """CORS-P0-004-T1: Origins with trailing slash rejected."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(["https://example.com/"], "development")

        assert "trailing slash" in str(exc_info.value).lower()

    def test_accepts_origin_without_trailing_slash(self):
        """CORS-P0-004-T2: Origins without trailing slash accepted."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        result = validate_cors_origins(["https://example.com"], "development")
        assert "https://example.com" in result


@pytest.mark.integration
@pytest.mark.security
class TestCORSMixedWildcard:
    """CORS-P0-005: Mixed wildcard + specific origins tests."""

    def test_rejects_mixed_wildcard_and_specific(self):
        """CORS-P0-005-T1: Cannot mix wildcard with specific origins."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(
                ["*", "https://example.com"],
                "development"
            )

        assert "wildcard" in str(exc_info.value).lower()
        assert "specific" in str(exc_info.value).lower()

    def test_accepts_multiple_specific_origins(self):
        """CORS-P0-005-T2: Multiple specific origins allowed."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        result = validate_cors_origins(
            ["https://app.example.com", "https://admin.example.com"],
            "production"
        )

        assert len(result) == 2
        assert "https://app.example.com" in result
        assert "https://admin.example.com" in result


@pytest.mark.integration
@pytest.mark.security
class TestCORSEmptyOrigin:
    """CORS-P0-006: Empty origin validation tests."""

    def test_rejects_empty_string_origin(self):
        """CORS-P0-006-T1: Empty string origin rejected."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins([""], "development")

        assert "empty" in str(exc_info.value).lower()

    def test_rejects_whitespace_only_origin(self):
        """CORS-P0-006-T2: Whitespace-only origin rejected."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins(["   "], "development")

        assert "empty" in str(exc_info.value).lower()

    def test_production_requires_cors_configuration(self):
        """CORS-P0-006-T3: Production requires explicit CORS configuration."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        with pytest.raises(ValueError) as exc_info:
            validate_cors_origins([], "production")

        assert "production" in str(exc_info.value).lower()

    def test_development_allows_empty_cors(self):
        """CORS-P0-006-T4: Development allows empty CORS (for local testing)."""
        from src.core.config_validators.cors_validator import validate_cors_origins

        result = validate_cors_origins([], "development")
        assert result == []
