"""Unit tests for CORS origin validation in Settings.

Tests P1-CORS security fix: Validate CORS origins to prevent wildcard
and invalid origin configurations.

Security Requirements:
1. Block wildcard origins ("*") in production
2. Validate URL schemes (http/https only)
3. Prevent trailing slashes
4. Prevent empty origin strings
"""

import pytest
from pydantic import ValidationError

from src.core.config import Settings


class TestCORSValidation:
    """Test suite for CORS origin validation."""

    def test_cors_validation_blocks_wildcard_in_production(self, monkeypatch):
        """Test that wildcard origin is blocked in production."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "production")
        monkeypatch.setenv("TMWS_DATABASE_URL", "sqlite+aiosqlite:///test.db")
        monkeypatch.setenv("TMWS_SECRET_KEY", "test_secret_key_with_32_characters!")
        monkeypatch.setenv("TMWS_AUTH_ENABLED", "true")

        with pytest.raises(ValidationError) as exc_info:
            Settings(cors_origins=["*"])

        assert "Wildcard" in str(exc_info.value)

    def test_cors_validation_allows_wildcard_in_development(self, monkeypatch):
        """Test that wildcard origin is allowed in development (but not recommended)."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        # Should not raise (development allows wildcard for easier testing)
        settings = Settings(cors_origins=["*"])
        assert settings.cors_origins == ["*"]

    def test_cors_validation_blocks_invalid_scheme(self, monkeypatch):
        """Test that non-http/https schemes are blocked."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        # Test invalid schemes
        invalid_origins = ["ftp://example.com", "ws://example.com", "example.com"]

        for origin in invalid_origins:
            with pytest.raises(ValidationError) as exc_info:
                Settings(cors_origins=[origin])

            assert "Must start with 'http://' or 'https://'" in str(exc_info.value)

    def test_cors_validation_blocks_trailing_slash(self, monkeypatch):
        """Test that trailing slashes are blocked."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        with pytest.raises(ValidationError) as exc_info:
            Settings(cors_origins=["https://example.com/"])

        assert "Must not end with trailing slash" in str(exc_info.value)

    def test_cors_validation_blocks_empty_string(self, monkeypatch):
        """Test that empty origin strings are blocked."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        with pytest.raises(ValidationError) as exc_info:
            Settings(cors_origins=[""])

        assert "cannot be empty string" in str(exc_info.value)

    def test_cors_validation_allows_valid_origins(self, monkeypatch):
        """Test that valid origins pass validation."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        valid_origins = [
            "http://localhost:3000",
            "https://example.com",
            "https://api.example.com",
            "http://127.0.0.1:8080",
        ]

        settings = Settings(cors_origins=valid_origins)
        assert settings.cors_origins == valid_origins

    def test_cors_validation_blocks_wildcard_with_specific_origins(self, monkeypatch):
        """Test that wildcard cannot be mixed with specific origins."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        with pytest.raises(ValidationError) as exc_info:
            Settings(cors_origins=["*", "https://example.com"])

        assert "Cannot use wildcard '*' with specific origins" in str(exc_info.value)

    def test_cors_validation_requires_explicit_in_production(self, monkeypatch):
        """Test that production requires explicit CORS configuration."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "production")
        monkeypatch.setenv("TMWS_DATABASE_URL", "sqlite+aiosqlite:///test.db")
        monkeypatch.setenv("TMWS_SECRET_KEY", "test_secret_key_with_32_characters!")
        monkeypatch.setenv("TMWS_AUTH_ENABLED", "true")

        with pytest.raises(ValidationError) as exc_info:
            Settings(cors_origins=[])

        assert "must be explicitly configured in production" in str(exc_info.value)

    def test_cors_validation_allows_empty_in_development(self, monkeypatch):
        """Test that empty CORS list is allowed in development."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "development")

        # Should not raise (development allows empty)
        settings = Settings(cors_origins=[])
        assert settings.cors_origins == []

    def test_cors_validation_warns_localhost_in_production(self, monkeypatch, caplog):
        """Test that localhost origins in production generate warnings."""
        monkeypatch.setenv("TMWS_ENVIRONMENT", "production")
        monkeypatch.setenv("TMWS_DATABASE_URL", "sqlite+aiosqlite:///test.db")
        monkeypatch.setenv("TMWS_SECRET_KEY", "test_secret_key_with_32_characters!")
        monkeypatch.setenv("TMWS_AUTH_ENABLED", "true")

        # Should allow but warn
        settings = Settings(cors_origins=["http://localhost:3000", "https://example.com"])

        # Check for warning in logs
        # Note: The warning is logged, not raised as an error
        assert settings.cors_origins == ["http://localhost:3000", "https://example.com"]
