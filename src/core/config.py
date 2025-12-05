"""Configuration management for TMWS.
404 Security Standards: Zero compromise, zero defaults for sensitive data.
"""

import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .exceptions import ConfigurationError

logger = logging.getLogger(__name__)

# Smart defaults for uvx one-command installation
TMWS_HOME = Path.home() / ".tmws"
TMWS_DATA_DIR = TMWS_HOME / "data"
TMWS_CHROMA_DIR = TMWS_HOME / "chroma"
TMWS_SECRET_FILE = TMWS_HOME / ".secret_key"


class Settings(BaseSettings):
    """Application settings with Artemis 404 security standards.

    Security Principles:
    1. No hardcoded credentials - ALL sensitive data from environment
    2. Fail fast on missing required values
    3. Production-grade validation enforced
    4. Development defaults ONLY where safe
    """

    # ==== CRITICAL SECURITY SETTINGS (REQUIRED) ====
    # Database - MANDATORY environment variable, no fallbacks
    database_url: str = Field(
        default="",
        description="Database connection URL - MUST be set via TMWS_DATABASE_URL",
        min_length=10,
    )

    # Security - MANDATORY secret key, no insecure defaults
    secret_key: str = Field(
        default="",
        description="Cryptographic secret key - MUST be set via TMWS_SECRET_KEY (min 32 chars)",
        min_length=32,
    )

    # Environment - REQUIRED for proper validation
    environment: str = Field(
        default="development",
        description="Runtime environment - MUST be set via TMWS_ENVIRONMENT",
        pattern="^(development|staging|production|test)$",
    )

    # ==== DATABASE CONFIGURATION ====
    db_echo_sql: bool = Field(default=False)  # Never log SQL in production

    # ==== LOCAL DATABASE (SQLite + Chroma) ====
    # v2.2.6: Full migration to SQLite (metadata) + Chroma (vectors)

    # ==== API CONFIGURATION ====
    api_host: str = Field(default="127.0.0.1")  # Secure default: localhost only
    api_port: int = Field(default=8000, ge=1024, le=65535)
    api_reload: bool = Field(default=False)  # Never auto-reload in production
    api_title: str = Field(default="TMWS - Trinitas Memory & Workflow Service")
    api_version: str = Field(default="2.2.0")
    api_description: str = Field(default="Backend service for Trinitas AI agents")

    # ==== WEBSOCKET MCP CONFIGURATION ====
    ws_enabled: bool = Field(default=True, description="Enable WebSocket MCP server")
    ws_host: str = Field(default="127.0.0.1", description="WebSocket server host")
    ws_port: int = Field(default=8001, ge=1024, le=65535, description="WebSocket server port")

    # ==== JWT & AUTHENTICATION ====
    # Authentication mode control (404 Security Standard)
    auth_enabled: bool = Field(
        default=False,
        description="Enable production authentication - default False for development mode",
    )

    # ==== CORS - RESTRICTIVE BY DEFAULT ====
    cors_origins: list[str] = Field(
        default_factory=list,
        description="CORS origins - MUST be explicitly set for production",
    )

    # ==== SECURITY HARDENING ====
    security_headers_enabled: bool = Field(default=True)
    session_cookie_secure: bool = Field(default=True)
    session_cookie_httponly: bool = Field(default=True)
    session_cookie_samesite: str = Field(default="strict", pattern="^(strict|lax|none)$")

    # Content Security Policy
    csp_enabled: bool = Field(default=True)
    csp_policy: str = Field(
        default="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    )

    # ==== RATE LIMITING & SECURITY ====
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_requests: int = Field(default=100, ge=1, le=10000)

    # v2.4.4: Sliding window rate limiting (experimental)
    # When True, uses more accurate sliding window algorithm
    # When False (default), uses simpler fixed window algorithm
    use_sliding_window: bool = Field(
        default=False,
        description="Enable sliding window rate limiting (experimental)",
    )

    # v2.4.4: Rate limiter cache cleanup interval (seconds)
    # Old client stats are cleaned up periodically to prevent memory leaks
    rate_limit_cleanup_interval: int = Field(
        default=300,  # 5 minutes
        ge=60,
        le=3600,
        description="Interval between rate limit cache cleanups (seconds)",
    )

    # v2.4.4: Rate limiter cache retention period (seconds)
    # Client stats older than this are removed during cleanup
    rate_limit_cache_ttl: int = Field(
        default=3600,  # 1 hour
        ge=300,
        le=86400,
        description="Time to keep client stats before cleanup (seconds)",
    )

    # ==== VECTORIZATION & CHROMADB (v2.2.6: 1024-dim Multilingual-E5 Large) ====
    embedding_model: str = Field(default="zylonai/multilingual-e5-large")
    vector_dimension: int = Field(default=1024, ge=1, le=4096)  # ✅ Updated to 1024-dim (v2.2.6)

    # ChromaDB configuration
    chroma_persist_directory: str = Field(
        default=str(TMWS_CHROMA_DIR),
        description="ChromaDB persistence directory (smart default: ~/.tmws/chroma)",
    )
    chroma_collection: str = Field(default="tmws_memories")

    # ==== SKILLS SYSTEM CONFIGURATION (Phase 5B) ====
    # Core instructions length for Progressive Disclosure Layer 2
    skills_core_instructions_max_length: int = Field(
        default=500,
        ge=100,
        le=10000,
        description="Maximum length of core instructions extracted from skill content (default: 500 chars)",
    )

    # Input validation limits (S-3-M1: Input Size Validation)
    skills_max_field_length: int = Field(
        default=255,
        ge=1,
        le=1000,
        description="Maximum length for skill name, persona, and namespace fields (default: 255 chars)",
    )

    # ==== OLLAMA EMBEDDING CONFIGURATION (v2.3.0 - Ollama Required) ====
    # ⚠️ CRITICAL: Ollama is REQUIRED - no fallback mechanisms
    # This ensures consistent embedding dimensions and prevents silent failures
    # Install: https://ollama.ai/download
    # Setup: ollama pull zylonai/multilingual-e5-large && ollama serve

    # Ollama server configuration
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server URL for embedding generation",
    )

    # ==== LICENSE VERIFICATION (v2.4.1 - Ed25519 Public Key) ====
    # ⚠️ SECURITY: Public key for license signature verification
    # - Private key is kept by Trinitas (never distributed)
    # - Public key is embedded in Docker images (safe to distribute)
    # - Ed25519 provides 128-bit security level
    # - Signature verification prevents license key forgery
    # Format: Base64-encoded 32-byte Ed25519 public key
    license_public_key: str = Field(
        default="",
        description="Ed25519 public key for license verification (Base64-encoded). "
        "Set via TMWS_LICENSE_PUBLIC_KEY. If empty, falls back to HMAC verification.",
    )

    # ==== LOGGING & MONITORING ====
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")

    # Security logging
    audit_log_enabled: bool = Field(default=True)

    # ==== EMAIL ALERTS CONFIGURATION (P0 Security TODO) ====
    # SMTP configuration for security alert emails
    smtp_host: str = Field(
        default="",
        description="SMTP server hostname (e.g., smtp.gmail.com) - Optional, set via TMWS_SMTP_HOST",
    )
    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        description="SMTP server port (default: 587 for TLS)",
    )
    smtp_use_tls: bool = Field(
        default=True,
        description="Use TLS encryption for SMTP (recommended: True)",
    )
    smtp_username: str = Field(
        default="",
        description="SMTP authentication username - Optional, set via TMWS_SMTP_USERNAME",
    )
    smtp_password: str = Field(
        default="",
        description="SMTP authentication password - Optional, set via TMWS_SMTP_PASSWORD",
    )
    alert_email_from: str = Field(
        default="",
        description="Sender email address for alerts - Optional, set via TMWS_ALERT_EMAIL_FROM",
    )
    alert_email_to: str = Field(
        default="",
        description="Recipient email address for alerts - Optional, set via TMWS_ALERT_EMAIL_TO",
    )
    alert_webhook_url: str = Field(
        default="",
        description="Webhook URL for security alerts (Slack, Discord, etc.) - Optional, set via TMWS_ALERT_WEBHOOK_URL",
    )

    # ==== PERFORMANCE & CACHING ====
    cache_ttl: int = Field(default=3600, ge=1, le=86400)

    # ==== DATABASE ENCRYPTION (v2.4.12 - SQLCipher AES-256-GCM) ====
    # ⚠️ SECURITY: Database encryption at rest using SQLCipher
    # When enabled, requires pysqlcipher3 package and encryption key
    # Keys are stored in ~/.tmws/secrets/db_encryption.key (auto-generated)
    db_encryption_enabled: bool = Field(
        default=False,
        description="Enable SQLite database encryption using SQLCipher AES-256-GCM",
    )
    db_encryption_key_name: str = Field(
        default="db_encryption.key",
        description="Filename for encryption key in ~/.tmws/secrets/",
    )

    # ==== SKILLS API CONFIGURATION (Phase 6A) ====
    # Content validation limits
    skills_max_field_length: int = Field(
        default=255,
        ge=1,
        le=1000,
        description="Maximum length for skill name, description, etc.",
    )
    skills_core_instructions_max_length: int = Field(
        default=8000,
        ge=100,
        le=100000,
        description="Maximum length for core instructions (progressive disclosure level 2)",
    )

    # ==== VALIDATION RULES ====
    @model_validator(mode="before")
    @classmethod
    def validate_required_env_vars(cls, values):
        """Smart defaults for uvx one-command installation.

        Priority:
        1. Explicit environment variables (TMWS_*)
        2. Smart defaults (development only)
        3. Error for production without explicit config
        """
        import os

        # Get environment
        environment = (
            values.get("environment")
            or values.get("ENVIRONMENT")
            or os.environ.get("TMWS_ENVIRONMENT")
            or os.environ.get("ENVIRONMENT", "development")
        )
        values["environment"] = environment

        # Database URL
        if not values.get("database_url"):
            values["database_url"] = (
                values.get("DATABASE_URL")
                or os.environ.get("TMWS_DATABASE_URL")
                or os.environ.get("DATABASE_URL", "")
            )

        # Smart default for database (development only)
        if not values.get("database_url") and environment == "development":
            TMWS_DATA_DIR.mkdir(parents=True, exist_ok=True)
            values["database_url"] = f"sqlite+aiosqlite:///{TMWS_DATA_DIR}/tmws.db"
            logger.info(f"📁 Using smart default database: {values['database_url']}")

        # SMTP Configuration (Email Alerts - Optional)
        smtp_fields = {
            "smtp_host": ["SMTP_HOST", "TMWS_SMTP_HOST"],
            "smtp_port": ["SMTP_PORT", "TMWS_SMTP_PORT"],
            "smtp_use_tls": ["SMTP_USE_TLS", "TMWS_SMTP_USE_TLS"],
            "smtp_username": ["SMTP_USERNAME", "TMWS_SMTP_USERNAME"],
            "smtp_password": ["SMTP_PASSWORD", "TMWS_SMTP_PASSWORD"],
            "alert_email_from": ["ALERT_EMAIL_FROM", "TMWS_ALERT_EMAIL_FROM"],
            "alert_email_to": ["ALERT_EMAIL_TO", "TMWS_ALERT_EMAIL_TO"],
            "alert_webhook_url": ["ALERT_WEBHOOK_URL", "TMWS_ALERT_WEBHOOK_URL"],
        }

        for field, env_vars in smtp_fields.items():
            if not values.get(field):
                for env_var in env_vars:
                    env_value = os.environ.get(env_var, "")
                    if env_value:
                        values[field] = env_value
                        break

        # Secret Key
        if not values.get("secret_key"):
            values["secret_key"] = (
                values.get("SECRET_KEY")
                or os.environ.get("TMWS_SECRET_KEY")
                or os.environ.get("SECRET_KEY", "")
            )

        # Smart default for secret key (development only)
        if not values.get("secret_key") and environment == "development":
            TMWS_HOME.mkdir(parents=True, exist_ok=True)

            # Try to load existing secret key
            if TMWS_SECRET_FILE.exists():
                values["secret_key"] = TMWS_SECRET_FILE.read_text().strip()
                logger.info("🔐 Using existing secret key from ~/.tmws/.secret_key")
            else:
                # Generate and save new secret key
                values["secret_key"] = secrets.token_urlsafe(32)
                TMWS_SECRET_FILE.write_text(values["secret_key"])
                TMWS_SECRET_FILE.chmod(0o600)  # Read-only for owner
                logger.info("🔑 Generated new secret key and saved to ~/.tmws/.secret_key")

        # Validate required fields for production
        if environment == "production":
            errors = []
            if not values.get("database_url"):
                errors.append("TMWS_DATABASE_URL environment variable is required in production")
            if not values.get("secret_key"):
                errors.append("TMWS_SECRET_KEY environment variable is required in production")

            if errors:
                raise ValueError(f"Critical configuration missing: {'; '.join(errors)}")

        return values

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key_security(cls, v, info):
        """404 Security: Secret key must meet cryptographic standards."""
        environment = info.data.get("environment", "development") if info.data else "development"

        # Production requirements
        if environment == "production":
            if len(v) < 32:
                raise ValueError("Production secret key must be at least 32 characters")

            # Check for common weak keys
            weak_keys = [
                "change-this-in-production-to-a-secure-random-key",
                "debug",
                "test",
                "dev",
                "development",
                "secret",
                "password",
                "12345",
                "admin",
                "root",
                "default",
            ]

            if v.lower() in weak_keys or v.lower().startswith(tuple(weak_keys)):
                raise ValueError("Weak or default secret key detected in production")

            # Entropy check - must contain mixed case, numbers, special chars
            if not (
                any(c.isupper() for c in v)
                and any(c.islower() for c in v)
                and any(c.isdigit() for c in v)
            ):
                logger.warning("Secret key should contain mixed case letters and numbers")

        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url_security(cls, v, info):
        """404 Security: Database URL validation."""
        environment = info.data.get("environment", "development") if info.data else "development"

        # SQLite file path security check - Ensure not in /tmp or world-writable location
        if (
            environment == "production"
            and v.startswith("sqlite")
            and ("/tmp/" in v or "world-writable" in v)
        ):
            logger.warning("SQLite database in potentially insecure location")

        return v

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_security(cls, v, info):
        """404 Security: CORS must be properly configured.

        Prevents:
        1. Wildcard origins ("*") in production
        2. Invalid URL schemes (only http/https allowed)
        3. Trailing slashes in origins
        4. Empty origin strings

        Raises:
            ValueError: If validation fails
        """
        environment = info.data.get("environment", "development") if info.data else "development"

        # Empty list check
        if not v:
            if environment == "production":
                raise ValueError("CORS origins must be explicitly configured in production")
            return v  # Allow empty in development

        # Validate each origin
        for origin in v:
            # Empty string check
            if not origin or not origin.strip():
                raise ValueError("CORS origin cannot be empty string")

            # Block wildcard
            if origin == "*":
                if environment == "production":
                    raise ValueError(
                        "Wildcard CORS origin '*' not allowed in production. "
                        "Specify explicit origins like 'https://example.com'"
                    )
                # Also check for mixed wildcard + specific origins
                if len(v) > 1:
                    raise ValueError("Cannot use wildcard '*' with specific origins")

            # Validate URL scheme (skip wildcard)
            if origin != "*":
                if not origin.startswith(("http://", "https://")):
                    raise ValueError(
                        f"Invalid CORS origin '{origin}': Must start with 'http://' or 'https://'"
                    )

                # No trailing slash
                if origin.endswith("/"):
                    raise ValueError(
                        f"Invalid CORS origin '{origin}': Must not end with trailing slash"
                    )

        # Check for localhost origins in production
        if environment == "production":
            localhost_origins = [o for o in v if "localhost" in o or "127.0.0.1" in o]
            if localhost_origins:
                logger.warning(f"Localhost CORS origins in production: {localhost_origins}")

        return v

    @field_validator("api_host")
    @classmethod
    def validate_api_host_security(cls, v, info):
        """404 Security: API host validation."""
        environment = info.data.get("environment", "development") if info.data else "development"

        if environment == "production" and v == "0.0.0.0":
            logger.warning("API bound to 0.0.0.0 in production - ensure proper firewall/proxy")

        return v

    @field_validator("auth_enabled")
    @classmethod
    def validate_auth_enabled_security(cls, v, info):
        """404 Security: Authentication must be enabled in production.

        v2.2.0 Enhancement: Automatic enforcement, no bypass possible.
        """
        environment = info.data.get("environment", "development") if info.data else "development"

        if environment == "production":
            if not v:
                # Auto-enable authentication in production, log critical warning
                logger.critical(
                    "SECURITY: Authentication was disabled in production - AUTO-ENABLED for safety",
                )
                return True  # Force enable
            return v

        if environment == "staging" and not v:
            logger.warning(
                "Authentication disabled in staging - consider enabling for realistic testing",
            )

        return v

    @model_validator(mode="after")
    def validate_production_security(self):
        """404 Security: Final validation for production mode.

        v2.2.0: Multiple security validations with clear error messages.
        """
        errors = []

        # Authentication is mandatory
        if self.environment == "production" and not self.auth_enabled:
            # This should never happen due to auto-enable, but double-check
            errors.append("Authentication MUST be enabled (TMWS_AUTH_ENABLED=true)")

        # Rate limiting is mandatory
        if self.environment == "production" and not self.rate_limit_enabled:
            errors.append("Rate limiting MUST be enabled (TMWS_RATE_LIMIT_ENABLED=true)")

        # Security headers are mandatory
        if self.environment == "production" and not self.security_headers_enabled:
            errors.append("Security headers MUST be enabled (TMWS_SECURITY_HEADERS_ENABLED=true)")

        # Audit logging is mandatory
        if self.environment == "production" and not self.audit_log_enabled:
            errors.append("Audit logging MUST be enabled (TMWS_AUDIT_LOG_ENABLED=true)")

        if errors:
            raise ValueError(
                "CRITICAL PRODUCTION SECURITY VIOLATIONS:\n"
                + "\n".join(f"  - {e}" for e in errors),
            )

        return self

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"

    @property
    def is_staging(self) -> bool:
        """Check if running in staging environment."""
        return self.environment == "staging"

    @property
    def database_url_async(self) -> str:
        """Get async database URL (SQLite with aiosqlite)."""
        # v2.2.6: SQLite-only architecture, no PostgreSQL conversion needed
        return self.database_url

    def get_security_headers(self) -> dict:
        """Get security headers for HTTP responses."""
        headers = {}

        if self.security_headers_enabled:
            headers.update(
                {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                },
            )

            if self.csp_enabled:
                headers["Content-Security-Policy"] = self.csp_policy

        return headers

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  # Allow case insensitive env vars for better compatibility
        env_prefix="TMWS_",
        secrets_dir="/run/secrets" if os.path.exists("/run/secrets") else None,
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=False,
        extra="ignore",  # Ignore extra environment variables
    )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance with 404-level validation.

    Raises:
        ValueError: If critical configuration is missing or invalid
        EnvironmentError: If environment-specific validation fails

    """
    try:
        settings = Settings()

        # Validate critical security settings
        if settings.is_production:
            _validate_production_settings(settings)
        elif settings.is_staging:
            _validate_staging_settings(settings)

        return settings

    except (KeyboardInterrupt, SystemExit):
        # Never suppress user interrupts
        raise
    except ValueError as e:
        # Configuration validation errors (expected)
        logger.error(f"Configuration validation failed: {e}")
        logger.error("Ensure all required environment variables are set:")
        logger.error("- TMWS_DATABASE_URL")
        logger.error("- TMWS_SECRET_KEY")
        logger.error("- TMWS_ENVIRONMENT")
        raise ConfigurationError("Settings validation failed", details={"error": str(e)}) from e
    except Exception as e:
        # Unexpected errors - log with full context
        logger.critical(f"Unexpected error loading settings: {e}", exc_info=True)
        raise


def _validate_production_settings(settings: Settings) -> None:
    """404 Production Validation: Zero tolerance for security issues.

    Raises:
        ValueError: If any production security issue is detected

    """
    issues = []

    # Security validations
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

    if not settings.session_cookie_secure:
        issues.append("Insecure session cookies in production")

    if settings.session_cookie_samesite != "strict":
        logger.warning("Session cookies not using 'strict' SameSite in production")

    if not settings.security_headers_enabled:
        issues.append("Security headers disabled in production")

    # Authentication validation
    if not settings.auth_enabled:
        issues.append("Authentication disabled in production - critical security risk")

    # Rate limiting validation
    if not settings.rate_limit_enabled:
        issues.append("Rate limiting disabled in production")

    if settings.rate_limit_requests > 1000:
        logger.warning("High rate limit in production - consider lowering")

    if issues:
        raise ValueError(f"PRODUCTION SECURITY ISSUES DETECTED: {'; '.join(issues)}")

    logger.info("✅ Production security validation passed")


def _validate_staging_settings(settings: Settings) -> None:
    """Validate settings for staging environment."""
    warnings = []

    if settings.db_echo_sql:
        warnings.append("SQL echo enabled in staging")

    if settings.log_level == "DEBUG":
        warnings.append("Debug logging in staging")

    if warnings:
        logger.warning(f"Staging configuration warnings: {'; '.join(warnings)}")


def create_secure_env_template() -> str:
    """Create a template .env file with 404 security standards.

    Returns:
        str: Complete .env template with security comments

    """
    return """# TMWS Configuration - 404 Security Standards
# ============================================
# Copy this file to .env and update ALL values
# Never commit .env files to version control

# ==== CRITICAL CONFIGURATION (REQUIRED) ====
# Database connection - SQLite (metadata) + Chroma (vectors)
# Default: ~/.tmws/data/tmws.db (auto-created in development)
TMWS_DATABASE_URL=sqlite+aiosqlite:///path/to/your/tmws.db

# Cryptographic secret - Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
TMWS_SECRET_KEY=CHANGE_THIS_TO_A_SECURE_32_CHAR_RANDOM_KEY

# Runtime environment - Controls security validation
TMWS_ENVIRONMENT=development  # development|staging|production

# ==== API CONFIGURATION ====
# Bind to localhost for development, specific IP for production
TMWS_API_HOST=127.0.0.1
TMWS_API_PORT=8000
TMWS_API_RELOAD=false

# ==== SECURITY CONFIGURATION ====
# JWT settings
TMWS_JWT_ALGORITHM=HS256
TMWS_JWT_EXPIRE_MINUTES=30
TMWS_JWT_REFRESH_EXPIRE_DAYS=7

# Authentication control (404 Security Standard)
# Default: false (development mode), set to true for production
TMWS_AUTH_ENABLED=false

# CORS - Specify exact origins for production
TMWS_CORS_ORIGINS=["http://localhost:3000"]
TMWS_CORS_CREDENTIALS=false

# Session security
TMWS_SESSION_COOKIE_SECURE=true
TMWS_SESSION_COOKIE_HTTPONLY=true
TMWS_SESSION_COOKIE_SAMESITE=strict

# Security headers and CSP
TMWS_SECURITY_HEADERS_ENABLED=true
TMWS_CSP_ENABLED=true

# Rate limiting and brute force protection
TMWS_RATE_LIMIT_ENABLED=true
TMWS_RATE_LIMIT_REQUESTS=100
TMWS_RATE_LIMIT_PERIOD=60
TMWS_MAX_LOGIN_ATTEMPTS=5
TMWS_LOCKOUT_DURATION_MINUTES=15

# ==== DATABASE CONFIGURATION ====
TMWS_DB_MAX_CONNECTIONS=10
TMWS_DB_ECHO_SQL=false
TMWS_DB_POOL_PRE_PING=true
TMWS_DB_POOL_RECYCLE=3600

# ==== LOGGING & MONITORING ====
TMWS_LOG_LEVEL=INFO
TMWS_LOG_FORMAT=json
TMWS_SECURITY_LOG_ENABLED=true
TMWS_AUDIT_LOG_ENABLED=true

# ==== PERFORMANCE & CACHING ====
TMWS_CACHE_TTL=3600
TMWS_CACHE_MAX_SIZE=1000

# ==== VECTORIZATION (v2.2.6: 1024-dim Multilingual-E5 Large) ====
TMWS_EMBEDDING_MODEL=zylonai/multilingual-e5-large
TMWS_VECTOR_DIMENSION=1024
TMWS_MAX_EMBEDDING_BATCH_SIZE=32

# ==== OLLAMA EMBEDDING CONFIGURATION (v2.3.0 - Ollama Required) ====
# ⚠️ CRITICAL: Ollama is REQUIRED - no fallback mechanisms
# Install: https://ollama.ai/download
# Setup: ollama pull zylonai/multilingual-e5-large && ollama serve

# Ollama server URL (default: localhost)
TMWS_OLLAMA_BASE_URL=http://localhost:11434

# Ollama embedding model (zylonai/multilingual-e5-large for cross-lingual support)
TMWS_OLLAMA_EMBEDDING_MODEL=zylonai/multilingual-e5-large

# Ollama request timeout (seconds)
TMWS_OLLAMA_TIMEOUT=30.0

# ==== OPTIONAL CONFIGURATION ====
# Log file path (optional)
# TMWS_LOG_FILE=/var/log/tmws/app.log

# Custom CSP policy (optional)
# TMWS_CSP_POLICY="default-src 'self'; script-src 'self'"
"""


def validate_environment_security() -> dict:
    """Validate current environment security configuration.

    Returns:
        dict: Security validation results

    """
    try:
        settings = get_settings()

        results = {
            "environment": settings.environment,
            "security_level": "unknown",
            "issues": [],
            "warnings": [],
            "recommendations": [],
        }

        if settings.is_production:
            try:
                _validate_production_settings(settings)
                results["security_level"] = "production-grade"
            except ValueError as e:
                results["security_level"] = "insecure"
                results["issues"].append(str(e))

        elif settings.is_staging:
            _validate_staging_settings(settings)
            results["security_level"] = "staging-appropriate"

        else:
            results["security_level"] = "development"
            results["recommendations"].append("Ensure production settings before deployment")

        return results

    except (KeyboardInterrupt, SystemExit):
        # Never suppress user interrupts
        raise
    except ConfigurationError as e:
        # Configuration errors (expected) - return structured error
        logger.error(f"Configuration error during validation: {e}")
        return {
            "environment": "unknown",
            "security_level": "configuration_error",
            "issues": [str(e)],
            "warnings": [],
            "recommendations": ["Fix configuration errors before proceeding"],
        }
    except Exception as e:
        # Unexpected errors - log and return error state
        logger.critical(f"Unexpected error during security validation: {e}", exc_info=True)
        return {
            "environment": "unknown",
            "security_level": "configuration_error",
            "issues": [f"Unexpected error: {e}"],
            "warnings": [],
            "recommendations": ["Fix configuration errors before proceeding"],
        }


# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
SRC_DIR = PROJECT_ROOT / "src"
MIGRATIONS_DIR = PROJECT_ROOT / "migrations"
TESTS_DIR = PROJECT_ROOT / "tests"
LOGS_DIR = PROJECT_ROOT / "logs"

# Ensure critical directories exist (skip in Docker/production environments)
# In Docker, directories are created by docker-compose volumes
try:
    LOGS_DIR.mkdir(exist_ok=True, mode=0o750)  # Secure directory permissions
except PermissionError:
    # In Docker/production, directories are managed externally
    pass

# Global settings instance for application use
settings = get_settings()

# Export public interface
__all__ = [
    "Settings",
    "get_settings",
    "settings",
    "create_secure_env_template",
    "validate_environment_security",
    "PROJECT_ROOT",
    "SRC_DIR",
    "MIGRATIONS_DIR",
    "TESTS_DIR",
    "LOGS_DIR",
]
