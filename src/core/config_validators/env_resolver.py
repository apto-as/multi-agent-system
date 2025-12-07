"""Environment Resolver - Environment variable resolution.

This module handles smart environment variable resolution:
- Resolve environment with fallback chain
- Resolve database URL with smart defaults
- Resolve SMTP configuration fields
- Resolve secret key with smart defaults

Security Patterns:
- Explicit environment variables take priority
- Smart defaults only in development mode
- Production requires explicit configuration
"""

import logging
import os
from pathlib import Path
from typing import Any

from .secret_manager import load_or_generate_secret_key

logger = logging.getLogger(__name__)

# Smart defaults for uvx one-command installation
TMWS_HOME = Path.home() / ".tmws"
TMWS_DATA_DIR = TMWS_HOME / "data"


def resolve_environment_variables(values: dict[str, Any]) -> dict[str, Any]:
    """Resolve environment variables with smart defaults.

    Priority order:
    1. Explicit values in dict
    2. TMWS_* prefixed environment variables
    3. Non-prefixed environment variables
    4. Smart defaults (development only)

    Args:
        values: Dictionary of configuration values

    Returns:
        Updated dictionary with resolved values

    Raises:
        ValueError: If production is missing required config
    """
    # Step 1: Resolve environment
    environment = _resolve_environment(values)
    values["environment"] = environment

    # Step 2: Resolve database URL
    values["database_url"] = _resolve_database_url(values, environment)

    # Step 3: Resolve SMTP fields
    _resolve_smtp_fields(values)

    # Step 4: Resolve secret key
    values["secret_key"] = _resolve_secret_key(values, environment)

    # Step 5: Validate production requirements
    _validate_production_requirements(values, environment)

    return values


def _resolve_environment(values: dict[str, Any]) -> str:
    """Resolve the runtime environment.

    Args:
        values: Configuration values dict

    Returns:
        Resolved environment string
    """
    return (
        values.get("environment")
        or values.get("ENVIRONMENT")
        or os.environ.get("TMWS_ENVIRONMENT")
        or os.environ.get("ENVIRONMENT", "development")
    )


def _resolve_database_url(values: dict[str, Any], environment: str) -> str:
    """Resolve database URL with smart defaults.

    Args:
        values: Configuration values dict
        environment: Current environment

    Returns:
        Resolved database URL
    """
    # Try explicit values first
    database_url = (
        values.get("database_url")
        or values.get("DATABASE_URL")
        or os.environ.get("TMWS_DATABASE_URL")
        or os.environ.get("DATABASE_URL", "")
    )

    # Smart default for development only
    if not database_url and environment == "development":
        TMWS_DATA_DIR.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite+aiosqlite:///{TMWS_DATA_DIR}/tmws.db"
        logger.info(f"Using smart default database: {database_url}")

    return database_url


def _resolve_smtp_fields(values: dict[str, Any]) -> None:
    """Resolve SMTP configuration fields.

    Modifies values dict in place.

    Args:
        values: Configuration values dict to update
    """
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


def _resolve_secret_key(values: dict[str, Any], environment: str) -> str:
    """Resolve secret key with smart defaults.

    Args:
        values: Configuration values dict
        environment: Current environment

    Returns:
        Resolved secret key
    """
    # Try explicit values first
    secret_key = (
        values.get("secret_key")
        or values.get("SECRET_KEY")
        or os.environ.get("TMWS_SECRET_KEY")
        or os.environ.get("SECRET_KEY", "")
    )

    # Smart default for development only
    if not secret_key and environment == "development":
        secret_key = load_or_generate_secret_key(environment)

    return secret_key


def _validate_production_requirements(values: dict[str, Any], environment: str) -> None:
    """Validate required fields for production.

    Args:
        values: Configuration values dict
        environment: Current environment

    Raises:
        ValueError: If production is missing required config
    """
    if environment != "production":
        return

    errors = []
    if not values.get("database_url"):
        errors.append("TMWS_DATABASE_URL environment variable is required in production")
    if not values.get("secret_key"):
        errors.append("TMWS_SECRET_KEY environment variable is required in production")

    if errors:
        raise ValueError(f"Critical configuration missing: {'; '.join(errors)}")
