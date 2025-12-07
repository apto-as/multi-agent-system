"""CORS Validator - CORS security validation.

This module handles CORS origin validation:
- Block wildcard origins in production
- Validate URL schemes (http/https only)
- Check for trailing slashes
- Warn about localhost in production

Security Patterns:
- 404 Security Standards compliance
- Zero tolerance for wildcard in production
- Explicit origin configuration required
"""

import logging

logger = logging.getLogger(__name__)


def validate_cors_origins(origins: list[str], environment: str) -> list[str]:
    """Validate CORS origins for security compliance.

    Prevents:
    1. Wildcard origins ("*") in production
    2. Invalid URL schemes (only http/https allowed)
    3. Trailing slashes in origins
    4. Empty origin strings
    5. Mixed wildcard with specific origins

    Args:
        origins: List of CORS origin strings
        environment: Current runtime environment

    Returns:
        Validated list of origins

    Raises:
        ValueError: If validation fails
    """
    # Empty list check
    if not origins:
        if environment == "production":
            raise ValueError("CORS origins must be explicitly configured in production")
        return origins  # Allow empty in development

    # Check for wildcard presence
    has_wildcard = "*" in origins

    # Validate each origin
    for origin in origins:
        _validate_single_origin(origin, environment, has_wildcard, len(origins))

    # Check for localhost origins in production
    _warn_localhost_in_production(origins, environment)

    return origins


def _validate_single_origin(
    origin: str,
    environment: str,
    has_wildcard: bool,
    total_origins: int,
) -> None:
    """Validate a single CORS origin.

    Args:
        origin: Origin string to validate
        environment: Current runtime environment
        has_wildcard: Whether wildcard is present in origins list
        total_origins: Total number of origins

    Raises:
        ValueError: If origin is invalid
    """
    # Empty string check
    if not origin or not origin.strip():
        raise ValueError("CORS origin cannot be empty string")

    # Wildcard validation
    if origin == "*":
        if environment == "production":
            raise ValueError(
                "Wildcard CORS origin '*' not allowed in production. "
                "Specify explicit origins like 'https://example.com'"
            )
        # Check for mixed wildcard + specific origins
        if total_origins > 1:
            raise ValueError("Cannot use wildcard '*' with specific origins")
        return  # Wildcard is valid, no further checks needed

    # URL scheme validation (skip wildcard)
    if not origin.startswith(("http://", "https://")):
        raise ValueError(
            f"Invalid CORS origin '{origin}': Must start with 'http://' or 'https://'"
        )

    # Trailing slash check
    if origin.endswith("/"):
        raise ValueError(
            f"Invalid CORS origin '{origin}': Must not end with trailing slash"
        )


def _warn_localhost_in_production(origins: list[str], environment: str) -> None:
    """Warn about localhost origins in production.

    Args:
        origins: List of CORS origins
        environment: Current runtime environment
    """
    if environment != "production":
        return

    localhost_origins = [o for o in origins if "localhost" in o or "127.0.0.1" in o]
    if localhost_origins:
        logger.warning(f"Localhost CORS origins in production: {localhost_origins}")
