"""Config Validators Package - Extracted validators for config.py.

This package contains validators extracted from config.py to reduce C901 complexity:
- secret_manager: Secret key generation and loading
- env_resolver: Environment variable resolution
- cors_validator: CORS security validation
- production_validator: Production security checks

All validators are pure functions that can be used by config.py's Pydantic validators.
"""

from .cors_validator import validate_cors_origins
from .env_resolver import resolve_environment_variables
from .production_validator import (
    validate_production_settings,
    validate_staging_settings,
)
from .secret_manager import load_or_generate_secret_key

__all__ = [
    "load_or_generate_secret_key",
    "resolve_environment_variables",
    "validate_cors_origins",
    "validate_production_settings",
    "validate_staging_settings",
]
