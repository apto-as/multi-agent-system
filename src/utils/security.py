"""Unified Security Utilities for TMWS
Centralized security functions to avoid duplication
"""

import hashlib
import logging
import secrets

from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# Single source of truth for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password to hash

    Returns:
        Hashed password string

    """
    if not password:
        raise ValueError("Password cannot be empty")

    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hashed password.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to compare against

    Returns:
        True if password matches, False otherwise

    """
    if not plain_password or not hashed_password:
        return False

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.warning(f"Password verification failed: {e}")
        return False


def hash_password_with_salt(password: str) -> tuple[str, str]:
    """Hash a password with a separate salt (for legacy compatibility).

    WARNING: This function uses SHA256 which is NOT secure for password hashing.
    It is vulnerable to GPU-accelerated brute force attacks.

    DEPRECATED: Use hash_password() instead, which uses bcrypt.
    This function exists only for backward compatibility with existing data.
    It will be removed in a future version.

    Args:
        password: Plain text password to hash

    Returns:
        Tuple of (hashed_password, salt)

    """
    import warnings

    warnings.warn(
        "hash_password_with_salt() is deprecated and insecure. "
        "Use hash_password() instead, which uses bcrypt.",
        DeprecationWarning,
        stacklevel=2,
    )
    logger.warning(
        "SECURITY: hash_password_with_salt() uses weak SHA256 hashing. "
        "Migrate to hash_password() which uses bcrypt.",
    )

    salt = secrets.token_hex(32)
    combined = password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return hashed, salt


def verify_password_with_salt(password: str, hashed: str, salt: str) -> bool:
    """Verify a password with a separate salt (for legacy compatibility).

    Args:
        password: Plain text password to verify
        hashed: Hashed password to compare against
        salt: Salt used in hashing

    Returns:
        True if password matches, False otherwise

    """
    if not all([password, hashed, salt]):
        return False

    combined = password + salt
    computed_hash = hashlib.sha256(combined.encode()).hexdigest()
    return secrets.compare_digest(computed_hash, hashed)


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token.

    Args:
        length: Length of the token in bytes (default 32)

    Returns:
        Hex string of the token

    """
    return secrets.token_hex(length)


def generate_api_key() -> str:
    """Generate a secure API key.

    Returns:
        API key string

    """
    return f"tmws_{secrets.token_urlsafe(32)}"


def generate_and_hash_api_key_for_agent() -> tuple[str, str]:
    """Generate a new API key for an agent and hash it with bcrypt (SECURE).

    This function should be used when creating new agents or regenerating API keys.

    Returns:
        Tuple of (raw_api_key, api_key_hash):
        - raw_api_key: Plaintext API key to give to the agent (show once only!)
        - api_key_hash: Bcrypt hash to store in Agent.api_key_hash

    Example:
        >>> raw_key, key_hash = generate_and_hash_api_key_for_agent()
        >>> agent.api_key_hash = key_hash  # Store bcrypt hash in DB
        >>> # Give raw_key to agent (display once, never store plaintext!)

    Security:
        - Uses bcrypt for secure hashing (CVSS 0.0 - not vulnerable to GPU brute force)
        - Replaces deprecated SHA256 with salt (CVSS 7.5 HIGH)
    """
    # Generate secure API key
    raw_api_key = generate_api_key()

    # Hash with bcrypt (SECURE)
    api_key_hash = hash_password(raw_api_key)

    return raw_api_key, api_key_hash


def detect_hash_format(api_key_hash: str) -> str:
    """Detect hash format from api_key_hash string.

    Args:
        api_key_hash: Hashed API key string

    Returns:
        "bcrypt" if bcrypt format ($2b$... or $2a$...)
        "sha256_salt" if "salt:hash" format

    Raises:
        ValueError: If hash format is unknown

    Example:
        >>> detect_hash_format("$2b$12$...")
        'bcrypt'
        >>> detect_hash_format("abc123:def456")
        'sha256_salt'
    """
    if not api_key_hash:
        raise ValueError("api_key_hash cannot be empty")

    # Bcrypt format: $2b$... or $2a$...
    if api_key_hash.startswith("$2b$") or api_key_hash.startswith("$2a$"):
        return "bcrypt"

    # SHA256 with salt format: "salt:hash"
    if ":" in api_key_hash:
        return "sha256_salt"

    # Unknown format
    raise ValueError(
        f"Unknown hash format: {api_key_hash[:20]}... "
        "(expected bcrypt '$2b$...' or SHA256 'salt:hash')"
    )


# Alias for backward compatibility
get_password_hash = hash_password
