"""
Unified Security Utilities for TMWS
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
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password to hash

    Returns:
        Hashed password string
    """
    if not password:
        raise ValueError("Password cannot be empty")

    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password.

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
    """
    Hash a password with a separate salt (for legacy compatibility).

    Args:
        password: Plain text password to hash

    Returns:
        Tuple of (hashed_password, salt)
    """
    salt = secrets.token_hex(32)
    combined = password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return hashed, salt


def verify_password_with_salt(password: str, hashed: str, salt: str) -> bool:
    """
    Verify a password with a separate salt (for legacy compatibility).

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
    return computed_hash == hashed


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Length of the token in bytes (default 32)

    Returns:
        Hex string of the token
    """
    return secrets.token_hex(length)


def generate_api_key() -> str:
    """
    Generate a secure API key.

    Returns:
        API key string
    """
    return f"tmws_{secrets.token_urlsafe(32)}"


# Alias for backward compatibility
get_password_hash = hash_password
