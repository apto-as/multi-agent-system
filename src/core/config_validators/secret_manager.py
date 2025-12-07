"""Secret Manager - Secret key generation and loading.

This module handles cryptographic secret key management:
- Load existing secret key from file
- Generate new cryptographically secure secret key
- Save secret key with secure file permissions

Security Patterns:
- 404 Security Standards compliance
- File permissions: 0o600 (owner read/write only)
- Cryptographic randomness via secrets module
"""

import logging
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

# Smart defaults for uvx one-command installation
TMWS_HOME = Path.home() / ".tmws"
TMWS_SECRET_FILE = TMWS_HOME / ".secret_key"


def load_or_generate_secret_key(
    environment: str,
    secret_file: Path = TMWS_SECRET_FILE,
    tmws_home: Path = TMWS_HOME,
) -> str:
    """Load existing secret key or generate a new one.

    This function implements the smart default pattern for development:
    1. If secret file exists, load and return it
    2. Otherwise, generate a new cryptographically secure key
    3. Save the key with secure file permissions (0o600)

    Args:
        environment: Current runtime environment
        secret_file: Path to secret key file (default: ~/.tmws/.secret_key)
        tmws_home: TMWS home directory (default: ~/.tmws)

    Returns:
        Secret key string (32 bytes, URL-safe base64 encoded)

    Note:
        Only generates keys in development mode. Production requires
        explicit TMWS_SECRET_KEY environment variable.
    """
    if environment != "development":
        # Production/staging should not auto-generate keys
        return ""

    # Ensure TMWS home directory exists
    tmws_home.mkdir(parents=True, exist_ok=True)

    # Try to load existing secret key
    if secret_file.exists():
        secret_key = secret_file.read_text().strip()
        logger.info("Using existing secret key from ~/.tmws/.secret_key")
        return secret_key

    # Generate and save new secret key
    secret_key = secrets.token_urlsafe(32)
    secret_file.write_text(secret_key)
    secret_file.chmod(0o600)  # Read/write for owner only
    logger.info("Generated new secret key and saved to ~/.tmws/.secret_key")

    return secret_key
