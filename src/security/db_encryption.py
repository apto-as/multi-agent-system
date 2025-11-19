"""Database Encryption Module for TMWS v2.3.3

This module provides SQLite database encryption using SQLCipher with AES-256-GCM.
Implements P0-1 security fix for plaintext database storage (CVSS 9.1 CRITICAL).

Features:
- AES-256-GCM encryption (256-bit key)
- Secure key generation and storage
- Transparent encryption/decryption
- Production-ready key management

Security:
- Encryption keys stored in .tmws/secrets/ (git-ignored)
- Key rotation support (future)
- Machine-bound keys (Phase 2 integration)

Author: Artemis (Technical Perfectionist)
Created: 2025-11-19
Version: 2.3.3
"""

import secrets
from pathlib import Path
from typing import Any

import logging

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import StaticPool

# Use standard logging to avoid config dependencies
logger = logging.getLogger(__name__)


class DatabaseEncryptionService:
    """Service for managing encrypted SQLite databases with SQLCipher.

    This service provides encryption for SQLite databases using SQLCipher,
    ensuring data at rest is protected from unauthorized access.

    Usage:
        service = DatabaseEncryptionService()
        engine = await service.create_encrypted_engine(db_path, encryption_key)

    Security Notes:
        - Encryption keys must be 256-bit (64 hex characters)
        - Keys should be stored securely in .tmws/secrets/
        - Never commit encryption keys to version control
    """

    CIPHER = "aes-256-gcm"  # Hestia's requirement: strongest available cipher
    KEY_LENGTH_BITS = 256
    KEY_LENGTH_HEX = 64  # 256 bits = 64 hex characters

    def __init__(self):
        """Initialize database encryption service."""
        self.secrets_dir = Path.home() / ".tmws" / "secrets"
        self.secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)  # Owner-only permissions

        logger.info("DatabaseEncryptionService initialized")
        logger.debug(f"Secrets directory: {self.secrets_dir}")

    def generate_encryption_key(self) -> str:
        """Generate a secure 256-bit encryption key.

        Returns:
            64-character hex string (256 bits)

        Example:
            >>> service = DatabaseEncryptionService()
            >>> key = service.generate_encryption_key()
            >>> len(key)
            64
        """
        key = secrets.token_hex(32)  # 32 bytes = 256 bits = 64 hex chars
        logger.info("Generated new 256-bit encryption key")
        return key

    def save_encryption_key(self, key: str, key_name: str = "db_encryption.key") -> Path:
        """Save encryption key to secure storage.

        Args:
            key: 64-character hex encryption key
            key_name: Filename for the key (default: db_encryption.key)

        Returns:
            Path to saved key file

        Raises:
            ValueError: If key length is invalid

        Security:
            - File permissions set to 0o600 (owner read/write only)
            - Directory permissions: 0o700 (owner only)
        """
        if len(key) != self.KEY_LENGTH_HEX:
            error_msg = f"Invalid key length: {len(key)} (expected {self.KEY_LENGTH_HEX})"
            logger.error(error_msg)
            raise ValueError(error_msg)

        key_path = self.secrets_dir / key_name
        key_path.write_text(key, encoding="utf-8")
        key_path.chmod(0o600)  # Owner read/write only

        logger.info(f"Encryption key saved: {key_path}")
        logger.warning("⚠️ CRITICAL: Backup this key securely. Lost keys = lost data.")

        return key_path

    def load_encryption_key(self, key_name: str = "db_encryption.key") -> str:
        """Load encryption key from secure storage.

        Args:
            key_name: Filename of the key (default: db_encryption.key)

        Returns:
            64-character hex encryption key

        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key length is invalid
        """
        key_path = self.secrets_dir / key_name

        if not key_path.exists():
            error_msg = f"Encryption key not found: {key_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        key = key_path.read_text(encoding="utf-8").strip()

        if len(key) != self.KEY_LENGTH_HEX:
            error_msg = f"Invalid key length in {key_path}: {len(key)} (expected {self.KEY_LENGTH_HEX})"
            logger.error(error_msg)
            raise ValueError(error_msg)

        logger.info(f"Encryption key loaded: {key_path}")
        return key

    async def create_encrypted_engine(
        self,
        db_path: str | Path,
        encryption_key: str | None = None,
        pool_size: int = 10,
        max_overflow: int = 20,
        echo: bool = False,
    ) -> AsyncEngine:
        """Create an async SQLAlchemy engine with SQLCipher encryption.

        Args:
            db_path: Path to SQLite database file
            encryption_key: 64-char hex encryption key (auto-loaded if None)
            pool_size: Connection pool size (default: 10)
            max_overflow: Max overflow connections (default: 20)

        Returns:
            Configured AsyncEngine with encryption enabled

        Example:
            >>> service = DatabaseEncryptionService()
            >>> engine = await service.create_encrypted_engine("./data/tmws.db")
        """
        # Auto-load encryption key if not provided
        if encryption_key is None:
            encryption_key = self.load_encryption_key()

        # Convert Path to string
        if isinstance(db_path, Path):
            db_path = str(db_path.resolve())

        # SQLCipher connection URL
        # Note: We use pysqlcipher3 package which provides SQLCipher support
        database_url = f"sqlite+pysqlcipher:///{db_path}"

        # Connection arguments for SQLCipher
        connect_args = {
            "check_same_thread": False,  # Required for async usage
            "key": encryption_key,  # Encryption key (raw hex string)
            "cipher": self.CIPHER,  # AES-256-GCM
            "kdf_iter": 256000,  # PBKDF2 iterations (SQLCipher 4 default)
        }

        # Create async engine
        # Note: StaticPool (used for :memory:) doesn't support pool_size/max_overflow
        if ":memory:" in db_path:
            engine = create_async_engine(
                database_url,
                connect_args=connect_args,
                poolclass=StaticPool,
                echo=echo,
            )
        else:
            engine = create_async_engine(
                database_url,
                connect_args=connect_args,
                pool_size=pool_size,
                max_overflow=max_overflow,
                echo=echo,
            )

        logger.info(f"Encrypted database engine created: {db_path}")
        logger.debug(f"Cipher: {self.CIPHER}, Pool size: {pool_size}, Max overflow: {max_overflow}")

        return engine

    def key_exists(self, key_name: str = "db_encryption.key") -> bool:
        """Check if encryption key exists.

        Args:
            key_name: Filename of the key (default: db_encryption.key)

        Returns:
            True if key exists, False otherwise
        """
        key_path = self.secrets_dir / key_name
        return key_path.exists()


# Singleton instance for application use
_encryption_service: DatabaseEncryptionService | None = None


def get_encryption_service() -> DatabaseEncryptionService:
    """Get or create singleton DatabaseEncryptionService instance.

    Returns:
        Singleton DatabaseEncryptionService instance
    """
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = DatabaseEncryptionService()
    return _encryption_service
