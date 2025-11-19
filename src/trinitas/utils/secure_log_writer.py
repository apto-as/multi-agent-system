"""
Secure Log Writer - WK-6 Fix: Direct Log File Access

This module provides secure log file writing with:
1. Enforced file permissions (0o600 - owner read/write only)
2. Optional encryption for sensitive log entries
3. Automatic permission validation on every write

Security References:
- WK-6: Direct Log File Access (HIGH)
- CWE-732: Incorrect Permission Assignment for Critical Resource
- OWASP Logging Security
"""

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


class SecureLogWriter:
    """
    Secure log file writer with enforced permissions and optional encryption.

    Features:
    - Automatic chmod 600 on all log files (owner read/write only)
    - Optional encryption for sensitive entries
    - Permission validation on every write
    - Rotation support with secure permissions

    Example:
        >>> writer = SecureLogWriter(Path("logs/app.log"))
        >>> writer.write("Normal log entry")
        >>> writer.write_encrypted("Sensitive data", encryption_key)
    """

    SECURE_PERMISSIONS = 0o600  # Owner read/write only

    def __init__(
        self,
        log_file: Path,
        encryption_key: bytes | None = None,
        enforce_permissions: bool = True,
    ):
        """
        Initialize secure log writer.

        Args:
            log_file: Path to log file
            encryption_key: Optional Fernet key for encryption (32 bytes)
            enforce_permissions: Whether to enforce file permissions (default: True)

        Raises:
            ValueError: If encryption_key is provided but invalid
        """
        self.log_file = log_file
        self.enforce_permissions = enforce_permissions
        self.cipher: Fernet | None = None

        if encryption_key:
            try:
                self.cipher = Fernet(encryption_key)
            except Exception as e:
                raise ValueError(f"Invalid encryption key: {e}") from e

        # Ensure parent directory exists and log file is created with secure permissions
        self._ensure_secure_setup()

    def _ensure_secure_setup(self) -> None:
        """
        Ensure log file and directory have secure permissions.

        Creates parent directory if needed, touches log file with secure
        permissions, and validates current permissions.
        """
        # Create parent directory with restrictive permissions
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Touch file with secure permissions if it doesn't exist
        if not self.log_file.exists():
            self.log_file.touch(mode=self.SECURE_PERMISSIONS)
            logger.info(f"Created log file with secure permissions: {self.log_file}")

        # Enforce permissions if enabled
        if self.enforce_permissions:
            self._enforce_permissions()

    def _enforce_permissions(self) -> None:
        """
        Enforce secure file permissions (0o600).

        Raises:
            PermissionError: If unable to set permissions
        """
        try:
            current_permissions = self.log_file.stat().st_mode & 0o777

            if current_permissions != self.SECURE_PERMISSIONS:
                os.chmod(self.log_file, self.SECURE_PERMISSIONS)
                logger.warning(
                    f"Fixed insecure permissions on {self.log_file}: "
                    f"{oct(current_permissions)} -> {oct(self.SECURE_PERMISSIONS)}"
                )
        except Exception as e:
            raise PermissionError(
                f"Failed to enforce permissions on {self.log_file}: {e}"
            ) from e

    def _validate_permissions(self) -> bool:
        """
        Validate current file permissions are secure.

        Returns:
            True if permissions are secure (0o600), False otherwise
        """
        if not self.enforce_permissions:
            return True

        try:
            current_permissions = self.log_file.stat().st_mode & 0o777
            return current_permissions == self.SECURE_PERMISSIONS
        except Exception as e:
            logger.error(f"Failed to validate permissions: {e}")
            return False

    def write(self, message: str, validate_permissions: bool = True) -> None:
        """
        Write message to log file with permission validation.

        Args:
            message: Message to write
            validate_permissions: Whether to validate permissions before write

        Raises:
            PermissionError: If permissions are insecure and validation is enabled
        """
        if validate_permissions and not self._validate_permissions():
            self._enforce_permissions()

        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(message)
                if not message.endswith('\n'):
                    f.write('\n')
        except Exception as e:
            logger.error(f"Failed to write to log file {self.log_file}: {e}")
            raise

    def write_encrypted(self, message: str, encryption_key: bytes | None = None) -> None:
        """
        Write encrypted message to log file.

        Args:
            message: Message to encrypt and write
            encryption_key: Optional key to override instance key

        Raises:
            ValueError: If no encryption key is available
        """
        cipher = self.cipher
        if encryption_key:
            try:
                cipher = Fernet(encryption_key)
            except Exception as e:
                raise ValueError(f"Invalid encryption key: {e}") from e

        if not cipher:
            raise ValueError("No encryption key available")

        try:
            encrypted = cipher.encrypt(message.encode('utf-8'))
            encrypted_str = encrypted.decode('ascii')
            self.write(f"[ENCRYPTED] {encrypted_str}")
        except Exception as e:
            logger.error(f"Failed to encrypt and write message: {e}")
            raise

    def read_encrypted(
        self,
        line: str,
        encryption_key: bytes | None = None
    ) -> str | None:
        """
        Decrypt an encrypted log line.

        Args:
            line: Encrypted log line (must start with "[ENCRYPTED] ")
            encryption_key: Optional key to override instance key

        Returns:
            Decrypted message, or None if decryption fails
        """
        cipher = self.cipher
        if encryption_key:
            try:
                cipher = Fernet(encryption_key)
            except Exception as e:
                logger.error(f"Invalid encryption key: {e}")
                return None

        if not cipher:
            logger.error("No encryption key available")
            return None

        if not line.startswith("[ENCRYPTED] "):
            return None

        try:
            encrypted_str = line[12:].strip()
            encrypted = encrypted_str.encode('ascii')
            decrypted = cipher.decrypt(encrypted)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return None

    def rotate(self, max_size_mb: int = 10) -> bool:
        """
        Rotate log file if it exceeds max size.

        Args:
            max_size_mb: Maximum file size in MB before rotation

        Returns:
            True if rotation occurred, False otherwise
        """
        if not self.log_file.exists():
            return False

        size_mb = self.log_file.stat().st_size / (1024 * 1024)
        if size_mb < max_size_mb:
            return False

        # Rotate: log.txt -> log.txt.1, log.txt.1 -> log.txt.2, etc.
        backup_path = self.log_file.with_suffix(self.log_file.suffix + '.1')

        try:
            if backup_path.exists():
                backup_path.unlink()

            self.log_file.rename(backup_path)

            # Set secure permissions on backup
            if self.enforce_permissions:
                os.chmod(backup_path, self.SECURE_PERMISSIONS)

            # Create new log file with secure permissions
            self.log_file.touch(mode=self.SECURE_PERMISSIONS)

            logger.info(f"Rotated log file: {self.log_file} -> {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to rotate log file: {e}")
            return False

    @staticmethod
    def generate_encryption_key() -> bytes:
        """
        Generate a new Fernet encryption key.

        Returns:
            32-byte encryption key suitable for Fernet
        """
        return Fernet.generate_key()

    def __repr__(self) -> str:
        """String representation of SecureLogWriter."""
        return (
            f"SecureLogWriter(log_file={self.log_file}, "
            f"encrypted={self.cipher is not None}, "
            f"permissions={oct(self.SECURE_PERMISSIONS)})"
        )
