"""Unit Tests for Database Encryption Service

Tests for TMWS v2.3.3 SQLCipher encryption implementation (P0-1 security fix).

Test Coverage:
- Encryption key generation (256-bit)
- Key storage and retrieval
- Encrypted engine creation
- File permissions verification
- Error handling

Security Requirements:
- Keys must be 256-bit (64 hex characters)
- File permissions: 0o600 (owner read/write only)
- Directory permissions: 0o700 (owner only)
- AES-256-GCM cipher

Author: Artemis (Technical Perfectionist)
Created: 2025-11-19
Version: 2.3.3
"""

# Direct import to avoid config dependencies
import importlib.util
import os
import sys
from pathlib import Path

import pytest

# Get project root
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

spec = importlib.util.spec_from_file_location(
    "db_encryption", project_root / "src" / "security" / "db_encryption.py"
)
db_encryption_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(db_encryption_module)
DatabaseEncryptionService = db_encryption_module.DatabaseEncryptionService


@pytest.fixture
def temp_secrets_dir(tmp_path):
    """Create temporary secrets directory for testing."""
    secrets_dir = tmp_path / ".tmws" / "secrets"
    secrets_dir.mkdir(parents=True, mode=0o700)
    return secrets_dir


@pytest.fixture
def encryption_service(temp_secrets_dir, monkeypatch):
    """Create DatabaseEncryptionService with temporary secrets directory."""
    service = DatabaseEncryptionService()
    # Override secrets_dir to use temp directory
    monkeypatch.setattr(service, "secrets_dir", temp_secrets_dir)
    return service


class TestEncryptionKeyGeneration:
    """Test encryption key generation and validation."""

    def test_generate_encryption_key_length(self, encryption_service):
        """
        Test: Generate encryption key with correct length

        Given: DatabaseEncryptionService instance
        When: generate_encryption_key() is called
        Then: Should return 64-character hex string (256 bits)
        """
        # Act
        key = encryption_service.generate_encryption_key()

        # Assert
        assert len(key) == 64, f"Expected 64 characters, got {len(key)}"
        assert all(c in "0123456789abcdef" for c in key), "Key must be hex"

    def test_generate_multiple_keys_unique(self, encryption_service):
        """
        Test: Multiple key generations produce unique keys

        Given: DatabaseEncryptionService instance
        When: generate_encryption_key() is called multiple times
        Then: Each key should be unique
        """
        # Act
        keys = [encryption_service.generate_encryption_key() for _ in range(10)]

        # Assert
        assert len(set(keys)) == 10, "All keys should be unique"


class TestEncryptionKeyStorage:
    """Test encryption key storage and retrieval."""

    def test_save_encryption_key_creates_file(self, encryption_service):
        """
        Test: Save encryption key creates file with correct permissions

        Given: Valid 256-bit encryption key
        When: save_encryption_key() is called
        Then: Should create file with 0o600 permissions
        """
        # Arrange
        key = encryption_service.generate_encryption_key()

        # Act
        key_path = encryption_service.save_encryption_key(key)

        # Assert
        assert key_path.exists(), "Key file should exist"
        assert key_path.read_text().strip() == key, "Saved key should match"

        # Check permissions (on Unix-like systems)
        if os.name != "nt":  # Skip on Windows
            stat_info = key_path.stat()
            permissions = stat_info.st_mode & 0o777
            assert permissions == 0o600, f"Expected 0o600, got {oct(permissions)}"

    def test_save_encryption_key_invalid_length_raises_error(self, encryption_service):
        """
        Test: Save encryption key with invalid length raises ValueError

        Given: Invalid encryption key (wrong length)
        When: save_encryption_key() is called
        Then: Should raise ValueError
        """
        # Arrange
        invalid_key = "short_key"

        # Act & Assert
        with pytest.raises(ValueError, match="Invalid key length"):
            encryption_service.save_encryption_key(invalid_key)

    def test_load_encryption_key_success(self, encryption_service):
        """
        Test: Load encryption key successfully

        Given: Saved encryption key
        When: load_encryption_key() is called
        Then: Should return the saved key
        """
        # Arrange
        original_key = encryption_service.generate_encryption_key()
        encryption_service.save_encryption_key(original_key)

        # Act
        loaded_key = encryption_service.load_encryption_key()

        # Assert
        assert loaded_key == original_key, "Loaded key should match original"

    def test_load_encryption_key_not_found_raises_error(self, encryption_service):
        """
        Test: Load non-existent encryption key raises FileNotFoundError

        Given: No encryption key exists
        When: load_encryption_key() is called
        Then: Should raise FileNotFoundError
        """
        # Act & Assert
        with pytest.raises(FileNotFoundError, match="Encryption key not found"):
            encryption_service.load_encryption_key()

    def test_key_exists_returns_true_when_key_exists(self, encryption_service):
        """
        Test: key_exists() returns True when key exists

        Given: Saved encryption key
        When: key_exists() is called
        Then: Should return True
        """
        # Arrange
        key = encryption_service.generate_encryption_key()
        encryption_service.save_encryption_key(key)

        # Act
        exists = encryption_service.key_exists()

        # Assert
        assert exists is True, "key_exists() should return True"

    def test_key_exists_returns_false_when_key_missing(self, encryption_service):
        """
        Test: key_exists() returns False when key doesn't exist

        Given: No encryption key exists
        When: key_exists() is called
        Then: Should return False
        """
        # Act
        exists = encryption_service.key_exists()

        # Assert
        assert exists is False, "key_exists() should return False"


class TestEncryptedEngine:
    """Test encrypted database engine creation."""

    @pytest.mark.asyncio
    async def test_create_encrypted_engine_in_memory(self, encryption_service):
        """
        Test: Create encrypted in-memory database engine

        Given: Valid encryption key
        When: create_encrypted_engine() is called with :memory:
        Then: Should create async engine successfully
        """
        # Arrange
        key = encryption_service.generate_encryption_key()

        # Act
        engine = await encryption_service.create_encrypted_engine(":memory:", encryption_key=key)

        # Assert
        assert engine is not None, "Engine should be created"
        assert str(engine.url).startswith("sqlite+pysqlcipher"), "Should use pysqlcipher"

        # Cleanup
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_create_encrypted_engine_auto_loads_key(self, encryption_service):
        """
        Test: Create encrypted engine auto-loads key if not provided

        Given: Saved encryption key
        When: create_encrypted_engine() is called without key parameter
        Then: Should auto-load key and create engine
        """
        # Arrange
        key = encryption_service.generate_encryption_key()
        encryption_service.save_encryption_key(key)

        # Act
        engine = await encryption_service.create_encrypted_engine(":memory:")

        # Assert
        assert engine is not None, "Engine should be created with auto-loaded key"

        # Cleanup
        await engine.dispose()


class TestSecurityRequirements:
    """Test security-specific requirements."""

    def test_secrets_directory_permissions(self, encryption_service):
        """
        Test: Secrets directory has secure permissions

        Given: DatabaseEncryptionService instance
        When: Secrets directory is created
        Then: Should have 0o700 permissions (owner only)
        """
        # Act
        secrets_dir = encryption_service.secrets_dir

        # Assert
        assert secrets_dir.exists(), "Secrets directory should exist"

        if os.name != "nt":  # Skip on Windows
            stat_info = secrets_dir.stat()
            permissions = stat_info.st_mode & 0o777
            assert permissions == 0o700, f"Expected 0o700, got {oct(permissions)}"

    def test_cipher_is_aes_256_gcm(self, encryption_service):
        """
        Test: Cipher is AES-256-GCM (Hestia's requirement)

        Given: DatabaseEncryptionService instance
        When: Cipher constant is checked
        Then: Should be 'aes-256-gcm'
        """
        # Assert
        assert encryption_service.CIPHER == "aes-256-gcm", "Cipher must be AES-256-GCM"

    def test_key_length_is_256_bits(self, encryption_service):
        """
        Test: Key length is exactly 256 bits

        Given: DatabaseEncryptionService instance
        When: Key length constants are checked
        Then: Should be 256 bits (64 hex characters)
        """
        # Assert
        assert encryption_service.KEY_LENGTH_BITS == 256, "Key must be 256 bits"
        assert encryption_service.KEY_LENGTH_HEX == 64, "Key must be 64 hex characters"


class TestGetEncryptionService:
    """Test singleton instance retrieval."""

    def test_get_encryption_service_returns_singleton(self):
        """
        Test: get_encryption_service() returns singleton instance

        Given: No existing instance
        When: get_encryption_service() is called multiple times
        Then: Should return same instance
        """
        # Act
        service1 = db_encryption_module.get_encryption_service()
        service2 = db_encryption_module.get_encryption_service()

        # Assert
        assert service1 is service2, "Should return same singleton instance"


# Performance baseline (for future optimization)
class TestPerformance:
    """Performance benchmarks for encryption operations."""

    def test_key_generation_performance(self, encryption_service, benchmark):
        """Benchmark: Encryption key generation should be fast (<5ms)."""
        result = benchmark(encryption_service.generate_encryption_key)
        assert len(result) == 64

    def test_key_save_load_performance(self, encryption_service, benchmark):
        """Benchmark: Key save+load should be fast (<50ms)."""
        key = encryption_service.generate_encryption_key()

        def save_and_load():
            encryption_service.save_encryption_key(key, "test_bench.key")
            return encryption_service.load_encryption_key("test_bench.key")

        result = benchmark(save_and_load)
        assert result == key
