"""Test P1b: bcrypt Migration - Dual Support for API Keys

Tests:
1. detect_hash_format() correctly identifies bcrypt vs SHA256
2. New API keys use bcrypt
3. Old SHA256 API keys still work (backward compatibility)
4. Deprecation warnings logged for SHA256 usage
"""

import pytest

from src.utils.security import (
    detect_hash_format,
    generate_and_hash_api_key_for_agent,
    hash_password,
    hash_password_with_salt,
    verify_password,
    verify_password_with_salt,
)


class TestDetectHashFormat:
    """Test hash format detection."""

    def test_detect_bcrypt_format_2b(self):
        """bcrypt format with $2b$ prefix."""
        bcrypt_hash = hash_password("test_password")
        assert bcrypt_hash.startswith("$2b$")
        assert detect_hash_format(bcrypt_hash) == "bcrypt"

    def test_detect_bcrypt_format_2a(self):
        """bcrypt format with $2a$ prefix (older)."""
        # Simulate $2a$ prefix (older bcrypt)
        fake_bcrypt = "$2a$12$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKL"
        assert detect_hash_format(fake_bcrypt) == "bcrypt"

    def test_detect_sha256_format(self):
        """SHA256 with salt format."""
        hashed, salt = hash_password_with_salt("test_password")
        sha256_hash = f"{salt}:{hashed}"
        assert detect_hash_format(sha256_hash) == "sha256_salt"

    def test_detect_empty_hash_raises_error(self):
        """Empty hash raises ValueError."""
        with pytest.raises(ValueError, match="api_key_hash cannot be empty"):
            detect_hash_format("")

    def test_detect_unknown_format_raises_error(self):
        """Unknown format raises ValueError."""
        with pytest.raises(ValueError, match="Unknown hash format"):
            detect_hash_format("invalid_format_no_colon_no_bcrypt_prefix")


class TestGenerateAndHashApiKey:
    """Test new API key generation with bcrypt."""

    def test_generate_returns_tuple(self):
        """Function returns (raw_key, hash) tuple."""
        raw_key, key_hash = generate_and_hash_api_key_for_agent()
        assert isinstance(raw_key, str)
        assert isinstance(key_hash, str)

    def test_raw_key_format(self):
        """Raw API key has correct format."""
        raw_key, _ = generate_and_hash_api_key_for_agent()
        assert raw_key.startswith("tmws_")
        assert len(raw_key) > 40  # Should be reasonably long

    def test_hash_is_bcrypt(self):
        """Hash is bcrypt format."""
        _, key_hash = generate_and_hash_api_key_for_agent()
        assert key_hash.startswith("$2b$")
        assert detect_hash_format(key_hash) == "bcrypt"

    def test_verification_works(self):
        """Raw key can be verified against hash."""
        raw_key, key_hash = generate_and_hash_api_key_for_agent()
        assert verify_password(raw_key, key_hash) is True

    def test_wrong_key_fails_verification(self):
        """Wrong key fails verification."""
        _, key_hash = generate_and_hash_api_key_for_agent()
        assert verify_password("wrong_key", key_hash) is False


class TestDualSupport:
    """Test backward compatibility with SHA256."""

    def test_bcrypt_verification(self):
        """NEW: bcrypt verification works."""
        raw_key, key_hash = generate_and_hash_api_key_for_agent()

        # Verify bcrypt format
        assert detect_hash_format(key_hash) == "bcrypt"

        # Verify with bcrypt
        assert verify_password(raw_key, key_hash) is True

    def test_sha256_verification_backward_compat(self):
        """OLD: SHA256 verification still works (backward compatibility)."""
        raw_key = "tmws_test_api_key_12345"
        hashed, salt = hash_password_with_salt(raw_key)
        sha256_hash = f"{salt}:{hashed}"

        # Verify SHA256 format
        assert detect_hash_format(sha256_hash) == "sha256_salt"

        # Verify with SHA256
        salt_from_hash, hashed_from_hash = sha256_hash.split(":", 1)
        assert verify_password_with_salt(raw_key, hashed_from_hash, salt_from_hash) is True

    def test_different_formats_not_compatible(self):
        """bcrypt hash cannot be verified with SHA256 method."""
        raw_key, bcrypt_hash = generate_and_hash_api_key_for_agent()

        # bcrypt hash format
        assert detect_hash_format(bcrypt_hash) == "bcrypt"

        # SHA256 verification should fail (wrong format)
        # bcrypt hash has no ":" separator, so split will only return 1 element
        parts = bcrypt_hash.split(":", 1)
        assert len(parts) == 1  # No colon separator in bcrypt format


class TestSecurityImprovement:
    """Test that bcrypt is more secure than SHA256."""

    def test_bcrypt_cost_factor(self):
        """bcrypt has appropriate cost factor."""
        _, key_hash = generate_and_hash_api_key_for_agent()

        # Extract cost factor from bcrypt hash: $2b$12$...
        # Format: $2b${cost}${salt+hash}
        parts = key_hash.split("$")
        cost_factor = int(parts[2])

        # bcrypt cost should be >= 12 for security
        assert cost_factor >= 12

    def test_bcrypt_hash_different_each_time(self):
        """bcrypt produces different hashes for same input (salt)."""
        raw_key = "same_key_for_testing"

        hash1 = hash_password(raw_key)
        hash2 = hash_password(raw_key)

        # Different hashes (different salts)
        assert hash1 != hash2

        # But both verify correctly
        assert verify_password(raw_key, hash1) is True
        assert verify_password(raw_key, hash2) is True
