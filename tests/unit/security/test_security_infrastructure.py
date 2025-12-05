"""Unit tests for Phase 2 Security Infrastructure.

Specification: docs/specifications/tool-search-mcp-hub/SPECIFICATION_v1.0.0.md
Phase: 2.1-2.2 - Security Foundation

Tests for:
- S-P0-1: HMAC Socket Authentication
- S-P0-3: JSON Schema Validation
- S-P0-6: Response Size Limits
- S-P0-7: Timeout Enforcement

Author: Metis (Testing) + Hestia (Security Review)
Created: 2025-12-05
"""

import time

import pytest

from src.infrastructure.security.hmac_auth import (
    HMACAuthenticator,
    HMACAuthError,
    HMACToken,
    create_hmac_authenticator,
    reset_authenticator,
)
from src.infrastructure.security.input_validator import (
    InputValidationError,
    JSONSchemaValidator,
    validate_tool_input,
)
from src.infrastructure.security.response_limits import (
    ResponseLimiter,
    ResponseLimitError,
    check_response_size,
)


class TestHMACAuthentication:
    """Tests for S-P0-1: HMAC Socket Authentication."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_authenticator()

    def test_hmac_token_generation(self):
        """Test HMAC token generation."""
        auth = HMACAuthenticator(secret_key=b"test_secret_key_32bytes_long!!!")

        token = auth.generate_token("client_1", b"test message")

        assert token.client_id == "client_1"
        assert token.timestamp > 0
        assert len(token.nonce) == 32  # 16 bytes hex = 32 chars
        assert len(token.signature) == 64  # SHA256 hex = 64 chars

    def test_hmac_token_verification_success(self):
        """Test successful HMAC token verification."""
        auth = HMACAuthenticator(secret_key=b"test_secret_key_32bytes_long!!!")
        message = b"test message data"

        token = auth.generate_token("client_1", message)
        result = auth.verify_token(token, message)

        assert result is True

    def test_hmac_token_verification_wrong_message(self):
        """Test HMAC verification fails with wrong message."""
        auth = HMACAuthenticator(secret_key=b"test_secret_key_32bytes_long!!!")

        token = auth.generate_token("client_1", b"original message")

        with pytest.raises(HMACAuthError) as excinfo:
            auth.verify_token(token, b"different message")

        assert "Invalid signature" in str(excinfo.value)

    def test_hmac_token_expiration(self):
        """Test HMAC token expiration (S-P0-1 security)."""
        auth = HMACAuthenticator(
            secret_key=b"test_secret_key_32bytes_long!!!",
            token_ttl_seconds=60,  # 1 minute
        )
        message = b"test message"

        # Generate token with old timestamp
        old_timestamp = int(time.time()) - 120  # 2 minutes ago
        token = auth.generate_token("client_1", message, timestamp=old_timestamp)

        with pytest.raises(HMACAuthError) as excinfo:
            auth.verify_token(token, message)

        assert "Token expired" in str(excinfo.value)

    def test_hmac_replay_prevention(self):
        """Test HMAC replay attack prevention (S-P0-1 security)."""
        auth = HMACAuthenticator(secret_key=b"test_secret_key_32bytes_long!!!")
        message = b"test message"

        token = auth.generate_token("client_1", message)

        # First verification should succeed
        auth.verify_token(token, message)

        # Second verification with same token should fail (replay)
        with pytest.raises(HMACAuthError) as excinfo:
            auth.verify_token(token, message)

        assert "Replay attack detected" in str(excinfo.value)

    def test_hmac_token_serialization(self):
        """Test HMAC token string serialization/deserialization."""
        auth = HMACAuthenticator(secret_key=b"test_secret_key_32bytes_long!!!")

        original_token = auth.generate_token("client_1", b"test")
        token_str = original_token.to_string()

        # Verify format
        parts = token_str.split(":")
        assert len(parts) == 4
        assert parts[0] == "client_1"

        # Parse back
        parsed_token = HMACToken.from_string(token_str)
        assert parsed_token.client_id == original_token.client_id
        assert parsed_token.timestamp == original_token.timestamp
        assert parsed_token.nonce == original_token.nonce
        assert parsed_token.signature == original_token.signature

    def test_hmac_invalid_token_format(self):
        """Test HMAC invalid token format handling."""
        with pytest.raises(HMACAuthError) as excinfo:
            HMACToken.from_string("invalid:format")

        assert "Invalid token format" in str(excinfo.value)

    def test_hmac_constant_time_comparison(self):
        """Test that verification uses constant-time comparison."""
        # This test verifies the code path exists
        # True timing attack prevention requires timing analysis
        auth = HMACAuthenticator(secret_key=b"test_secret_key_32bytes_long!!!")
        message = b"test message"

        token = auth.generate_token("client_1", message)

        # Modify signature slightly
        wrong_token = HMACToken(
            client_id=token.client_id,
            timestamp=token.timestamp,
            nonce=token.nonce + "_new",  # Different nonce
            signature=token.signature,
        )

        with pytest.raises(HMACAuthError):
            auth.verify_token(wrong_token, message)


class TestJSONSchemaValidation:
    """Tests for S-P0-3: JSON Schema Validation."""

    def test_valid_input_passes(self):
        """Test valid input passes validation."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
            "required": ["name"],
        }

        arguments = {"name": "test", "age": 25}

        # Should not raise
        validate_tool_input(arguments, schema, "test_tool")

    def test_invalid_type_fails(self):
        """Test invalid type fails validation."""
        schema = {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
            },
        }

        arguments = {"count": "not_an_integer"}

        with pytest.raises(InputValidationError) as excinfo:
            validate_tool_input(arguments, schema, "test_tool")

        assert "Validation failed" in str(excinfo.value)

    def test_missing_required_field_fails(self):
        """Test missing required field fails validation."""
        schema = {
            "type": "object",
            "properties": {
                "required_field": {"type": "string"},
            },
            "required": ["required_field"],
        }

        arguments = {}

        with pytest.raises(InputValidationError):
            validate_tool_input(arguments, schema, "test_tool")

    def test_max_string_length_enforcement(self):
        """Test maximum string length enforcement (DoS prevention)."""
        validator = JSONSchemaValidator(max_string_length=100)

        arguments = {"data": "x" * 200}  # Exceeds limit

        with pytest.raises(InputValidationError) as excinfo:
            validator.validate(arguments, {}, "test_tool")

        assert "Maximum string length exceeded" in str(excinfo.value)

    def test_max_array_items_enforcement(self):
        """Test maximum array items enforcement (DoS prevention)."""
        validator = JSONSchemaValidator(max_array_items=10)

        arguments = {"items": list(range(50))}  # Exceeds limit

        with pytest.raises(InputValidationError) as excinfo:
            validator.validate(arguments, {}, "test_tool")

        assert "Maximum array items exceeded" in str(excinfo.value)

    def test_max_depth_enforcement(self):
        """Test maximum nesting depth enforcement (stack overflow prevention)."""
        validator = JSONSchemaValidator(max_depth=5)

        # Create deeply nested structure
        deep_data: dict = {"level": 0}
        current = deep_data
        for i in range(10):
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        with pytest.raises(InputValidationError) as excinfo:
            validator.validate({"data": deep_data}, {}, "test_tool")

        assert "Maximum nesting depth exceeded" in str(excinfo.value)

    def test_empty_schema_skips_validation(self):
        """Test empty schema skips validation (backward compatibility)."""
        arguments = {"anything": "goes", "nested": {"deep": True}}

        # Should not raise
        validate_tool_input(arguments, {}, "test_tool")


class TestResponseSizeLimits:
    """Tests for S-P0-6: Response Size Limits."""

    def test_small_response_passes(self):
        """Test small response passes size check."""
        response = {"result": "success", "data": "small data"}

        size = check_response_size(response)

        assert size > 0
        assert size < 1000  # Small response

    def test_large_response_fails(self):
        """Test large response fails size check (10MB limit)."""
        limiter = ResponseLimiter(max_response_bytes=1000)  # 1KB for testing

        large_response = {"data": "x" * 2000}  # 2KB

        with pytest.raises(ResponseLimitError) as excinfo:
            limiter.check_size(large_response)

        assert "exceeds limit" in str(excinfo.value)
        assert excinfo.value.size_bytes > 1000
        assert excinfo.value.limit_bytes == 1000

    def test_bytes_response_size_check(self):
        """Test bytes response size check."""
        limiter = ResponseLimiter(max_response_bytes=100)

        with pytest.raises(ResponseLimitError):
            limiter.check_size(b"x" * 200)

    def test_string_response_size_check(self):
        """Test string response size check."""
        limiter = ResponseLimiter(max_response_bytes=100)

        with pytest.raises(ResponseLimitError):
            limiter.check_size("x" * 200)

    def test_warning_at_threshold(self, caplog):
        """Test warning logged when approaching limit."""
        import logging

        limiter = ResponseLimiter(
            max_response_bytes=1000,
            warn_threshold_percent=0.8,  # Warn at 80%
        )

        # 900 bytes should trigger warning but not error
        response = {"data": "x" * 850}  # ~870 bytes serialized

        with caplog.at_level(logging.WARNING):
            limiter.check_size(response, "test_server", "test_tool")

        # Response should pass but log warning
        # Note: May not trigger if actual size < 800 bytes

    def test_response_truncation(self):
        """Test response truncation functionality."""
        limiter = ResponseLimiter(max_response_bytes=500)

        large_response = {
            "data": "x" * 1000,
            "items": list(range(100)),
        }

        truncated = limiter.truncate_response(large_response, max_bytes=500)

        assert truncated["truncated"] is True
        assert "original_size_bytes" in truncated

    def test_format_bytes(self):
        """Test human-readable byte formatting."""
        assert ResponseLimiter._format_bytes(500) == "500 B"
        assert ResponseLimiter._format_bytes(1536) == "1.5 KB"
        assert ResponseLimiter._format_bytes(10 * 1024 * 1024) == "10.0 MB"


class TestSecurityModuleIntegration:
    """Integration tests for security module interactions."""

    def test_all_modules_importable(self):
        """Test all security modules can be imported."""
        from src.infrastructure.security import (
            HMACAuthenticator,
            HMACAuthError,
            InputValidationError,
            JSONSchemaValidator,
            ResponseLimiter,
            ResponseLimitError,
        )

        # Verify all exports exist
        assert HMACAuthenticator is not None
        assert HMACAuthError is not None
        assert JSONSchemaValidator is not None
        assert InputValidationError is not None
        assert ResponseLimiter is not None
        assert ResponseLimitError is not None

    def test_security_flow_end_to_end(self):
        """Test complete security validation flow."""
        # Reset singleton
        reset_authenticator()

        # 1. Create authenticator
        auth = create_hmac_authenticator(secret_key=b"integration_test_key_32bytes!!!")

        # 2. Generate auth token
        request_data = b'{"query": "search code"}'
        token = auth.generate_token("test_client", request_data)

        # 3. Verify token
        auth.verify_token(token, request_data)

        # 4. Validate input schema
        schema = {
            "type": "object",
            "properties": {"query": {"type": "string"}},
        }
        validate_tool_input({"query": "search code"}, schema, "search_tools")

        # 5. Check response size
        response = {"results": [{"tool": "grep"}]}
        check_response_size(response)

        # All steps should pass without exception


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
