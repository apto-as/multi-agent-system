"""
Security Tests for TTL Validation (TMWS v2.3.0 Phase 1A Part 2)

Tests the _validate_ttl_days() function security:
- V-TTL-1: Prevents extreme TTL values (> 3650 days)
- V-TTL-2: Prevents zero/negative TTL values
- V-TTL-3: Prevents type confusion attacks

These tests verify that the validation function blocks security attacks
targeting the TTL (Time-To-Live) parameter of create_memory().
"""

import pytest

from src.services.memory_service import validate_ttl_days as _validate_ttl_days


class TestTTLValidationAllowedValues:
    """Test cases for valid TTL values that should be accepted."""

    def test_ttl_days_None_allowed(self):
        """Test that ttl_days=None is allowed for permanent memories."""
        # Act & Assert - Should not raise any exception
        _validate_ttl_days(None)  # Permanent memory

    def test_ttl_days_1_allowed(self):
        """Test that ttl_days=1 (minimum value) is allowed."""
        # Act & Assert - Should not raise any exception
        _validate_ttl_days(1)  # 1 day (minimum)

    def test_ttl_days_3650_allowed(self):
        """Test that ttl_days=3650 (maximum value, 10 years) is allowed."""
        # Act & Assert - Should not raise any exception
        _validate_ttl_days(3650)  # 10 years (maximum)

    def test_ttl_days_typical_values_allowed(self):
        """Test that typical TTL values are allowed."""
        # Typical values
        typical_values = [7, 30, 90, 180, 365, 730]

        # Act & Assert
        for ttl in typical_values:
            _validate_ttl_days(ttl)  # Should not raise


class TestTTLValidationValueErrors:
    """Test cases for V-TTL-1 and V-TTL-2: Value validation."""

    def test_ttl_days_0_raises_ValueError(self):
        """Test that ttl_days=0 raises ValueError (V-TTL-2: Zero value attack)."""
        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            _validate_ttl_days(0)

        # Verify error message is informative
        assert "must be at least 1 day" in str(exc_info.value)
        assert "delete_memory()" in str(exc_info.value)  # Suggests correct action

    def test_ttl_days_negative_raises_ValueError(self):
        """Test that negative ttl_days raises ValueError (V-TTL-2: Negative value attack)."""
        # Test various negative values
        negative_values = [-1, -10, -100, -9999]

        for negative_ttl in negative_values:
            with pytest.raises(ValueError) as exc_info:
                _validate_ttl_days(negative_ttl)

            # Verify error message
            assert "must be at least 1 day" in str(exc_info.value)

    def test_ttl_days_3651_raises_ValueError(self):
        """Test that ttl_days=3651 raises ValueError (V-TTL-1: Extreme value attack)."""
        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            _validate_ttl_days(3651)  # One day over maximum

        # Verify error message is informative
        assert "must be at most 3650 days" in str(exc_info.value)
        assert "ttl_days=None" in str(exc_info.value)  # Suggests permanent storage

    def test_ttl_days_extreme_values_raise_ValueError(self):
        """Test that extreme TTL values raise ValueError (V-TTL-1)."""
        # Test various extreme values
        extreme_values = [10000, 100000, 999999, 2**31 - 1]

        for extreme_ttl in extreme_values:
            with pytest.raises(ValueError) as exc_info:
                _validate_ttl_days(extreme_ttl)

            # Verify error message
            assert "must be at most 3650 days" in str(exc_info.value)


class TestTTLValidationTypeErrors:
    """Test cases for V-TTL-3: Type confusion attacks."""

    def test_ttl_days_string_raises_TypeError(self):
        """Test that string ttl_days raises TypeError (V-TTL-3: String confusion)."""
        # Test various string inputs
        string_values = ["7", "30", "invalid", "None", ""]

        for string_ttl in string_values:
            with pytest.raises(TypeError) as exc_info:
                _validate_ttl_days(string_ttl)  # type: ignore

            # Verify error message indicates type mismatch
            assert "must be an integer or None" in str(exc_info.value)

    def test_ttl_days_float_raises_TypeError(self):
        """Test that float ttl_days raises TypeError (V-TTL-3: Float confusion)."""
        # Test various float inputs
        float_values = [7.0, 7.5, 30.9, 365.25]

        for float_ttl in float_values:
            with pytest.raises(TypeError) as exc_info:
                _validate_ttl_days(float_ttl)  # type: ignore

            # Verify error message
            assert "must be an integer or None" in str(exc_info.value)
            assert "float" in str(exc_info.value)

    def test_ttl_days_other_types_raise_TypeError(self):
        """Test that other invalid types raise TypeError (V-TTL-3)."""
        # Test various invalid types
        # Note: bool is subclass of int in Python, so True/False are accepted as 1/0
        invalid_types = [
            [7],  # list
            {"days": 7},  # dict
            (7,),  # tuple
            b"7",  # bytes
        ]

        for invalid_ttl in invalid_types:
            with pytest.raises(TypeError) as exc_info:
                _validate_ttl_days(invalid_ttl)  # type: ignore

            # Verify error message
            assert "must be an integer or None" in str(exc_info.value)


class TestTTLValidationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_ttl_days_boundary_values(self):
        """Test boundary values (1 and 3650) are accepted."""
        # Boundary values should be accepted
        _validate_ttl_days(1)  # Lower boundary
        _validate_ttl_days(3650)  # Upper boundary

        # Just outside boundaries should be rejected
        with pytest.raises(ValueError):
            _validate_ttl_days(0)  # Below lower boundary

        with pytest.raises(ValueError):
            _validate_ttl_days(3651)  # Above upper boundary

    def test_ttl_days_None_vs_zero_distinction(self):
        """Test that None (permanent) is different from 0 (invalid)."""
        # None should be allowed
        _validate_ttl_days(None)

        # 0 should be rejected
        with pytest.raises(ValueError):
            _validate_ttl_days(0)
